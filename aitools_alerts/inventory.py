"""What is installed on this machine, for matching against advisories.

Every probe runs a FIXED argv from TOOLS (no shell, no argument from a post,
a config file or the caller) with a 5 s timeout. A missing binary, a non-zero
exit, a timeout or output without a readable version yields nothing.
Config files give server keys and plugin keys, and each MCP server's
``command`` and ``args`` are read only to derive the package it runs: a
package name and an exact version, each in a fixed grammar, are all that
enters the inventory from them. No command, argument, environment value or
URL does. A path a config names is only read (bounded, and only a
``package.json`` or a directory listing), never executed; nothing is
started for an MCP server. ``collect`` never raises.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import subprocess
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import schema, versions

MAX_CONFIG_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_CHARS = 4096
MAX_NAME_CHARS = 200
MAX_ARGS = 64
MAX_ARG_CHARS = 4096
MAX_DIST_INFO = 4096

Runner = Callable[[tuple], "str | None"]


@dataclass(frozen=True)
class Installed:
    name: str
    version: str | None
    path: str
    package: str | None = None  # npm:<name> or pypi:<name>, lowercase: what an MCP server runs
    source: str | None = None  # a plugin's marketplace
    server: str | None = None  # the MCP server's configured key


@dataclass(frozen=True)
class Inventory:
    products: dict[str, list[Installed]]


# ecosystem -> (fixed argv, regex capturing the version token on line 1).
# The token runs to the next space, comma, "(" or end of line, so a
# pre-release such as 22.1.0-rc.1 is captured whole: versions cannot read it,
# and check reports unparsable-version instead of comparing 22.1.0.
_TOKEN = r"([0-9]{1,9}\.[0-9A-Za-z.+_~-]{1,63})"
_TOKEN_ANY = r"([0-9][0-9A-Za-z.+_~-]{0,63})"
_EDGE = r"(?=$|[\s,(])"
_RAW = re.compile(r"[0-9][0-9A-Za-z.+_~-]{0,63}")
TOOLS: dict[str, tuple[tuple[str, ...], re.Pattern]] = {
    "claude-code": (("claude", "--version"), re.compile(rf"^(?:claude-code/)?v?{_TOKEN}{_EDGE}")),
    "codex": (("codex", "--version"), re.compile(rf"^(?:codex(?:-cli)? )?v?{_TOKEN}{_EDGE}")),
    "gemini-cli": (("gemini", "--version"), re.compile(rf"^v?{_TOKEN}{_EDGE}")),
    "node": (("node", "--version"), re.compile(rf"^v{_TOKEN}{_EDGE}")),
    "python": (("python3", "--version"), re.compile(rf"^Python {_TOKEN}{_EDGE}")),
    "go": (("go", "version"), re.compile(rf"^go version go{_TOKEN}{_EDGE}")),
    "rust": (("rustc", "--version"), re.compile(rf"^rustc {_TOKEN}{_EDGE}")),
    "docker": (("docker", "--version"), re.compile(rf"^Docker version {_TOKEN}{_EDGE}")),
    "tailscale": (("tailscale", "version"), re.compile(rf"^{_TOKEN_ANY}{_EDGE}")),
    "openssh": (("ssh", "-V"), re.compile(rf"^OpenSSH_{_TOKEN}{_EDGE}")),
    "git": (("git", "--version"), re.compile(rf"^git version {_TOKEN}{_EDGE}")),
    "macos": (("sw_vers", "-productVersion"), re.compile(rf"^{_TOKEN_ANY}{_EDGE}")),
    # Not checked against a real install: a bare version or one after the name.
    "openclaw": (("openclaw", "--version"), re.compile(rf"^(?:[Oo]pen[Cc]law )?v?{_TOKEN}{_EDGE}")),
}


# Components of a scope entry that a host can report on its own, as
# name -> (ecosystem, fixed argv, regex). check matches them by name only.
COMPONENT_TOOLS: dict[str, tuple[str, tuple[str, ...], re.Pattern]] = {
    "containerd": ("docker", ("containerd", "--version"), re.compile(rf"^containerd \S+ v?{_TOKEN}{_EDGE}")),
    "runc": ("docker", ("runc", "--version"), re.compile(rf"^runc version {_TOKEN}{_EDGE}")),
}


def default_runner(argv: tuple) -> str | None:
    """Run one fixed argv; stdout (stderr if stdout is empty), or None."""
    try:
        r = subprocess.run(list(argv), capture_output=True, text=True,
                           errors="replace", timeout=5,
                           stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if r.returncode != 0:
        return None
    out = r.stdout if r.stdout.strip() else r.stderr
    return out[:MAX_OUTPUT_CHARS]


def _scope_names() -> dict[str, str]:
    return {e.ecosystem: e.name for e in schema.load_scope()}


def collect_tool(ecosystem: str, runner: Runner, name: str) -> Installed | None:
    return _probe(*TOOLS[ecosystem], runner, name)


def _probe(argv: tuple, rx: re.Pattern, runner: Runner, name: str) -> Installed | None:
    out = runner(argv)
    if not isinstance(out, str):
        return None
    lines = out.strip().splitlines()
    m = rx.match(lines[0].strip()) if lines else None
    if not m:
        return None
    # A token versions cannot read is kept raw: the tool is installed, and
    # check() reports unparsable-version (notify, never act) for it.
    version = versions.normalize(m.group(1)) or m.group(1)
    if not _RAW.fullmatch(version):
        return None
    return Installed(name=name, version=version, path=argv[0])


def collect_cursor(apps_dirs: list[Path], name: str) -> Installed | None:
    for d in apps_dirs:
        plist = Path(d) / "Cursor.app" / "Contents" / "Info.plist"
        data = _read(plist)
        if data is None:
            continue
        try:
            info = plistlib.loads(data)
        except Exception:
            continue
        raw = info.get("CFBundleShortVersionString") if isinstance(info, dict) else None
        version = versions.normalize(raw)
        if version is not None:
            return Installed(name=name, version=version, path=str(plist))
    return None


def collect_hermes(home: Path, name: str) -> Installed | None:
    """Hermes from the pyproject.toml of its default install. ``hermes
    --version`` is not run: it checks for updates over the network."""
    path = home / ".hermes" / "hermes-agent" / "pyproject.toml"
    raw = _read(path)
    if raw is None:
        return None
    try:
        project = tomllib.loads(raw.decode("utf-8")).get("project")
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(project, dict) or project.get("name") != "hermes-agent":
        return None
    version = versions.normalize(project.get("version"))
    return Installed(name=name, version=version, path=str(path)) if version else None


def _read(path: Path) -> bytes | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return None
        return path.read_bytes()
    except OSError:
        return None


def _json(path: Path):
    data = _read(path)
    if data is None:
        return None
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        return None


def _ok_name(name) -> bool:
    return (isinstance(name, str) and 1 <= len(name) <= MAX_NAME_CHARS
            and not any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp")
                        for c in name))


def _named(names, path: Path) -> list[Installed]:
    out, seen = [], set()
    for n in names:
        if _ok_name(n) and n not in seen:
            seen.add(n)
            out.append(Installed(name=n, version=None, path=str(path)))
    return out


def _plugins(keys, path: Path) -> list[Installed]:
    """A plugin key is name@marketplace: the name, with the marketplace as
    its source. A key whose halves are not both names keeps no source."""
    out = []
    for k in keys:
        name, sep, market = k.rpartition("@")
        if sep and _ok_name(name) and _ok_name(market):
            out.append(Installed(name=name, version=None, path=str(path), source=market))
        else:
            out += _named([name or k], path)
    return list(dict.fromkeys(out))


def collect_skills(home: Path) -> list[Installed]:
    """Skill directory names, and plugin names from installed_plugins.json
    keys (name@marketplace: the marketplace is the plugin's source). Plugin
    directories are Claude Code's own bookkeeping (cache, marketplaces,
    ...), so they are not read."""
    found = []
    skills = home / ".claude" / "skills"
    try:
        dirs = sorted(p.name for p in skills.iterdir()
                      if p.is_dir() and not p.name.startswith("."))
    except OSError:
        dirs = []
    found += _named(dirs, skills)
    plugins_file = home / ".claude" / "plugins" / "installed_plugins.json"
    data = _json(plugins_file)
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if isinstance(plugins, dict):
        found += _plugins([k for k in plugins if isinstance(k, str)], plugins_file)
    return found


def _keys(table) -> list:
    return list(table) if isinstance(table, dict) else []


# ------------------------------------------------- MCP server -> package

_NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*")
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_EXACT = re.compile(r"[0-9]{1,9}(?:\.[0-9]{1,9}){0,4}(?:[a-z][a-z0-9]{0,15})?")
_NPX = frozenset({"npx", "bunx"})
_NPX_FLAGS = frozenset({"-y", "--yes", "-q", "--quiet", "--no-install", "--prefer-offline"})
_PY_SPEC = frozenset({"--from", "--spec"})
_PY_VALUE = frozenset({
    "--python", "-p", "--with", "--with-editable", "--with-requirements", "--index",
    "--index-url", "--extra-index-url", "--default-index", "-i", "--find-links", "-f",
    "--constraint", "-c", "--override", "--python-preference", "--cache-dir",
    "--directory", "--project", "--env-file", "--pip-args", "--index-strategy",
    "--keyring-provider", "--refresh-package", "--reinstall-package", "--upgrade-package"})


def _exact(v: str | None) -> str | None:
    """An exact version (a pin), or None for a tag, a range or nothing."""
    return v if isinstance(v, str) and _EXACT.fullmatch(v) and versions.normalize(v) == v else None


def _npm_spec(spec: str):
    name, version = spec, None
    at = spec.rfind("@")
    if at > 0:
        name, version = spec[:at], _exact(spec[at + 1:])
    if len(name) > 214 or not _NPM_NAME.fullmatch(name):
        return None
    return f"npm:{name}", name, version


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pypi_spec(spec: str):
    version = None
    for sep in ("==", "@"):
        if sep in spec:
            spec, rest = spec.split(sep, 1)
            version = _exact(rest.strip())
            break
    spec = spec.split("[", 1)[0].strip()
    if len(spec) > MAX_NAME_CHARS or not _PYPI_NAME.fullmatch(spec):
        return None
    name = _pep503(spec)
    return f"pypi:{name}", name, version


def _first_spec(args: list, spec_flags: frozenset, value_flags: frozenset,
                plain_flags: frozenset) -> str | None:
    """The package spec a runner's arguments name: the value of a spec flag,
    else the first positional. An unknown option ends the reading."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in spec_flags:
            return args[i + 1] if i + 1 < len(args) else None
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("--") and "=" in a and a.split("=", 1)[0] in spec_flags:
            return a.split("=", 1)[1]
        if a in value_flags:
            i += 2
            continue
        if a.startswith("-"):
            if a in plain_flags or (a.startswith("--") and "=" in a):
                i += 1
                continue
            return None
        return a
    return None


def _node_modules(path: str):
    parts = path.replace("\\", "/").split("/")
    if "node_modules" not in parts:
        return None
    i = len(parts) - 1 - parts[::-1].index("node_modules")
    rest = parts[i + 1:]
    if not rest:
        return None
    pkg = "/".join(rest[:2]) if rest[0].startswith("@") and len(rest) > 1 else rest[0]
    got = _npm_spec(pkg) if "@" not in pkg[1:] else None
    if got is None:
        return None
    meta = _json(Path("/".join(parts[:i + 1])) / pkg / "package.json")
    version = None
    if isinstance(meta, dict) and meta.get("name") == pkg:
        version = _exact(meta.get("version"))
    return got[0], got[1], version


def _venv(path: str):
    p = Path(path)
    if p.parent.name != "bin" or not p.name:
        return None
    root = p.parent.parent
    try:
        if not (root / "pyvenv.cfg").is_file():
            return None
        libs = sorted(d for d in (root / "lib").iterdir() if d.name.startswith("python3"))
    except OSError:
        return None
    want = _pep503(p.name)
    for lib in libs:
        try:
            with os.scandir(lib / "site-packages") as it:
                for n, entry in enumerate(it):
                    if n >= MAX_DIST_INFO:
                        break
                    stem = entry.name[:-len(".dist-info")] if entry.name.endswith(".dist-info") else None
                    if not stem or "-" not in stem:
                        continue
                    dist, ver = stem.rsplit("-", 1)
                    if _pep503(dist) == want and _PYPI_NAME.fullmatch(dist):
                        return f"pypi:{want}", want, _exact(ver)
        except OSError:
            continue
    return None


def mcp_package(command, args) -> tuple[str, str, str | None] | None:
    """(package, name, version) for the package an MCP server's command
    runs, or None. Reads at most a package.json or a directory listing;
    starts nothing. Never raises."""
    try:
        if not isinstance(command, str) or not 0 < len(command) <= MAX_ARG_CHARS:
            return None
        args = [] if args is None else args
        if (not isinstance(args, list) or len(args) > MAX_ARGS
                or not all(isinstance(a, str) and len(a) <= MAX_ARG_CHARS for a in args)):
            return None
        base = command.replace("\\", "/").rsplit("/", 1)[-1]
        if base in _NPX:
            spec = _first_spec(args, frozenset({"-p", "--package"}), frozenset(), _NPX_FLAGS)
            return _npm_spec(spec) if spec else None
        py = None
        if base == "uvx":
            py = args
        elif base == "uv" and args[:2] == ["tool", "run"]:
            py = args[2:]
        elif base == "pipx" and args[:1] == ["run"]:
            py = args[1:]
        if py is not None:
            spec = _first_spec(py, _PY_SPEC, _PY_VALUE, frozenset({"-q", "--quiet", "-v", "--verbose",
                                                                    "--isolated", "--no-cache", "--offline"}))
            return _pypi_spec(spec) if spec else None
        target = args[0] if base in ("node", "node.exe") and args else command
        if "/node_modules/" in target.replace("\\", "/"):
            return _node_modules(target)
        if "/" in command:
            return _venv(command)
    except Exception:
        return None
    return None


def _servers(table, path: Path) -> list[Installed]:
    """One record per configured server key: the package its command runs
    when that resolves, else the key alone."""
    out = []
    if not isinstance(table, dict):
        return out
    for key, conf in table.items():
        if not _ok_name(key):
            continue
        got = mcp_package(conf.get("command"), conf.get("args")) if isinstance(conf, dict) else None
        if got is None:
            out.append(Installed(name=key, version=None, path=str(path), server=key))
        else:
            out.append(Installed(name=got[1], version=got[2], path=str(path),
                                 package=got[0], server=key))
    return out


def collect_mcp(home: Path) -> list[Installed]:
    """MCP servers from the Claude, Codex and Cursor configs: each key, with
    the package its command runs when that resolves."""
    found = []
    claude_json = home / ".claude.json"
    data = _json(claude_json)
    if isinstance(data, dict):
        found += _servers(data.get("mcpServers"), claude_json)
        projects = data.get("projects")
        if isinstance(projects, dict):
            for proj in projects.values():
                if isinstance(proj, dict):
                    found += _servers(proj.get("mcpServers"), claude_json)
    codex_toml = home / ".codex" / "config.toml"
    raw = _read(codex_toml)
    if raw is not None:
        try:
            found += _servers(tomllib.loads(raw.decode("utf-8")).get("mcp_servers"), codex_toml)
        except (ValueError, UnicodeDecodeError, RecursionError):
            pass
    cursor_json = home / ".cursor" / "mcp.json"
    data = _json(cursor_json)
    if isinstance(data, dict):
        found += _servers(data.get("mcpServers"), cursor_json)
    return list(dict.fromkeys(found))


def collect(home: Path | None = None, runner: Runner | None = None,
            apps_dirs: list[Path] | None = None) -> Inventory:
    """Everything installed, keyed by every scope ecosystem. Never raises."""
    try:
        if home is None:
            from .config import home as passwd_home
            home = passwd_home()
        home = Path(home)
    except Exception:
        home = Path("/nonexistent")
    runner = runner or default_runner
    if apps_dirs is None:
        apps_dirs = [Path("/Applications"), home / "Applications"]
    try:
        names = _scope_names()
    except Exception:
        names = {}
    products: dict[str, list[Installed]] = {eco: [] for eco in names}

    def add(eco: str, fn, *args):
        try:
            got = fn(*args)
        except Exception:
            return
        if got is None:
            return
        products.setdefault(eco, []).extend(got if isinstance(got, list) else [got])

    for eco in TOOLS:
        add(eco, collect_tool, eco, runner, names.get(eco, eco))
    for name, (eco, argv, rx) in COMPONENT_TOOLS.items():
        add(eco, _probe, argv, rx, runner, name)
    add("cursor", collect_cursor, apps_dirs, names.get("cursor", "Cursor"))
    add("hermes", collect_hermes, home, names.get("hermes", "Hermes"))
    add("skill", collect_skills, home)
    add("mcp", collect_mcp, home)
    return Inventory(products=products)
