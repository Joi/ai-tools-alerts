"""What is installed on this machine, for matching against advisories.

Every probe runs a FIXED argv from TOOLS (no shell, no argument from a post,
a config file or the caller) with a 5 s timeout. A missing binary, a non-zero
exit, a timeout or output without a readable version yields nothing.
Config files are read for key names only: no command, argument, environment
value or URL from them enters the inventory. ``collect`` never raises.
"""

from __future__ import annotations

import json
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

Runner = Callable[[tuple], "str | None"]


@dataclass(frozen=True)
class Installed:
    name: str
    version: str | None
    path: str


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


def collect_skills(home: Path) -> list[Installed]:
    """Skill directory names, and plugin names from installed_plugins.json
    keys (the part before "@"). Plugin directories are Claude Code's own
    bookkeeping (cache, marketplaces, ...), so they are not read."""
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
        found += _named([k.rsplit("@", 1)[0] for k in plugins if isinstance(k, str)],
                        plugins_file)
    return found


def _keys(table) -> list:
    return list(table) if isinstance(table, dict) else []


def collect_mcp(home: Path) -> list[Installed]:
    """MCP server names (keys only) from the Claude, Codex and Cursor configs."""
    found = []
    claude_json = home / ".claude.json"
    data = _json(claude_json)
    if isinstance(data, dict):
        names = _keys(data.get("mcpServers"))
        projects = data.get("projects")
        if isinstance(projects, dict):
            for proj in projects.values():
                if isinstance(proj, dict):
                    names += _keys(proj.get("mcpServers"))
        found += _named(names, claude_json)
    codex_toml = home / ".codex" / "config.toml"
    raw = _read(codex_toml)
    if raw is not None:
        try:
            found += _named(_keys(tomllib.loads(raw.decode("utf-8")).get("mcp_servers")),
                            codex_toml)
        except (ValueError, UnicodeDecodeError, RecursionError):
            pass
    cursor_json = home / ".cursor" / "mcp.json"
    data = _json(cursor_json)
    if isinstance(data, dict):
        found += _named(_keys(data.get("mcpServers")), cursor_json)
    return found


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
    add("skill", collect_skills, home)
    add("mcp", collect_mcp, home)
    return Inventory(products=products)
