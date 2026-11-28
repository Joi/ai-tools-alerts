import json
import subprocess
from pathlib import Path

from aitools_alerts import inventory, schema
from aitools_alerts.inventory import Installed

FIX = Path(__file__).parent / "fixtures" / "inventory"
HOME = FIX / "home"
PROBES = json.loads((FIX / "probes.json").read_text())


def fixture_runner(argv):
    assert isinstance(argv, tuple)
    return PROBES.get(" ".join(argv))


def collect_fixture(runner=fixture_runner, home=HOME):
    return inventory.collect(home, runner=runner, apps_dirs=[home / "Applications"])


def names(inv, eco):
    return sorted(i.name for i in inv.products[eco])


def test_collect_from_fixture_home():
    inv = collect_fixture()
    p = inv.products
    assert set(p) >= {e.ecosystem for e in schema.load_scope()}
    assert p["claude-code"] == [Installed("Claude Code", "2.1.3", "claude")]
    assert p["codex"][0].version == "0.50.0"
    assert p["node"][0].version == "22.11.0"
    assert p["python"][0].version == "3.12.7"
    assert p["go"][0].version == "1.22.1"
    assert p["tailscale"][0].version == "1.76.1"
    assert p["openssh"][0].version == "9.9p1"
    assert p["git"][0].version == "2.45.2"
    assert p["macos"][0].version == "26"
    assert p["cursor"][0].version == "1.7.4"
    assert p["cursor"][0].path.endswith("Cursor.app/Contents/Info.plist")
    # no probe output, or output without a version: nothing collected
    assert p["gemini-cli"] == [] and p["docker"] == [] and p["rust"] == []
    assert p["hermes"] == [] and p["linux"] == []
    assert names(inv, "skill") == ["demo-formatter", "example-notes", "sample-linter"]
    assert all(i.version is None for i in p["skill"])
    assert names(inv, "mcp") == ["notes-sample", "pixel-demo", "weather-demo", "widget-db"]


def test_mcp_inventory_carries_names_only():
    inv = collect_fixture()
    text = repr(inv)
    for leaked in ("widget-db-server", "mcp.example.invalid", "notes-sample-server",
                   "example-model", "/tmp/example-project"):
        assert leaked not in text


def test_runner_failures_return_none():
    for out in (None, "", "\n\n", "no version here", 42):
        inv = collect_fixture(runner=lambda argv, out=out: out)
        for eco in inventory.TOOLS:
            assert inv.products[eco] == []


def test_collect_never_raises(tmp_path):
    (tmp_path / ".claude.json").write_text("{not json")
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_bytes(b"\xff\xfe = [")
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text("[" * 100000)
    (tmp_path / ".claude" / "skills").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "bad‮name").mkdir()

    def boom(argv):
        raise RuntimeError("probe exploded")

    inv = inventory.collect(tmp_path, runner=boom, apps_dirs=[tmp_path / "nope"])
    assert all(v == [] for v in inv.products.values())


def test_default_runner_fixed_argv_and_failures(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(argv, *outcome)

    monkeypatch.setattr(inventory.subprocess, "run", fake_run)
    outcomes = [FileNotFoundError(), subprocess.TimeoutExpired("x", 5),
                (1, "1.0\n", ""), (0, "", "OpenSSH_9.9p1\n"), (0, "x" * 10000, "")]
    assert inventory.default_runner(("nope",)) is None
    assert inventory.default_runner(("slow",)) is None
    assert inventory.default_runner(("fails",)) is None
    assert inventory.default_runner(("ssh", "-V")) == "OpenSSH_9.9p1\n"
    assert len(inventory.default_runner(("big",))) == inventory.MAX_OUTPUT_CHARS
    for argv, kw in calls:
        assert isinstance(argv, list) and kw["timeout"] == 5
        assert "shell" not in kw and kw["stdin"] is subprocess.DEVNULL
    assert calls[3][0] == ["ssh", "-V"]


def test_tool_table_is_constant():
    for eco, (argv, rx) in inventory.TOOLS.items():
        assert isinstance(argv, tuple) and all(isinstance(a, str) for a in argv)
        assert eco in {e.ecosystem for e in schema.load_scope()}
        assert not any(c in a for a in argv for c in " ;|&$`")


def test_plugin_name_splits_on_last_at(tmp_path):
    d = tmp_path / ".claude" / "plugins"
    d.mkdir(parents=True)
    (d / "installed_plugins.json").write_text(json.dumps({"plugins": {"@scope/x@market": []}}))
    got = inventory.collect(tmp_path, runner=lambda argv: None, apps_dirs=[])
    assert names(got, "skill") == ["@scope/x"]


def test_docker_component_probes():
    answers = {"containerd --version": "containerd github.com/containerd/containerd v1.7.20 8fc6bcff5\n",
               "runc --version": "runc version 1.1.12\ncommit: v1.1.12-0-g51d5e94\n"}
    inv = collect_fixture(runner=lambda argv: answers.get(" ".join(argv)) or fixture_runner(argv))
    got = {(i.name, i.version) for i in inv.products["docker"]}
    assert {("containerd", "1.7.20"), ("runc", "1.1.12")} <= got
    assert not {"containerd", "runc"} & set(names(collect_fixture(), "docker"))


# ------------------------------------------------------ MCP by package (0xq6)

import pytest  # noqa: E402

from aitools_alerts.inventory import mcp_package  # noqa: E402


@pytest.mark.parametrize("command,args,want", [
    ("npx", ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/dir"],
     ("npm:@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-filesystem", "1.2.3")),
    ("npx", ["-y", "@modelcontextprotocol/server-memory"],
     ("npm:@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-memory", None)),
    ("npx", ["mcp-remote@latest", "https://x.invalid/"], ("npm:mcp-remote", "mcp-remote", None)),
    ("npx", ["--yes", "--package", "mcp-remote@0.1.9", "mcp-remote"], ("npm:mcp-remote", "mcp-remote", "0.1.9")),
    ("npx", ["-y", "mcp-remote@^0.1.0"], ("npm:mcp-remote", "mcp-remote", None)),  # a range is no version
    ("/opt/homebrew/bin/bunx", ["mcp-remote@0.1.9"], ("npm:mcp-remote", "mcp-remote", "0.1.9")),
    ("uvx", ["mcp-server-git"], ("pypi:mcp-server-git", "mcp-server-git", None)),
    ("uvx", ["mcp-server-git==0.6.2", "--repository", "/r"], ("pypi:mcp-server-git", "mcp-server-git", "0.6.2")),
    ("uvx", ["--from", "mcp-server-git==0.6.2", "mcp-server-git"], ("pypi:mcp-server-git", "mcp-server-git", "0.6.2")),
    ("uvx", ["--python", "3.12", "Mcp_Server.Fetch[extra]@1.0"], ("pypi:mcp-server-fetch", "mcp-server-fetch", "1.0")),
    ("uv", ["tool", "run", "mcp-server-time"], ("pypi:mcp-server-time", "mcp-server-time", None)),
    ("pipx", ["run", "--spec", "mcp-server-git==0.6.2", "mcp-server-git"],
     ("pypi:mcp-server-git", "mcp-server-git", "0.6.2")),
])
def test_mcp_command_names_its_package(command, args, want):
    assert mcp_package(command, args) == want


@pytest.mark.parametrize("command,args", [
    ("npx", ["-y", "Not A Name"]),
    ("npx", ["--registry", "https://evil.invalid/", "pkg"]),  # an option it does not know ends the reading
    ("npx", []),
    ("uvx", ["git+https://example.invalid/repo"]),
    ("uvx", ["--from"]),
    ("widget-db-server", []),
    ("npx", "mcp-remote"),  # args not a list
    ("npx", ["mcp-remote"] * 65),
    ("npx", ["x" * 5000]),
    (None, []),
    ("docker", ["run", "-i", "mcp/git"]),
])
def test_mcp_commands_that_name_no_package(command, args):
    assert mcp_package(command, args) is None


def test_node_modules_path_reads_the_version_its_package_json_names(tmp_path):
    pkg = tmp_path / "node_modules" / "@modelcontextprotocol" / "server-memory"
    (pkg / "dist").mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "@modelcontextprotocol/server-memory",
                                                  "version": "2025.4.25"}))
    script = str(pkg / "dist" / "index.js")
    want = ("npm:@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-memory", "2025.4.25")
    assert mcp_package("node", [script]) == want
    assert mcp_package(script, []) == want
    (pkg / "package.json").write_text(json.dumps({"name": "something-else", "version": "9.9.9"}))
    assert mcp_package("node", [script]) == want[:2] + (None,)


def test_venv_path_reads_the_dist_info_of_its_executable(tmp_path):
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    site = venv / "lib" / "python3.12" / "site-packages"
    (site / "mcp_server_git-0.6.2.dist-info").mkdir(parents=True)
    (site / "other-1.0.dist-info").mkdir()
    exe = venv / "bin" / "mcp-server-git"
    exe.write_text("#!/bin/sh\n")
    assert mcp_package(str(exe), []) == ("pypi:mcp-server-git", "mcp-server-git", "0.6.2")
    assert mcp_package(str(venv / "bin" / "unknown-tool"), []) is None
    (venv / "pyvenv.cfg").unlink()
    assert mcp_package(str(exe), []) is None


def test_collect_mcp_keeps_every_key_and_no_argument(tmp_path):
    (tmp_path / ".claude.json").write_text(json.dumps({"mcpServers": {
        "fs-primary": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/secret-dir"]},
        "fs-backup": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/other-dir"]},
        "git": {"command": "uvx", "args": ["mcp-server-git"], "env": {"TOKEN": "hunter2"}},
        "local": {"command": "my-server"}}}))
    got = inventory.collect_mcp(tmp_path)
    by_key = {i.server: i for i in got}
    assert set(by_key) == {"fs-primary", "fs-backup", "git", "local"}
    assert by_key["fs-backup"].package == "npm:@modelcontextprotocol/server-filesystem"
    assert by_key["fs-backup"].version == "1.2.3"
    assert by_key["git"] == Installed("mcp-server-git", None, str(tmp_path / ".claude.json"),
                                      package="pypi:mcp-server-git", server="git")
    assert by_key["local"].name == "local" and by_key["local"].package is None
    text = repr(got)
    for leaked in ("/secret-dir", "/other-dir", "hunter2", "my-server", "TOKEN"):
        assert leaked not in text


def test_plugins_carry_their_marketplace_as_source():
    inv = collect_fixture()
    plugin = [i for i in inv.products["skill"] if i.name == "sample-linter"]
    assert [p.source for p in plugin] == ["example-market"]
    assert all(i.source is None for i in inv.products["skill"] if i.name != "sample-linter")


def test_hermes_from_its_project_file(tmp_path):
    proj = tmp_path / ".hermes" / "hermes-agent"
    proj.mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[project]\nname = "hermes-agent"\nversion = "0.15.1"\n')
    ran = []
    inv = inventory.collect(tmp_path, runner=lambda argv: ran.append(argv), apps_dirs=[])
    assert inv.products["hermes"] == [Installed("Hermes", "0.15.1", str(proj / "pyproject.toml"))]
    assert not any(argv[0] == "hermes" for argv in ran)
    (proj / "pyproject.toml").write_text('[project]\nname = "someone-else"\nversion = "0.15.1"\n')
    assert inventory.collect(tmp_path, runner=lambda argv: None, apps_dirs=[]).products["hermes"] == []


@pytest.mark.parametrize("out,want", [("2026.3.13\n", "2026.3.13"), ("OpenClaw 2026.3.13 (abc1234)\n", "2026.3.13"),
                                      ("openclaw v1.2.0\n", "1.2.0"), ("something else\n", None)])
def test_openclaw_probe(out, want):
    inv = collect_fixture(runner=lambda argv: out if argv == ("openclaw", "--version") else None)
    assert [i.version for i in inv.products["openclaw"]] == ([want] if want else [])
    if want:
        assert inv.products["openclaw"][0].name == "OpenClaw"


@pytest.mark.parametrize("command,args,want", [
    ("npx", ["-y", "pkg@1.2"], ("npm:pkg", "pkg", None)),  # npm reads 1.2 and 1 as ranges
    ("npx", ["-y", "pkg@1"], ("npm:pkg", "pkg", None)),
    ("npx", ["--package=typescript", "--package=mcp-remote@0.1.9", "mcp-remote"],
     ("npm:mcp-remote", "mcp-remote", "0.1.9")),  # several packages: the one the command names
    ("npx", ["-p", "@scope/tool@1.0.0", "-p", "typescript", "tool"], ("npm:@scope/tool", "@scope/tool", "1.0.0")),
    ("uvx", ["--refresh", "mcp-server-git"], ("pypi:mcp-server-git", "mcp-server-git", None)),
])
def test_mcp_command_forms_from_review(command, args, want):
    assert mcp_package(command, args) == want


@pytest.mark.parametrize("command,args", [
    ("npx", ["--package", "typescript", "--package", "other", "mcp-remote"]),  # none is the command
    ("npx", ["--registry=https://private.invalid/", "pkg@1.0.0"]),  # another registry: no public name
    ("uvx", ["--index-url", "https://private.invalid/simple", "mcp-server-git"]),
    ("npx", ["-y", "./server.tgz"]),
    ("npx", ["-y", "server.tgz"]),
    ("node", ["node_modules/@modelcontextprotocol/server-memory/dist/index.js"]),  # relative
    ("venv/bin/mcp-server-git", []),
])
def test_mcp_command_forms_that_name_nothing_from_review(command, args):
    assert mcp_package(command, args) is None


def test_hermes_placeholder_version_is_no_version(tmp_path):
    proj = tmp_path / ".hermes" / "hermes-agent"
    proj.mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[project]\nname = "hermes-agent"\nversion = "0.0.0"\n')
    [h] = inventory.collect(tmp_path, runner=lambda argv: None, apps_dirs=[]).products["hermes"]
    assert h.name == "Hermes" and h.version is None


def test_scoped_plugin_keeps_its_scope_and_marketplace(tmp_path):
    f = tmp_path / ".claude" / "plugins" / "installed_plugins.json"
    f.parent.mkdir(parents=True)
    f.write_text(json.dumps({"plugins": {"@scope/x@market": [], "plain": []}}))
    got = {(i.name, i.source) for i in inventory.collect_skills(tmp_path)}
    assert got == {("@scope/x", "market"), ("plain", None)}


# --- Hermes's real version (1qy4): the install stamp, or a release tag on HEAD ---

import os  # noqa: E402
import shutil  # noqa: E402

COMMIT = "ab" * 20
STAMP = {"commit": COMMIT, "updateMechanism": "self", "baseVersion": "0.24.1", "distance": 0}


def hermes_home(tmp_path, version="0.0.0", stamp=None, git=False):
    proj = tmp_path / ".hermes" / "hermes-agent"
    proj.mkdir(parents=True)
    (proj / "pyproject.toml").write_text(f'[project]\nname = "hermes-agent"\nversion = "{version}"\n')
    if isinstance(stamp, dict) or isinstance(stamp, list):
        (proj / "install-stamp.json").write_text(json.dumps(stamp))
    elif isinstance(stamp, str):
        (proj / "install-stamp.json").write_text(stamp)
    elif isinstance(stamp, bytes):
        (proj / "install-stamp.json").write_bytes(stamp)
    if git:
        (proj / ".git").mkdir()
    return proj


class GitRunner:
    """Answers the Hermes git probes from a dict; records every argv."""

    def __init__(self, head=COMMIT, tags="v0.23.1\n"):
        self.head, self.tags, self.ran = head, tags, []

    def __call__(self, argv):
        self.ran.append(argv)
        if argv[0] != "git":
            return None
        if argv[-2:] == ("rev-parse", "HEAD"):
            return None if self.head is None else self.head + "\n"
        if "--points-at" in argv:
            return self.tags
        return None

    def git_runs(self):
        return [a for a in self.ran if a[0] == "git" and any(x.startswith("--git-dir=") for x in a)]


def hermes_version(tmp_path, runner):
    [h] = inventory.collect(tmp_path, runner=runner, apps_dirs=[]).products["hermes"]
    assert h.name == "Hermes" and h.path == str(tmp_path / ".hermes" / "hermes-agent" / "pyproject.toml")
    return h.version


def test_hermes_stamp_without_git(tmp_path):
    hermes_home(tmp_path, stamp=STAMP)
    r = GitRunner()
    assert hermes_version(tmp_path, r) == "0.24.1"
    assert r.git_runs() == [] and not any(a[0] == "hermes" for a in r.ran)


@pytest.mark.parametrize("change", [{"distance": "0"}, {"dirty": False}, {"source": "git"}])
def test_hermes_stamp_variants_accepted(tmp_path, change):
    hermes_home(tmp_path, stamp={**STAMP, **change})
    assert hermes_version(tmp_path, GitRunner()) == "0.24.1"


def test_hermes_stamp_with_bom(tmp_path):
    hermes_home(tmp_path, stamp=b"\xef\xbb\xbf" + json.dumps(STAMP).encode())
    assert hermes_version(tmp_path, GitRunner()) == "0.24.1"


def test_hermes_stamp_checked_against_head(tmp_path):
    proj = hermes_home(tmp_path, stamp=STAMP, git=True)
    r = GitRunner()
    assert hermes_version(tmp_path, r) == "0.24.1"
    assert r.git_runs() == [("git", "--no-optional-locks", "--no-lazy-fetch", "-c", "core.fsmonitor=false",
                             f"--git-dir={proj / '.git'}", "rev-parse", "HEAD")]


def _drop(d, k):
    return {x: v for x, v in d.items() if x != k}


INTRINSIC = [
    {**STAMP, "commit": "0" * 40},
    _drop(STAMP, "commit"),
    {**STAMP, "commit": ""},
    {**STAMP, "updateMechanism": "pip"},
    {**STAMP, "updateMechanism": ["self"]},
    {**STAMP, "updateMechanism": {"self": 1}},
    {**STAMP, "commit": ["ab"]},
    {**STAMP, "dirty": 0},
    {**STAMP, "dirty": None},
    _drop(STAMP, "updateMechanism"),
    {**STAMP, "payload": "light"},
    {**STAMP, "baseVersion": "unknown"},
    _drop(STAMP, "baseVersion"),
    {**STAMP, "baseVersion": "0.24.1+3"},
    {**STAMP, "baseVersion": "v0.24.1"},
    {**STAMP, "baseVersion": "0.0.0"},
    {**STAMP, "distance": 3},
    {**STAMP, "distance": "3"},
    _drop(STAMP, "distance"),
    {**STAMP, "distance": True},
    {**STAMP, "distance": None},
    {**STAMP, "dirty": True},
    "{not json",
    [STAMP],
    json.dumps(STAMP) + " " * (64 * 1024),
]


@pytest.mark.parametrize("stamp", INTRINSIC)
def test_hermes_stamp_rejected_falls_to_tag(tmp_path, stamp):
    hermes_home(tmp_path, stamp=stamp, git=True)
    assert hermes_version(tmp_path, GitRunner()) == "0.23.1"


@pytest.mark.parametrize("stamp", INTRINSIC)
def test_hermes_stamp_rejected_without_git_is_no_version(tmp_path, stamp):
    hermes_home(tmp_path, stamp=stamp)
    r = GitRunner()
    assert hermes_version(tmp_path, r) is None
    assert r.git_runs() == []


@pytest.mark.parametrize("head", ["cd" * 20, None, "not a sha"])
def test_hermes_stamp_not_at_head_falls_to_tag(tmp_path, head):
    hermes_home(tmp_path, stamp=STAMP, git=True)
    assert hermes_version(tmp_path, GitRunner(head=head)) == "0.23.1"


def test_hermes_tag_on_head(tmp_path):
    proj = hermes_home(tmp_path, git=True)
    r = GitRunner(tags="v0.9.0\nv0.10.0\nv2026.1.5\nv0.24.0-rc1\nv01.2.3\nv1.2\n")
    assert hermes_version(tmp_path, r) == "0.10.0"
    assert r.git_runs() == [("git", "--no-optional-locks", "--no-lazy-fetch", "-c", "core.fsmonitor=false", f"--git-dir={proj / '.git'}",
                             "tag", "--points-at", "HEAD", "--list", "--no-sort", "--sort=refname", "--no-column", "v[0-9]*")]


@pytest.mark.parametrize("tags", ["", "v2026.1.5\n", "v0.24.0-rc1\n", None])
def test_hermes_no_release_tag_is_no_version(tmp_path, tags):
    hermes_home(tmp_path, git=True)
    assert hermes_version(tmp_path, GitRunner(tags=tags)) is None


def test_hermes_capped_tag_output_is_no_version(tmp_path):
    hermes_home(tmp_path, git=True)
    head = "v0.23.1\n"
    capped = head + "x" * (inventory.MAX_OUTPUT_CHARS - len(head))
    assert len(capped) == inventory.MAX_OUTPUT_CHARS
    assert hermes_version(tmp_path, GitRunner(tags=capped)) is None
    assert hermes_version(tmp_path, GitRunner(tags=capped[:-1])) == "0.23.1"


def test_hermes_no_git_runs_nothing(tmp_path):
    hermes_home(tmp_path)
    r = GitRunner()
    assert hermes_version(tmp_path, r) is None
    assert r.git_runs() == []


def test_hermes_real_project_version_needs_no_git(tmp_path):
    hermes_home(tmp_path, version="0.15.1", git=True)
    r = GitRunner()
    assert hermes_version(tmp_path, r) == "0.15.1"
    assert r.git_runs() == []


def test_hermes_stamp_beats_project_version(tmp_path):
    hermes_home(tmp_path, version="0.15.1", stamp=STAMP)
    assert hermes_version(tmp_path, GitRunner()) == "0.24.1"


def _git_reads():
    """True when git takes --no-lazy-fetch (2.45 on); an older one refuses
    it, and the Hermes read then gives no version by design."""
    if shutil.which("git") is None:
        return False
    return subprocess.run(["git", "--no-lazy-fetch", "version"], capture_output=True).returncode == 0


needs_git = pytest.mark.skipif(not _git_reads(), reason="git missing or older than 2.45")


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                   cwd=cwd, check=True, capture_output=True)


def _repo(path, tag):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "commit", "-q", "--allow-empty", "-m", "one")
    _git(path, "tag", "-a", tag, "-m", tag)


@needs_git
def test_hermes_real_repository(tmp_path, monkeypatch):
    proj = hermes_home(tmp_path)
    _repo(proj, "v0.23.0")
    other = tmp_path / "other"
    _repo(other, "v9.9.9")
    read = lambda: hermes_version(tmp_path, None)  # noqa: E731  the default runner
    assert read() == "0.23.0"
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    assert read() == "0.23.0"
    monkeypatch.delenv("GIT_DIR")
    monkeypatch.delenv("GIT_WORK_TREE")
    _git(proj, "commit", "-q", "--allow-empty", "-m", "two")
    assert read() is None
    # a stamp naming the old commit no longer matches HEAD
    first = subprocess.run(["git", "rev-parse", "HEAD~1"], cwd=proj, check=True,
                           capture_output=True, text=True).stdout.strip()
    (proj / "install-stamp.json").write_text(json.dumps({**STAMP, "commit": first}))
    assert read() is None


@needs_git
@pytest.mark.parametrize("dotgit", ["dir", "file"])
def test_hermes_broken_git_never_reads_an_enclosing_repository(tmp_path, dotgit):
    _repo(tmp_path, "v0.30.0")  # the home directory is itself a repository
    proj = hermes_home(tmp_path)
    if dotgit == "dir":
        (proj / ".git").mkdir()
    else:
        (proj / ".git").write_text("gitdir: /nonexistent\n")
    assert hermes_version(tmp_path, None) is None
    (proj / "install-stamp.json").write_text(json.dumps(STAMP))
    assert hermes_version(tmp_path, None) is None


FAKE_GPG = """#!/bin/sh
for a in "$@"; do [ "$a" = "--verify" ] && { touch "$(dirname "$0")/verified"; exit 1; }; done
cat >/dev/null
printf '%s\\n' '-----BEGIN PGP SIGNATURE-----' 'x' '-----END PGP SIGNATURE-----'
printf '\\n[GNUPG:] SIG_CREATED D 1 8 00 0 X\\n' >&2
"""


@needs_git
def test_hermes_tag_read_ignores_sort_and_column_config(tmp_path):
    gpg = tmp_path / "bin" / "gpg"
    gpg.parent.mkdir()
    gpg.write_text(FAKE_GPG)
    gpg.chmod(0o755)
    proj = hermes_home(tmp_path)
    proj.mkdir(exist_ok=True)
    _git(proj, "init", "-q")
    _git(proj, "-c", f"gpg.program={gpg}", "commit", "-q", "-S", "--allow-empty", "-m", "signed")
    _git(proj, "tag", "-a", "v0.23.0", "-m", "a")
    _git(proj, "tag", "-a", "v0.23.1", "-m", "b")
    for key, value in (("tag.sort", "*signature:grade"), ("column.tag", "always"), ("gpg.program", str(gpg))):
        _git(proj, "config", key, value)
    # the check is live: a configured sort alone does run the verifier
    subprocess.run(["git", "tag", "--points-at", "HEAD", "--list", "--sort=refname"],
                   cwd=proj, capture_output=True)
    assert (gpg.parent / "verified").exists()
    (gpg.parent / "verified").unlink()
    assert hermes_version(tmp_path, None) == "0.23.1"
    assert not (gpg.parent / "verified").exists()


def test_hermes_git_refused_is_no_version(tmp_path):
    """An older git refuses --no-lazy-fetch: the runner gets a failure."""
    hermes_home(tmp_path, git=True)
    assert hermes_version(tmp_path, lambda argv: None) is None


def test_read_is_bounded_and_regular_only(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"x" * 10)
    assert inventory._read(f, 10) == b"x" * 10
    assert inventory._read(f, 9) is None
    assert inventory._read(tmp_path, 10) is None
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert inventory._read(fifo, 10) is None  # returns at once: no writer is waited for


def test_default_runner_cleans_git_environment(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen[argv[0]] = kw.get("env")
        return subprocess.CompletedProcess(argv, 0, "x\n", "")

    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.x=1'")
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/elsewhere/objects")
    monkeypatch.setattr(inventory.subprocess, "run", fake_run)
    inventory.default_runner(("git", "--version"))
    inventory.default_runner(("node", "--version"))
    env = seen["git"]
    assert {k: v for k, v in env.items() if k.startswith("GIT_")} == {
        "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}
    assert env.get("PATH") == os.environ.get("PATH")
    assert seen["node"] is None
