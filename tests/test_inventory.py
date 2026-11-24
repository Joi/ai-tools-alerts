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
