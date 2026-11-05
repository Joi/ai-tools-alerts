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
