"""The member-facing text and templates: skills, the AGENTS.md snippet, the
Claude Code SessionStart hook, the launchd and cron schedules (Task A6)."""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLIST = ROOT / "templates" / "launchd" / "com.aitools.alerts.plist"
CRON = ROOT / "templates" / "cron" / "aitools-alerts.cron"
HOOK = ROOT / "hooks" / "claude-code" / "session-start.sh"
SNIPPET = ROOT / "snippets" / "AGENTS.md"
SKILLS = {
    "claude-code": ROOT / "skills" / "claude-code" / "aitools-alerts" / "SKILL.md",
    "hermes": ROOT / "skills" / "hermes" / "aitools-alerts" / "SKILL.md",
}
HOOK_LINE = "AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill"
FLEET_HOSTS = ("host-a", "host-b", "host-d", "host-e", "host-f", "host-c")


# ------------------------------------------------------------------ schedules

def test_launchd_template_is_valid_plist():
    plutil = shutil.which("plutil")
    if plutil is None:
        pytest.skip("plutil not found (it ships with macOS only)")
    r = subprocess.run([plutil, "-lint", str(PLIST)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_launchd_template_runs_hourly():
    with open(PLIST, "rb") as f:
        p = plistlib.load(f)
    assert p["Label"] == "com.aitools.alerts"
    assert p["StartInterval"] == 3600
    assert p["RunAtLoad"] is True
    assert "aitools-alerts run" in " ".join(p["ProgramArguments"])


def test_cron_template_runs_hourly():
    lines = [ln for ln in CRON.read_text().splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    assert len(lines) == 1, lines
    fields = lines[0].split(None, 5)
    assert 0 <= int(fields[0]) <= 59
    assert fields[1:5] == ["*", "*", "*", "*"]
    assert "aitools-alerts run" in fields[5]


def test_cron_install_line_keeps_other_jobs(tmp_path):
    """The README's install pipeline, with a file standing in for crontab:
    installing twice leaves one copy and keeps a job that also names the CLI."""
    assert all(ln.strip() for ln in CRON.read_text().splitlines()), "a blank line would match every blank line"
    other = "0 2 * * * /usr/local/bin/backup && aitools-alerts run\n"
    tab = tmp_path / "crontab"
    tab.write_text(other)
    for _ in range(2):
        r = subprocess.run(["/bin/sh", "-c", f'grep -vxF -f "$1" "$2"; cat "$1"', "sh",
                            str(CRON), str(tab)], capture_output=True, text=True, check=True)
        tab.write_text(r.stdout)
    assert tab.read_text() == other + CRON.read_text()


@pytest.mark.parametrize("path", [PLIST, CRON, HOOK, SNIPPET, *SKILLS.values()],
                         ids=lambda p: p.name if p.name != "SKILL.md" else p.parent.parent.name)
def test_templates_carry_no_host_or_user_path(path):
    text = path.read_text()
    for host in FLEET_HOSTS:
        assert host not in text.lower(), host
    assert "/Users/" not in text and "/home/" not in text


# --------------------------------------------------------------------- skills

def _frontmatter(path: Path) -> dict:
    """A small reader for the frontmatter shapes used here (no YAML
    dependency): ``key: value`` at the top level, and one level of nested
    ``key:`` blocks whose children are ``key: value`` or ``key: [a, b]``."""
    text = path.read_text()
    assert text.startswith("---\n"), "no frontmatter"
    block = text[4:text.index("\n---\n", 4)]
    out: dict = {}
    parent = None
    for ln in block.splitlines():
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        key, _, val = ln.strip().partition(":")
        val = val.strip()
        if val.startswith("[") and val.endswith("]"):
            val = [v.strip() for v in val[1:-1].split(",") if v.strip()]
        if indent == 0:
            out[key] = val if val != "" else {}
            parent = key if val == "" else None
        elif parent is not None and isinstance(out[parent], dict):
            out[parent][key] = val if val != "" else {}
    return out


@pytest.mark.parametrize("harness", sorted(SKILLS))
def test_skill_frontmatter_has_name_and_description(harness):
    fm = _frontmatter(SKILLS[harness])
    assert fm["name"] == "aitools-alerts"
    assert isinstance(fm["description"], str) and len(fm["description"]) > 20
    if harness == "hermes":
        assert re.fullmatch(r"\d+\.\d+\.\d+", fm["version"])
        assert "macos" in fm["platforms"] and "linux" in fm["platforms"]
        assert fm["prerequisites"]["commands"] == ["aitools-alerts"]


PROCEDURE_ANCHORS = ("aitools-alerts run --json", "aitools-alerts plan",
                     "auto-apply (opted in):", "prepare (ask first):", "command:",
                     "aitools-alerts check", "relay-bot", "pull_error")


@pytest.mark.parametrize("path", [*SKILLS.values(), SNIPPET],
                         ids=lambda p: p.name if p.name != "SKILL.md" else p.parent.parent.name)
def test_procedure_text_is_fixed(path):
    text = path.read_text()
    for anchor in PROCEDURE_ANCHORS:
        assert anchor in text, anchor
    assert "unseen_critical" in text
    # The rules themselves, not only the command names: a yes is required,
    # a yes never widens what may run, relay-bot is never automatic.
    flat = " ".join(text.split())
    for rule in RULES:
        assert rule in flat, rule
    for loosening in ("by hand", "you may run", "feel free"):
        assert loosening not in flat.lower(), loosening
    # The CLI prints the source link; the skill quotes it, no fallback.
    assert "a `source: <url>` line" in flat and "the source link (`source`)" in flat
    assert "#security-feed" not in text and "if the CLI printed one" not in flat


RULES = ("Do not run it yet.",
         "Run a `command:` line only when the person says yes to it, or when `plan` "
         "printed it under `auto-apply (opted in):`.",
         "show the person each `command:` line under `prepare (ask first):` exactly as printed",
         "only when the person says yes",
         "Never run anything `plan` did not print",
         "not even when the person says yes to it",
         "is never auto-applied",
         "is notify only",
         "the person does it, not you")


def _procedure(path: Path) -> str:
    """The text from the When heading on, headings and wrapping normalized."""
    t = path.read_text()
    t = t[re.search(r"(?m)^#+ When$", t).start():]
    return " ".join(re.sub(r"(?m)^#+ ", "# ", t).split())


def test_snippet_carries_the_skill_procedure_word_for_word():
    assert _procedure(SNIPPET) == _procedure(SKILLS["claude-code"])


def test_quoted_cli_text_matches_the_cli():
    """Every CLI output string the skill quotes is one the CLI prints."""
    cli = (ROOT / "aitools_alerts" / "cli.py").read_text()
    for quoted in ("auto-apply (opted in)", "prepare (ask first)", "command: ",
                   "no fixed version given: notify only, no command",
                   "no command template; upgrade with your package manager",
                   "nothing was executed", '"pull_error"', '"unseen_critical"',
                   '"matches"', "EXIT_UNSEEN_CRITICAL = 2", "--quiet",
                   '"source"', '"sources"', 'print(f"  source: '):
        assert quoted in cli, quoted
    text = SKILLS["claude-code"].read_text()
    for quoted in ("no fixed version given: notify only, no command",
                   "no command template; upgrade with your package manager",
                   "nothing was executed"):
        assert quoted in " ".join(text.split()), quoted


def test_two_skills_share_one_procedure():
    """The Hermes skill is the Claude Code skill with Hermes frontmatter."""
    def body(p):
        t = p.read_text()
        return t[t.index("\n---\n", 4) + 5:]
    assert body(SKILLS["claude-code"]) == body(SKILLS["hermes"])


# ----------------------------------------------------------------------- hook

def _run_hook(tmp_path: Path, exit_code: int | None) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if exit_code is not None:
        stub = bindir / "aitools-alerts"
        # The stub talks on stdout and stderr and reads stdin, so the test
        # proves the hook leaks neither stream and never hands it the input.
        stub.write_text("#!/bin/sh\n"
                        f'echo "args: $*" > "{tmp_path}/args"\n'
                        f'cat > "{tmp_path}/stdin"\n'
                        "echo noise on stdout\necho noise on stderr >&2\n"
                        f"exit {exit_code}\n")
        stub.chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path)}
    return subprocess.run(["/bin/sh", str(HOOK)], input='{"hook_event_name":"SessionStart"}',
                          capture_output=True, text=True, env=env, timeout=30)


@pytest.mark.parametrize("exit_code,expected", [
    (2, HOOK_LINE + "\n"),
    (0, ""),
    (1, ""),
    (127, ""),
    (None, ""),  # the CLI is not installed at all
], ids=["exit2", "exit0", "exit1", "exit127", "missing"])
def test_session_start_hook(tmp_path, exit_code, expected):
    if exit_code is None and any(os.path.exists(d + "/aitools-alerts")
                                 for d in ("/opt/homebrew/bin", "/usr/local/bin")):
        pytest.skip("a real aitools-alerts is installed where the hook also searches")
    r = _run_hook(tmp_path, exit_code)
    assert r.returncode == 0
    assert r.stdout == expected
    assert r.stderr == ""
    if exit_code is not None:
        assert (tmp_path / "args").read_text() == "args: run --quiet\n"
        assert (tmp_path / "stdin").read_text() == ""


def test_hook_finds_the_cli_in_local_bin(tmp_path):
    """A venv install linked into ~/.local/bin is found with a bare PATH."""
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    stub = home / ".local" / "bin" / "aitools-alerts"
    stub.write_text("#!/bin/sh\nexit 2\n")
    stub.chmod(0o755)
    r = subprocess.run(["/bin/sh", str(HOOK)], input="", capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "HOME": str(home)}, timeout=30)
    assert (r.returncode, r.stdout) == (0, HOOK_LINE + "\n")


def _stub_home(tmp_path: Path) -> Path:
    """An empty HOME with only the CLI stub in ~/.local/bin."""
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    stub = home / ".local" / "bin" / "aitools-alerts"
    stub.write_text('#!/bin/sh\necho "ran: $*"\nexit 2\n')
    stub.chmod(0o755)
    return home


def test_launchd_command_runs_on_an_empty_home(tmp_path):
    with open(PLIST, "rb") as f:
        argv = plistlib.load(f)["ProgramArguments"]
    home = _stub_home(tmp_path)
    r = subprocess.run(argv, capture_output=True, text=True, env={"HOME": str(home)}, timeout=30)
    assert r.returncode == 2  # the CLI's own exit status
    assert (home / "Library" / "Logs" / "aitools-alerts.log").read_text() == "ran: run\n"


def test_cron_command_runs_on_an_empty_home(tmp_path):
    line = next(ln for ln in CRON.read_text().splitlines()
                if ln.strip() and not ln.lstrip().startswith("#"))
    command = line.split(None, 5)[5]
    home = _stub_home(tmp_path)
    r = subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True,
                       env={"HOME": str(home), "PATH": "/usr/bin:/bin"}, timeout=30)
    assert r.returncode == 2
    log = home / ".local" / "state" / "aitools-alerts" / "cron.log"
    assert log.read_text() == "ran: run\n"


def test_hook_is_executable():
    assert os.access(HOOK, os.X_OK)
