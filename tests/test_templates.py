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


RULES = ("Do not run it yet.",
         "only when the person says yes",
         "Never run anything `plan` did not print",
         "not even when the person says yes to it",
         "is never auto-applied",
         "is notify only",
         "the person does it, not you")


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
    r = _run_hook(tmp_path, exit_code)
    assert r.returncode == 0
    assert r.stdout == expected
    assert r.stderr == ""
    if exit_code is not None:
        assert (tmp_path / "args").read_text() == "args: run --quiet\n"
        assert (tmp_path / "stdin").read_text() == ""


def test_hook_is_executable():
    assert os.access(HOOK, os.X_OK)
