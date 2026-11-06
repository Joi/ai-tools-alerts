"""ops/vm/aitools-poster-shell: the poster user's login shell allows one command shape.

The tracked guard runs under bash against a fake sudo and a fake buzz-send in
a temporary directory. The test copy changes only the RELAY_USER_FILE= and
WRAPPER= lines, so the checks it exercises are the installed ones.
"""

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from aitools_alerts.poster.transport import remote_argv

ROOT = Path(__file__).resolve().parent.parent
VM = ROOT / "ops" / "vm"
GUARD = VM / "aitools-poster-shell"
WRAPPER_LINE = 'WRAPPER="/home/$RELAY_USER/bin/buzz-send"\n'
USER_FILE_LINE = "RELAY_USER_FILE=/etc/aitools-poster/relay-user\n"
DIR = object()  # relay_user=DIR puts a directory where the file goes
CHANNEL = "599adb9f-4f9f-4b19-aee3-66667c3293e8"
REPLY = "ab" * 32


def _bash_major(path: str) -> int:
    try:
        out = subprocess.run([path, "-c", 'echo "${BASH_VERSINFO[0]}"'],
                             capture_output=True, text=True, timeout=10).stdout
        return int(out.strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return 0


# The relay VM runs bash 5; the guard needs mapfile (bash 4+). macOS /bin/bash is 3.2.
BASH = next((b for b in (os.environ.get("POSTER_SHELL_BASH"), shutil.which("bash"),
                         "/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/bin/bash")
             if b and _bash_major(b) >= 4), None)

FAKE_SUDO = r"""#!/usr/bin/env bash
d="$(dirname "$0")"
printf '%s\0' "$@" > "$d/sudo-argv"
[ "$1" = "-n" ] && [ "$2" = "-u" ] && [ "$3" = "$(cat "$d/expect-user")" ] && [ "$4" = "--" ] || exit 99
shift 4
exec "$@"
"""

FAKE_WRAPPER = r"""#!/usr/bin/env bash
d="$(dirname "$0")"
printf '%s\0' "$@" > "$d/wrapper-argv"
cat > "$d/wrapper-stdin"
echo '{"accepted":true,"event_id":"00"}'
"""


def _make_guard(tmp_path, bash, relay_user="relayuser\n"):
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "expect-user").write_text(relay_user.strip() if isinstance(relay_user, str) else "")
    user_file = tmp_path / "relay-user"
    if relay_user is DIR:
        user_file.mkdir()
    elif relay_user is not None:
        user_file.write_text(relay_user)
    for name, body in (("sudo", FAKE_SUDO), ("buzz-send", FAKE_WRAPPER)):
        (fake / name).write_text(body)
        (fake / name).chmod(0o755)
    wrapper = str(fake / "buzz-send")
    src = GUARD.read_text()
    assert src.count(WRAPPER_LINE) == 1 and src.count(USER_FILE_LINE) == 1
    copy = tmp_path / "aitools-poster-shell"
    copy.write_text(src.replace(WRAPPER_LINE, f"WRAPPER={shlex.quote(wrapper)}\n")
                    .replace(USER_FILE_LINE, f"RELAY_USER_FILE={shlex.quote(str(user_file))}\n"))
    env = {"PATH": f"{fake}:{os.environ['PATH']}", "HOME": str(tmp_path)}

    def run(*args, stdin=b"hello", lang=None):
        return subprocess.run([bash, str(copy), *args], input=stdin,
                              env=env if lang is None else {**env, "LANG": lang},
                              cwd=tmp_path, capture_output=True, timeout=30)

    run.fake = fake
    run.wrapper = wrapper
    return run


def _bash_guard(tmp_path, relay_user="relayuser\n"):
    if BASH is None:  # a skip would let the gate pass without testing the guard
        pytest.fail("no bash 4+ (the relay VM runs bash 5): brew install bash, or set POSTER_SHELL_BASH")
    return _make_guard(tmp_path, BASH, relay_user)


@pytest.fixture
def guard(tmp_path):
    return _bash_guard(tmp_path)


def _argv(path: Path) -> list[str]:
    return path.read_bytes().decode().split("\0")[:-1]


def _refused(r, fake: Path, why: str):
    assert r.returncode == 1, r
    lines = r.stderr.decode().splitlines()
    assert len(lines) == 1
    err = json.loads(lines[0])
    assert err["error"] == "user_error" and err["message"].startswith("aitools-poster-shell: refused")
    assert why in err["message"]
    assert not (fake / "sudo-argv").exists() and not (fake / "wrapper-argv").exists()


def test_bash3_fails_closed(tmp_path):
    """Under a bash without mapfile (macOS /bin/bash 3.2) every command is refused."""
    if _bash_major("/bin/bash") >= 4:
        pytest.skip("/bin/bash here is 4+")
    g = _make_guard(tmp_path, "/bin/bash")
    r = g("-c", shlex.join(remote_argv(CHANNEL, wrapper=g.wrapper)))
    assert r.returncode == 1
    assert "refused: unparsable command" in r.stderr.decode()
    assert not (g.fake / "wrapper-argv").exists()


def test_tracked_guard_is_executable_and_names_no_relay_user():
    assert os.access(GUARD, os.X_OK)
    src = GUARD.read_text()
    assert "RELAY_USER=\"RELAY_USER\"" not in src and src.count(USER_FILE_LINE) == 1
    assert "AITOOLS_" not in src  # the installed guard takes no path from its environment


@pytest.mark.parametrize("content, why", [
    (None, "relay user file missing"), (DIR, "relay user file missing"),
    ("", "not one user name"), ("\n", "not one user name"), ("a\nb\n", "not one user name"),
    ("relayuser\n\n", "not one user name"), ("relayuser\r\n", "not one user name"),
    ("Relay\n", "not one user name"), ("1relay\n", "not one user name"),
    ("relay user\n", "not one user name"), ("../x\n", "not one user name"),
    ("a" * 33 + "\n", "not one user name"), ("relay\0user\n", "not one user name"),
    ("relayuser\n\0", "not one user name"), ("\0relayuser", "not one user name"),
])
def test_relay_user_file_refused(tmp_path, content, why):
    g = _bash_guard(tmp_path, content)
    for args in (("-c", shlex.join(remote_argv(CHANNEL, wrapper=g.wrapper))), ()):
        _refused(g(*args), g.fake, why)


@pytest.mark.parametrize("content", ["relayuser", "_r-1\n", "a" * 32 + "\n"])
def test_relay_user_file_good_names(tmp_path, content):
    g = _bash_guard(tmp_path, content)
    argv = remote_argv(CHANNEL, wrapper=g.wrapper)
    r = g("-c", shlex.join(argv))
    assert r.returncode == 0, r.stderr
    assert _argv(g.fake / "sudo-argv")[:3] == ["-n", "-u", content.strip()]


@pytest.mark.parametrize("reply_to", [None, REPLY])
def test_allowed_shape_reaches_the_wrapper(guard, reply_to):
    argv = remote_argv(CHANNEL, reply_to, wrapper=guard.wrapper)
    r = guard("-c", shlex.join(argv), stdin="日本語\n--relay x".encode())
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["accepted"] is True
    assert _argv(guard.fake / "sudo-argv") == ["-n", "-u", "relayuser", "--", *argv]
    assert _argv(guard.fake / "wrapper-argv") == argv[1:]
    assert (guard.fake / "wrapper-stdin").read_bytes() == "日本語\n--relay x".encode()


def test_interactive_extra_and_empty_refused(guard):
    cmd = shlex.join(remote_argv(CHANNEL, wrapper=guard.wrapper))
    for args, why in (((), "interactive"), (("-l",), "interactive"),
                      (("-c", cmd, "extra"), "interactive"), (("-c", ""), "empty command")):
        _refused(guard(*args), guard.fake, why)


def _cmd(guard, *rest):
    return " ".join([shlex.quote(guard.wrapper), *rest])


SEND = f"messages send --channel {CHANNEL} --content -"


@pytest.mark.parametrize("tail, why", [
    ("messages send --channel 'unbalanced", "unparsable command"),
    (f"'messages\nsend' --channel {CHANNEL} --content -", "argument count 6"),
    (SEND + " --reply-to", "argument count 8"),
    (SEND + f" --reply-to {REPLY} extra", "argument count 10"),
    ("channels delete --channel " + CHANNEL + " --content -", "subcommand"),
    (f"messages send --relay {CHANNEL} --content -", "argument 4"),
    (f"messages send --channel {CHANNEL.upper()} --content -", "channel id"),
    ("messages send --channel 599adb9f4f9f4b19aee366667c3293e8xxxx --content -", "channel id"),
    (f"messages send --channel {CHANNEL} --content hi", "content must come from stdin"),
    (f"messages send --channel {CHANNEL} --private-key -", "content must come from stdin"),
    (SEND + f" --relay {REPLY}", "argument 8"),
    (SEND + " --reply-to " + REPLY[:-1], "reply-to id"),
    (SEND + " --reply-to " + REPLY.upper(), "reply-to id"),
    (SEND + " --reply-to " + shlex.quote(REPLY + "\n" + REPLY), "reply-to id"),
])
def test_other_shapes_refused(guard, tail, why):
    _refused(guard("-c", _cmd(guard, tail)), guard.fake, why)


def test_python_failure_after_partial_output_refused(guard):
    """python3 printing a valid prefix and then failing is a refusal, not a 7-argument send."""
    argv = remote_argv(CHANNEL, wrapper=guard.wrapper)
    fake = guard.fake / "python3"
    fake.write_text("#!/bin/sh\nprintf '%s\\0' " + shlex.join(argv) + "\nexit 1\n")
    fake.chmod(0o755)
    _refused(guard("-c", shlex.join(argv)), guard.fake, "unparsable command")


def test_non_utf8_argument_refused_under_utf8_locale(guard):
    """A non-UTF-8 byte in argument 8 under a client-sent UTF-8 LANG (ai-tools-alerts#zeqm).

    End-to-end only: which check refuses depends on the platform python's
    locale handling. The fake-python test above is the deterministic one.
    """
    cmd = _cmd(guard, SEND).encode() + b" \xff " + REPLY.encode()
    r = guard("-c", cmd, lang="en_US.UTF-8")
    why = "unparsable command" if b"unparsable" in r.stderr else "argument 8"
    _refused(r, guard.fake, why)


@pytest.mark.parametrize("program", ["/bin/sh", "buzz-send", "~/bin/buzz-send", "ls"])
def test_other_programs_refused(guard, program):
    _refused(guard("-c", f"{program} {SEND}"), guard.fake, "program")


@pytest.mark.parametrize("inject", ["; touch PWNED", "$(touch PWNED)", "`touch PWNED`", "&& touch PWNED"])
def test_shell_metacharacters_never_run(guard, tmp_path, inject):
    r = guard("-c", _cmd(guard, SEND, inject))
    assert r.returncode == 1
    assert not (guard.fake / "wrapper-argv").exists()
    assert not list(tmp_path.rglob("PWNED"))


def test_sudoers_reference_matches_the_guard():
    lines = [ln for ln in (VM / "sudoers-aitools-poster").read_text().splitlines()
             if ln and not ln.startswith("#")]
    w = "/home/RELAY_USER/bin/buzz-send messages send --channel [0-9a-f]* --content -"
    assert lines == [f"aitools-poster ALL=(RELAY_USER) NOPASSWD: {w}, {w} --reply-to [0-9a-f]*"]


def test_sshd_match_reference():
    lines = [ln.strip() for ln in (VM / "sshd-match-aitools-poster.conf").read_text().splitlines()
             if ln.strip() and not ln.startswith("#")]
    assert lines == ["Match User aitools-poster",
                     "AuthorizedKeysFile /home/aitools-poster/.ssh/authorized_keys",
                     *(f"{k} no" for k in ("AllowTcpForwarding", "AllowAgentForwarding",
                                           "X11Forwarding", "PermitTTY", "PermitTunnel",
                                           "AllowStreamLocalForwarding")),
                     "DisableForwarding yes", "PermitUserRC no"]
