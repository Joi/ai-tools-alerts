"""ops/vm/aitools-poster-shell: the poster user's login shell allows one command shape,
``mirror-put checkpoint`` (nfm3). Posting through it (buzz-send) retired with vzc3.

The tracked guard runs under bash against a fake sudo and a fake mirror-put in
a temporary directory. The test copy changes only the RELAY_USER_FILE= and
PUT= lines, so the checks it exercises are the installed ones.
"""

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VM = ROOT / "ops" / "vm"
GUARD = VM / "aitools-poster-shell"
PUT_LINE = 'PUT="/home/$RELAY_USER/bin/mirror-put"\n'
USER_FILE_LINE = "RELAY_USER_FILE=/etc/aitools-poster/relay-user\n"
DIR = object()  # relay_user=DIR puts a directory where the file goes
CHANNEL = "599adb9f-4f9f-4b19-aee3-66667c3293e8"


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

FAKE_PUT = r"""#!/usr/bin/env bash
d="$(dirname "$0")"
printf '%s\0' "$@" > "$d/put-argv"
cat > "$d/put-stdin"
echo '{"stored":true,"bytes":1}'
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
    for name, body in (("sudo", FAKE_SUDO), ("mirror-put", FAKE_PUT)):
        (fake / name).write_text(body)
        (fake / name).chmod(0o755)
    src = GUARD.read_text()
    assert src.count(USER_FILE_LINE) == 1 and src.count(PUT_LINE) == 1
    copy = tmp_path / "aitools-poster-shell"
    put = str(fake / "mirror-put")
    copy.write_text(src.replace(PUT_LINE, f"PUT={shlex.quote(put)}\n")
                    .replace(USER_FILE_LINE, f"RELAY_USER_FILE={shlex.quote(str(user_file))}\n"))
    env = {"PATH": f"{fake}:{os.environ['PATH']}", "HOME": str(tmp_path)}

    def run(*args, stdin=b"hello", lang=None):
        return subprocess.run([bash, str(copy), *args], input=stdin,
                              env=env if lang is None else {**env, "LANG": lang},
                              cwd=tmp_path, capture_output=True, timeout=30)

    run.fake = fake
    run.put = put
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
    assert not (fake / "sudo-argv").exists() and not (fake / "put-argv").exists()


def _put_cmd(guard):
    return shlex.join([guard.put, "checkpoint"])


def test_bash3_fails_closed(tmp_path):
    """Under a bash without mapfile (macOS /bin/bash 3.2) every command is refused."""
    if _bash_major("/bin/bash") >= 4:
        pytest.skip("/bin/bash here is 4+")
    g = _make_guard(tmp_path, "/bin/bash")
    r = g("-c", _put_cmd(g))
    assert r.returncode == 1
    assert "refused: unparsable command" in r.stderr.decode()
    assert not (g.fake / "put-argv").exists()


def test_tracked_guard_is_executable_and_names_no_relay_user():
    assert os.access(GUARD, os.X_OK)
    src = GUARD.read_text()
    assert "RELAY_USER=\"RELAY_USER\"" not in src and src.count(USER_FILE_LINE) == 1
    assert "AITOOLS_" not in src  # the installed guard takes no path from its environment
    assert "buzz-send" not in src.split("set +x", 1)[1]  # vzc3: no send shape in the code


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
    for args in (("-c", _put_cmd(g)), ()):
        _refused(g(*args), g.fake, why)


@pytest.mark.parametrize("content", ["relayuser", "_r-1\n", "a" * 32 + "\n"])
def test_relay_user_file_good_names(tmp_path, content):
    g = _bash_guard(tmp_path, content)
    r = g("-c", _put_cmd(g))
    assert r.returncode == 0, r.stderr
    assert _argv(g.fake / "sudo-argv")[:3] == ["-n", "-u", content.strip()]


def test_interactive_extra_and_empty_refused(guard):
    cmd = _put_cmd(guard)
    for args, why in (((), "interactive"), (("-l",), "interactive"),
                      (("-c", cmd, "extra"), "interactive"), (("-c", ""), "empty command")):
        _refused(guard(*args), guard.fake, why)


SEND = f"messages send --channel {CHANNEL} --content -"


@pytest.mark.parametrize("program", ["/home/relayuser/bin/buzz-send", "buzz-send", "~/bin/buzz-send", "/bin/sh", "ls"])
def test_the_retired_send_shape_and_other_programs_are_refused(guard, program):
    """vzc3: the poster posts over HTTPS; nothing can post through this route."""
    _refused(guard("-c", f"{program} {SEND}"), guard.fake, "argument count")
    _refused(guard("-c", f"{program} checkpoint"), guard.fake, "program")


def test_unparsable_and_python_failure_refused(guard):
    _refused(guard("-c", shlex.quote(guard.put) + " 'unbalanced"), guard.fake, "unparsable command")
    fake = guard.fake / "python3"  # a valid prefix, then failure: a refusal, not a put
    fake.write_text("#!/bin/sh\nprintf '%s\\0' " + _put_cmd(guard) + "\nexit 1\n")
    fake.chmod(0o755)
    _refused(guard("-c", _put_cmd(guard)), guard.fake, "unparsable command")


def test_a_newline_cannot_rebuild_the_shape(guard):
    _refused(guard("-c", shlex.quote(guard.put + "\ncheckpoint")), guard.fake, "argument count 1")


@pytest.mark.parametrize("inject", ["; touch PWNED", "$(touch PWNED)", "`touch PWNED`", "&& touch PWNED"])
def test_shell_metacharacters_never_run(guard, tmp_path, inject):
    r = guard("-c", _put_cmd(guard) + " " + inject)
    assert r.returncode == 1
    assert not (guard.fake / "put-argv").exists()
    assert not list(tmp_path.rglob("PWNED"))


def test_sudoers_reference_matches_the_guard():
    lines = [ln for ln in (VM / "sudoers-aitools-poster").read_text().splitlines()
             if ln and not ln.startswith("#")]
    p = "/home/RELAY_USER/bin/mirror-put checkpoint"  # no wildcard: sudo matches the command whole
    assert lines == [f"aitools-poster ALL=(RELAY_USER) NOPASSWD: {p}"]


def test_sshd_match_reference():
    lines = [ln.strip() for ln in (VM / "sshd-match-aitools-poster.conf").read_text().splitlines()
             if ln.strip() and not ln.startswith("#")]
    assert lines == ["Match User aitools-poster",
                     "AuthorizedKeysFile /home/aitools-poster/.ssh/authorized_keys",
                     *(f"{k} no" for k in ("AllowTcpForwarding", "AllowAgentForwarding",
                                           "X11Forwarding", "PermitTTY", "PermitTunnel",
                                           "AllowStreamLocalForwarding")),
                     "DisableForwarding yes", "PermitUserRC no"]


# ------------------------------------------- the shape: mirror-put checkpoint (nfm3)

def test_put_shape_reaches_mirror_put_with_stdin_intact(guard):
    from aitools_alerts.poster import transport
    seen = {}

    def ssh(argv, **kw):  # what transport.put hands to ssh is exactly what the guard accepts
        seen["remote"] = argv[-1]
        return subprocess.CompletedProcess(argv, 0, b'{"stored":true,"bytes":1}\n', b"")
    assert transport.put("checkpoint", b'{"x":1}', ssh, host="relay.example.invalid", wrapper=guard.put) == (True, "stored")
    doc = '{"id":"日本語"}\n--relay x'.encode()
    r = guard("-c", seen["remote"], stdin=doc)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"stored": True, "bytes": 1}
    assert _argv(guard.fake / "sudo-argv") == ["-n", "-u", "relayuser", "--", guard.put, "checkpoint"]
    assert _argv(guard.fake / "put-argv") == ["checkpoint"]
    assert (guard.fake / "put-stdin").read_bytes() == doc


@pytest.mark.parametrize("tail", [
    [], ["manifest"], ["checkpoint", "extra"], ["checkpoint", ""], ["Checkpoint"], ["checkpoint;id"],
    ["--help"], ["checkpoint", "--out", "/etc/passwd"], ["messages", "send"]])
def test_other_put_shapes_refused(guard, tail):
    r = guard("-c", shlex.join([guard.put, *tail]))
    assert r.returncode == 1 and not (guard.fake / "put-argv").exists()
    assert not (guard.fake / "sudo-argv").exists()
    assert json.loads(r.stderr.decode().splitlines()[0])["message"].startswith("aitools-poster-shell: refused")


@pytest.mark.parametrize("program", ["/tmp/mirror-put", "mirror-put", "/home/other/bin/mirror-put",
                                     "/home/relayuser/bin/../bin/mirror-put"])
def test_mirror_put_at_another_path_refused(guard, program):
    r = guard("-c", shlex.join([program, "checkpoint"]))
    assert r.returncode == 1 and not (guard.fake / "put-argv").exists() and not (guard.fake / "sudo-argv").exists()


def test_put_argument_checks_in_transport():
    from aitools_alerts.poster import transport
    for kw in (dict(kind="manifest"), dict(wrapper="mirror-put"), dict(wrapper="/x/y z"), dict(host="-oProxy"),
               dict(data="text"), dict(data=b"")):
        args = dict(kind="checkpoint", data=b"{}", host="h.example.invalid", wrapper="/home/u/bin/mirror-put")
        args.update(kw)
        with pytest.raises(ValueError):
            transport.put(args["kind"], args["data"], lambda *a, **k: None, host=args["host"], wrapper=args["wrapper"])

    def refused(argv, **kw):
        return subprocess.CompletedProcess(argv, 1, b"", b'{"error":"user_error","message":"mirror-put: x"}\n')
    ok, detail = transport.put("checkpoint", b"{}", refused, host="h.example.invalid", wrapper="/home/u/bin/mirror-put")
    assert ok is False and detail.startswith("exit 1")

    def timeout(argv, **kw):
        raise subprocess.TimeoutExpired("ssh", 1)
    assert transport.put("checkpoint", b"{}", timeout, host="h.example.invalid", wrapper="/home/u/bin/mirror-put")[0] is False
