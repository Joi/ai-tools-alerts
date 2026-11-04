"""ops/vm/buzz-send: the key reaches the Buzz CLI only through its environment.

Every key here is generated per test; no real key is ever read.
"""

import json
import os
import secrets
import stat
import subprocess
from pathlib import Path

import pytest

from aitools_alerts import nostr

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "ops" / "vm" / "buzz-send"
RELAY = "https://buzz.ai-tools.md"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TOKEN = "DISTINCTIVE-TOKEN-7f3a"

STUB = r"""#!/usr/bin/env bash
d="$(dirname "$0")"
printf '%s\0' "$@" > "$d/argv"
printf '%s' "${BUZZ_PRIVATE_KEY-}" > "$d/key"
printf '%s' "${BUZZ_RELAY_URL-}" > "$d/relay"
printf '%s' "${BUZZ_AUTH_TAG-UNSET}" > "$d/authtag"
cat > "$d/stdin"
exit "${STUB_EXIT:-0}"
"""


def _sec_hex() -> str:
    while True:
        h = secrets.token_hex(32)
        if 1 <= int(h, 16) < N:
            return h


def _bech32_with_payload(payload: bytes, hrp: str = "nsec") -> str:
    return nostr._bech32_encode(hrp, payload)


@pytest.fixture
def env(tmp_path):
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    stub = stub_dir / "buzz"
    stub.write_text(STUB)
    stub.chmod(0o700)
    sec = _sec_hex()
    key = nostr.nsec(sec)
    key_file = tmp_path / "agent.nsec"
    key_file.write_text(key + "\n")
    key_file.chmod(0o600)

    class Env:
        pass

    e = Env()
    e.dir = stub_dir
    e.key = key
    e.key_file = key_file
    e.base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "BUZZ_SEND_BUZZ": str(stub),
        "BUZZ_SEND_KEY_FILE": str(key_file),
    }
    return e


def run(e, args, extra_env=None, stdin=b""):
    environ = dict(e.base)
    if extra_env:
        environ.update(extra_env)
    return subprocess.run(
        ["bash", str(WRAPPER), *args],
        input=stdin,
        env=environ,
        capture_output=True,
        timeout=10,
    )


def argv_of(e):
    raw = (e.dir / "argv").read_bytes().decode()
    parts = raw.split("\0")
    assert parts[-1] == ""
    return parts[:-1]


SEND = ["messages", "send", "--channel", "X", "--content", "-"]


def test_key_reaches_child_only_in_env(env):
    r = run(env, SEND)
    assert r.returncode == 0, r.stderr
    argv = argv_of(env)
    assert argv == SEND
    assert (env.dir / "key").read_text() == env.key
    assert all(env.key not in a for a in argv)
    assert env.key.encode() not in r.stdout + r.stderr


def test_relay_pinned_and_auth_tag_cleared(env):
    r = run(env, SEND, {"BUZZ_RELAY_URL": "http://evil.example", "BUZZ_AUTH_TAG": "{}"})
    assert r.returncode == 0, r.stderr
    assert (env.dir / "relay").read_text() == RELAY
    assert (env.dir / "authtag").read_text() == "UNSET"


def test_caller_key_env_overridden(env):
    other = nostr.nsec(_sec_hex())
    r = run(env, SEND, {"BUZZ_PRIVATE_KEY": other})
    assert r.returncode == 0, r.stderr
    assert (env.dir / "key").read_text() == env.key


def test_stdin_and_exit_pass_through(env):
    r = run(env, SEND, {"STUB_EXIT": "5"}, stdin=b"hello\n\x00tail")
    assert r.returncode == 5
    assert (env.dir / "stdin").read_bytes() == b"hello\n\x00tail"


@pytest.mark.parametrize(
    "flag",
    [["--private-key", "x"], ["--private-key=x"], ["--relay", "x"], ["--relay=x"]],
)
def test_refuses_private_key_and_relay_flags(env, flag):
    r = run(env, [*SEND, *flag])
    assert r.returncode == 1
    assert not (env.dir / "argv").exists()
    err = json.loads(r.stderr.decode().strip())
    assert err["error"] == "user_error"


def _bad_cases():
    good = nostr.nsec(_sec_hex())
    last = good[-1]
    swapped = "q" if last != "q" else "p"
    return {
        "shape": f"not-a-key {TOKEN}\n",
        "bad_checksum": good[:-1] + swapped + "\n",
        "zero_scalar_nsec": _bech32_with_payload(bytes(32)) + "\n",
        "order_scalar_nsec": _bech32_with_payload(N.to_bytes(32, "big")) + "\n",
        "zero_scalar_hex": "0" * 64 + "\n",
        "order_scalar_hex": f"{N:064x}\n",
        "npub": nostr.npub(nostr.pubkey_gen(bytes.fromhex(_sec_hex())).hex()) + "\n",
        "short_payload": _bech32_with_payload(bytes(31) + b"") + "\n",
        "uppercase_hex": _sec_hex().upper() + "\n",
    }


def _assert_fail_closed(e, r, secret_text=""):
    assert r.returncode == 1, (r.returncode, r.stderr)
    assert not (e.dir / "argv").exists()
    lines = r.stderr.decode().strip().splitlines()
    assert len(lines) == 1, lines
    assert json.loads(lines[0])["error"] == "user_error"
    out = (r.stdout + r.stderr).decode()
    assert TOKEN not in out
    stripped = secret_text.strip()
    if stripped:
        assert stripped not in out


@pytest.mark.parametrize("case", sorted(_bad_cases()))
def test_bad_key_content_fails_closed(env, case):
    text = _bad_cases()[case]
    env.key_file.write_text(text)
    r = run(env, SEND)
    _assert_fail_closed(env, r, text)


def test_missing_key_file_fails_closed(env):
    env.key_file.unlink()
    _assert_fail_closed(env, run(env, SEND))


def test_empty_key_file_fails_closed(env):
    env.key_file.write_text("")
    _assert_fail_closed(env, run(env, SEND))


def test_directory_key_path_fails_closed(env, tmp_path):
    d = tmp_path / "keydir"
    d.mkdir()
    _assert_fail_closed(env, run(env, SEND, {"BUZZ_SEND_KEY_FILE": str(d)}))


def test_fifo_key_path_fails_closed_without_blocking(env, tmp_path):
    f = tmp_path / "keyfifo"
    os.mkfifo(f)
    assert stat.S_ISFIFO(f.stat().st_mode)
    _assert_fail_closed(env, run(env, SEND, {"BUZZ_SEND_KEY_FILE": str(f)}))


def test_hex_key_accepted(env):
    h = _sec_hex()
    env.key_file.write_text(h + "\n")
    r = run(env, SEND)
    assert r.returncode == 0, r.stderr
    assert (env.dir / "key").read_text() == h


def _nostr_accepts(text: str) -> bool:
    k = text.strip()
    try:
        if k.startswith("nsec1"):
            h = nostr.nsec_to_hex(k)
        else:
            if len(k) != 64 or any(c not in "0123456789abcdef" for c in k):
                return False
            h = k
        return 1 <= int(h, 16) < N
    except Exception:
        return False


def test_validator_agrees_with_nostr(env):
    cases = [nostr.nsec(_sec_hex()) + "\n" for _ in range(20)]
    cases += list(_bad_cases().values())
    for text in cases:
        env.key_file.write_text(text)
        for f in ("argv", "key"):
            p = env.dir / f
            if p.exists():
                p.unlink()
        r = run(env, SEND)
        assert (r.returncode == 0) == _nostr_accepts(text), text
