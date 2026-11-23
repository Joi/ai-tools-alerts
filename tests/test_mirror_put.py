"""ops/vm/mirror-put: stores one JSON event for the exporter to verify; verifies nothing itself."""

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from aitools_alerts import nostr

ROOT = Path(__file__).resolve().parent.parent
PUT = ROOT / "ops" / "vm" / "mirror-put"
BASH = shutil.which("bash")


def event(**over) -> bytes:
    sec, _ = nostr.keygen()
    ev = nostr.sign_event(sec, {"created_at": 1, "kind": 30078, "tags": [["d", "aitools-alerts-checkpoint"]],
                                "content": "{}"})
    ev.update(over)
    return json.dumps(ev, ensure_ascii=False).encode()


@pytest.fixture
def put(tmp_path):
    home = tmp_path / "home"
    home.mkdir()

    def run(*args, stdin=b""):
        return subprocess.run([BASH, str(PUT), *args], input=stdin, capture_output=True, timeout=30,
                              env={"HOME": str(home), "PATH": os.environ["PATH"]}, cwd=tmp_path)
    run.inbox = home / "alerts-inbox"
    run.file = run.inbox / "checkpoint.json"
    return run


def refused(r, why):
    assert r.returncode == 1 and r.stdout == b""
    (line,) = r.stderr.decode().splitlines()
    err = json.loads(line)
    assert err["error"] == "user_error" and err["message"].startswith("mirror-put: ") and why in err["message"]


def test_script_is_executable_and_names_no_deployment():
    assert os.access(PUT, os.X_OK)
    text = PUT.read_text()
    assert text.startswith("#!/usr/bin/env bash") and "set +x" in text and "umask 077" in text


def test_stores_a_checkpoint_atomically_with_private_modes(put):
    doc = event(content=json.dumps({"note": "日本語 \U0001F512"}, ensure_ascii=False))
    r = put("checkpoint", stdin=doc)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"stored": True, "bytes": len(doc)}
    assert put.file.read_bytes() == doc
    assert stat.S_IMODE(put.file.stat().st_mode) == 0o600 and stat.S_IMODE(put.inbox.stat().st_mode) == 0o700
    assert [p.name for p in put.inbox.iterdir()] == ["checkpoint.json"]  # no temporary file left
    newer = event()
    assert put("checkpoint", stdin=newer).returncode == 0 and put.file.read_bytes() == newer


@pytest.mark.parametrize("args, why", [((), "usage"), (("checkpoint", "x"), "usage"), (("manifest",), "refused kind"),
                                       (("Checkpoint",), "refused kind"), (("--help",), "refused kind")])
def test_only_the_one_command(put, args, why):
    refused(put(*args, stdin=event()), why)
    assert not put.inbox.exists() or list(put.inbox.iterdir()) == []


@pytest.mark.parametrize("doc, why", [
    (b"", "empty"), (b"not json", "not one JSON event"), (b"[]", "not one JSON event"), (b'"x"', "not one JSON event"),
    (b"{}", "not one JSON event"), (b"\xff\xfe", "not one JSON event"),
    (json.dumps({"id": 1, "pubkey": 1, "created_at": 1, "kind": 1, "tags": 1, "content": 1}).encode(), "not one JSON event"),
    (json.dumps({"id": 1, "pubkey": 1, "created_at": 1, "kind": 1, "tags": 1, "content": 1, "sig": 1, "x": 1}).encode(),
     "not one JSON event"),
    (b'{"id":1,"id":2,"pubkey":1,"created_at":1,"kind":1,"tags":1,"content":1,"sig":1}', "not one JSON event"),
    (b"{" + b" " * 262144 + b"}", "larger than"),
])
def test_refusals_leave_the_previous_file(put, doc, why):
    good = event()
    assert put("checkpoint", stdin=good).returncode == 0
    refused(put("checkpoint", stdin=doc), why)
    assert put.file.read_bytes() == good and [p.name for p in put.inbox.iterdir()] == ["checkpoint.json"]


def test_the_largest_allowed_document_is_stored(put):
    pad = 262144 - len(event(content=""))
    doc = event(content="x" * pad)
    assert len(doc) == 262144
    assert put("checkpoint", stdin=doc).returncode == 0 and put.file.stat().st_size == 262144


def test_an_inbox_that_is_a_symlink_is_refused(put, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    put.inbox.symlink_to(elsewhere)
    refused(put("checkpoint", stdin=event()), "not a directory")
    assert list(elsewhere.iterdir()) == []


def test_a_directory_where_the_file_goes_is_refused(put):
    """mv would move the temporary file INTO the directory and report success."""
    put.inbox.mkdir(mode=0o700)
    put.file.mkdir()
    (put.file / "kept").write_text("x")
    refused(put("checkpoint", stdin=event()), "is a directory")
    assert [p.name for p in put.file.iterdir()] == ["kept"]
    assert [p.name for p in put.inbox.iterdir()] == ["checkpoint.json"]  # no temporary file left
