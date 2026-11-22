"""ops/vm/scan-for-poster-keys.py: finds a manifest poster's secret key in files and
nested archives by its derived public key, and prints no key (ai-tools-alerts#vzc3)."""

import bz2
import gzip
import importlib.util
import io
import lzma
import zipfile
import json
import os
import tarfile
from pathlib import Path

import pytest

from aitools_alerts import nostr

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scan", REPO / "ops" / "vm" / "scan-for-poster-keys.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

POSTER_SEC, POSTER_PUB = nostr.keygen()
OTHER_SEC, _ = nostr.keygen()


@pytest.fixture
def manifest(tmp_path):
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps({"content": json.dumps({"posters": [
        {"name": "bot", "pubkey": POSTER_PUB, "role": "relay-bot"}]})}))
    return p


def tar_bytes(files: dict, gz=False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def run(manifest, root, capsys):
    code = scan.main(["--manifest", str(manifest), str(root)])
    out = capsys.readouterr()
    assert POSTER_SEC not in out.out + out.err and nostr.nsec(POSTER_SEC) not in out.out + out.err
    return code, out.out


@pytest.mark.parametrize("plant", [
    lambda d: (d / "agent.sec.hex").write_text(POSTER_SEC + "\n"),
    lambda d: (d / "renamed.txt").write_text("x=" + nostr.nsec(POSTER_SEC) + "\n"),
    lambda d: (d / "UPPER").write_text(POSTER_SEC.upper()),
    lambda d: (d / "b.tar").write_bytes(tar_bytes({"home/.buzz-keys/agent.nsec": nostr.nsec(POSTER_SEC).encode()})),
    lambda d: (d / "b.tar.gz").write_bytes(tar_bytes({"MANIFEST.txt": b"x", "scaffolding.tar.gz": tar_bytes(
        {"home/.buzz-keys/agent.sec.hex": POSTER_SEC.encode()}, gz=True)}, gz=True)),
    lambda d: (d / "k.gz").write_bytes(gzip.compress(POSTER_SEC.encode())),
    lambda d: (d / "UPPER.nsec").write_text(nostr.nsec(POSTER_SEC).upper()),
    lambda d: (d / "k.xz").write_bytes(lzma.compress(nostr.nsec(POSTER_SEC).encode())),
    lambda d: (d / "k.bz2").write_bytes(bz2.compress(POSTER_SEC.encode())),
    lambda d: (d / "k.zip").write_bytes(zip_bytes({"keys/agent.sec.hex": POSTER_SEC.encode()})),
])
def test_a_planted_poster_key_fails(tmp_path, manifest, capsys, plant):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    plant(root / "sub")
    code, out = run(manifest, root, capsys)
    assert code == 1 and "POSTER KEY: " in out and "poster_keys=0" not in out  # an archive and its member both count


def test_other_keys_and_hex_pass(tmp_path, manifest, capsys):
    root = tmp_path / "root"
    root.mkdir()
    (root / "other.nsec").write_text(nostr.nsec(OTHER_SEC))
    (root / "ids.txt").write_text(POSTER_PUB + " " + "ab" * 32 + " " + "00" * 32 + " " + "f" * 128)
    (root / "a.tar.gz").write_bytes(tar_bytes({"x": OTHER_SEC.encode()}, gz=True))
    code, out = run(manifest, root, capsys)
    assert code == 0 and "poster_keys=0" in out and "unread=0" in out


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_an_unreadable_file_fails(tmp_path, manifest, capsys):
    root = tmp_path / "root"
    root.mkdir()
    f = root / "locked"
    f.write_text("x")
    f.chmod(0)
    try:
        code, out = run(manifest, root, capsys)
    finally:
        f.chmod(0o600)
    assert code == 1 and "UNREAD: " in out


def test_a_corrupt_archive_fails(tmp_path, manifest, capsys):
    root = tmp_path / "root"
    root.mkdir()
    (root / "bad.gz").write_bytes(b"\x1f\x8b" + b"junk" * 10)
    code, out = run(manifest, root, capsys)
    assert code == 1 and "UNREAD: " in out


def test_a_missing_root_fails_and_a_bad_manifest_is_2(tmp_path, manifest, capsys):
    assert run(manifest, tmp_path / "nope", capsys)[0] == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert scan.main(["--manifest", str(bad), str(tmp_path)]) == 2


def test_symlinks_are_not_followed(tmp_path, manifest, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "k").write_text(POSTER_SEC)
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)
    (root / "flink").symlink_to(outside / "k")
    assert run(manifest, root, capsys)[0] == 0


def test_the_repo_manifest_loads():
    keys = scan.poster_pubkeys(REPO / "trust" / "manifest.json")
    assert len(keys) == 2


def test_an_archive_past_the_depth_limit_fails_closed(tmp_path, manifest, capsys, monkeypatch):
    monkeypatch.setattr(scan, "MAX_DEPTH", 2)
    root = tmp_path / "root"
    root.mkdir()
    inner = gzip.compress(gzip.compress(gzip.compress(b"nothing here")))
    (root / "deep.gz").write_bytes(inner)
    code, out = run(manifest, root, capsys)
    assert code == 1 and "nested deeper" in out


@pytest.mark.parametrize("big", ["file", "unpacked"])
def test_anything_past_the_size_limit_fails_closed(tmp_path, manifest, capsys, monkeypatch, big):
    root = tmp_path / "root"
    root.mkdir()
    if big == "file":
        (root / "f").write_bytes(b"x" * 200)
    else:
        (root / "z.gz").write_bytes(gzip.compress(b"x" * 200))  # small packed, large unpacked
    monkeypatch.setattr(scan, "MAX_BLOB", 150)
    code, out = run(manifest, root, capsys)
    assert code == 1 and "UNREAD: " in out


def test_a_tar_member_past_the_size_limit_fails_closed(monkeypatch):
    blob = tar_bytes({"m": b"x" * 200})
    monkeypatch.setattr(scan, "MAX_BLOB", 199)
    s = scan.Scan({POSTER_PUB})
    s.data("t.tar", blob, 0)  # the member alone is over the limit
    assert any("!m (too large)" in u for u in s.unread)


def test_a_format_it_cannot_open_fails_closed(tmp_path, manifest, capsys):
    root = tmp_path / "root"
    root.mkdir()
    (root / "b.tar.zst").write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 40)
    code, out = run(manifest, root, capsys)
    assert code == 1 and "zstd: cannot open" in out


def test_member_names_print_without_control_bytes(tmp_path, manifest, capsys):
    root = tmp_path / "root"
    root.mkdir()
    (root / "t.tar").write_bytes(tar_bytes({"evil\x1b[2Jname": POSTER_SEC.encode()}))
    code, out = run(manifest, root, capsys)
    assert code == 1 and "\x1b" not in out and "evil?[2Jname" in out
