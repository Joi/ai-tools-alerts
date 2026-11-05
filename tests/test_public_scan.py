"""scripts/public-scan.sh: every tracked file, as bytes; errors are not clean."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NAME = "mac" + "azbd"  # built here, so this file never spells a fleet name


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git not found")
    (tmp_path / "scripts").mkdir()
    for f in ("public-scan.sh", "test-gate.sh"):
        shutil.copy(ROOT / "scripts" / f, tmp_path / "scripts" / f)
    (tmp_path / "clean.txt").write_text("nothing here\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return tmp_path


def scan(repo, *paths):
    if paths:
        subprocess.run(["git", "add", "--", *paths], cwd=repo, check=True)
    subprocess.run(["git", "add", "scripts", "clean.txt"], cwd=repo, check=True)
    return subprocess.run(["sh", "scripts/public-scan.sh"], cwd=repo, capture_output=True, text=True)


def test_clean_tree_passes(repo):
    assert scan(repo).returncode == 0


@pytest.mark.parametrize("name, data", [
    ("notes.md", f"runs on {NAME.upper()}\n".encode()),
    ("with space.md", f"x\n{NAME}\n".encode()),
    ("blob.bin", b"\x00\x01" + NAME.encode() + b"\x00"),
    (f"{NAME}.txt", b"no content hit\n"),
])
def test_hit_fails(repo, name, data):
    (repo / name).write_bytes(data)
    r = scan(repo, name)
    assert r.returncode == 1 and name in r.stdout


def test_unreadable_tracked_file_is_an_error(repo):
    (repo / "gone.txt").write_text("x\n")
    subprocess.run(["git", "add", "gone.txt"], cwd=repo, check=True)
    (repo / "gone.txt").unlink()
    assert scan(repo).returncode == 2


def test_gate_fails_on_a_hit(repo):
    (repo / "notes.md").write_text(f"{NAME}\n")
    scan(repo, "notes.md")
    r = subprocess.run(["sh", "scripts/test-gate.sh"], cwd=repo, capture_output=True, text=True)
    assert r.returncode == 1 and "notes.md" in r.stdout
