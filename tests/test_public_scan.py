"""scripts/public-scan.sh: terms from an untracked file; every tracked file, as bytes; errors are not clean."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TERM = "example-forbidden-term"  # fixture terms only: the real ones are never in the tree
TERMS = f"# fixture\n\n{TERM}\n\\bforbidden\\.example\\b\n"


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git not found")
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    for f in ("public-scan.sh", "test-gate.sh"):
        shutil.copy(ROOT / "scripts" / f, root / "scripts" / f)
    (root / "clean.txt").write_text("nothing here\n")
    (tmp_path / "terms").write_text(TERMS)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


def run(repo, *paths, cmd="scripts/public-scan.sh", terms=None, home=None):
    if paths:
        subprocess.run(["git", "add", "--", *paths], cwd=repo, check=True)
    subprocess.run(["git", "add", "scripts", "clean.txt"], cwd=repo, check=True)
    env = {k: v for k, v in os.environ.items() if k != "PUBLIC_SCAN_TERMS"}
    env["HOME"] = str(home or repo.parent / "nohome")
    if terms is not False:
        env["PUBLIC_SCAN_TERMS"] = str(terms or repo.parent / "terms")
    return subprocess.run(["sh", cmd], cwd=repo, capture_output=True, text=True, env=env)


def test_clean_tree_passes(repo):
    r = run(repo)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("name, data", [
    ("notes.md", f"see {TERM.upper()}\n".encode()),
    ("with space.md", f"x\n{TERM}\n".encode()),
    ("blob.bin", b"\x00\x01" + TERM.encode() + b"\x00"),
    (f"{TERM}.txt", b"no content hit\n"),
    ("domain.md", b"https://forbidden.example/x\n"),
])
def test_hit_fails(repo, name, data):
    (repo / name).write_bytes(data)
    r = run(repo, name)
    assert r.returncode == 1 and name in r.stdout


def test_word_boundary_term_is_not_a_substring_hit(repo):
    (repo / "code.py").write_text("host = notforbidden.examples\n")
    assert run(repo, "code.py").returncode == 0


def test_the_scanner_itself_is_scanned(repo):
    with open(repo / "scripts" / "public-scan.sh", "a") as fh:
        fh.write(f"# {TERM}\n")
    r = run(repo)
    assert r.returncode == 1 and "scripts/public-scan.sh" in r.stdout


def test_unreadable_tracked_file_is_an_error(repo):
    (repo / "gone.txt").write_text("x\n")
    subprocess.run(["git", "add", "gone.txt"], cwd=repo, check=True)
    (repo / "gone.txt").unlink()
    assert run(repo).returncode == 2


def test_gate_fails_on_a_hit(repo):
    (repo / "notes.md").write_text(f"{TERM}\n")
    r = run(repo, "notes.md", cmd="scripts/test-gate.sh")
    assert r.returncode == 1 and "notes.md" in r.stdout


@pytest.mark.parametrize("content", [None, "", "# only a comment\n\n   \n", "(unclosed\n", "a{99999999999999999999}\n"])
def test_missing_empty_or_bad_terms_file_cannot_run(repo, content):
    terms = repo.parent / "bad-terms"
    if content is not None:
        terms.write_text(content)
    r = run(repo, terms=terms)
    assert r.returncode == 2 and str(terms) in r.stderr and r.stdout == ""


def test_a_term_that_matches_nothing_lets_a_contributor_run_the_gate(repo):
    terms = repo.parent / "none"
    terms.write_text("(?!)\n")  # the README's example: it matches no text, this file included
    (repo / "notes.md").write_text(f"{TERM}\n")
    assert run(repo, "notes.md", terms=terms).returncode == 0


def test_default_terms_path_is_under_home(repo, tmp_path):
    home = tmp_path / "home"
    r = run(repo, terms=False, home=home)
    assert r.returncode == 2 and str(home / ".config/aitools-alerts/public-scan.terms") in r.stderr
    (home / ".config" / "aitools-alerts").mkdir(parents=True)
    (home / ".config" / "aitools-alerts" / "public-scan.terms").write_text(TERM + "\n")
    (repo / "notes.md").write_text(f"{TERM}\n")
    assert run(repo, "notes.md", terms=False, home=home).returncode == 1
