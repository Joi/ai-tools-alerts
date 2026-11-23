"""The suite never runs its git commands against a repository it did not make (ai-tools-alerts#4e1y).

On 2026-11-23 a pytest run started with GIT_DIR set made tests/test_public_scan.py run
git init, checkout, commit and update-ref -d against a shared clone: every branch, tag
and reflog there was deleted. Any git hook sets GIT_DIR too."""

import os
import subprocess
import sys
from pathlib import Path

import conftest

ROOT = Path(__file__).resolve().parent.parent


def _git(repo, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                           "-c", "commit.gpgsign=false", *args], capture_output=True, text=True, check=True, env=env)


def test_location_variables_are_gone_inside_a_test(monkeypatch):
    assert not [v for v in conftest.GIT_LOCATION_VARS if v in os.environ]
    assert {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"} <= set(conftest.GIT_LOCATION_VARS)


def test_a_run_started_with_git_dir_set_leaves_that_repository_alone(tmp_path):
    """A bait repository with a branch, a tag and a commit; the ref-deleting test of the
    public scan is run by an inner pytest whose environment points GIT_DIR at the bait."""
    bait = tmp_path / "bait"
    bait.mkdir()
    _git(bait, "init", "-q")
    (bait / "f.txt").write_text("x\n")
    _git(bait, "add", "f.txt")
    _git(bait, "commit", "-q", "-m", "bait")
    _git(bait, "branch", "keep")
    _git(bait, "tag", "v-bait")
    before = _git(bait, "for-each-ref").stdout, _git(bait, "rev-parse", "HEAD").stdout, (bait / ".git" / "HEAD").read_text()
    assert "refs/heads/keep" in before[0] and "refs/tags/v-bait" in before[0]
    env = {**os.environ, "GIT_DIR": str(bait / ".git"), "GIT_WORK_TREE": str(bait),
           "GIT_INDEX_FILE": str(bait / ".git" / "index")}
    inner = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_public_scan.py",
                            "-k", "detached_head_with_no_named_ref or history"], cwd=ROOT, env=env,
                           capture_output=True, text=True, timeout=300)
    assert inner.returncode == 0, inner.stdout[-2000:] + inner.stderr[-2000:]
    assert "passed" in inner.stdout
    after = _git(bait, "for-each-ref").stdout, _git(bait, "rev-parse", "HEAD").stdout, (bait / ".git" / "HEAD").read_text()
    assert after == before
    assert _git(bait, "status", "--porcelain").stdout == ""
