"""The suite never runs its git commands against a repository it did not make (ai-tools-alerts#4e1y).

Every child process here gets an environment built from nothing (PATH, a temp HOME, and
the contamination under test, which points only at bait directories this test made), so
these tests stay harmless when the cleanup they test is broken or removed."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import git_env

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"


def base_env(tmp_path) -> dict:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {"PATH": os.environ["PATH"], "HOME": str(home), "PYTHONPATH": os.pathsep.join((str(TESTS), str(ROOT))),
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def git(repo, *args, env):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                           "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                          capture_output=True, text=True, check=True, env=env, timeout=60)


@pytest.fixture
def bait(tmp_path):
    """A repository with a commit, a branch and a tag, and a function giving its state."""
    env = base_env(tmp_path)
    repo = tmp_path / "bait"
    repo.mkdir()
    git(repo, "init", "-q", env=env)
    (repo / "f.txt").write_text("x\n")
    git(repo, "add", "f.txt", env=env)
    git(repo, "commit", "-q", "-m", "bait", env=env)
    git(repo, "branch", "keep", env=env)
    git(repo, "tag", "v-bait", env=env)

    def state():
        return (git(repo, "for-each-ref", env=env).stdout, git(repo, "rev-parse", "HEAD", env=env).stdout,
                (repo / ".git" / "HEAD").read_text(), git(repo, "status", "--porcelain", env=env).stdout,
                sorted(p.name for p in repo.iterdir()))
    assert "refs/heads/keep" in state()[0] and "refs/tags/v-bait" in state()[0]
    return repo, state, env


CONTAMINATIONS = {
    "location variables": lambda b: {"GIT_DIR": str(b / ".git"), "GIT_WORK_TREE": str(b),
                                     "GIT_INDEX_FILE": str(b / ".git" / "index")},
    "common dir": lambda b: {"GIT_DIR": str(b / ".git"), "GIT_COMMON_DIR": str(b / ".git")},
    "config count: core.worktree": lambda b: {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.worktree",
                                              "GIT_CONFIG_VALUE_0": str(b)},
    "config parameters: core.worktree": lambda b: {"GIT_CONFIG_PARAMETERS": f"'core.worktree={b}'"},
}


@pytest.mark.parametrize("how", sorted(CONTAMINATIONS))
def test_a_run_started_with_git_redirected_leaves_that_repository_alone(bait, tmp_path, how):
    """The public scan's git tests (one deletes every ref it can see) run in an inner
    pytest whose environment redirects git to the bait."""
    repo, state, env = bait
    before = state()
    inner = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_public_scan.py",
                            "-k", "detached_head_with_no_named_ref or tag_names_directly"],
                           cwd=ROOT, env={**env, **CONTAMINATIONS[how](repo)}, capture_output=True, text=True, timeout=300)
    assert inner.returncode == 0 and "passed" in inner.stdout, inner.stdout[-1500:] + inner.stderr[-1500:]
    assert state() == before


def test_import_alone_clears_the_environment(tmp_path):
    """The first boundary: importing the suite's conftest, before any fixture exists."""
    code = ("import os, sys\n"
            "os.environ.update(GIT_DIR='/nonexistent/x', GIT_WORK_TREE='/nonexistent', GIT_CONFIG_COUNT='1',\n"
            "                  GIT_CONFIG_KEY_0='core.worktree', GIT_CONFIG_VALUE_0='/nonexistent',\n"
            "                  GIT_CONFIG_PARAMETERS=\"'a.b=c'\", GIT_TEMPLATE_DIR='/nonexistent', GIT_CONFIG_GLOBAL='/nonexistent/g')\n"
            "import conftest\n"
            "left = sorted(k for k in os.environ if k.startswith('GIT_'))\n"
            "print(left, os.environ['GIT_CONFIG_GLOBAL'])\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=TESTS, env=base_env(tmp_path), capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr[-1500:]
    assert r.stdout.strip() == f"{sorted(git_env.ISOLATION)} {os.devnull}"


def test_each_test_starts_clean_whatever_the_one_before_left(tmp_path):
    """The second boundary, without the first: an inner run whose first test leaks GIT_DIR
    into os.environ after import; the autouse fixture must clear it before the second."""
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "conftest.py").write_text("from git_env import git_env_is_ours  # noqa: F401\n")
    (inner / "test_leak.py").write_text(
        "import os\n\n"
        "def test_a_leaks():\n"
        "    os.environ['GIT_DIR'] = '/nonexistent/leaked'\n"
        "    os.environ['GIT_CONFIG_COUNT'] = '1'\n\n"
        "def test_b_starts_clean():\n"
        "    assert 'GIT_DIR' not in os.environ and 'GIT_CONFIG_COUNT' not in os.environ\n"
        "    assert os.environ['GIT_CONFIG_NOSYSTEM'] == '1'\n")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(inner), str(inner)],
                       cwd=inner, env=base_env(tmp_path), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "2 passed" in r.stdout, r.stdout[-1500:] + r.stderr[-1500:]


def test_scrub_removes_every_git_variable_and_sets_the_isolation():
    env = {"GIT_DIR": "x", "GIT_ANYTHING_NEW": "y", "GIT_CONFIG_GLOBAL": "/etc/other", "PATH": "/bin", "GITHUB_TOKEN": "t"}
    assert sorted(git_env.scrub(env)) == ["GIT_ANYTHING_NEW", "GIT_CONFIG_GLOBAL", "GIT_DIR"]
    assert env == {"PATH": "/bin", "GITHUB_TOKEN": "t", **git_env.ISOLATION}  # not a GIT_ variable: left alone
    assert not [k for k in os.environ if k.startswith("GIT_") and k not in git_env.ISOLATION]
