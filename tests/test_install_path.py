"""The install path: a signed tag and its commit, checked before any install (C1)."""

import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mirror"))
import export_mirror as em  # noqa: E402

README = (ROOT / "README.md").read_text()
OPS = (ROOT / "ops" / "vm" / "README.md").read_text()


def section(text, heading):
    start = text.index(heading + "\n")
    nxt = re.search(r"^#{1,3} ", text[start + len(heading):], re.M)
    return text[start:start + len(heading) + (nxt.start() if nxt else len(text))]


def test_pin_constants():
    assert re.fullmatch(r"v\d+\.\d+\.\d+", em.RELEASE_TAG)
    assert re.fullmatch(r"[0-9a-f]{40}", em.RELEASE_COMMIT)
    assert em.PIPX_LINE == f"pipx install git+{em.REPO_URL}@{em.RELEASE_COMMIT}"


def test_pin_matches_the_tag_when_the_checkout_has_it():
    if shutil.which("git") is None:
        pytest.skip("git not found")
    r = subprocess.run(["git", "rev-parse", "--verify", "-q", f"refs/tags/{em.RELEASE_TAG}^{{commit}}"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"{em.RELEASE_TAG} not in this checkout")
    assert r.stdout.strip() == em.RELEASE_COMMIT


def test_readme_names_the_pin_and_no_unpinned_install():
    assert em.RELEASE_TAG in README and em.RELEASE_COMMIT in README and em.PIPX_LINE in README
    assert not re.search(r"ai-tools-alerts@(?![0-9a-f]{40}\b)", README), "install by branch or tag name"
    assert "v0.1.0" not in README
    for line in README.splitlines():
        if "pipx install git+" in line:
            assert em.RELEASE_COMMIT in line


def test_checks_come_before_any_install():
    first_check = README.index("tag -v")
    assert README.index("rev-parse") > first_check
    for word in ("pipx install", "pip install"):
        assert README.index(word) > README.index(f"git rev-parse '{em.RELEASE_TAG}^{{commit}}'"), word


def test_quick_install_names_tag_commit_and_stop():
    quick = section(README, "## Quick install")
    for want in (em.RELEASE_TAG, em.RELEASE_COMMIT, "tag -v", "rev-parse", "stop", "install nothing",
                 em.RELEASE_SIGNER_FP, '"Install" section'):
        assert want in quick, want


def test_install_section_is_release_agnostic():
    # A release tree's README pins the release before it; following Install must not switch to it.
    install = section(README, "### Install")
    assert "git checkout" not in install and "@v" not in install
    assert not re.search(r"\b[0-9a-f]{40}\b", install)
    assert "pipx install --force ." in install


def test_ops_vm_readme_installs_only_from_the_verified_export():
    assert "origin/main" not in OPS
    files = section(OPS, "## Release files")
    for want in (f"tag -v {em.RELEASE_TAG}", f"rev-parse '{em.RELEASE_TAG}^{{commit}}'", em.RELEASE_COMMIT,
                 f"archive {em.RELEASE_COMMIT}"):
        assert want in files, want
    assert 'scp "$rel/ops/vm/buzz-send"' in OPS and 'shasum -a 256 "$rel/ops/vm/buzz-send"' in OPS
    assert "scp ops/vm/" not in OPS and 'install-mirror.sh "$rel"' in OPS
    for f in ("aitools-poster-shell", "sudoers-aitools-poster", "sshd-match-aitools-poster.conf"):
        assert f"$rel/ops/vm/{f}" in OPS, f


def test_build_backend_is_pinned_exactly():
    req = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]["requires"]
    assert len(req) == 1 and re.fullmatch(r"setuptools==\d+\.\d+\.\d+", req[0])


def test_security_policy_and_codeowners():
    sec = (ROOT / "SECURITY.md").read_text()
    assert "https://github.com/Joi/ai-tools-alerts/security/advisories/new" in sec
    owners = {l.split()[0] for l in (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
              if l.strip() and not l.startswith("#")}
    for path in ("/trust/", "/spec/", "/ops/", "/hooks/", "/skills/", "/snippets/", "/README.md", "/pyproject.toml"):
        assert path in owners, path
