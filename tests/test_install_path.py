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
    assert not re.search(r"ai-tools-alerts(?:\.git)?@(?![0-9a-f]{40}\b)", README), "install by branch or tag name"
    assert "v0.1.0" not in README
    for line in README.splitlines():
        if re.search(r"pip[x]? install .*git\+", line):
            assert em.RELEASE_COMMIT in line


def test_checks_come_before_any_install():
    first_check = README.index("tag -v")
    assert README.index("rev-parse") > first_check
    for word in ("pipx install", "pip install"):
        assert README.index(word) > README.index(f"git rev-parse '{em.RELEASE_TAG}^{{commit}}'"), word


def test_quick_install_names_tag_commit_and_stop():
    quick = section(README, "## Quick install")
    for want in (em.RELEASE_TAG, em.RELEASE_COMMIT, "tag -v", "rev-parse", "stop", "install nothing",
                 em.RELEASE_SIGNER_FP, "--sort=-v:refname", f"git checkout --detach {em.RELEASE_COMMIT}",
                 "pipx install --force .", "never clone again", "never check out or install any other"):
        assert want in quick, want
    # The install happens in the prompt itself: the pinned tree's README may be an older layout.
    assert quick.index("rev-parse") < quick.index("pipx install --force .")


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
                 f"archive -o \"$d/release.tar\" {em.RELEASE_COMMIT}"):
        assert want in files, want
    assert "scp ops/vm/" not in OPS and 'install-mirror.sh "${rel:?}"' in OPS
    # vzc3 retired posting through the VM: buzz-send is never installed. The route left is
    # put-only (nfm3), and every file of it comes from the verified export.
    assert "ops/vm/buzz-send" not in OPS.replace("history before vzc3 (`ops/vm/buzz-send`)", "")
    for f in ("aitools-poster-shell", "sudoers-aitools-poster", "sshd-match-aitools-poster.conf", "mirror-put"):
        assert f"${{rel:?}}/ops/vm/{f}" in OPS, f
    assert not re.search(r'"\$rel[/"]', OPS), "an install step that runs on with $rel unset"


def release_block():
    files = section(OPS, "## Release files")
    return files.split("```bash\n", 1)[1].split("```", 1)[0]


@pytest.mark.parametrize("case", ["unsigned", "other-commit"])
def test_ops_vm_release_block_sets_nothing_when_a_check_fails(tmp_path, case):
    for tool in ("git", "ssh-keygen", "bash"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not found")
    repo = tmp_path / "checkout"
    (repo / "trust").mkdir(parents=True)
    (repo / "mirror").mkdir(parents=True)
    (repo / "mirror" / "export_mirror.py").write_text("x\n")
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    pub = key.with_suffix(".pub").read_text().split()
    (repo / "trust" / "allowed_signers").write_text(f"t@example.invalid {pub[0]} {pub[1]}\n")
    g = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "gpg.format=ssh", "-c", f"user.signingkey={key}"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(g + ["add", "."], check=True)
    subprocess.run(g + ["commit", "-q", "-m", "c"], check=True)
    sign = ["-a"] if case == "unsigned" else ["-s"]
    subprocess.run(g + ["-c", "tag.gpgsign=false", "tag", *sign, em.RELEASE_TAG, "-m", "t"], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", str(repo)], check=True)
    script = release_block().replace("<ai-tools-alerts checkout>", str(repo)) + '\nprintf "rel=%s\\n" "${rel:-}"\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, cwd=tmp_path)
    assert "rel=\n" in r.stdout and "VERIFICATION FAILED" in r.stdout, r.stdout + r.stderr
    if case == "other-commit":
        assert 'Good "git" signature' in r.stderr  # the signature passed; the commit check stopped it


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


def test_the_checkpoint_route_is_installed_only_from_a_release_that_has_it():
    """v0.1.5 has the send guard and no mirror-put (vzc3, after nfm3); the pinned
    release carries the put-only route. The route's section makes the operator
    check the export before installing it."""
    route = section(OPS, "## The poster's ssh route: the checkpoint only")
    for want in ('test -f "${rel:?}/ops/vm/mirror-put"', "! grep -q 'bin/buzz-send' \"${rel:?}/ops/vm/aitools-poster-shell\"",
                 "WRONG RELEASE: install nothing", "predates this route"):
        assert want in route, want
    guard = (ROOT / "ops" / "vm" / "aitools-poster-shell").read_text()
    assert "bin/buzz-send" not in guard and "buzz-send" not in (ROOT / "ops" / "vm" / "sudoers-aitools-poster").read_text()
    if shutil.which("git") and subprocess.run(["git", "cat-file", "-e", f"{em.RELEASE_COMMIT}:ops/vm/aitools-poster-shell"],
                                              cwd=ROOT, capture_output=True).returncode == 0:
        old = subprocess.run(["git", "show", f"{em.RELEASE_COMMIT}:ops/vm/aitools-poster-shell"],
                             cwd=ROOT, capture_output=True, text=True).stdout
        assert "bin/buzz-send" not in old  # the pin passes the check above
        assert subprocess.run(["git", "cat-file", "-e", f"{em.RELEASE_COMMIT}:ops/vm/mirror-put"],
                              cwd=ROOT, capture_output=True).returncode == 0
    if shutil.which("git") and subprocess.run(["git", "cat-file", "-e", "v0.1.5^{commit}"],
                                              cwd=ROOT, capture_output=True).returncode == 0:
        prev = subprocess.run(["git", "show", "v0.1.5:ops/vm/aitools-poster-shell"],
                              cwd=ROOT, capture_output=True, text=True).stdout
        assert "bin/buzz-send" in prev  # the check above stops an install from v0.1.5
