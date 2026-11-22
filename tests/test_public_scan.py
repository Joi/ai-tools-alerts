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


@pytest.mark.parametrize("content", [None, "", "# only a comment\n\n   \n", "(unclosed\n", "a{99999999999999999999}\n", "(\n)\n", "x(?i)y\n"])
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


def test_bom_and_crlf_terms_file_keeps_its_first_term(repo):
    terms = repo.parent / "bom"
    terms.write_bytes(b"\xef\xbb\xbf" + TERM.encode() + b"\r\n# note\r\n")
    (repo / "notes.md").write_text(f"{TERM}\n")
    assert run(repo, "notes.md", terms=terms).returncode == 1


def test_default_terms_path_is_under_home(repo, tmp_path):
    home = tmp_path / "home"
    r = run(repo, terms=False, home=home)
    assert r.returncode == 2 and str(home / ".config/aitools-alerts/public-scan.terms") in r.stderr
    (home / ".config" / "aitools-alerts").mkdir(parents=True)
    (home / ".config" / "aitools-alerts" / "public-scan.terms").write_text(TERM + "\n")
    (repo / "notes.md").write_text(f"{TERM}\n")
    assert run(repo, "notes.md", terms=False, home=home).returncode == 1


# History pass: every object reachable from every ref.

def commit(repo, *paths, msg="c", name="t", tag=None):
    git = ["git", "-c", f"user.name={name}", "-c", "user.email=t@example.invalid",
           "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
    subprocess.run(["git", "add", "-A", "--", *paths], cwd=repo, check=True)
    subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", msg], cwd=repo, check=True)
    if tag:
        subprocess.run(git + ["tag", "-a", "t1", "-m", tag], cwd=repo, check=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True,
                          check=True).stdout.strip()


def oid(repo, spec):
    return subprocess.run(["git", "rev-parse", spec], cwd=repo, capture_output=True, text=True,
                          check=True).stdout.strip()


def test_a_hit_removed_at_the_tip_still_fails_from_history(repo):
    (repo / "notes.md").write_text(f"{TERM}\n")
    commit(repo, ".")
    blob = oid(repo, "HEAD:notes.md")
    (repo / "notes.md").write_text("clean now\n")
    commit(repo, ".")
    r = run(repo)
    assert r.returncode == 1 and blob in r.stdout and "notes.md:1" in r.stdout


@pytest.mark.parametrize("where", ["message", "author", "tag"])
def test_a_hit_in_a_commit_or_tag_object_fails(repo, where):
    c = commit(repo, ".", msg=f"see {TERM}" if where == "message" else "c",
               name=TERM if where == "author" else "t",
               tag=f"tag says {TERM}" if where == "tag" else None)
    r = run(repo)
    want = oid(repo, "t1") if where == "tag" else c
    assert r.returncode == 1 and want in r.stdout, r.stdout


def test_a_hit_in_a_ref_name_fails(repo):
    commit(repo, ".")
    subprocess.run(["git", "branch", f"x-{TERM}"], cwd=repo, check=True)
    r = run(repo)
    assert r.returncode == 1 and f"ref refs/heads/x-{TERM}" in r.stdout


def test_a_hit_on_a_branch_other_than_the_checkout_fails(repo):
    commit(repo, ".")
    subprocess.run(["git", "checkout", "-q", "-b", "side"], cwd=repo, check=True)
    (repo / "side.md").write_text(f"{TERM}\n")
    commit(repo, ".")
    subprocess.run(["git", "checkout", "-q", "-"], cwd=repo, check=True)
    assert run(repo).returncode == 1


def test_a_hit_in_an_old_path_fails(repo):
    (repo / f"{TERM}.txt").write_text("x\n")
    commit(repo, ".")
    (repo / f"{TERM}.txt").rename(repo / "renamed.txt")
    commit(repo, ".")
    r = run(repo)
    assert r.returncode == 1 and f"tree entry {TERM}.txt" in r.stdout


def known_file(repo, *ids):
    k = repo.parent / "known"
    k.write_text("# recorded privately\n\n" + "".join(i + "\n" for i in ids))
    return k


def run_known(repo, known, *args):
    env = {k: v for k, v in os.environ.items() if k not in ("PUBLIC_SCAN_TERMS", "PUBLIC_SCAN_KNOWN")}
    env.update(HOME=str(repo.parent / "nohome"), PUBLIC_SCAN_TERMS=str(repo.parent / "terms"),
               PUBLIC_SCAN_KNOWN=str(known))
    return subprocess.run(["sh", "scripts/public-scan.sh", *args], cwd=repo, capture_output=True,
                          text=True, env=env)


def test_listed_objects_pass_and_print_no_detail(repo):
    (repo / "notes.md").write_text(f"{TERM}\n")
    c = commit(repo, ".", msg=f"see {TERM}")
    blob = oid(repo, "HEAD:notes.md")
    (repo / "notes.md").write_text("clean\n")
    commit(repo, ".")
    r = run_known(repo, known_file(repo, c, blob))
    assert r.returncode == 0, r.stdout + r.stderr
    assert TERM not in r.stdout + r.stderr and "2 known history hits in 2 objects" in r.stderr


def test_a_new_hit_beside_listed_ones_still_fails(repo):
    c = commit(repo, ".", msg=f"see {TERM}")
    c2 = commit(repo, ".", msg=f"again {TERM}")
    r = run_known(repo, known_file(repo, c))
    assert r.returncode == 1 and c2 in r.stdout and c not in r.stdout


def test_hit_ids_prints_ids_only(repo):
    c = commit(repo, ".", msg=f"see {TERM}")
    r = run_known(repo, repo.parent / "absent", "--hit-ids")
    assert r.returncode == 1 and r.stdout == c + "\n" and TERM not in r.stderr
    r = run_known(repo, known_file(repo, *r.stdout.split()), "--hit-ids")
    assert r.returncode == 0 and r.stdout == ""


@pytest.mark.parametrize("content", ["not-an-id\n", "abc123\n", "A" * 40 + "\n"])
def test_bad_known_file_cannot_run(repo, content):
    k = repo.parent / "known"
    k.write_text(content)
    r = run_known(repo, k)
    assert r.returncode == 2 and str(k) in r.stderr


def test_unknown_argument_cannot_run(repo):
    assert run_known(repo, repo.parent / "absent", "--all").returncode == 2


def test_clean_history_passes(repo):
    commit(repo, ".")
    commit(repo, ".", tag="release")
    assert run(repo).returncode == 0


def test_a_replace_ref_does_not_hide_the_stored_object(repo):
    (repo / "notes.md").write_text(f"{TERM}\n")
    commit(repo, ".")
    bad = oid(repo, "HEAD:notes.md")
    (repo / "notes.md").write_text("clean\n")
    commit(repo, ".")
    good = oid(repo, "HEAD:notes.md")
    subprocess.run(["git", "replace", bad, good], cwd=repo, check=True)
    r = run(repo)
    assert r.returncode == 1 and bad in r.stdout


def test_a_known_tree_does_not_cover_the_same_name_in_a_new_tree(repo):
    (repo / f"{TERM}.txt").write_text("x\n")
    added = commit(repo, ".")
    tree = oid(repo, "HEAD^{tree}")
    (repo / f"{TERM}.txt").unlink()
    commit(repo, ".")
    assert run_known(repo, known_file(repo, tree, added)).returncode == 0
    (repo / f"{TERM}.txt").write_text("y\n")
    (repo / "other.txt").write_text("z\n")
    again = commit(repo, ".")
    (repo / f"{TERM}.txt").unlink()
    commit(repo, ".")
    r = run_known(repo, known_file(repo, tree, added))
    assert r.returncode == 1 and tree not in r.stdout and again in r.stdout


def test_hit_ids_hides_tip_detail_too(repo):
    (repo / "notes.md").write_text(f"{TERM}\n")
    commit(repo, ".")
    r = run_known(repo, repo.parent / "absent", "--hit-ids")
    assert r.returncode == 1 and TERM not in r.stdout + r.stderr
    assert all(len(l) == 40 for l in r.stdout.split())


def test_a_term_spanning_directories_fails_from_history(repo):
    terms = repo.parent / "span"
    terms.write_text("secretdir/conf\n")
    (repo / "secretdir").mkdir()
    (repo / "secretdir" / "conf.txt").write_text("x\n")
    c = commit(repo, ".")
    (repo / "secretdir" / "conf.txt").unlink()
    commit(repo, ".")
    r = run(repo, terms=terms)
    assert r.returncode == 1 and f"{c} path secretdir/conf.txt" in r.stdout


def test_a_path_added_by_a_merge_fails(repo):
    commit(repo, ".")
    subprocess.run(["git", "checkout", "-q", "-b", "side"], cwd=repo, check=True)
    commit(repo, ".")
    subprocess.run(["git", "checkout", "-q", "-"], cwd=repo, check=True)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(git + ["merge", "-q", "--no-ff", "--no-commit", "side"], cwd=repo, check=True)
    (repo / f"{TERM}.md").write_text("x\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(git + ["commit", "-q", "-m", "merge"], cwd=repo, check=True)
    m = oid(repo, "HEAD")
    (repo / f"{TERM}.md").unlink()
    commit(repo, ".")
    r = run(repo)
    assert r.returncode == 1 and f"{m} path {TERM}.md" in r.stdout


def test_a_detached_head_with_no_named_ref_is_still_scanned(repo):
    (repo / "notes.md").write_text(f"{TERM}\n")
    bad = commit(repo, ".")
    (repo / "notes.md").write_text("clean\n")
    commit(repo, ".")
    subprocess.run(["git", "checkout", "-q", "--detach"], cwd=repo, check=True)
    for ref in subprocess.run(["git", "for-each-ref", "--format=%(refname)"], cwd=repo, capture_output=True,
                              text=True, check=True).stdout.split():
        subprocess.run(["git", "update-ref", "-d", ref], cwd=repo, check=True)
    r = run(repo)
    assert r.returncode == 1 and oid(repo, f"{bad}:notes.md") in r.stdout


def test_a_path_in_a_tree_a_tag_names_directly_fails(repo):
    terms = repo.parent / "span"
    terms.write_text("secretdir/conf\n")
    (repo / "secretdir").mkdir()
    (repo / "secretdir" / "conf.txt").write_text("x\n")
    subprocess.run(["git", "add", "secretdir"], cwd=repo, check=True)
    tree = subprocess.run(["git", "write-tree"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    subprocess.run(["git", "rm", "-rq", "--cached", "secretdir"], cwd=repo, check=True)
    (repo / "secretdir" / "conf.txt").unlink()
    commit(repo, ".")
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "tag.gpgsign=false",
                    "tag", "-a", "treetag", "-m", "a tree", tree], cwd=repo, check=True)
    r = run(repo, terms=terms)
    assert r.returncode == 1 and f"{tree} path secretdir/conf.txt" in r.stdout


def test_hit_ids_withholds_paths_in_diagnostics(repo):
    (repo / f"{TERM}.txt").write_text("x\n")
    subprocess.run(["git", "add", f"{TERM}.txt"], cwd=repo, check=True)
    (repo / f"{TERM}.txt").unlink()
    r = run_known(repo, repo.parent / "absent", "--hit-ids")
    assert r.returncode == 2 and TERM not in r.stdout + r.stderr
    c = commit(repo, ".", msg=f"see {TERM}")
    r = run_known(repo, known_file(repo, c), "--hit-ids")
    assert r.returncode == 0 and str(repo.parent) not in r.stderr and "1 known history hits" in r.stderr


def test_known_objects_only_local_refs_reach_are_counted(repo):
    c = commit(repo, ".", msg=f"see {TERM}")
    r = run_known(repo, known_file(repo, c))
    assert r.returncode == 0 and "1 of them are reachable only from local refs" in r.stderr
