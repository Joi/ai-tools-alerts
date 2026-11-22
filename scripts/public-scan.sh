#!/bin/sh
# Public scan: nothing in this repository, at the tip or in its history, names
# the deployment (hosts, domains, home paths, vault variable names). The terms
# are not in this repo: one regex fragment per line, matched case-insensitively,
# in $PUBLIC_SCAN_TERMS or else ~/.config/aitools-alerts/public-scan.terms
# (keep it untracked, mode 600). Blank lines and lines starting with # are
# skipped.
#
# Tip pass: every tracked file, this one included, is read as bytes, binary ones
# too, and file names are scanned.
# History pass: every object reachable from every ref or HEAD (git rev-list
# --objects --all, plus annotated tags and the trees a tag names), as stored,
# ignoring replace refs: each blob's
# lines, each tree's entry names, each full path where a commit added it,
# each commit's and tag's raw text (author,
# committer, tagger, message), and every ref name.
#
# It reads only what this clone holds: a shallow or partial clone gives a
# partial pass, and GitHub's refs/pull/* are not fetched by default.
#
# Known hits: a history hit inside an object whose id is listed in
# $PUBLIC_SCAN_KNOWN or else ~/.config/aitools-alerts/public-scan.known (one
# 40- or 64-hex object id per line, # comments; keep it untracked) is counted
# and not printed. Those are leaks already in history and recorded privately;
# a missing file lists none. A ref name is never known: rename the ref. A
# name in history is known only through the tree that holds it, so the same
# name in a new tree fails again. Known objects that only local refs reach are
# counted on stderr: pushing those refs would publish them.
#
# --hit-ids prints the ids of the objects with unlisted history hits, one per
# line, and no content, not even for a hit at the tip or in a ref name (those
# set the exit code only): record the detail privately, then add the ids to
# the known file. Without --hit-ids the detail goes to stdout, for the person
# running the scan; never paste it into a public file, commit or pull request.
#
# Exit 0 clean, 1 on a hit (each printed: path:line at the tip, object id in
# history), 2 when the scan cannot run: no terms file, no term in it, a bad
# term, a bad known file, a tracked file that cannot be read, or git failing.
cd "$(dirname "$0")/.." || exit 2
exec python3 -I - "$@" <<'PY'
import os, re, subprocess, sys, threading
ARGS = sys.argv[1:]
if ARGS not in ([], ["--hit-ids"]):
    print("usage: scripts/public-scan.sh [--hit-ids]", file=sys.stderr)
    sys.exit(2)
HIT_IDS = ARGS == ["--hit-ids"]
TERMS = os.environ.get("PUBLIC_SCAN_TERMS") or os.path.expanduser("~/.config/aitools-alerts/public-scan.terms")
KNOWN = os.environ.get("PUBLIC_SCAN_KNOWN") or os.path.expanduser("~/.config/aitools-alerts/public-scan.known")
def where(path):  # --hit-ids prints ids and nothing else: no file name, not even in a diagnostic
    return "(path withheld under --hit-ids)" if HIT_IDS else path
def fail(why, detail=""):
    print(f"public-scan: {why}{'' if HIT_IDS else detail}: {where(TERMS)} (set PUBLIC_SCAN_TERMS to a terms file)",
          file=sys.stderr)
    sys.exit(2)
try:
    with open(TERMS, "rb") as fh:
        lines = fh.read().removeprefix(b"\xef\xbb\xbf").split(b"\n")
    terms = [(n, t) for n, t in enumerate((l.strip() for l in lines), 1) if t and not t.startswith(b"#")]
except OSError as e:
    fail(f"cannot read terms file ({e.strerror})")
if not terms:
    fail("no term in terms file")
try:
    for n, t in terms:  # each alone first: two bad fragments can join into a valid pattern
        line = n
        re.compile(t, re.I)
    line = None
    PATTERN = re.compile(b"|".join(b"(?:" + t + b")" for _, t in terms), re.I)
except (re.error, OverflowError, RecursionError, ValueError) as e:
    fail(f"bad term in terms file{f' at line {line}' if line else ''}", f" ({e})")

known = set()
try:
    with open(KNOWN, "rb") as fh:
        for n, raw in enumerate(fh.read().removeprefix(b"\xef\xbb\xbf").split(b"\n"), 1):
            t = raw.strip()
            if not t or t.startswith(b"#"):
                continue
            if not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", t):
                print(f"public-scan: known file line {n} is not an object id: {where(KNOWN)}", file=sys.stderr)
                sys.exit(2)
            known.add(t)
except FileNotFoundError:
    pass
except OSError as e:
    print(f"public-scan: cannot read known file ({e.strerror}): {where(KNOWN)}", file=sys.stderr)
    sys.exit(2)

# A replace ref would show sanitized content in place of the stored object: read what is stored.
os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"

def git(*args):
    try:
        return subprocess.run(["git", *args], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"public-scan: git {args[0]} failed: {e}", file=sys.stderr)
        sys.exit(2)

def show(b):
    return b[:200].decode("utf-8", "replace")

# Tip pass
listed = git("ls-files", "-z")
hits, errors = 0, 0
for path in filter(None, listed.split(b"\0")):
    name = path.decode("utf-8", "replace")
    if PATTERN.search(path):
        if not HIT_IDS:
            print(f"{name}: (file name)")
        hits += 1
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        print(f"public-scan: cannot read {where(name)}: {e.strerror}", file=sys.stderr)
        errors += 1
        continue
    for n, line in enumerate(data.split(b"\n"), 1):
        if PATTERN.search(line):
            if not HIT_IDS:
                print(f"{name}:{n}: {show(line)}")
            hits += 1

# History pass
paths = {}  # oid -> every path rev-list reports for it
refs = git("for-each-ref", "--format=%(objectname) %(objecttype) %(refname)")
ref_names, tag_trees = [], set()  # tag_trees: trees a ref or a tag names directly
for row in refs.splitlines():
    oid, kind, name = row.split(b" ", 2)
    ref_names.append(name)
    if kind == b"tag":
        paths.setdefault(oid, set())
    elif kind == b"tree":  # a ref straight to a tree: its paths belong to no commit
        tag_trees.add(oid)
# rev-list --all also follows HEAD, which can be a detached commit with no named ref.
head = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], capture_output=True).returncode == 0
has_history = bool(ref_names) or head  # an empty repository has neither
if has_history:
    for row in git("rev-list", "--objects", "--all").splitlines():
        oid, _, path = row.partition(b" ")
        s = paths.setdefault(oid, set())
        if path:
            s.add(path)

history_hits, known_hits, known_objects, hit_ids = 0, 0, set(), set()
def hit(oid, text):
    global history_hits, known_hits
    if oid in known:
        known_hits += 1
        known_objects.add(oid)
        return
    history_hits += 1
    hit_ids.add(oid)
    if not HIT_IDS:
        print(text)

for name in ref_names:
    if PATTERN.search(name):
        history_hits += 1
        if not HIT_IDS:
            print(f"ref {show(name)}")

oids = sorted(paths)
if oids:
    try:
        cat = subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as e:
        print(f"public-scan: git cat-file failed: {e}", file=sys.stderr)
        sys.exit(2)
    def feed():
        try:
            cat.stdin.write(b"".join(o + b"\n" for o in oids))
            cat.stdin.close()
        except OSError:
            pass
    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    for oid in oids:
        header = cat.stdout.readline().split()
        if len(header) != 3 or header[0] != oid:
            print(f"public-scan: git cat-file gave no object for {oid.decode()}", file=sys.stderr)
            sys.exit(2)
        kind, size = header[1], int(header[2])
        data = cat.stdout.read(size)
        cat.stdout.read(1)
        o = oid.decode()
        if kind == b"tree":  # names live in trees: rev-list gives one path per object, so a rename hides the old one
            i, width = 0, len(oid) // 2
            while i < len(data):
                sp, nul = data.find(b" ", i), data.find(b"\0", i)
                if sp < 0 or nul < 0:
                    break
                if PATTERN.search(data[sp + 1:nul]):
                    hit(oid, f"{o} tree entry {show(data[sp + 1:nul])}")
                i = nul + 1 + width
            continue
        if kind == b"tag":
            head_lines = data.split(b"\n\n", 1)[0].split(b"\n")
            if b"type tree" in head_lines and head_lines[0].startswith(b"object "):
                tag_trees.add(head_lines[0][7:])
        label = f"blob {show(min(paths[oid]))}" if kind == b"blob" and paths[oid] else kind.decode()
        for n, line in enumerate(data.split(b"\n"), 1):
            if PATTERN.search(line):
                hit(oid, f"{o} {label}:{n}: {show(line)}")
    writer.join()
    if cat.wait() != 0:
        print("public-scan: git cat-file failed", file=sys.stderr)
        sys.exit(2)

# Full paths: a term can span directories ("a/b"), which no single tree entry holds. Every path
# in a commit's tree was added by some commit, so each commit's paths against each parent (the
# root against nothing, a merge against each side) cover them; a hit is known through the commit
# that added the path. A tree that a tag or a ref names directly belongs to no commit: its paths
# are listed whole, and a hit there is known through that tree.
for tree in sorted(tag_trees):
    for p in filter(None, git("ls-tree", "-r", "-z", "--name-only", tree.decode()).split(b"\0")):
        if PATTERN.search(p):
            hit(tree, f"{tree.decode()} path {show(p)}")
if has_history:
    commits = git("rev-list", "--all")
    try:
        out = subprocess.run(["git", "diff-tree", "--stdin", "-r", "-m", "--root", "--no-renames", "--diff-filter=A",
                              "--name-only", "-z"], input=commits, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"public-scan: git diff-tree failed: {e}", file=sys.stderr)
        sys.exit(2)
    ids, current = set(commits.split()), None
    for tok in out.split(b"\0"):
        if tok in ids:
            current = tok
        elif tok and current and PATTERN.search(tok):
            hit(current, f"{current.decode()} path {show(tok)}")

if HIT_IDS:
    for oid in sorted(hit_ids):
        print(oid.decode())
if known_hits:
    print(f"public-scan: {known_hits} known history hits in {len(known_objects)} objects (listed in {where(KNOWN)})",
          file=sys.stderr)
    # Known is not harmless: an object only a local ref reaches is published by pushing that ref.
    remote = {r.split(b" ", 1)[0] for r in git("rev-list", "--objects", "--remotes").splitlines()}
    local_only = len(known_objects - remote)
    if local_only:
        print(f"public-scan: {local_only} of them are reachable only from local refs; pushing those refs "
              "would publish them", file=sys.stderr)
if errors:
    sys.exit(2)
if hits or history_hits:
    if not HIT_IDS:
        print("public-scan: the repository names deployment detail (see above)", file=sys.stderr)
    sys.exit(1)
PY
