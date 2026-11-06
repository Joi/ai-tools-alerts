#!/bin/sh
# Public scan: no tracked file names the deployment (hosts, domains, home paths,
# vault variable names). The terms are not in this repo: one regex fragment per
# line, matched case-insensitively, in $PUBLIC_SCAN_TERMS or else
# ~/.config/aitools-alerts/public-scan.terms (keep it untracked, mode 600).
# Blank lines and lines starting with # are skipped. Every tracked file, this
# one included, is read as bytes, binary ones too, and file names are scanned.
# Exit 0 clean, 1 on a hit (each hit printed as path:line), 2 when the scan
# cannot run: no terms file, no term in it, a bad term, or a tracked file that
# cannot be read.
cd "$(dirname "$0")/.." || exit 2
exec python3 -I - <<'PY'
import os, re, subprocess, sys
TERMS = os.environ.get("PUBLIC_SCAN_TERMS") or os.path.expanduser("~/.config/aitools-alerts/public-scan.terms")
def fail(why):
    print(f"public-scan: {why}: {TERMS} (set PUBLIC_SCAN_TERMS to a terms file)", file=sys.stderr)
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
    fail(f"bad term in terms file{f' at line {line}' if line else ''} ({e})")
try:
    listed = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
except (OSError, subprocess.CalledProcessError) as e:
    print(f"public-scan: cannot list tracked files: {e}", file=sys.stderr)
    sys.exit(2)
hits, errors = 0, 0
for path in filter(None, listed.split(b"\0")):
    name = path.decode("utf-8", "replace")
    if PATTERN.search(path):
        print(f"{name}: (file name)")
        hits += 1
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        print(f"public-scan: cannot read {name}: {e.strerror}", file=sys.stderr)
        errors += 1
        continue
    for n, line in enumerate(data.split(b"\n"), 1):
        if PATTERN.search(line):
            print(f"{name}:{n}: {line[:200].decode('utf-8', 'replace')}")
            hits += 1
if errors:
    sys.exit(2)
if hits:
    print("public-scan: tracked files name deployment detail (see above)", file=sys.stderr)
    sys.exit(1)
PY
