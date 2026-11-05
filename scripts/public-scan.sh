#!/bin/sh
# Public scan: no tracked file names a fleet host, the relay VM's domain or login
# user, a home-directory path on the poster Mac, the tailnet, the secrets
# cache or the vault variable names. This file is the only place
# the pattern is spelled, so it skips itself. Every tracked file is read as bytes,
# binary ones included. Exit 0 clean, 1 on a hit (each hit printed as path:line),
# 2 when the scan cannot run or a tracked file cannot be read.
cd "$(dirname "$0")/.." || exit 2
exec python3 -I - <<'PY'
import re, subprocess, sys
PATTERN = re.compile(rb"host-a|host-b|host-d|host-e|host-f|host-c|vm\.example|relayuser|/home/user"
                     rb"|exampletailnet|\bts\.net\b|\.cache/amplifier|AITOOLS_ALERTS_ROOT_NSEC|BUZZ_AITOOLS_AGENT_NSEC"
                     rb"|claude-pool", re.I)
SELF = b"scripts/public-scan.sh"
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
    if path == SELF:
        continue
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
