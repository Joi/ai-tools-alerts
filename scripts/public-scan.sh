#!/bin/sh
# Public scan: no tracked file names a fleet host, the relay VM's domain or login
# user, or a home-directory path on the poster Mac. This file is the only place
# the pattern is spelled, so it skips itself. Exit 0 clean, 1 on a hit (the hits
# are printed), 2 if this is not a git checkout.
cd "$(dirname "$0")/.." || exit 2
git rev-parse --git-dir >/dev/null 2>&1 || { echo "public-scan: not a git checkout" >&2; exit 2; }
PATTERN='host-a|host-b|host-d|host-e|host-f|host-c|vm\.example|relayuser|/home/user'
hits="$(git ls-files -z -- . ':!:scripts/public-scan.sh' | xargs -0 grep -nIiE "$PATTERN" --)"
if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    echo "public-scan: tracked files name deployment detail (see above)" >&2
    exit 1
fi
exit 0
