#!/bin/sh
# Repo gate: the public scan, then the whole test suite.
cd "$(dirname "$0")/.." || exit 2
scripts/public-scan.sh || exit $?
exec python3 -m pytest -q
