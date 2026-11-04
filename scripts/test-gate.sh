#!/bin/sh
# Repo gate: the whole test suite.
cd "$(dirname "$0")/.." || exit 2
exec python3 -m pytest -q
