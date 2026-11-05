#!/bin/sh
# Claude Code SessionStart hook for ai-tools-alerts.
#
# Runs one pull, check and notify. When a critical advisory that matches
# this machine had not been seen before, prints one line to stdout, which
# Claude Code adds to the session's context. Anything else prints nothing.
# The hook always exits 0: a missing CLI, an unreadable mirror or a slow
# network must never block or fail a session.
#
# stdin is closed for the CLI (Claude Code writes the hook's JSON input
# there), and its stdout and stderr are discarded so only the one line
# below can reach the context.

aitools-alerts run --quiet </dev/null >/dev/null 2>&1
if [ "$?" -eq 2 ]; then
    printf '%s\n' "AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill"
fi
exit 0
