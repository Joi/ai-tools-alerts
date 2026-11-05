#!/bin/sh
# Claude Code SessionStart hook for ai-tools-alerts.
#
# Runs one pull, check and notify. When a critical advisory that matches
# this machine had not been seen before, prints one line to stdout, which
# Claude Code adds to the session's context. Anything else prints nothing.
# The hook always exits 0: a missing CLI, an unreadable mirror or a slow
# network must never fail a session. The pull and a notification each have
# their own timeout; the timeout in settings.json (README) bounds the rest.
#
# stdin is closed for the CLI (Claude Code writes the hook's JSON input
# there), and its stdout and stderr are discarded so only the one line
# below can reach the context.
#
# PATH: the session's own PATH, with ~/.local/bin (pipx, or the link the
# README makes for a venv install) in front and Homebrew at the end, the
# same places the launchd template searches.

PATH="$HOME/.local/bin:$PATH:/opt/homebrew/bin:/usr/local/bin"
export PATH
aitools-alerts run --quiet </dev/null >/dev/null 2>&1
if [ "$?" -eq 2 ]; then
    printf '%s\n' "AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill"
fi
exit 0
