#!/bin/sh
# Claude Code SessionStart hook for ai-tools-alerts.
#
# Runs one pull, check and notify. When a critical advisory that matches
# this machine had not been seen before, prints one line to stdout, which
# Claude Code adds to the session's context; when no new signed post
# arrived for over 3 days, or the manifest is over 90 days old (a frozen or
# replayed mirror), prints another fixed line. Anything else prints nothing.
# The hook always exits 0: a missing CLI, an unreadable mirror or a slow
# network must never fail a session. The pull and a notification each have
# their own timeout; the timeout in settings.json (README) bounds the rest.
#
# stdin is closed for the CLI (Claude Code writes the hook's JSON input
# there), its stderr is discarded and its stdout (run --json) is only
# searched, so only the fixed lines below can reach the context. Post text
# cannot forge the stale_since match: JSON writes a quote inside a string
# as \", so only the key itself is followed by an unescaped quote.
#
# PATH: the session's own PATH, with ~/.local/bin (pipx, or the link the
# README makes for a venv install) in front and Homebrew at the end, the
# same places the launchd template searches.

PATH="$HOME/.local/bin:$PATH:/opt/homebrew/bin:/usr/local/bin"
export PATH
out=$(aitools-alerts run --json </dev/null 2>/dev/null)
if [ "$?" -eq 2 ]; then
    printf '%s\n' "AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill"
fi
case $out in
    *'"stale_since": "'*)
        printf '%s\n' "AITOOLS-ALERT: alerts may be stale (no new signed post for over 3 days, or a trust manifest over 90 days old); run aitools-alerts check" ;;
esac
exit 0
