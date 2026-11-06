#!/bin/sh -p
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
# Environment: the session's environment includes the env block of the
# project's .claude/settings.json, so a project could point HOME at its own
# config and state, PATH at its own aitools-alerts, or PYTHONPATH at its own
# code. The hook takes HOME from the password database (the CLI does too)
# and runs the CLI in an empty environment holding only HOME, USER, LOGNAME
# and the launchd template's PATH: ~/.local/bin (pipx, or the link the
# README makes for a venv install), Homebrew, /usr/bin and /bin. Register
# this file by its absolute path (README): a ~ in the hook command expands
# against the session's HOME. -p stops bash, which is /bin/sh on macOS, from
# importing functions and SHELLOPTS from the environment. On Linux the
# desktop bus comes from the uid's /run/user directory, never the session.
# If the user cannot be resolved, the hook prints nothing.

# --- home: begin
u=$(/usr/bin/id -un 2>/dev/null) || exit 0
case $u in '' | -* | *[!A-Za-z0-9._-]*) exit 0 ;; esac
case $u in *[!0-9]*) ;; *) exit 0 ;; esac   # bash reads ~0 as the directory stack
eval "HOME=~$u"
case $HOME in /*) ;; *) exit 0 ;; esac
export HOME
# --- home: end
PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
r=/run/user/$(/usr/bin/id -u)
set --
if [ -S "$r/bus" ]; then set -- XDG_RUNTIME_DIR="$r" DBUS_SESSION_BUS_ADDRESS="unix:path=$r/bus"; fi
out=$(/usr/bin/env -i HOME="$HOME" PATH="$PATH" USER="$u" LOGNAME="$u" "$@" \
    aitools-alerts run --json </dev/null 2>/dev/null)
if [ "$?" -eq 2 ]; then
    printf '%s\n' "AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill"
fi
case $out in
    *'"stale_since": "'*)
        printf '%s\n' "AITOOLS-ALERT: alerts may be stale (no new signed post for over 3 days, or a trust manifest over 90 days old); run aitools-alerts check" ;;
esac
exit 0
