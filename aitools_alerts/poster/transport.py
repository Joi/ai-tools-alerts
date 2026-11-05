"""Send one post to the relay: ssh to the VM, run the buzz-send wrapper, read the event id.

The wrapper on the VM (``ops/vm/buzz-send``) holds jibot's key and the relay URL,
so this side passes neither: no key, key path, key flag or relay flag appears
here. The post text goes on stdin; the remote command is one
``shlex.join``-ed string, so the remote shell sees each argument as one word.

Every send ends in one of three outcomes. ``ok``: the relay accepted it and
returned its id. ``failed``: the post certainly did not happen (ssh never reached
the VM, the CLI refused it before sending, the relay rejected it), so the caller
may try again next hour. ``unknown``: it may have happened (timeout, a session
dropped mid-command, the CLI's "delivery unknown"), so the caller must never
resend it until a human has looked.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass

from aitools_alerts import schema

# The ssh destination and the wrapper's path come from the poster config
# (relay_ssh_host, relay_send_wrapper); the public code names neither.
_WRAPPER = re.compile(r"/[A-Za-z0-9._/-]{1,255}")
# -T and RequestTTY=no: no terminal, so stdin reaches the wrapper as bytes; RemoteCommand=none:
# no ssh_config entry can replace the command. "--" ends options before the host.
SSH_OPTIONS = ("-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
               "-o", "RequestTTY=no", "-o", "RemoteCommand=none")
TIMEOUT = 120
MAX_CONTENT = schema.MAX_POST_CHARS
MAX_STDERR = 2000

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
# ssh's own lines when the connection never reached a remote command, anchored per line
# so the remote CLI's own text ("network error: ... connection refused") never matches.
_SSH_NEVER_RAN = re.compile(
    r"^(?:ssh: connect to host \S+ port \d+: .+"
    r"|ssh: Could not resolve hostname \S+: .+"
    r"|\S+: Permission denied \(.+\)\.?"
    r"|Host key verification failed\.)\r?$",
    re.M,
)
# Relay rejections that prove the event was not stored; any other status (a proxy's
# 408, a 5xx) proves nothing.
_RELAY_REJECTED = frozenset({400, 401, 403, 413, 422, 429})
_RELAY_STATUS = re.compile(r"relay error (\d{3}):")
# Exits that prove nothing was submitted: usage or not found (and the wrapper's own
# refusals), auth or key, other (raised before submit), conflict, and the remote
# command not starting (126, 127). Every other non-zero exit is unknown.
_NEVER_SENT = frozenset({1, 3, 4, 5, 126, 127})


@dataclass(frozen=True)
class SendResult:
    ok: bool
    event_id: str | None
    exit_code: int | None
    stderr: str
    outcome: str  # "ok" | "failed" | "unknown"


def remote_argv(channel_id: str, reply_to: str | None = None, *, wrapper: str) -> list[str]:
    """The wrapper's argv for one send; raises ValueError for a malformed id or path."""
    if not isinstance(wrapper, str) or not _WRAPPER.fullmatch(wrapper):
        raise ValueError("wrapper must be an absolute path on the relay VM")
    if not isinstance(channel_id, str) or not _UUID.fullmatch(channel_id):
        raise ValueError("channel_id must be a lowercase UUID")
    argv = [wrapper, "messages", "send", "--channel", channel_id, "--content", "-"]
    if reply_to is not None:
        if not isinstance(reply_to, str) or not _HEX64.fullmatch(reply_to):
            raise ValueError("reply_to must be a 64-hex event id")
        argv += ["--reply-to", reply_to]
    return argv


def _decode(b) -> str:
    if isinstance(b, bytes):
        b = b.decode("utf-8", "replace")
    return b if isinstance(b, str) else ""


def _cli_error(stderr: str) -> tuple[str | None, str]:
    """The Buzz CLI's error line: one JSON object {"error": category, "message": ...},
    the last such line on stderr (crates/buzz-cli/src/error.rs print_error)."""
    for line in reversed(stderr.splitlines()):
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("error"), str):
            msg = obj.get("message")
            return obj["error"], msg if isinstance(msg, str) else ""
    return None, ""


def _default_ssh(*args, **kwargs):
    return subprocess.run(*args, **kwargs)


def _classify(rc: int, stdout, stderr: str) -> tuple[str, str | None]:
    if rc == 0:
        try:
            out = json.loads(stdout.decode("utf-8") if isinstance(stdout, bytes) else stdout)
        except (ValueError, AttributeError):
            return "unknown", None
        if not isinstance(out, dict):
            return "unknown", None
        if out.get("accepted") is False:
            msg = out.get("message")
            if isinstance(msg, str) and msg.lower().startswith("duplicate"):
                return "unknown", None  # NIP-01: the relay already holds this event
            return "failed", None
        eid = out.get("event_id")
        if out.get("accepted") is True and isinstance(eid, str) and _HEX64.fullmatch(eid):
            return "ok", eid
        return "unknown", None
    if rc == 255:  # ssh itself failed: before the command ran, or mid-session?
        never_ran = _SSH_NEVER_RAN.search(stderr) and not _decode(stdout).strip()
        return ("failed" if never_ran else "unknown"), None
    if rc == 2:  # the CLI's network/relay/delivery-unknown code: read its own error line
        category, message = _cli_error(stderr)
        if category == "network_error":
            return "failed", None  # the CLI keeps only never-received failures as network errors
        if category == "relay_error":
            m = _RELAY_STATUS.match(message)
            if m and int(m.group(1)) in _RELAY_REJECTED:
                return "failed", None
        return "unknown", None  # delivery_unknown, a relay 5xx, or no recognisable error line
    if rc in _NEVER_SENT:
        return "failed", None
    return "unknown", None  # a signal (negative) or any other exit proves nothing


def send(channel_id: str, content: str, reply_to: str | None = None, ssh=None, *,
         host: str, wrapper: str, timeout: float = TIMEOUT) -> SendResult:
    """Post ``content`` to ``channel_id`` (optionally as a reply to ``reply_to``).

    ``ssh`` is a callable with ``subprocess.run``'s signature; None means the real
    ssh (looked up at call time, so tests can block it). Malformed arguments raise
    ValueError before anything runs.
    """
    if not isinstance(content, str) or not content or len(content) > MAX_CONTENT or "\x00" in content:
        raise ValueError("content must be non-empty text within the post size cap, without NUL")
    if not isinstance(host, str) or not host or host.startswith("-"):
        raise ValueError("host must be a host name")
    argv = ["ssh", *SSH_OPTIONS, "--", host, shlex.join(remote_argv(channel_id, reply_to, wrapper=wrapper))]
    ssh = ssh if ssh is not None else _default_ssh
    try:
        proc = ssh(argv, input=content.encode("utf-8"), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return SendResult(False, None, None, "ssh timed out", "unknown")
    except OSError as e:
        return SendResult(False, None, None, f"ssh could not start: {e}"[-MAX_STDERR:], "failed")
    stderr = _decode(proc.stderr)
    outcome, eid = _classify(proc.returncode, proc.stdout, stderr)  # on the whole stderr
    return SendResult(outcome == "ok", eid, proc.returncode, stderr[-MAX_STDERR:], outcome)
