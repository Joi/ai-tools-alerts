"""Send one post to the relay: ssh to the VM, run the buzz-send wrapper, read the event id.

The wrapper on the VM (``ops/vm/buzz-send``) holds jibot's key and the relay URL,
so this side passes neither: no key, key path, ``--private-key`` or ``--relay``
appears here. The post text goes on stdin; the remote command is one
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

HOST = "relay-vm.example"
WRAPPER = "/home/relay/bin/buzz-send"
SSH_OPTIONS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4")
TIMEOUT = 120
MAX_CONTENT = schema.MAX_POST_CHARS
MAX_STDERR = 2000

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
# ssh's own messages when the connection never reached a remote command.
_SSH_NEVER_RAN = re.compile(
    r"could not resolve hostname|connection refused|connection timed out|no route to host"
    r"|permission denied|host key verification failed|network is unreachable|connect to host",
    re.I,
)
_RELAY_4XX = re.compile(r"relay error 4\d\d\b")
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


def remote_argv(channel_id: str, reply_to: str | None = None) -> list[str]:
    """The wrapper's argv for one send; raises ValueError for a malformed id."""
    if not isinstance(channel_id, str) or not _UUID.fullmatch(channel_id):
        raise ValueError("channel_id must be a lowercase UUID")
    argv = [WRAPPER, "messages", "send", "--channel", channel_id, "--content", "-"]
    if reply_to is not None:
        if not isinstance(reply_to, str) or not _HEX64.fullmatch(reply_to):
            raise ValueError("reply_to must be a 64-hex event id")
        argv += ["--reply-to", reply_to]
    return argv


def _text(b) -> str:
    if isinstance(b, bytes):
        b = b.decode("utf-8", "replace")
    return (b or "")[-MAX_STDERR:]


def _classify(rc: int, stdout, stderr: str) -> tuple[str, str | None]:
    if rc == 0:
        try:
            out = json.loads(stdout.decode("utf-8") if isinstance(stdout, bytes) else stdout)
        except (ValueError, AttributeError):
            return "unknown", None
        if not isinstance(out, dict):
            return "unknown", None
        if out.get("accepted") is False:
            return "failed", None
        eid = out.get("event_id")
        if out.get("accepted") is True and isinstance(eid, str) and _HEX64.fullmatch(eid):
            return "ok", eid
        return "unknown", None
    if rc == 255:  # ssh itself failed: before the command ran, or mid-session?
        return ("failed" if _SSH_NEVER_RAN.search(stderr) else "unknown"), None
    if rc == 2:  # the CLI's network/relay/delivery-unknown code
        low = stderr.lower()
        if "delivery unknown" not in low and ("network error" in low or _RELAY_4XX.search(low)):
            return "failed", None  # never stored: a connect failure or a rejection
        return "unknown", None  # delivery unknown, a relay 5xx, or anything unrecognised
    if rc in _NEVER_SENT:
        return "failed", None
    return "unknown", None  # a signal (negative) or any other exit proves nothing


def send(channel_id: str, content: str, reply_to: str | None = None, ssh=subprocess.run, *,
         host: str = HOST, timeout: float = TIMEOUT) -> SendResult:
    """Post ``content`` to ``channel_id`` (optionally as a reply to ``reply_to``).

    ``ssh`` is ``subprocess.run`` or a callable with its signature. Malformed
    arguments raise ValueError before anything runs.
    """
    if not isinstance(content, str) or not content or len(content) > MAX_CONTENT or "\x00" in content:
        raise ValueError("content must be non-empty text within the post size cap, without NUL")
    argv = ["ssh", *SSH_OPTIONS, host, shlex.join(remote_argv(channel_id, reply_to))]
    try:
        proc = ssh(argv, input=content.encode("utf-8"), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return SendResult(False, None, None, "ssh timed out", "unknown")
    except OSError as e:
        return SendResult(False, None, None, _text(f"ssh could not start: {e}"), "failed")
    stderr = _text(proc.stderr)
    outcome, eid = _classify(proc.returncode, proc.stdout, stderr)
    return SendResult(outcome == "ok", eid, proc.returncode, stderr, outcome)
