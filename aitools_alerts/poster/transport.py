"""Send one post to the relay: sign it here and POST it over HTTPS.

The poster holds jibot's key (read from the secrets helper on the poster machine)
and signs two events per post: the kind 9 channel message (with the claim tag of
the state it gives its thread, when the caller has one: spec/wire.md), and a NIP-98 kind
27235 event that authorises the HTTP request. The relay requires the message's
author to be the NIP-98 signer, and the signer to be a relay member. The relay
machine never holds the key.

Every send ends in one of four outcomes. ``ok``: the relay holds the event and
returned its id, which is the id computed here. ``failed``: the post certainly
did not happen (no byte of the request was written, or the relay answered that
it did not store it for a reason other than the event itself), so the caller
may try again next hour. ``unknown``: it may have happened (a timeout or a drop
after the request began, a 5xx, an answer that does not parse), so the caller
must never resend it until a human has looked. ``refused``: the relay rejected
this event itself (HTTP 413, or 400 with its ``invalid:`` error): resending the
same text changes nothing.

Each send runs under one wall-clock deadline. A lock-guarded gate sits between
connecting and writing: when the deadline passes before the gate, the send is
cancelled and no byte can be written afterwards (``failed``); after the gate it
is ``unknown``.

The key never appears in a result, an exception or a log line.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import secrets
import shlex
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from aitools_alerts import nostr, schema, wire

MAX_CONTENT = schema.MAX_POST_CHARS
DEADLINE = 90.0  # the whole send: connect, write, response (the ssh route allowed 120 s)
CONNECT_TIMEOUT = 20.0
IO_TIMEOUT = 30.0  # each socket operation after connecting
MAX_RESPONSE = 64 * 1024
MAX_STDERR = 2000
MESSAGE_KIND = 9
NIP98_KIND = 27235

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
# Statuses that prove the relay did not store the event, for a reason other than the
# event itself (auth, membership, not found, rate limit): next hour.
_NOT_STORED = frozenset({401, 403, 404, 429})


class KeyUnavailable(Exception):
    """The relay key could not be read; the message never carries key material."""


@dataclass(frozen=True)
class SendResult:
    ok: bool
    event_id: str | None
    exit_code: int | None  # the HTTP status, or None when there was none
    stderr: str  # a short reason; never key material
    outcome: str  # "ok" | "failed" | "unknown" | "refused"
    message: str = ""  # a refusal's reason, from the relay's error


def check_send(channel_id, content, reply_to=None, claim=None) -> None:
    """Every shape check a send makes, before anything is marked pending; ValueError if not.
    ``claim``: None, or the event tag exactly as ``wire.claim_tag`` writes it."""
    if claim is not None:
        obj = wire.claim_of({"tags": [claim]}) if isinstance(claim, list) else None
        if obj is None or wire.claim_tag(obj) != claim:
            raise ValueError("claim must be the tag wire.claim_tag writes")
    if not isinstance(channel_id, str) or not _UUID.fullmatch(channel_id):
        raise ValueError("channel_id must be a lowercase UUID")
    if reply_to is not None and (not isinstance(reply_to, str) or not _HEX64.fullmatch(reply_to)):
        raise ValueError("reply_to must be a 64-hex event id")
    if not isinstance(content, str) or not content or len(content) > MAX_CONTENT or "\x00" in content:
        raise ValueError("content must be non-empty text within the post size cap, without NUL")


def check_url(url) -> str:
    """The relay's base URL: ``https://<host>``, nothing else. Returns the host."""
    if not isinstance(url, str):
        raise ValueError("relay_url must be https://<host>")
    parts = urlsplit(url)
    host = parts.hostname or ""
    if (parts.scheme != "https" or url != f"https://{host}" or not _HOST.fullmatch(host)):
        raise ValueError("relay_url must be https://<host>")
    return host


def message_event(channel_id: str, content: str, reply_to: str | None, *, created_at: int,
                  claim: list | None = None) -> dict:
    """The unsigned channel message (buzz-sdk ``build_message``). The poster replies
    only to a thread root, so a reply is always a direct one: one ``e`` tag, ``reply``.
    ``claim``: the claim tag of the state this event gives its thread (spec/wire.md),
    signed with the event, last among its tags."""
    check_send(channel_id, content, reply_to, claim)
    tags = [["h", channel_id]]
    if reply_to is not None:
        tags.append(["e", reply_to, "", "reply"])
    if claim is not None:
        tags.append(list(claim))
    return {"created_at": int(created_at), "kind": MESSAGE_KIND, "tags": tags, "content": content}


def auth_header(sec_hex: str, url: str, body: bytes, *, created_at: int, nonce: str) -> str:
    """The NIP-98 ``Authorization`` value for one POST of ``body`` to ``url``."""
    ev = nostr.sign_event(sec_hex, {
        "created_at": int(created_at), "kind": NIP98_KIND, "content": "",
        "tags": [["u", url], ["method", "POST"], ["payload", hashlib.sha256(body).hexdigest()],
                 ["nonce", nonce]]})
    raw = json.dumps(ev, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "Nostr " + base64.b64encode(raw).decode("ascii")


def _printable(s: str, n: int = 300) -> str:
    s = " ".join(s.split())[:n]
    return "".join(ch if ch.isprintable() else "?" for ch in s)


def classify(status: int, body: bytes, event_id: str) -> tuple[str, str]:
    """(outcome, reason) for the relay's answer to a POST of the event ``event_id``."""
    if status == 200:
        try:
            out = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return "unknown", "200 with a body that is not JSON"
        if not isinstance(out, dict):
            return "unknown", "200 with a body that is not an object"
        msg = out.get("message") if isinstance(out.get("message"), str) else ""
        if out.get("accepted") is True:
            if out.get("event_id") == event_id:
                return "ok", ""
            return "unknown", "200 naming another event id"
        if out.get("accepted") is False:
            if msg.lower().startswith("duplicate"):
                if out.get("event_id") in (None, event_id):
                    return "ok", ""  # the relay already holds this exact event (its id is its hash)
                return "unknown", "duplicate naming another event id"
            return "failed", "not accepted: " + _printable(msg)
        return "unknown", "200 without an accepted field"
    if status == 413:
        return "refused", "413 event too large"
    if status == 400:
        try:
            err = json.loads(body.decode("utf-8")).get("error")
        except (UnicodeDecodeError, ValueError, AttributeError):
            err = None
        if isinstance(err, str) and err.startswith("invalid:"):
            return "refused", _printable(err)
        return "failed", "400 " + (_printable(err) if isinstance(err, str) else "(not the relay's error)")
    if status in _NOT_STORED:
        return "failed", f"{status}"
    return "unknown", f"{status}"


def _connect(host: str, timeout: float):
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ssl.create_default_context())
    conn.connect()
    return conn


class Relay:
    """``send(channel_id, content, reply_to, claim) -> SendResult`` against one relay.

    ``key_source()`` returns the signing key as 64 hex, or raises KeyUnavailable; it
    runs on the first send and its result is kept for this object's life. A key whose
    public key is not ``expected_pubkey`` sends nothing. ``connect(host, timeout)``
    returns an http.client connection, already connected (tests replace it).
    ``on_signed(event_id)`` is called with the id of each message event once it is signed
    and before the request is made (ai-tools-alerts#m729); when it raises, nothing is
    sent and the outcome is ``failed``.
    """

    def __init__(self, url: str, key_source, *, expected_pubkey: str, connect=None,
                 clock=time.time, deadline: float | None = None, on_signed=None):
        self.host = check_url(url)
        self.url = f"https://{self.host}/events"
        self._key_source, self._expected = key_source, expected_pubkey
        self._connect = connect or _connect
        self._clock = clock
        self._deadline = DEADLINE if deadline is None else deadline
        self._key: str | None = None
        self._key_error: str | None = None
        self._on_signed = on_signed

    def _signing_key(self) -> str | None:
        if self._key is None and self._key_error is None:
            try:
                k = self._key_source()
            except KeyUnavailable as e:
                self._key_error = f"relay key unavailable: {e}"
                return None
            except Exception:  # noqa: BLE001 - never echo what a helper raised
                self._key_error = "relay key unavailable"
                return None
            k = k.strip().lower() if isinstance(k, str) else ""
            try:
                if k.startswith("nsec1"):
                    k = nostr.nsec_to_hex(k)
                pub = nostr.pubkey_gen(bytes.fromhex(k)).hex() if _HEX64.fullmatch(k) else None
            except (ValueError, TypeError):
                pub = None
            if pub is None:
                self._key_error = "relay key unavailable: not a secret key"
            elif pub != self._expected:
                self._key_error = "relay key is not the manifest's relay-bot key"
            else:
                self._key = k
        return self._key

    def send(self, channel_id: str, content: str, reply_to: str | None = None,
             claim: list | None = None) -> SendResult:
        check_send(channel_id, content, reply_to, claim)
        key = self._signing_key()
        if key is None:
            return SendResult(False, None, None, self._key_error or "relay key unavailable", "failed")
        now = int(self._clock())
        event = nostr.sign_event(key, message_event(channel_id, content, reply_to, created_at=now, claim=claim))
        if self._on_signed is not None:
            # m729: the id is written down before a byte is sent, so whatever becomes of the
            # send or of this process, the poster knows the event as its own.
            try:
                self._on_signed(event["id"])
            except Exception:  # noqa: BLE001 - not recorded, so not sent: next hour
                return SendResult(False, None, None, "the sent record could not be written", "failed")
        body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {"Authorization": auth_header(key, self.url, body, created_at=now,
                                                nonce=secrets.token_hex(16)),
                   "Content-Type": "application/json", "Content-Length": str(len(body)),
                   "User-Agent": "aitools-alerts-poster"}
        return self._post(body, headers, event["id"])

    def _post(self, body: bytes, headers: dict, event_id: str) -> SendResult:
        gate = {"phase": "connecting", "cancelled": False}
        lock = threading.Lock()
        box: list = []

        def work():
            conn = None
            try:
                conn = self._connect(self.host, min(CONNECT_TIMEOUT, self._deadline))
                with lock:
                    if gate["cancelled"]:
                        return
                    gate["phase"] = "writing"
                if getattr(conn, "sock", None) is not None:
                    conn.sock.settimeout(IO_TIMEOUT)
                conn.request("POST", "/events", body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read(MAX_RESPONSE + 1)
                box.append(("response", resp.status, data))
            except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as e:
                box.append(("error", type(e).__name__, None))
            except Exception as e:  # noqa: BLE001 - classified below, never re-raised
                box.append(("error", type(e).__name__, None))
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass

        t = threading.Thread(target=work, name="aitools-alerts-poster-send", daemon=True)
        t.start()
        t.join(self._deadline)
        with lock:
            if not box:  # still running (or ended without a word): the gate decides
                if gate["phase"] == "connecting":
                    gate["cancelled"] = True  # the worker writes nothing after this
                    return SendResult(False, None, None, "connect did not finish before the deadline", "failed")
                return SendResult(False, None, None, "no response before the deadline", "unknown")
            phase = gate["phase"]
        kind, a, data = box[0]
        if kind == "error":
            if phase == "connecting":
                return SendResult(False, None, None, f"connect failed ({a})", "failed")
            return SendResult(False, None, None, f"request failed after it began ({a})", "unknown")
        status = a
        if len(data) > MAX_RESPONSE:
            return SendResult(False, None, status, "response too large", "unknown")
        outcome, reason = classify(status, data, event_id)
        reason = reason[-MAX_STDERR:]
        return SendResult(outcome == "ok", event_id if outcome == "ok" else None, status, reason, outcome,
                          reason if outcome == "refused" else "")


# ---------------------------------------------------------------- the checkpoint route (nfm3)
# Posts go over HTTPS (above). The feed checkpoint, a document the relay does not store,
# goes to the mirror directory on the relay VM through a put-only ssh route: the guard
# shell there allows ``<relay_put_wrapper> checkpoint`` and nothing else. The route
# holds no key. The ssh destination and the wrapper's path come from the poster config
# (relay_ssh_host, relay_put_wrapper); the public code names neither.
_WRAPPER = re.compile(r"/[A-Za-z0-9._/-]{1,255}")
# -T and RequestTTY=no: no terminal, so stdin reaches the wrapper as bytes; RemoteCommand=none:
# no ssh_config entry can replace the command. "--" ends options before the host.
SSH_OPTIONS = ("-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
               "-o", "RequestTTY=no", "-o", "RemoteCommand=none")
TIMEOUT = 120


def put(kind: str, data: bytes, ssh=None, *, host: str, wrapper: str, timeout: float = TIMEOUT) -> tuple[bool, str]:
    """Hand one signed document to the relay VM's storing command
    (``ops/vm/mirror-put``): ``<wrapper> <kind>`` with ``data`` on stdin.
    Returns (stored, a short detail for the log). Nothing is retried: the
    next run signs a newer document. Malformed arguments raise ValueError."""
    if kind != "checkpoint":
        raise ValueError("kind must be checkpoint")
    if not isinstance(wrapper, str) or not _WRAPPER.fullmatch(wrapper):
        raise ValueError("wrapper must be an absolute path on the relay VM")
    if not isinstance(host, str) or not host or host.startswith("-"):
        raise ValueError("host must be a host name")
    if not isinstance(data, bytes) or not data:
        raise ValueError("data must be bytes")
    argv = ["ssh", *SSH_OPTIONS, "--", host, shlex.join([wrapper, kind])]
    ssh = ssh if ssh is not None else _default_ssh
    try:
        proc = ssh(argv, input=data, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "ssh timed out"
    except OSError as e:
        return False, f"ssh could not start: {e}"[-MAX_STDERR:]
    try:
        ok = proc.returncode == 0 and json.loads(_decode(proc.stdout).strip().splitlines()[-1]).get("stored") is True
    except (ValueError, IndexError, AttributeError):
        ok = False
    detail = "stored" if ok else f"exit {proc.returncode}: {_decode(proc.stderr)[-300:]}"
    return ok, "".join(ch if ch.isprintable() else "?" for ch in detail)


def _decode(b) -> str:
    if isinstance(b, bytes):
        b = b.decode("utf-8", "replace")
    return b if isinstance(b, str) else ""


def _default_ssh(*args, **kwargs):
    return subprocess.run(*args, **kwargs)
