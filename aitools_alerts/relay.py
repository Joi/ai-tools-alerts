"""Send one signed event to the relay over NIP-42 (the curator path).

``send`` refuses unless the signing key is a curator in a manifest that
verifies under the trust root, then: wait for the relay's ``["AUTH",
challenge]``, answer with a signed kind-22242 event, require its ``OK``,
send ``["EVENT", ev]`` and return the relay's ``OK`` as
``(event_id, accepted, message)``.

``websockets`` (the ``curator`` extra) is imported only when a connection
is opened, so the member package stays standard-library only. Nothing here
puts the key in a message, a log line or an exception.
"""

from __future__ import annotations

import json
import threading
import time
from urllib.parse import urlsplit

from . import TRUST_ROOT_PUBKEY, manifest, nostr

RELAY_URL = "wss://buzz.ai-tools.md"
AUTH_KIND = 22242
TIMEOUT = 20
MAX_MSG = 1 << 20
MAX_READS = 100
GRACE = 5  # seconds past the timeout for connect and close
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
INSTALL_HINT = "install the curator extra: pip install 'aitools-alerts[curator]'"


class RelayError(Exception):
    pass


class RelayUnavailable(RelayError):
    """The websockets extra is not installed."""


def check_url(url: str) -> str:
    """wss:// to any host; ws:// only to a loopback host (a local test relay)."""
    try:
        u = urlsplit(url)
        host = u.hostname
    except ValueError:
        host = None
    if not isinstance(url, str) or host is None:
        raise RelayError("relay URL is not a ws(s) URL")
    if u.scheme == "wss" or (u.scheme == "ws" and host in _LOOPBACK):
        return url
    raise RelayError("relay URL must be wss:// (ws:// only to a loopback host)")


def auth_event(sec: str, relay_url: str, challenge: str, now: int | None = None) -> dict:
    return nostr.sign_event(sec, {
        "created_at": int(time.time() if now is None else now), "kind": AUTH_KIND,
        "tags": [["relay", relay_url], ["challenge", challenge]], "content": ""})


def require_curator(event: dict, sec: str, m, root_pubkey: str = TRUST_ROOT_PUBKEY) -> str:
    """The key's pubkey, if it is a curator in ``m`` (verified under the root)
    and signed ``event``; else RelayError."""
    if m is None or not manifest.verify(m, root_pubkey):
        raise RelayError("no manifest that verifies under the trust root; run: aitools-alerts pull")
    try:
        pub = nostr.pubkey_gen(bytes.fromhex(sec)).hex()
    except (ValueError, TypeError):
        raise RelayError("the curator key is not a valid secret key") from None
    if manifest.role_of(m, pub) != "curator":
        raise RelayError(f"key {nostr.npub(pub)} has no curator role in manifest v{m.version}")
    if not isinstance(event, dict) or event.get("pubkey") != pub or not nostr.verify_event(event):
        raise RelayError("the event is not signed by the curator key")
    return pub


def _default_connect(url: str, timeout: float):
    try:
        from websockets.sync.client import connect
    except ImportError:
        raise RelayUnavailable(INSTALL_HINT) from None
    return connect(url, open_timeout=timeout, close_timeout=5, max_size=MAX_MSG)


def _read(ws, deadline: float, want: str, ref: str | None = None) -> list:
    """The next message of type ``want`` (for ``OK``: about event ``ref``)."""
    for _ in range(MAX_READS):
        left = deadline - time.monotonic()
        if left <= 0:
            break
        try:
            raw = ws.recv(timeout=left)
        except TimeoutError:
            break
        if not isinstance(raw, str) or len(raw) > MAX_MSG:
            raise RelayError("relay sent a frame that is not a text message")
        try:
            msg = json.loads(raw)
        except ValueError:
            raise RelayError("relay sent a message that is not JSON") from None
        if not isinstance(msg, list) or not msg or msg[0] != want:
            continue  # NOTICE, EOSE and the like
        if want == "AUTH" and len(msg) >= 2 and isinstance(msg[1], str) and 0 < len(msg[1]) <= 1024:
            return msg
        if want == "OK" and len(msg) >= 3 and msg[1] == ref and isinstance(msg[2], bool):
            return msg
    raise RelayError(f"no {want} from the relay in time")


def _exchange(event, relay_url, key, connect, timeout, now, box) -> tuple:
    deadline = time.monotonic() + timeout
    try:
        with (connect or _default_connect)(relay_url, timeout) as ws:
            box["ws"] = ws
            challenge = _read(ws, deadline, "AUTH")[1]
            auth = auth_event(key, relay_url, challenge, now)
            ws.send(json.dumps(["AUTH", auth]))
            ok = _read(ws, deadline, "OK", auth["id"])
            if not ok[2]:
                raise RelayError(f"relay refused AUTH: {str(ok[3] if len(ok) > 3 else '')[:200]}")
            ws.send(json.dumps(["EVENT", event]))
            ok = _read(ws, deadline, "OK", event["id"])
    except RelayError:
        raise
    except Exception as e:  # OSError, a closed or refused websocket: name it, nothing more
        raise RelayError(f"relay connection failed: {type(e).__name__}") from None
    msg = ok[3] if len(ok) > 3 and isinstance(ok[3], str) else ""
    return ok[1], ok[2], msg[:500]


def send(event: dict, relay_url: str = RELAY_URL, key: str | None = None, *, manifest=None,
         root_pubkey: str = TRUST_ROOT_PUBKEY, connect=None, timeout: float = TIMEOUT,
         now: int | None = None) -> tuple[str, bool, str]:
    """NIP-42 AUTH, then EVENT; the relay's OK as (event_id, accepted, message).
    The whole exchange (connect, sends, reads, close) is bounded: it runs in a
    worker thread, and a peer that stalls a write or the close is cut off."""
    check_url(relay_url)
    require_curator(event, key, manifest, root_pubkey)
    box: dict = {}

    def run():
        try:
            box["ok"] = _exchange(event, relay_url, key, connect, timeout, now, box)
        except BaseException as e:  # handed to the caller below
            box["err"] = e

    t = threading.Thread(target=run, name="aitools-relay", daemon=True)
    t.start()
    t.join(timeout + GRACE)
    if t.is_alive():
        sock = getattr(box.get("ws"), "socket", None)
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass
        raise RelayError(f"relay exchange did not finish within {timeout + GRACE:.0f} s")
    if "err" in box:
        raise box["err"]
    return box["ok"]
