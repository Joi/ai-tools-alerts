"""The relay transport (ai-tools-alerts#vzc3): the poster signs the message and its
NIP-98 header and POSTs them over HTTPS. A fake connection records each request;
nothing reaches the network."""

import base64
import hashlib
import json
import threading
import time

import pytest

from aitools_alerts import nostr
from aitools_alerts.poster import transport

SEC, PUB = nostr.keygen()
OTHER_SEC, OTHER_PUB = nostr.keygen()
CH = "599adb9f-4f9f-4b19-aee3-66667c3293e8"
ROOT = "ab" * 32
URL = "https://relay.example.net"
NOW = 1795400000


class FakeResp:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def read(self, n=-1):
        return self.body if n < 0 else self.body[:n]


class FakeSock:
    timeout = None

    def settimeout(self, t):
        self.timeout = t


class FakeConn:
    """An http.client connection that answers from ``answer(body) -> (status, bytes)``
    or raises ``error`` at ``fail_at`` ("request" or "response")."""

    def __init__(self, answer=None, error=None, fail_at=None):
        self.answer = answer or (lambda body: (200, json.dumps(
            {"accepted": True, "event_id": json.loads(body)["id"], "message": ""}).encode()))
        self.error, self.fail_at = error, fail_at
        self.sock = FakeSock()
        self.requests, self.closed = [], False

    def request(self, method, path, body=None, headers=None):
        if self.fail_at == "request":
            raise self.error
        self.requests.append((method, path, body, dict(headers)))

    def getresponse(self):
        if self.fail_at == "response":
            raise self.error
        return FakeResp(*self.answer(self.requests[-1][2]))

    def close(self):
        self.closed = True


def relay(conn=None, key=SEC, expected=PUB, connect=None, **kw):
    conn = conn or FakeConn()
    calls = []

    def default_connect(host, timeout):
        calls.append((host, timeout))
        return conn
    r = transport.Relay(URL, (key if callable(key) else lambda: key), expected_pubkey=expected,
                        connect=connect or default_connect, clock=lambda: NOW, **kw)
    return r, conn, calls


def sent(conn):
    method, path, body, headers = conn.requests[-1]
    return method, path, json.loads(body), body, headers


def nip98(headers):
    scheme, b64 = headers["Authorization"].split(" ", 1)
    assert scheme == "Nostr"
    return json.loads(base64.b64decode(b64))


def test_a_root_is_a_signed_kind_9_with_the_channel_tag():
    r, conn, calls = relay()
    res = r.send(CH, "CRITICAL: x")
    method, path, ev, body, headers = sent(conn)
    assert (method, path, calls) == ("POST", "/events", [("relay.example.net", transport.CONNECT_TIMEOUT)])
    assert ev["kind"] == 9 and ev["tags"] == [["h", CH]] and ev["content"] == "CRITICAL: x"
    assert ev["pubkey"] == PUB and ev["created_at"] == NOW and nostr.verify_event(ev)
    assert (res.ok, res.outcome, res.event_id, res.exit_code) == (True, "ok", ev["id"], 200)
    assert conn.closed and conn.sock.timeout == transport.IO_TIMEOUT
    assert headers["Content-Type"] == "application/json" and headers["Content-Length"] == str(len(body))


def test_a_reply_is_a_direct_reply_to_its_root():
    r, conn, _ = relay()
    r.send(CH, "lang: ja\nx", ROOT)
    assert sent(conn)[2]["tags"] == [["h", CH], ["e", ROOT, "", "reply"]]


def test_the_nip98_header_binds_url_method_and_body():
    r, conn, _ = relay()
    r.send(CH, "x")
    _, _, ev, body, headers = sent(conn)
    auth = nip98(headers)
    assert auth["kind"] == 27235 and auth["pubkey"] == PUB and auth["created_at"] == NOW
    assert nostr.verify_event(auth) and auth["content"] == ""
    tags = {t[0]: t[1:] for t in auth["tags"]}
    assert tags["u"] == ["https://relay.example.net/events"] and tags["method"] == ["POST"]
    assert tags["payload"] == [hashlib.sha256(body).hexdigest()]
    assert len(tags["nonce"][0]) == 32
    r.send(CH, "x")
    assert nip98(conn.requests[-1][3])["id"] != auth["id"]  # a fresh nonce each send: no replay refusal


@pytest.mark.parametrize("status, body, outcome", [
    (200, {"accepted": True, "event_id": "SAME", "message": ""}, "ok"),
    (200, {"accepted": True, "event_id": "SAME", "message": "duplicate:"}, "ok"),
    (200, {"accepted": False, "event_id": "SAME", "message": "duplicate: already have it"}, "ok"),
    (200, {"accepted": False, "message": "duplicate:"}, "ok"),
    (200, {"accepted": False, "event_id": "cd" * 32, "message": "duplicate:"}, "unknown"),
    (200, {"accepted": True, "event_id": "cd" * 32, "message": ""}, "unknown"),
    (200, {"accepted": False, "message": "rate-limited: slow down"}, "failed"),
    (200, {"event_id": "SAME"}, "unknown"),
    (200, b"<html>proxy</html>", "unknown"),
    (200, [1], "unknown"),
    (400, {"error": "invalid: content too long"}, "refused"),
    (400, {"error": "restricted: relay-only kind"}, "failed"),
    (400, {"error": "invalid JSON"}, "failed"),
    (400, b"<html>Bad Request</html>", "failed"),
    (401, {"error": "NIP-98: created_at too far"}, "failed"),
    (403, {"error": "not a relay member"}, "failed"),
    (404, {"error": "no community"}, "failed"),
    (429, {"error": "slow down"}, "failed"),
    (413, b"", "refused"),
    (408, b"", "unknown"),
    (500, {"error": "internal server error"}, "unknown"),
    (502, b"Bad Gateway", "unknown"),
])
def test_every_answer_has_one_outcome(status, body, outcome):
    def answer(sent_body):
        eid = json.loads(sent_body)["id"]
        if isinstance(body, bytes):
            return status, body
        return status, json.dumps(body).replace('"SAME"', json.dumps(eid)).encode()
    r, conn, _ = relay(FakeConn(answer))
    res = r.send(CH, "x")
    assert res.outcome == outcome and res.ok == (outcome == "ok") and res.exit_code == status
    assert (res.event_id is not None) == (outcome == "ok")
    if outcome == "refused":
        assert res.message
    assert conn.closed


def test_a_refusal_message_is_printable_and_bounded():
    r, _, _ = relay(FakeConn(lambda b: (400, json.dumps({"error": "invalid: \x1b[31mbad\n" + "x" * 900}).encode())))
    res = r.send(CH, "x")
    assert res.outcome == "refused" and res.message.startswith("invalid: ?[31mbad x")
    assert len(res.message) <= 300 and res.message.isprintable()


def test_a_body_past_the_cap_is_unknown():
    r, _, _ = relay(FakeConn(lambda b: (200, b"{" + b" " * transport.MAX_RESPONSE + b"}")))
    assert r.send(CH, "x").outcome == "unknown"


def test_a_connect_failure_is_failed_and_nothing_was_written():
    def connect(host, timeout):
        raise ConnectionRefusedError("refused")
    r, conn, _ = relay(connect=connect)
    res = r.send(CH, "x")
    assert res.outcome == "failed" and "connect failed" in res.stderr and conn.requests == []


@pytest.mark.parametrize("fail_at", ["request", "response"])
@pytest.mark.parametrize("error", [TimeoutError("timed out"), ConnectionResetError("reset"), BrokenPipeError("pipe")])
def test_a_failure_once_the_request_began_is_unknown(fail_at, error):
    r, conn, _ = relay(FakeConn(error=error, fail_at=fail_at))
    res = r.send(CH, "x")
    assert res.outcome == "unknown" and conn.closed


def test_a_stalled_response_ends_at_the_deadline_as_unknown():
    release = threading.Event()

    class Stalled(FakeConn):
        def getresponse(self):
            release.wait(5)
            return super().getresponse()
    r, conn, _ = relay(Stalled(), deadline=0.2)
    t0 = time.monotonic()
    res = r.send(CH, "x")
    release.set()
    assert res.outcome == "unknown" and time.monotonic() - t0 < 2


def test_a_dripped_response_ends_at_the_deadline_as_unknown():
    class Drip(FakeResp):
        def read(self, n=-1):
            out = b""
            for ch in b'{"accepted": true}':
                time.sleep(0.05)
                out += bytes([ch])
            return out

    class Conn(FakeConn):
        def getresponse(self):
            return Drip(200, b"")
    r, _, _ = relay(Conn(), deadline=0.2)
    assert r.send(CH, "x").outcome == "unknown"


def test_a_connect_that_finishes_after_the_deadline_never_writes():
    go = threading.Event()
    conn = FakeConn()

    def slow_connect(host, timeout):
        go.wait(5)
        return conn

    r, _, _ = relay(conn, connect=slow_connect, deadline=0.1)
    res = r.send(CH, "x")
    assert res.outcome == "failed"
    go.set()
    time.sleep(0.2)  # the worker reaches the gate, finds it cancelled, and closes
    assert conn.requests == [] and conn.closed


def test_the_key_is_read_once_and_never_shown():
    reads = []

    def source():
        reads.append(1)
        return SEC
    r, conn, _ = relay(key=source)
    a, b = r.send(CH, "x"), r.send(CH, "y")
    assert reads == [1] and a.ok and b.ok
    for res in (a, b):
        assert SEC not in repr(res)
    assert all(SEC not in json.dumps(req[3]) and SEC.encode() not in req[2] for req in conn.requests)


def test_an_nsec_key_is_accepted():
    r, _, _ = relay(key=nostr.nsec(SEC))
    assert r.send(CH, "x").ok


@pytest.mark.parametrize("key", ["", "zz", "00" * 32, "nsec1notakey"])
def test_a_key_that_is_not_a_secret_key_sends_nothing(key):
    r, conn, calls = relay(key=key)
    res = r.send(CH, "x")
    assert res.outcome == "failed" and conn.requests == [] and calls == []
    assert key not in res.stderr or not key


def test_a_key_that_is_not_the_relay_bot_sends_nothing():
    r, conn, calls = relay(key=OTHER_SEC)
    res = r.send(CH, "x")
    assert res.outcome == "failed" and "relay-bot" in res.stderr and calls == [] and OTHER_SEC not in res.stderr


def test_an_unavailable_key_is_failed_without_its_text():
    def source():
        raise transport.KeyUnavailable("get_secret exit 1")
    r, _, calls = relay(key=source)
    res = r.send(CH, "x")
    assert res.outcome == "failed" and "relay key unavailable: get_secret exit 1" == res.stderr and calls == []

    def leaky():
        raise RuntimeError(SEC)  # anything else a helper raises is never echoed
    r, _, _ = relay(key=leaky)
    res = r.send(CH, "x")
    assert res.outcome == "failed" and SEC not in res.stderr


@pytest.mark.parametrize("args", [("not-a-uuid", "x", None), (CH, "", None), (CH, "a\x00b", None),
                                  (CH, "x" * (transport.MAX_CONTENT + 1), None), (CH, "x", "AB" * 32),
                                  (CH, "x", "ab"), (CH, 3, None)])
def test_malformed_sends_raise_before_anything_runs(args):
    r, conn, calls = relay()
    with pytest.raises(ValueError):
        r.send(*args)
    with pytest.raises(ValueError):
        transport.check_send(*args)
    assert calls == [] and conn.requests == []


@pytest.mark.parametrize("url", ["http://relay.example.net", "https://relay.example.net/", "https://relay.example.net/x",
                                 "https://u@relay.example.net", "https://relay.example.net:444", "https://RELAY.example.net",
                                 "https://localhost", "https://relay.example.net?x", "", None])
def test_the_relay_url_is_https_and_a_host_only(url):
    with pytest.raises(ValueError):
        transport.check_url(url)


def test_the_real_connect_is_blocked_in_tests():
    r = transport.Relay(URL, lambda: SEC, expected_pubkey=PUB, clock=lambda: NOW)
    res = r.send(CH, "x")
    assert res.outcome == "failed" and "connect failed" in res.stderr


# ---------------------------------------------------------------- the claim tag (hh5s)

def _claim_tag():
    from aitools_alerts import schema, wire
    v = json.loads((schema.SPEC_DIR / "claim-vectors.json").read_text(encoding="utf-8"))["claims"][0]
    return wire.claim_tag(v["claim"]), v["claim"]


def test_message_event_carries_one_claim_tag_last_and_is_unchanged_without_one():
    tag, _ = _claim_tag()
    ev = transport.message_event(CH, "x", ROOT, created_at=NOW, claim=tag)
    assert ev["tags"] == [["h", CH], ["e", ROOT, "", "reply"], tag]
    assert transport.message_event(CH, "x", None, created_at=NOW, claim=tag)["tags"] == [["h", CH], tag]
    plain = transport.message_event(CH, "x", ROOT, created_at=NOW)
    assert plain == transport.message_event(CH, "x", ROOT, created_at=NOW, claim=None)
    assert plain == {"created_at": NOW, "kind": 9, "tags": [["h", CH], ["e", ROOT, "", "reply"]], "content": "x"}


@pytest.mark.parametrize("bad", [["claim"], ["claim", "{}", "x"], ["claim", '{"b":1, "a":2}'], ["claim", '{"b":1,"a":2}'],
                                 ["claim", "[]"], ["other", "{}"], ["claim", json.dumps({"a": "x" * 2100})],
                                 "claim", ("claim", "{}"), [["claim", "{}"]], ["claim", 7], {}, 0])
def test_check_send_refuses_what_claim_tag_would_not_write(bad):
    with pytest.raises(ValueError):
        transport.check_send(CH, "x", None, bad)
    with pytest.raises(ValueError):
        transport.message_event(CH, "x", None, created_at=NOW, claim=bad)


def test_relay_send_signs_the_claim_and_dates_the_event_by_its_own_clock():
    from aitools_alerts import wire
    tag, obj = _claim_tag()
    r, conn, _ = relay()
    res = r.send(CH, "Level is now notice.", ROOT, tag)
    ev = sent(conn)[2]
    assert res.ok and nostr.verify_event(ev) and wire.claim_of(ev) == obj
    assert ev["tags"] == [["h", CH], ["e", ROOT, "", "reply"], tag] and ev["created_at"] == NOW
    forged = {**ev, "tags": [["h", CH], ["e", ROOT, "", "reply"], ["claim", tag[1].replace("critical", "notice")]]}
    assert not nostr.verify_event(forged)  # the tag is under the signature
    r, conn, _ = relay()
    with pytest.raises(ValueError):
        r.send(CH, "x", ROOT, ["claim", "{}x"])
    assert conn.requests == []
