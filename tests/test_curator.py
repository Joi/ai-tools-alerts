"""The curator subcommand: events the readers accept, a private key, NIP-42."""

import json
import sys
import threading
import time

import pytest

from aitools_alerts import cli, config, curator, nostr, pull, relay, schema
from aitools_alerts.schema import Action
from aitools_alerts.state import State
from mirror_helpers import T0, Mirror

NOW = T0 + 300
FEED = "599adb9f-4f9f-4b19-aee3-66667c3293e8"
CRITICAL = "ac446e7a-1e2c-4d74-ac8d-9c16ecb3801b"
PRIMARY = "https://osv.dev/vulnerability/GHSA-test-0001"


def no_connect(*a):
    pytest.fail("connected")


@pytest.fixture
def mirror(home, monkeypatch):
    m = Mirror()
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    return m


def write_key(text, mode=0o600):
    p = config.key_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text + "\n")
    p.chmod(mode)
    return p


def pulled(m: Mirror) -> State:
    st = State.load()
    res = pull.fetch("https://mirror.example.invalid/alerts", st, fetch=m.fetch, root_pubkey=m.root)
    assert res.error is None
    return st


def thread_of(m: Mirror, root_id: str):
    return [t for t in pull.advisories(pulled(m)) if t.root_id == root_id][0]


def post(m, **over):
    kw = dict(level="high", title="Invented high for tests", product="Claude Code",
              ecosystem="claude-code", affected="<99.0.0", fixed=None,
              actions=[Action("review_setting", "Claude Code", None)], sources=[PRIMARY], now=NOW)
    kw.update(over)
    return curator.post_events(m.cur_sec, pulled(m).manifest, m.root, **kw)


def publish(m, *evs):
    for ev in evs:
        m.events["feed.json"].append(ev)
    return evs[0]


def amend(m, root, now=NOW + 5, **kw):
    st = pulled(m)
    [(t, root_ev)] = curator.find_threads(st, m.root, root["id"])
    return curator.amend_event(m.cur_sec, st.manifest, m.root, st, t, root_ev, now=now, **kw)


def retract(m, root, now=NOW + 1, **kw):
    st = pulled(m)
    [(t, root_ev)] = curator.find_threads(st, m.root, root["id"])
    return curator.retract_event(m.cur_sec, st.manifest, m.root, st, t, root_ev, now=now, **kw)


def test_post_event_has_block_and_h_tag(mirror):
    [ev] = post(mirror)
    assert ev["kind"] == 9 and ev["tags"] == [["h", FEED]] and nostr.verify_event(ev)
    adv = schema.parse_post(ev["content"])
    assert adv.level == "high" and adv.posted_by == "curator" and adv.posted_at == NOW
    assert ev["content"].startswith("HIGH: Invented high for tests\n")
    crit = post(mirror, level="critical")  # the interrupt channel, and the feed stays complete
    assert [e["tags"] for e in crit] == [[["h", CRITICAL]], [["h", FEED]]]
    assert [e["tags"] for e in post(mirror, level="critical", channel="feed")] == [[["h", FEED]]]
    t = thread_of(mirror, publish(mirror, ev)["id"])
    assert t.adv == adv and not t.retracted
    with pytest.raises(curator.CuratorError, match="primary-source"):
        post(mirror, sources=["https://example.invalid/blog"])


def test_retract_is_reply_with_convention_text(mirror):
    root = publish(mirror, *post(mirror))
    ev = retract(mirror, root, reason="Withdrawn by the vendor.")
    assert ev["tags"] == [["h", FEED], ["e", root["id"], "", "root"]]
    assert ev["content"] == "retract\nWithdrawn by the vendor."
    publish(mirror, ev)
    assert thread_of(mirror, root["id"]).retracted
    with pytest.raises(curator.CuratorError, match="retracted"):
        curator.find_threads(pulled(mirror), mirror.root, root["id"])


def test_retract_by_advisory_id_covers_both_channels(mirror):
    publish(mirror, *post(mirror, level="critical", adv_id="AITA-TEST-0042"))
    st = pulled(mirror)
    pairs = curator.find_threads(st, mirror.root, "AITA-TEST-0042")
    evs = [curator.retract_event(mirror.cur_sec, st.manifest, mirror.root, st, t, r, now=NOW + 1)
           for t, r in pairs]
    assert sorted(e["tags"][0][1] for e in evs) == sorted([CRITICAL, FEED])
    publish(mirror, *evs)
    assert all(t.retracted for t in pull.advisories(pulled(mirror)))


def test_amend_patch_validates_before_send(mirror):
    root = publish(mirror, *post(mirror, actions=[Action("upgrade", "Claude Code", None)]))
    ev = amend(mirror, root, fixed="99.0.1", sources=["https://example.invalid/fix"])
    patch = json.loads(schema._last_block(ev["content"]))
    assert set(patch) == {"products", "actions", "sources"}  # changed fields only
    assert ev["tags"][1] == ["e", root["id"], "", "root"]
    publish(mirror, ev)
    adv = thread_of(mirror, root["id"]).adv
    assert adv.products[0].fixed == "99.0.1" and adv.actions[0].value == "99.0.1"
    for bad in (dict(fixed="not a version"), dict(expires_at=T0), dict(title="")):
        with pytest.raises(curator.CuratorError, match="not valid"):
            amend(mirror, root, **bad)
    with pytest.raises(curator.CuratorError, match="nothing to change"):
        amend(mirror, root, level="high")


def test_amend_lower_uses_convention_line_and_raise_uses_patch(mirror):
    root = publish(mirror, *post(mirror, level="critical", channel="feed"))
    ev = amend(mirror, root, level="notice", note="Lowered after review.")
    assert ev["content"].split("\n")[0] == "level: notice"
    assert pull._patch(ev["content"]) is None  # convention text only
    publish(mirror, ev)
    assert thread_of(mirror, root["id"]).adv.level == "notice"
    up = amend(mirror, root, now=NOW + 6, level="high", note="retract")  # a note is never the first line
    assert up["content"].startswith("Amended: ") and json.loads(
        schema._last_block(up["content"])) == {"level": "high"}
    publish(mirror, up)
    t = thread_of(mirror, root["id"])
    assert t.adv.level == "high" and not t.retracted
    for note in ("ok\nretract", "```aitools-alert", "~~~", "x" * 501):
        with pytest.raises(curator.CuratorError, match="one line"):
            amend(mirror, root, level="critical", note=note)


def test_amend_sorts_after_the_replies_it_saw(mirror):
    root = publish(mirror, *post(mirror, actions=[Action("upgrade", "Claude Code", None)]))
    publish(mirror, amend(mirror, root, now=NOW + 50, title="Seen amendment"))  # a skewed clock
    ev = amend(mirror, root, now=NOW + 10, fixed="99.0.2")
    assert ev["created_at"] == NOW + 51
    publish(mirror, ev)
    adv = thread_of(mirror, root["id"]).adv
    assert adv.title == "Seen amendment" and adv.products[0].fixed == "99.0.2"


def test_send_refuses_without_curator_role(mirror):
    st = pulled(mirror)
    with pytest.raises(curator.CuratorError, match="no curator role"):
        curator.post_events(mirror.bot_sec, st.manifest, mirror.root, level="high", title="t",
                            product="p", ecosystem="claude-code", sources=[PRIMARY])
    [ev] = post(mirror)
    bot_ev = nostr.sign_event(mirror.bot_sec, {k: ev[k] for k in ("created_at", "kind", "tags", "content")})
    tampered = {**ev, "content": ev["content"] + " "}
    for e, sec, why in ((bot_ev, mirror.bot_sec, "no curator role"),
                        (ev, mirror.bot_sec, "no curator role"),
                        (bot_ev, mirror.cur_sec, "not signed by the curator key"),
                        (tampered, mirror.cur_sec, "not signed by the curator key")):
        with pytest.raises(relay.RelayError, match=why):
            relay.send(e, "ws://127.0.0.1:1", sec, manifest=st.manifest, root_pubkey=mirror.root,
                       connect=no_connect)
    other_root = nostr.keygen()[1]  # the right curator, a manifest from another root
    with pytest.raises(relay.RelayError, match="trust root"):
        relay.send(ev, "ws://127.0.0.1:1", mirror.cur_sec, manifest=st.manifest,
                   root_pubkey=other_root, connect=no_connect)


def test_manifest_and_threads_come_from_the_requested_root(mirror):
    root = publish(mirror, *post(mirror))
    v1 = pulled(mirror).accepted(mirror.root)
    mirror.publish_manifest(posters=[{"pubkey": mirror.bot, "role": "relay-bot", "name": "bot"}])
    st = pulled(mirror)  # v2 revokes the curator
    test_root = Mirror()
    pull.fetch("https://x.invalid/", st, fetch=test_root.fetch, root_pubkey=test_root.root)
    assert st.manifest_root == test_root.root
    m = curator.role_manifest(st, mirror.root)
    assert m.version == v1.version + 1  # never rolled back by another root's pull
    with pytest.raises(curator.CuratorError, match="no curator role"):
        curator.post_events(mirror.cur_sec, m, mirror.root, level="high", title="t", product="p",
                            ecosystem="claude-code", sources=[PRIMARY])
    with pytest.raises(curator.CuratorError, match="not pulled under this trust root"):
        curator.find_threads(st, mirror.root, root["id"])


def test_ws_url_must_be_wss_or_loopback():
    assert relay.check_url("wss://buzz.ai-tools.md") and relay.check_url("ws://localhost:7000")
    for bad in ("ws://buzz.ai-tools.md", "https://buzz.ai-tools.md", "wss://", "nonsense"):
        with pytest.raises(relay.RelayError):
            relay.check_url(bad)


POST_ARGV = ["curator", "post", "--level", "high", "--title", "Invented", "--product",
             "Claude Code", "--ecosystem", "claude-code", "--source", PRIMARY]


def test_key_file_must_be_private_and_never_printed(mirror, capsys):
    pulled(mirror)
    nsec = nostr.nsec(mirror.cur_sec)
    argv = POST_ARGV + ["--dry-run"]
    bad = [(nsec, 0o644), (nsec[:-1] + ("q" if nsec[-1] != "q" else "p"), 0o600),
           (mirror.cur_sec[:-1], 0o600), ("0" * 64, 0o600), (mirror.cur_sec.upper(), 0o600)]
    for text, mode in bad:
        write_key(text, mode)
        assert cli.main(argv) == 1
    write_key(mirror.cur_sec)  # hex is accepted as well as nsec
    assert cli.main(argv) == 0
    out = capsys.readouterr()
    assert "not private" in out.err and out.err.count("not a valid nsec") == 4
    for secret in (nsec[5:30], mirror.cur_sec[:24], mirror.cur_sec.upper()[:24]):
        assert secret not in out.out + out.err
    [ev] = json.loads(out.out)
    assert nostr.verify_event(ev) and ev["pubkey"] == mirror.cur


def test_cli_amend_and_retract_dry_run(mirror, capsys):
    root = publish(mirror, *post(mirror))
    pulled(mirror)
    write_key(nostr.nsec(mirror.cur_sec))
    assert cli.main(["curator", "amend", "AITA-NOPE", "--no-pull"]) == 1
    assert cli.main(["curator", "amend", root["id"], "--no-pull", "--dry-run", "--level", "notice"]) == 0
    assert cli.main(["curator", "retract", root["id"], "--no-pull", "--dry-run"]) == 0
    out = capsys.readouterr()
    assert "run: aitools-alerts pull" in out.err
    assert '"content": "level: notice' in out.out and '"content": "retract"' in out.out


def test_missing_websockets_prints_install_hint(mirror, capsys, monkeypatch):
    pulled(mirror)
    write_key(nostr.nsec(mirror.cur_sec))
    monkeypatch.setitem(sys.modules, "websockets.sync.client", None)
    assert cli.main(POST_ARGV + ["--relay-url", "ws://127.0.0.1:1"]) == 1
    assert "pip install 'aitools-alerts[curator]'" in capsys.readouterr().err


class FakeWs:
    def __init__(self, script, stall_send=False):
        self.script, self.sent, self.stall_send = list(script), [], stall_send

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send(self, text):
        if self.stall_send:
            time.sleep(60)
        self.sent.append(json.loads(text))

    def recv(self, timeout=None):
        if not self.script:
            raise TimeoutError
        nxt = self.script.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt if isinstance(nxt, str) else json.dumps(nxt(self.sent) if callable(nxt) else nxt)


def test_relay_failures_are_bounded_errors(mirror, capsys, monkeypatch):
    st = pulled(mirror)
    [ev] = post(mirror)

    def go(ws, timeout=2):
        return relay.send(ev, "ws://127.0.0.1:1", mirror.cur_sec, manifest=st.manifest,
                          root_pubkey=mirror.root, connect=lambda *a: ws, timeout=timeout)
    ws = FakeWs([["AUTH", "c"], lambda sent: ["OK", sent[-1][1]["id"], False, "restricted: no"]])
    with pytest.raises(relay.RelayError, match="refused AUTH"):
        go(ws)
    assert len(ws.sent) == 1  # the event was never sent
    for script, why in (([["NOTICE", "hi"]], "no AUTH"), (["not json"], "not JSON"),
                        ([ConnectionResetError("x")], "ConnectionResetError")):
        with pytest.raises(relay.RelayError, match=why):
            go(FakeWs(script))
    monkeypatch.setattr(relay, "GRACE", 0.3)
    t0 = time.monotonic()
    with pytest.raises(relay.RelayError, match="did not finish"):
        go(FakeWs([["AUTH", "c"]], stall_send=True), timeout=0.2)
    assert time.monotonic() - t0 < 10
    # through the CLI: exit 1, one line, no traceback, no key
    write_key(nostr.nsec(mirror.cur_sec))
    monkeypatch.setattr(relay, "_default_connect", lambda url, timeout: FakeWs(
        [["AUTH", "c"], lambda sent: ["OK", sent[-1][1]["id"], False, "auth-required: no"]]))
    assert cli.main(POST_ARGV + ["--relay-url", "ws://127.0.0.1:1"]) == 1
    err = capsys.readouterr().err
    assert "refused AUTH" in err and "Traceback" not in err and mirror.cur_sec[:24] not in err


def test_nip42_auth_then_event_ok(mirror):
    pytest.importorskip("websockets")
    from websockets.sync.server import serve

    st = pulled(mirror)
    [ev] = post(mirror)
    got = []

    def handler(conn):
        conn.send(json.dumps(["AUTH", "challenge-1"]))
        auth = json.loads(conn.recv())
        got.append(auth)
        ok = (auth[0] == "AUTH" and auth[1]["kind"] == 22242 and nostr.verify_event(auth[1])
              and ["challenge", "challenge-1"] in auth[1]["tags"])
        conn.send(json.dumps(["OK", auth[1]["id"], ok, ""]))
        msg = json.loads(conn.recv())
        got.append(msg)
        conn.send(json.dumps(["NOTICE", "unrelated"]))
        conn.send(json.dumps(["OK", msg[1]["id"], True, "stored"]))

    with serve(handler, "127.0.0.1", 0) as server:
        url = f"ws://127.0.0.1:{server.socket.getsockname()[1]}"
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            res = relay.send(ev, url, mirror.cur_sec, manifest=st.manifest, root_pubkey=mirror.root)
        finally:
            server.shutdown()
    assert res == (ev["id"], True, "stored")
    assert got[0][1]["pubkey"] == mirror.cur and ["relay", url] in got[0][1]["tags"]
    assert got[1] == ["EVENT", ev]
