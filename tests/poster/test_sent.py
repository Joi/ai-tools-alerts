"""The poster checks its own key (ai-tools-alerts#m729): the sent record."""

import json
import threading

import pytest

from aitools_alerts import nostr
from aitools_alerts.poster import sent
from mirror_helpers import CHANNELS, Mirror, advisory

FEED = frozenset(CHANNELS.values())
NOW = 4070908800 + 5000


def _bot(m, n, **kw):
    return m.root_post(m.bot_sec, advisory(id=f"AITA-TEST-{n:04d}", posted_by="relay-bot"), files=("feed.json",), **kw)


def _events(m):
    return {e["id"]: e for evs in m.events.values() for e in evs}.values()


def _rec(path):
    return json.loads(path.read_text())


def test_nothing_is_judged_or_written_before_the_record_is_started(tmp_path):
    m, path = Mirror(), tmp_path / "sent.json"
    _bot(m, 1)
    assert sent.check(path, _events(m), m.man, NOW, channels=FEED) == set()
    assert not path.exists() and sent.unsaid(path) == [] and sent.holds(path) == set()


def test_the_start_takes_what_it_is_handed_and_nothing_because_it_is_on_the_mirror(tmp_path, capsys):
    m, path = Mirror(), tmp_path / "sent.json"
    mine, forged = _bot(m, 1), _bot(m, 2)
    got = sent.check(path, _events(m), m.man, NOW, adopt={mine["id"], "not an id"}, channels=FEED)
    assert got == {forged["id"]}
    rec = _rec(path)
    assert rec["since"] == NOW and rec["ids"] == {mine["id"]: NOW} and rec["foreign"] == {forged["id"]: NOW}
    assert "started with 1 ids" in capsys.readouterr().err
    assert sent.check(path, _events(m), m.man, NOW + 60, adopt={forged["id"]}, channels=FEED) == {forged["id"]}
    assert _rec(path)["foreign"] == {forged["id"]: NOW}  # started once; the first sight is kept


def test_only_a_relay_bot_event_in_an_alert_channel_is_judged(tmp_path):
    m, path = Mirror(), tmp_path / "sent.json"
    sent.check(path, [], m.man, NOW, adopt=set(), channels=FEED)
    cur = m.root_post(m.cur_sec, advisory())
    other = m.post(m.bot_sec, "elsewhere", h="00000000-0000-4000-8000-000000000000")
    stranger = m.post(nostr.keygen()[0], "nobody")
    forged = _bot(m, 3)
    assert sent.check(path, _events(m), m.man, NOW, channels=FEED) == {forged["id"]}
    assert {cur["id"], other["id"], stranger["id"]}.isdisjoint(_rec(path)["foreign"])


def test_a_noted_id_is_never_foreign_and_is_kept_for_good(tmp_path):
    m, path = Mirror(), tmp_path / "sent.json"
    sent.check(path, [], m.man, NOW, adopt=set(), channels=FEED)
    ev = _bot(m, 4)
    sent.note(path, ev["id"], NOW)
    sent.note(path, "nonsense", NOW)
    assert sent.check(path, _events(m), m.man, NOW + 1, channels=FEED) == set()
    assert sent.check(path, [], m.man, NOW + 500 * 86400, channels=FEED) == set()
    assert _rec(path)["ids"] == {ev["id"]: NOW}  # not on the mirror, 500 days on: still the poster's
    assert sent.holds(path) == {ev["id"]}


def test_the_line_is_owed_once_per_event_until_it_is_recorded_or_gone(tmp_path):
    m, path = Mirror(), tmp_path / "sent.json"
    sent.check(path, [], m.man, NOW, adopt=set(), channels=FEED)
    a, b = _bot(m, 5), _bot(m, 6)
    sent.check(path, _events(m), m.man, NOW, channels=FEED)
    assert sent.unsaid(path) == sorted([a["id"], b["id"]])
    sent.mark_said(path, [a["id"], "f" * 64])
    assert sent.unsaid(path) == [b["id"]] and _rec(path)["said"] == [a["id"]]
    sent.note(path, b["id"], NOW)  # it was the poster's after all (a send settled late)
    assert sent.unsaid(path) == []
    m.events["feed.json"].remove(a)  # gone from the mirror, then back: said again
    sent.check(path, _events(m), m.man, NOW + 1, channels=FEED)
    assert _rec(path)["said"] == [] and _rec(path)["foreign"] == {}
    m.events["feed.json"].append(a)
    sent.check(path, _events(m), m.man, NOW + 2, channels=FEED)
    assert sent.unsaid(path) == [a["id"]]


@pytest.mark.parametrize("damage", ["not json", '{"since": 1, "ids": {}}', '{"since": "x", "ids": {}, "foreign": {}, "said": []}',
                                    '{"since": 1, "ids": {"zz": 1}, "foreign": {}, "said": []}'])
def test_a_damaged_record_starts_again_from_what_it_is_handed(tmp_path, capsys, damage):
    m, path = Mirror(), tmp_path / "sent.json"
    mine, forged = _bot(m, 7), _bot(m, 8)
    sent.check(path, _events(m), m.man, NOW, adopt={mine["id"]}, channels=FEED)
    path.write_text(damage)
    capsys.readouterr()
    assert sent.check(path, _events(m), m.man, NOW + 5, channels=FEED) == set()  # nothing judged, nothing adopted
    assert "is unreadable; started again" in capsys.readouterr().err
    assert sent.check(path, _events(m), m.man, NOW + 9, adopt={mine["id"]}, channels=FEED) == {forged["id"]}


def test_a_record_that_cannot_be_written_still_gives_the_answer(tmp_path, monkeypatch, capsys):
    m, path = Mirror(), tmp_path / "sent.json"
    mine, forged = _bot(m, 9), _bot(m, 10)

    def boom(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(sent, "write_json", boom)
    assert sent.check(path, _events(m), m.man, NOW, adopt={mine["id"]}, channels=FEED) == {forged["id"]}
    assert "not written" in capsys.readouterr().err
    with pytest.raises(OSError):
        sent.note(path, mine["id"], NOW)


def test_two_writers_lose_no_id(tmp_path):
    path = tmp_path / "sent.json"

    def work(k):
        for i in range(40):
            sent.note(path, f"{k * 1000 + i:064x}", NOW)
    threads = [threading.Thread(target=work, args=(k,)) for k in (1, 2, 3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(_rec(path)["ids"]) == 120


# ---------------------------------------------------------------- the signer leaves foreign events out

from dataclasses import replace  # noqa: E402

from aitools_alerts import pull  # noqa: E402
from aitools_alerts.poster import main, signer, transport  # noqa: E402
from aitools_alerts.state import State  # noqa: E402
from test_main import T0, FakeRelay, at, env, finding  # noqa: E402,F401 - env is a fixture
from test_signer import (PutRelay, _claim, _reader_pull, _renewal, on_mirror, owed_ids,  # noqa: E402,F401
                         signing)

HOUR = 3600


def _forged(m, n=1, when=T0 + 100, **kw):
    """A relay-bot root the poster never signed: what a thief of the key posts."""
    return m.root_post(m.bot_sec, advisory(id=f"CVE-2026-90{n:02d}", title="Forged", posted_by="relay-bot"),
                       created_at=when, files=("feed.json",), **kw)


def _token(summary):
    return summary.split(" checkpoint=")[1].split()[0]


def _stored(env):  # noqa: F811
    return State.load(env.config.mirror_dir).events_for(env.mirror.root)


def test_a_relay_bot_event_the_poster_did_not_sign_is_in_no_checkpoint(signing, tmp_path):
    """Acceptance: the forged alert is in no checkpoint and in no member's advisories."""
    m = signing.mirror
    real = on_mirror(m, "A real alert", T0 - 500)
    _, summary, ssh = signing.run(relay=PutRelay())
    assert _token(summary) == "sent" and real["id"] in ssh.last().events
    forged = _forged(m)
    answer = m.reply(m.cur_sec, forged, "A curator answers the forgery.", created_at=T0 + 200)
    for hour in (1, 2):
        _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + hour * HOUR)
        assert _token(summary) == "sent,foreign=1"  # it never stops the signing
        listed = ssh.last().events
        assert real["id"] in listed and forged["id"] not in listed and answer["id"] not in listed
    m.clock = T0 + 2 * HOUR
    m.stored_checkpoint = ssh.last().event
    res, st = _reader_pull(m, tmp_path, T0 + 2 * HOUR + 60)
    assert res.error is None
    shown = {t.root_id for t in pull.advisories(st)}
    assert real["id"] in shown and forged["id"] not in shown


def test_the_first_run_takes_what_its_own_checkpoint_listed_and_nothing_because_it_is_served(signing):
    m = signing.mirror
    vouched = on_mirror(m, "Vouched for before the upgrade", T0 - 500, sec=m.bot_sec)
    m.checkpoint()  # the poster's last checkpoint lists it
    forged = _forged(m, when=T0 - 100)  # on the mirror at the first run, in no checkpoint of this key
    _, summary, ssh = signing.run(relay=PutRelay())
    assert _token(summary) == "sent,foreign=1"
    assert vouched["id"] in ssh.last().events and forged["id"] not in ssh.last().events


def test_with_no_checkpoint_of_this_key_served_only_the_ledger_and_the_owed_list_start_the_record(signing):
    m = signing.mirror
    signing.collector([finding()])
    m.raw["checkpoint.json"] = None
    stray = on_mirror(m, "Signed by the bot, known to nobody", T0 - 500, sec=m.bot_sec)
    _, summary, ssh = signing.run(relay=PutRelay())
    assert _token(summary) == "sent,foreign=1" and stray["id"] not in ssh.last().events
    assert set(ssh.ids) <= ssh.last().events  # what this run sent is owed, recorded and listed


def test_losing_the_record_never_brings_back_what_was_left_out(signing):
    m = signing.mirror
    real = on_mirror(m, "A real alert", T0 - 500)
    signing.run(relay=PutRelay())
    forged = _forged(m)
    _, _, ssh = signing.run(relay=PutRelay(), now=T0 + HOUR)
    m.stored_checkpoint = ssh.last().event  # what the exporter serves from now on
    signing.config.sent_state.unlink()
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 2 * HOUR)
    assert _token(summary) == "sent,foreign=1"
    assert forged["id"] not in ssh.last().events and real["id"] in ssh.last().events


def test_a_foreign_reply_is_left_out_of_a_real_thread(signing):
    m = signing.mirror
    root = on_mirror(m, "A real alert", T0 - 500, sec=m.bot_sec)
    m.checkpoint()
    signing.run(relay=PutRelay())
    lowered = m.reply(m.bot_sec, root, m.patch_text(level="notice"), created_at=T0 + 100)
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + HOUR)
    assert _token(summary) == "sent,foreign=1"
    assert root["id"] in ssh.last().events and lowered["id"] not in ssh.last().events


def test_a_reply_still_owed_to_a_foreign_root_is_not_listed(signing):
    m = signing.mirror
    signing.run(relay=PutRelay())
    forged = _forged(m)
    signer.record_sent(signing.config.owed_state, "ab" * 32, 300, forged["id"], T0 + 200)
    _, _, ssh = signing.run(relay=PutRelay(), now=T0 + HOUR)
    assert "ab" * 32 not in ssh.last().events and "ab" * 32 in owed_ids(signing)


def test_a_foreign_renewal_keeps_no_lapsed_thread_listed(signing):
    """A claimed critical root, 20 days old and never renewed, has lapsed. A renewal
    under the bot's key that the poster did not sign must not make it read as standing."""
    m, days = signing.mirror, 86400
    root = m.root_post(m.bot_sec, advisory(id="CVE-2026-0001", posted_by="relay-bot"), created_at=T0 - 20 * days,
                       tags=[_claim(T0 - 20 * days)], files=("feed.json",))
    m.checkpoint()
    _, summary, ssh = signing.run(relay=PutRelay())
    assert "threads_suppressed=1" in summary and root["id"] not in ssh.last().events
    fake = _renewal(m, root, T0 + 100)
    assert signer.lapsed([e for evs in m.events.values() for e in evs], m.man, T0 + HOUR) == set()  # it would stand
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + HOUR)
    assert "threads_suppressed=1,foreign=1" in summary
    assert root["id"] not in ssh.last().events and fake["id"] not in ssh.last().events


def test_a_foreign_event_the_mirror_stops_serving_leaves_the_store(signing):
    m = signing.mirror
    signing.run(relay=PutRelay())
    forged = _forged(m)
    signing.run(relay=PutRelay(), now=T0 + HOUR)
    assert forged["id"] in _stored(signing)  # served: kept, as evidence
    m.events["feed.json"].remove(forged)
    _, summary, _ = signing.run(relay=PutRelay(), now=T0 + 2 * HOUR)
    assert forged["id"] not in _stored(signing)
    _, summary, _ = signing.run(relay=PutRelay(), now=T0 + 3 * HOUR)
    assert _token(summary) == "sent"


def test_foreign_events_cannot_hold_the_store_at_its_limit(signing, monkeypatch):
    m = signing.mirror
    real = on_mirror(m, "A real alert", T0 - 500)
    signing.run(relay=PutRelay())
    old = [_forged(m, n, when=T0 + n) for n in range(1, 7)]
    signing.run(relay=PutRelay(), now=T0 + HOUR)
    assert all(e["id"] in _stored(signing) for e in old)
    monkeypatch.setattr(pull, "MAX_STORED_EVENTS", len(_stored(signing)) + 1)
    for e in old:  # the thief's batch is replaced by another one, larger than the room left
        m.events["feed.json"].remove(e)
    new = [_forged(m, n, when=T0 + n) for n in range(10, 13)]
    late = on_mirror(m, "A real alert posted during the flood", T0 + HOUR + 100)
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 2 * HOUR)
    assert _token(summary) == "sent,foreign=3"
    assert {real["id"], late["id"]} <= ssh.last().events
    assert not {e["id"] for e in old + new} & ssh.last().events
    assert not {e["id"] for e in old} & set(_stored(signing))


# ---------------------------------------------------------------- recorded before the send, settled by id

import datetime as dt  # noqa: E402

from aitools_alerts.poster import compose, inputs  # noqa: E402
from aitools_alerts.poster.ledger import Ledger  # noqa: E402
from test_transport import FakeConn  # noqa: E402


class Dies(BaseException):
    """The process ends here."""


def _sender(env, conn, clock, die=False):  # noqa: F811
    """The real transport over a fake connection, signing with the mirror's bot key and
    writing each id down first, as ``main.relay_sender`` wires it."""
    m = env.mirror
    send = transport.Relay("https://relay.example.net", lambda: m.bot_sec, expected_pubkey=m.bot,
                           connect=lambda host, timeout: conn, clock=lambda: clock,
                           on_signed=lambda eid: sent.note(env.config.sent_state, eid, clock)).send

    def dying(*a, **kw):
        send(*a, **kw)
        raise Dies  # after the request left, before anything of its result is used
    return dying if die else send


def _taken(m, conn):
    """Put on the mirror what the relay took over ``conn`` and never answered for."""
    out = []
    for _, _, body, _ in conn.requests:
        ev = json.loads(body)
        name = next(k for k, v in CHANNELS.items() if v == next(t[1] for t in ev["tags"] if t[0] == "h"))
        m.events[f"{name}.json"].append(ev)
        out.append(ev)
    return out


def _copy(m, ev, earlier=1):
    """A thief's copy of ``ev``: the same text and tags, signed again, dated earlier."""
    name = next(k for k, v in CHANNELS.items() if v == next(t[1] for t in ev["tags"] if t[0] == "h"))
    copy = nostr.sign_event(m.bot_sec, {"created_at": ev["created_at"] - earlier, "kind": ev["kind"],
                                        "tags": ev["tags"], "content": ev["content"]})
    m.events[f"{name}.json"].append(copy)
    return copy


def _roots(env):  # noqa: F811
    with Ledger(env.config.ledger) as led:
        return led.event_ids()


@pytest.mark.parametrize("how", ["no answer", "the run dies mid-send"])
def test_an_unknown_send_is_settled_by_its_recorded_id_never_by_a_copy_of_its_text(signing, how):
    m = signing.mirror
    signing.run(relay=PutRelay())  # the record is started
    signing.collector([finding()])
    conn = FakeConn(error=TimeoutError("timed out"), fail_at="response")
    if how == "no answer":
        code, _, _ = signing.run(now=T0 + HOUR, relay=_sender(signing, conn, T0 + HOUR), ssh=PutRelay())
        assert code == 1
    else:
        with pytest.raises(Dies):
            signing.run(now=T0 + HOUR, relay=_sender(signing, conn, T0 + HOUR, die=True), ssh=PutRelay())
    (real,) = _taken(m, conn)
    assert real["id"] in json.loads(signing.config.sent_state.read_text())["ids"]  # on disk before the send returned
    assert _roots(signing) == set()
    copy = _copy(m, real)  # the oldest match by text
    _, summary, ssh = signing.run(now=T0 + 2 * HOUR, relay=PutRelay())
    assert real["id"] in _roots(signing) and copy["id"] not in _roots(signing)
    assert ",foreign=1" in summary and "delivered:" in summary
    assert real["id"] in ssh.last().events and copy["id"] not in ssh.last().events


def test_a_lost_record_settles_nothing_from_the_mirror(signing):
    """The relay never took the send; a thief posts its text. With the record the copy is
    foreign. Then the record is lost: the copy must still not become the poster's."""
    m = signing.mirror
    signing.run(relay=PutRelay())
    signing.collector([finding()])
    conn = FakeConn(error=TimeoutError("timed out"), fail_at="response")
    signing.run(now=T0 + HOUR, relay=_sender(signing, conn, T0 + HOUR), ssh=PutRelay())
    (real,) = [json.loads(body) for _, _, body, _ in conn.requests]  # never on the mirror
    copy = _copy(m, real, earlier=0 - 5)
    _, summary, ssh = signing.run(now=T0 + 2 * HOUR, relay=PutRelay())
    assert ",foreign=1" in summary and copy["id"] not in ssh.last().events and _roots(signing) == set()
    m.stored_checkpoint = ssh.last().event
    signing.config.sent_state.unlink()
    _, summary, ssh = signing.run(now=T0 + 3 * HOUR, relay=PutRelay())
    assert _roots(signing) == set() and "delivered:" not in summary
    assert ",foreign=1" in summary and copy["id"] not in ssh.last().events
    assert copy["id"] not in json.loads(signing.config.sent_state.read_text())["ids"]


def test_without_a_checkpoint_key_a_send_is_settled_by_its_text_as_before(env):  # noqa: F811
    from test_settle import run as settle_run, show, unknown_root
    ev = show(env, unknown_root(env))
    settle_run(env, T0 + HOUR)
    assert ev["id"] in _roots(env) and not env.config.sent_state.exists()


def test_a_sent_record_that_cannot_be_written_stops_the_run_from_signing(signing, monkeypatch):
    signing.collector([finding()])
    real = sent.note

    def fails(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(sent, "note", fails)
    code, summary, ssh = signing.run(relay=PutRelay())
    assert code == 1 and _token(summary).startswith("owed-unrecorded") and ssh.puts == []
    monkeypatch.setattr(sent, "note", real)
    code, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 60)
    assert code == 0 and _token(summary) == "sent"
    assert set(json.loads(signing.config.sent_state.read_text())["ids"]) >= set(owed_ids(signing)) != set()


# ---------------------------------------------------------------- the transport hook

def _relay(conn, **kw):
    sec, pub = nostr.keygen()
    calls = []

    def connect(host, timeout):
        calls.append(host)
        return conn
    return transport.Relay("https://relay.example.net", lambda: sec, expected_pubkey=pub, connect=connect,
                           clock=lambda: T0, **kw), calls


def test_the_id_is_handed_over_before_the_connection_is_made():
    conn, seen = FakeConn(), []
    r, calls = _relay(conn, on_signed=lambda eid: seen.append((eid, list(calls))))
    res = r.send(CHANNELS["feed"], "text")
    assert res.outcome == "ok" and seen == [(res.event_id, [])] and len(calls) == 1
    assert json.loads(conn.requests[0][2])["id"] == res.event_id


def test_an_id_that_cannot_be_written_down_is_not_sent():
    conn = FakeConn()

    def refuse(eid):
        raise OSError(28, "No space left on device")
    r, calls = _relay(conn, on_signed=refuse)
    res = r.send(CHANNELS["feed"], "text")
    assert (res.outcome, res.event_id, calls, conn.requests) == ("failed", None, [], [])
    assert "sent record" in res.stderr


def test_the_real_sender_writes_ids_down_only_with_a_checkpoint_key(tmp_path, monkeypatch):
    seen = {}

    class Relay:
        def __init__(self, url, key_source, *, expected_pubkey, **kw):
            seen.update(kw)

        def send(self, *a):
            raise AssertionError("not sent in this test")
    monkeypatch.setattr(main.transport, "Relay", Relay)
    base = dict(ledger=tmp_path / "l.json", relay_url="https://relay.example.net", relay_key_secret="RELAY_TEST_NSEC",
                secrets_helper=tmp_path / "secrets.sh")
    main.relay_sender(inputs.Config(**base))
    assert seen == {}
    key = tmp_path / "ck.nsec"
    config = inputs.Config(**base, checkpoint_key_file=key, relay_ssh_host="op@relay.example.net",
                           relay_put_wrapper="/opt/relay/bin/mirror-put")
    main.relay_sender(config)
    seen["on_signed"]("cd" * 32)
    assert "cd" * 32 in json.loads(config.sent_state.read_text())["ids"]


# ---------------------------------------------------------------- the digest says it once

LINE = {"en": "Warning: an event signed with this service's key was not sent by this service. "
              "No checkpoint lists it, so the CLI does not apply it.",
        "ja": "警告: このサービスの鍵で署名され、このサービスが送信していないイベントがあります。"
              "チェックポイントに載せていないため、CLI はこれを適用しません。"}


def test_the_line_is_fixed_and_absent_unless_asked_for():
    day, adv = dt.date(2026, 11, 5), advisory(posted_by="relay-bot", sources=[advisory().sources[0]])
    for lang in ("en", "ja"):
        assert LINE[lang] not in compose.digest([], day, lang)
        assert compose.digest([], day, lang, foreign=True).endswith("\n\n" + LINE[lang])
        assert compose.digest([], day, lang, foreign=True, dropped=2, summary="S").endswith("\n\n" + LINE[lang] + "\n\nS")
        assert compose.digest([adv], day, lang, foreign=False) == compose.digest([adv], day, lang)


@pytest.mark.parametrize("day", ["quiet", "with an alert"])
def test_the_digest_says_it_once_in_both_languages(signing, day):
    m = signing.mirror
    signing.run(relay=PutRelay())
    if day == "with an alert":
        signing.collector([finding()])
    forged = _forged(m)  # arrives after the last run: the digest's own check finds it
    _, _, relay = signing.run(relay=PutRelay(), now=at(5, 9))
    (digest,) = [c[2] for c in relay.calls if c[2].startswith("Daily digest")]
    assert LINE["en"] in digest and forged["id"] not in digest
    (ja,) = [c[2] for c in relay.ja if "デイリーダイジェスト" in c[2]]
    assert LINE["ja"] in ja
    rec = json.loads(signing.config.sent_state.read_text())
    assert rec["said"] == [forged["id"]]
    _, _, relay = signing.run(relay=PutRelay(), now=at(6, 9))
    (digest,) = [c[2] for c in relay.calls if c[2].startswith("Daily digest")]
    assert LINE["en"] not in digest  # still on the mirror, still left out, said once


def test_a_digest_that_did_not_arrive_says_it_again(signing):
    m = signing.mirror
    signing.run(relay=PutRelay())
    _forged(m)
    code, _, relay = signing.run(relay=PutRelay("fail"), now=at(5, 9))
    assert code == 1 and LINE["en"] in relay.calls[0][2]
    assert json.loads(signing.config.sent_state.read_text())["said"] == []
    _, _, relay = signing.run(relay=PutRelay(), now=at(5, 10))
    assert LINE["en"] in relay.calls[0][2]
    assert len(json.loads(signing.config.sent_state.read_text())["said"]) == 1


def test_an_event_that_turns_out_to_be_the_posters_is_not_said(signing):
    m = signing.mirror
    signing.run(relay=PutRelay())
    ev = _forged(m)
    _, summary, _ = signing.run(relay=PutRelay(), now=T0 + HOUR)
    assert ",foreign=1" in summary
    sent.note(signing.config.sent_state, ev["id"], T0 + HOUR)  # e.g. a person's resolve --delivered
    _, _, relay = signing.run(relay=PutRelay(), now=at(5, 9))
    (digest,) = [c[2] for c in relay.calls if c[2].startswith("Daily digest")]
    assert LINE["en"] not in digest


# ---------------------------------------------------------------- the files

def test_the_sent_record_and_its_lock_join_the_path_checks(tmp_path):
    base = dict(ledger=tmp_path / "ledger.json")
    for clash in (tmp_path / "ledger.json.sent.json", tmp_path / "ledger.json.sent.json.lock",
                  tmp_path / "LEDGER.JSON.SENT.JSON"):
        with pytest.raises(inputs.ConfigError, match="must differ"):
            inputs.Config(**base, kev_cache=clash).check_paths()
    c = inputs.Config(**base, kev_cache=tmp_path / "kev.json")
    c.check_paths()
    c.check_catalog_paths()
    assert c.sent_state.name == "ledger.json.sent.json"


def test_a_digest_item_may_name_the_foreign_ids_it_reported():
    from test_inputs import digest_item
    good = digest_item()
    adv = good["adv"]
    assert inputs._item_ok({**good, "adv": {**adv, "foreign": ["ab" * 32, "cd" * 32]}})
    for bad in ([], ["ab" * 32, "ab" * 32], ["xyz"], "ab" * 32, [1], ["ab" * 32] * 0 + [f"{i:064x}" for i in range(201)]):
        assert not inputs._item_ok({**good, "adv": {**adv, "foreign": bad}})
