"""The reversible withdrawn state, member's half (ai-tools-alerts#y484, findings D4 and D13
of the design review): a relay-bot reply whose block is exactly ``{"level":"withdrawn"}``
hides its thread while the member's own source check confirms it, is a lowering to notice
otherwise, and never hides anything unchecked."""

import json

import pytest

from aitools_alerts import cli, pull, schema, verify, wire
from aitools_alerts.state import State
from mirror_helpers import T0, advisory
from test_curator_hold import AT, HOLD, bot_root, says, thread
from test_curator_hold_cli import ALL, DAY, levels, serve
from test_unchecked_lowering import claim, ghsa_fields
from test_unverified_cli import C0, claimed_root, lower
from test_verify import G1, G2, NOW, Net, adv, ghsa, go, gurl
from test_verify_cli import bot, env, feed, out_of, use  # noqa: F401 - env and feed are fixtures
import test_expiry

WAIT = pull.UNCHECKED_LOWERING_S
GONE = "withdrawn"
MALWARE = claim("ghsa", ghsa_fields(type="malware"))  # the fields give critical
WITHDRAWN = ghsa(type="malware", withdrawn_at="2026-11-01T00:00:00Z")


@pytest.fixture(autouse=True)
def _home(home):
    return home


def block(obj, first="Withdrawn by its source.") -> str:
    return f"{first}\n\n```{schema.INFO_STRING}\n{json.dumps(obj)}\n```\n"


def withdraw(m, root, at=AT, obj=None, first="Withdrawn by its source.", tag=None):
    tags = [["e", root["id"], "", "root"]] + ([tag] if tag else [])
    return m.post(m.bot_sec, block({"level": GONE} if obj is None else obj, first), created_at=at, tags=tags)


def by(answer=None, asked=None):
    """A check that is asked about the withdrawal and nothing else (a KeyError for any other level)."""
    def check(a, level, stated=()):
        if asked is not None:
            asked.append(level)
        return {GONE: answer}[level]
    return check


def state(m, now, check=None, since=None):
    """(level, waiting, refused) of the thread under a checkpoint issued at ``now``; None when it is not shown."""
    ts = pull.active([thread(m)], now, None, check, since=since)
    return (ts[0].adv.level, ts[0].waiting, ts[0].refused) if ts else None


# ---------------------------------------------------------------- the wire word

def test_the_withdrawal_block_is_exactly_one_key_and_no_level():
    assert wire.is_withdrawal({"level": "withdrawn"})
    for p in ({"level": "Withdrawn"}, {"level": "withdrawn", "title": "x"}, {"level": ["withdrawn"]}, {}, None,
              {"level": "none"}, {"level": "notice"}, "withdrawn", [("level", "withdrawn")]):
        assert not wire.is_withdrawal(p)
    assert GONE == wire.WITHDRAWN == pull.WITHDRAWN and GONE not in wire.LEVELS | schema.LEVELS and GONE not in pull._RANK
    assert not wire.is_lowering({"level": GONE}, "critical")


# ---------------------------------------------------------------- the reader's replay

def test_a_withdrawal_is_published_and_not_applied(mirror):
    root = bot_root(mirror)
    before = thread(mirror)
    reply = withdraw(mirror, root)
    t = thread(mirror)
    assert (t.offered, t.offered_by) == (GONE, reply["id"])
    assert t.adv.level == t.wide.level == "critical" and not t.retracted and t.held_until is None
    assert t.stated == before.stated and t.renewals == before.renewals  # it names no level: no statement, no renewal
    assert state(mirror, AT + 900 * DAY) == ("critical", None, None)  # no check, no record: as a released reader


def test_sent_again_it_keeps_the_first_reply(mirror):
    root = bot_root(mirror)
    first = withdraw(mirror, root)
    withdraw(mirror, root, AT + 10)
    assert thread(mirror).offered_by == first["id"]


@pytest.mark.parametrize("level, offered", [("critical", None), ("high", "high"), ("notice", "notice")])
def test_a_level_reply_ends_it(mirror, level, offered):
    root = bot_root(mirror)
    withdraw(mirror, root)
    back = lower(mirror, root, level, AT + 10)
    t = thread(mirror)
    assert (t.offered, t.offered_by) == (offered, back["id"] if offered else None)
    assert t.root_id == root["id"] and t.wide.level == "critical"  # the same thread, at its level or offered a lower one


def test_a_raise_above_the_widest_level_ends_it(mirror):
    root = bot_root(mirror, level="high")
    withdraw(mirror, root)
    lower(mirror, root, "critical", AT + 10)
    t = thread(mirror)
    assert (t.offered, t.adv.level) == (None, "critical")


def test_a_lowering_then_a_withdrawal(mirror):
    root = bot_root(mirror)
    lower(mirror, root, "notice")
    assert thread(mirror).offered == "notice"
    reply = withdraw(mirror, root, AT + 10)
    assert (thread(mirror).offered, thread(mirror).offered_by) == (GONE, reply["id"])


@pytest.mark.parametrize("obj, first", [
    ({"level": "withdrawn", "title": "x"}, "Update."), ({"level": "Withdrawn"}, "Update."),
    ({"level": ["withdrawn"]}, "Update."), ({"level": "none"}, "Update."),
    ({"level": "withdrawn"}, "retract"),  # the bot has no retract: such a reply's block is not read
])
def test_near_misses_are_no_withdrawal(mirror, obj, first):
    root = bot_root(mirror)
    withdraw(mirror, root, obj=obj, first=first)
    t = thread(mirror)
    assert t.offered is None and not t.retracted and t.adv.level == "critical"


def test_a_root_that_names_withdrawn_is_no_advisory(mirror):
    text = schema.render_post(advisory(posted_by="relay-bot"), "Body line.").replace('"critical"', '"withdrawn"')
    assert '"level": "withdrawn"' in text or '"level":"withdrawn"' in text
    mirror.post(mirror.bot_sec, text, created_at=T0 + 100)
    assert pull.threads_from(mirror.events["feed.json"], mirror.man) == []


def test_on_a_curator_s_own_thread_it_is_discussion(mirror):
    root = mirror.root_post(mirror.cur_sec, advisory(), created_at=T0 + 100, files=("feed.json",))
    withdraw(mirror, root)
    t = thread(mirror)
    assert t.offered is None and t.wide is None and not t.retracted
    assert pull.active([t], AT + DAY, None, says(True))[0].adv.level == "critical"


def test_asks_and_the_record(mirror):
    root = bot_root(mirror)
    reply = withdraw(mirror, root)
    t = thread(mirror)
    assert pull.asks(t) == [GONE] and pull.unchecked_level(t) == "notice"  # one question, one result
    assert pull.offers([t], {}, AT + 50, {root["id"], reply["id"]}) == {reply["id"]: AT + 50}
    assert pull.offers([t], {}, AT + 50, {root["id"]}) == {}  # a checkpoint that does not list the reply


def test_on_a_notice_thread_there_is_one_question(mirror):
    withdraw(mirror, bot_root(mirror, level="notice"))
    t = thread(mirror)
    assert pull.asks(t) == [GONE] and pull.unchecked_level(t) is None


# ---------------------------------------------------------------- standing

def test_hidden_only_while_the_check_confirms(mirror):
    withdraw(mirror, bot_root(mirror))
    asked = []
    assert state(mirror, AT + DAY, by(True, asked)) is None
    assert set(asked) == {GONE}  # one question: no second result that an older or a newer run could contradict it with
    assert state(mirror, AT + DAY, by(None)) == ("critical", None, None)
    t = pull.standing(thread(mirror), AT + DAY, by(True))
    assert t.retracted and t.adv.level == "critical"


def test_unconfirmed_it_is_a_lowering_to_notice_nobody_has_checked(mirror):
    root = bot_root(mirror)
    reply = withdraw(mirror, root)
    since = {reply["id"]: AT + 100}
    assert state(mirror, AT + 100 + WAIT - 1, by(None), since) == ("critical", "notice", None)
    assert state(mirror, AT + 100 + WAIT, by(None), since) == ("notice", None, None)
    assert state(mirror, AT + 100 + WAIT, None, since) == ("notice", None, None)  # verify = "off"
    assert state(mirror, AT + 900 * DAY, by(None), since) == ("notice", None, None)  # never hidden unchecked
    assert state(mirror, AT + 900 * DAY, by(None), None) == ("critical", None, None)  # no record: no wait runs
    assert state(mirror, None, by(None), since) == ("critical", "notice", None)  # no checkpoint, no clock


def test_a_contradicted_withdrawal_is_refused_however_long_it_stands(mirror):
    root = bot_root(mirror)
    reply = withdraw(mirror, root)
    assert state(mirror, AT + 900 * DAY, by(False), {reply["id"]: AT + 100}) == ("critical", None, GONE)
    assert state(mirror, AT + DAY, by(False), None) == ("critical", None, GONE)


def test_on_a_notice_thread_there_is_nothing_to_lower(mirror):
    root = bot_root(mirror, level="notice")
    reply = withdraw(mirror, root)
    since = {reply["id"]: AT}
    assert state(mirror, AT + 900 * DAY, by(None), since) == ("notice", None, None)
    assert state(mirror, AT + DAY, by(False), since) == ("notice", None, GONE)
    assert state(mirror, AT + DAY, by(True), since) is None


@pytest.mark.parametrize("curator_first", [True, False])
def test_a_curator_s_hold_governs(mirror, curator_first):
    root = bot_root(mirror)
    patch = mirror.patch_text(title="A clearer title")
    mirror.reply(mirror.cur_sec, root, patch, created_at=AT if curator_first else AT + 10)
    withdraw(mirror, root, AT + 10 if curator_first else AT)
    t = thread(mirror)
    assert t.offered == GONE and t.held_until is not None
    assert state(mirror, t.held_until, says(True)) == ("critical", None, None)  # as the curator left it
    assert state(mirror, t.held_until + 1, by(True)) is None


def test_a_curator_s_retraction_is_unchanged(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "retract", created_at=AT)
    t = thread(mirror)
    assert t.offered == pull.NONE and pull.asks(t, AT + 1) == [pull.NONE]

    def only_withdrawn(a, level, stated=()):
        return True if level == GONE else None
    assert pull.active([t], AT + HOLD, None, only_withdrawn) == []
    (back,) = pull.active([t], AT + HOLD + 1, None, only_withdrawn)  # a check that would confirm a withdrawal is not asked
    assert back.adv.level == "critical"


@pytest.mark.parametrize("word, offered, after", [
    ("retract", pull.NONE, "critical"), ("level: notice", "notice", "notice"),
    ("block high", "high", "high"), ("block critical", None, "critical"),
])
def test_a_curator_s_later_word_on_the_level_takes_the_offer(mirror, word, offered, after):
    """A curator who retracts, or names a level, after the withdrawal has the last word on
    the level: the withdrawal is gone, and after the hold the thread stands by the curator's
    offer (confirmed here) or at its level. Never hidden: the higher side."""
    root = bot_root(mirror)
    withdraw(mirror, root)
    text = mirror.patch_text(level=word.split()[1]) if word.startswith("block") else word
    mirror.reply(mirror.cur_sec, root, text, created_at=AT + 10)
    t = thread(mirror)
    assert (t.offered, t.offered_by) == (offered, None)
    def check(a, level, stated=()):  # confirms any level, and a withdrawal if it were asked; never a retraction
        return None if level == pull.NONE else True
    (back,) = pull.active([t], t.held_until + 1, None, check)
    assert back.adv.level == after


def test_expiry_is_not_changed(mirror):
    """A claimed thread decays as before, hidden or shown; the withdrawal is no renewal."""
    m = mirror
    root = test_expiry.bot_root(m)  # a claim confirmed at T0 + 100: critical 14 days, notice to day 90
    reply = withdraw(m, root, T0 + 200, tag=test_expiry.claim(T0 + 200, level="none"))
    t = test_expiry.thread(m)
    assert t.enrolled_at == T0 + 100 and len(t.renewals) == 1
    early, late = T0 + 100 + 10 * DAY, T0 + 100 + 91 * DAY
    assert pull.active([t], early, None, by(True)) == []
    assert [x.adv.level for x in pull.active([t], early, None, by(False))] == ["critical"]  # published again
    assert [x.adv.level for x in pull.active([t], early, None, by(None), since={reply["id"]: T0 + 300})] == ["notice"]
    for check in (by(True), by(False), by(None)):
        assert pull.active([t], late, None, check, since={reply["id"]: T0 + 300}) == []  # run out: gone, whatever is read


# ---------------------------------------------------------------- the check

def lowering(tmp_path, a, level, source_table, stated=None, now=NOW, **kw):
    ask = verify.at_level(a, level, verify.claimed(a, level, stated))
    go(tmp_path, [a, ask], source_table, wanted=[ask], recheck=[ask], now=now)
    return verify.lowering(a, level, verify.load(tmp_path), now, stated=stated, **kw)


SAID = (("critical", MALWARE),)


@pytest.mark.parametrize("stated, want", [
    (SAID, True),
    ((("critical", MALWARE), ("notice", claim("ghsa", ghsa_fields(type="malware")))), True),
    ((("critical", MALWARE), ("notice", None)), False),  # every statement needs its claim, the lowest too
    ((("critical", None),), False), ((), False), (None, False),
])
def test_claimed_for_a_withdrawal_needs_every_statement_claimed(stated, want):
    a = adv(level="critical")
    assert verify.claimed(a, GONE, stated) is want
    assert verify.claimed(a, "none", stated) is False  # a curator's retraction: never


def test_a_withdrawal_is_asked_as_the_state_at_none():
    a = adv(level="critical")
    assert verify.at_level(a, GONE).level == "none"
    assert verify.state_key(verify.at_level(a, GONE, True)) == verify.state_key(verify.at_level(a, "none", True))
    assert verify.state_key(verify.at_level(a, GONE, True)) != verify.state_key(verify.at_level(a, GONE))


def test_the_check_confirms_a_withdrawal_only_claimed_fresh_and_whole(tmp_path):
    a = adv(level="critical")
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), WITHDRAWN), SAID) is True
    assert verify.lowering(a, GONE, verify.load(tmp_path), NOW + verify.FRESH_S, stated=SAID) is True
    assert verify.lowering(a, GONE, verify.load(tmp_path), NOW + verify.FRESH_S + 1, stated=SAID) is None  # too old
    assert verify.lowering(a, GONE, verify.load(tmp_path), NOW - 1, stated=SAID) is None  # a clock set back
    assert verify.lowering(a, GONE, None, NOW, stated=SAID) is None  # verify = "off"
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), WITHDRAWN), (("critical", None),)) is None
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), WITHDRAWN)) is None
    assert lowering(tmp_path, a, "none", Net().set(gurl(G1), WITHDRAWN), SAID) is None  # a retraction: never


def test_support_above_notice_contradicts_a_withdrawal_and_a_failed_read_keeps_that(tmp_path):
    a = adv(level="critical")
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), ghsa()), SAID) is False  # the source gives high
    assert verify.lowering(a, GONE, verify.load(tmp_path), NOW, stated=SAID, whole=True) is False
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), OSError("down")), SAID, now=NOW + verify.RETRY_S) is False
    assert verify.lowering(a, GONE, verify.load(tmp_path), NOW + 900 * DAY, stated=SAID) is False  # at any age
    assert lowering(tmp_path, a, "none", Net().set(gurl(G1), ghsa()), SAID, now=NOW + 2 * verify.RETRY_S) is False


def test_support_of_exactly_notice_hides_nothing_and_refuses_nothing(tmp_path):
    """The advisory is published and gives notice: no withdrawal, and no contradiction of
    the notice the reply is read as. Not settled: the reader's 72 hours decide."""
    a = adv(level="critical")
    at_notice = Net().set(gurl(G1), ghsa(high=False))
    assert lowering(tmp_path, a, GONE, at_notice, SAID) is None
    assert lowering(tmp_path, a, GONE, at_notice) is None
    assert lowering(tmp_path, a, GONE, at_notice, whole=True) is True  # whole reads, no more than notice: a refusal ends
    assert verify.lowering(a, GONE, verify.load(tmp_path), NOW + verify.FRESH_S + 1, whole=True) is None
    assert lowering(tmp_path, a, "none", at_notice, SAID) is False  # a curator's retraction: as before


def test_whole_ends_a_refusal_only_on_fresh_whole_reads(tmp_path):
    a = adv(level="critical")
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), WITHDRAWN), whole=True) is True  # unclaimed: whole, not confirmed
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), WITHDRAWN)) is None
    down = Net().set(gurl(G1), OSError("down"))
    assert lowering(tmp_path, a, GONE, down, whole=True, now=NOW + verify.RETRY_S) is None
    silent = Net().set(gurl(G1), ghsa(pkgs=(("npm", "another-package"),)))
    # an authority that no longer names the product: no support, so a refusal ends; and no withdrawal
    assert lowering(tmp_path, a, GONE, silent, whole=True, now=NOW + 2 * verify.RETRY_S) is True
    assert lowering(tmp_path, a, GONE, silent, SAID, now=NOW + 3 * verify.RETRY_S) is None
    anyone = Net().set(gurl(G1), ghsa(type="unreviewed", withdrawn_at="2026-11-01T00:00:00Z"))
    assert lowering(tmp_path, a, GONE, anyone, whole=True, now=NOW + 4 * verify.RETRY_S) is None  # no authority at all


def test_a_source_silent_about_the_product_confirms_no_withdrawal(tmp_path):
    a = adv(level="critical")
    silent = ghsa(pkgs=(("npm", "another-package"),))
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), silent), SAID) is None


def test_an_incomplete_read_confirms_nothing_and_ends_a_confirmation(tmp_path):
    a = adv(level="critical")
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), WITHDRAWN), SAID) is True
    later = NOW + verify.RETRY_S
    assert lowering(tmp_path, a, GONE, Net().set(gurl(G1), OSError("down")), SAID, now=later) is None  # a failed refresh
    # a withdrawn first advisory that names a second id whose read fails
    named = dict(WITHDRAWN, identifiers=[{"type": "GHSA", "value": G1}, {"type": "GHSA", "value": G2}])
    n = Net().set(gurl(G1), named).set(gurl(G2), OSError("down"))
    assert lowering(tmp_path, a, GONE, n, SAID, now=later + verify.RETRY_S) is None


def test_two_products_of_which_the_source_names_one_is_no_withdrawal(tmp_path):
    a = adv(level="critical", products=("Claude Code", "Codex"))
    said = (("critical", MALWARE),)
    ask = verify.at_level(a, GONE, True)  # asked as claimed, to show the results alone do not confirm
    go(tmp_path, [a, ask], Net().set(gurl(G1), WITHDRAWN), wanted=[ask], recheck=[ask])
    whys = {p["why"] for p in verify.result_for(ask, verify.load(tmp_path)).values()}
    assert whys != {"match"}
    assert verify.lowering(a, GONE, verify.load(tmp_path), NOW, stated=said) is None


def test_a_refresh_cut_short_never_leaves_two_answers(tmp_path, mirror, monkeypatch):
    """The withdrawal is one state with one result. Confirmed, then the advisory is
    published again: a refresh that reads it contradicts; one cut short before it reads
    anything is not a confirmation. No older answer is left beside a newer one."""
    a = adv(level="critical")
    gone = verify.at_level(a, GONE, True)

    def said(now):
        return verify.lowering(a, GONE, verify.load(tmp_path), now, stated=SAID)
    go(tmp_path, [a, gone], Net().set(gurl(G1), WITHDRAWN), wanted=[gone], recheck=[gone])
    assert said(NOW) is True
    later = NOW + verify.RETRY_S
    monkeypatch.setattr(verify, "MAX_FETCHES", 0)
    go(tmp_path, [a, gone], Net().set(gurl(G1), ghsa(type="malware")), wanted=[gone], recheck=[gone], now=later)
    assert said(later) is True  # nothing was read: the day-old confirmation stands, for no more than two days
    assert said(NOW + verify.FRESH_S + 1) is None
    monkeypatch.setattr(verify, "MAX_FETCHES", 10)
    go(tmp_path, [a, gone], Net().set(gurl(G1), ghsa(type="malware")), wanted=[gone], recheck=[gone], now=later + 1)
    assert said(later + 1) is False
    withdraw(mirror, bot_root(mirror))
    t = thread(mirror)
    (shown,) = pull.active([t], AT + 900 * DAY, None, lambda _a, level, stated=(): said(later + 1), since={t.offered_by: AT})
    assert (shown.adv.level, shown.refused, shown.waiting) == ("critical", GONE, None)


# ---------------------------------------------------------------- through the CLI

def refusal(ident, more="critical"):
    return f"source check: a withdrawal of {ident} is not applied: the source supports {more} for Claude Code"


def later(monkeypatch, seconds):
    """This machine's clock, as the CLI and the source check read it, ``seconds`` on."""
    real = __import__("time")
    start = real.time()

    class Later:
        def __getattr__(self, name):
            return getattr(real, name)

        def time(self):
            return start + seconds
    monkeypatch.setattr(verify, "time", Later())
    monkeypatch.setattr(cli, "time", Later())


def test_a_confirmed_withdrawal_is_shown_nowhere_and_comes_back_when_published_again(feed, monkeypatch, capsys,
                                                                                     reader_clock):
    m = feed([], ALL)
    root = claimed_root(m, bot(id=G1, level="critical"), MALWARE)
    withdraw(m, root)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), WITHDRAWN))
    assert levels(capsys) == {G1: "critical"}  # nothing read yet: as a released reader shows it
    _, out, _ = out_of(capsys, ["verify"])
    assert "1 lowerings, withdrawals or retractions asked about: 1 confirmed" in out
    assert levels(capsys) == {} and out_of(capsys, ["check", "--json"])[1].strip() == "[]"
    status, out, err = out_of(capsys, ["check"])
    assert G1 not in out + err
    # the source publishes the advisory again: no reply is needed for the alert to come back
    serve(m, reader_clock, C0 + DAY + 1)
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    later(monkeypatch, verify.RETRY_S + 60)
    assert levels(capsys) == {}  # the confirmation is a day old and still stands until the check reads again
    _, out, _ = out_of(capsys, ["verify"])
    assert refusal(G1) in out
    assert levels(capsys) == {G1: "critical"}
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert (d["level"], d["lowering_refused"], d["lowering_waits"]) == ("critical", GONE, None)
    assert State.load().refused == {root["id"]}
    # and the poster's reply that names the level ends the withdrawal in the same thread
    lower(m, root, "critical", AT + 2 * DAY)
    serve(m, reader_clock, C0 + 2 * DAY + 2)
    assert levels(capsys) == {G1: "critical"}
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert d["lowering_refused"] is None and d["thread"] == root["id"]


def test_an_unclaimed_withdrawal_is_a_lowering_to_notice_after_72_hours(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=G1, level="critical")], ALL)  # the root carries no claim: no withdrawal is confirmed
    withdraw(m, m.events["feed.json"][0])
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), WITHDRAWN))
    assert levels(capsys) == {G1: "critical"}
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert (d["lowering_waits"], d["lowering_refused"]) == ("notice", None)  # the wait a lowering to notice has
    cli.main(["verify"])
    # 0z4e already shows an alert whose source supports nothing at notice; the withdrawal adds no hiding
    assert levels(capsys) == {G1: "notice"}
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys) == {G1: "notice"}
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert (d["lowering_waits"], d["lowering_refused"]) == (None, None)  # applied: the 72 hours have run
    serve(m, reader_clock, C0 + 60 * DAY)
    cli.main(["verify"])
    assert levels(capsys) == {G1: "notice"}  # never hidden


def refused_thread(feed, monkeypatch, capsys, reader_clock):
    """A claimed critical with a withdrawal on the feed, whose source still supports critical: read and refused."""
    m = feed([], ALL)
    root = claimed_root(m, bot(id=G1, level="critical"), MALWARE)
    withdraw(m, root)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    cli.main(["pull"])
    _, out, _ = out_of(capsys, ["verify"])
    assert out.count(refusal(G1)) == 1 and State.load().refused == {root["id"]}
    return m, root


def test_a_contradicted_withdrawal_is_remembered_through_failed_reads(feed, monkeypatch, capsys, reader_clock):
    m, root = refused_thread(feed, monkeypatch, capsys, reader_clock)
    later(monkeypatch, verify.RETRY_S + 60)  # the result is due again
    down = use(monkeypatch, Net().set(gurl(G1), OSError("down")))
    serve(m, reader_clock, C0 + WAIT + DAY)
    cli.main(["pull"])
    cli.main(["verify"])
    assert gurl(G1) in down.urls  # the read was tried, and failed
    assert levels(capsys) == {G1: "critical"} and State.load().refused == {root["id"]}
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert (d["lowering_refused"], d["lowering_waits"]) == (GONE, None)  # no wait runs behind a refusal
    serve(m, reader_clock, C0 + 12 * DAY)  # inside the 14 days the root's claim keeps critical standing
    assert levels(capsys) == {G1: "critical"}


@pytest.mark.parametrize("now_says", [
    ghsa(high=False),  # the advisory now gives notice: published, not withdrawn
    ghsa(type="malware", pkgs=(("npm", "another-package"),)),  # corrected: it no longer names the product
])
def test_a_refusal_ends_on_whole_reads_of_no_more_than_notice_and_the_wait_starts_then(feed, monkeypatch, capsys,
                                                                                        reader_clock, now_says):
    m, root = refused_thread(feed, monkeypatch, capsys, reader_clock)
    later(monkeypatch, verify.RETRY_S + 60)
    n = use(monkeypatch, Net().set(gurl(G1), now_says))
    serve(m, reader_clock, C0 + DAY)
    cli.main(["pull"])
    cli.main(["verify"])
    assert gurl(G1) in n.urls and State.load().refused == set()
    assert levels(capsys) == {G1: "critical"}  # not hidden, and not lowered unchecked yet
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert (d["lowering_refused"], d["lowering_waits"]) == (None, "notice")
    serve(m, reader_clock, C0 + DAY + WAIT - 1)
    assert levels(capsys) == {G1: "critical"}
    serve(m, reader_clock, C0 + DAY + WAIT)
    assert levels(capsys) == {G1: "notice"}  # the 72 hours ran from the checkpoint the refusal ended under
