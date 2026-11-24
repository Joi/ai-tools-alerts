"""Expiry is computed from signed claims and judged by the signed head (ai-tools-alerts#r0ra)."""

import pytest

from aitools_alerts import cli, config, inventory, pull, ruleset, wire
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.state import State
from mirror_helpers import T0, Boom, Mirror, advisory, break_write

DAY = 86400
URL = "https://mirror.example.invalid/alerts"
CVE = "CVE-2098-0001"


@pytest.fixture(autouse=True)
def _home(home):
    return home


def claim(confirmed, checked=None, level="critical", adv_id=CVE):
    return wire.claim_tag({"id": adv_id, "source": "kev", "fields": {"cve_id": adv_id, "name": None},
                           "ruleset": 1, "level": level, "confirmed_at": confirmed,
                           "checked_at": confirmed if checked is None else checked})


def bot_root(m: Mirror, at=T0 + 100, tags=None, **over):
    """A relay-bot critical for CVE, dated ``at``, with a claim confirmed then."""
    adv = advisory(id=CVE, posted_by="relay-bot", posted_at=at, **over)
    return m.root_post(m.bot_sec, adv, created_at=at, tags=[claim(at)] if tags is None else tags)


def renew(m: Mirror, root, at, tag, sec=None, text="Still listed."):
    return m.post(sec or m.bot_sec, text, created_at=at, tags=[["e", root["id"], "", "root"], tag])


def pull_at(m: Mirror, at):
    """The signer signs a head at ``at``; the member, whose clock agrees, pulls."""
    m.checkpoint(now=at)
    st = State.load()
    return pull.fetch(URL, st, fetch=m.fetch, root_pubkey=m.root, now=at)


def shown(st=None) -> dict:
    st = st or State.load()
    return {t.adv.id: t.adv.level for t in pull.active(pull.advisories(st), *pull.head_clock(st))}


def thread(m: Mirror):
    (t,) = pull.threads_from(m.events["feed.json"], m.man)
    return t


# ---------------------------------------------------------------- the function

def test_a_level_stands_for_its_ttl_after_a_confirmation():
    rs = ruleset.load()
    for level, days in (("critical", 14), ("high", 30), ("notice", 90)):
        assert rs.stands_until(level, T0, T0) == T0 + days * DAY
    one = [(T0, T0)]
    steps = [(14, "critical"), (30, "high"), (90, "notice")]  # a critical steps down through each
    for days, level in steps:
        assert rs.level_at("critical", one, T0 + days * DAY) == level
    assert [rs.level_at("critical", one, T0 + d * DAY + 1) for d, _ in steps] == ["high", "notice", ruleset.NONE]
    assert [rs.level_at("high", one, T0 + d * DAY + 1) for d in (14, 30, 90)] == ["high", "notice", ruleset.NONE]
    assert rs.level_at("notice", [(T0, T0)], T0 + 90 * DAY + 1) == ruleset.NONE
    assert rs.level_at("critical", [], T0) == ruleset.NONE


def test_a_check_that_could_not_confirm_holds_the_level_to_day_45_and_no_further():
    rs = ruleset.load()
    assert ruleset.UNCONFIRMED_DAYS == 45
    assert rs.stands_until("critical", T0, T0 + 10 * DAY) == T0 + 24 * DAY
    assert rs.stands_until("critical", T0, T0 + 40 * DAY) == T0 + 45 * DAY
    assert rs.stands_until("high", T0, T0 + 44 * DAY) == T0 + 45 * DAY
    assert rs.stands_until("notice", T0, T0 + 80 * DAY) == T0 + 90 * DAY  # its own TTL is longer
    assert rs.level_at("critical", [(T0, T0 + 40 * DAY)], T0 + 45 * DAY + 1) == "notice"


def test_a_higher_level_never_shows_lower():
    """A raise must not shorten what a thread shows: the bot key can raise without a claim."""
    rs = ruleset.load()
    rank = {ruleset.NONE: 0, "notice": 1, "high": 2, "critical": 3}
    for day in range(0, 100):
        got = [rank[rs.level_at(lv, [(T0, T0)], T0 + day * DAY + 1)] for lv in ("notice", "high", "critical")]
        assert got == sorted(got), day


def test_the_longest_renewal_counts_and_a_shorter_one_changes_nothing():
    rs = ruleset.load()
    long, short = (T0 + 20 * DAY, T0 + 20 * DAY), (T0 - 50 * DAY, T0 - 50 * DAY)
    for renewals in ([long, short], [short, long]):
        assert rs.level_at("critical", renewals, T0 + 34 * DAY) == "critical"
        assert rs.level_at("critical", renewals, T0 + 34 * DAY + 1) == "high"


# ---------------------------------------------------------------- what is a renewal

def test_renewals_are_the_relay_bots_well_formed_claims_for_this_thread(mirror):
    root = bot_root(mirror)
    at = T0 + 5 * DAY
    good = renew(mirror, root, at, claim(at - 60, at - 30))
    renew(mirror, root, at + 1, claim(at, adv_id="CVE-2098-0002"))          # another advisory
    renew(mirror, root, at + 2, ["claim", '{"id": "CVE-2098-0001"}'])       # not a claim
    renew(mirror, root, at + 3, claim(at, level="none"))                     # a withdrawal is no renewal
    renew(mirror, root, at + 4, claim(at, at + 5))                           # checked after it was sent
    renew(mirror, root, at + 5, claim(at + 5), sec=mirror.cur_sec, text="lang: ja\n\nmada")  # a curator's key
    t = thread(mirror)
    assert t.renewals == ((T0 + 100, T0 + 100, T0 + 100), (at - 60, at - 30, good["created_at"]))
    assert not t.curated


def test_a_claim_under_an_alias_renews_and_a_refused_lowering_still_renews(mirror):
    root = bot_root(mirror, aliases=["GHSA-aaaa-bbbb-cccc"])
    ghsa = {"id": "GHSA-aaaa-bbbb-cccc", "source": "ghsa", "ruleset": 1, "level": "notice",
            "confirmed_at": T0 + 300, "checked_at": T0 + 300,
            "fields": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "type": "reviewed", "withdrawn_at": None, "repository": None,
                       "severity": None, "cvss_vector": None, "cwes": [], "packages": []}}
    renew(mirror, root, T0 + 300, wire.claim_tag(ghsa), text=mirror.patch_text(level="notice"))
    t = thread(mirror)
    assert t.adv.level == "critical"  # the lowering is refused, as before
    assert (T0 + 300, T0 + 300, T0 + 300) in t.renewals


def test_a_relay_bot_expiry_is_not_read_and_a_curators_is(mirror):
    bot_root(mirror, expires_at=T0 + 101)
    cur = mirror.root_post(mirror.cur_sec, advisory(expires_at=T0 + 5 * DAY), created_at=T0 + 100)
    dropped = pull.Counter()
    threads = {t.adv.id: t for t in pull.threads_from(mirror.events["feed.json"], mirror.man, dropped)}
    assert threads[CVE].adv.expires_at is None and dropped["bot-expiry"] == 1
    assert threads["AITA-TEST-0001"].adv.expires_at == T0 + 5 * DAY and threads["AITA-TEST-0001"].curated
    ts = list(threads.values())
    assert len(pull.active(ts)) == 2                                         # no head: nothing expires
    assert len(pull.active(ts, T0 + 5 * DAY)) == 2
    assert [t.adv.id for t in pull.active(ts, T0 + 5 * DAY + 1)] == [CVE]
    assert len(pull.active(ts, T0 + 5 * DAY + 1, frozenset())) == 2          # a head that does not list them
    assert [t.adv.id for t in pull.active(ts, T0 + 5 * DAY + 1, frozenset({cur["id"]}))] == [CVE]


def test_a_thread_whose_root_has_no_claim_cannot_be_ended_by_a_reply(mirror):
    """Every alert posted before the poster sent claims: the bot key must not be able
    to end one by replying with a claim confirmed in 1970."""
    root = mirror.root_post(mirror.bot_sec, advisory(id=CVE, posted_by="relay-bot"), created_at=T0 + 100)
    renew(mirror, root, T0 + 200, claim(0))
    t = thread(mirror)
    assert t.enrolled_at is None and t.renewals == ()
    assert [x.adv.level for x in pull.active([t], T0 + 365 * DAY)] == ["critical"]
    assert pull_at(mirror, T0 + 30 * DAY).error is None and shown() == {CVE: "critical"}


def test_an_enrolled_thread_is_not_shortened_by_an_ancient_claim(mirror):
    root = bot_root(mirror)
    renew(mirror, root, T0 + 200, claim(0))
    t = thread(mirror)
    assert t.enrolled_at == T0 + 100
    assert [x.adv.level for x in pull.active([t], T0 + 100 + 14 * DAY)] == ["critical"]


def test_a_raise_counts_from_its_own_date_with_or_without_a_claim(mirror):
    """The root's confirmation of high is 19 days old, past critical's 14: the raise
    must not be judged by it."""
    root = bot_root(mirror, tags=[claim(T0 + 100, level="high")], level="high")
    level = lambda now: [t.adv.level for t in pull.active([thread(mirror)], now)]  # noqa: E731
    assert level(T0 + 20 * DAY) == ["high"]
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=T0 + 19 * DAY)
    assert level(T0 + 20 * DAY) == ["critical"]
    assert level(T0 + 33 * DAY) == ["critical"] and level(T0 + 33 * DAY + 1) == ["high"]
    assert level(T0 + 19 * DAY - 30) == ["critical"]  # posted in the run whose head is dated before it


def test_no_state_or_a_writers_pull_gives_no_clock(mirror):
    assert pull.head_clock(State.load()) == (None, None)
    bot_root(mirror)
    st = State.load()
    assert pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 365 * DAY, checkpoint=False).error is None
    assert pull.head_clock(State.load()) == (None, None) and shown() == {CVE: "critical"}


def test_dropping_an_alias_does_not_drop_the_renewal_made_under_it(mirror):
    root = bot_root(mirror)
    alias = "CVE-2098-0777"
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(aliases=[alias]), created_at=T0 + 200)
    renew(mirror, root, T0 + 89 * DAY, claim(T0 + 89 * DAY, adv_id=alias))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(aliases=[]), created_at=T0 + 90 * DAY)
    t = thread(mirror)
    assert t.adv.aliases == [] and (T0 + 89 * DAY, T0 + 89 * DAY, T0 + 89 * DAY) in t.renewals
    assert [x.adv.level for x in pull.active([t], T0 + 95 * DAY)] == ["critical"]


def test_a_reply_cannot_end_a_thread_whose_roots_claim_is_still_held_back(mirror):
    """A checkpoint may list a root dated after it. Until a checkpoint reaches the
    root's date, an ancient claim in a reply dated earlier must not count alone."""
    root = bot_root(mirror, at=T0 + 950)
    renew(mirror, root, T0 + 900, claim(0))
    t = thread(mirror)
    assert [x.adv.level for x in pull.active([t], T0 + 900)] == ["critical"]
    assert [x.adv.level for x in pull.active([t], T0 + 950)] == ["critical"]


def test_a_curated_thread_and_a_thread_without_a_claim_do_not_decay(mirror):
    root = bot_root(mirror)
    plain = mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", posted_by="relay-bot"), created_at=T0 + 100)
    year = T0 + 365 * DAY
    by_id = lambda ts: {t.adv.id: t.adv.level for t in ts}  # noqa: E731
    ts = pull.threads_from(mirror.events["feed.json"], mirror.man)
    assert by_id(pull.active(ts, year)) == {"AITA-TEST-0002": "critical"}
    assert by_id(pull.active(ts, year, frozenset({plain["id"]}))) == {"AITA-TEST-0002": "critical", CVE: "critical"}
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(title="A curator's title"), created_at=T0 + 200)
    ts = pull.threads_from(mirror.events["feed.json"], mirror.man)
    assert by_id(pull.active(ts, year)) == {"AITA-TEST-0002": "critical", CVE: "critical"}


def test_a_thread_with_a_renewal_dated_after_the_head_is_not_judged_yet(mirror):
    root = bot_root(mirror)
    renew(mirror, root, T0 + 30 * DAY, claim(T0 + 30 * DAY))
    ts = pull.threads_from(mirror.events["feed.json"], mirror.man)
    level = lambda now: [t.adv.level for t in pull.active(ts, now)]  # noqa: E731
    assert level(T0 + 20 * DAY) == ["critical"]  # not judged: the head has not reached the renewal's date
    assert level(T0 + 30 * DAY) == ["critical"] and level(T0 + 44 * DAY + 1) == ["high"]


def test_a_damaged_ruleset_expires_nothing(mirror, monkeypatch):
    bot_root(mirror)
    ts = pull.threads_from(mirror.events["feed.json"], mirror.man)

    def broken():
        raise ruleset.RulesetError("damaged")
    monkeypatch.setattr(ruleset, "load", broken)
    assert [t.adv.level for t in pull.active(ts, T0 + 365 * DAY)] == ["critical"]


# ---------------------------------------------------------------- the acceptance cases

def test_a_mirror_frozen_for_thirty_days_keeps_the_critical_and_reads_stale(mirror):
    bot_root(mirror)
    assert pull_at(mirror, T0 + 1000).error is None
    later = T0 + 1000 + 30 * DAY
    st = State.load()
    res = pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=later)  # the same files again
    assert res.error is None and shown() == {CVE: "critical"}
    assert pull.unverified(State.load(), later) == "checkpoint out of date"
    assert pull.stale_since(State.load(), later) == T0 + 1000


def test_a_mirror_that_drops_a_renewal_is_incomplete_and_expires_nothing(mirror):
    root = bot_root(mirror)
    assert pull_at(mirror, T0 + 1000).error is None
    renewal = renew(mirror, root, T0 + 13 * DAY, claim(T0 + 13 * DAY))
    mirror.checkpoint(now=T0 + 15 * DAY)  # after the first claim's 14 days; it lists the renewal
    mirror.events["feed.json"].remove(renewal)
    st = State.load()
    res = pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 15 * DAY)
    assert res.error == "mirror incomplete" and shown() == {CVE: "critical"}
    assert pull.head_clock(State.load())[0] == T0 + 1000  # the head it holds is the earlier one
    mirror.events["feed.json"].append(renewal)
    st = State.load()
    assert pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 15 * DAY).error is None
    assert pull.head_clock(State.load())[0] == T0 + 15 * DAY and shown() == {CVE: "critical"}


def test_a_short_expiry_from_the_bot_key_does_not_shorten_the_threads_life(mirror):
    root = bot_root(mirror, expires_at=T0 + 101)                       # one second after posted_at
    renew(mirror, root, T0 + 200, claim(T0 - 80 * DAY))                # a claim whose life is nearly over
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(expires_at=T0 + 102), created_at=T0 + 300)
    assert pull_at(mirror, T0 + 13 * DAY).error is None
    assert shown() == {CVE: "critical"}


def test_an_event_dated_ten_years_ahead_is_refused_and_the_stale_check_still_fires(mirror):
    root = bot_root(mirror)
    assert pull_at(mirror, T0 + 1000).error is None
    ahead = renew(mirror, root, T0 + 3650 * DAY, claim(T0 + 3650 * DAY))
    mirror.checkpoint(ids=mirror.honest_ids(T0 + 4000 * DAY), now=T0 + 2000)  # a head that lists it
    st = State.load()
    res = pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 2000)
    assert res.error == "mirror incomplete" and res.dropped == {"future-dated": 1}
    assert ahead["id"] not in State.load().events
    for days in (30, 80):
        assert pull.stale_since(State.load(), T0 + days * DAY) == T0 + 1000
    assert shown() == {CVE: "critical"}  # its claim keeps nothing alive either: the head held is the first


def test_a_renewal_dated_after_the_head_that_lists_it_is_held_back_not_refused(mirror):
    """The honest signer dates a checkpoint at the start of its run and lists the posts
    of that run, so such an event is admitted; the thread is judged by the next head."""
    root = bot_root(mirror, at=T0 - 20 * DAY)                          # critical until T0 - 6 days, then high
    late = renew(mirror, root, T0 + 950, claim(T0 + 950))
    mirror.checkpoint(ids=mirror.honest_ids(T0 + 950), now=T0 + 900)   # lists it, 50 seconds early
    st = State.load()
    res = pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 1000)
    assert res.error is None and late["id"] in State.load().events
    assert shown() == {CVE: "critical"}
    assert pull_at(mirror, T0 + 950).error is None and shown() == {CVE: "critical"}


def test_a_head_saved_over_an_earlier_store_expires_nothing(mirror, monkeypatch):
    """The checkpoint is written before the events. A crash between the two must not
    leave a clock that has passed a renewal the store does not hold."""
    root = bot_root(mirror)
    assert pull_at(mirror, T0 + 1000).error is None
    renewal = renew(mirror, root, T0 + 13 * DAY, claim(T0 + 13 * DAY))
    mirror.checkpoint(now=T0 + 15 * DAY)
    mend = break_write(monkeypatch, "events.json", 2)
    with pytest.raises(Boom):
        pull.fetch(URL, State.load(), fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 15 * DAY)
    mend()
    st = State.load()
    assert st.checkpoint_for(mirror.root).created_at == T0 + 15 * DAY and renewal["id"] not in st.events
    assert pull.head_clock(st) == (None, None) and shown(st) == {CVE: "critical"}
    assert pull.fetch(URL, State.load(), fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 15 * DAY).error is None
    assert pull.head_clock(State.load())[0] == T0 + 15 * DAY and shown() == {CVE: "critical"}


def test_a_member_clock_a_year_out_expires_and_revives_nothing(mirror):
    def old(n, days):  # a critical last confirmed ``days`` before T0
        at = T0 - days * DAY
        adv = advisory(id=f"CVE-2098-000{n}", posted_by="relay-bot", posted_at=at)
        return mirror.root_post(mirror.bot_sec, adv, created_at=at, tags=[claim(at, adv_id=adv.id)])
    old(1, 100), old(2, 20), old(3, 0)
    assert pull_at(mirror, T0 + 1000).error is None
    want = {"CVE-2098-0002": "high", "CVE-2098-0003": "critical"}  # 0001 is past notice's 90 days
    assert shown() == want
    for clock in (T0 + 1000 + 365 * DAY, T0 + 1000 - 365 * DAY):
        st = State.load()
        res = pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=clock)
        assert res.error is not None  # the certificate has run out; the head is dated ahead
        assert shown() == want and pull.unverified(State.load(), clock) is not None
        assert len(State.load().events) == 3  # the one 465 days behind the fast clock is still stored


def test_a_critical_with_no_renewal_decays_under_a_fresh_head_that_lists_none(mirror):
    bot_root(mirror)
    assert pull_at(mirror, T0 + 100 + 14 * DAY).error is None
    assert shown() == {CVE: "critical"}  # the last second of its 14 days
    assert pull_at(mirror, T0 + 101 + 14 * DAY).error is None
    assert shown() == {CVE: "high"}
    assert pull_at(mirror, T0 + 100 + 30 * DAY).error is None and shown() == {CVE: "high"}
    assert pull_at(mirror, T0 + 101 + 30 * DAY).error is None and shown() == {CVE: "notice"}
    assert pull_at(mirror, T0 + 100 + 90 * DAY).error is None and shown() == {CVE: "notice"}
    assert pull_at(mirror, T0 + 101 + 90 * DAY).error is None and shown() == {}


def test_check_prints_the_decayed_level(mirror, monkeypatch, capsys):
    bot_root(mirror)
    assert pull_at(mirror, T0 + 101 + 14 * DAY).error is None
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, mirror.root)
    config.write_default(force=True)
    config.config_path().write_text("trust_root_override = true\n")
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert f"(id {CVE}, " in out and "HIGH: " in out and "CRITICAL" not in out


def test_a_pull_refused_for_size_ages_nothing_by_the_head_it_did_not_accept(mirror, monkeypatch):
    old = bot_root(mirror, at=T0 - 399 * DAY)
    assert pull_at(mirror, T0).error is None
    for n in (2, 3):  # two new threads: over the limit even without the old one
        mirror.root_post(mirror.bot_sec, advisory(id=f"AITA-TEST-000{n}", posted_by="relay-bot"), created_at=T0 + DAY)
    monkeypatch.setattr(pull, "MAX_STORED_EVENTS", 1)
    res = pull_at(mirror, T0 + 2 * DAY)  # under this head the old thread would be 401 days old
    assert res.error == "state limit reached: new events not stored"
    st = State.load()
    assert pull.head_clock(st)[0] == T0 and set(st.events) == {old["id"]}
