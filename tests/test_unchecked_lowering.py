"""A relay-bot lowering the member cannot check, and what its claims are worth
(ai-tools-alerts#tavj, finding D8 of the design review): the reader and the check."""

import json

import pytest

from aitools_alerts import pull, ruleset, verify, wire
from aitools_alerts.state import State
from mirror_helpers import T0, advisory
from test_curator_hold import AT, bot_root, says, thread
from test_verify import CVE, G1, G2, G3, KEV_CC, NOW, Net, adv, ghsa, go, gurl, kev, one

HOURS = 3600
WAIT = pull.UNCHECKED_LOWERING_S
G4 = "GHSA-kkkk-mmmm-nnnn"
KEV_FIELDS = {"cve_id": CVE, "name": "Anthropic Claude Code"}


@pytest.fixture(autouse=True)
def _home(home):
    return home


def claim(source, fields, product="Claude Code", at=T0):
    return ruleset.load().claim(source, fields, product, at, at)


def ghsa_fields(**kw):
    return verify._ghsa_reading(ghsa(**kw), kw.get("i", G1))[0]


def lower(m, root, level, at=AT, tag=None):
    tags = [["e", root["id"], "", "root"]] + ([tag] if tag else [])
    return m.post(m.bot_sec, m.patch_text(level=level), created_at=at, tags=tags)


def level_at(m, now, check=None, since=None, listed=None):
    (t,) = pull.active([thread(m)], now, listed, check, since=since)
    return t.adv.level, t.waiting, t.refused


# ---------------------------------------------------------------- the reader

def test_seventy_two_hours():
    assert WAIT == 72 * HOURS


def test_the_reply_that_offered_a_level_is_kept_and_a_new_level_names_a_new_one(mirror):
    root = bot_root(mirror)
    first = lower(mirror, root, "high")
    assert (thread(mirror).offered, thread(mirror).offered_by) == ("high", first["id"])
    lower(mirror, root, "high", AT + 10)  # the same level again: the first reply's wait goes on
    assert thread(mirror).offered_by == first["id"]
    lowest = lower(mirror, root, "notice", AT + 20)
    assert (thread(mirror).offered, thread(mirror).offered_by) == ("notice", lowest["id"])
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT + 30)  # a curator's offer has no reply to wait on
    assert (thread(mirror).offered, thread(mirror).offered_by) == ("notice", None)


def test_a_block_that_applies_ends_the_offer(mirror):
    root = bot_root(mirror, level="high")
    lower(mirror, root, "notice")
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=AT + 10)
    assert (thread(mirror).offered, thread(mirror).offered_by) == (None, None)


def test_an_unsettled_lowering_applies_after_72_hours_of_the_clock_it_is_given(mirror):
    root = bot_root(mirror)
    low = lower(mirror, root, "high")
    since = {low["id"]: AT + 100}
    assert level_at(mirror, AT + 100 + WAIT - 1, says(None), since) == ("critical", "high", None)
    assert level_at(mirror, AT + 100 + WAIT, says(None), since) == ("high", None, None)
    assert level_at(mirror, AT + 100 + WAIT, None, since) == ("high", None, None)  # no check at all: verify = "off"
    # no record, or none of this reply: no wait runs, and nothing says one does
    assert level_at(mirror, AT + 900 * 86400, says(None), None) == ("critical", None, None)
    assert level_at(mirror, AT + 900 * 86400, says(None), {}) == ("critical", None, None)
    assert level_at(mirror, None, says(None), since) == ("critical", "high", None)  # no checkpoint, no clock
    assert level_at(mirror, AT + 900 * 86400, says(False), since) == ("critical", None, "high")  # refused, however long
    assert level_at(mirror, AT + 101, says(True), since) == ("high", None, None)


def test_the_reply_s_own_date_is_never_the_start_of_the_wait(mirror):
    root = bot_root(mirror)
    low = lower(mirror, root, "high", at=T0 + 150)  # dated long before the checkpoint that first lists it
    first_listed = AT + 30 * 86400
    assert pull.offers([thread(mirror)], {}, first_listed, frozenset({root["id"], low["id"]})) == {low["id"]: first_listed}
    assert level_at(mirror, first_listed + WAIT - 1, says(None), {low["id"]: first_listed})[0] == "critical"


def test_a_wait_counts_only_while_the_checkpoint_lists_the_reply(mirror):
    root = bot_root(mirror)
    low = lower(mirror, root, "high")
    since, late = {low["id"]: AT}, AT + WAIT
    assert level_at(mirror, late, says(None), since, frozenset({root["id"]}))[0] == "critical"
    assert level_at(mirror, late, says(None), since, frozenset({root["id"], low["id"]}))[0] == "high"


def test_a_curator_s_lowering_and_a_retraction_never_apply_unchecked(mirror):
    root = bot_root(mirror)
    cur = mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT)
    after = AT + pull.CURATOR_HOLD_S + WAIT
    assert level_at(mirror, after, says(None), {cur["id"]: AT})[0] == "critical"
    gone = mirror.reply(mirror.cur_sec, root, "retract", created_at=AT + 10)
    assert level_at(mirror, after, says(None), {gone["id"]: AT})[0] == "critical"


def test_the_record_of_offers(mirror):
    root = bot_root(mirror)
    low = lower(mirror, root, "high")
    both = frozenset({root["id"], low["id"]})
    ts = [thread(mirror)]
    assert pull.offers(ts, {}, AT + 5, both) == {low["id"]: AT + 5}
    assert pull.offers(ts, {low["id"]: AT + 5}, AT + 900, both) == {low["id"]: AT + 5}  # the first time stays
    assert pull.offers(ts, {low["id"]: AT + 900}, AT + 5, both) == {low["id"]: AT + 5}  # never after the clock
    assert pull.offers(ts, {low["id"]: AT + 5, "f" * 64: 1}, AT + 900, both) == {low["id"]: AT + 5}  # nothing else is kept
    assert pull.offers(ts, {low["id"]: AT + 5}, AT + 900, frozenset({root["id"]})) == {}  # no longer listed: starts again
    assert pull.offers(ts, {low["id"]: AT + 5}, AT + 900, frozenset({low["id"]})) == {}
    assert pull.offers(ts, {low["id"]: AT + 5}, None, None) == {low["id"]: AT + 5}  # no checkpoint: unchanged
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=AT + 50)  # the offer is over
    assert pull.offers([thread(mirror)], {low["id"]: AT + 5}, AT + 900, both) == {}


def test_what_a_thread_stated(mirror):
    c = claim("kev", KEV_FIELDS)
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot", id=CVE, level="high"), created_at=T0 + 100,
                            files=("feed.json",), tags=[wire.claim_tag(c)])
    assert thread(mirror).stated == (("high", c),)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=AT)  # no claim
    lower(mirror, root, "notice", AT + 10, wire.claim_tag(c))
    mirror.reply(mirror.cur_sec, root, "level: high", created_at=AT + 20)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(title="No level named"), created_at=AT + 30)
    assert thread(mirror).stated == (("high", c), ("critical", None), ("notice", c), ("high", None))
    cur = mirror.root_post(mirror.cur_sec, advisory(id="AITA-TEST-0002"), created_at=T0 + 100, files=("critical.json",))
    (own,) = pull.threads_from([cur], mirror.man)
    assert own.stated == () and own.offered_by is None


# ---------------------------------------------------------------- the record on disk

def test_the_record_is_read_and_written_and_a_missing_one_is_empty(tmp_path):
    st = State.load(tmp_path)
    assert (st.lowerings, st.refused, st.interrupts, st.held, st.reset_at, st.unverified_damaged) == (
        {}, set(), {}, {}, None, False)
    st.lowerings, st.refused, st.interrupts, st.reset_at = {"a" * 64: 5}, {"a" * 64}, {"b" * 64: {"c" * 64: 7}}, 9
    st.held = {"d" * 64: 3}
    st.save_unverified()
    again = State.load(tmp_path)
    assert (again.lowerings, again.refused, again.interrupts, again.held, again.reset_at) == (
        {"a" * 64: 5}, {"a" * 64}, {"b" * 64: {"c" * 64: 7}}, {"d" * 64: 3}, 9)


@pytest.mark.parametrize("damage", [
    "{", "[]", '{"lowerings": {}}', '{"lowerings": {}, "refused": [], "interrupts": {}, "held": {}, "reset_at": "soon"}',
    '{"lowerings": {"x": 1}, "refused": [], "interrupts": {}, "held": {}, "reset_at": null}',
    '{"lowerings": {}, "refused": [7], "interrupts": {}, "held": {}, "reset_at": null}',
    '{"lowerings": {}, "refused": [], "interrupts": {"%s": [1]}, "held": {}, "reset_at": null}' % ("a" * 64),
    '{"lowerings": {"%s": -1}, "refused": [], "interrupts": {}, "held": {}, "reset_at": null}' % ("a" * 64),
    '{"lowerings": {}, "refused": [], "interrupts": {}, "held": [], "reset_at": null}',
    '{"lowerings": {}, "refused": [], "interrupts": {}, "reset_at": null}',
    '{"lowerings": {}, "refused": [], "interrupts": {}, "held": {}, "reset_at": null, "more": 1}',
])
def test_a_damaged_record_is_flagged_and_never_an_error(tmp_path, damage):
    (tmp_path / "unverified.json").write_text(damage)
    st = State.load(tmp_path)
    assert st.unverified_damaged and (st.lowerings, st.refused, st.interrupts, st.reset_at) == ({}, set(), {}, None)
    st.save_unverified()
    assert not State.load(tmp_path).unverified_damaged
    assert set(json.loads((tmp_path / "unverified.json").read_text())) == {"lowerings", "refused", "interrupts", "held", "reset_at", "supported"}


# ---------------------------------------------------------------- the check: withdrawal

def test_a_withdrawn_advisory_at_notice_is_confirmed_and_silence_is_still_unsupported(tmp_path):
    a = adv(level="notice")
    go(tmp_path, [a], Net().set(gurl(G1), ghsa(withdrawn_at="2026-11-01T00:00:00Z")))
    assert one(tmp_path, a) == ("confirmed", "withdrawn")
    assert verify.summary(verify.result_for(a, verify.load(tmp_path))) == ("confirmed", "withdrawn")
    go(tmp_path, [a], Net().set(gurl(G1), ghsa(pkgs=(("npm", "another-package"),))), now=NOW + verify.RETRY_S)
    assert one(tmp_path, a) == ("contradicted", "unsupported")  # an authority that does not name the product
    high = adv(level="high")
    go(tmp_path, [high], Net().set(gurl(G1), ghsa(withdrawn_at="2026-11-01T00:00:00Z")))
    assert one(tmp_path, high) == ("contradicted", "unsupported")  # above notice a withdrawal supports nothing


def test_a_withdrawn_result_is_read_again_after_a_day(tmp_path):
    a = adv(level="notice")
    n = Net().set(gurl(G1), ghsa(withdrawn_at="2026-11-01T00:00:00Z"))
    go(tmp_path, [a], n)
    go(tmp_path, [a], n, now=NOW + verify.RETRY_S - 1)
    assert len(n.calls) == 1
    go(tmp_path, [a], n.set(gurl(G1), ghsa()), now=NOW + verify.RETRY_S)  # published again
    assert len(n.calls) == 2 and one(tmp_path, a) == ("contradicted", "below-source")


# ---------------------------------------------------------------- the check: claimed

MALWARE = claim("ghsa", ghsa_fields(type="malware"))  # the fields give critical
REVIEWED = claim("ghsa", ghsa_fields())  # the fields give high


@pytest.mark.parametrize("stated, level, want", [
    ((("critical", MALWARE),), "notice", True),
    ((("critical", MALWARE),), "high", True),
    ((("high", REVIEWED),), "notice", True),
    ((("high", REVIEWED), ("notice", None)), "notice", True),  # a statement at or below the level needs no claim
    ((("critical", None),), "notice", False),
    ((("critical", MALWARE), ("high", None)), "notice", False),  # a later level with no claim may be a reading
    ((("critical", MALWARE), ("high", None)), "high", True),
    ((("critical", REVIEWED),), "notice", False),  # the claim's fields give less than was stated
    ((("high", dict(REVIEWED, level="critical")),), "notice", False),  # not what this reader's ruleset computes
    ((("high", dict(REVIEWED, ruleset=99)),), "notice", False),  # a ruleset this reader does not know
    ((("high", claim("kev", KEV_FIELDS)),), "notice", False),  # another id than the thread's first
    ((("high", {"level": "high"}),), "notice", False),  # not a claim
    ((("high", REVIEWED), ("loud", REVIEWED)), "notice", False),
    ((), "notice", False), (None, "notice", False),
    ((("critical", MALWARE),), "none", False), ((("critical", MALWARE),), "loud", False),
])
def test_claimed(stated, level, want):
    assert verify.claimed(adv(level="critical"), level, stated) is want


def test_claimed_needs_the_claim_to_hold_for_every_product_and_an_id_that_names_a_source():
    assert verify.claimed(adv(level="critical", products=("Claude Code", "Codex")), "notice", (("critical", MALWARE),)) is False
    assert verify.claimed(adv(id="AITA-TEST-0001", level="critical"), "notice", (("critical", MALWARE),)) is False
    assert verify.claimed(adv(id=G1 + ":slug", level="critical"), "notice", (("critical", MALWARE),)) is True  # a ledger key


def test_claimed_under_a_pin_this_reader_does_not_meet_is_false():
    rs = ruleset.load()
    pin = ruleset.Pin(version=rs.version, sha256="0" * 64, min_version=1)
    assert verify.claimed(adv(level="critical"), "notice", (("critical", MALWARE),), rs, pin) is False


def lowering(tmp_path, a, level, source_table, stated=None, now=NOW):
    """What the check says about lowering ``a`` to ``level`` after one run over ``source_table``."""
    ask = verify.at_level(a, level, verify.claimed(a, level, stated))
    go(tmp_path, [a, ask], source_table, wanted=[ask], recheck=[ask], now=now)
    return verify.lowering(a, level, verify.load(tmp_path), now, stated=stated)


WITHDRAWN = ghsa(type="malware", withdrawn_at="2026-11-01T00:00:00Z")


def test_a_withdrawal_confirms_a_lowering_to_notice_only_for_a_claimed_thread(tmp_path):
    a = adv(level="critical")
    assert lowering(tmp_path, a, "notice", Net().set(gurl(G1), WITHDRAWN), (("critical", MALWARE),)) is True
    assert lowering(tmp_path, a, "notice", Net().set(gurl(G1), WITHDRAWN), (("critical", None),)) is None
    assert lowering(tmp_path, a, "notice", Net().set(gurl(G1), WITHDRAWN)) is None
    assert lowering(tmp_path, a, "notice", Net().set(gurl(G1), ghsa()), (("critical", MALWARE),)) is False  # the source gives high
    assert lowering(tmp_path, a, "notice", Net().set(gurl(G1), OSError("down")), (("critical", MALWARE),)) is False  # and a failed read keeps that
    assert lowering(tmp_path, a, "none", Net().set(gurl(G1), WITHDRAWN), (("critical", MALWARE),)) is None  # never a retraction


def test_fields_that_give_notice_confirm_a_claimed_lowering_to_notice(tmp_path):
    a = adv(level="high")
    assert lowering(tmp_path, a, "notice", Net().set(gurl(G1), ghsa(high=False)), (("high", REVIEWED),)) is True
    assert lowering(tmp_path, a, "notice", Net().set(gurl(G1), ghsa(high=False)), (("high", None),)) is None


def test_a_lowering_to_the_reading_cap_needs_no_claim_when_the_sources_give_less(tmp_path):
    """Nothing this reader cannot see holds more than ``reading_cap``: fields that give
    notice, read whole from an authority, say the critical is gone."""
    assert ruleset.load().reading_cap == "high"
    a = adv(level="critical")
    assert lowering(tmp_path, a, "high", Net().set(gurl(G1), ghsa(high=False))) is True
    later = NOW + verify.RETRY_S
    assert lowering(tmp_path, a, "high", Net().set(gurl(G1), ghsa(type="unreviewed", high=False)), now=later) is None  # no authority
    assert verify.lowering(a, "high", verify.load(tmp_path), later, whole=True) is None


def test_whole_is_true_for_whole_reads_that_give_no_more_claimed_or_not(tmp_path):
    a = adv(level="high")
    ask = verify.at_level(a, "notice")
    go(tmp_path, [a, ask], Net().set(gurl(G1), ghsa(high=False)), wanted=[ask])
    cache = verify.load(tmp_path)
    assert verify.lowering(a, "notice", cache, NOW) is None and verify.lowering(a, "notice", cache, NOW, whole=True) is True
    assert verify.lowering(a, "notice", cache, NOW + verify.FRESH_S + 1, whole=True) is None  # not on an old read


# ---------------------------------------------------------------- the check: a CVE the catalog no longer lists

KEV_CLAIM = (("critical", claim("kev", KEV_FIELDS)),)


def test_a_delisting_confirms_a_lowering_only_for_a_claimed_thread(tmp_path):
    a = adv(id=CVE, level="critical")
    assert lowering(tmp_path, a, "notice", Net().set(verify.KEV_URL, kev()), KEV_CLAIM) is True
    assert lowering(tmp_path, a, "high", Net().set(verify.KEV_URL, kev()), KEV_CLAIM) is True
    assert lowering(tmp_path, a, "notice", Net().set(verify.KEV_URL, kev())) is None  # the catalog's silence alone
    assert lowering(tmp_path, a, "high", Net().set(verify.KEV_URL, kev())) is None
    assert lowering(tmp_path, a, "notice", Net().set(verify.KEV_URL, KEV_CC), KEV_CLAIM) is False  # still listed
    assert lowering(tmp_path, a, "notice", Net().set(verify.KEV_URL, OSError("down")), KEV_CLAIM) is False
    # the stored record of the catalog's silence is no authority for any other state
    assert verify.load(tmp_path)["sources"][CVE]["lowers"] is True  # listed, from the read above
    go(tmp_path, [a], Net().set(verify.KEV_URL, kev()), now=NOW + verify.RETRY_S)
    assert verify.load(tmp_path)["sources"][CVE]["lowers"] is False and one(tmp_path, a) == ("unknown", "unauthoritative")


def test_a_claim_about_another_product_s_listing_does_not_make_the_silence_an_authority(tmp_path):
    other = (("critical", claim("kev", {"cve_id": CVE, "name": "OpenAI Codex"}, "Codex")),)
    assert lowering(tmp_path, adv(id=CVE, level="critical"), "notice", Net().set(verify.KEV_URL, kev()), other) is None


def test_support_through_an_alias_refuses_a_claimed_delisting(tmp_path):
    a = adv(id=CVE, aliases=[G1], level="critical")
    sources = Net().set(verify.KEV_URL, kev()).set(gurl(G1), ghsa(cve=CVE))  # the advisory gives high
    assert lowering(tmp_path, a, "notice", sources, KEV_CLAIM) is False
    assert lowering(tmp_path, a, "high", sources, KEV_CLAIM) is True


def test_the_alias_that_supported_the_thread_is_read_first(tmp_path):
    """Only MAX_ALIASES are read. A reply dated before the one that added the supporting
    alias puts three others in front of it; the read must still reach it."""
    sources = Net().set(verify.KEV_URL, kev()).set(gurl(G1), ghsa(type="malware", cve=CVE))
    a = adv(id=CVE, aliases=[G1], level="critical")
    assert lowering(tmp_path, a, "high", sources) is False
    crowded = adv(id=CVE, aliases=[G2, G3, G4, G1], level="critical")
    n = Net().set(verify.KEV_URL, kev()).set(gurl(G1), ghsa(type="malware", cve=CVE))
    assert lowering(tmp_path, crowded, "high", n, now=NOW + 60) is False
    assert n.urls[:2] == [verify.KEV_URL, gurl(G1)]
