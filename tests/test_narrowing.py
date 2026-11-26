"""A relay-bot narrowing of products is kept as published and decided by ``standing``
(ai-tools-alerts#swfe, rule 6 of the revised design on ai-tools-alerts#h29n): the reader."""

from dataclasses import asdict

import pytest

from aitools_alerts import pull
from aitools_alerts.schema import Product
from mirror_helpers import T0, advisory
from test_curator_hold import AT, CC, DAY, HOLD, bot_root, says, thread

WAIT = pull.UNCHECKED_LOWERING_S
WIDE = [Product(**CC)]
FIX = dict(CC, affected="<9.9.9", fixed="9.9.9")  # a shorter range and an earlier fix
CODEX = {"name": "Codex CLI", "ecosystem": "codex", "affected": "<5.0.0", "fixed": "5.0.0"}


@pytest.fixture(autouse=True)
def _home(home):
    return home


def narrow(m, root, *entries, at=AT, sec=None):
    return m.reply(sec or m.bot_sec, root, m.patch_text(products=list(entries)), created_at=at)


def check(narrowing=None, level=None, asked=None):
    """A ``check`` of pull.standing that answers a narrowing with ``narrowing``."""
    c = says(level)

    def ask(adv, products):
        if asked is not None:
            asked.append((adv, products))
        return narrowing
    c.narrowing = ask
    return c


def seen(m, now, check=None, since=None, listed=None):
    (t,) = pull.active([thread(m)], now, listed, check, since=since)
    return [asdict(p) for p in t.adv.products], t.narrow_waiting, t.narrow_refused


# ---------------------------------------------------------------- what is kept

def test_a_narrower_list_is_kept_as_published_and_joins_nothing_away(mirror):
    root = bot_root(mirror)
    reply = narrow(mirror, root, FIX)
    t = thread(mirror)
    assert t.narrowed == (Product(**FIX),) and t.narrowed_by == reply["id"]
    assert t.adv.products == WIDE and t.wide.products == WIDE and pull.widest(t).products == WIDE
    assert pull.standing(t) == t  # no check, no record: nothing applies and nothing is said


def test_the_same_list_again_keeps_the_first_reply_and_another_list_names_a_new_one(mirror):
    root = bot_root(mirror)
    first = narrow(mirror, root, FIX)
    narrow(mirror, root, FIX, at=AT + 10)
    assert thread(mirror).narrowed_by == first["id"]
    other = narrow(mirror, root, dict(FIX, affected="<9.0.0", fixed="9.0.0"), at=AT + 20)
    t = thread(mirror)
    assert (t.narrowed[0].fixed, t.narrowed_by) == ("9.0.0", other["id"])


@pytest.mark.parametrize("entries", [[CC], [dict(CC, affected="*", fixed=None)], [CC, CODEX]])
def test_a_list_that_stands_for_the_widest_state_ends_the_offer(mirror, entries):
    root = bot_root(mirror)
    narrow(mirror, root, FIX)
    narrow(mirror, root, *entries, at=AT + 10)
    t = thread(mirror)
    assert (t.narrowed, t.narrowed_by) == (None, None)


def test_a_list_that_adds_one_product_and_drops_another_is_a_narrowing(mirror):
    root = bot_root(mirror)
    reply = narrow(mirror, root, CODEX)
    t = thread(mirror)
    assert t.narrowed == (Product(**CODEX),) and t.narrowed_by == reply["id"]
    assert [p.name for p in t.wide.products] == ["Claude Code", "Codex CLI"]  # the join keeps both


def test_a_products_block_that_does_not_validate_changes_no_offer(mirror):
    root = bot_root(mirror)
    first = narrow(mirror, root, FIX)
    narrow(mirror, root, dict(FIX, fixed="not a version"), at=AT + 10)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products="none"), created_at=AT + 20)
    assert thread(mirror).narrowed_by == first["id"]


def test_a_narrowing_sent_with_a_refused_level_is_still_an_offer(mirror):
    root = bot_root(mirror)
    reply = mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="notice", products=[FIX]), created_at=AT)
    t = thread(mirror)
    assert t.narrowed_by == reply["id"] and t.adv.level == "critical" and t.offered is None


def test_a_curator_s_products_end_the_offer_and_a_curator_s_own_thread_has_none(mirror):
    root = bot_root(mirror)
    narrow(mirror, root, FIX)
    narrow(mirror, root, FIX, at=AT + 10, sec=mirror.cur_sec)
    assert thread(mirror).narrowed is None
    mirror.events["feed.json"].clear()
    own = mirror.root_post(mirror.cur_sec, advisory(), created_at=T0 + 100, files=("feed.json",))
    narrow(mirror, own, FIX)
    assert thread(mirror).narrowed is None and thread(mirror).wide is None


def test_a_flooded_thread_still_takes_an_offer_and_can_be_corrected(mirror):
    root = bot_root(mirror)
    for n in range(5):  # 250 entries none of which stands for another
        narrow(mirror, root, *[dict(CC, name=f"Product {n}-{i}") for i in range(50)], at=AT + n)
    assert len(thread(mirror).wide.products) > pull._JOIN_SCAN
    reply = narrow(mirror, root, CC, at=AT + 50)  # past the scan no list is compared: every valid one is an offer
    t = thread(mirror)
    assert t.narrowed == tuple(WIDE) and t.narrowed_by == reply["id"] and len(t.narrowings) == 6
    assert seen(mirror, AT + 100 + WAIT, check(None), {reply["id"]: AT + 100}) == ([CC], False, False)


def test_every_list_the_thread_published_keeps_its_key(mirror):
    root = bot_root(mirror)
    narrow(mirror, root, FIX)
    other = dict(FIX, affected="<9.0.0", fixed="9.0.0")
    narrow(mirror, root, other, at=AT + 10)
    narrow(mirror, root, CC, at=AT + 20)  # the offer ends; what was published stays known
    narrow(mirror, root, FIX, at=AT + 30)
    t = thread(mirror)
    key = pull.narrow_key(root["id"], [Product(**FIX)])
    assert t.narrowings == (key, pull.narrow_key(root["id"], [Product(**other)]))
    assert pull.narrow_key(root["id"], t.narrowed) == key != pull.narrow_key("0" * 64, t.narrowed)
    assert len(key) == 64 and int(key, 16) >= 0


# ---------------------------------------------------------------- what stands

def test_confirmed_applies_at_once_and_only_the_products_change(mirror):
    root = bot_root(mirror)
    narrow(mirror, root, FIX)
    asked = []
    (t,) = pull.active([thread(mirror)], AT + 1, None, check(True, asked=asked))
    assert [asdict(p) for p in t.adv.products] == [FIX] and not t.narrow_waiting and not t.narrow_refused
    assert t.adv.level == "critical" and t.adv.actions == thread(mirror).wide.actions
    assert asked == [(pull.widest(thread(mirror)), (Product(**FIX),))]  # asked about the widest state


def test_contradicted_never_applies(mirror):
    root = bot_root(mirror)
    reply = narrow(mirror, root, FIX)
    since = {reply["id"]: AT + 100}
    assert seen(mirror, AT + 900 * DAY, check(False), since) == ([CC], False, True)


def test_unsettled_applies_after_72_hours_of_the_clock_it_is_given(mirror):
    root = bot_root(mirror)
    reply = narrow(mirror, root, FIX)
    since = {reply["id"]: AT + 100}
    assert seen(mirror, AT + 100 + WAIT - 1, check(None), since) == ([CC], True, False)
    assert seen(mirror, AT + 100 + WAIT, check(None), since) == ([FIX], False, False)
    assert seen(mirror, AT + 100 + WAIT, None, since) == ([FIX], False, False)  # no check at all: verify = "off"
    assert seen(mirror, AT + 100 + WAIT, says(None), since) == ([FIX], False, False)  # a check that knows no narrowing
    # no record, or none of this reply: no wait runs, and nothing says one does
    assert seen(mirror, AT + 900 * DAY, check(None), None) == ([CC], False, False)
    assert seen(mirror, AT + 900 * DAY, check(None), {}) == ([CC], False, False)
    assert seen(mirror, None, check(None), since) == ([CC], True, False)  # no checkpoint, no clock


def test_a_record_counts_only_while_the_checkpoint_lists_the_reply(mirror):
    root = bot_root(mirror)
    reply = narrow(mirror, root, FIX)
    since = {reply["id"]: AT + 100}
    assert seen(mirror, AT + 100 + WAIT, check(None), since, listed={root["id"]}) == ([CC], False, False)
    assert seen(mirror, AT + 100 + WAIT, check(None), since, listed={root["id"], reply["id"]})[0] == [FIX]


def test_a_curator_s_hold_governs_until_it_lapses(mirror):
    root = bot_root(mirror)
    narrow(mirror, root, FIX)
    mirror.reply(mirror.cur_sec, root, "level: high", created_at=AT + 10)
    held = seen(mirror, AT + 10 + HOLD, check(True))
    assert held == ([CC], False, False)
    assert seen(mirror, AT + 11 + HOLD, check(True)) == ([FIX], False, False)


def test_a_lowering_and_a_narrowing_on_one_thread_are_decided_apart(mirror):
    root = bot_root(mirror)
    low = mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="high"), created_at=AT)
    reply = narrow(mirror, root, FIX, at=AT + 10)
    (t,) = pull.active([thread(mirror)], AT + 20, None, check(True, level=False))
    assert (t.adv.level, t.refused, [asdict(p) for p in t.adv.products]) == ("critical", "high", [FIX])
    (t,) = pull.active([thread(mirror)], AT + 20, None, check(False, level=True))
    assert (t.adv.level, t.narrow_refused, [asdict(p) for p in t.adv.products]) == ("high", True, [CC])
    since = {low["id"]: AT + 100, reply["id"]: AT + 100 + DAY}
    (t,) = pull.active([thread(mirror)], AT + 100 + WAIT, None, check(None), since=since)
    assert (t.adv.level, t.waiting, t.narrow_waiting, t.adv.products) == ("high", None, True, WIDE)


def test_a_retracted_thread_takes_no_narrowing(mirror):
    root = bot_root(mirror)
    narrow(mirror, root, FIX)
    mirror.reply(mirror.cur_sec, root, "retract", created_at=AT + 10)
    assert pull.standing(thread(mirror), AT + 20, check(True)).retracted


# ---------------------------------------------------------------- the record

def test_offers_records_the_narrowing_reply_under_the_checkpoint_that_lists_it(mirror):
    root = bot_root(mirror)
    reply = narrow(mirror, root, FIX)
    ts = [thread(mirror)]
    both = {root["id"], reply["id"]}
    assert pull.offers(ts, {}, AT + 100, both) == {reply["id"]: AT + 100}
    assert pull.offers(ts, {reply["id"]: AT + 100}, AT + 500, both) == {reply["id"]: AT + 100}  # the first time stays
    assert pull.offers(ts, {reply["id"]: AT + 100}, AT + 500, {root["id"]}) == {}  # no longer listed: from nothing
    assert pull.offers(ts, {reply["id"]: AT + 100}, None, None) == {reply["id"]: AT + 100}  # no checkpoint: unchanged
    narrow(mirror, root, CC, at=AT + 10)  # the offer ends
    assert pull.offers([thread(mirror)], {reply["id"]: AT + 100}, AT + 500, both) == {}
