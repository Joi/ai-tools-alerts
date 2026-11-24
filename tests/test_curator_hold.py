"""A curator's word on a relay-bot thread holds 14 days, is checked by the member, and no
longer silences the bot (ai-tools-alerts#c1g2, finding D9 of the design review)."""

import pytest

from aitools_alerts import pull, wire
from mirror_helpers import T0, Mirror, advisory

DAY = 86400
HOLD = pull.CURATOR_HOLD_S
AT = T0 + 300  # when the curator acts
CC = {"name": "Claude Code", "ecosystem": "claude-code", "affected": "<99.0.0", "fixed": "99.0.0"}


@pytest.fixture(autouse=True)
def _home(home):
    return home


def bot_root(m: Mirror, **over):
    return m.root_post(m.bot_sec, advisory(posted_by="relay-bot", **over), created_at=T0 + 100, files=("feed.json",))


def thread(m: Mirror):
    (t,) = pull.threads_from(m.events["feed.json"], m.man)
    return t


def shown(m: Mirror, now, check=None, listed=None):
    """The thread as a member sees it under a checkpoint issued at ``now``, or None."""
    ts = pull.active([thread(m)], now, listed, check)
    return ts[0] if ts else None


def says(answer, asked=None):
    def check(adv, level, stated=()):
        if asked is not None:
            asked.append((adv, level))
        return answer
    return check


# ---------------------------------------------------------------- the hold

def test_fourteen_days():
    assert HOLD == 14 * DAY


def test_a_retraction_holds_fourteen_days_and_lapses_unless_renewed(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "retract\nfalse alarm", created_at=AT)
    t = thread(mirror)
    assert t.retracted and t.held_until == AT + HOLD and t.offered == pull.NONE and t.wide.level == "critical"
    assert shown(mirror, AT + HOLD) is None
    back = shown(mirror, AT + HOLD + 1)
    assert back.adv.level == "critical" and not back.retracted and not back.curated
    assert shown(mirror, None) is None  # no checkpoint: no clock, nothing lapses
    mirror.reply(mirror.cur_sec, root, "retract", created_at=AT + 10 * DAY)  # said again: renewed
    assert shown(mirror, AT + 20 * DAY) is None and shown(mirror, AT + 24 * DAY) is None
    assert shown(mirror, AT + 24 * DAY + 1).adv.level == "critical"


def test_a_lowering_holds_fourteen_days_and_lapses_unless_renewed(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT)
    assert shown(mirror, AT + HOLD).adv.level == "notice" and shown(mirror, AT + HOLD + 1).adv.level == "critical"
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT + 13 * DAY)  # the same level again
    assert thread(mirror).held_until == AT + 27 * DAY
    assert shown(mirror, AT + 27 * DAY).adv.level == "notice" and shown(mirror, AT + 27 * DAY + 1).adv.level == "critical"


def test_a_hold_lapses_only_under_a_checkpoint_that_lists_the_root(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT)
    late = AT + HOLD + 1
    assert shown(mirror, late, listed=frozenset()).adv.level == "notice"
    assert shown(mirror, late, listed=frozenset({root["id"]})).adv.level == "critical"


def test_a_narrowing_and_an_expiry_lapse_with_the_hold(mirror):
    root = bot_root(mirror)
    other = {"name": "Other", "ecosystem": "git", "affected": "<0.1", "fixed": "0.1"}
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(products=[other], actions=[], expires_at=AT + DAY), created_at=AT)
    held = shown(mirror, AT + 10)
    assert [p.name for p in held.adv.products] == ["Other"] and held.adv.actions == [] and held.curated
    assert shown(mirror, AT + DAY + 1) is None  # the curator's expiry, while its hold is in force
    back = shown(mirror, AT + HOLD + 1)
    # what the curator added stays, what it took away is back, the expiry is gone
    assert sorted(p.name for p in back.adv.products) == ["Claude Code", "Other"]
    assert len(back.adv.actions) == 1 and back.adv.expires_at is None


def test_what_a_curator_adds_or_raises_outlasts_the_hold(mirror):
    root = bot_root(mirror, level="high")
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(level="critical", title="Curated"), created_at=AT)
    t = shown(mirror, AT + 365 * DAY)
    assert (t.adv.level, t.adv.title, t.offered) == ("critical", "Curated", None)


def test_a_curator_raise_sent_with_an_expiry_outlasts_the_hold_and_the_expiry_does_not(mirror):
    root = bot_root(mirror, level="high")
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(level="critical", expires_at=AT + 300 * DAY), created_at=AT)
    t = thread(mirror)
    assert (t.adv.level, t.adv.expires_at, t.wide.level, t.wide.expires_at) == ("critical", AT + 300 * DAY, "critical", None)
    assert shown(mirror, AT + HOLD + 1).adv.level == "critical"


# ---------------------------------------------------------------- the bot is not silenced

def test_a_bot_raise_shows_at_once_and_any_other_change_after_the_hold(mirror):
    root = bot_root(mirror, level="high")
    mirror.reply(mirror.cur_sec, root, "level: notice\n" + mirror.patch_text(title="Curated"), created_at=AT)
    wider = dict(CC, affected="<99.5.0", fixed="99.5.0")
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(title="The bot's", products=[wider]), created_at=AT + DAY)
    t = shown(mirror, AT + 2 * DAY)
    assert (t.adv.level, t.adv.title, t.adv.products[0].fixed) == ("notice", "Curated", "99.0.0")
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical", title="Raised"), created_at=AT + 3 * DAY)
    t = shown(mirror, AT + 4 * DAY)
    assert (t.adv.level, t.adv.title, t.adv.products[0].fixed) == ("critical", "Curated", "99.0.0")
    t = shown(mirror, AT + HOLD + 1)
    assert (t.adv.level, t.adv.title, t.adv.products[0].fixed) == ("critical", "Raised", "99.5.0")


def test_a_bot_level_between_the_held_and_the_widest_raises_the_held_one(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="high"), created_at=AT + DAY)
    t = thread(mirror)
    assert (t.adv.level, t.wide.level, t.offered) == ("high", "critical", "high")
    assert shown(mirror, AT + HOLD + 1).adv.level == "critical"  # nobody confirmed the lowering to high


def test_a_bot_raise_does_not_undo_a_retraction(mirror):
    root = bot_root(mirror, level="high")
    mirror.reply(mirror.cur_sec, root, "retract", created_at=AT)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=AT + DAY)
    assert shown(mirror, AT + 2 * DAY) is None
    assert shown(mirror, AT + HOLD + 1).adv.level == "critical"


def test_no_relay_bot_event_however_dated_ends_a_hold(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(title="Years ahead"), created_at=AT + 3650 * DAY)
    mirror.reply(mirror.bot_sec, root, "still here", created_at=AT + 3651 * DAY)
    t = thread(mirror)
    assert (t.adv.level, t.adv.title, t.held_until) == ("notice", advisory().title, AT + HOLD)


def test_a_later_curator_reply_does_not_bring_a_lapsed_lowering_back(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT)
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(title="A fix of the title"), created_at=AT + 20 * DAY)
    t = shown(mirror, AT + 21 * DAY)
    assert (t.adv.level, t.adv.title, t.held_until) == ("critical", "A fix of the title", AT + 34 * DAY)


def test_claims_are_counted_through_a_retraction(mirror):
    cve = "CVE-2098-0001"

    def claim(at):
        return wire.claim_tag({"id": cve, "source": "kev", "fields": {"cve_id": cve, "name": None}, "ruleset": 1,
                               "level": "critical", "confirmed_at": at, "checked_at": at})
    root = mirror.root_post(mirror.bot_sec, advisory(id=cve, posted_by="relay-bot"), created_at=T0 + 100,
                            files=("feed.json",), tags=[claim(T0 + 100)])
    mirror.reply(mirror.cur_sec, root, "retract", created_at=AT)
    mirror.post(mirror.bot_sec, "Still listed.", created_at=AT + 13 * DAY, tags=[["e", root["id"], "", "root"], claim(AT + 13 * DAY)])
    assert shown(mirror, AT + 13 * DAY) is None
    assert shown(mirror, AT + 20 * DAY).adv.level == "critical"  # the renewal made while retracted keeps it standing
    assert shown(mirror, AT + 28 * DAY).adv.level == "high"  # and it decays by its claims again


# ---------------------------------------------------------------- what is not touched

def test_a_curator_s_own_thread_is_as_before(mirror):
    root = mirror.root_post(mirror.cur_sec, advisory(), created_at=T0 + 100, files=("feed.json",))
    mirror.reply(mirror.cur_sec, root, "level: high", created_at=AT)
    for at in (AT + DAY, AT + 15 * DAY, AT + 400 * DAY):
        mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical", title="The bot's"), created_at=at)
    t = thread(mirror)
    assert (t.wide, t.held_until, t.offered, t.curated) == (None, None, None, True)
    assert shown(mirror, AT + 500 * DAY).adv == advisory(level="high")
    mirror.reply(mirror.cur_sec, root, "retract", created_at=AT + 401 * DAY)
    assert thread(mirror).retracted and shown(mirror, AT + 3650 * DAY) is None  # for good


def test_the_manifest_s_retraction_never_lapses(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "level: notice", created_at=AT)
    mirror.publish_manifest(retracted=["AITA-TEST-0001"])
    t = thread(mirror)
    assert t.retracted and t.wide is None and shown(mirror, AT + 3650 * DAY, says(False)) is None


# ---------------------------------------------------------------- a published lowering and the check

def test_a_relay_bot_lowering_is_published_and_applied_only_when_the_check_confirms(mirror):
    root = bot_root(mirror)
    dropped = __import__("collections").Counter()
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="high"), created_at=AT)
    (t,) = pull.threads_from(mirror.events["feed.json"], mirror.man, dropped)
    assert (t.adv.level, t.offered, t.held_until, dropped["bad-patch"]) == ("critical", "high", None, 0)
    asked = []
    assert shown(mirror, AT + DAY).adv.level == "critical"  # no check: nothing settles it
    assert shown(mirror, AT + DAY, says(None)).adv.level == "critical"
    low = shown(mirror, AT + DAY, says(True, asked))
    assert (low.adv.level, low.refused) == ("high", None) and asked == [(pull.widest(t), "high")]
    kept = shown(mirror, AT + DAY, says(False))
    assert (kept.adv.level, kept.refused) == ("critical", "high")
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=AT + 2 * DAY)
    assert thread(mirror).offered is None and shown(mirror, AT + 3 * DAY, says(True)).adv.level == "critical"


def test_a_lowering_mixed_with_anything_else_is_refused_as_before(mirror):
    root = bot_root(mirror)
    dropped = __import__("collections").Counter()
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="high", title="And a title"), created_at=AT)
    (t,) = pull.threads_from(mirror.events["feed.json"], mirror.man, dropped)
    assert (t.adv.level, t.adv.title, t.offered, dropped["bad-patch"]) == ("critical", advisory().title, None, 1)


def test_a_curator_s_lowering_the_check_contradicts_is_not_applied_narrowing_and_all(mirror):
    root = bot_root(mirror)
    other = {"name": "Other", "ecosystem": "git", "affected": "<0.1", "fixed": "0.1"}
    mirror.reply(mirror.cur_sec, root, "level: notice\n" + mirror.patch_text(products=[other]), created_at=AT)
    asked = []
    held = shown(mirror, AT + DAY, says(None, asked))
    assert (held.adv.level, [p.name for p in held.adv.products], held.refused) == ("notice", ["Other"], None)
    assert [(level, [p.name for p in adv.products]) for adv, level in asked] == [("notice", ["Claude Code", "Other"])]
    kept = shown(mirror, AT + DAY, says(False))
    assert (kept.adv.level, sorted(p.name for p in kept.adv.products), kept.refused) == (
        "critical", ["Claude Code", "Other"], "notice")
    # confirmed: as the curator left it while the hold lasts, then the widest state at that level
    assert shown(mirror, AT + DAY, says(True)).adv.level == "notice"
    after = shown(mirror, AT + HOLD + 1, says(True))
    assert (after.adv.level, sorted(p.name for p in after.adv.products)) == ("notice", ["Claude Code", "Other"])
    assert shown(mirror, AT + HOLD + 1, says(None)).adv.level == "critical"


def test_a_retraction_the_check_contradicts_is_not_applied(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "retract", created_at=AT)
    asked = []
    kept = shown(mirror, AT + DAY, says(False, asked))
    assert (kept.adv.level, kept.retracted, kept.refused) == ("critical", False, pull.NONE)
    assert [level for _, level in asked] == [pull.NONE]
    assert shown(mirror, AT + HOLD + 1, says(False)).refused == pull.NONE


def test_the_check_is_asked_about_every_alias_and_the_fixed_version_the_thread_has_held(mirror):
    """A relay-bot reply may replace the aliases and clear ``fixed`` (a widening for
    matching). Neither may change what the source check is asked: with no fixed version
    the source's level would be held to the action cap, and a lowering to it confirmed."""
    root = bot_root(mirror, aliases=["GHSA-aaaa-bbbb-cccc"])
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(aliases=[], products=[dict(CC, fixed=None)]), created_at=AT)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="high"), created_at=AT + 10)
    t = thread(mirror)
    assert t.adv.aliases == [] and [p.fixed for p in t.adv.products] == [None] and t.offered == "high"
    w = pull.widest(t)
    assert w.aliases == ["GHSA-aaaa-bbbb-cccc"] and [p.fixed for p in w.products] == ["99.0.0"]
    assert pull.asks(t) == ["high"]


def test_a_curator_block_s_level_is_published_and_a_later_raise_withdraws_it(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(level="high"), created_at=AT)  # a lowering in a block
    t = thread(mirror)
    assert (t.adv.level, t.wide.level, t.offered) == ("high", "critical", "high")
    assert shown(mirror, AT + HOLD + 1, says(True)).adv.level == "high"  # confirmed: it outlasts the hold
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(level="critical"), created_at=AT + DAY)  # the curator takes it back
    t = thread(mirror)
    assert (t.adv.level, t.offered) == ("critical", None)
    assert shown(mirror, AT + DAY + HOLD + 1, says(True)).adv.level == "critical"  # no stale offer to confirm


def test_a_level_line_followed_by_a_raising_block_leaves_nothing_published(mirror):
    root = bot_root(mirror)
    mirror.reply(mirror.cur_sec, root, "level: high", created_at=AT)
    mirror.reply(mirror.cur_sec, root, "level: notice\n" + mirror.patch_text(level="critical"), created_at=AT + DAY)
    t = thread(mirror)
    assert (t.adv.level, t.offered) == ("critical", None)


def test_a_product_put_in_another_spelling_is_still_asked_about_by_its_first_name(mirror):
    """The join compares product names without case; the source check reads the scope
    file's exact name. An entry in capitals can take the original's place."""
    root = bot_root(mirror)
    loud = {"name": "CLAUDE CODE", "ecosystem": "claude-code", "affected": None, "fixed": None}
    mirror.reply(mirror.cur_sec, root, "level: notice\n" + mirror.patch_text(products=[loud]), created_at=AT)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[loud]), created_at=AT + 10)
    t = thread(mirror)
    assert [p.name for p in t.adv.products] == ["CLAUDE CODE"]  # the curator's held state
    assert ("Claude Code", "99.0.0") in [(p.name, p.fixed) for p in pull.widest(t).products]
    # Whatever the join's rule for names is, a name the widest state has lost is still asked about.
    from dataclasses import replace
    lost = replace(t, wide=replace(t.wide, products=list(t.adv.products)), held_products=(schema_product(),))
    assert [(p.name, p.fixed) for p in pull.widest(lost).products] == [("CLAUDE CODE", None), ("Claude Code", "99.0.0")]


def test_a_fix_and_an_alias_a_curator_supplied_are_part_of_what_is_asked(mirror):
    root = bot_root(mirror, level="high", products=[schema_product(fixed=None)], actions=[])
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(
        level="critical", products=[CC], actions=[{"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"}]),
        created_at=AT)
    mirror.reply(mirror.cur_sec, root, "level: high\n" + mirror.patch_text(aliases=["GHSA-aaaa-bbbb-cccc"]),
                 created_at=AT + 10)
    t = thread(mirror)
    assert [p.fixed for p in t.wide.products] == [None]  # the bot's rules do not take a fix where there was none
    w = pull.widest(t)
    assert [p.fixed for p in w.products] == ["99.0.0"] and w.aliases == ["GHSA-aaaa-bbbb-cccc"]


def test_a_flood_of_aliases_is_kept_once_each(mirror):
    root = bot_root(mirror)
    for i in range(40):
        mirror.reply(mirror.bot_sec, root, mirror.patch_text(aliases=[f"AITA-X-{i}-{j}" for j in range(50)]),
                     created_at=AT + i)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(aliases=["AITA-X-0-0"]), created_at=AT + 100)
    t = thread(mirror)
    assert len(t.held_aliases) == 2000 == len(set(t.held_aliases)) and t.adv.aliases == ["AITA-X-0-0"]


def schema_product(**over):
    from aitools_alerts.schema import Product
    return Product(**{**CC, **over})


def test_asks(mirror):
    root = bot_root(mirror)
    assert pull.asks(thread(mirror)) == []
    mirror.reply(mirror.cur_sec, root, "level: high", created_at=AT)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="notice"), created_at=AT + 10)
    t = thread(mirror)
    assert pull.asks(t) == ["high", "notice"] and pull.asks(t, AT + HOLD + 1) == ["notice"]
