"""A relay-bot patch never shrinks what a member sees (ai-tools-alerts#tyje).

Finding D1 of the 2026-11-23 design review: with the relay-bot key, a patch
that lowers ``fixed``, replaces ``products``, empties ``actions`` or replaces
``sources`` was applied whole, so one signature took an alert away from every
member while its thread still read critical."""

from collections import Counter

import pytest

from aitools_alerts import check, pull, versions
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.schema import Action, Product, Source
from aitools_alerts.state import State
from mirror_helpers import T0, advisory

MEMBER = Inventory(products={"claude-code": [Installed("Claude Code", "2.1.3", "claude")]})
CC = {"name": "Claude Code", "ecosystem": "claude-code", "affected": "<99.0.0", "fixed": "99.0.0"}
UPGRADE = Action("upgrade", "Claude Code", "99.0.0")
SOURCE = "https://example.invalid/advisory"


@pytest.fixture(autouse=True)
def _home(home):
    return home


def read(mirror):
    """(the one thread, the dropped counter) after a member's pull."""
    st = State.load()
    res = pull.fetch("https://mirror.example.invalid/alerts", st, fetch=mirror.fetch,
                     root_pubkey=mirror.root, now=T0 + 1000)
    assert res.error is None, res.error
    dropped = Counter()
    [t] = pull.advisories(State.load(), dropped)
    return t, dropped


def bot_thread(mirror, patch_sec=None, adv=None, **patch):
    root = mirror.root_post(mirror.bot_sec, adv or advisory(posted_by="relay-bot"))
    mirror.reply(patch_sec or mirror.bot_sec, root, mirror.patch_text(**patch))
    return read(mirror)


def member_sees(t):
    """The upgrade the member is shown for the thread, or None when the
    member's installation no longer matches it."""
    found = check.match([t.adv], MEMBER)
    if not found:
        return None
    return [a for m in found for a in check.plan(m, check.Config()).prepare]


# ------------------------------------------- the four patches of finding D1

SILENCERS = {
    "fixed lowered": {"products": [dict(CC, fixed="0.0.1")]},
    "products replaced": {"products": [{"name": "Nobody Runs This", "ecosystem": "git",
                                        "affected": "<0.1", "fixed": "0.1"}]},
    "actions emptied": {"actions": []},
    "sources replaced": {"sources": [{"url": "https://example.invalid/unrelated", "published_at": None}]},
}


@pytest.mark.parametrize("name", sorted(SILENCERS))
def test_a_relay_bot_patch_cannot_silence_its_alert(mirror, name):
    t, dropped = bot_thread(mirror, **SILENCERS[name])
    assert t.adv == advisory(posted_by="relay-bot")  # nothing of the patch applied
    assert member_sees(t) == [UPGRADE]
    assert [s.url for s in t.adv.sources] == [SOURCE]
    assert dropped == {"narrowing": 1}


def test_all_four_in_one_patch_count_once_and_the_rest_applies(mirror):
    patch = {k: v for p in SILENCERS.values() for k, v in p.items()}
    t, dropped = bot_thread(mirror, title="Resolved", **patch)
    assert t.adv == advisory(posted_by="relay-bot", title="Resolved")
    assert member_sees(t) == [UPGRADE] and dropped == {"narrowing": 1}


@pytest.mark.parametrize("products", [
    [dict(CC, affected="<2.0.0")],                    # a narrower range
    [dict(CC, affected=">=2.1.4,<99.0.0")],           # a lower bound where there was none
    [dict(CC, name="claude-code")],                   # another spelling is another name
    [dict(CC, ecosystem="codex")],
    [dict(CC, fixed="1.0zz")],                        # unreadable: every match would lose its actions
    [dict(CC, affected="=2.1.3", fixed=None)],
])
def test_narrower_products_are_held(mirror, products):
    t, dropped = bot_thread(mirror, products=products)
    assert t.adv.products == advisory().products and dropped == {"narrowing": 1}
    assert member_sees(t) == [UPGRADE]


def test_a_fixed_version_where_there_was_none_is_held(mirror):
    """The patch a real fix sends, and the one a thief sends with 0.0.1: the
    reader cannot tell them apart, so members at the fixed version keep the
    alert until a curator or the member's own source check confirms it."""
    nofix = advisory(posted_by="relay-bot", products=[Product("Claude Code", "claude-code", None, None)],
                     actions=[])
    t, dropped = bot_thread(mirror, adv=nofix, products=[dict(CC, affected=None, fixed="0.0.1")],
                            actions=[{"verb": "upgrade", "target": "Claude Code", "value": "0.0.1"}])
    assert t.adv.products == nofix.products and dropped == {"narrowing": 1}
    assert t.adv.actions == [Action("upgrade", "Claude Code", "0.0.1")]  # an action added: applied
    assert member_sees(t) == [Action("upgrade", "Claude Code", None)]  # the version is products[].fixed


@pytest.mark.parametrize("fixed,shown", [("99.0.0", "99.0.0"), (None, None)])
def test_fixed_never_falls_inside_an_unchanged_range(mirror, fixed, shown):
    """``affected`` alone already bounds the match at 50.0.0, so a ``fixed``
    of 50.0.0 takes no member out of the match set. It would still change the
    upgrade the member is shown, which check.plan reads from ``fixed``."""
    adv = advisory(posted_by="relay-bot", products=[Product("Claude Code", "claude-code", "<50.0.0", fixed)],
                   actions=[Action("upgrade", "Claude Code", fixed)])
    t, dropped = bot_thread(mirror, adv=adv, products=[dict(CC, affected="<50.0.0", fixed="50.0.0")])
    assert t.adv == adv and dropped == {"narrowing": 1}
    assert member_sees(t) == [Action("upgrade", "Claude Code", shown)]


def test_a_curator_amendment_does_not_adopt_a_held_narrowing(mirror):
    """A curator's patch replaces the fields it names. A field it omits was
    never the curator's word: it stays as the reader holds it, not as the
    bot's refused patch left it."""
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot"))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[
        {"name": "Codex", "ecosystem": "codex", "affected": "<9.0", "fixed": "9.0"}]), created_at=T0 + 150)
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(title="Retitled by a person"), created_at=T0 + 160)
    t, dropped = read(mirror)
    assert t.adv == advisory(posted_by="relay-bot", title="Retitled by a person")
    assert member_sees(t) == [UPGRADE] and dropped == {"narrowing": 1}


@pytest.mark.parametrize("actions", [
    [{"verb": "upgrade", "target": "Claude Code", "value": "0.0.1"}],   # the version lowered
    [{"verb": "upgrade", "target": "Claude Code", "value": None}],      # the version taken away
    [{"verb": "upgrade", "target": "Other", "value": "99.0.0"}],
    [{"verb": "review_setting", "target": "Claude Code", "value": "99.0.0"}],
])
def test_an_action_changed_into_less_is_held(mirror, actions):
    t, dropped = bot_thread(mirror, actions=actions)
    assert t.adv.actions == [UPGRADE] and dropped == {"narrowing": 1}


def test_a_changed_value_of_another_verb_is_held(mirror):
    adv = advisory(posted_by="relay-bot", actions=[UPGRADE, Action("rotate_credential", "api key", "now")])
    t, dropped = bot_thread(mirror, adv=adv, actions=[
        {"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"},
        {"verb": "rotate_credential", "target": "api key", "value": "later"}])
    assert t.adv.actions == adv.actions and dropped == {"narrowing": 1}


def test_an_upgrade_with_no_version_cannot_gain_one(mirror):
    """Asserted on the stored action: check.plan would hide it, since it
    takes the version from ``fixed``."""
    adv = advisory(posted_by="relay-bot", products=[Product("Claude Code", "claude-code", "<50.0.0", None)],
                   actions=[Action("upgrade", "Claude Code", None)])
    t, dropped = bot_thread(mirror, adv=adv, actions=[{"verb": "upgrade", "target": "Claude Code", "value": "0.0.1"}])
    assert t.adv.actions == [Action("upgrade", "Claude Code", None)] and dropped == {"narrowing": 1}


CODEX = {"name": "Codex", "ecosystem": "codex", "affected": "<9.0", "fixed": "9.0"}
GIT = {"name": "git", "ecosystem": "git", "affected": "<3.0", "fixed": "3.0"}
STOP = {"verb": "stop_using", "target": "Claude Code", "value": None}
UP = {"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"}
SRC = [{"url": SOURCE, "published_at": None}, {"url": "https://example.invalid/second", "published_at": None}]
NEW_SRC = {"url": "https://example.invalid/third", "published_at": None}


@pytest.mark.parametrize("field,start,patched", [
    ("products", [CC, CODEX], [CC]),                    # one of two entries removed
    ("products", [CC, CODEX], [CODEX]),
    ("products", [CC, CODEX], [CC, GIT]),               # one removed, one added
    ("products", [CC, CODEX], [dict(CC, fixed="0.0.1"), CODEX, GIT]),  # one narrowed, one added
    ("actions", [UP, STOP], [UP]),
    ("actions", [UP, STOP], [STOP]),
    ("actions", [UP, STOP], [UP, {"verb": "review_setting", "target": "x", "value": None}]),
    ("sources", SRC, SRC[:1]),
    ("sources", SRC, SRC[1:]),
    ("sources", SRC, [SRC[0], NEW_SRC]),
])
def test_every_entry_of_a_list_is_kept_or_the_whole_field_is_held(mirror, field, start, patched):
    """Keeping one entry does not pay for dropping another, and nothing a
    refused field adds survives its refusal."""
    cls = {"products": Product, "actions": Action, "sources": Source}[field]
    adv = advisory(posted_by="relay-bot", **{field: [cls(**e) for e in start]})
    t, dropped = bot_thread(mirror, adv=adv, title="Other fields apply", **{field: patched})
    assert t.adv == advisory(posted_by="relay-bot", title="Other fields apply",
                             **{field: [cls(**e) for e in start]})
    assert dropped == {"narrowing": 1}


# ------------------------------------------------- what a bot patch may do

def test_a_relay_bot_patch_raising_fixed_applies(mirror):
    """A real correction: the first fix did not fix it."""
    t, dropped = bot_thread(mirror, products=[dict(CC, affected="<99.1.0", fixed="99.1.0")],
                            actions=[{"verb": "upgrade", "target": "Claude Code", "value": "99.1.0"}])
    assert t.adv.products == [Product("Claude Code", "claude-code", "<99.1.0", "99.1.0")]
    assert member_sees(t) == t.adv.actions == [Action("upgrade", "Claude Code", "99.1.0")]
    assert not dropped


@pytest.mark.parametrize("patch,field,want", [
    ({"products": [CC, {"name": "Codex", "ecosystem": "codex", "affected": "*", "fixed": None}]},
     "products", [Product(**CC), Product("Codex", "codex", "*", None)]),
    ({"products": [dict(CC, affected="<=99.0.0", fixed=None)]},
     "products", [Product("Claude Code", "claude-code", "<=99.0.0", None)]),
    ({"products": [dict(CC, affected=None, fixed=None)]},
     "products", [Product("Claude Code", "claude-code", None, None)]),
    ({"products": [dict(CC, name="CLAUDE CODE")]},  # the same name to check.match
     "products", [Product("CLAUDE CODE", "claude-code", "<99.0.0", "99.0.0")]),
    ({"actions": [{"verb": "stop_using", "target": "Claude Code", "value": None},
                  {"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"}]},
     "actions", [Action("stop_using", "Claude Code", None), UPGRADE]),
    ({"sources": [{"url": "https://example.invalid/vendor", "published_at": None},
                  {"url": SOURCE, "published_at": "2026-11-01"}]},
     "sources", [Source("https://example.invalid/vendor", None), Source(SOURCE, "2026-11-01")]),
])
def test_a_relay_bot_patch_may_add_and_widen(mirror, patch, field, want):
    t, dropped = bot_thread(mirror, **patch)
    assert getattr(t.adv, field) == want and not dropped
    assert member_sees(t)  # still matched, still an action


def test_a_narrowing_does_not_stop_a_level_raise(mirror):
    adv = advisory(posted_by="relay-bot", level="high")
    t, dropped = bot_thread(mirror, adv=adv, level="critical", products=[dict(CC, fixed="0.0.1")])
    assert t.adv.level == "critical" and t.adv.products == adv.products
    assert dropped == {"narrowing": 1}


def test_the_widest_state_holds_across_patches(mirror):
    """Widen, then try to go back to the root's range: the widened one stays."""
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot"))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[dict(CC, affected="<99.1.0", fixed="99.1.0")]),
                 created_at=T0 + 150)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[CC]), created_at=T0 + 160)
    t, dropped = read(mirror)
    assert t.adv.products == [Product("Claude Code", "claude-code", "<99.1.0", "99.1.0")]
    assert dropped == {"narrowing": 1}


# ------------------------------------------------------ the curator's word

def test_a_curator_patch_still_narrows(mirror):
    t, dropped = bot_thread(mirror, patch_sec=mirror.cur_sec, products=[dict(CC, affected="<2.0.0", fixed="2.0.0")],
                            actions=[], sources=[{"url": "https://example.invalid/other", "published_at": None}])
    assert t.adv.products == [Product("Claude Code", "claude-code", "<2.0.0", "2.0.0")]
    assert t.adv.actions == [] and [s.url for s in t.adv.sources] == ["https://example.invalid/other"]
    assert member_sees(t) is None and not dropped


def test_a_bot_narrowing_on_a_curator_thread_is_discussion(mirror):
    root = mirror.root_post(mirror.cur_sec)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(actions=[]))
    t, dropped = read(mirror)
    assert t.adv == advisory() and not dropped  # never read as a patch at all


# ---------------------------------------------------------- versions.covers

ANY = ("*", None)


@pytest.mark.parametrize("inner,outer,want", [
    (("<2.0", "2.0"), ("<2.0", "2.0"), True),       # 1. the same range
    (("1.0zz", None), ("1.0zz", None), True),
    (("<2.0", "2.0"), (None, None), True),          # 2. covered by a match by name
    (("1.0zz", None), (None, None), True),
    ((None, None), ANY, False),                     # 3. a match by name is covered by nothing else
    ((None, None), (None, "999"), False),
    ((None, "1.0zz"), (None, "2.0zz"), True),       # 4. unreadable: by unreadable, or by no bound
    ((None, "1.0zz"), ANY, True),
    ((None, "1.0zz"), (">=0", None), False),
    (("<2.0", None), (None, "1.0zz"), False),       # 5. an unreadable range covers nothing readable
    ((">3,<2", None), ("=7", None), True),          # 6. an empty range is covered
    (("<2.0", "1.0"), (">3,<2", None), False),      # 7. and covers nothing
    (("<2.0", "2.0"), ("<2.0", "2.1"), True),       # 8. bounds
    (("<2.0", "2.0"), (None, "2.1"), True),
    (("<2.0", "2.0"), ("<2.1", "2.1"), True),
    (("<2.0", "2.0"), ("<2.1", "1.9"), False),      # fixed lowered under a wider affected
    (("<2.0", "2.0"), ("<1.9", "2.0"), False),
    (("<2.0", None), ("<=2.0", None), True),
    (("<=2.0", None), ("<2.0", None), False),       # the inclusive bound is the wider
    (("<=2.0", None), (None, "2.0"), False),
    ((">=1.0", "2.0"), (">1.0", "2.0"), False),
    ((">1.0", "2.0"), (">=1.0", "2.0"), True),
    ((">=1.0", "2.0"), ANY, True),
    (ANY, (">=0", None), False),                    # a bound where there was none
    (ANY, (None, "999"), False),
    (("=1.5", None), (">=1.0,<2.0", None), True),
    ((">=1.0,<2.0", None), ("=1.5", None), False),
    (("<2.0", "2.0"), ("<2.0", "2.0rc1"), False),   # a pre-release sorts below its release
    (("<2.0", "2.0"), ("<2.0p1", "2.0p1"), True),
    (("<1,<2,<3,<4,<5", None), ANY, True),          # five comparators: unreadable to check
    (ANY, ("<1,<2,<3,<4,<5", None), False),
])
def test_covers(inner, outer, want):
    assert versions.covers(*inner, *outer) is want


def test_covers_agrees_with_check_match():
    """Over a grid of ranges and installations (readable, unreadable and
    missing versions): whenever covers says yes, check.match gives the outer
    range every match the inner has, with its actions."""
    bounds = ["1.0", "1.5", "2.0", "2.0rc1", "2.0p1"]
    ranges = [(a, f) for a in [None, "*"] + [op + v for op in ("<", "<=", ">", ">=", "=") for v in bounds]
              + [">=1.0,<2.0", ">1.5,<=2.0", ">3,<2", "<1.0zz"]
              for f in [None, "1.5", "2.0", "1.0zz"]]
    installed = ["0.9", "1.0", "1.2", "1.5", "1.7", "2.0rc1", "2.0", "2.0p1", "2.1", "junk", None]

    def seen(rng, v):  # 0 no match, 1 matched without actions, 2 matched with them
        adv = advisory(products=[Product("Claude Code", "claude-code", *rng)])
        found = check.match([adv], Inventory(products={"claude-code": [Installed("Claude Code", v, "claude")]}))
        return 0 if not found else 2 if found[0].actions_allowed == [UPGRADE] else 1

    assert [seen((None, None), "junk"), seen(ANY, "junk"), seen(ANY, "1.0")] == [2, 1, 2]  # why case 3 is a no
    assert not versions.covers(None, None, *ANY)
    said_yes = 0
    for inner in ranges:
        for outer in ranges:
            if versions.covers(*inner, *outer):
                said_yes += 1
                for v in installed:
                    assert seen(outer, v) >= seen(inner, v), (inner, outer, v)
    assert said_yes > len(ranges)  # more than each range covering itself
