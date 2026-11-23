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

JUNK = {"name": "Nobody Runs This", "ecosystem": "git", "affected": "<0.1", "fixed": "0.1"}
OTHER = {"url": "https://example.invalid/unrelated", "published_at": None}
SILENCERS = {
    "fixed lowered": ({"products": [dict(CC, fixed="0.0.1")]}, {}),
    "products replaced": ({"products": [JUNK]}, {"products": [Product(**CC), Product(**JUNK)]}),
    "actions emptied": ({"actions": []}, {}),
    "sources replaced": ({"sources": [OTHER]}, {"sources": [Source(SOURCE, None), Source(**OTHER)]}),
}


@pytest.mark.parametrize("name", sorted(SILENCERS))
def test_a_relay_bot_patch_cannot_silence_its_alert(mirror, name):
    """Nothing is taken away; what the patch adds is added."""
    patch, added = SILENCERS[name]
    t, dropped = bot_thread(mirror, **patch)
    assert t.adv == advisory(posted_by="relay-bot", **added)
    assert member_sees(t) == [UPGRADE]
    assert SOURCE in [s.url for s in t.adv.sources]
    assert dropped == {"narrowing": 1}


def test_all_four_in_one_patch_count_once_and_the_rest_applies(mirror):
    patch = {k: v for p, _ in SILENCERS.values() for k, v in p.items()}
    t, dropped = bot_thread(mirror, title="Resolved", **patch)
    assert t.adv == advisory(posted_by="relay-bot", title="Resolved", products=[Product(**CC), Product(**JUNK)],
                             sources=[Source(SOURCE, None), Source(**OTHER)])
    assert member_sees(t) == [UPGRADE] and dropped == {"narrowing": 1}


@pytest.mark.parametrize("entry,joins", [
    (dict(CC, affected="<2.0.0"), False),                    # a narrower range: the thread's stands for it
    (dict(CC, affected=">=2.1.4,<99.0.0"), False),           # a lower bound where there was none
    (dict(CC, affected="=2.1.3", fixed=None), True),         # no upper bound from fixed: neither stands for the other
    (dict(CC, name="claude-code"), True),                    # another spelling is another name
    (dict(CC, ecosystem="codex"), True),
    (dict(CC, fixed="1.0zz"), True),                         # unreadable: it would match with no actions
])
def test_a_narrower_entry_never_replaces_the_thread_s(mirror, entry, joins):
    t, dropped = bot_thread(mirror, products=[entry])
    assert t.adv.products == [Product(**CC)] + ([Product(**entry)] if joins else [])
    assert dropped == {"narrowing": 1}
    assert UPGRADE in member_sees(t)


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


def test_a_curator_amendment_does_not_adopt_a_refused_narrowing(mirror):
    """A curator's patch replaces the fields it names. A field it omits was
    never the curator's word: it stays as the reader holds it, not as the
    bot's patch would have left it."""
    codex = {"name": "Codex", "ecosystem": "codex", "affected": "<9.0", "fixed": "9.0"}
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot"))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[codex]), created_at=T0 + 150)
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(title="Retitled by a person"), created_at=T0 + 160)
    t, dropped = read(mirror)
    assert t.adv == advisory(posted_by="relay-bot", title="Retitled by a person",
                             products=[Product(**CC), Product(**codex)])
    assert member_sees(t) == [UPGRADE] and dropped == {"narrowing": 1}


@pytest.mark.parametrize("action,joins", [
    ({"verb": "upgrade", "target": "Claude Code", "value": "0.0.1"}, False),  # the version lowered
    ({"verb": "upgrade", "target": "Other", "value": "99.0.0"}, True),
    ({"verb": "review_setting", "target": "Claude Code", "value": "99.0.0"}, True),
])
def test_an_action_is_never_replaced_by_less(mirror, action, joins):
    t, dropped = bot_thread(mirror, actions=[action])
    assert t.adv.actions == [UPGRADE] + ([Action(**action)] if joins else [])
    assert dropped == {"narrowing": 1}


def test_a_changed_value_of_another_verb_joins_the_first(mirror):
    adv = advisory(posted_by="relay-bot", actions=[UPGRADE, Action("rotate_credential", "api key", "now")])
    t, dropped = bot_thread(mirror, adv=adv, actions=[
        {"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"},
        {"verb": "rotate_credential", "target": "api key", "value": "later"}])
    assert t.adv.actions == adv.actions + [Action("rotate_credential", "api key", "later")]
    assert dropped == {"narrowing": 1}


def test_an_upgrade_with_no_version_cannot_gain_one(mirror):
    """Asserted on the stored action: check.plan would hide it, since it
    takes the version from ``fixed``. No version is the highest, as for
    ``fixed``."""
    adv = advisory(posted_by="relay-bot", products=[Product("Claude Code", "claude-code", "<50.0.0", None)],
                   actions=[Action("upgrade", "Claude Code", None)])
    t, dropped = bot_thread(mirror, adv=adv, actions=[{"verb": "upgrade", "target": "Claude Code", "value": "0.0.1"}])
    assert t.adv.actions == [Action("upgrade", "Claude Code", None)] and dropped == {"narrowing": 1}


CODEX = {"name": "Codex", "ecosystem": "codex", "affected": "<9.0", "fixed": "9.0"}
GIT = {"name": "git", "ecosystem": "git", "affected": "<3.0", "fixed": "3.0"}
STOP = {"verb": "stop_using", "target": "Claude Code", "value": None}
UP = {"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"}
REVIEW = {"verb": "review_setting", "target": "x", "value": None}
SRC = [{"url": SOURCE, "published_at": None}, {"url": "https://example.invalid/second", "published_at": None}]
NEW_SRC = {"url": "https://example.invalid/third", "published_at": None}


@pytest.mark.parametrize("field,start,patched,added", [
    ("products", [CC, CODEX], [CC], []),                    # one of two entries removed
    ("products", [CC, CODEX], [CODEX], []),
    ("products", [CC, CODEX], [CC, GIT], [GIT]),            # one removed, one added
    ("products", [CC, CODEX], [dict(CC, fixed="0.0.1"), CODEX, GIT], [GIT]),  # one narrowed, one added
    ("actions", [UP, STOP], [UP], []),
    ("actions", [UP, STOP], [STOP], []),
    ("actions", [UP, STOP], [UP, REVIEW], [REVIEW]),
    ("sources", SRC, SRC[:1], []),
    ("sources", SRC, SRC[1:], []),
    ("sources", SRC, [SRC[0], NEW_SRC], [NEW_SRC]),
])
def test_every_entry_of_a_list_stays_whatever_the_patch_keeps(mirror, field, start, patched, added):
    """Keeping one entry does not pay for dropping another: every entry the
    thread held is still there, in its place, and additions follow."""
    cls = {"products": Product, "actions": Action, "sources": Source}[field]
    adv = advisory(posted_by="relay-bot", **{field: [cls(**e) for e in start]})
    t, dropped = bot_thread(mirror, adv=adv, title="Other fields apply", **{field: patched})
    assert t.adv == advisory(posted_by="relay-bot", title="Other fields apply",
                             **{field: [cls(**e) for e in start + added]})
    assert dropped == {"narrowing": 1}


# ------------------------------------------------- what a bot patch may do

def test_a_relay_bot_patch_raising_fixed_applies(mirror):
    """A real correction: the first fix did not fix it. The wider entry
    replaces the one it stands for."""
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
    ({"products": [dict(CC, name="CLAUDE CODE")]},  # the same entry to check.match: nothing to add
     "products", [Product(**CC)]),
    ({"actions": [{"verb": "stop_using", "target": "Claude Code", "value": None},
                  {"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"}]},
     "actions", [UPGRADE, Action("stop_using", "Claude Code", None)]),
    ({"actions": [{"verb": "upgrade", "target": "Claude Code", "value": None}]},  # no version: the highest
     "actions", [Action("upgrade", "Claude Code", None)]),
    ({"actions": [{"verb": "upgrade", "target": "Claude Code", "value": "99.1.0"}]},  # the version alone rises
     "actions", [Action("upgrade", "Claude Code", "99.1.0")]),
    ({"sources": [{"url": "https://example.invalid/vendor", "published_at": None},
                  {"url": SOURCE, "published_at": "2026-11-01"}]},
     "sources", [Source(SOURCE, None), Source("https://example.invalid/vendor", None)]),
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


# ------------------------------------------ the order patches are read in

WIDER = dict(CC, affected="<99.1.0", fixed="99.1.0")
AT_99 = Inventory(products={"claude-code": [Installed("Claude Code", "99.0.5", "claude")]})


@pytest.mark.parametrize("field,widening,backdated,survives", [
    # Code review, blocker: each read replays the thread in (created_at, id)
    # order, which the signer sets. A patch dated before an applied widening,
    # published after it, must not make the widening fail on the next read.
    ("products", [WIDER], [CC, GIT], Product(**WIDER)),
    ("actions", [UP, STOP], [UP, REVIEW], Action(**STOP)),
    ("sources", [SRC[0], SRC[1]], [SRC[0], NEW_SRC], Source(**SRC[1])),
])
def test_a_backdated_patch_cannot_undo_an_applied_widening(mirror, field, widening, backdated, survives):
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot"))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(**{field: widening}), created_at=T0 + 200)
    t, _ = read(mirror)
    assert survives in getattr(t.adv, field)
    seen_before = check.match([t.adv], AT_99)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(**{field: backdated}), created_at=T0 + 150)
    t, _ = read(mirror)
    assert survives in getattr(t.adv, field)
    assert len(check.match([t.adv], AT_99)) == len(seen_before)
    assert member_sees(t)


def test_a_backdated_level_raise_cannot_cost_a_later_patch_its_widening(mirror):
    """The later patch raised notice to high and widened the range. Once a
    patch dated before it says critical, the later one reads as a lowering
    and is refused; what it added to products still counts."""
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot", level="notice"))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="high", title="Later", products=[WIDER]),
                 created_at=T0 + 200)
    t, _ = read(mirror)
    assert t.adv.level == "high" and len(check.match([t.adv], AT_99)) == 1
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=T0 + 150)
    t, dropped = read(mirror)
    assert t.adv.level == "critical" and t.adv.title == advisory().title  # the refused patch's title is not applied
    assert t.adv.products == [Product(**WIDER)] and len(check.match([t.adv], AT_99)) == 1
    assert dropped == {"bad-patch": 1}


def test_every_order_of_the_same_patches_keeps_every_entry():
    """_apply_patch folded over every order of five product patches: each
    entry any of them signed is stood for at the end, whatever the order."""
    import itertools
    lists = [[dict(CC, fixed="0.0.1")], [WIDER], [CC, GIT], [CODEX, dict(GIT, affected="<5.0", fixed="5.0")],
             [dict(CC, affected=">=1.0,<2.0", fixed=None)]]
    start = advisory(posted_by="relay-bot")
    signed = list(start.products) + [Product(**e) for lst in lists for e in lst]
    for order in itertools.permutations(lists):
        adv = start
        for lst in order:
            adv = pull._apply_patch(adv, {"products": lst}, "relay-bot")
        assert all(pull._covered(p, adv.products) for p in signed), order
        assert len(adv.products) == 4  # WIDER, the unbounded-above entry, CODEX, the wider GIT


def test_a_joined_list_past_the_schema_limit_does_not_block_later_patches(mirror):
    """The limit of 50 is on what one event carries. A thread joined past it
    still takes a patch that omits the field, a level raise for instance."""
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot", level="high"))
    for n in range(2):
        mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[
            dict(JUNK, name=f"junk-{n}-{i}") for i in range(50)]), created_at=T0 + 150 + n)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="critical"), created_at=T0 + 160)
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(title="A person's title"), created_at=T0 + 170)
    t, dropped = read(mirror)
    assert len(t.adv.products) == 101 and t.adv.products[0] == Product(**CC)
    assert t.adv.level == "critical" and t.adv.title == "A person's title"
    assert member_sees(t) == [UPGRADE] and dropped == {"narrowing": 2}


def test_a_flooded_thread_costs_no_more_than_its_size(monkeypatch):
    """Delta review: 200 patches of 50 ranges none of which stands for
    another would cost a pairwise comparison on every read. Past
    pull._JOIN_SCAN entries the join appends without comparing."""
    calls = [0]
    real = versions.covers
    monkeypatch.setattr(versions, "covers", lambda *a: calls.__setitem__(0, calls[0] + 1) or real(*a))
    adv, dropped = advisory(posted_by="relay-bot"), Counter()
    for n in range(200):
        adv = pull._apply_patch(adv, {"products": [dict(CC, affected=f"={n}.{i}", fixed=None) for i in range(50)]},
                                "relay-bot", dropped)
    assert len(adv.products) == 10001 and adv.products[0] == Product(**CC)
    assert calls[0] < 200_000 and dropped == {"narrowing": 200}
    again = pull._apply_patch(adv, {"products": [dict(CC, affected="=0.0", fixed=None)]}, "relay-bot")
    assert len(again.products) == 10001  # an entry already there is not added twice


# ------------------------------------------------------ the curator's word

def _amend(mirror, root, **kw):
    from aitools_alerts import curator
    st = State.load()
    res = pull.fetch("https://mirror.example.invalid/alerts", st, fetch=mirror.fetch, root_pubkey=mirror.root,
                     now=T0 + 1000, checkpoint=False)
    assert res.error is None, res.error
    [(t, root_ev)] = curator.find_threads(st, mirror.root, root["id"])
    ev = curator.amend_event(mirror.cur_sec, st.manifest, mirror.root, st, t, root_ev, now=T0 + 1000, **kw)
    mirror.events["feed.json"].append(ev)
    return read(mirror)


def test_the_curator_command_amends_a_thread_joined_past_the_limit(mirror):
    """Delta review: the command validated the whole amended advisory, so 51
    products made even a title change fail."""
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot"))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[dict(JUNK, name=f"junk-{i}") for i in range(50)]))
    t, _ = _amend(mirror, root, title="A person's title", level="notice")
    assert t.adv.title == "A person's title" and t.adv.level == "notice" and len(t.adv.products) == 51
    assert member_sees(t) == [UPGRADE]


def test_the_curator_command_sets_fixed_on_a_product_listed_twice(mirror):
    """Delta review: --fixed wanted exactly one entry of the name, and a
    bot reply can now leave two."""
    root = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot"))
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(products=[dict(CC, affected="=2.1.3", fixed=None)]))
    t, _ = _amend(mirror, root, fixed="Claude Code=100.0.0")
    assert t.adv.products == [Product("Claude Code", "claude-code", "<99.0.0", "100.0.0"),
                              Product("Claude Code", "claude-code", "=2.1.3", "100.0.0")]
    assert t.adv.actions == [Action("upgrade", "Claude Code", "100.0.0")]

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


def test_covers_is_transitive():
    """_join drops an entry another stands for; that is safe only if
    standing-for chains: a covers b and b covers c give a covers c."""
    ranges = [(a, f) for a in [None, "*", "<1.5", "<=1.5", ">1.0", ">=1.0", "=1.5", ">=1.0,<2.0", ">3,<2", "<1.0zz"]
              for f in [None, "1.5", "2.0", "1.0zz"]]
    over = {r: [q for q in ranges if versions.covers(*r, *q)] for r in ranges}
    for c in ranges:
        for b in over[c]:
            for a in over[b]:
                assert versions.covers(*c, *a), (c, b, a)
