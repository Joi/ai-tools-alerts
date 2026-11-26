"""The member's check of a published narrowing against the versions its source states
(ai-tools-alerts#swfe): what is kept of a read, and ``verify.narrowing``."""

import json

import pytest

from aitools_alerts import verify
from aitools_alerts.schema import Product
from test_verify import CC, CVE, G1, G2, KEV_CC, NOW, Net, adv, ghsa, go, gurl, net, osv, ourl

WIDE = Product("Claude Code", "claude-code", "<99.0.0", "99.0.0")  # what test_verify.adv carries
SOURCE = ["<9.9.9", "9.9.9"]  # what test_verify.ghsa states


def entry(affected="<9.9.9", fixed="9.9.9", name="Claude Code", ecosystem="claude-code"):
    return Product(name, ecosystem, affected, fixed)


def vuln(rng, patched, pkg=CC):
    return {"package": {"ecosystem": pkg[0], "name": pkg[1]}, "vulnerable_version_range": rng,
            "first_patched_version": patched, "vulnerable_functions": []}


def asked(tmp_path, products, a=None, fetch=None, at=NOW, **kw):
    """``verify.narrowing`` of ``products`` for thread ``a`` after one run against ``fetch``."""
    a = a or adv()
    go(tmp_path, [a], fetch or net((gurl(G1), ghsa())), **kw)
    return verify.narrowing(a, products, verify.load(tmp_path), at)


# ---------------------------------------------------------------- what is kept of a read

def test_a_pair_is_kept_only_in_the_version_grammar():
    assert verify._pair("< 9.9.9", "9.9.9") == SOURCE
    assert verify._pair(">= 1.0.0, < 2.0.0", None) == [">=1.0.0,<2.0.0", None]
    assert verify._pair("= 1.2.3", "1.2.4") == ["=1.2.3", "1.2.4"]
    for rng, patched in ((None, "1.0"), ("< 1.0.0-beta.1", None), ("<1.0", "1.0.0-rc.1"), ("< 1.0 || > 2", None),
                         ("<" + "1" * 200, None), (7, None), ("<1.0", 7), ("ZZ-SENTINEL", None)):
        assert verify._pair(rng, patched) is None


def test_a_record_keeps_each_range_of_a_product_and_null_for_one_it_cannot_read(tmp_path):
    body = ghsa(vulnerabilities=[vuln("< 9.9.9", "9.9.9"), vuln(">= 10.0.0, < 10.2.0", "10.2.0"),
                                 vuln("< 1.0.0-beta.1", None), vuln("< 9.9.9", "9.9.9", ("npm", "left-pad"))])
    cache = go(tmp_path, [adv()], net((gurl(G1), body)))
    assert cache["sources"][G1]["ranges"] == {"Claude Code": [None, SOURCE, [">=10.0.0,<10.2.0", "10.2.0"]]}
    (result,) = cache["results"].values()
    assert result["whole"] is True and result["ranges"] == cache["sources"][G1]["ranges"]


def test_the_catalog_states_no_version_and_an_osv_entry_s_are_not_read(tmp_path):
    a = adv(id=CVE, aliases=["MAL-2026-1"], level="critical")
    cache = go(tmp_path, [a], net((verify.KEV_URL, KEV_CC), (ourl("MAL-2026-1"), osv("MAL-2026-1", aliases=[CVE]))))
    assert cache["sources"][CVE]["ranges"] == {}
    assert cache["sources"]["MAL-2026-1"]["ranges"] == {"Claude Code": [None]}


@pytest.mark.parametrize("damage", [
    lambda c: c.update(version=3),
    lambda c: c["sources"][G1].pop("ranges"),
    lambda c: c["sources"][G1]["ranges"].update({"Claude Code": [["< 9.9.9", "9.9.9"]]}),  # not as _pair writes it
    lambda c: c["sources"][G1]["ranges"].update({"Claude Code": [["ZZ-SENTINEL", None]]}),
    lambda c: c["sources"][G1]["ranges"].update({"Claude Code": None}),
    lambda c: next(iter(c["results"].values())).pop("whole"),
    lambda c: next(iter(c["results"].values())).update(whole="yes"),
    lambda c: next(iter(c["results"].values())).update(ranges={"Claude Code": [["<1", "1", "x"]]}),
])
def test_a_cache_of_another_shape_is_dropped_whole(tmp_path, damage):
    cache = go(tmp_path, [adv()], net((gurl(G1), ghsa())))
    damage(cache)
    (tmp_path / verify.FILE).write_text(json.dumps(cache))
    assert verify.load(tmp_path)["results"] == {}


def test_a_result_written_without_ranges_still_loads(tmp_path):
    cache = go(tmp_path, [adv()], net((gurl(G1), ghsa())))
    (r,) = cache["results"].values()
    del r["ranges"], r["whole"]  # as a run that ran out of requests writes it
    (tmp_path / verify.FILE).write_text(json.dumps(cache))
    assert verify.load(tmp_path)["results"] and verify.narrowing(adv(), [entry()], verify.load(tmp_path), NOW) is None


# ---------------------------------------------------------------- the comparison

@pytest.mark.parametrize("products, want", [
    ([entry()], True),                                         # what the advisory states
    ([entry(affected="<50.0.0", fixed="50.0.0")], False),      # fixed past the advisory's
    ([entry(affected="<9.9.9", fixed="50.0.0")], False),
    ([entry(affected="<9.0.0", fixed="9.0.0")], False),        # fixed below it
    ([entry(affected="<9.0.0", fixed="9.9.9")], False),        # a shorter range
    ([entry(affected=">=2.0.0,<9.9.9")], False),               # a lower bound the source does not state
    ([entry(affected="<=9.9.9", fixed=None)], True),           # wider, and no fix named: nothing lost, nothing misdirected
    ([entry(affected="<9.9.9", fixed=None)], True),
    ([entry(affected="*", fixed="9.9.9")], True),
    ([entry(affected=None, fixed=None)], False),               # "may apply" interrupts nobody
    ([], False),                                               # the product dropped
    ([entry(name="Codex CLI", ecosystem="codex")], False),
    ([entry(), entry(affected="<50.0.0", fixed="50.0.0")], False),   # a correct entry carries no wrong one through
    ([entry(), entry(affected="<9.0.0", fixed="9.0.0")], False),
    ([entry(ecosystem="codex")], False),                       # moved to another ecosystem: it matches nobody it matched
    ([entry(), entry(ecosystem="codex")], None),               # beside the right entry, a product no source states: not settled
    ([entry(), entry(name="claude code")], True),              # the advisory's entry under another spelling: it states the range
    ([entry(), entry(name="claude code", fixed="50.0.0")], False),   # and a wrong one under another spelling
    ([entry(), entry(name="Left Pad")], None),                 # a name the thread does not carry and no authority states
    ([entry(), WIDE], True),                                   # the thread's own entry beside the advisory's
    ([WIDE], True),                                            # nothing changed (the reader never offers such a list)
])
def test_the_list_is_compared_with_what_the_advisory_states(tmp_path, products, want):
    assert asked(tmp_path, products) is want


def test_an_unchanged_product_needs_no_source_and_a_changed_one_without_ranges_is_not_settled(tmp_path):
    a = adv(products=("Claude Code", "git"))
    git = Product("git", "git", "<99.0.0", "99.0.0")  # as test_verify.adv posts it
    assert asked(tmp_path, [entry(), git], a) is True  # the advisory names no git package: git is as it was
    assert asked(tmp_path, [entry()], a) is None  # git dropped, and no authority states versions for it
    assert asked(tmp_path, [entry(fixed="50.0.0")], a) is False  # a contradiction counts whatever else is unsettled


def test_a_thread_holding_two_ecosystems_keeps_both(tmp_path):
    a = adv()
    a = verify.at_level(a, a.level)  # an Advisory copy to extend
    a = type(a)(**{**{f: getattr(a, f) for f in a.__dataclass_fields__},
                   "products": [WIDE, Product("Claude Code", "npm", "<99.0.0", "99.0.0")]})
    # "Claude Code" under npm is no scope product (2mgd): a product of its own, which no source states
    assert asked(tmp_path, [entry()], a) is None
    assert asked(tmp_path, [entry(affected="<1.0.0", fixed="1.0.0")], a) is False
    assert asked(tmp_path, [entry(), Product("Claude Code", "npm", "<99.0.0", "99.0.0")], a) is True


def test_a_readable_range_still_contradicts_beside_one_this_reader_cannot_read(tmp_path):
    fetch = net((gurl(G1), ghsa(vulnerabilities=[vuln("< 9.9.9", "9.9.9"), vuln("< 12.0.0-beta.1", None)])))
    assert asked(tmp_path, [entry(affected="<1.0.0", fixed="1.0.0")], fetch=fetch) is False
    assert asked(tmp_path, [entry()], fetch=fetch) is None  # and nothing is confirmed over it
    assert asked(tmp_path, [entry(), entry(affected="<50.0.0", fixed="50.0.0")], fetch=fetch) is None  # rule 2 needs every range


def test_whole_asks_only_whether_fresh_whole_reads_contradict(tmp_path):
    a = adv(products=("Claude Code", "git"))
    drop_git = [entry(affected="<99.0.0", fixed="99.0.0")]  # git left out; no authority states versions for it
    go(tmp_path, [a], net((gurl(G1), ghsa())))
    cache = verify.load(tmp_path)
    assert verify.narrowing(a, drop_git, cache, NOW) is None and verify.narrowing(a, drop_git, cache, NOW, whole=True) is True
    assert verify.narrowing(a, [entry(affected="<1.0.0", fixed="1.0.0")], cache, NOW, whole=True) is False
    assert verify.narrowing(a, drop_git, cache, NOW + verify.FRESH_S + 1, whole=True) is None  # not fresh
    go(tmp_path, [a], Net(), now=NOW + verify.RETRY_S)  # a failed read
    assert verify.narrowing(a, drop_git, verify.load(tmp_path), NOW + verify.RETRY_S, whole=True) is None
    assert verify.narrowing(a, drop_git, None, NOW, whole=True) is None  # verify = "off"


def test_a_fixed_version_the_thread_s_signer_planted_is_not_what_the_thread_shows(tmp_path):
    """``pull.widest`` fills an entry with no fixed version with the first one the thread
    stated: the state the sources are asked about. A list equal to that filled state is a
    change of what the thread shows, and the advisory contradicts it."""
    bare = entry(affected=">=2.0.0,<99.0.0", fixed=None)
    planted = entry(affected="<1.0.0", fixed="1.0.0")
    filled = entry(affected=">=2.0.0,<99.0.0", fixed="1.0.0")
    a = adv()
    widest = type(a)(**{**{f: getattr(a, f) for f in a.__dataclass_fields__}, "products": [filled, planted]})
    go(tmp_path, [widest], net((gurl(G1), ghsa())))
    cache = verify.load(tmp_path)
    assert verify.narrowing(widest, [filled, planted], cache, NOW, [bare, planted]) is False
    assert verify.narrowing(widest, [filled, planted], cache, NOW, [bare, planted], whole=True) is False
    other = Product("Claude Code", "npm", "<1.0.0", "1.0.0")  # the same, planted in another ecosystem
    assert verify.narrowing(widest, [filled, other], cache, NOW, [bare, other]) is False


def test_a_respelled_entry_is_still_held_to_the_advisory(tmp_path):
    """A reply can put a wider entry under another spelling in the original's place. It is
    the same scope product by the matcher's rule (``verify.scope_of``): narrowing that
    entry is narrowing the product, under any name of the tool."""
    a = adv()
    respelled = Product("claude code", "claude-code", "*", None)
    widest = type(a)(**{**{f: getattr(a, f) for f in a.__dataclass_fields__}, "products": [respelled, WIDE]})
    go(tmp_path, [widest], net((gurl(G1), ghsa())))
    cache = verify.load(tmp_path)
    short = Product("claude code", "claude-code", "<1.0.0", "1.0.0")
    assert verify.narrowing(widest, [short], cache, NOW, [respelled]) is False
    assert verify.narrowing(widest, [Product("claude code", "claude-code", "<9.9.9", "9.9.9")], cache, NOW, [respelled]) is True
    package = Product("@anthropic-ai/claude-code", "claude-code", "*", None)  # the tool by its package name
    assert verify.narrowing(widest, [short], cache, NOW, [package]) is False
    assert verify.narrowing(widest, [Product("Claude Code", "claude-code", "<9.9.9", "9.9.9")], cache, NOW, [package]) is True


def test_names_are_one_product_only_when_the_matcher_reads_them_as_one(tmp_path):
    """``str.casefold`` makes U+017F an s; ``str.lower``, which check.match compares names
    by, does not. A list that puts such a spelling in the product's place states the
    advisory's range under a name no installation matches: never confirmed. Found by the
    delta review of this change."""
    long_s = "Herme\u017f"
    assert long_s.casefold() == "hermes" != long_s.lower()
    a = adv()
    hermes = Product("Hermes", "hermes", "<99.0.0", "99.0.0")
    wide = type(a)(**{**{f: getattr(a, f) for f in a.__dataclass_fields__}, "products": [hermes]})
    cache = go(tmp_path, [wide], net((gurl(G1), ghsa())))
    key = verify.state_key(wide)
    cache["results"][key] = {**cache["results"][key], "ranges": {"Hermes": [SOURCE]}, "whole": True}
    assert verify.narrowing(wide, [Product(long_s, "hermes", "<9.9.9", "9.9.9")], cache, NOW) is False
    assert verify.narrowing(wide, [Product("HERMES", "hermes", "<9.9.9", "9.9.9")], cache, NOW) is True  # the matcher's same name


def test_two_ranges_need_an_entry_each(tmp_path):
    fetch = net((gurl(G1), ghsa(vulnerabilities=[vuln("< 9.9.9", "9.9.9"), vuln(">= 10.0.0, < 10.2.0", "10.2.0")])))
    assert asked(tmp_path, [entry()], fetch=fetch) is False
    assert asked(tmp_path, [entry(), entry(affected=">=10.0.0,<10.2.0", fixed="10.2.0")], fetch=fetch) is True


def test_a_source_its_subject_s_attacker_can_write_settles_nothing(tmp_path):
    fetch = net((gurl(G1), ghsa(type="unreviewed")))
    assert asked(tmp_path, [entry()], fetch=fetch) is None
    assert asked(tmp_path, [entry(affected="<1.0.0", fixed="1.0.0")], fetch=fetch) is None


def test_the_catalog_alone_settles_no_narrowing(tmp_path):
    a = adv(id=CVE, level="critical")
    assert asked(tmp_path, [entry()], a, net((verify.KEV_URL, KEV_CC))) is None


def test_true_needs_a_fresh_whole_read_and_false_does_not(tmp_path):
    good, bad = [entry()], [entry(affected="<1.0.0", fixed="1.0.0")]
    assert asked(tmp_path, good, at=NOW + verify.FRESH_S) is True
    assert asked(tmp_path, good, at=NOW + verify.FRESH_S + 1) is None
    assert asked(tmp_path, bad, at=NOW + 900 * 86400) is False
    assert asked(tmp_path, good, at=NOW - 1) is None  # a clock set back


def test_a_partial_read_confirms_nothing_and_still_contradicts(tmp_path):
    a = adv(id=G1)
    fetch = net((gurl(G1), ghsa(cve=CVE, identifiers=[{"type": "GHSA", "value": G1}, {"type": "GHSA", "value": G2}])))
    go(tmp_path, [a], fetch)  # G2, which the advisory names, is not served: the thread is not read whole
    (r,) = verify.load(tmp_path)["results"].values()
    assert r["whole"] is False and r["ranges"] == {"Claude Code": [SOURCE]}
    assert verify.narrowing(a, [entry()], verify.load(tmp_path), NOW) is None
    assert verify.narrowing(a, [entry(affected="<1.0.0", fixed="1.0.0")], verify.load(tmp_path), NOW) is False
    # rule 2 on a partial read: the body not read could state the other entry's range
    assert verify.narrowing(a, [entry(), entry(affected="<50.0.0", fixed="50.0.0")], verify.load(tmp_path), NOW) is None


def test_a_kept_contradiction_of_the_level_does_not_keep_a_confirmation_fresh(tmp_path):
    """The thread is published at notice and the source supports high: ``below-source``, which
    ``_settled`` keeps over later failed reads, with a new time. The ranges read with it
    confirmed a narrowing; they must not go on confirming it without a read."""
    a = adv(level="notice")
    good, bad = [entry()], [entry(affected="<1.0.0", fixed="1.0.0")]
    go(tmp_path, [a], net((gurl(G1), ghsa())), recheck=[a])
    assert verify.narrowing(a, good, verify.load(tmp_path), NOW) is True
    for day in (1, 2, 3):
        at = NOW + day * verify.RETRY_S
        go(tmp_path, [a], Net(), recheck=[a], now=at)
        (r,) = verify.load(tmp_path)["results"].values()
        assert (r["at"], r["whole"], r["products"]["claude-code\nClaude Code"]["why"]) == (at, False, "below-source")
        assert verify.narrowing(a, good, verify.load(tmp_path), at) is None
        assert verify.narrowing(a, bad, verify.load(tmp_path), at) is False  # what was read still contradicts


@pytest.mark.parametrize("held_first", [False, True])
def test_a_run_cut_short_keeps_what_it_read_to_refuse_and_confirms_nothing(tmp_path, monkeypatch, held_first):
    a = adv()
    body = ghsa(identifiers=[{"type": "GHSA", "value": G1}, {"type": "GHSA", "value": G2}])
    fetch = net((gurl(G1), body), (gurl(G2), ghsa(G2)))
    if held_first:
        go(tmp_path, [a], fetch, recheck=[a])
        assert verify.narrowing(a, [entry()], verify.load(tmp_path), NOW) is True
    monkeypatch.setattr(verify, "MAX_FETCHES", 1)  # the advisory arrives; the id it names is not asked for
    at = NOW + verify.RETRY_S
    go(tmp_path, [a], fetch, recheck=[a], now=at)
    (r,) = verify.load(tmp_path)["results"].values()
    assert (r["at"], r["whole"], r["ranges"]) == (at, False, {"Claude Code": [SOURCE]})
    assert verify.narrowing(a, [entry(affected="<1.0.0", fixed="1.0.0")], verify.load(tmp_path), at) is False
    assert verify.narrowing(a, [entry()], verify.load(tmp_path), at) is None


def test_max_pairs_is_the_product_of_the_two_limits():
    from aitools_alerts import ruleset
    assert verify.MAX_PAIRS == (verify.MAX_ALIASES + 1) * ruleset.MAX_PACKAGES


def test_off_a_failed_read_and_a_curator_s_thread_give_none(tmp_path):
    assert verify.narrowing(adv(), [entry()], None, NOW) is None
    assert asked(tmp_path, [entry()], fetch=Net()) is None
    assert asked(tmp_path, [entry(affected="<1.0.0", fixed="1.0.0")], fetch=Net()) is None
    from dataclasses import replace
    assert verify.narrowing(replace(adv(), posted_by="curator"), [entry()], verify.load(tmp_path), NOW) is None


def test_a_list_of_five_thousand_products_is_answered(tmp_path):
    a = adv()
    many = [Product(f"Product {i}", "claude-code", "<1.0.0", "1.0.0") for i in range(5000)]
    a = type(a)(**{**{f: getattr(a, f) for f in a.__dataclass_fields__}, "products": [WIDE, *many]})
    cache = go(tmp_path, [adv()], net((gurl(G1), ghsa())))
    cache["results"][verify.state_key(a)] = next(iter(cache["results"].values()))
    assert verify.narrowing(a, [entry()], cache, NOW) is None  # the 5000 dropped names have no ranges
    assert verify.narrowing(a, [entry(fixed="50.0.0")], cache, NOW) is False
