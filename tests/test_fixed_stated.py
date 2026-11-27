"""Whether a source states the fixed version an entry shows (ai-tools-alerts#53fy):
``verify.fixed_stated``, and what a contradicted ``fixed`` does to a plan and a notification."""

from dataclasses import replace

import pytest

from aitools_alerts import check, notify, verify
from aitools_alerts.inventory import Installed
from aitools_alerts.schema import Action, Product
from mirror_helpers import advisory
from test_verify import CVE, G1, G2, KEV_CC, NOW, Net, adv, ghsa, go, gurl, net, osv, ourl
from test_verify_narrowing import vuln


def thread(fixed="9.9.9", affected="<9.9.9", **kw):
    """A relay-bot thread whose one entry states ``fixed``; test_verify.ghsa states 9.9.9."""
    a = adv(**kw)
    return replace(a, products=[replace(p, affected=affected, fixed=fixed) for p in a.products])


def stated(tmp_path, a, fetch=None, product=None):
    cache = go(tmp_path, [a], fetch or net((gurl(G1), ghsa())))
    return verify.fixed_stated(a, product or a.products[0], cache)


# ---------------------------------------------------------------- the question

def test_a_fixed_the_advisory_states_is_stated(tmp_path):
    assert stated(tmp_path, thread()) is True


def test_a_fixed_no_range_states_is_not(tmp_path):
    assert stated(tmp_path, thread("50.0.0", "<50.0.0")) is False
    assert stated(tmp_path, thread("9.9.8")) is False


def test_an_advisory_with_no_first_patched_version_states_none(tmp_path):
    body = ghsa(vulnerabilities=[vuln("< 9.9.9", None)])
    assert stated(tmp_path, thread(), net((gurl(G1), body))) is False


def test_any_range_of_the_product_may_state_it(tmp_path):
    body = ghsa(vulnerabilities=[vuln("< 9.9.9", "9.9.9"), vuln(">= 10.0.0, < 10.2.0", "10.2.0")])
    assert stated(tmp_path, thread("10.2.0", "<10.2.0"), net((gurl(G1), body))) is True
    assert stated(tmp_path, thread("10.1.0", "<10.2.0"), net((gurl(G1), body))) is False


def test_a_withdrawn_advisory_contradicts_no_fixed(tmp_path):
    """It still lists its ranges, and supports the product at no level: what it no longer
    supports is ai-tools-alerts#0z4e's question."""
    body = ghsa(withdrawn_at="2026-11-01T00:00:00Z")
    assert stated(tmp_path, thread("50.0.0", "<50.0.0"), net((gurl(G1), body))) is None


def test_a_range_of_another_package_states_nothing_for_this_product(tmp_path):
    body = ghsa(vulnerabilities=[vuln("< 9.9.9", "9.9.9"), vuln("< 50.0.0", "50.0.0", ("npm", "left-pad"))])
    assert stated(tmp_path, thread("50.0.0", "<50.0.0"), net((gurl(G1), body))) is False


def test_nothing_is_known_without_a_cache_a_fixed_or_a_relay_bot(tmp_path):
    a = thread("50.0.0", "<50.0.0")
    cache = go(tmp_path, [a], net((gurl(G1), ghsa())))
    assert verify.fixed_stated(a, a.products[0], None) is None  # verify = "off"
    assert verify.fixed_stated(a, replace(a.products[0], fixed=None), cache) is None
    mine = replace(a, posted_by="curator")
    assert verify.fixed_stated(mine, mine.products[0], cache) is None


def test_nothing_is_known_for_a_state_with_no_result(tmp_path):
    """A reply that changes ``fixed`` is a new state: what was read for the old one says nothing."""
    cache = go(tmp_path, [thread()], net((gurl(G1), ghsa())))
    raised = thread("50.0.0", "<50.0.0")
    assert verify.fixed_stated(raised, raised.products[0], cache) is None


def test_nothing_is_known_for_a_product_that_is_no_scope_product(tmp_path):
    a = thread("50.0.0", "<50.0.0")
    other = Product("invented-thing", "claude-code", "<50.0.0", "50.0.0")
    a = replace(a, products=[*a.products, other])
    assert stated(tmp_path, a, product=other) is None


@pytest.mark.parametrize("answer", [404, 429, OSError("ZZ-SENTINEL")])
def test_a_failed_read_says_nothing(tmp_path, answer):
    assert stated(tmp_path, thread("50.0.0", "<50.0.0"), net((gurl(G1), answer))) is None


def test_a_failed_read_after_a_whole_one_says_nothing(tmp_path):
    a = thread("50.0.0", "<50.0.0")
    assert stated(tmp_path, a) is False
    # the CLI reads a relay-bot match again daily (``recheck``); that read fails
    cache = go(tmp_path, [a], net((gurl(G1), 404)), now=NOW + verify.RETRY_S + 1, recheck=[a])
    assert verify.fixed_stated(a, a.products[0], cache) is None


def test_a_read_that_was_not_whole_never_says_no(tmp_path):
    """The advisory names another id that is not read: that one may state the version."""
    a = thread("50.0.0", "<50.0.0")
    body = ghsa(identifiers=[{"type": "GHSA", "value": G1}, {"type": "GHSA", "value": G2}])
    cache = go(tmp_path, [a], Net().set(gurl(G1), body).set(gurl(G2), 404))
    (result,) = cache["results"].values()
    assert result["whole"] is False and result["ranges"] == {"Claude Code": [["<9.9.9", "9.9.9"]]}
    assert verify.fixed_stated(a, a.products[0], cache) is None
    right = thread()
    cache = go(tmp_path, [right], Net().set(gurl(G1), body).set(gurl(G2), 404))
    assert verify.fixed_stated(right, right.products[0], cache) is True  # what was read states it


def test_a_range_this_reader_cannot_compare_never_says_no(tmp_path):
    body = ghsa(vulnerabilities=[vuln("< 9.9.9", "9.9.9"), vuln("< 1.0.0-beta.1", None)])
    assert stated(tmp_path, thread("50.0.0", "<50.0.0"), net((gurl(G1), body))) is None
    assert stated(tmp_path, thread(), net((gurl(G1), body))) is True  # what it could read states it


def test_the_catalog_states_no_version_and_an_osv_entry_s_are_not_read(tmp_path):
    a = thread("50.0.0", "<50.0.0", id=CVE, level="critical")
    assert stated(tmp_path, a, net((verify.KEV_URL, KEV_CC))) is None
    b = thread("50.0.0", "<50.0.0", id=CVE, aliases=["MAL-2026-1"], level="critical")
    fetch = net((verify.KEV_URL, KEV_CC), (ourl("MAL-2026-1"), osv("MAL-2026-1", aliases=[CVE])))
    assert stated(tmp_path, b, fetch) is None


# ---------------------------------------------------------------- the plan and the notification

def match(posted_by="relay-bot", flagged=True, **kw):
    a = advisory(posted_by=posted_by, **kw)
    inst = Installed("Claude Code", "2.0.0", "/invented")
    return check.Match(adv=a, installed=inst, actions_allowed=list(a.actions), reason="affected",
                       product=a.products[0], fixed_contradicted=flagged)


def test_a_contradicted_fixed_plans_the_upgrade_with_no_version():
    m = match()
    (up,) = check.plan(m, check.Config()).prepare
    assert (up.verb, up.value) == ("upgrade", None)
    assert check.describe(up, True) == "upgrade Claude Code (the fixed version given is not the advisory's)"
    (was,) = check.plan(replace(m, fixed_contradicted=False), check.Config()).prepare
    assert was.value == "99.0.0" and check.describe(was, True) == check.describe(was) == "upgrade Claude Code to 99.0.0 or later"


def test_the_flag_alone_keeps_an_upgrade_out_of_auto_apply():
    cfg = check.Config(auto_apply=frozenset({"upgrade"}))
    m = match(posted_by="curator", flagged=False)
    assert [a.verb for a in check.plan(m, cfg).auto_apply] == ["upgrade"]
    p = check.plan(replace(m, fixed_contradicted=True), cfg)
    assert p.auto_apply == [] and [(a.verb, a.value) for a in p.prepare] == [("upgrade", None)]


def test_describe_of_other_actions_does_not_change():
    for a in (Action("disable_skill", "invented", None), Action("upgrade", "Claude Code", None), Action("invented", "x", "y")):
        assert check.describe(a) == check.describe(a, False)
    assert check.describe(Action("disable_skill", "invented", None), True) == check.describe(Action("disable_skill", "invented", None))
    assert check.describe(Action("upgrade", "Claude Code", None)) == "upgrade Claude Code (no fixed version given)"


def test_the_notification_of_a_contradicted_fixed_names_no_version_and_uses_no_translation():
    m = match()
    text = notify.format_text(m.adv, m, "題\n99.0.0 以降に更新してください。")
    assert "99.0.0" not in text and "更新" not in text and "題" not in text
    lines = text.splitlines()
    assert "Affected: Claude Code 2.0.0" in lines
    assert "Action: upgrade Claude Code (the fixed version given is not the advisory's)" in lines
    plain = replace(m, fixed_contradicted=False)
    assert "(fixed in 99.0.0)" in notify.format_text(m.adv, plain) and "更新" in notify.format_text(m.adv, plain, "題\n更新")
