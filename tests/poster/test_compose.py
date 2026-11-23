"""Post composition (Task B3)."""

import dataclasses
import json
import re
import socket

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import compose, rules
from aitools_alerts.poster.candidates import Candidate, Source

GHSA = "https://github.com/anthropics/claude-code/security/advisories/GHSA-abcd-efgh-ijkl"
BLOG = "https://example.org/write-up"
NOW = 1_800_000_000

# Invented host names, plus the shape of a fleet name (a mac/azbd/jibot stem
# followed by more letters or digits). The real names never appear here.
DENY_NAMES = ("host-alpha", "host-bravo")
DENY_PATTERN = re.compile(r"\b(?:mac(?!os\b)[a-z0-9]{2,}|azbd[a-z0-9]*|jibot[a-z0-9]+|joim[a-z0-9]+)\b", re.I)


def cand(**kw) -> Candidate:
    base = dict(id="CVE-2026-0001", aliases=("GHSA-abcd-efgh-ijkl",),
                product_text="Anthropic Claude Code", advisory_severity=None,
                local_level_hint=None, exploited=False, trojanized=False,
                injection_exec=True, fixed="v2.1.0", affected="< 2.1.0",
                sources=(Source(BLOG, None), Source(GHSA, "2026-11-01")), observed_at=None)
    base.update(kw)
    return Candidate(**base)


def scope(c):
    return rules.scope_of(c.product_text)


def root(c, level=("critical", "injection-exec-fixed")):
    return compose.root_post(c, level, scope(c), posted_at=NOW)


def test_root_post_body_has_four_lines_and_block():
    text, adv = root(cand())
    body, rest = text.split("\n\n```aitools-alert\n", 1)
    lines = body.split("\n")
    assert len(lines) == 4
    assert lines[0] == "CRITICAL: Claude Code: injection to code execution (CVE-2026-0001)"
    assert lines[1] == "Affected: Claude Code below 2.1.0. Fixed in 2.1.0."
    assert lines[2] == "Action: upgrade Claude Code to 2.1.0 or later."
    assert lines[3] == f"Source: {GHSA}"  # the primary source, though listed second
    assert schema.parse_post(text) == adv
    assert adv.posted_by == "relay-bot" and adv.advisory_severity is None
    assert adv.products == [schema.Product("Claude Code", "claude-code", "<2.1.0", "2.1.0")]
    assert adv.actions == [schema.Action("upgrade", "Claude Code", "2.1.0")]
    assert [s.url for s in adv.sources] == [GHSA, BLOG]
    assert adv.aliases == ["GHSA-abcd-efgh-ijkl"] and adv.posted_at == NOW


def test_root_post_without_fix_and_unverified():
    c = cand(injection_exec=False, trojanized=True, fixed=None, affected=None)
    text, adv = root(c, ("high", "unverified"))
    lines = text.split("\n")
    assert lines[0].startswith("HIGH (unverified")
    assert "unverified" in lines[0]
    assert lines[1] == ("Affected: Claude Code, versions not stated. "
                        "The source does not state a fixed version; check the vendor's advisory.")
    assert lines[2] == "Action: check the vendor for an update and apply it."
    assert adv.actions == [] and "trojanized release" in adv.title
    # A bare level string is accepted.
    assert compose.root_post(c, "notice", scope(c), posted_at=NOW)[1].level == "notice"


@pytest.mark.parametrize("raw,want", [
    ("< 2.1.0", "<2.1.0"), (">=1.0, <1.4.2", ">=1.0,<1.4.2"), ("<=9.9p1", "<=9.9p1"),
    ("2.0.0", None), ("<2.0 || >3.0", None), ("!=1.0", None), ("^1.2", None), (None, None),
])
def test_affected_conversion(raw, want):
    assert compose.schema_affected(raw) == want


@pytest.mark.parametrize("raw,want", [("v2.1.0", "2.1.0"), ("9.9p1", "9.9p1"),
                                      ("2.1.0-beta+x", None), (None, None)])
def test_fixed_conversion(raw, want):
    assert compose.schema_fixed(raw) == want


def test_no_usable_source_is_refused():
    with pytest.raises(ValueError):
        root(cand(sources=(Source("http://example.org/x", None),)))


def _all_text(c):
    text, adv = root(c)
    reply = compose.reply_post(adv, c, {"level": "high"})
    return text + reply + compose.digest([adv], "2026-11-05")


def test_body_never_contains_host_names(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "host-alpha.example")
    out = _all_text(cand())
    for name in DENY_NAMES:
        assert name not in out.lower()
    assert not DENY_PATTERN.search(out)
    assert "host-alpha" not in out
    # An alias that is not a CVE or GHSA id is never published (h340), a host name included.
    text, adv = root(cand(aliases=("host-alpha", "OSV-2026-9", "CVE-2026-0001:claude-code", "CVE-2026-0044")))
    assert adv.aliases == ["CVE-2026-0044"] and "host-alpha" not in text and "OSV" not in text


def test_rule_inputs_never_reach_post_text():
    c = cand(product_text="Claude Code 2.0.77 on a laptop",
             advisory_severity="CVSS 9.8, seen at 2.0.77", observed_at="2026-11-04")
    text, adv = compose.root_post(c, "critical", rules.scope_of("claude code"), posted_at=NOW)
    out = text + compose.reply_post(adv, c, {"level": "high"}) + compose.digest([adv], "2026-11-05")
    assert "2.0.77" not in out and "CVSS" not in out and "laptop" not in out


def _block(reply):
    return json.loads(reply.split("```aitools-alert\n", 1)[1].rsplit("\n```", 1)[0])


def test_reply_only_carries_changed_fields():
    c = cand()
    _, prev = root(c)
    fixed = [{"name": "Claude Code", "ecosystem": "claude-code", "affected": "<2.1.1", "fixed": "2.1.1"}]
    reply = compose.reply_post(prev, c, {"level": "critical", "products": fixed,
                                         "expires_at": NOW + 10})
    block = _block(reply)
    assert set(block) == {"products", "actions", "expires_at"}  # level unchanged; action follows fixed
    assert block["actions"] == [{"verb": "upgrade", "target": "Claude Code", "value": "2.1.1"}]
    assert "Fixed in 2.1.1" in reply and "upgrade Claude Code to 2.1.1" in reply
    merged = compose.parse_reply(reply, prev)
    assert merged == compose.apply_patch(prev, block)
    assert merged.products[0].fixed == "2.1.1" and merged.id == prev.id and merged.level == prev.level
    assert compose.apply_patch(merged, {"expires_at": None}).expires_at is None  # null clears
    for bad in ({}, {"level": "critical"}, {"id": "X-1"}, {"posted_by": "curator"},
                {"colour": "red"}, {"title": None}, {"level": "urgent"}):
        with pytest.raises(ValueError):
            compose.reply_post(prev, c, bad)
    for bad in ({"id": "X-1"}, {"title": None}, {"colour": 1}, [], {"level": "urgent"}):
        with pytest.raises(ValueError):
            compose.apply_patch(prev, bad)
    # The wire form is decoded strictly: duplicate keys, NaN, an unfinished block.
    for text in ('```aitools-alert\n{"level": "high", "level": "notice"}\n```\n',
                 '```aitools-alert\n{"expires_at": NaN}\n```\n',
                 '```aitools-alert\n{"level": "high"}\n', "no block"):
        assert compose.parse_reply(text, prev) is None


def test_reply_is_held_to_root_publication_rules():
    c = cand()
    _, prev = root(c)
    other = [{"name": "Docker", "ecosystem": "docker", "affected": None, "fixed": None}]
    for hostile in ({"title": "Evidence: /Users/someone/report.json"},
                    {"title": "Claude Code 2.0.77 seen locally"},
                    {"advisory_severity": "seen at 2.0.77"}, {"posted_at": NOW + 1},
                    {"products": other},
                    {"actions": [{"verb": "rotate_credential", "target": "api key", "value": None}]},
                    {"aliases": ["GHSA-abcd-efgh-ijkl", "host-alpha"]},
                    {"sources": [{"url": "https://example.org/home/x/notes", "published_at": None}]}):
        with pytest.raises(ValueError):
            with pytest.MonkeyPatch.context() as m:
                m.setattr(socket, "gethostname", lambda: "host-alpha")
                compose.reply_post(prev, c, hostile)
    # Unions past the schema's caps are cut, not refused.
    many = compose.reply_post(prev, c, {"aliases": [f"CVE-2026-{1000 + i}" for i in range(60)]})
    assert len(_block(many)["aliases"]) == 50
    # A level change for an unverified critical says so.
    unv = compose.reply_post(prev, c, {"level": "high"}, reason="unverified")
    assert unv.split("\n")[0].startswith("Unverified") and "Level is now high." in unv


def test_digest_lists_every_item_once():
    _, crit = root(cand())
    _, high = root(cand(id="CVE-2026-0002", aliases=()), ("high", "fix-rce-tier1"))
    c3 = cand(id="CVE-2026-0003", aliases=(), product_text="linux kernel")
    _, note = compose.root_post(c3, ("notice", "notice"), scope(c3), posted_at=NOW)
    later = dataclasses.replace(high, posted_at=NOW + 5, level="critical")
    out = compose.digest([note, high, crit, later], "2026-11-05")
    lines = out.split("\n")
    assert lines[0] == "Daily digest for 2026-11-05: 3 advisories."
    assert out.count("CVE-2026-0001") == 1 and out.count("CVE-2026-0002") == 1
    assert out.count("CVE-2026-0003") == 1
    assert out.index("Critical") < out.index("CVE-2026-0002") < out.index("Notice")
    assert "High" not in out  # 0002's later version is critical; empty sections are omitted
    assert compose.digest([], "2026-11-05") == "Daily digest for 2026-11-05: no advisories."


def test_review_fixes_publication():
    c = cand()
    _, prev = root(c)
    for url in ("https://user:pw@example.org/a", "https://10.0.0.5/advisory",
                "https://example.org/%68ome/alice/evidence.json"):
        with pytest.raises(ValueError):  # dropped by B1's URL checks, leaving nothing changed
            compose.reply_post(prev, c, {"sources": [{"url": url, "published_at": None}]})
    tup = compose.reply_post(prev, c, {"aliases": ("CVE-2026-0009", "OSV-2026-9", "bad alias!", "x" * 128)})
    assert _block(tup)["aliases"] == ["GHSA-abcd-efgh-ijkl", "CVE-2026-0009"]  # union, CVE and GHSA ids only
    # A fix the schema cannot express is not "no fix".
    text, adv = root(cand(fixed="2.0.0-rc.1"))
    assert "A fix is listed upstream" in text and "no fix" not in text and adv.actions == []
    # Unverified survives into the title, so the digest and replies keep it.
    _, unv = root(cand(injection_exec=False, trojanized=True), ("high", "unverified"))
    assert "unverified" in compose.digest([unv], "2026-11-05")
    # One CVE under two scopes is two digest items; a guarded item is withheld, not fatal.
    c2 = cand(product_text="docker engine")
    _, dock = compose.root_post(c2, "high", scope(c2), posted_at=NOW)
    bad = dataclasses.replace(dock, id="CVE-2026-0009", title="Docker: host-alpha (CVE-2026-0009)")
    with pytest.MonkeyPatch.context() as m:
        m.setattr(socket, "gethostname", lambda: "host-alpha")
        out = compose.digest([prev, dock, bad], "2026-11-05")
    assert out.count("CVE-2026-0001") == 2 and "1 item withheld" in out and "host-alpha" not in out


@pytest.mark.parametrize("alias", ["evidence/Library/Logs/build.log", "x%2FLibrary%2FLogs%2Fy",
                                   "evidence/library/logs/build.log", "x=/volumes/Work/y"])
def test_guard_refuses_cased_macos_paths(alias):
    with pytest.raises(ValueError, match="local path"):
        compose._guard(f"HIGH: Claude Code: security advisory (CVE-2026-1)\nAlso known as: {alias}.")


def test_guard_keeps_apple_developer_library_urls():
    text = "Source: https://developer.apple.com/library/archive/releasenotes/x.html"
    assert compose._guard(text) == text


def test_synthetic_root_marks_the_block_title():
    text, adv = root(cand(id="CVE-2099-0010", aliases=()))
    head = text.split("\n")[0]
    assert head == ("CRITICAL (SYNTHETIC TEST): SYNTHETIC TEST: Claude Code: "
                    "injection to code execution (CVE-2099-0010)")
    assert adv.title.startswith("SYNTHETIC TEST: Claude Code") and adv.title.count("SYNTHETIC") == 1
    assert schema.parse_post(text).title == adv.title
    assert schema.parse_post(schema.render_post(adv, "Body.")).title == adv.title  # one mark
    real_text, real = root(cand(aliases=("CVE-2099-0011",)))  # a reserved alias never marks
    assert "SYNTHETIC" not in real_text and not real.title.startswith("SYNTHETIC")


def test_synthetic_digest_and_reply_keep_one_mark():
    c = cand(id="CVE-2099-0010", aliases=())
    _, adv = root(c)
    legacy = dataclasses.replace(adv, title="Claude Code: injection to code execution (CVE-2099-0010)")
    for a in (adv, legacy):  # a synthetic test never reaches a digest, marked or not
        assert compose.digest([a], "2026-11-05") == "Daily digest for 2026-11-05: no advisories."
    assert adv.title in compose._titles("Claude Code", adv.id)
    assert legacy.title not in compose._titles("Claude Code", adv.id)
    assert compose.reply_post(adv, c, {"level": "high"}).count("SYNTHETIC") == 0  # block: changed fields
    with pytest.raises(ValueError, match="template title"):  # the writer never sends an unmarked title
        compose.reply_post(adv, c, {"title": legacy.title})


REL = "https://support.apple.com/en-us/149521"  # primary: a digest lists only primary-sourced items
USN = "https://ubuntu.com/security/notices/USN-8928-1"
SOCIAL = "https://social.example.com/@bot/"
KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _plain(i, product, url, level="notice", fixed=None, prefix="CVE-2098-", **kw):
    lead = prefix.startswith("LEAD-")  # root_post composes no lead (h340): an advisory an older poster held
    c = cand(id=f"{'CVE-2097-' if lead else prefix}{i:04d}", aliases=(), product_text=product, injection_exec=False,
             fixed=fixed, affected=None, sources=(Source(url, None),), **kw)
    adv = compose.root_post(c, (level, level), scope(c), posted_at=NOW + i)[1]
    return dataclasses.replace(adv, id=f"{prefix}{i:04d}", title=adv.title.replace(c.id, f"{prefix}{i:04d}")) if lead else adv


def test_digest_groups_releases_and_leaves_out_leads():
    advs = [_plain(i, "macOS", REL) for i in range(1, 45)]
    advs += [_plain(100 + i, "linux kernel", USN) for i in range(9)]
    leads = [_plain(200 + i, "Chrome", f"{SOCIAL}{i}", prefix="LEAD-2099-") for i in range(12)]
    leads += [_plain(220, "Chrome", REL, prefix="LEAD-2099-")]  # a lead with a primary source too
    leads += [dataclasses.replace(_plain(221, "Chrome", REL, prefix="LEAD-2099-"), level="high")]
    crit = dataclasses.replace(_plain(300, "macOS", REL), level="critical")
    out = compose.digest(advs + leads + [crit], "2026-11-06")
    lines = out.split("\n")
    assert lines[0] == "Daily digest for 2026-11-06: 3 advisories."  # leads are not counted
    assert "Critical (1)" in lines and "Notice (2)" in lines and "High" not in out
    assert f"- macOS: release 149521, 44 CVEs; update available. {REL}" in lines
    assert f"- Linux kernel: release USN-8928-1, 9 CVEs; update available. {USN}" in lines
    assert "LEAD-" not in out and "leads" not in out and "Chrome" not in out  # 8ke5
    assert out.count("CVE-2098-0300") == 1 and "CVE-2098-0001" not in out
    same = [_plain(i, "macOS", REL, fixed="27.2") for i in range(1, 4)]
    assert "3 CVEs; fixed in 27.2." in compose.digest(same, "2026-11-06")
    # Only leads, or only items with no primary source: nothing to list, in either language.
    social = [_plain(400 + i, "macOS", f"{SOCIAL}{i}") for i in range(3)]
    for lang in ("en", "ja"):
        assert compose.digest(leads + social, "2026-11-06", lang=lang) \
            == compose.digest([], "2026-11-06", lang=lang)


def test_digest_groups_keep_marks_and_kinds_apart():
    real = [_plain(i, "macOS", REL, prefix="CVE-2026-") for i in (1, 2)]
    syn = [_plain(i, "macOS", REL, prefix="CVE-2099-") for i in (3, 4)]
    out = compose.digest(real + syn, "2026-11-06")
    assert f"- macOS: release 149521, 2 CVEs; update available. {REL}" in out.split("\n")
    assert "SYNTHETIC" not in out and "1 advisory." in out
    # A shared catalog URL is not a release, and unverified titles keep their mark.
    kev = [_plain(i, "macOS", KEV, level="high", exploited=True, prefix="CVE-2026-") for i in (5, 6)]
    c = cand(id="CVE-2026-0007", aliases=(), product_text="macOS", injection_exec=False,
             sources=(Source(REL, None),))
    unv = [compose.root_post(dataclasses.replace(c, id=f"CVE-2026-000{i}"), ("high", "unverified"),
                             scope(c), posted_at=NOW)[1] for i in (7, 8)]
    out = compose.digest(kev + unv, "2026-11-06")
    assert "4 advisories" in out and "CVEs" not in out and out.count("unverified") == 2
    # An unverified trojanized release keeps its own line and its mark, at any level.
    tc = cand(id="CVE-2026-0011", aliases=(), product_text="macOS", injection_exec=False,
              trojanized=True, fixed=None, sources=(Source(REL, None),))
    troj = [compose.root_post(dataclasses.replace(tc, id=f"CVE-2026-001{i}"), ("high", "unverified"),
                              scope(tc), posted_at=NOW)[1] for i in (1, 2)]
    out = compose.digest(troj, "2026-11-06")
    assert "2 advisories" in out and "CVEs" not in out and out.count("unverified trojanized release") == 2
    notice = [dataclasses.replace(a, level="notice") for a in troj]  # the title alone keeps them apart
    out = compose.digest(notice, "2026-11-06")
    assert "2 advisories" in out and "CVEs" not in out and out.count("unverified trojanized release") == 2
    # A group the guard refuses is one withheld item; the next group still prints.
    bad = [dataclasses.replace(a, products=[dataclasses.replace(a.products[0], name="host-alpha")],
                               title=f"host-alpha: security advisory ({a.id})") for a in real]
    with pytest.MonkeyPatch.context() as m:
        m.setattr(socket, "gethostname", lambda: "host-alpha")
        out = compose.digest(bad + [_plain(i, "linux kernel", USN) for i in (3, 4)], "2026-11-06")
    assert "1 item withheld" in out and "host-alpha" not in out and "2 CVEs" in out


# ------------------------------------------------ components (ai-tools-alerts#qme5)

def containerd_kev():
    return cand(id="CVE-2026-0901", aliases=(), product_text="containerd containerd",
                exploited=True, injection_exec=False, fixed="1.7.29", affected="< 1.7.29",
                sources=(Source(KEV, None),))


def test_containerd_kev_composes_containerd():
    c = containerd_kev()
    text, adv = root(c, ("critical", "kev"))
    assert adv.title == "containerd: known exploited vulnerability (CVE-2026-0901)"
    assert [(p.name, p.ecosystem, p.fixed) for p in adv.products] == [("containerd", "docker", "1.7.29")]
    assert [(a.verb, a.target, a.value) for a in adv.actions] == [("upgrade", "containerd", "1.7.29")]
    assert "Action: upgrade containerd to 1.7.29 or later." in text.split("\n")
    assert "Docker" not in text


def test_entry_fallback_composes_under_the_entry_name():
    _, adv = root(cand(product_text="MCP server", fixed="1.2.0"))
    assert adv.products[0].name == adv.actions[0].target == "MCP servers and clients"


def test_root_post_refuses_unresolved_entry():
    [docker] = [e for e in schema.load_scope() if e.name == "Docker"]
    with pytest.raises(ValueError):
        compose.root_post(containerd_kev(), "critical", docker, posted_at=NOW)


# ---------------------------------------------------------------- Japanese lang: ja replies (rd8t)


def test_root_post_ja_keeps_names_ids_versions_urls():
    c = cand()
    _, adv = root(c)
    lines = compose.root_post_ja(adv, None, compose.fix_unexpressed(c)).split("\n")
    assert lines == ["緊急: Claude Code: コード実行につながるインジェクション (CVE-2026-0001)",
                     "影響: Claude Code（2.1.0 未満）。 修正版: 2.1.0。",
                     "対応: Claude Code を 2.1.0 以降に更新してください。",
                     f"出典: {GHSA}"]
    c = cand(injection_exec=False, trojanized=True, fixed=None, affected=None)
    _, adv = root(c, ("high", "unverified"))
    lines = compose.root_post_ja(adv, "unverified").split("\n")
    assert lines[0] == ("重要 (unverified: no primary source confirmed it): "
                        "Claude Code: unverified 改ざんされたリリース (CVE-2026-0001)")
    assert lines[1] == ("影響: Claude Code（バージョン不明）。 "
                        "出典には修正版の記載がありません。ベンダーのアドバイザリを確認してください。")
    assert lines[2] == "対応: ベンダーの更新情報を確認し、リリースがあれば適用してください。"
    syn = cand(id="CVE-2099-0001", aliases=())
    _, adv = root(syn, ("high", "high"))
    assert compose.root_post_ja(adv).startswith(
        "重要 (SYNTHETIC TEST): SYNTHETIC TEST: Claude Code: コード実行につながるインジェクション (CVE-2099-0001)")


_NO_FIX_CLAIMS = ("no fix", "No fixed version is known", "watch this thread", "修正版はまだ", "修正はまだ")


def test_root_post_kev_without_version_never_says_no_fix():
    """A KEV entry carries no version data: the post says the source states none and
    sends the reader to the vendor, and a known-exploited one says to update now."""
    kev = cand(id="CVE-2026-1253", aliases=(), product_text="Chrome", exploited=True,
               injection_exec=False, fixed=None, affected=None, sources=(Source(BLOG, None),))
    for level, mark in ((("high", "high"), ""), (("high", "unverified"), "unverified ")):
        text, adv = compose.root_post(kev, level, scope(kev), posted_at=NOW)
        assert adv.title == f"Chrome: {mark}known exploited vulnerability (CVE-2026-1253)"
        lines = text.split("\n\n```")[0].split("\n")
        assert lines[1:3] == [
            "Affected: Chrome, versions not stated. "
            "The source does not state a fixed version; check the vendor's advisory.",
            "Action: check the vendor for an update; this is exploited in the wild, "
            "so update now if a release is out."]
        ja = compose.root_post_ja(adv, level[1], compose.fix_unexpressed(kev))
        assert ja.split("\n")[1:3] == [
            "影響: Chrome（バージョン不明）。 出典には修正版の記載がありません。ベンダーのアドバイザリを確認してください。",
            "対応: ベンダーの更新情報を確認してください。悪用が確認されているため、リリースがあれば直ちに更新してください。"]
        digests = compose.digest([adv], "2026-11-11") + compose.digest([adv], "2026-11-11", lang="ja")
        for claim in _NO_FIX_CLAIMS:
            assert claim not in text and claim not in ja and claim not in digests
    # A thread that was a trojanized release keeps that title when KEV adds it at the same
    # level (main.plan_known): the candidate's flag still makes the action urgent.
    tro = dataclasses.replace(kev, exploited=False, trojanized=True)
    _, adv = compose.root_post(tro, ("high", "high"), scope(tro), posted_at=NOW)
    assert "trojanized release" in adv.title
    assert compose.root_post_ja(adv).split("\n")[2] == "対応: ベンダーの更新情報を確認し、リリースがあれば適用してください。"
    assert "直ちに更新" in compose.root_post_ja(adv, exploited=True).split("\n")[2]
    # A synthetic KEV check keeps the exploited action.
    syn = dataclasses.replace(kev, id="CVE-2099-0001")
    text, adv = compose.root_post(syn, ("high", "high"), scope(syn), posted_at=NOW)
    assert "update now if a release is out" in text
    assert "直ちに更新" in compose.root_post_ja(adv)


def test_root_post_fixed_line_unchanged_and_unexpressed_has_no_action():
    """The fixed branch reads exactly as before 4yr1."""
    kev = cand(exploited=True, injection_exec=False)
    text, adv = root(kev)
    assert text.split("\n")[1:3] == ["Affected: Claude Code below 2.1.0. Fixed in 2.1.0.",
                                     "Action: upgrade Claude Code to 2.1.0 or later."]
    assert compose.root_post_ja(adv).split("\n")[1:3] == [
        "影響: Claude Code（2.1.0 未満）。 修正版: 2.1.0。", "対応: Claude Code を 2.1.0 以降に更新してください。"]
    for c in (cand(fixed="2.0.0-rc.1"), cand(fixed="2.0.0-rc.1", exploited=True, injection_exec=False)):
        text, adv = root(c)
        # h340: a fix the schema cannot express names no version and gets no action sentence.
        assert text.split("\n")[1:3] == [
            "Affected: Claude Code below 2.1.0. A fix is listed upstream; see the source.", f"Source: {GHSA}"]
        assert "Action:" not in text and adv.actions == []
        ja = compose.root_post_ja(adv, None, True)
        assert ja.split("\n")[1:3] == [
            "影響: Claude Code（2.1.0 未満）。 修正は上流で公開されています。出典を参照してください。", f"出典: {GHSA}"]
        assert "対応:" not in ja


def test_reply_post_ja_names_the_changed_fields():
    c = cand(fixed=None)
    _, prev = root(c)
    reply = compose.reply_post(prev, cand(), {"products": [schema.Product(
        "Claude Code", "claude-code", "<2.1.0", "2.1.0")]})
    ja = compose.reply_post_ja(compose.parse_reply(reply, prev), cand(), ["products", "actions"],
                               reason="unverified")
    assert ja.split("\n") == ["Unverified: no primary source confirmed it.",
                              "対応: Claude Code を 2.1.0 以降に更新してください。",
                              "影響: Claude Code（2.1.0 未満）。 修正版: 2.1.0。",
                              f"出典: {GHSA}"]


def test_digest_ja_scaffold_and_groups():
    assert compose.digest([], "2026-11-06", lang="ja") == "2026-11-06 のデイリーダイジェスト: アドバイザリはありません。"
    advs = [_plain(i, "macOS", REL) for i in range(1, 4)] + [_plain(9, "Chrome", KEV)]
    advs += [_plain(10, "Chrome", BLOG), _plain(11, "Chrome", f"{SOCIAL}1", prefix="LEAD-2099-")]  # left out
    en, ja = compose.digest(advs, "2026-11-06"), compose.digest(advs, "2026-11-06", lang="ja")
    assert len(en.split("\n")) == len(ja.split("\n"))
    lines = ja.split("\n")
    assert lines[0] == "2026-11-06 のデイリーダイジェスト: 2 件。" and "注意 (2)" in lines
    assert f"- macOS: リリース 149521, CVE 3 件; 更新あり。 {REL}" in lines
    assert f"- Chrome: セキュリティアドバイザリ (CVE-2098-0009); 修正版の記載なし、ベンダーの情報を確認してください。 {KEV}" in lines
    assert (f"- Chrome: security advisory (CVE-2098-0009); fixed version not stated, check the vendor. {KEV}"
            in en.split("\n"))
    assert "CVE-2098-0010" not in en + ja and "LEAD-" not in en + ja and "未評価" not in ja


def test_digest_leaves_out_retracted_expired_and_synthetic():
    """ai-tools-alerts#d3f6: a retracted, expired or synthetic root is never announced again."""
    _, crit = root(cand(id="CVE-2026-0001", aliases=()))
    def adv(n, **kw):
        return dataclasses.replace(crit, id=f"CVE-2026-{n}", title=f"Claude Code: x (CVE-2026-{n})", **kw)
    retr = adv("0002", aliases=["GHSA-aaaa-bbbb-cccc"])
    gone, edge = adv("0003", expires_at=NOW + 9), adv("0004", expires_at=NOW + 10)  # expiring now is active
    _, syn = root(cand(id="CVE-2099-0010", aliases=()))
    cleared = dataclasses.replace(gone, posted_at=NOW + 1, expires_at=None)  # the latest version wins
    advs, kw = [crit, retr, gone, edge, syn], dict(retracted=["ghsa-AAAA-bbbb-cccc"], now=NOW + 10)
    for lang, head, empty in (("en", "Daily digest for 2026-11-05: 2 advisories.", "no advisories"),
                              ("ja", "2026-11-05 のデイリーダイジェスト: 2 件。", "アドバイザリはありません")):
        out = compose.digest(advs, "2026-11-05", lang=lang, **kw)
        assert out.split("\n")[0] == head and "(2)" in out
        assert "0001" in out and "0004" in out and not any(i in out for i in ("0002", "0003", "2099"))
        assert "0003" in compose.digest(advs + [cleared], "2026-11-05", lang=lang, **kw)
        assert "0003" in compose.digest(advs, "2026-11-05", lang=lang)  # no now: expiry not judged
        assert empty in compose.digest([retr, gone, syn], "2026-11-05", lang=lang, **kw)


def test_lang_reply_header_and_refusals():
    eid = "a" * 64
    assert compose.lang_reply("本文") == "lang: ja\n\n本文"
    assert compose.lang_reply("本文", eid) == f"lang: ja\nof: {eid}\n\n本文"
    for body, of in (("本文", "x" * 64), ("", None), (f"本文\n\n```{schema.INFO_STRING}\n{{}}\n```\n", None)):
        with pytest.raises(ValueError):
            compose.lang_reply(body, of)


# ---------------------------------------------------------------- r7hr: the source title

TOCTOU = "TOCTOU Race in Edit Tool Allows File Writes Outside the Workspace"


def test_root_post_carries_the_source_title_second():
    c = cand(source_title=TOCTOU)
    text, adv = root(c, ("high", None))
    lines = text.split("\n\n```aitools-alert\n", 1)[0].split("\n")
    assert lines[0] == "HIGH: Claude Code: injection to code execution (CVE-2026-0001)"
    assert lines[1] == TOCTOU and len(lines) == 5
    assert TOCTOU not in adv.title and schema.parse_post(text) == adv  # never in the block
    ja = compose.root_post_ja(adv, None, False, compose.source_title(c)).split("\n")
    assert ja[1] == f"原題: {TOCTOU}"
    assert root(cand())[0] == root(cand(source_title=None))[0]  # no title: exactly as before


def test_source_title_equal_to_a_template_kind_is_dropped():
    for t in ("Security Advisory", "unverified security advisory", "  ", "two\nlines", "a ``` fence"):
        assert compose.source_title(cand(source_title=t)) is None


def test_digest_line_carries_the_title_after_the_id():
    _, adv = root(cand(injection_exec=False), ("high", None))
    titles = {(adv.id, "Claude Code"): TOCTOU}
    en = compose.digest([adv], "2026-11-07", titles=titles)
    assert f"(CVE-2026-0001): {TOCTOU}; fixed in 2.1.0." in en
    ja = compose.digest([adv], "2026-11-07", lang="ja", titles=titles)
    assert f"(CVE-2026-0001) 原題: {TOCTOU};" in ja
    assert compose.digest([adv], "2026-11-07") == compose.digest([adv], "2026-11-07", titles={})


# ---------------------------------------------------------------- k5tr: an @token is inline code

MCP = ("@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-everything",
       "@modelcontextprotocol/inspector")


def bare_mentions(text):
    """What the relay would read as a mention: @ at the start or after whitespace, outside code."""
    return re.findall(r"(?<!\S)@[A-Za-z0-9._-]+", re.sub(r"`[^`]*`", "", text))


def test_inline_wraps_whitespace_at_tokens_only():
    i = compose._inline
    assert i("see @scope/pkg.") == "see `@scope/pkg`."
    assert i("@a/b@1.2 x\n@c;") == "`@a/b@1.2` x\n`@c`;"
    for same in ("https://mastodon.social/@user/1", "a@b.c", "@ x", "(@x)"):
        assert i(same) == same
    assert i("x https://h.example/a`b y") == "x https://h.example/a%60b y"
    assert i("a `b @s/p c`") == "a b `@s/p` c"
    assert i("影響: @s/p（x）。\t@.\n@a\\ b") == "影響: `@s/p`（x）。\t`@.`\n`@a`\\ b"


def test_root_and_digest_wrap_a_scoped_package_title():
    title = f"Path traversal in {MCP[0]} allows reads outside roots"
    c = cand(source_title=title)
    text, adv = root(c, ("high", None))
    plain, _ = root(cand(), ("high", None))
    assert f"`{MCP[0]}`" in text and not bare_mentions(text)
    assert text.split("```aitools-alert", 1)[1] == plain.split("```aitools-alert", 1)[1]
    assert schema.parse_post(text) == adv
    ja = compose.root_post_ja(adv, None, False, compose.source_title(c))
    assert f"`{MCP[0]}`" in ja and not bare_mentions(ja)
    for lang in ("en", "ja"):
        d = compose.digest([adv], "2026-11-08", lang, titles={(adv.id, "Claude Code"): title})
        assert f"`{MCP[0]}`" in d and not bare_mentions(d)


def test_title_backtick_cannot_pair_with_ours():
    c = cand(source_title="a `b @scope/pkg c")
    line = root(c, ("high", None))[0].split("\n")[1]
    assert line == "a b `@scope/pkg` c"


def test_digest_shaped_like_2026_11_08_has_no_bare_mention():
    advs, titles = [], {}
    for n in range(43):
        _, adv = compose.root_post(cand(id=f"CVE-2026-{1000 + n}", aliases=()), ("high", None),
                                   scope(cand()), posted_at=NOW + n)
        advs.append(adv)
    for n, pkg in enumerate((MCP[0], MCP[1], MCP[0], MCP[2])):
        titles[(advs[n].id, "Claude Code")] = f"Advisory for {pkg} before 2026.11"
    for lang in ("en", "ja"):
        d = compose.digest(advs, "2026-11-08", lang, titles=titles)
        assert "43" in d.split("\n")[0] and d.count("`@modelcontextprotocol/") == 4
        assert not bare_mentions(d)


def test_a_scoped_product_name_is_inline_code_in_roots_and_replies():
    pkg = MCP[2]
    sc = dataclasses.replace(scope(cand()), name=pkg)
    c = cand()
    text, prev = compose.root_post(c, ("high", None), sc, posted_at=NOW)
    assert text.startswith(f"HIGH: `{pkg}`: ") and not bare_mentions(text.split("```")[0])
    fixed = [{"name": pkg, "ecosystem": prev.products[0].ecosystem, "affected": "<2.1.1", "fixed": "2.1.1"}]
    reply = compose.reply_post(prev, c, {"products": fixed})
    body = reply.split("```")[0]
    assert f"upgrade `{pkg}` to 2.1.1" in body and not bare_mentions(body)
    assert _block(reply)["products"] == fixed  # the block keeps the name as it is
    merged = compose.parse_reply(reply, prev)
    assert merged.products[0].name == pkg
    ja = compose.reply_post_ja(merged, c, _block(reply)) + compose.root_post_ja(merged)
    assert f"`{pkg}`" in ja and not bare_mentions(ja)


# ------------------------------------------------------------ curator translations (mz81)

def relay_mentions(text):
    """Unknown names the relay would read as mentions: a port of buzz-sdk strip_code_regions
    (a fence at a line start runs to the end of its closing fence line; a backtick pairs with
    the next one on the same line; each region becomes one space) and of the ASCII branch of
    extract_at_mentions_with_known with no known names."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("```", i) and not text[text.rfind("\n", 0, i) + 1:i].strip(" \t\r\f"):
            nl = text.find("\n", i + 3)
            j, end = (len(text) if nl < 0 else nl + 1), len(text)
            while j < len(text) and (p := text.find("```", j)) >= 0:
                if not text[text.rfind("\n", 0, p) + 1:p].strip(" \t\r\f"):
                    nl = text.find("\n", p + 3)
                    end = len(text) if nl < 0 else nl + 1
                    break
                j = p + 3
            else:
                end = len(text)
            out.append(" ")
            i = end
            continue
        if text[i] == "`":
            close = text.find("`", i + 1)
            if close >= 0 and "\n" not in text[i + 1:close]:
                out.append(" ")
                i = close + 1
                continue
        out.append(text[i])
        i += 1
    s = "".join(out)
    return re.findall(r"(?:^|(?<=[ \t\n\r\f]))@([A-Za-z0-9._-]+)", s)


def test_relay_oracle_matches_the_scanner():
    assert relay_mentions("a @x `@y` z\n`b`@w") == ["x", "w"]
    assert relay_mentions("```\n@x\n```\n@y") == ["y"]
    assert relay_mentions("a ` @x") == ["x"] and relay_mentions("a@b `@c`") == []
    # buzz-sdk's own strip_code_regions vectors, as mentions, and the fence edges
    assert relay_mentions("before\n```rust\n@x\n```\nafter @y") == ["y"]
    assert relay_mentions("see `@x` here") == [] and relay_mentions("hello `@world") == [] and relay_mentions("hello ` @world") == ["world"]
    assert relay_mentions("```\n@x") == [] and relay_mentions("  ```\n@x\n  ``` tail\n@y") == ["y"]
    assert relay_mentions("a\n@x `") == ["x"] and relay_mentions("x\v@y\n\v```\n@z") == ["z"]


def test_mention_safe_wraps_outside_spans_and_never_touches_one():
    m = compose.mention_safe
    pkg = "@modelcontextprotocol/inspector"
    assert m(f"影響: {pkg} 2.1.0\n{pkg}.") == f"影響: `{pkg}` 2.1.0\n`{pkg}`."
    for same in ("https://mastodon.social/@user/1 a@b.example", f"`{pkg}`", "対象は@scope/pkg",
                 "no backtick", "a ` lone, no token", "```\ncode\n```\nend", "@"):
        assert m(same) == same
    span = "run `npm i @scope/pkg --help` then @other/pkg"
    assert m(span) == "run `npm i @scope/pkg --help` then `@other/pkg`"
    assert m("影響:　@s/p") == "影響:　`@s/p`"
    for x in ("a @x b", span, "`a` b `c` @d"):
        assert m(m(x)) == m(x) and not relay_mentions(m(x))


def test_mention_safe_refuses_what_it_cannot_wrap_safely():
    m = compose.mention_safe
    for bad in ("`code`@x", "a @x`code`", "a ` lone @x", "a ` lone `@x`", "```\n@x\n```",
                "``a`` @x", "\\` @scope/pkg `", "\\`literal`npm i @scope/pkg --help` tail `"):
        assert m(bad) is None, bad


def test_mention_safe_never_rewrites_where_a_reader_could_pair_backticks_otherwise():
    m = compose.mention_safe
    for amb in ("`\r\r`npm i @scope/pkg --help`\r\r`",  # CR breaks a Markdown paragraph
                "See <https://example.invalid/a`b> then `npm i @scope/pkg --help` tail `.",
                "See https://example.invalid/a`b then `npm i @scope/pkg --help` tail `."):
        assert m(amb) is None, amb
    assert m('See <span\ntitle="`"> `npm i @scope/pkg --help` tail `.') is None  # delta review
    for same in ("a\r\nb `c`", "<https://example.invalid/a> `x`", "https://example.invalid/a `c`",
                 '<span\ntitle="`"> `c`'):
        assert m(same) == same
    # Without a backtick there is no pairing to disagree on: a version range or a CR still wraps.
    assert m("Affected: @s/p <2.1, <=3\r\n@t/q") == "Affected: `@s/p` <2.1, <=3\r\n`@t/q`"
    assert m("`x` @s/p <2.1 and <=3") == "`x` `@s/p` <2.1 and <=3"


# ------------------------------------------------ ledger keys are never aliases (8ke5)

def test_a_ledger_key_is_never_published_as_an_alias():
    key = "CVE-2026-0001:claude-code"
    assert not compose.public_id(key) and not compose.public_id("ghsa-abcd-efgh-ijkl:x")
    assert compose.public_id("GHSA-abcd-efgh-ijkl") and compose.public_id("CVE-2026-0002")
    c = cand(id="CVE-2026-0002", aliases=(key, "GHSA-abcd-efgh-ijkl"))
    _, adv = root(c)
    assert adv.aliases == ["GHSA-abcd-efgh-ijkl"]
    out = compose.reply_post(adv, c, {"aliases": [key, "CVE-2026-0003"]})
    patch = json.loads(schema._last_block(out))
    assert patch["aliases"] == ["GHSA-abcd-efgh-ijkl", "CVE-2026-0003"] and key not in out
    with pytest.raises(ValueError, match="no changed field"):  # only a key: nothing to say
        compose.reply_post(adv, c, {"aliases": [key]})


def test_a_published_ledger_key_stays_in_the_list_and_off_the_line():
    """The live OpenSSH thread published CVE-2026-123158:openssh as an alias: a later
    reply keeps it in the block (a list replaces the reader's whole) and never shows it."""
    key = "CVE-2026-0001:claude-code"
    c = cand(aliases=())
    _, adv = root(c)
    adv = dataclasses.replace(adv, aliases=[key])  # as the live thread holds it
    out = compose.reply_post(adv, c, {"aliases": ["CVE-2026-0009"]})
    patch = json.loads(schema._last_block(out))
    assert patch["aliases"] == [key, "CVE-2026-0009"]
    assert "Also known as: CVE-2026-0009." in out and out.count(key) == 1  # in the block only
    merged = compose.parse_reply(out, adv)
    ja = compose.reply_post_ja(merged, c, patch)
    assert "別名: CVE-2026-0009。" in ja and key not in ja


# ---------------------------------------------------------------- 0dvh

def test_a_title_names_the_public_id_and_the_block_keeps_the_key():
    text, adv = root(cand(id="CVE-2026-103435:claude-code", aliases=("CVE-2026-103435",), injection_exec=False),
                     ("high", "severity-tier1"))
    assert text.split("\n")[0] == "HIGH: Claude Code: security advisory (CVE-2026-103435)"
    assert adv.id == "CVE-2026-103435:claude-code" and ":claude-code" not in json.dumps(adv.aliases)
    assert schema.parse_post(text) == adv  # a v0.1.4 reader's parse: same block, same keys


def test_a_thread_titled_with_its_ledger_key_still_matches_the_templates():
    key = "CVE-2026-88968:claude-code"
    legacy = f"Claude Code: known exploited vulnerability ({key})"
    assert legacy in compose._titles("Claude Code", key)
    _, adv = root(cand(id=key, aliases=()), ("high", "severity-tier1"))
    old = dataclasses.replace(adv, title=legacy)
    assert compose._exploited(old) and compose._ja_title(old).endswith(f"悪用が確認された脆弱性 ({key})")
    plain = dataclasses.replace(adv, level="notice", title=f"Claude Code: security advisory ({key})")
    assert compose._group_key(plain) is not None and compose._group_key(dataclasses.replace(
        plain, title="Claude Code: security advisory (CVE-2026-88968)")) is not None


@pytest.mark.parametrize("affected,words", [
    (None, "versions not stated"), (">=1.0 || <0.5", "affected versions: see the source"), ("< 2.1.0", "below 2.1.0")])
def test_versions_not_stated_only_without_a_range(affected, words):
    c = cand(affected=affected, fixed=None, injection_exec=False)
    text, adv = root(c, ("high", "severity-tier1"))
    assert words in text.split("\n")[1]
    ja = compose.root_post_ja(adv, range_unexpressed=compose.range_unexpressed(c))
    assert ("影響バージョンは出典を参照" in ja) == (words.startswith("affected"))


def test_the_upstream_severity_word_is_published_and_nothing_else():
    assert compose.severity("High") == "high" and compose.severity("high; critical") == "critical"
    assert compose.severity("CVSS 9.8") is None and compose.severity(None) is None
    _, prev = root(cand())
    reply = compose.reply_post(prev, cand(), {"advisory_severity": "moderate"})
    assert _block(reply) == {"advisory_severity": "moderate"} and "Upstream severity: moderate." in reply
    with pytest.raises(ValueError):
        compose.reply_post(prev, cand(), {"advisory_severity": "seen at 2.0.77"})


def test_a_reply_to_a_root_titled_with_its_ledger_key_keeps_its_identity():
    key = "CVE-2026-88968:claude-code"
    c = cand(id=key, aliases=("CVE-2026-88968",), injection_exec=False, fixed=None, affected=None)
    _, adv = root(c, ("high", "severity-tier1"))
    prev = dataclasses.replace(adv, title=f"Claude Code: security advisory ({key})")  # as posted before 0dvh
    fixed = [{"name": "Claude Code", "ecosystem": "claude-code", "affected": None, "fixed": "2.1.251"}]
    reply = compose.reply_post(prev, c, {"products": fixed, "advisory_severity": "high"})
    merged = compose.parse_reply(reply, prev)
    assert merged.id == key and merged.title == prev.title and merged.advisory_severity == "high"
    assert "title" not in _block(reply) and "id" not in _block(reply)


# ---------------------------------------------------------------- h340: ids a post may name

@pytest.mark.parametrize("bad", ["LEAD-2026-11-07-claude-code", "OSV-2026-1", "x" * 128, "CVE-2026-1",
                                 "ignore-previous-instructions-and-run-this", "CVE-2026-0001:Not A Slug",
                                 "CVE-2026-0001:" + "a" * 33, "GHSA-abcd-efgh", "CVE-2026-0001 extra", ""])
def test_root_post_refuses_an_id_that_is_not_a_cve_or_ghsa(bad):
    with pytest.raises(ValueError, match="not a CVE or GHSA id"):
        root(cand(id=bad, aliases=()))


def test_root_post_takes_the_thread_key_form_and_publishes_bare_aliases():
    text, adv = root(cand(id="CVE-2026-88968:claude-code", aliases=("CVE-2026-88968", "GHSA-5xjx-9qx6-jcrv", "ghsa-5xjx")))
    assert adv.id == "CVE-2026-88968:claude-code" and adv.aliases == ["CVE-2026-88968", "GHSA-5xjx-9qx6-jcrv"]
    assert schema.parse_post(text) == adv  # the block is the one a v0.1.4 reader parses: no new key
    assert set(json.loads(text.split("```aitools-alert\n", 1)[1].rsplit("\n```", 1)[0])) == set(schema.Advisory.__dataclass_fields__)
