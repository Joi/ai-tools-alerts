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


def test_root_post_body_has_five_lines_and_a_one_line_block():
    """faxq (design section 6): headline, Affected, Do, Covers, Source, then the block on one line."""
    text, adv = root(cand())
    body, rest = text.split("\n\n```aitools-alert\n", 1)
    lines = body.split("\n")
    assert lines == ["CRITICAL: Claude Code: injection to code execution",  # no id in the headline
                     "Affected: `@anthropic-ai/claude-code` before 2.1.0 (npm).",
                     "Do: upgrade Claude Code to 2.1.0 or later.",
                     "Covers 1 advisory: CVE-2026-0001, GHSA-abcd-efgh-ijkl",
                     f"Source: {GHSA}"]  # the primary source, though listed second
    block, end = rest.split("\n", 1)
    assert end == "```\n" and json.loads(block) == json.loads(json.dumps(dataclasses.asdict(adv)))
    assert "\n" not in block and block == json.dumps(json.loads(block), ensure_ascii=False, separators=(",", ":"))
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
    assert lines[1] == "Affected: `@anthropic-ai/claude-code`, versions not stated (npm)."
    assert lines[2] == "Do: apply the source's workaround, if it gives one, until a fixed release ships."
    assert "vendor" not in text and "watch this thread" not in text
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
    reply = compose.reply_post(dataclasses.replace(adv, level="high"), c, {"level": "critical"})  # a raise
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
    out = (text + compose.reply_post(dataclasses.replace(adv, level="high"), c, {"level": "critical"})
           + compose.level_post(adv, "high") + compose.digest([adv], "2026-11-05"))
    assert "2.0.77" not in out and "CVSS" not in out and "laptop" not in out


def _block(reply):
    return json.loads(reply.split("```aitools-alert\n", 1)[1].rsplit("\n```", 1)[0])


def test_reply_only_carries_changed_fields():
    c = cand()
    _, prev = root(c)
    fixed = [{"name": "Claude Code", "ecosystem": "claude-code", "affected": "<2.1.1", "fixed": "2.1.1"}]
    reply = compose.reply_post(prev, c, {"level": "critical", "products": fixed, "expires_at": None})
    block = _block(reply)
    assert set(block) == {"products", "actions"}  # level and expires_at unchanged; action follows fixed
    for expiry in (NOW + 10, None):  # spec/wire.md: no relay-bot reply sets or clears an expiry
        with pytest.raises(ValueError, match="carries no expires_at"):
            compose.reply_post(dataclasses.replace(prev, expires_at=NOW + 5), c, {"products": fixed, "expires_at": expiry})
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
    unv = compose.reply_post(dataclasses.replace(prev, level="high"), c, {"level": "critical"}, reason="unverified")
    assert unv.split("\n")[0].startswith("Unverified") and "Level is now critical." in unv
    # A lowering never shares a reply (spec/wire.md): it is level_post's.
    with pytest.raises(ValueError, match="travels alone"):
        compose.reply_post(prev, c, {"level": "high"})


def test_digest_lists_every_item_once():
    """qwpw: one line per post, loudest first, a level word on each line, no sections."""
    _, crit = root(cand())
    _, high = root(cand(id="CVE-2026-0002", aliases=()), ("high", "fix-rce-tier1"))
    c3 = cand(id="CVE-2026-0003", aliases=(), product_text="linux kernel")
    _, note = compose.root_post(c3, ("notice", "notice"), scope(c3), posted_at=NOW)
    later = dataclasses.replace(high, posted_at=NOW + 5, level="critical")
    out = compose.digest([note, high, crit, later], "2026-11-05")
    lines = out.split("\n")
    assert lines[0] == "Daily digest for 2026-11-05: 3 new alerts." and len(lines) == 4
    assert out.count("CVE-2026-0001") == 1 and out.count("CVE-2026-0002") == 1
    assert out.count("CVE-2026-0003") == 1
    assert [ln.split(":")[0] for ln in lines[1:]] == ["- CRITICAL", "- CRITICAL", "- NOTICE"]
    assert out.index("CVE-2026-0001") < out.index("CVE-2026-0002")  # same level: oldest first
    assert "High" not in out and "Critical (" not in out  # no sections
    assert compose.digest([], "2026-11-05") == "Daily digest for 2026-11-05: no new alerts. 0 notices added to the catalog this week: https://buzz.ai-tools.md/alerts/"


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
    text, adv = root(cand(fixed="2.0.0-rc.1"), ("high", "fix-rce-tier1"))  # 9kgk: a critical needs a stated version
    assert "the fixed release the source names" in text and "no fix" not in text and adv.actions == []
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
    assert head == "CRITICAL (SYNTHETIC TEST): Claude Code: injection to code execution"  # the head marks it
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
        assert compose.digest([a], "2026-11-05") == "Daily digest for 2026-11-05: no new alerts. 0 notices added to the catalog this week: https://buzz.ai-tools.md/alerts/"
    assert adv.title in compose._titles("Claude Code", adv.id)
    assert legacy.title not in compose._titles("Claude Code", adv.id)
    assert compose.reply_post(dataclasses.replace(adv, level="high"), c,
                              {"level": "critical"}).count("SYNTHETIC") == 0  # block: changed fields
    assert compose.level_post(adv, "high").count("SYNTHETIC") == 0
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


def test_digest_one_line_per_post_and_leaves_out_leads():
    """qwpw: no release grouping (a v1 rule; faxq makes one post per fix): one line per post."""
    advs = [_plain(i, "macOS", REL) for i in range(1, 4)]
    leads = [_plain(200 + i, "Chrome", f"{SOCIAL}{i}", prefix="LEAD-2099-") for i in range(12)]
    leads += [_plain(220, "Chrome", REL, prefix="LEAD-2099-")]  # a lead with a primary source too
    leads += [dataclasses.replace(_plain(221, "Chrome", REL, prefix="LEAD-2099-"), level="high")]
    crit = dataclasses.replace(_plain(300, "macOS", REL), level="critical")
    out = compose.digest(advs + leads + [crit], "2026-11-06")
    lines = out.split("\n")
    assert lines[0] == "Daily digest for 2026-11-06: 4 new alerts." and len(lines) == 5  # leads are not counted
    assert lines[1].startswith("- CRITICAL: ") and "CVE-2098-0300" in lines[1]
    assert lines[2] == ("- NOTICE: macOS: security advisory (CVE-2098-0001); "
                        f"fixed version not stated, check the vendor. {REL}")
    assert "LEAD-" not in out and "leads" not in out and "Chrome" not in out  # 8ke5
    assert "CVEs" not in out and "release 149521" not in out
    # Only leads, or only items with no primary source: nothing to list, in either language.
    social = [_plain(400 + i, "macOS", f"{SOCIAL}{i}") for i in range(3)]
    for lang in ("en", "ja"):
        assert compose.digest(leads + social, "2026-11-06", lang=lang) \
            == compose.digest([], "2026-11-06", lang=lang)


def test_digest_keeps_marks_and_withholds_one_line():
    real = [_plain(i, "macOS", REL, prefix="CVE-2026-") for i in (1, 2)]
    syn = [_plain(i, "macOS", REL, prefix="CVE-2099-") for i in (3, 4)]
    out = compose.digest(real + syn, "2026-11-06")
    assert "SYNTHETIC" not in out and "2 new alerts." in out and "2099" not in out
    c = cand(id="CVE-2026-0007", aliases=(), product_text="macOS", injection_exec=False,
             sources=(Source(REL, None),))
    unv = [compose.root_post(dataclasses.replace(c, id=f"CVE-2026-000{i}"), ("high", "unverified"),
                             scope(c), posted_at=NOW)[1] for i in (7, 8)]
    out = compose.digest(unv, "2026-11-06")
    assert "2 new alerts" in out and out.count("unverified") == 2
    # A line the guard refuses is one withheld item; the next line still prints.
    bad = [dataclasses.replace(a, products=[dataclasses.replace(a.products[0], name="host-alpha")],
                               title=f"host-alpha: security advisory ({a.id})") for a in real[:1]]
    with pytest.MonkeyPatch.context() as m:
        m.setattr(socket, "gethostname", lambda: "host-alpha")
        out = compose.digest(bad + [_plain(i, "linux kernel", USN) for i in (3, 4)], "2026-11-06")
    assert "1 item withheld" in out and "host-alpha" not in out and out.count("Linux kernel") == 2


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
    assert "Do: upgrade containerd to 1.7.29 or later." in text.split("\n")
    assert "Docker" not in text


def test_entry_fallback_composes_under_the_entry_name():
    _, adv = root(cand(product_text="agent skills", fixed="1.2.0"))
    assert adv.products[0].name == adv.actions[0].target == "ClawHub and skills.sh"


def test_root_post_refuses_unresolved_entry():
    [docker] = [e for e in schema.load_scope() if e.name == "Docker"]
    with pytest.raises(ValueError):
        compose.root_post(containerd_kev(), "critical", docker, posted_at=NOW)


# ---------------------------------------------------------------- Japanese lang: ja replies (rd8t)


def test_root_post_ja_keeps_names_ids_versions_urls():
    c = cand()
    _, adv = root(c)
    lines = compose.root_post_ja(adv, None, compose.fix_unexpressed(c)).split("\n")
    assert lines == ["緊急: Claude Code: コード実行につながるインジェクション",
                     "影響: Claude Code（2.1.0 未満）。",
                     "対応: Claude Code を 2.1.0 以降に更新してください。",
                     "対象: アドバイザリ 1 件: CVE-2026-0001, GHSA-abcd-efgh-ijkl",
                     f"出典: {GHSA}"]
    pkg = compose.package_of(scope(c))
    assert pkg == ("@anthropic-ai/claude-code", "npm")
    assert compose.root_post_ja(adv, package=pkg).split("\n")[1] == "影響: `@anthropic-ai/claude-code`（2.1.0 未満）（npm）。"
    c = cand(injection_exec=False, trojanized=True, fixed=None, affected=None)
    _, adv = root(c, ("high", "unverified"))
    lines = compose.root_post_ja(adv, "unverified").split("\n")
    assert lines[0] == ("重要 (unverified: no primary source confirmed it): "
                        "Claude Code: 改ざんされたリリース")  # the head marks it, once
    assert lines[1] == "影響: Claude Code（バージョン不明）。"
    assert lines[2] == "対応: 出典に回避策があれば適用し、修正版が出るまで続けてください。"
    syn = cand(id="CVE-2099-0001", aliases=())
    _, adv = root(syn, ("high", "high"))
    assert compose.root_post_ja(adv).startswith(
        "重要 (SYNTHETIC TEST): Claude Code: コード実行につながるインジェクション\n")


_NO_FIX_CLAIMS = ("no fix", "No fixed version is known", "watch this thread", "修正版はまだ", "修正はまだ")


def test_root_post_kev_without_version_never_says_no_fix():
    """A KEV entry carries no version data: the post never says there is no fix, and a
    known-exploited one says so in its one action sentence (faxq: never "check the vendor")."""
    kev = cand(id="CVE-2026-1253", aliases=(), product_text="Chrome", exploited=True,
               injection_exec=False, fixed=None, affected=None, sources=(Source(BLOG, None),))
    for level, mark in ((("high", "high"), ""), (("high", "unverified"), "unverified ")):
        text, adv = compose.root_post(kev, level, scope(kev), posted_at=NOW)
        assert adv.title == f"Chrome: {mark}known exploited vulnerability (CVE-2026-1253)"
        lines = text.split("\n\n```")[0].split("\n")
        assert lines[1:3] == [
            "Affected: Chrome, versions not stated.",
            "Do: this is exploited in the wild. Apply the source's workaround, if it gives one, "
            "until a fixed release ships."]
        assert "vendor" not in text.split("\n\n```")[0]
        ja = compose.root_post_ja(adv, level[1], compose.fix_unexpressed(kev))
        assert ja.split("\n")[1:3] == [
            "影響: Chrome（バージョン不明）。",
            "対応: 悪用が確認されています。出典に回避策があれば適用し、修正版が出るまで続けてください。"]
        digests = compose.digest([adv], "2026-11-11") + compose.digest([adv], "2026-11-11", lang="ja")
        for claim in _NO_FIX_CLAIMS:
            assert claim not in text and claim not in ja and claim not in digests
    # A thread that was a trojanized release keeps that title when KEV adds it at the same
    # level (main.plan_known): the candidate's flag still makes the action urgent.
    tro = dataclasses.replace(kev, exploited=False, trojanized=True)
    _, adv = compose.root_post(tro, ("high", "high"), scope(tro), posted_at=NOW)
    assert "trojanized release" in adv.title
    assert compose.root_post_ja(adv).split("\n")[2] == "対応: 出典に回避策があれば適用し、修正版が出るまで続けてください。"
    assert "悪用が確認" in compose.root_post_ja(adv, exploited=True).split("\n")[2]
    # A synthetic KEV check keeps the exploited action.
    syn = dataclasses.replace(kev, id="CVE-2099-0001")
    text, adv = compose.root_post(syn, ("high", "high"), scope(syn), posted_at=NOW)
    assert "exploited in the wild" in text
    assert "悪用が確認" in compose.root_post_ja(adv)


def test_root_post_fixed_line_unchanged_and_unexpressed_has_no_action():
    """The fixed branch: the upgrade sentence, exploited or not."""
    kev = cand(exploited=True, injection_exec=False)
    text, adv = root(kev)
    assert text.split("\n")[1:3] == ["Affected: `@anthropic-ai/claude-code` before 2.1.0 (npm).",
                                     "Do: upgrade Claude Code to 2.1.0 or later."]
    assert compose.root_post_ja(adv).split("\n")[1:3] == [
        "影響: Claude Code（2.1.0 未満）。", "対応: Claude Code を 2.1.0 以降に更新してください。"]
    for c in (cand(fixed="2.0.0-rc.1"), cand(fixed="2.0.0-rc.1", exploited=True, injection_exec=False)):
        text, adv = root(c, ("high", "fix-rce-tier1"))  # 9kgk: a critical needs a stated version
        # h340: a fix the schema cannot express names no version; the sentence sends the
        # member to the release the source names, and the block carries no action.
        assert text.split("\n")[1:3] == [
            "Affected: `@anthropic-ai/claude-code` before 2.1.0 (npm).",
            "Do: upgrade Claude Code to the fixed release the source names."]
        assert "2.0.0-rc" not in text.split("\n\n```")[0] and adv.actions == []
        ja = compose.root_post_ja(adv, None, True)
        assert ja.split("\n")[1:3] == [
            "影響: Claude Code（2.1.0 未満）。", "対応: Claude Code を出典に記載された修正版に更新してください。"]


def test_a_critical_carries_a_complete_action():
    """9kgk: an upgrade to a stated version, or stop_using for a malicious release; any
    other critical does not post. A bare level (a thread's standing one) composes."""
    text, adv = root(cand(fixed=None), ("critical", "stop-using"))
    assert [(a.verb, a.target, a.value) for a in adv.actions] == [("stop_using", "Claude Code", None)]
    assert "Do: no fix yet. Stop using Claude Code until one ships." in text.split("\n")
    assert "対応: 修正版はまだありません。修正版が出るまで Claude Code の使用を停止してください。" \
        in compose.root_post_ja(adv).split("\n")
    for reason in ("kev-tier1", "fields", "reading"):
        with pytest.raises(ValueError, match="complete action"):
            root(cand(fixed=None), ("critical", reason))
        with pytest.raises(ValueError, match="complete action"):
            root(cand(fixed="2.0.0-rc.1"), ("critical", reason))  # a fix the schema cannot say
    _, fixed = root(cand(fixed="2.1.0"), ("critical", "kev-tier1"))
    assert [(a.verb, a.value) for a in fixed.actions] == [("upgrade", "2.1.0")]
    _, kept = root(cand(fixed=None), "critical")
    assert kept.actions == []


def test_a_stop_using_thread_keeps_its_action_until_a_fix():
    """Stage-1 review: a reply on a stop_using critical thread that is not a fix keeps
    stop_using and publishes; the fix replaces it with the upgrade."""
    _, prev = root(cand(fixed=None), ("critical", "stop-using"))
    rng = compose.reply_post(prev, cand(), {"products": [schema.Product("Claude Code", "claude-code", "<2.5.0", None)]})
    merged = compose.parse_reply(rng, prev)
    assert [(a.verb, a.value) for a in merged.actions] == [("stop_using", None)]
    ids = compose.parse_reply(compose.reply_post(prev, cand(), {"aliases": ["CVE-2026-0009"]}), prev)
    assert [a.verb for a in ids.actions] == ["stop_using"]
    fix = compose.reply_post(prev, cand(), {"products": [schema.Product("Claude Code", "claude-code", "<2.5.0", "2.5.0")]})
    assert [(a.verb, a.value) for a in compose.parse_reply(fix, prev).actions] == [("upgrade", "2.5.0")]
    _, plain = root(cand(fixed=None), ("high", "fix-rce-tier1"))  # a thread that never had stop_using
    with pytest.raises(ValueError):
        compose.reply_post(plain, cand(), {"actions": [schema.Action("stop_using", "Claude Code", None)]})


def test_reply_post_ja_names_the_changed_fields():
    c = cand(fixed=None)
    _, prev = root(c, ("high", "fix-rce-tier1"))
    reply = compose.reply_post(prev, cand(), {"products": [schema.Product(
        "Claude Code", "claude-code", "<2.1.0", "2.1.0")]})
    ja = compose.reply_post_ja(compose.parse_reply(reply, prev), cand(), ["products", "actions"],
                               reason="unverified")
    assert ja.split("\n") == ["Unverified: no primary source confirmed it.",
                              "対応: Claude Code を 2.1.0 以降に更新してください。",
                              "影響: Claude Code（2.1.0 未満）。 修正版: 2.1.0。",
                              f"出典: {GHSA}"]


def test_digest_ja_scaffold():
    assert compose.digest([], "2026-11-06", lang="ja") == (
        "2026-11-06 のデイリーダイジェスト: 新しいアラートはありません。"
        "今週カタログに追加された注意: 0 件: https://buzz.ai-tools.md/alerts/")
    advs = [_plain(i, "macOS", REL) for i in range(1, 4)] + [_plain(9, "Chrome", KEV)]
    advs += [_plain(10, "Chrome", BLOG), _plain(11, "Chrome", f"{SOCIAL}1", prefix="LEAD-2099-")]  # left out
    en, ja = compose.digest(advs, "2026-11-06"), compose.digest(advs, "2026-11-06", lang="ja")
    assert len(en.split("\n")) == len(ja.split("\n")) == 5
    lines = ja.split("\n")
    assert lines[0] == "2026-11-06 のデイリーダイジェスト: 新しいアラート 4 件。"
    assert f"- 注意: Chrome: セキュリティアドバイザリ (CVE-2098-0009); 修正版の記載なし、ベンダーの情報を確認してください。 {KEV}" in lines
    assert (f"- NOTICE: Chrome: security advisory (CVE-2098-0009); fixed version not stated, check the vendor. {KEV}"
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
    for lang, head, empty in (("en", "Daily digest for 2026-11-05: 2 new alerts.", "no new alerts"),
                              ("ja", "2026-11-05 のデイリーダイジェスト: 新しいアラート 2 件。", "新しいアラートはありません")):
        out = compose.digest(advs, "2026-11-05", lang=lang, **kw)
        assert out.split("\n")[0] == head and len(out.split("\n")) == 3
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


def test_the_source_title_is_the_headline():
    """faxq: in this slice the headline is the source's own title, after the product
    name when the title does not name it; the block's title keeps its template."""
    c = cand(source_title=TOCTOU)
    text, adv = root(c, ("high", None))
    lines = text.split("\n\n```aitools-alert\n", 1)[0].split("\n")
    assert lines[0] == f"HIGH: Claude Code: {TOCTOU}" and len(lines) == 5
    assert TOCTOU not in adv.title and schema.parse_post(text) == adv  # never in the block
    ja = compose.root_post_ja(adv, None, False, compose.source_title(c)).split("\n")
    assert ja[0] == f"重要: Claude Code: {TOCTOU}" and not any("原題" in x for x in ja)
    named = root(cand(source_title="Claude Code: edit tool writes outside the workspace"), ("high", None))[0]
    assert named.split("\n")[0] == "HIGH: Claude Code: edit tool writes outside the workspace"  # not twice
    assert root(cand())[0] == root(cand(source_title=None))[0]


def test_the_headline_is_at_most_90_characters_and_cut_at_a_word():
    long = "A deliberately long advisory title that keeps going well past what fits on one line of a post"
    head = root(cand(source_title=long), ("high", None))[0].split("\n")[0]
    assert len(head) <= compose.HEADLINE_MAX and head.endswith("…") and head.startswith("HIGH: Claude Code: A ")
    assert long.startswith(head[len("HIGH: Claude Code: "):-1])  # cut, not rewritten
    assert not head[:-1].endswith(" ")
    marked = root(cand(source_title=long), ("high", "unverified"))[0].split("\n")[0]
    assert marked.startswith(f"HIGH ({compose.UNVERIFIED}): ")  # the mark is never cut


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
    line = root(c, ("high", None))[0].split("\n")[0]
    assert line == "HIGH: Claude Code: a b `@scope/pkg` c"


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
    assert text.split("\n")[0] == "HIGH: Claude Code: security advisory"  # faxq: no id in the headline
    assert "Covers 1 advisory: CVE-2026-103435" in text.split("\n")
    assert adv.title == "Claude Code: security advisory (CVE-2026-103435)"  # the block's names the public id
    assert adv.id == "CVE-2026-103435:claude-code" and ":claude-code" not in json.dumps(adv.aliases)
    assert schema.parse_post(text) == adv  # a v0.1.4 reader's parse: same block, same keys


def test_a_thread_titled_with_its_ledger_key_still_matches_the_templates():
    key = "CVE-2026-88968:claude-code"
    legacy = f"Claude Code: known exploited vulnerability ({key})"
    assert legacy in compose._titles("Claude Code", key)
    _, adv = root(cand(id=key, aliases=()), ("high", "severity-tier1"))
    old = dataclasses.replace(adv, title=legacy)
    assert compose._exploited(old) and compose._ja_title(old).endswith(f"悪用が確認された脆弱性 ({key})")


@pytest.mark.parametrize("affected,words", [
    (None, "versions not stated"), (">=1.0 || <0.5", "affected versions: see the source"), ("< 2.1.0", "before 2.1.0")])
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


def test_the_block_severity_is_the_pages_word_never_the_records():  # dmmf
    assert root(cand(advisory_severity="critical"))[1].advisory_severity is None
    assert root(cand(advisory_severity="low", severity_word="high; critical"))[1].advisory_severity == "critical"
    assert "severity_word" not in cand(severity_word="high").to_dict()  # read again on each admit


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


# ---------------------------------------------------------------- faxq review

def test_covers_counts_only_what_the_ids_can_say():
    _, adv = root(cand())
    one = dataclasses.replace(adv, aliases=["GHSA-abcd-efgh-ijkl", "GHSA-zzzz-zzzz-zzzz"])
    assert compose.covers(one)[0] == 2  # two GHSA advisories, the CVE an alias of one
    mixed = dataclasses.replace(adv, aliases=["GHSA-abcd-efgh-ijkl", "CVE-2026-0002", "CVE-2026-0003"])
    assert compose.covers(mixed) == (None, ["CVE-2026-0001", "GHSA-abcd-efgh-ijkl", "CVE-2026-0002", "CVE-2026-0003"])
    assert "Covers: CVE-2026-0001, GHSA-abcd-efgh-ijkl, CVE-2026-0002, CVE-2026-0003" in compose._covers_line(mixed)
    cves = dataclasses.replace(adv, aliases=["CVE-2026-0002"])
    assert compose.covers(cves)[0] == 2


def test_a_headline_with_a_mention_still_fits_after_wrapping():
    long = "@scope/pkg " + "and a long description of what goes wrong when it is used " * 2
    head = root(cand(source_title=long), ("high", None))[0].split("\n")[0]
    assert "`@scope/pkg`" in head and len(head) <= compose.HEADLINE_MAX
    git = root(cand(source_title="digital signature bypass"), ("high", None))[0].split("\n")[0]
    assert git == "HIGH: Claude Code: digital signature bypass"


def test_a_title_change_without_the_level_still_says_something():
    """Review: on a lowered thread the level travels alone; a title change left in the
    other reply gets its own line, never a body of only "Source:"."""
    c = cand(injection_exec=False, trojanized=True)
    _, prev = root(c, ("high", "high"))
    new_title = "Claude Code: known exploited vulnerability (CVE-2026-0001)"
    out = compose.reply_post(prev, c, {"title": new_title})
    assert out.split("\n")[0] == "Now: Claude Code: known exploited vulnerability."
    ja = compose.reply_post_ja(compose.parse_reply(out, prev), c, {"title": new_title})
    assert ja.split("\n")[0] == "件名: Claude Code: 悪用が確認された脆弱性"
