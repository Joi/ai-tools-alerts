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
    assert lines[1] == "Affected: Claude Code, versions not stated. No fixed version is known yet."
    assert lines[2] == "Action: no fix is published yet; watch this thread."
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
    # The guard refuses a candidate that would carry the local host name.
    with pytest.raises(ValueError):
        root(cand(aliases=("host-alpha",)))


def test_rule_inputs_never_reach_post_text():
    c = cand(product_text="Claude Code 2.0.77 on a laptop",
             advisory_severity="CVSS 9.8, seen at 2.0.77", observed_at="2026-11-04")
    out = _all_text(c)
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
    many = compose.reply_post(prev, c, {"aliases": [f"OSV-{i}" for i in range(60)]})
    assert len(_block(many)["aliases"]) == 50
    # A level change for an unverified critical says so.
    unv = compose.reply_post(prev, c, {"level": "high"}, reason="unverified")
    assert unv.split("\n")[0].startswith("Unverified") and "Level is now high." in unv


def test_digest_lists_every_item_once():
    _, crit = root(cand())
    _, high = root(cand(id="CVE-2026-0002", aliases=()), ("high", "fix-rce-tier1"))
    c3 = cand(id="CVE-2026-0003", aliases=(), product_text="Ubuntu linux kernel")
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
    tup = compose.reply_post(prev, c, {"aliases": ("OSV-2026-9", "bad alias!")})
    assert _block(tup)["aliases"] == ["GHSA-abcd-efgh-ijkl", "OSV-2026-9"]  # union, filtered
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


REL = "https://vendor.example.com/en-us/149521"
USN = "https://distro.example.com/security/notices/USN-8928-1"
KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _plain(i, product, url, level="notice", fixed=None, prefix="CVE-2098-", **kw):
    c = cand(id=f"{prefix}{i:04d}", aliases=(), product_text=product, injection_exec=False,
             fixed=fixed, affected=None, sources=(Source(url, None),), **kw)
    return compose.root_post(c, (level, level), scope(c), posted_at=NOW + i)[1]


def test_digest_groups_releases_and_leads():
    advs = [_plain(i, "macOS", REL) for i in range(1, 45)]
    advs += [_plain(100 + i, "Ubuntu linux kernel", USN) for i in range(9)]
    advs += [_plain(200 + i, "Chrome", f"https://social.example.com/@bot/{i}", prefix="LEAD-2099-")
             for i in range(12)]
    crit = dataclasses.replace(_plain(300, "macOS", REL), level="critical")
    out = compose.digest(advs + [crit], "2026-11-06")
    lines = out.split("\n")
    assert lines[0] == "Daily digest for 2026-11-06: 4 advisories."
    assert "Critical (1)" in lines and "Notice (3)" in lines
    assert f"- macOS: release 149521, 44 CVEs; see the release. {REL}" in lines
    assert f"- Linux kernel: release USN-8928-1, 9 CVEs; see the release. {USN}" in lines
    assert "- Chrome: 12 unrated leads." in lines  # a LEAD id is never a reserved one
    assert out.count("CVE-2098-0300") == 1 and "CVE-2098-0001" not in out
    # An allowlisted vendor URL says an update exists; one fixed version is named.
    with pytest.MonkeyPatch.context() as m:
        m.setattr(schema, "is_primary", lambda url, domains=None: url == REL)
        assert "44 CVEs; update available." in compose.digest(advs, "2026-11-06")
    same = [_plain(i, "macOS", REL, fixed="27.2") for i in range(1, 4)]
    assert "3 CVEs; fixed in 27.2." in compose.digest(same, "2026-11-06")


def test_digest_groups_keep_marks_and_kinds_apart():
    real = [_plain(i, "macOS", REL, prefix="CVE-2026-") for i in (1, 2)]
    syn = [_plain(i, "macOS", REL, prefix="CVE-2099-") for i in (3, 4)]
    out = compose.digest(real + syn, "2026-11-06")
    assert f"- macOS: release 149521, 2 CVEs; see the release. {REL}" in out.split("\n")
    assert "SYNTHETIC" not in out and "1 advisory." in out
    # A shared catalog URL is not a release, and unverified titles keep their mark.
    kev = [_plain(i, "macOS", KEV, level="high", exploited=True, prefix="CVE-2026-") for i in (5, 6)]
    c = cand(id="CVE-2026-0007", aliases=(), product_text="macOS", injection_exec=False,
             sources=(Source(REL, None),))
    unv = [compose.root_post(dataclasses.replace(c, id=f"CVE-2026-000{i}"), ("high", "unverified"),
                             scope(c), posted_at=NOW)[1] for i in (7, 8)]
    out = compose.digest(kev + unv, "2026-11-06")
    assert "4 advisories" in out and "CVEs" not in out and out.count("unverified") == 2
    # So do unverified or higher-rated leads: only plain notice leads are "unrated".
    lc = cand(id="LEAD-2099-0001", aliases=(), product_text="Chrome", injection_exec=False,
              trojanized=True, fixed=None, sources=(Source("https://social.example.com/@bot/1", None),))
    leads = [compose.root_post(dataclasses.replace(lc, id=f"LEAD-2099-000{i}"), ("high", "unverified"),
                               scope(lc), posted_at=NOW)[1] for i in (1, 2)]
    leads += [dataclasses.replace(_plain(i, "Chrome", REL, prefix="LEAD-2099-"), level="high") for i in (3, 4)]
    out = compose.digest(leads, "2026-11-06")
    assert "4 advisories" in out and "leads" not in out and out.count("unverified trojanized release") == 2
    notice = [dataclasses.replace(a, level="notice") for a in leads[:2]]  # the title alone keeps them apart
    out = compose.digest(notice, "2026-11-06")
    assert "2 advisories" in out and "leads" not in out and out.count("unverified trojanized release") == 2
    # A group the guard refuses is one withheld item; the next group still prints.
    bad = [dataclasses.replace(a, products=[dataclasses.replace(a.products[0], name="host-alpha")],
                               title=f"host-alpha: security advisory ({a.id})") for a in real]
    with pytest.MonkeyPatch.context() as m:
        m.setattr(socket, "gethostname", lambda: "host-alpha")
        out = compose.digest(bad + [_plain(i, "Ubuntu linux kernel", USN) for i in (3, 4)], "2026-11-06")
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
    _, adv = root(cand(product_text="Example MCP server", fixed="1.2.0"))
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
    assert lines[1] == "影響: Claude Code（バージョン不明）。 修正版はまだ知られていません。"
    syn = cand(id="CVE-2099-0001", aliases=())
    _, adv = root(syn, ("high", "high"))
    assert compose.root_post_ja(adv).startswith(
        "重要 (SYNTHETIC TEST): SYNTHETIC TEST: Claude Code: コード実行につながるインジェクション (CVE-2099-0001)")


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
    advs = [_plain(i, "macOS", REL) for i in range(1, 4)] + [_plain(9, "Chrome", BLOG)]
    en, ja = compose.digest(advs, "2026-11-06"), compose.digest(advs, "2026-11-06", lang="ja")
    assert len(en.split("\n")) == len(ja.split("\n"))
    lines = ja.split("\n")
    assert lines[0] == "2026-11-06 のデイリーダイジェスト: 2 件。" and "注意 (2)" in lines
    assert f"- macOS: リリース 149521, CVE 3 件; リリースを参照。 {REL}" in lines
    assert f"- Chrome: セキュリティアドバイザリ (CVE-2098-0009); 修正版はまだありません。 {BLOG}" in lines


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
