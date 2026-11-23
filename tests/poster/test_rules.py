"""Level rules, exact scope identity and authoritative evidence (Task B2, ai-tools-alerts#h340)."""

from pathlib import Path

import threading
import time
import urllib.error
import urllib.request
from dataclasses import replace

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import candidates, compose, rules
from pages import advisory_page
from aitools_alerts.poster.candidates import Candidate, Source

KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def cand(**kw) -> Candidate:
    base = dict(
        id="CVE-2026-0001",
        aliases=(),
        product_text="Anthropic Claude Code",
        advisory_severity=None,
        local_level_hint=None,
        exploited=False,
        trojanized=False,
        injection_exec=False,
        fixed=None,
        affected=None,
        sources=(Source(KEV_PAGE, None),),
        observed_at=None,
    )
    base.update(kw)
    return Candidate(**base)


def level(c: Candidate, source_ok=False):
    return rules.level_for(c, rules.scope_of(c.product_text), source_ok)


def test_kev_tier1_is_critical():
    c = cand(exploited=True)
    assert level(c, True) == ("critical", "kev-tier1")
    # The KEV clause is mechanical: it does not wait on a source fetch.
    assert level(c, False) == ("critical", "kev-tier1")


def test_kev_tier2_is_high():
    c = cand(product_text="Linux Kernel", exploited=True)
    assert rules.scope_of(c.product_text).tier == 2
    assert level(c, True) == ("high", "kev-tier2")
    # Tier 2 never reaches critical, whatever the flags.
    every = cand(product_text="Apple macOS", exploited=True, trojanized=True,
                 injection_exec=True, fixed="15.1", advisory_severity="remote code execution",
                 local_level_hint="critical")
    assert level(every, True)[0] == "high"
    for flags in ({"trojanized": True}, {"injection_exec": True, "fixed": "1.0"},
                  {"fixed": "1.0", "advisory_severity": "remote code execution"}):
        for ok in (True, False):
            assert level(cand(product_text="Google Chrome", **flags), ok) == ("notice", "notice")


def test_trojanized_without_primary_is_high_unverified():
    c = cand(product_text="npm:@anthropic-ai/claude-code", trojanized=True)
    assert level(c, False) == ("high", "unverified")
    assert level(c, True) == ("critical", "trojanized-primary")


def test_injection_exec_needs_fix():
    c = cand(product_text="Cursor IDE", injection_exec=True)
    assert level(c, True) == ("notice", "notice")
    fixed = cand(product_text="Cursor IDE", injection_exec=True, fixed="1.7.4")
    assert level(fixed, True) == ("critical", "injection-exec-fixed")
    assert level(fixed, False) == ("high", "unverified")

def test_out_of_scope_is_none():
    for text in ("acme widget", "", "   ", None, 42, b"claude code"):
        assert rules.scope_of(text) is None
    with pytest.raises(ValueError):
        rules.level_for(cand(product_text="acme widget", exploited=True), None, True)


def test_fix_rce_tier1_is_high():
    c = cand(product_text="Node.js", fixed="22.11.1", advisory_severity="High: remote code execution")
    assert level(c) == ("high", "fix-rce-tier1")
    cred = cand(product_text="Tailscale", fixed="1.76.0", advisory_severity="credential exposure")
    assert level(cred) == ("high", "fix-rce-tier1")
    plain = cand(product_text="Node.js", fixed="22.11.1", advisory_severity="CRITICAL")
    assert level(plain) == ("high", "severity-tier1")  # the level word alone: severity-tier1
    for text in ("High; remote code-execution", "lets an attacker execute arbitrary commands",
                 "\uff32\uff23\uff25 in the inspector"):
        assert level(cand(product_text="Node.js", fixed="22.11.1", advisory_severity=text)) == \
            ("high", "fix-rce-tier1"), text
    nofix = cand(product_text="Node.js", advisory_severity="remote code execution")
    assert level(nofix) == ("notice", "notice")


def test_severity_tier1_is_high():
    for sev in ("high", "critical", "High ", " CRITICAL", "\uff28\uff49\uff47\uff48", "high\u3000"):
        assert level(cand(advisory_severity=sev)) == ("high", "severity-tier1"), sev
    ghsa = cand(id="GHSA-5xjx-9qx6-jcrv", advisory_severity="high")
    assert level(ghsa) == ("high", "severity-tier1")
    alias = cand(id="OSV-2026-1", aliases=("CVE-2026-0009",), advisory_severity="high")
    assert level(alias) == ("high", "severity-tier1")
    upper = cand(id="GHSA-5XJX-9QX6-JCRV", advisory_severity="high")
    assert level(upper) == ("high", "severity-tier1")
    for sev in ("moderate", "low", "medium", None, "high-ish", "not high", ""):
        assert level(cand(advisory_severity=sev)) == ("notice", "notice"), sev
    # Tier 2 stays notice; critical stays reserved for the three critical rules.
    assert level(cand(product_text="Google Chrome", advisory_severity="critical")) == ("notice", "notice")
    assert level(cand(advisory_severity="critical"), True)[0] == "high"


def test_fix_rce_tier1_wins_over_severity_tier1():
    c = cand(fixed="2.1.251", advisory_severity="high")
    assert level(c) == ("high", "severity-tier1")
    rce = cand(fixed="2.1.251", advisory_severity="high: remote code execution")
    assert level(rce) == ("high", "fix-rce-tier1")


def test_news_lead_severity_never_raises_level():
    for cid, aliases in (("LEAD-2026-11-07-claude-code", ()), ("LEAD-1", ("not-an-advisory",)),
                         ("CVE-2026-01", ()), ("CVE-2026-0001x", ()), ("GHSA-5xjx-9qx6", ())):
        lead = cand(id=cid, aliases=aliases, advisory_severity="critical")
        assert level(lead, True) == ("notice", "notice"), cid


def test_collector_claude_code_advisory_is_tier1_high():
    # The cfe8 collector record: a repo-level GHSA on Claude Code, no "fixed" field.
    record = {"schema_version": 1, "findings": [{
        "id": "CVE-2026-88968", "aliases": ["GHSA-5xjx-9qx6-jcrv"], "product": "claude-code",
        "advisory_severity": "high",
        "sources": [{"url": "https://github.com/anthropics/claude-code/security/advisories/"
                            "GHSA-5xjx-9qx6-jcrv", "published_at": "2026-11-05T00:00:00Z"}],
    }]}
    out = candidates.from_collector(record)
    assert len(out) == 1, out.skipped
    c = out[0]
    assert (c.advisory_severity, c.fixed) == ("high", None)  # what from_collector sets today
    scope = rules.scope_of(c.product_text)
    assert scope.tier == 1
    assert rules.level_for(c, scope, False) == ("high", "severity-tier1")


def test_hint_never_raises_level():
    c = cand(local_level_hint="critical")
    assert level(c, True) == ("notice", "notice")


def test_source_ok_must_be_true_bool():
    c = cand(trojanized=True)
    for not_ok in (1, "yes", [True], None):
        assert level(c, not_ok) == ("high", "unverified")


def test_bad_tier_raises():
    entry = schema.ScopeEntry(name="x", ecosystem="x", tier=3, match=["x"])
    with pytest.raises(ValueError):
        rules.level_for(cand(exploited=True), entry, True)

def test_unmatched_log_is_caller_owned():
    assert rules.scope_of("Anthropic") is None  # no log given: nothing kept anywhere
    assert not [n for n in vars(rules) if "unmatched" in n.lower()]


def test_vendor_words_from_tier1_names():
    words = rules.vendor_words(schema.load_scope())
    assert {"claude", "codex", "cursor", "docker", "git", "go", "anthropic", "openai",
            "containerd", "runc", "rustup"} <= words
    assert "ubuntu" not in words and "macos" not in words


def test_source_is_schema_source():
    assert candidates.Source is schema.Source


# ------------------------------------------- exact identity (ai-tools-alerts#h340)

def test_scope_is_exact_identity():
    assert rules.scope_of("ANTHROPIC CLAUDE CODE").name == "Claude Code"
    assert rules.scope_of("Anthropic Claude Code").tier == 1
    # Compatibility characters, case, Unicode dashes and whitespace runs normalise first.
    for text in ("Ｄｏｃｋｅｒ Engine", "Claude  Code", "claude‑code", "claude–code", "Claude\tCode",
                 "  claude code  "):
        assert rules.scope_of(text) is not None, text
    # A component's identity resolves to the component, with its own authority.
    hit = rules.scope_of("opencontainers/runc")
    assert (hit.name, hit.ecosystem, hit.components) == ("runc", "docker", ())
    assert hit.authority == ("github.com/opencontainers/runc/",)
    assert rules.scope_of("docker").authority == rules.scope_of("moby/moby").authority != ()
    assert rules.scope_of("mcp-remote").authority == ()  # an empty list replaces the entry's


# The finding's names (H4) and other text the word rule used to match: none is a product.
THIRD_PARTY = ("claude-code-router", "my-docker-helper", "awesome-openssh-wrapper",
               "musistudio claude-code-router", "npm:claude-code-router", "npm:claude-code",
               "Docker Desktop on Ubuntu", "OpenSSH9.8p1", "openssh/openssh-portable 9.8",
               "@anthropic-ai/claude-code npm package", "System Information Library for Node.JS",
               "Example MCP server", "mcp-server-evil", "claude code router", "docker-compose",
               "golang.org/x/crypto", "@openclaw/discord", "skills.shopify", "Anthropic Claude Desktop")


def test_a_third_party_name_is_never_a_product():
    log: list[str] = []
    for text in THIRD_PARTY:
        assert rules.scope_of(text, log) is None, text
    # Each holds a tier-1 vendor word, so each is logged for review; the log decides nothing.
    assert set(log) >= {"claude-code-router", "my-docker-helper", "musistudio claude-code-router"}
    assert rules.scope_of("acme widget", log) is None and "acme widget" not in log
    rules.scope_of("Claude Code", log)
    assert "Claude Code" not in log  # matched text is never logged


def test_every_identity_resolves_to_its_owner_and_no_other():
    entries = schema.load_scope()
    seen = set()
    for e in entries:
        for owner, ids in [(e.name, e.match)] + [(c.name, c.match) for c in e.components]:
            for m in ids:
                assert m not in seen, m
                seen.add(m)
                hit = rules.scope_of(m)
                assert hit is not None and hit.name == owner, (m, owner, hit and hit.name)
                # No identity is reachable by adding or removing a word.
                assert rules.scope_of(m + " plugin") is None and rules.scope_of("my-" + m) is None, m


# CISA KEV's vendorProject and product, joined: each listed, none assumed.
KEV_FORMS = {"Anthropic Claude Code": "Claude Code", "OpenBSD OpenSSH": "OpenSSH", "Node.js Node.js": "Node.js",
             "containerd containerd": "containerd", "Google Chrome": "Chrome", "Google Chromium V8": "Chromium",
             "Apple macOS": "macOS", "Apple Safari": "Safari", "Mozilla Firefox": "Firefox",
             "Linux Kernel": "Linux kernel", "Git Git": "git", "Docker Desktop": "Docker",
             "Tailscale Tailscale": "Tailscale", "OpenAI Codex": "Codex"}
# Repository slugs and package keys the sources use.
SOURCE_FORMS = {"anthropics/claude-code": "Claude Code", "@anthropic-ai/claude-code": "Claude Code",
                "npm:@anthropic-ai/claude-code": "Claude Code", "openai/codex": "Codex", "npm:@openai/codex": "Codex",
                "openai/codex-cli": "Codex", "OpenAI Codex CLI": "Codex", "cursor/cursor": "Cursor",
                "Cursor CLI": "Cursor", "google-gemini/gemini-cli": "Gemini CLI", "@google/gemini-cli": "Gemini CLI",
                "NousResearch/hermes-agent": "Hermes", "openclaw/openclaw": "OpenClaw",
                "modelcontextprotocol/servers": "MCP servers and clients", "@modelcontextprotocol/sdk": "MCP TypeScript SDK",
                "nodejs/node": "Node.js", "python/cpython": "Python", "golang/go": "Go", "rust-lang/rust": "Rust",
                "moby/moby": "Docker", "github.com/docker/cli": "Docker", "docker-ce": "Docker",
                "opencontainers/runc": "runc", "getcursor/cursor": "Cursor", "cursor-agent": "Cursor",
                "dockerd": "Docker", "tailscale/tailscale": "Tailscale", "tailscaled": "Tailscale",
                "openssh/openssh-portable": "OpenSSH", "git/git": "git", "MCP servers": "MCP servers and clients",
                "Agent Skills": "ClawHub and skills.sh", "skills.sh": "skills.sh"}


def test_kev_and_source_forms_resolve():
    for text, name in {**KEV_FORMS, **SOURCE_FORMS}.items():
        hit = rules.scope_of(text)
        assert hit is not None and hit.name == name, (text, hit and hit.name)
    kev = {"vulnerabilities": [
        {"cveID": "CVE-2099-0031", "dateAdded": "2099-01-02", "vendorProject": "musistudio",
         "product": "claude-code-router"},
        {"cveID": "CVE-2099-0032", "dateAdded": "2099-01-02", "vendorProject": "Node.js", "product": "Node.js",
         "vulnerabilityName": "Node.js Path Traversal Vulnerability"}]}
    other, runtime = candidates.from_kev(kev, "2099-01-01")
    assert rules.scope_of(other.product_text) is None  # a KEV entry for another vendor's product binds to none
    scope = rules.scope_of(runtime.product_text)
    assert rules.level_for(runtime, scope, False) == ("critical", "kev-tier1")
    assert runtime.source_title == "Node.js Path Traversal Vulnerability"  # CISA's own name for it


def test_vendor_only_text_is_logged_not_matched():
    log: list[str] = []
    for text in ("Python", "Go", "Git", "Rust", "Cursor", "Anthropic"):
        assert rules.scope_of(text, log) is None, text
    assert log == ["Python", "Go", "Git", "Rust", "Cursor", "Anthropic"]


def test_custom_entries_resolve_by_identity_only():
    entries = [schema.ScopeEntry("Widget", "widget", 1, ["acme widget"], authority=("anthropic.com/",),
                                 components=(schema.ScopeComponent("Gadget", ("acme gadget",)),
                                             schema.ScopeComponent("Gizmo", ("acme gizmo",), ())))]
    assert rules.scope_of("Acme Widget", entries=entries).name == "Widget"
    assert rules.scope_of("acme gadget", entries=entries).authority == ("anthropic.com/",)  # the entry's
    assert rules.scope_of("acme gizmo", entries=entries).authority == ()  # its own, empty
    assert rules.scope_of("acme widget pro", entries=entries) is None
    assert rules.scope_of("docker", entries=entries) is None


# ------------------------------------------- authority and evidence (ai-tools-alerts#h340)

CLAUDE = rules.scope_of("claude code")
REPO = "https://github.com/anthropics/claude-code/security/advisories/"
G1, G2 = "GHSA-abcd-efgh-ijkl", "GHSA-mnop-qrst-uvwx"
VENDOR = "https://www.anthropic.com/security/advisory-1"
FIXTURE = (Path(__file__).parent.parent / "fixtures" / "poster" / "advisory-page.html").read_text()


def test_authoritative_is_the_products_own_location():
    for url in (REPO + G1, REPO + G1 + "/", VENDOR, "https://anthropic.com/news/x",
                "https://github.com/Anthropics/Claude-Code/security/advisories/" + G1):
        assert rules.authoritative(url, CLAUDE), url
    for url in ("https://github.com/advisories/" + G1,  # anyone's advisory lands there
                "https://github.com/anthropics/anthropic-sdk-python/security/advisories/" + G1,  # another repository
                "https://github.com/attacker/claude-code-router/security/advisories/" + G1,
                "https://github.com/openai/codex/security/advisories/" + G1,  # another product's vendor
                "https://github.com/anthropics/claude-code/issues/1",  # not an advisory (off the primary list)
                "https://ubuntu.com/security/CVE-2026-0001", KEV_PAGE, "https://www.anthropic.com/",
                "https://anthropic.com.evil.example/security/x", "http://www.anthropic.com/security/x",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0001", None, 42):
        assert not rules.authoritative(url, CLAUDE), url
    assert not rules.authoritative(VENDOR, None)
    assert not rules.authoritative(REPO + G1, rules.scope_of("google chrome"))  # no authority: KEV only


def test_read_advisory_reads_the_labelled_fields_of_a_real_page():
    p = rules.read_advisory(FIXTURE)
    assert (p.ghsa, p.cve, p.severity) == ("GHSA-5j29-h97v-84ch", "CVE-2026-103435", "high")
    assert p.blocks == (rules.Block("@anthropic-ai/claude-code", "npm", "< 2.1.129", "2.1.129"),)
    assert p.title == "Arbitrary File Write via Write-Time Symlink Following (TOCTOU) in Claude Code"
    assert rules.read_advisory(advisory_page(G1, cve="CVE-2026-0007", severity="Critical")) == rules.AdvisoryPage(
        G1, "CVE-2026-0007", (rules.Block("@anthropic-ai/claude-code", "npm", "< 2.1.0", "2.1.0"),), "critical", "A flaw")
    soft = rules.read_advisory(advisory_page(G1, package="Claude Desktop", ecosystem=None))
    assert (soft.blocks[0].name, soft.blocks[0].ecosystem, soft.cve) == ("Claude Desktop", "", None)


def test_read_advisory_takes_nothing_from_the_description_or_an_unknown_shape():
    # Text in the description cannot stand in for a field: blocks and the id are read before it,
    # and the page's own CVE ID and Severity come after it.
    spoof = ("</p><h2>Package</h2><span>@anthropic-ai/claude-code</span><span>(npm)</span><h2>Affected versions</h2>"
             "<div>&lt; 99.0.0</div><h2>Patched versions</h2><div>99.0.0</div><h3>CVE ID</h3><div>CVE-2026-9999</div><p>")
    page = advisory_page(G1, package="some-other-package", cve="CVE-2026-0007").replace("Details.", spoof)
    p = rules.read_advisory(page)
    assert [b.name for b in p.blocks] == ["some-other-package"] and p.cve == "CVE-2026-0007"
    for broken in ("", "<html>plain</html>", advisory_page(G1).replace("Description", "Details"),
                   advisory_page(G1).replace(G1, "an advisory"), advisory_page(G1).replace("Affected versions", "Versions"),
                   None, 42):
        assert rules.read_advisory(broken) is None
    assert rules.read_advisory(advisory_page(G1).replace("· Advisory ·", "|")).title is None
    assert rules.read_advisory(advisory_page(G1, severity="Spicy")).severity is None


def served(pages):
    calls = []

    def page(url, allow):
        calls.append(url)
        assert allow(url)
        return pages.get(url, (404, ""))
    page.calls = calls
    return page


def ghsa_cand(**kw):
    kw.setdefault("id", G1)
    kw.setdefault("product_text", "claude-code")
    kw.setdefault("sources", (Source(REPO + G1, None),))
    return cand(**kw)


def test_kev_is_evidence_without_a_fetch():
    page = served({})
    ev = rules.evidence(cand(exploited=True), CLAUDE, page)
    assert ev.ok and ev.kev and ev.url is None and ev.ids == {"cve-2026-0001"} and page.calls == []
    assert (ev.fixed, ev.affected, ev.title, ev.severity) == (None, None, None, None)
    # The KEV page is evidence for no candidate that KEV did not produce.
    assert not rules.evidence(cand(), CLAUDE, page).ok and page.calls == []
    assert not rules.evidence(cand(id="GHSA-abcd-efgh-ijkl", exploited=True), CLAUDE, page).ok  # KEV lists CVEs


def test_the_vendors_own_advisory_page_is_evidence_and_the_fields_are_its():
    page = served({REPO + G1: (200, advisory_page(G1, cve="CVE-2026-0007", affected="< 2.1.251", patched="2.1.251",
                                                    title="TOCTOU race in the Edit tool"))})
    # The record's own fixed version, range and severity are never read.
    c = ghsa_cand(fixed="99.0.0", affected="<99.0.0", advisory_severity="critical", aliases=("CVE-2026-0007",))
    ev = rules.evidence(c, CLAUDE, page)
    assert ev.ok and not ev.kev and ev.url == REPO + G1 and ev.ids == {G1.lower(), "cve-2026-0007"}
    assert (ev.fixed, ev.affected, ev.title, ev.severity) == ("2.1.251", "<2.1.251", "TOCTOU race in the Edit tool", "high")
    # A candidate that carries only the CVE is confirmed by the page's CVE ID field.
    by_cve = rules.evidence(ghsa_cand(id="CVE-2026-0007:claude-code"), CLAUDE, page)
    assert by_cve.url == REPO + G1 and G1.lower() in by_cve.ids
    assert rules.evidence(ghsa_cand(id="CVE-2026-0008"), CLAUDE, page).ok is False  # not this page's CVE


def test_a_vendor_page_for_another_advisory_or_another_package_confirms_nothing():
    other = advisory_page(G2, cve="CVE-2026-0009")
    # Attacker advisory A (G1) citing the vendor's page for B (G2), with B as an alias.
    a = ghsa_cand(aliases=(G2, "CVE-2026-0009"), sources=(Source(REPO + G2, None),))
    assert not rules.evidence(a, CLAUDE, served({REPO + G2: (200, other)})).ok
    # The URL names one advisory and the page is another's: not parsed as that advisory.
    swapped = rules.evidence(ghsa_cand(), CLAUDE, served({REPO + G1: (200, other)}))
    assert not swapped.ok and swapped.unparsed and swapped.retry
    # An advisory in the product's repository about another package (Claude Desktop).
    for pkg, eco in (("Claude Desktop", None), ("Claude Desktop", "anthropic"), ("claude-code-router", "npm"),
                     ("claude-code", "pip")):
        page = served({REPO + G1: (200, advisory_page(G1, package=pkg, ecosystem=eco))})
        assert not rules.evidence(ghsa_cand(), CLAUDE, page).ok, (pkg, eco)
    # "Software: Claude Code" with no registry is the product by name.
    assert rules.evidence(ghsa_cand(), CLAUDE, served({REPO + G1: (200, advisory_page(G1, package="Claude Code",
                                                                                      ecosystem=None))})).ok


def test_only_the_products_own_sources_are_fetched():
    urls = ("https://github.com/advisories/" + G1, "https://github.com/attacker/claude-code-router/security/advisories/" + G1,
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0001", KEV_PAGE, "https://www.anthropic.com/")
    page = served({u: (200, advisory_page(G1)) for u in urls})
    assert not rules.evidence(ghsa_cand(sources=tuple(Source(u, None) for u in urls)), CLAUDE, page).ok
    assert page.calls == []
    assert not rules.evidence(ghsa_cand(id="LEAD-1"), CLAUDE, page).ok and page.calls == []  # not an advisory id
    # Every source an adapter keeps is read; past that, the unread ones make it a retry, never a "no".
    many = tuple(Source(f"https://www.anthropic.com/security/{i}", None) for i in range(rules.MAX_PAGES + 2))
    ev = rules.evidence(ghsa_cand(sources=many), CLAUDE, page)
    assert not ev.ok and ev.retry and ev.budget and len(page.calls) == rules.MAX_PAGES == candidates.MAX_SOURCES
    assert not rules.evidence(ghsa_cand(sources=many[:3]), CLAUDE, served({})).retry  # all read, all said no


def test_fixed_is_the_highest_patched_version_and_the_range_needs_one_block():
    def ev(**kw):
        return rules.evidence(ghsa_cand(fixed="2.0", affected="<2.0"), CLAUDE,
                              served({REPO + G1: (200, advisory_page(G1, **kw))}))
    # "Affects 1.0 to 2.0, fixed in 3.0": a record saying fixed 2.0 changes nothing.
    one = ev(affected=">= 1.0, <= 2.0", patched="3.0")
    assert (one.fixed, one.affected) == ("3.0", ">=1.0,<=2.0")
    assert ev(patched="1.2.9, 2.1.251").fixed == "2.1.251"
    two = ev(blocks=[("@anthropic-ai/claude-code", "npm", "< 1.2.9", "1.2.9"),
                     ("claude code", None, "< 2.1.251", "v2.1.251"),
                     ("Claude Desktop", "anthropic", "< 9.0", "9.0")])  # the third is another product
    assert (two.fixed, two.affected) == ("2.1.251", rules.UNEXPRESSED)  # dmmf: ranges stated, none carried
    # One of the product's packages fixed in 1.9.0, another (2.x) with no patch: no version is safe for all.
    mixed = ev(blocks=[("@anthropic-ai/claude-code", "npm", "< 1.9.0", "1.9.0"), ("claude code", None, ">= 2.0.0", "None")])
    assert (mixed.fixed, mixed.affected) == (None, rules.UNEXPRESSED)
    assert ev(affected=">= 1.0 || < 0.5").affected == rules.UNEXPRESSED  # dmmf: a range the schema cannot say
    for patched in ("None", "none", ""):  # the vendor states no fix
        assert ev(patched=patched).fixed is None, patched
    for patched in ("2.1.x", "see release notes", "2.1.251 or 3.0.0-beta+1", "2.0.0-rc.1", ">= 2.1.251"):
        got = ev(patched=patched).fixed  # a fix the schema cannot carry: said to exist, never named
        assert got == rules.UNEXPRESSED and compose.schema_fixed(got) is None, patched
    for affected in ("*", "all versions", "2.1.0"):  # dmmf: stated, not carried: "see the source"
        assert ev(affected=affected).affected == rules.UNEXPRESSED, affected
    assert ev(affected="").affected is None  # an empty field states no range


def test_a_vendor_site_page_needs_the_id_and_the_product_name_and_gives_no_fields():
    c = cand(product_text="claude code", sources=(Source(VENDOR, None),), fixed="99.0.0", affected="<99.0.0")
    ok = rules.evidence(c, CLAUDE, served({VENDOR: (200, "<title>Notes</title> CVE-2026-0001 affects Claude Code.")}))
    assert ok.ok and ok.url == VENDOR and ok.ids == {"cve-2026-0001"}
    assert (ok.fixed, ok.affected, ok.title, ok.severity) == (None, None, None, None)
    for text in ("CVE-2026-00010 affects Claude Code.", "CVE-2026-0001 affects Claude Desktop.",
                 "xCVE-2026-0001 in claude codex", ""):
        assert not rules.evidence(c, CLAUDE, served({VENDOR: (200, text)})).ok, text
    # A repository page wins over a site page for the fields.
    both = cand(id="CVE-2026-0007", product_text="claude code", sources=(Source(VENDOR, None), Source(REPO + G1, None)))
    ev = rules.evidence(both, CLAUDE, served({VENDOR: (200, "CVE-2026-0007 claude code"),
                                              REPO + G1: (200, advisory_page(G1, cve="CVE-2026-0007"))}))
    assert ev.url == REPO + G1 and ev.fixed == "2.1.0"


def test_a_site_page_reads_visible_text_only_and_never_a_url_with_a_query():
    c = cand(product_text="claude code", sources=(Source(VENDOR, None),))
    for text in ("CVE-2026-0001: <b>Claude</b>\n   Code", "CVE-2026-0001 Claude&nbsp;Code"):
        assert rules.evidence(c, CLAUDE, served({VENDOR: (200, text)})).ok, text
    for text in ('<a href="/x/CVE-2026-0001">Claude Code</a>', "<script>var a='CVE-2026-0001 claude code'</script>"):
        assert not rules.evidence(c, CLAUDE, served({VENDOR: (200, text)})).ok, text
    q = VENDOR + "?q=CVE-2026-0001+claude+code"
    page = served({q: (200, "CVE-2026-0001 claude code")})
    assert not rules.evidence(cand(product_text="claude code", sources=(Source(q, None),)), CLAUDE, page).ok
    assert page.calls == []
    # No version is read from a site page: an Apple page names one branch's release, not the fix for all.
    mac, url = rules.scope_of("macos"), "https://support.apple.com/en-us/120001"
    apple = "<title>About the security content of macOS Ventura 13.7.8 - Apple Support</title> CVE-2026-5000 macOS"
    ev = rules.evidence(cand(id="CVE-2026-5000", product_text="macOS", sources=(Source(url, None),)), mac, served({url: (200, apple)}))
    assert ev.ok and ev.fixed is None and not ev.structured


def test_the_vendors_page_for_the_id_naming_another_package_is_told_apart():
    page = served({REPO + G1: (200, advisory_page(G1, package="Claude Desktop", ecosystem="anthropic"))})
    ev = rules.evidence(ghsa_cand(), CLAUDE, page)
    assert not ev.ok and ev.other_package and not ev.retry
    assert not rules.evidence(ghsa_cand(id=G2), CLAUDE, page).other_package  # not this page's id at all


def test_a_failed_fetch_or_an_unparsed_page_asks_for_a_retry():
    for status in (0, 403, 408, 429, 500, 503, "200", None):
        ev = rules.evidence(ghsa_cand(), CLAUDE, served({REPO + G1: (status, "")}))
        assert not ev.ok and ev.retry and not ev.unparsed, status
    for status in (404, 410, 451):
        ev = rules.evidence(ghsa_cand(), CLAUDE, served({REPO + G1: (status, "")}))
        assert not ev.ok and not ev.retry, status
    ev = rules.evidence(ghsa_cand(), CLAUDE, served({REPO + G1: (200, "<html>new markup</html>")}))
    assert not ev.ok and ev.retry and ev.unparsed
    # Once a page confirms, another's failure asks for nothing.
    c = ghsa_cand(sources=(Source(VENDOR, None), Source(REPO + G1, None)))
    ev = rules.evidence(c, CLAUDE, served({VENDOR: (503, ""), REPO + G1: (200, advisory_page(G1))}))
    assert ev.ok and not ev.retry


# ------------------------------------------- the page fetch

class FakeResp:
    def __init__(self, status, body=b"page"):
        self.status, self.body, self.closed, self.asked = status, body, False, None

    def read(self, n=None):
        self.asked = n
        return self.body[:n]

    def close(self):
        self.closed = True


class FakeOpener:
    """Scripted transport: url -> status, or (3xx, Location), or (200, body), or an exception."""

    def __init__(self, script, clock=None, step=4):
        self.script, self.seen, self.made, self.clock, self.step = script, [], [], clock, step

    def open(self, req, timeout):
        assert 0 < timeout <= 10 and req.get_method() == "GET"
        self.seen.append(req.full_url)
        if self.clock:
            self.clock[0] += self.step
        r = self.script[req.full_url]
        if isinstance(r, Exception):
            raise r
        if isinstance(r, tuple) and r[0] != 200:
            fp = FakeResp(r[0])
            self.made.append(fp)
            raise urllib.error.HTTPError(req.full_url, r[0], "redirect", {"Location": r[1]} if r[1] is not None else {}, fp)
        fp = FakeResp(200, r[1]) if isinstance(r, tuple) else FakeResp(r)
        self.made.append(fp)
        if fp.status >= 400:
            raise urllib.error.HTTPError(req.full_url, r, "error", {}, fp)
        return fp

    def all_closed(self):
        return bool(self.made) and all(r.closed for r in self.made)


A = "https://www.cisa.gov/a"
B = "https://www.cisa.gov/b"


def test_http_page_gets_the_body_of_a_200_only():
    o = FakeOpener({A: (200, "Página CVE-2026-0001".encode())})
    assert rules.http_page(A, opener=o) == (200, "Página CVE-2026-0001")
    assert o.seen == [A] and o.all_closed() and o.made[0].asked == rules.MAX_PAGE_BYTES + 1
    # A body over the limit is a failure to retry, never a page cut short and read as whole.
    assert rules.http_page(A, opener=FakeOpener({A: (200, b"x" * (rules.MAX_PAGE_BYTES + 1))})) == (0, "")
    assert rules.http_page(A, opener=FakeOpener({A: (200, b"x" * rules.MAX_PAGE_BYTES)}))[0] == 200
    o = FakeOpener({A: (200, b"\xff\xfe broken utf-8")})
    assert rules.http_page(A, opener=o)[0] == 200  # undecodable bytes are replaced, never raised
    for status in (404, 403, 500):
        o = FakeOpener({A: status})
        assert rules.http_page(A, opener=o) == (status, "") and o.made[0].asked is None and o.all_closed()
    assert rules.http_page(A, opener=FakeOpener({A: OSError("reset")})) == (0, "")
    # A URL the caller's rule does not allow is never requested.
    o = FakeOpener({A: 200})
    assert rules.http_page(A, lambda u: False, opener=o) == (404, "") and o.seen == []
    assert rules.http_page("https://example.com/not-primary", opener=o) == (404, "") and o.seen == []


def test_redirects_are_followed_only_where_allowed():
    o = FakeOpener({A: (301, "/b"), B: (200, b"moved here")})
    assert rules.http_page(A, opener=o) == (200, "moved here")
    assert o.seen == [A, B] and o.all_closed()
    for target in ("https://127.0.0.1/a", "http://www.cisa.gov/a", "https://169.254.169.254/latest",
                   "https://evil.example/a", "//evil.example/a",
                   "https://github.com/someone/x/security/advisories/1",
                   "https://python.org/jobs/1", "file:///etc/passwd", "/", "https://www.cisa.gov"):
        o = FakeOpener({A: (302, target)})
        assert rules.http_page(A, opener=o) == (404, ""), target
        assert o.seen == [A] and o.all_closed(), target  # the target never reaches transport
    assert rules.http_page(A, opener=FakeOpener({A: (302, None)})) == (0, "")
    # The caller's rule decides: a redirect to another product's pages is refused.
    o = FakeOpener({REPO + G1: (302, "https://github.com/openai/codex/security/advisories/" + G1)})
    assert rules.http_page(REPO + G1, lambda u: rules.authoritative(u, CLAUDE), opener=o) == (404, "")
    assert o.seen == [REPO + G1]


def test_redirect_hops_are_bounded():
    o = FakeOpener({A: (302, B), B: (302, A)})
    assert rules.http_page(A, opener=o) == (0, "")
    assert len(o.seen) == rules.MAX_REDIRECTS + 1 and o.all_closed()
    chain = {f"https://www.cisa.gov/{i}": (302, f"https://www.cisa.gov/{i + 1}") for i in range(5)}
    chain["https://www.cisa.gov/5"] = 200
    assert rules.http_page("https://www.cisa.gov/0", opener=FakeOpener(chain))[0] == 200  # exactly 5 hops is fine


def test_http_page_has_one_deadline(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(rules.time, "monotonic", lambda: clock[0])
    o = FakeOpener({A: (302, B), B: (302, A)}, clock=clock)  # each request takes 4 s
    assert rules.http_page(A, opener=o) == (0, "")
    assert len(o.seen) == 3  # 0 s, 4 s, 8 s; nothing starts at 12 s
    clock[0] = 2000.0
    o = FakeOpener({A: 200}, clock=clock, step=11)  # answers 200 after 11 s
    assert rules.http_page(A, opener=o) == (0, "") and o.all_closed()


def test_hung_transport_is_cut_at_the_deadline():
    release = threading.Event()

    class Hung:
        def open(self, req, timeout):
            release.wait(5)  # a server that never answers within the socket timeout
            return FakeResp(200)

    t0 = time.monotonic()
    try:
        assert rules.http_page(A, timeout=0.2, opener=Hung()) == (0, "")
        assert time.monotonic() - t0 < 2
    finally:
        release.set()


def test_real_opener_does_not_follow_redirects():
    h = rules._NoRedirect()
    req = urllib.request.Request(A, method="GET")
    assert h.redirect_request(req, None, 302, "Found", {}, "https://www.cisa.gov/b") is None
    assert any(isinstance(x, rules._NoRedirect) for x in rules._opener().handlers)
    assert not any(type(x) is urllib.request.HTTPRedirectHandler for x in rules._opener().handlers)


def test_http_page_without_network_is_a_failure_not_a_raise():
    # The conftest blocks sockets; the production fetch reports failure, never raises.
    assert rules.http_page(KEV_PAGE) == (0, "")



# ------------------------------------------- the whole-branch review's findings (h340)

def test_a_trailing_dot_host_is_read_as_the_same_site():
    """github.com. is github.com to every rule: a repository advisory URL spelled with the
    dot is still read as that advisory, never as a plain page that only has to name things."""
    dotted = REPO.replace("github.com/", "github.com./") + G1
    assert rules.host_of(dotted) == rules.host_of("https://WWW.GitHub.com./x") == "github.com"
    assert rules.host_of(None) == rules.host_of("https://[bad") == ""
    wrong_pkg = advisory_page(G1, package="claude-code-router", ecosystem="npm", description="CVE-2026-0001 Claude Code")
    assert not rules.evidence(ghsa_cand(sources=(Source(dotted, None),)), CLAUDE, served({dotted: (200, wrong_pkg)})).ok
    wrong_id = advisory_page(G2, description=f"{G1} Claude Code")
    assert not rules.evidence(ghsa_cand(sources=(Source(dotted, None),)), CLAUDE, served({dotted: (200, wrong_id)})).ok
    assert rules.evidence(ghsa_cand(sources=(Source(dotted, None),)), CLAUDE, served({dotted: (200, advisory_page(G1))})).ok


def test_a_page_without_its_sidebar_is_not_read():
    """A description cannot supply the CVE ID of a page that lost its own: cut short, the
    field renamed, or its value not an id."""
    spoof = "</p><h3>CVE ID</h3><div>CVE-2026-9999</div><h3>Severity</h3><span>Critical</span><p>"
    whole = advisory_page(G1, cve="CVE-2026-0007").replace("Details.", spoof)
    assert rules.read_advisory(whole).cve == "CVE-2026-0007" and rules.read_advisory(whole).severity == "high"
    cut = whole[:whole.index("<h3>Severity</h3><span>High")]  # the first megabyte ended inside the description
    assert "CVE-2026-9999" in cut and rules.read_advisory(cut) is None
    assert rules.read_advisory(cut + "</body></html>") is None or rules.read_advisory(cut + "</body></html>").cve != "CVE-2026-0007"
    # A whole page whose own field was renamed: the description's heading is not GitHub's sidebar heading.
    renamed = whole.replace('class="mb-2 f6">CVE ID</h3>', 'class="mb-2 f6">CVE</h3>')
    assert renamed != whole and "CVE-2026-9999" in renamed and rules.read_advisory(renamed) is None
    for value in ("see below", "CVE-2026-0007 and more", ""):
        assert rules.read_advisory(advisory_page(G1).replace("No known CVE", value)) is None, value
    c = ghsa_cand(id="CVE-2026-9999")
    assert not rules.evidence(c, CLAUDE, served({REPO + G1: (200, cut)})).ok
    assert rules.evidence(c, CLAUDE, served({REPO + G1: (200, cut)})).unparsed


def test_the_run_budget_leaves_what_is_confirmed_standing():
    def spent(url, allow):
        raise rules.PageBudget
    kev = rules.evidence(cand(exploited=True, sources=(Source(KEV_PAGE, None), Source(VENDOR, None))), CLAUDE, spent)
    assert kev.ok and kev.kev and not kev.retry  # a KEV entry never waits on an optional vendor page
    none = rules.evidence(ghsa_cand(), CLAUDE, spent)
    assert not none.ok and none.retry and none.budget
    calls = []

    def one_then_spent(url, allow):
        calls.append(url)
        if len(calls) > 1:
            raise rules.PageBudget
        return 200, "CVE-2026-0001 claude code"
    c = cand(product_text="claude code", sources=(Source(VENDOR, None), Source(VENDOR + "b", None)))
    ev = rules.evidence(c, CLAUDE, one_then_spent)
    assert ev.ok and ev.url == VENDOR and not ev.retry


def test_a_redirect_to_a_url_with_a_query_is_refused():
    seen = []

    def page(url, allow):
        seen.append(url)
        return (200, "CVE-2026-0001 claude code") if allow(VENDOR + "?q=CVE-2026-0001+claude+code") else (404, "")
    c = cand(product_text="claude code", sources=(Source(VENDOR, None),))
    assert not rules.evidence(c, CLAUDE, page).ok and seen == [VENDOR]  # the fetcher's own rule refuses the hop
    o = FakeOpener({VENDOR: (302, VENDOR + "?q=x"), VENDOR + "?q=x": (200, b"CVE-2026-0001 claude code")})
    allow = lambda u: rules.authoritative(u, CLAUDE) and "?" not in u  # noqa: E731
    assert rules.http_page(VENDOR, allow, opener=o) == (404, "") and o.seen == [VENDOR]
