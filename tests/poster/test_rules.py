"""Level rules and scope matching (Task B2)."""

import threading
import time
import urllib.error
import urllib.request
from dataclasses import replace

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import candidates, rules
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
    c = cand(product_text="Ubuntu 24.04 linux kernel", exploited=True)
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
    c = cand(product_text="@anthropic-ai/claude-code npm package", trojanized=True)
    assert level(c, False) == ("high", "unverified")
    assert level(c, True) == ("critical", "trojanized-primary")


def test_injection_exec_needs_fix():
    c = cand(product_text="Cursor IDE", injection_exec=True)
    assert level(c, True) == ("notice", "notice")
    fixed = cand(product_text="Cursor IDE", injection_exec=True, fixed="1.7.4")
    assert level(fixed, True) == ("critical", "injection-exec-fixed")
    assert level(fixed, False) == ("high", "unverified")


def test_scope_match_is_pattern_based():
    assert rules.scope_of("ANTHROPIC CLAUDE CODE").name == "Claude Code"
    assert rules.scope_of("Anthropic Claude Code").tier == 1
    # The first tier-1 hit wins over a tier-2 hit in the same text.
    assert rules.scope_of("Docker Desktop on Ubuntu").name == "Docker"
    # Compatibility characters normalise before matching.
    assert rules.scope_of("Ｄｏｃｋｅｒ Engine").name == "Docker"
    # KEV's vendorProject alone does not match a product pattern, but is logged.
    log: list[str] = []
    assert rules.scope_of("Anthropic", log) is None
    assert rules.scope_of("Anthropic Claude Desktop", log) is None
    assert rules.scope_of("OpenAI ChatGPT Atlas", log) is None
    assert rules.scope_of("acme widget", log) is None
    assert rules.scope_of("Google Antigravity", log) is None
    assert rules.scope_of("Nous Research Psyche", log) is None
    assert rules.scope_of("Gogs server", log) is None  # "go" is a whole token only
    assert rules.scope_of("Digital Signage", log) is None  # "git" is a whole token only
    assert rules.scope_of("anthropic_desktop", log) is None  # "_" splits tokens
    assert log == ["Anthropic", "Anthropic Claude Desktop", "OpenAI ChatGPT Atlas",
                   "Google Antigravity", "Nous Research Psyche", "anthropic_desktop"]
    # Matched text is never logged.
    rules.scope_of("Claude Code", log)
    assert len(log) == 6


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
    assert level(plain) == ("notice", "notice")
    for text in ("High; remote code-execution", "lets an attacker execute arbitrary commands",
                 "\uff32\uff23\uff25 in the inspector"):
        assert level(cand(product_text="Node.js", fixed="22.11.1", advisory_severity=text)) == \
            ("high", "fix-rce-tier1"), text
    nofix = cand(product_text="Node.js", advisory_severity="remote code execution")
    assert level(nofix) == ("notice", "notice")


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


def test_source_ok_needs_primary_and_200():
    calls = []

    def fetch(status_by_url):
        def f(url, timeout):
            calls.append((url, timeout))
            s = status_by_url[url]
            if isinstance(s, Exception):
                raise s
            return s
        return f

    other = "https://example.com/advisory"
    vendor = "https://www.anthropic.com/security/advisory-1"
    assert rules.source_ok(cand(sources=(Source(other, None),)), fetch({other: 200})) is False
    assert calls == []  # a non-primary source is never fetched
    assert rules.source_ok(cand(sources=(Source(vendor, None),)), fetch({vendor: 404})) is False
    assert rules.source_ok(cand(sources=(Source(vendor, None),)), fetch({vendor: 200})) is True
    both = cand(sources=(Source(KEV_PAGE, None), Source(vendor, None)))
    calls.clear()
    assert rules.source_ok(both, fetch({KEV_PAGE: OSError("down"), vendor: 200})) is True
    assert calls == [(KEV_PAGE, 10), (vendor, 10)]
    assert rules.source_ok(cand(sources=()), fetch({})) is False
    # A truthy non-int status is not a 200.
    assert rules.source_ok(cand(sources=(Source(vendor, None),)), fetch({vendor: "200"})) is False


class FakeResp:
    def __init__(self, status):
        self.status, self.closed, self.read_called = status, False, False

    def read(self, *a):
        self.read_called = True  # asserted in the test thread; a raise here would be lost
        return b""

    def close(self):
        self.closed = True


class FakeOpener:
    """Scripted transport: url -> status, or (3xx, Location), or an exception.

    Keys are (method, url) or url. Records requests and every response made.
    """

    def __init__(self, script, clock=None, step=4):
        self.script, self.seen, self.made, self.clock, self.step = script, [], [], clock, step

    def open(self, req, timeout):
        assert 0 < timeout <= 10
        key = (req.get_method(), req.full_url)
        self.seen.append(key)
        if self.clock:
            self.clock[0] += self.step
        r = self.script[key] if key in self.script else self.script[req.full_url]
        if isinstance(r, Exception):
            raise r
        if isinstance(r, tuple):
            code, loc = r
            fp = FakeResp(code)
            self.made.append(fp)
            hdrs = {"Location": loc} if loc is not None else {}
            raise urllib.error.HTTPError(req.full_url, code, "redirect", hdrs, fp)
        fp = FakeResp(r)
        self.made.append(fp)
        if r >= 400:
            raise urllib.error.HTTPError(req.full_url, r, "error", {}, fp)
        return fp

    def all_closed(self):
        return bool(self.made) and all(r.closed and not r.read_called for r in self.made)


A = "https://www.cisa.gov/a"
B = "https://www.cisa.gov/b"


def test_http_status_head_then_get():
    o = FakeOpener({A: 200})
    assert rules.http_status(A, opener=o) == 200
    assert o.seen == [("HEAD", A)] and o.all_closed()
    o = FakeOpener({("HEAD", A): 405, ("GET", A): 200})
    assert rules.http_status(A, opener=o) == 200
    assert o.seen == [("HEAD", A), ("GET", A)] and o.all_closed()
    o = FakeOpener({("HEAD", A): OSError("reset"), ("GET", A): 200})
    assert rules.http_status(A, opener=o) == 200
    assert o.seen == [("HEAD", A), ("GET", A)] and o.all_closed()
    o = FakeOpener({A: 404})
    assert rules.http_status(A, opener=o) == 404
    assert o.all_closed()


def test_redirects_followed_only_to_primary():
    o = FakeOpener({A: (301, "/b"), B: 200})
    assert rules.http_status(A, opener=o) == 200
    assert o.seen == [("HEAD", A), ("HEAD", B)] and o.all_closed()
    for target in ("https://127.0.0.1/a", "http://www.cisa.gov/a", "https://169.254.169.254/latest",
                   "https://evil.example/a", "//evil.example/a",
                   "https://github.com/someone/x/security/advisories/1",
                   "https://python.org/jobs/1", "file:///etc/passwd", "/", "https://www.cisa.gov",
                   None):
        o = FakeOpener({A: (302, target)})
        assert rules.http_status(A, opener=o) == 0, target
        assert all(url == A for _, url in o.seen), target  # the target never reaches transport
        assert o.all_closed(), target


def test_redirect_hops_are_bounded():
    o = FakeOpener({A: (302, B), B: (302, A)})  # alternating between two URLs
    assert rules.http_status(A, opener=o) == 0
    assert len(o.seen) == 2 * (rules.MAX_REDIRECTS + 1)  # HEAD chain, then GET chain
    assert o.all_closed()
    chain = {f"https://www.cisa.gov/{i}": (302, f"https://www.cisa.gov/{i + 1}") for i in range(5)}
    chain["https://www.cisa.gov/5"] = 200
    o = FakeOpener(chain)
    assert rules.http_status("https://www.cisa.gov/0", opener=o) == 200  # exactly 5 hops is fine
    assert o.all_closed()


def test_http_status_has_one_deadline(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(rules.time, "monotonic", lambda: clock[0])
    o = FakeOpener({A: (302, B), B: (302, A)}, clock=clock)  # each request takes 4 s
    assert rules.http_status(A, opener=o) == 0
    assert len(o.seen) == 3  # 0 s, 4 s, 8 s; nothing starts at 12 s, GET included


def test_late_200_does_not_count(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(rules.time, "monotonic", lambda: clock[0])
    o = FakeOpener({A: 200}, clock=clock, step=11)  # HEAD answers 200 after 11 s
    assert rules.http_status(A, opener=o) == 0
    assert o.all_closed()
    clock[0] = 2000.0
    o = FakeOpener({("HEAD", A): 405, ("GET", A): 200}, clock=clock, step=6)  # GET ends at 12 s
    assert rules.http_status(A, opener=o) == 0
    assert o.seen == [("HEAD", A), ("GET", A)]


def test_hung_transport_is_cut_at_the_deadline():
    release = threading.Event()

    class Hung:
        def open(self, req, timeout):
            release.wait(5)  # a server that never answers within the socket timeout
            return FakeResp(200)

    t0 = time.monotonic()
    try:
        assert rules.http_status(A, timeout=0.2, opener=Hung()) == 0
        assert time.monotonic() - t0 < 2
    finally:
        release.set()


def test_source_ok_skips_root_pages():
    seen = []

    def fetch(url, timeout):
        seen.append(url)
        return 200

    for root in ("https://www.anthropic.com/", "https://www.anthropic.com", "https://www.cisa.gov/?q=1"):
        assert rules.source_ok(cand(sources=(Source(root, None),)), fetch) is False, root
    assert seen == []


def test_real_opener_does_not_follow_redirects():
    h = rules._NoRedirect()
    req = urllib.request.Request(A, method="HEAD")
    assert h.redirect_request(req, None, 302, "Found", {}, "https://www.cisa.gov/b") is None
    assert any(isinstance(x, rules._NoRedirect) for x in rules._opener().handlers)
    assert not any(type(x) is urllib.request.HTTPRedirectHandler for x in rules._opener().handlers)


def test_http_status_without_network_is_zero():
    # The conftest blocks sockets; the production fetch reports failure, never raises.
    assert rules.http_status("https://www.cisa.gov/known-exploited-vulnerabilities-catalog") == 0
    assert rules.http_status("https://example.com/not-primary") == 0


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


# ------------------------------------------- bounded matching (ai-tools-alerts#x838)

def test_short_pattern_does_not_match_inside_another_word():
    assert rules.scope_of("Shopify skills.shopify") is None
    assert rules.scope_of("dockerfile-x") is None
    assert rules.scope_of("Chromebook firmware") is None
    assert rules.scope_of("openclawd") is None
    # A bounded occurrence still matches, wherever it sits in the text.
    assert rules.scope_of("skills.sh registry").name == "skills.sh"
    assert rules.scope_of("skills.shopify and skills.sh").name == "skills.sh"
    assert rules.scope_of("docker-compose").name == "Docker"
    assert rules.scope_of("Docker Desktop").name == "Docker"
    assert rules.scope_of("docker_sdk").name == "Docker"  # "_" separates, as in _tokens
    # A version glued to a name that ends in a letter still matches.
    for text, name in (("OpenSSH9.8p1", "OpenSSH"), ("CPython3.12", "Python"),
                       ("Debian12", "Debian"), ("Docker2", "Docker")):
        hit = rules.scope_of(text)
        assert hit is not None and hit.name == name, (text, hit and hit.name)
    # Whitespace runs and Unicode dashes normalise before matching.
    for text in ("Claude  Code", "claude\u2011code", "claude\u2013code", "Claude\tCode"):
        assert rules.scope_of(text).name == "Claude Code", text
    # The left edge is bounded too: a letter or digit before the pattern.
    for text in ("notdocker", "2docker", "\u00e9docker", "\u30c9docker", "xopenssh", "mycpython"):
        assert rules.scope_of(text) is None, text
    assert rules.scope_of("foo_docker").name == "Docker"
    assert rules.scope_of("notdocker, then docker").name == "Docker"  # a later bounded hit counts
    # One plural "s" at a word-final edge, no more.
    for text, name in (("MCP servers", "MCP servers and clients"),
                       ("MCP servers and clients", "MCP servers and clients"),
                       ("Model Context Protocol clients", "MCP servers and clients"),
                       ("Agent Skills", "ClawHub and skills.sh"),
                       ("Claude skills", "ClawHub and skills.sh"),
                       ("git clients", "git"), ("Rust toolchains", "Rust")):
        hit = rules.scope_of(text)
        assert hit is not None and hit.name == name, (text, hit and hit.name)
    assert rules.scope_of("dockerss") is None


def test_codex_cli_slug_matches_codex():
    for text in ("openai/codex-cli", "codex-cli", "openai/codex", "@openai/codex",
                 "OpenAI Codex CLI"):
        assert rules.scope_of(text).name == "Codex", text


def test_every_pattern_resolves_to_its_own_entry():
    entries = schema.load_scope()
    assert entries and all(e.match_mode == "word" for e in entries)
    for e in entries:
        for owner, patterns in [(e.name, e.match)] + [(c.name, c.match) for c in e.components]:
            for m in patterns:
                hit = rules.scope_of(m)
                assert hit is not None and hit.name == owner, (m, owner, hit and hit.name)


# GitHub repository slugs and advisory package names the sources use (2026-11-05).
SOURCE_FORMS = {
    "anthropics/claude-code": "Claude Code",
    "@anthropic-ai/claude-code": "Claude Code",
    "openai/codex": "Codex",
    "npm:@openai/codex": "Codex",
    "cursor/cursor": "Cursor",
    "Cursor CLI": "Cursor",
    "google-gemini/gemini-cli": "Gemini CLI",
    "@google/gemini-cli": "Gemini CLI",
    "NousResearch/hermes-agent": "Hermes",
    "openclaw/openclaw": "OpenClaw",
    "@openclaw/discord": "OpenClaw",
    "modelcontextprotocol/servers": "MCP servers and clients",
    "@modelcontextprotocol/server-filesystem": "MCP servers and clients",
    "@modelcontextprotocol/sdk": "MCP TypeScript SDK",
    "mcp-server-fetch": "MCP servers and clients",
    "nodejs/node": "Node.js",
    "python/cpython": "Python",
    "golang/go": "Go",
    "golang.org/x/crypto": "Go",
    "rust-lang/rust": "Rust",
    "moby/moby": "Docker",
    "Moby (aka Docker CE, Docker Engine)": "Docker",
    "github.com/docker/cli": "Docker",
    "docker-ce": "Docker",
    "opencontainers/runc": "runc",
    "github.com/opencontainers/runc": "runc",
    "getcursor/cursor": "Cursor",
    "cursor-agent": "Cursor",
    "dockerd": "Docker",
    "tailscale/tailscale": "Tailscale",
    "tailscaled": "Tailscale",
    "openssh/openssh-portable": "OpenSSH",
    "git/git": "git",
    "Git Git": "git",  # KEV: vendorProject "Git", product "Git" (CVE-2025-48384)
}


def test_source_slugs_resolve():
    for text, name in SOURCE_FORMS.items():
        hit = rules.scope_of(text)
        assert hit is not None and hit.name == name, (text, hit and hit.name)


def test_vendor_only_text_is_logged_not_matched():
    log: list[str] = []
    for text in ("Python", "Go", "Git", "Rust", "Cursor"):
        assert rules.scope_of(text, log) is None, text
    assert log == ["Python", "Go", "Git", "Rust", "Cursor"]


def _scope_file(tmp_path, top: dict, match=("skills.sh",)):
    import json
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(dict(top, entries=[
        {"name": "Skills", "ecosystem": "skill", "tier": 1, "match": list(match)}])))
    return p


def test_scope_file_versions(tmp_path):
    # Version 4 is the only format read; it defaults to word matching.
    v4 = schema.load_scope(_scope_file(tmp_path, {"version": 4}))
    assert v4[0].match_mode == "word" and v4[0].components == ()
    assert rules.scope_of("skills.shopify", entries=v4) is None
    assert rules.scope_of("skills.sh", entries=v4).name == "Skills"
    v4s = schema.load_scope(_scope_file(tmp_path, {"version": 4, "match_mode": "substring"}))
    assert rules.scope_of("skills.shopify", entries=v4s).name == "Skills"
    # A reader refuses a format it does not know, older ones included.
    for bad in ({}, {"version": 1}, {"version": 2}, {"version": 3}, {"version": 5}, {"version": True},
                {"version": "4"}, {"version": 4.0}, {"version": 4, "match_mode": "regex"},
                {"match_mode": "word"}, {"version": 4, "extra": 1}, {"version": 4, "description": 5}):
        with pytest.raises(ValueError):
            schema.load_scope(_scope_file(tmp_path, bad))


def test_entries_without_a_mode_use_the_word_rule():
    entry = schema.ScopeEntry(name="X", ecosystem="x", tier=1, match=["skills.sh"])
    assert entry.match_mode == "word"
    assert rules.scope_of("skills.shopify", entries=[entry]) is None
    sub = schema.ScopeEntry(name="X", ecosystem="x", tier=1, match=["skills.sh"],
                            match_mode="substring")
    assert rules.scope_of("skills.shopify", entries=[sub]).name == "X"


# ------------------------------------------------ not_match (ai-tools-alerts#3r9h)

# The live KEV catalog's vendorProject/product for CVE-2021-21315, as from_kev joins them.
KEV_NODE_LIBRARY = "Npm package System Information Library for Node.JS"


def test_node_library_is_not_the_node_runtime():
    log: list[str] = []
    assert rules.scope_of(KEV_NODE_LIBRARY, log) is None
    assert log == [KEV_NODE_LIBRARY]  # an exclusion is kept for human review
    for text in ("Node.js Node.js", "nodejs/node", "Node.js", "NodeJS", "Node.js runtime",
                 "Security update for Node.js", "Node.js runtime (npm package manager included)",
                 "Node.js Node.js npm package", "Node.js npm package manager"):
        assert rules.scope_of(text).name == "Node.js", text  # the vendor's own wording survives
    for text in ("Google Chrome Extensions API", "Google Chromium Extensions",
                 "Mozilla Firefox Add-ons Manager", "Apple Safari Extensions", "Security update for Golang"):
        assert rules.scope_of(text) is not None, text


def test_other_not_match_lists():
    for text in ("Jenkins Git client Plugin",
                 "Example library for Golang", "Example Golang library",
                 "Example extension for Chrome", "Example add-on for Firefox"):
        assert rules.scope_of(text) is None, text
    for text, name in (("Git Git", "git"), ("Docker Desktop", "Docker"), ("golang/go", "Go"),
                       ("Docker Engine docker plugin install", "Docker"),
                       ("Google Chromium V8", "Chromium"), ("Mozilla Firefox", "Firefox")):
        assert rules.scope_of(text).name == name, text


def test_every_not_match_pattern_excludes_its_own_entry():
    entries = schema.load_scope()
    assert any(e.not_match for e in entries)
    for e in entries:
        for m in e.not_match:
            hit = rules.scope_of(m)
            assert hit is None or hit.name not in {e.name, *(c.name for c in e.components)}, (m, e.name)


def test_an_excluded_entry_does_not_stop_the_search():
    first = schema.ScopeEntry("A", "a", 1, ["node.js"], not_match=("for node.js",))
    second = schema.ScopeEntry("B", "b", 1, ["library"])
    tier2 = schema.ScopeEntry("C", "c", 2, ["node.js"])
    assert rules.scope_of("a library for node.js", entries=[first, second]).name == "B"
    assert rules.scope_of("tool for node.js", entries=[first, tier2]).name == "C"
    sub = schema.ScopeEntry("S", "s", 1, ["node"], match_mode="substring", not_match=("npm",))
    assert rules.scope_of("nodex", entries=[sub]).name == "S"
    assert rules.scope_of("npmjs nodex", entries=[sub]) is None  # same mode as match


def test_kev_node_library_does_not_post_and_the_runtime_still_does():
    kev = {"vulnerabilities": [
        {"cveID": "CVE-2099-0031", "dateAdded": "2099-01-02", "vendorProject": "Npm package",
         "product": "System Information Library for Node.JS"},
        {"cveID": "CVE-2099-0032", "dateAdded": "2099-01-02", "vendorProject": "Node.js",
         "product": "Node.js"},
        {"cveID": "CVE-2099-0033", "dateAdded": "2099-01-02", "vendorProject": "Node.js",
         "product": "Node.js runtime (npm package manager included)"},
    ]}
    lib, runtime, bundled = candidates.from_kev(kev, "2099-01-01")
    assert rules.scope_of(bundled.product_text).name == "Node.js"
    assert lib.product_text == KEV_NODE_LIBRARY and rules.scope_of(lib.product_text) is None
    scope = rules.scope_of(runtime.product_text)
    assert scope.name == "Node.js" and scope.tier == 1
    assert rules.level_for(runtime, scope, False)[0] == "critical"


def test_scope_file_not_match(tmp_path):
    import json
    p = tmp_path / "scope.json"

    def load(top, **extra):
        p.write_text(json.dumps(dict(top, entries=[
            dict({"name": "N", "ecosystem": "node", "tier": 1, "match": ["node.js"]}, **extra)])))
        return schema.load_scope(p)

    assert load({"version": 4})[0].not_match == ()
    assert load({"version": 4}, not_match=["npm package"])[0].not_match == ("npm package",)
    for top, nm in (({"version": 3}, ["npm package"]), ({}, ["npm package"]),
                    ({"version": 4}, []), ({"version": 4}, "npm package"),
                    ({"version": 4}, ["NPM"]), ({"version": 4}, [" npm"]),
                    ({"version": 4}, [5])):
        with pytest.raises(ValueError):
            load(top, not_match=nm)


# ------------------------------------------------ components (ai-tools-alerts#qme5)

def _components_file(tmp_path, entries):
    import json
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"version": 4, "entries": entries}))
    return p


def test_scope_file_components(tmp_path):
    comp = {"name": "containerd", "match": ["containerd"]}
    own = {"name": "D", "match": ["docker"], "not_match": ["docker plugin x"]}
    base = {"name": "D", "ecosystem": "docker", "tier": 1, "components": [comp, own]}
    [e] = schema.load_scope(_components_file(tmp_path, [base]))
    assert e.match == [] and e.not_match == ()
    assert e.components == (schema.ScopeComponent("containerd", ("containerd",)),
                            schema.ScopeComponent("D", ("docker",), ("docker plugin x",)))
    other = {"name": "O", "ecosystem": "go", "tier": 1, "match": ["golang"]}
    bad_comps = ([{"match": ["x"]}], [{"name": "x", "match": []}], [{"name": "x", "match": ["X"]}],
                 [{"name": "x", "match": ["x"], "extra": 1}], [{"name": "", "match": ["x"]}], [], "x",
                 [comp, comp], [own, own])
    for bad in [[dict(base, components=c)] for c in bad_comps] + [
            [base, dict(other, name="containerd")], [{"name": "N", "ecosystem": "go", "tier": 1}],
            [base, dict(other, components=[{"name": "containerd", "match": ["c2"]}])]]:
        with pytest.raises(ValueError):
            schema.load_scope(_components_file(tmp_path, bad))


def test_scope_of_resolves_components():
    for text, name, eco in (
            ("containerd containerd", "containerd", "docker"), ("Docker runc", "runc", "docker"),
            ("Docker Desktop", "Docker", "docker"), ("containerd shim in Docker Engine", "containerd", "docker"),
            ("@modelcontextprotocol/inspector", "MCP Inspector", "mcp"), ("mcp-remote", "mcp-remote", "mcp"),
            ("Example MCP server", "MCP servers and clients", "mcp"), ("openclaw/clawhub", "ClawHub", "skill"),
            ("skills.sh registry", "skills.sh", "skill"), ("Claude skill", "ClawHub and skills.sh", "skill"),
            ("Ubuntu linux-kernel", "Linux kernel", "linux"), ("Google Chrome", "Chrome", "browser"),
            ("rustup", "rustup", "rust"), ("Rust toolchain", "Rust", "rust")):
        hit = rules.scope_of(text)
        assert hit is not None and (hit.name, hit.ecosystem, hit.components) == (name, eco, ()), text
    assert rules.scope_of("containerd").tier == 1 and rules.scope_of("Ubuntu").tier == 2
    # The entry's not_match still vetoes every component: a third-party product.
    assert rules.scope_of("Example extension for Chrome") is rules.scope_of("Microsoft Edge (Chromium-based)") is None


def test_component_not_match_and_entry_not_match():
    a = schema.ScopeComponent("A", ("alpha",), ("alpha plugin",))
    b = schema.ScopeComponent("B", ("alpha plugin",))
    e = schema.ScopeEntry("E", "e", 1, ["alpha"], not_match=("vendor x",), components=(a, b))
    log: list[str] = []
    assert rules.scope_of("alpha", log, entries=[e]).name == "A"
    assert rules.scope_of("alpha plugin", log, entries=[e]).name == "B"
    assert rules.scope_of("alpha plugin", log, entries=[replace(e, components=(a,))]).name == "E"  # fallback
    assert rules.scope_of("alpha plugin", log, entries=[replace(e, match=[], components=(a,))]) is None
    assert rules.scope_of("alpha by vendor x", log, entries=[e]) is None
    assert log == ["alpha plugin", "alpha by vendor x"]
