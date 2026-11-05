"""Level rules and scope matching (Task B2)."""

import threading
import time
import urllib.error
import urllib.request

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
        self.status, self.closed = status, False

    def read(self, *a):
        raise AssertionError("a response body was read")

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
        return bool(self.made) and all(r.closed for r in self.made)


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
                   "https://python.org/jobs/1", "file:///etc/passwd", None):
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
    assert {"claude", "codex", "cursor", "docker", "git", "go", "anthropic", "openai"} <= words
    assert "ubuntu" not in words and "macos" not in words


def test_source_is_schema_source():
    assert candidates.Source is schema.Source
