"""Scope matching and the level rule: which candidates post, and how loudly.

The law is docs/plan.md's Global Constraints. Critical fires only by rule: the
product is in scope tier 1 and (KEV lists it as exploited, or a primary source
confirms a trojanized release, or an injection-to-execution path has a fix). The
two clauses a model reads from a source need a primary source that fetched; without
one the advisory is ``high`` and ``unverified``. Tier 2 never posts critical.
Items outside both tiers do not post.
"""

from __future__ import annotations

import functools
import re
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from aitools_alerts import schema
from aitools_alerts.poster.candidates import Candidate

FETCH_TIMEOUT = 10
MAX_REDIRECTS = 5
USER_AGENT = "aitools-alerts-poster"
_REDIRECTS = frozenset({301, 302, 303, 307, 308})

# Vendors behind tier-1 products whose names do not spell them. Together with the
# first word of each tier-1 entry's name they flag unmatched text for review.
EXTRA_VENDOR_WORDS = frozenset({"anthropic", "openai", "anysphere", "nousresearch", "nous", "google"})

# Advisory text that names code execution, credential theft or data loss.
_SEVERE = re.compile(
    r"code[ -]execution|\brce\b|command[ -](?:execution|injection)|arbitrary (?:code|commands?)"
    r"|credential|token theft|secret exposure|data loss|data exfiltration",
    re.I,
)
_TOKEN = re.compile(r"(?:[^\W_]|\.)+")


_DASHES = re.compile("[\u2010-\u2015\u2212]")
_SPACES = re.compile(r"\s+")


def _norm(text: str) -> str:
    """NFKC, lowercase, Unicode dashes to "-", whitespace runs to one space, so
    compatibility characters and spacing cannot dodge a pattern."""
    text = unicodedata.normalize("NFKC", text).lower()
    return _SPACES.sub(" ", _DASHES.sub("-", text))


def _tokens(text: str) -> set[str]:
    return {t.strip(".") for t in _TOKEN.findall(text)} - {""}


_WORD_CHAR = re.compile(r"[^\W_]")  # a letter or digit; "_" separates, as in _TOKEN


@functools.lru_cache(maxsize=1024)
def _word_pattern(pattern: str) -> re.Pattern:
    """pattern, bounded on each edge that is a letter or digit.

    An edge that is punctuation ("@scope/", a trailing "/") needs no boundary, so a
    package-scope prefix still matches every package under it. A word-final edge
    also ends at one plural "s" ("mcp server" matches "MCP servers") or where a
    digit starts a version glued to a name ending in a letter ("openssh9.8p1").
    """
    head = r"(?<![^\W_])" if _WORD_CHAR.match(pattern[:1]) else ""
    tail = ""
    if _WORD_CHAR.match(pattern[-1:]):
        version = r"|(?=\d)" if not pattern[-1].isdigit() else ""
        tail = r"(?:s?(?![^\W_])" + version + ")"
    return re.compile(head + re.escape(pattern) + tail)


def _matches(pattern: str, text: str, mode) -> bool:
    if mode == "substring":
        return pattern in text
    return _word_pattern(pattern).search(text) is not None  # "word", and any unknown mode


@functools.lru_cache(maxsize=1)
def _default_entries() -> tuple[schema.ScopeEntry, ...]:
    return tuple(schema.load_scope())


def _tier(entry) -> int | None:
    t = getattr(entry, "tier", None)
    return t if type(t) is int and t in (1, 2) else None


def vendor_words(entries) -> set[str]:
    """The first word of each tier-1 entry's name, plus EXTRA_VENDOR_WORDS."""
    words = set(EXTRA_VENDOR_WORDS)
    for e in entries:
        if _tier(e) == 1:
            first = _norm(e.name).split()
            if first and first[0].strip("."):
                words.add(first[0].strip("."))
    return words


@functools.lru_cache(maxsize=1)
def _default_vendor_words() -> frozenset[str]:
    return frozenset(vendor_words(_default_entries()))


def scope_of(product_text, log: list[str] | None = None, entries=None) -> schema.ScopeEntry | None:
    """The scope entry for product_text, or None when it is out of scope.

    Each entry's ``match`` patterns are tested against the normalised text by the
    entry's ``match_mode``. "word" (the default): the pattern occurs with no letter
    or digit touching an edge of it that is itself a letter or digit (a plural
    "s" or a glued version number excepted at the end), so "skills.sh" does not
    match "skills.shopify", "mcp server" matches "MCP servers" and "openssh"
    matches "OpenSSH9.8p1". "substring": any occurrence (a
    version-1 scope file). An entry whose ``not_match`` pattern also matches, by
    the same mode, is skipped ("npm package ... for node.js" is not Node.js), and
    the search goes on. Tier-1 entries are tried first, so a tier-1 hit wins over
    any tier-2 hit.
    When nothing matches but the text holds a tier-1 vendor word as a whole token,
    or an entry was skipped by ``not_match``, the text is appended to ``log`` (a
    list the caller owns) for human review.
    """
    if not isinstance(product_text, str):
        return None
    text = _norm(product_text).strip()
    if not text:
        return None
    default = entries is None
    entries = _default_entries() if default else tuple(entries)
    excluded = False
    for tier in (1, 2):
        for e in entries:
            mode = getattr(e, "match_mode", "word")
            if _tier(e) == tier and any(m and _matches(m, text, mode) for m in e.match):
                if not any(m and _matches(m, text, mode) for m in getattr(e, "not_match", ())):
                    return e
                excluded = True
    if log is not None:
        words = _default_vendor_words() if default else vendor_words(entries)
        if excluded or _tokens(text) & words:
            log.append(product_text)
    return None


def level_for(c: Candidate, scope: schema.ScopeEntry, source_ok: bool) -> tuple[str, str]:
    """(level, reason) for an in-scope candidate, by the Global Constraints.

    Reasons: kev-tier1, trojanized-primary, injection-exec-fixed, unverified,
    fix-rce-tier1, kev-tier2, notice. ``source_ok`` counts only when it is the
    bool True. ``local_level_hint`` is never read: it cannot raise a level.
    """
    if scope is None:
        raise ValueError("out of scope: an item outside both tiers does not post")
    tier = _tier(scope)
    if tier is None:
        raise ValueError(f"scope tier must be 1 or 2, got {getattr(scope, 'tier', None)!r}")
    verified = source_ok is True
    exploited = c.exploited is True  # only candidates.from_kev sets it
    if tier == 2:
        return ("high", "kev-tier2") if exploited else ("notice", "notice")
    if exploited:
        return "critical", "kev-tier1"  # the KEV clause is mechanical: no fetch needed
    trojanized = c.trojanized is True
    injection = c.injection_exec is True and bool(c.fixed)
    if trojanized or injection:
        if not verified:
            return "high", "unverified"
        return ("critical", "trojanized-primary") if trojanized else ("critical", "injection-exec-fixed")
    severity = c.advisory_severity
    if c.fixed and isinstance(severity, str) and _SEVERE.search(_norm(severity)):
        return "high", "fix-rce-tier1"
    return "notice", "notice"


def _countable(url) -> bool:
    """A primary-source URL that is not the host's root page (which confirms nothing)."""
    return isinstance(url, str) and schema.is_primary(url) and urlsplit(url).path not in ("", "/")


def source_ok(c: Candidate, fetch) -> bool:
    """True when at least one source is a primary source and fetches with 200.

    ``fetch(url, timeout) -> int`` is the HTTP status; the production one is
    ``http_status``. Non-primary sources and a host's root page (which confirms
    nothing) are never fetched. An exception from ``fetch`` fails that source only.
    """
    for s in c.sources:
        url = getattr(s, "url", None)
        if not _countable(url):
            continue
        try:
            status = fetch(url, FETCH_TIMEOUT)
        except Exception:
            continue
        if type(status) is int and status == 200:
            return True
    return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect inside urllib: a 3xx surfaces as an HTTPError.

    CPython drains a redirect body before following it and bounds distinct URLs,
    not hops; http_status follows redirects itself instead.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    return urllib.request.build_opener(_NoRedirect)


def _close(obj) -> None:
    try:
        obj.close()
    except Exception:
        pass


def _request(opener, method: str, url: str, deadline: float) -> int:
    """One method against url, following primary-only redirects; status or 0."""
    for _hop in range(MAX_REDIRECTS + 1):
        left = deadline - time.monotonic()
        if left <= 0:
            return 0
        req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
        try:
            resp = opener.open(req, timeout=left)
        except urllib.error.HTTPError as e:
            status, location = e.code, e.headers.get("Location") if e.headers else None
            _close(e)
            if status not in _REDIRECTS:
                return status
            if not isinstance(location, str):
                return 0
            url = urljoin(url, location)
            if not _countable(url):
                return 0  # a redirect off the primary-source list, or to a root page, is refused
            continue
        except Exception:  # network, TLS, protocol: a failed fetch, never a crash
            return 0
        status = getattr(resp, "status", 0)
        _close(resp)  # the body is never read
        if time.monotonic() > deadline:
            return 0  # an answer after the deadline does not count
        return status if type(status) is int else 0
    return 0  # too many hops


def http_status(url: str, timeout: float = FETCH_TIMEOUT, opener=None) -> int:
    """HEAD, then GET on a non-200; the final status, or 0 on any failure.

    One wall-clock deadline of ``timeout`` seconds covers DNS, both methods and
    every redirect: the fetch runs in a daemon thread and its answer counts only
    if it arrives in time. Refuses (0) a URL that is not a primary source or is
    a root page, and any redirect to such a URL or past MAX_REDIRECTS hops. Bodies are never read.
    """
    if not _countable(url):
        return 0
    opener = opener or _opener()
    deadline = time.monotonic() + timeout
    result = [0]

    def run():
        status = 0
        for method in ("HEAD", "GET"):
            status = _request(opener, method, url, deadline)
            if status == 200:
                break
        result[0] = status

    worker = threading.Thread(target=run, name="aitools-alerts-fetch", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if worker.is_alive() or time.monotonic() > deadline:
        return 0
    return result[0]
