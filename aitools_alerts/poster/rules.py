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


def _norm(text: str) -> str:
    """NFKC then lowercase, so compatibility characters cannot dodge a pattern."""
    return unicodedata.normalize("NFKC", text).lower()


def _tokens(text: str) -> set[str]:
    return {t.strip(".") for t in _TOKEN.findall(text)} - {""}


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

    Each entry's ``match`` patterns are lowercase substrings of the normalised
    text. Tier-1 entries are tried first, so a tier-1 hit wins over any tier-2 hit.
    When nothing matches but the text holds a tier-1 vendor word as a whole token,
    the text is appended to ``log`` (a list the caller owns) for human review.
    """
    if not isinstance(product_text, str):
        return None
    text = _norm(product_text).strip()
    if not text:
        return None
    default = entries is None
    entries = _default_entries() if default else tuple(entries)
    for tier in (1, 2):
        for e in entries:
            if _tier(e) == tier and any(m and m in text for m in e.match):
                return e
    if log is not None:
        words = _default_vendor_words() if default else vendor_words(entries)
        if _tokens(text) & words:
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
