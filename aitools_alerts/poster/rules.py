"""Scope identity, authority and the level rule: which candidates post, and how loudly.

The law is docs/plan.md's Global Constraints. A product is resolved by exact
identity only (``scope_of``): never by a word in free text, so a third-party
package cannot resolve to a channel product (h340). A candidate posts only when a
source authoritative for that product says so (``evidence``): the CISA KEV catalog
this run fetched, or a page under the product's own ``authority`` prefixes that
answers 200 and names the advisory's id. Critical fires only by rule and only by a
field: the product is in the channel class and KEV lists the CVE as exploited, or
a reading of a source's own fields gives critical. A catalog or out product is a
notice, unless its entry's channel_if lets a code-execution flaw post at high; an
out product's notice starts nothing (``starts``). A text no entry names does not post.
A critical posts only with a complete action (9kgk): an upgrade to a stated version, or
stop_using for a malicious release a reading confirms; otherwise it posts at
``action_cap`` (high) and is raised when the fix is known. The upstream severity word
never sets a level.

The level table itself is spec/ruleset.json, evaluated by ``aitools_alerts.ruleset``
(s6mt): ``level_for`` takes what the candidate's readings support, and a model's
reading of prose (the trojanized and injection flags, severity text) may raise to
``reading_cap`` and never makes a critical.
"""

from __future__ import annotations

import functools
import html
import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from aitools_alerts import ruleset, schema, versions
from aitools_alerts.poster import compose
from aitools_alerts.poster.candidates import BOT_ID, MAX_SOURCE_TEXT, Candidate

FETCH_TIMEOUT = 10
MAX_REDIRECTS = 5
MAX_PAGES = 8  # authoritative pages fetched for one candidate: every source an adapter keeps
MAX_PAGE_BYTES = 1024 * 1024
USER_AGENT = "aitools-alerts-poster"
_REDIRECTS = frozenset({301, 302, 303, 307, 308})

# Vendors behind channel products whose names do not spell them. Together with the
# first word of each channel entry's name they flag unmatched text for review.
EXTRA_VENDOR_WORDS = frozenset({"anthropic", "openai", "anysphere", "nousresearch", "nous", "google",
                                "mcp", "modelcontextprotocol"})  # wa6n: MCP entries are named by package

# Advisory text that names code execution, credential theft, data loss, or a sandbox or
# approval bypass (9kgk: the design's high consequences, read from prose, never critical).
_SEVERE = re.compile(
    r"code[ -]execution|\brce\b|command[ -](?:execution|injection)|arbitrary (?:code|commands?)"
    r"|(?:attacker|malicious)[- ]controlled code|\bruns (?:a |an |arbitrary )?(?:commands?|programs?|[\w.]*hook)\b"
    r"|credential|token theft|secret exposure|data loss|data exfiltration"
    r"|sandbox (?:escape|bypass)|escapes? the sandbox|bypass(?:es|ed)? (?:the )?(?:sandbox|approval|permission)"
    r"|(?:approval|permission) (?:check |prompt )?bypass|skips? approval|writes?(?: files?)? outside (?:the |its )?(?:workspace|sandbox)",
    re.I,
)
# What a catalog or out entry's channel_if needs from prose: remote code execution, said so.
_REMOTE_CODE = re.compile(r"remote code execution|\brce\b", re.I)
_TOKEN = re.compile(r"(?:[^\W_]|\.)+")


_norm, _class, _index = ruleset.norm, ruleset.class_of, ruleset.index  # one lookup for poster and CLI (s6mt)


def _tokens(text: str) -> set[str]:
    return {t.strip(".") for t in _TOKEN.findall(text)} - {""}


@functools.lru_cache(maxsize=1)
def _default_entries() -> tuple[schema.ScopeEntry, ...]:
    return tuple(schema.load_scope())


def vendor_words(entries) -> set[str]:
    """The first word of each channel entry's name, and of each entry channel_if can
    post, plus EXTRA_VENDOR_WORDS."""
    words = set(EXTRA_VENDOR_WORDS)
    for e in entries:
        if _class(e) == "channel" or getattr(e, "channel_if", None):
            first = _norm(e.name).split()
            if first and first[0].strip("."):
                words.add(first[0].strip("."))
            words |= {w.strip(".") for c in getattr(e, "components", ())
                      for w in _norm(c.name).split()[:1] if w.strip(".")}
    return words


@functools.lru_cache(maxsize=1)
def _default_vendor_words() -> frozenset[str]:
    return frozenset(vendor_words(_default_entries()))


@functools.lru_cache(maxsize=1)
def _default_index() -> dict[str, schema.ScopeEntry]:
    return _index(_default_entries())


def scope_of(product_text, log: list[str] | None = None, entries=None) -> schema.ScopeEntry | None:
    """The scope entry whose identity product_text is, or None when it is out of scope.

    The text is normalised (NFKC, lowercase, Unicode dashes to "-", whitespace runs
    to one space, trimmed) and must then EQUAL one identity of the scope file: a
    product name, a repository slug, a package key ``ecosystem:name`` or KEV's
    "vendor product". Nothing is matched by a word, a prefix or a substring, so
    "claude-code-router" is not Claude Code (h340). A component's identity comes
    back as the entry resolved to it. When nothing matches but the text holds a
    channel vendor word as a whole token, it is appended to ``log`` (a list the
    caller owns) for review; the log decides nothing.
    """
    if not isinstance(product_text, str):
        return None
    text = _norm(product_text).strip()
    if not text:
        return None
    default = entries is None
    entries = _default_entries() if default else tuple(entries)
    hit = (_default_index() if default else _index(entries)).get(text)
    if hit is None and log is not None:
        words = _default_vendor_words() if default else vendor_words(entries)
        if _tokens(text) & words:
            log.append(product_text)
    return hit


def _readings(c) -> list:
    """The candidate's readings as the ruleset takes them: [(source, fields)]."""
    return [(source, json.loads(text)) for source, text in getattr(c, "readings", ())]


def _fields_level(c, scope) -> str:
    """What the candidate's readings alone support for this product (ruleset.NONE..critical)."""
    return ruleset.load().level(_readings(c), scope.name)


def level_for(c: Candidate, scope: schema.ScopeEntry, source_ok: bool) -> tuple[str, str]:
    """(level, reason) for an in-scope candidate, by the Global Constraints.

    The level is the highest of what the candidate's readings support by
    spec/ruleset.json (reason ``fields`` when only they give it), the KEV row's
    level when ``exploited`` is set (carried by a merge or the ledger when this
    run made no reading: no fresh reading lowers nothing), and a reading of prose,
    which is ``high`` at most (s6mt): a flag that made a critical before makes
    ``high`` with reason ``reading``.

    Last, the ruleset's ``action_level`` (9kgk): a critical stands only with the action
    the root post will carry, an upgrade to a stated version or, for a malicious
    release a reading gives critical, stop_using (reason ``stop-using``); otherwise it
    is ``action_cap`` with reason ``no-action``.

    Reasons: kev-tier1, reading, unverified, fix-rce-tier1, fields, stop-using,
    no-action, notice (the names predate scope classes: tier1 is the channel class).
    The upstream severity word alone never raises (9kgk). ``source_ok`` is "a page
    authoritative for this product named this advisory" (``evidence``) and counts only when it is the
    bool True; main admits no candidate without evidence, so every level here rests on one. ``local_level_hint`` is never read: it cannot raise a level.
    """
    if scope is None:
        raise ValueError("out of scope: a text no scope entry names does not post")
    if _class(scope) is None:
        raise ValueError(f"scope class must be channel, catalog or out, got {getattr(scope, 'scope_class', None)!r}")
    rs = ruleset.load()
    level, reason = _prose_level(c, scope, source_ok is True, rs)
    fields = _fields_level(c, scope)
    if rs.rank(fields) > rs.rank(level):
        level, reason = fields, "fields"
    fixed = compose.schema_fixed(c.fixed)
    # a fix the schema cannot say is still a fix: no "stop using" then, so a critical posts at high
    action = ("upgrade", scope.name, fixed) if fixed else None if compose.fix_unexpressed(c) \
        else ("stop_using", scope.name, None)
    held = rs.action_level(level, [action] if action else [], scope.name, fixed, _readings(c))
    if held != level:
        return held, "no-action"
    if not fixed and rs.rank(level) > rs.rank(rs.action_cap):
        return level, "stop-using"
    return level, reason


def _prose_level(c, scope, verified: bool, rs) -> tuple[str, str]:
    """The level by the KEV flag and by readings of prose, each clause as it was before
    s6mt except that none returns a critical for a flag. A catalog or out product is a
    notice, except that one whose entry carries channel_if takes the reading clauses
    of a code-execution flaw (wa6n); the severity word alone never raises it."""
    channel = _class(scope) == "channel"
    if c.exploited is True and channel:  # only candidates.from_kev sets it; the KEV row is mechanical
        return rs.class_level("kev", scope), "kev-tier1"
    # Outside the channel KEV alone is a notice (ruleset): it neither raises nor masks the clauses below.
    if not channel and not getattr(scope, "channel_if", None):
        return "notice", "notice"
    cap = rs.reading_cap  # a reading never makes a critical
    trojanized = c.trojanized is True
    injection = c.injection_exec is True and bool(c.fixed)
    if (trojanized or injection) and channel:  # neither flag says remote code execution: channel only
        return cap, "reading" if verified else "unverified"
    severity = c.advisory_severity
    if c.fixed and isinstance(severity, str) and (_SEVERE if channel else _REMOTE_CODE).search(_norm(severity)):
        return cap, "fix-rce-tier1"
    return "notice", "notice"  # 9kgk: the severity word alone never raises


def evidence_rank(c, scope) -> int:
    """How high the candidate's own structured evidence reaches for this product: its
    readings by the ruleset, and the KEV row when it is marked exploited. Orders the
    members of a fix group (``ledger.merge``), loudest first; prose is not counted.
    The caller passes the candidate with only the readings its own first id's source
    ties (``Run._tied``): one the level would not count must not win the place."""
    rs = ruleset.load()
    level = _fields_level(c, scope)
    if c.exploited is True:
        level = rs.highest(level, rs.class_level("kev", scope))
    # No evidence and a notice's worth are one rank: every post is at least a notice, and
    # only evidence that sets a level above it should move a member ahead of a newer one.
    return rs.rank(rs.highest(level, "notice"))


def basis(c: Candidate, scope: schema.ScopeEntry, level: str) -> str:
    """``fields`` when the level rests on structured source fields: the candidate's
    readings support it, or it is the KEV row's (``exploited``). ``reading`` when it
    rests on a model's reading of prose: a member's CLI cannot recompute it, and
    shows it as unverified by design. A notice needs no support."""
    rs = ruleset.load()
    held = _fields_level(c, scope)
    if c.exploited is True:
        held = rs.highest(held, rs.class_level("kev", scope))
    return "fields" if level == "notice" or rs.rank(held) >= rs.rank(level) else "reading"


@functools.lru_cache(maxsize=1)
def out_names() -> frozenset[str]:
    """The entry and component names of out entries (wa6n)."""
    return frozenset(n for e in _default_entries() if _class(e) == "out"
                     for n in (e.name, *(c.name for c in e.components)))


def starts(scope, level: str) -> bool:
    """Whether a new advisory at ``level`` starts anything for this product: an out
    product's notice starts no thread and is not held for the digest (wa6n)."""
    return not (_class(scope) == "out" and level == "notice")


def reading_text(source: str, fields) -> str | None:
    """The reading's fields (or a function that builds them) as canonical JSON text
    (a frozen Candidate stays hashable), or None when they are not a reading the
    ruleset accepts."""
    try:
        fields = fields() if callable(fields) else fields
        ruleset.load().read(source, fields)
        return ruleset.canonical(fields).decode("utf-8")
    except (ruleset.RulesetError, TypeError, ValueError):  # no value a page states may stop the run
        return None


def ghsa_lookup(ghsa) -> str | None:
    """A GHSA id as the advisory API is asked for it: ``GHSA-`` then lower case."""
    return "GHSA" + ghsa.lower()[4:] if isinstance(ghsa, str) and _GHSA.fullmatch(ghsa) else None


def readings_for(c: Candidate, ev: "Evidence", read=None) -> tuple:
    """The candidate's readings after admission. A ``kev`` reading comes only from
    ``candidates.from_kev``, made from the catalog entry this run read, and is kept
    when the evidence is KEV's; the ``exploited`` flag alone, which a merge and the
    state file carry, never makes one. A ``ghsa`` reading is added when a repository
    advisory page confirmed the candidate and ``read`` (``sources.Reader.read``) gave
    that advisory's response from ``api.github.com/advisories/<id>``: its fields,
    whole, as a member's check builds them (3qyq). The page itself makes no reading:
    it shows no type, CWE or withdrawal. With no read there is none this run."""
    out = [r for r in getattr(c, "readings", ()) if r[0] == "kev" and ev.kev]
    got = read(ghsa_lookup(ev.ghsa)) if read is not None and ev.structured and ev.ghsa else None
    if got is not None and got.source == "ghsa":
        text = reading_text("ghsa", got.fields)
        if text is not None:
            out.append(("ghsa", text))
    return tuple(dict.fromkeys(out))


def claims_for(c: Candidate, scope: schema.ScopeEntry, now: int) -> list[dict]:
    """The claims this run can sign for an admitted candidate: one per reading, its
    level the ruleset's for this product, confirmed and checked now."""
    rs = ruleset.load()
    return [rs.claim(source, fields, scope.name, now, now) for source, fields in _readings(c)]


def _countable(url) -> bool:
    """A primary-source URL that is not the host's root page (which confirms nothing)."""
    return isinstance(url, str) and schema.is_primary(url) and urlsplit(url).path not in ("", "/")


def authoritative(url, scope) -> bool:
    """True when url is this product's own advisory location: on the primary-source
    list, not a root page, and under one of the scope entry's ``authority`` prefixes.
    github.com/advisories/, another owner's repository and a distribution's tracker
    are authoritative for nobody else's product."""
    if scope is None or not _countable(url):
        return False
    loc = (host_of(url) + urlsplit(url).path).lower()
    loc += "" if loc.endswith("/") else "/"
    return any(loc.startswith(p) for p in getattr(scope, "authority", ()))


def host_of(url) -> str:
    """The URL's host as the primary-source list reads it: lowercase, without one
    trailing dot or a leading "www."; "" when there is none. Every rule that asks
    which site a URL is on uses this one reading."""
    try:
        host = urlsplit(url).hostname or ""
    except (ValueError, TypeError, AttributeError):
        return ""
    host = host[:-1] if host.endswith(".") else host
    return host[4:] if host.startswith("www.") else host


def advisory_ids(c) -> set[str]:
    """The candidate's bare CVE and GHSA ids, lowercase (a thread key's slug dropped)."""
    out = set()
    for i in (c.id, *c.aliases):
        m = BOT_ID.fullmatch(i) if isinstance(i, str) else None
        if m:
            out.add(m.group(1).lower())
    return out


# ------------------------------------------------- the vendor's page, read by the poster

_REPO_ADVISORY = re.compile(r"/[^/]+/[^/]+/security/advisories/([^/]+)/?")
_GHSA = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_NOT_TEXT = re.compile(r"(?is)<(script|style|svg)\b.*?</\1\s*>")
_TAG = re.compile(r"<[^>]*>")
_SIDEBAR_CVE = re.compile(r"(?is)<h3\b[^>]*\bdata-view-component=[^>]*>\s*CVE ID\s*</h3>\s*<div\b[^>]*>(.*?)</div>")
_WHOLE = re.compile(r"(?i)</html\s*>\s*$")
_HTML_TITLE = re.compile(r"(?is)<title[^>]*>(.*?)</title\s*>")
# Package registries GitHub names beside a package; any other word there is a vendor label.
_REGISTRIES = frozenset({"npm", "pip", "pypi", "go", "rust", "cargo", "maven", "nuget", "rubygems",
                         "composer", "pub", "swift", "erlang", "actions"})
_SEVERITIES = frozenset({"low", "moderate", "medium", "high", "critical"})
_LABELS = frozenset({"Package", "Software", "Affected versions", "Patched versions"})


@dataclass(frozen=True)
class Block:
    """One "Package" or "Software" block of a repository advisory page."""
    name: str
    ecosystem: str  # "" under the Software label
    affected: str | None
    patched: str | None


@dataclass(frozen=True)
class AdvisoryPage:
    ghsa: str
    cve: str | None
    blocks: tuple[Block, ...]
    severity: str | None
    title: str | None
    description: str | None = None  # c6ak: the advisory's own prose, for the model's wording only


def _lines(text: str) -> list[str]:
    """The page's visible text, one entry per text node, whitespace collapsed."""
    text = _TAG.sub("\n", _NOT_TEXT.sub("\n", text))
    return [x for x in (" ".join(html.unescape(t).split()) for t in text.split("\n")) if x]


def _after(lines, label, want: re.Pattern | None = None) -> str | None:
    """The text node after the LAST node that is exactly ``label`` (the page's own
    field sits after any text of the description); None when there is no such node."""
    i = next((k for k in range(len(lines) - 2, -1, -1) if lines[k] == label), None)
    return None if i is None else lines[i + 1]


def read_advisory(text: str) -> AdvisoryPage | None:
    """The labelled fields GitHub renders on a repository security advisory, or None
    when the page does not have that shape. The id and the package blocks are read
    from the text before the "Description" heading only, so nothing written in a
    description can stand in for them; "CVE ID" and "Severity" are the last nodes
    with those labels, which on a whole page is the sidebar after the description. So
    a page that is not whole (no closing ``</html>``: cut short, or not a page), or
    whose sidebar CVE ID field is missing or is neither a CVE id nor "No known CVE", is
    not read at all: a description cannot supply the id of a page that lost its sidebar.
    Only labels and the text node after each are read."""
    if not isinstance(text, str) or not _WHOLE.search(text):
        return None
    lines = _lines(text)
    if "Description" not in lines:
        return None
    # The CVE ID is read from GitHub's own sidebar heading only: a heading written in a
    # description is rendered without the component attribute, so it can never stand in.
    fields = _SIDEBAR_CVE.findall(text)
    cve = " ".join(html.unescape(_TAG.sub(" ", fields[-1])).split()) if fields else None
    if cve is None or not (_CVE.fullmatch(cve) or cve == "No known CVE"):
        return None
    head = lines[:lines.index("Description")]
    ghsa = next((x for x in head if _GHSA.fullmatch(x)), None)
    blocks = []
    for i, label in enumerate(head):
        if label not in ("Package", "Software"):
            continue
        j = next((k for k in range(i + 2, min(i + 8, len(head))) if head[k] == "Affected versions"), None)
        if j is None:
            continue
        eco = "".join(head[i + 2:j]).strip("() ").lower() if label == "Package" else ""
        k, affected, patched = j + 1, None, None
        if k < len(head) and head[k] not in _LABELS:  # an empty field renders no text node
            affected, k = head[k], k + 1
        if head[k:k + 1] == ["Patched versions"] and k + 1 < len(head) and head[k + 1] not in _LABELS:
            patched = head[k + 1]
        blocks.append(Block(head[i + 1], eco, affected, patched))
    if ghsa is None or not blocks:
        return None
    severity = (_after(lines, "Severity") or "").lower()
    m = _HTML_TITLE.search(text)
    title = " ".join(html.unescape(m.group(1)).split()) if m else ""
    title = title.rsplit(" · Advisory · ", 1)[0] if " · Advisory · " in title else ""
    # c6ak: the description is the text between its heading and the sidebar's last
    # "Severity" label; it words a post and is never read for a field.
    d = lines.index("Description")
    end = max((k for k in range(d + 1, len(lines)) if lines[k] == "Severity"), default=len(lines))
    description = " ".join(lines[d + 1:end])[:MAX_SOURCE_TEXT].strip()
    return AdvisoryPage(ghsa=ghsa, cve=cve if _CVE.fullmatch(cve) else None, blocks=tuple(blocks),
                        severity=severity if severity in _SEVERITIES else None, title=title or None,
                        description=description or None)


def _names(text: str, token: str) -> bool:
    """token as a whole word of lowercase text: CVE-2026-1234 is not in CVE-2026-12345."""
    return re.search(rf"(?<![0-9a-z-]){re.escape(token.lower())}(?![0-9a-z-])", text) is not None


def _is_product(block: Block, scope, entries=None) -> bool:
    """The block's package is this scope's product, by exact identity: the registry
    key ``ecosystem:name`` where GitHub names a registry, else the name alone."""
    key = f"{block.ecosystem}:{block.name}" if block.ecosystem in _REGISTRIES else block.name
    hit = scope_of(key, entries=entries)
    return hit is not None and hit.name == scope.name


UNEXPRESSED = "unexpressed"  # a fix or range the vendor states and the schema cannot carry; never published


def _highest(patched) -> str | None:
    """The highest version over the blocks' "Patched versions": "upgrade to X or later"
    is then true for every branch the vendor patched. None when any block states no fix
    (empty, or "None"). UNEXPRESSED when one states a fix that is not a version the
    schema can express: compose then says a fix is listed and names no version."""
    found = []
    for value in patched:
        tokens = [t for t in re.split(r"[,\s]+", value or "") if t]
        if not tokens or [t.lower() for t in tokens] == ["none"]:
            return None  # one of the product's packages has no fix: no version is safe for all
        fixed = [compose.schema_fixed(t) for t in tokens]
        if None in fixed or any(versions.parse(f) is None for f in fixed):
            return UNEXPRESSED
        found += fixed
    return max(found, key=versions.parse) if found else None


def _stated_patch(patched) -> str | None:
    """A block's "Patched versions" text, or None where it states none (empty, "None")."""
    return patched if patched and patched.strip().lower() != "none" else None


class PageBudget(Exception):
    """The run has fetched its share of pages: the candidate waits for the next run."""


@dataclass(frozen=True)
class Evidence:
    """What authoritative sources state about one candidate. ``kev``: CISA lists it as
    exploited. ``url``: the page that confirmed it, or None. ``ids``: the advisory's
    ids as that source assigns them (lowercase). ``fixed``, ``affected``, ``title``,
    ``severity``: read from the page, never from the candidate. ``retry``: nothing
    confirmed it, and a fetch failed in a way that can pass, a repository page did
    not parse (``unparsed``) or the run's page budget ran out before every source was
    read (``budget``)."""
    kev: bool = False
    url: str | None = None
    ids: frozenset = frozenset()
    fixed: str | None = None
    affected: str | None = None
    title: str | None = None
    severity: str | None = None
    retry: bool = False
    unparsed: bool = False
    budget: bool = False
    structured: bool = False  # confirmed by a repository advisory page's own fields
    ghsa: str | None = None  # that page's GHSA id
    repository: str | None = None  # owner/repo of the page, lowercase
    packages: tuple = ()  # its blocks that are this product: (ecosystem or "", name, affected, patched) as stated
    other_package: bool = False  # the vendor's page for this id names only packages that are not this product
    text: str | None = None  # c6ak: the confirming page's description, for wording only

    @property
    def ok(self) -> bool:
        return self.kev or self.url is not None


def evidence(c: Candidate, scope, page, entries=None) -> Evidence:
    """The authoritative statement behind c, read by fetching c's own sources (h340).

    ``page(url, allow) -> (status, text)``; the production one is ``http_page``
    behind main's per-run cache. When it raises PageBudget the sources not yet read
    stay unread: what is already confirmed stands, and nothing confirmed is a retry. The candidate is a
    pointer: its id (``BOT_ID``; the base is the id without a thread key's slug),
    its product (``scope``) and its URLs. Only a source ``authoritative`` for the
    scope is fetched, at most MAX_PAGES a candidate.

    KEV: ``c.exploited`` and a CVE base id. A repository advisory page confirms c
    when it answers 200, parses (``read_advisory``) as the advisory its URL names,
    c's base id is that advisory's GHSA or CVE ID, and one of its package blocks is
    this product; it then gives the ids, the highest patched version, the range (one
    matching block only; UNEXPRESSED when a matching block states a range the schema
    cannot carry, or several do), the title and the severity word. Any other authoritative
    page (never one with a query string, which a site can echo back) confirms c when
    its visible text names c's base id and the product's name; it gives the base id
    alone, and main rates it a notice. A repository page wins over another page.
    """
    m = BOT_ID.fullmatch(c.id) if isinstance(c.id, str) else None
    if m is None or scope is None:
        return Evidence()
    base = m.group(1).lower()
    kev = c.exploited is True and base.startswith("cve-")
    found: dict = {}
    retry = unparsed = budget = other = False
    rank = fetched = 0
    for s in c.sources:
        u = getattr(s, "url", None)
        if not authoritative(u, scope) or urlsplit(u).query:
            continue
        if rank == 2:
            break
        if fetched >= MAX_PAGES:
            budget = True  # an unread source is not a "no"
            break
        fetched += 1
        try:
            status, text = page(u, lambda x: authoritative(x, scope) and not urlsplit(x).query)
        except PageBudget:
            budget = True
            break
        if type(status) is not int or status != 200 or not isinstance(text, str):
            retry |= type(status) is not int or status in (0, 403, 408, 429) or status >= 500
            continue
        host = host_of(u)
        repo = _REPO_ADVISORY.fullmatch(urlsplit(u).path) if host == "github.com" else None
        if host == "github.com" and repo is None:
            continue  # on github.com only a repository advisory page is read
        if repo:
            p = read_advisory(text)
            if p is None or p.ghsa.lower() != repo.group(1).lower():
                unparsed = True
                continue
            own = {p.ghsa.lower()} | ({p.cve.lower()} if p.cve else set())
            mine = [b for b in p.blocks if _is_product(b, scope, entries)]
            if base not in own or not mine:
                other |= base in own
                continue
            affected = compose.schema_affected(mine[0].affected) if len(mine) == 1 else None
            if affected in (None, "*") and any(b.affected for b in mine):
                affected = UNEXPRESSED  # dmmf: a range is stated, never "all": the post says "see the source"
            rank, found = 2, dict(url=u, ids=own, fixed=_highest(b.patched for b in mine),
                                  affected=affected, title=p.title, text=p.description,
                                  severity=p.severity, ghsa=p.ghsa,
                                  repository="/".join(urlsplit(u).path.split("/")[1:3]).lower(),
                                  packages=tuple((b.ecosystem if b.ecosystem in _REGISTRIES else "", b.name,
                                                  b.affected, _stated_patch(b.patched)) for b in mine))
        elif rank == 0:
            low = " ".join(_lines(text)).lower()  # what a reader sees: no tag, attribute or script
            if not (_names(low, base) and _names(low, scope.name)):
                continue
            rank, found = 1, dict(url=u, ids={base})
    ids = frozenset(found.get("ids", set()) | ({base} if kev else set()))
    return Evidence(kev=kev, url=found.get("url"), ids=ids, fixed=found.get("fixed"),
                    affected=found.get("affected"), title=found.get("title"), text=found.get("text"),
                    severity=found.get("severity"),
                    retry=(retry or unparsed or budget) and not found and not kev,
                    unparsed=unparsed and not found, budget=budget and not found,
                    structured=rank == 2, other_package=other and not found, ghsa=found.get("ghsa"),
                    repository=found.get("repository"), packages=found.get("packages", ()))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect inside urllib: a 3xx surfaces as an HTTPError.

    CPython drains a redirect body before following it and bounds distinct URLs,
    not hops; http_page follows redirects itself instead.
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


def _request(opener, url: str, deadline: float, allow) -> tuple[int, str]:
    """GET url, following redirects only where allow(url); (status, text) or (0, "")."""
    for _hop in range(MAX_REDIRECTS + 1):
        left = deadline - time.monotonic()
        if left <= 0:
            return 0, ""
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
        try:
            resp = opener.open(req, timeout=left)
        except urllib.error.HTTPError as e:
            status, location = e.code, e.headers.get("Location") if e.headers else None
            _close(e)
            if status not in _REDIRECTS:
                return status, ""
            if not isinstance(location, str):
                return 0, ""
            url = urljoin(url, location)
            if not allow(url):
                return 404, ""  # a redirect off the product's own pages: this URL confirms nothing
            continue
        except Exception:  # network, TLS, protocol: a failed fetch, never a crash
            return 0, ""
        status = getattr(resp, "status", 0)
        try:
            raw = resp.read(MAX_PAGE_BYTES + 1) if status == 200 else b""
        except Exception:
            status, raw = 0, b""
        if isinstance(raw, bytes) and len(raw) > MAX_PAGE_BYTES:
            status, raw = 0, b""  # a page cut short is never read as a page
        _close(resp)
        if time.monotonic() > deadline:
            return 0, ""  # an answer after the deadline does not count
        if type(status) is not int or not isinstance(raw, bytes):
            return 0, ""
        return status, raw.decode("utf-8", "replace")
    return 0, ""  # too many hops


def http_page(url: str, allow=_countable, timeout: float = FETCH_TIMEOUT, opener=None) -> tuple[int, str]:
    """(status, text) of a GET; (0, "") on any failure that may pass.

    One wall-clock deadline of ``timeout`` seconds covers DNS, the request, every
    redirect and the read: the fetch runs in a daemon thread and its answer counts
    only if it arrives in time. Refuses (404) a URL ``allow`` does not accept and any
    redirect to one; past MAX_REDIRECTS hops is a failure. A 200 body over
    MAX_PAGE_BYTES is a failure, never a page cut short; no other body is read.
    """
    if not allow(url):
        return 404, ""
    opener = opener or _opener()
    deadline = time.monotonic() + timeout
    result = [(0, "")]

    def run():
        result[0] = _request(opener, url, deadline, allow)

    worker = threading.Thread(target=run, name="aitools-alerts-fetch", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if worker.is_alive() or time.monotonic() > deadline:
        return 0, ""
    return result[0]
