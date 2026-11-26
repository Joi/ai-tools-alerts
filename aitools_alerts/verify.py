"""The member's own check of an alert against its primary source (fv4g).

Three endpoints, fixed here, and no other URL: the CISA KEV file,
``api.github.com/advisories/<GHSA id>`` and ``api.osv.dev/v1/vulns/<id>``.
The id comes from the thread's advisory id and aliases and enters a URL only
after ``norm_id`` accepted it (``ruleset.source_of`` names its source). No
URL, title or other text of an event is ever requested.

Every product of a relay-bot thread gets one of three results. ``confirmed``
and ``contradicted`` rest only on bodies that came with status 200, arrived
whole, parsed strictly and passed ``Ruleset.read``. If any read a thread
needs fails (a timeout, a redirect, 403, 404, 429, 5xx, a body cut short, a
parse error, a size overrun), every product of it is ``unknown``. This module
changes no level: it reports. ``lowering`` is the answer the reader applies to a
published lowering or retraction (ai-tools-alerts#c1g2, ``pull.standing``), and
``claimed`` tells a level that rests on the first id's fields from one that may rest
on a reading (ai-tools-alerts#tavj). ``narrowing`` is the answer to a published narrowing of
products, range or fixed version (ai-tools-alerts#swfe).

Nothing a response says is printed. What is stored from one: levels and
booleans the ruleset computed, an ETag of an ETag's shape, the ids the
response names, each only in the exact form of a CVE, GHSA or MAL id, and the
version ranges and first patched versions a GitHub advisory states for a scope
product, each only when ``versions`` reads it (``_pair``). A run makes at most MAX_FETCHES
requests in at most RUN_SECONDS, each bounded as a whole by a worker thread.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import threading
import time
from dataclasses import dataclass, fields
from pathlib import Path
from urllib.parse import quote, urlsplit

from . import check, ruleset, schema, versions
from .state import write_json

__all__ = ["KEV_URL", "HOSTS", "LIMITS", "TIMEOUT", "MAX_FETCHES", "RUN_SECONDS", "FILE", "BOT",
           "norm_id", "url_of", "default_fetch", "state_key", "judge", "summary", "load", "run",
           "result_for", "at_level", "lowering", "claimed", "Asked", "pkey", "scope_of", "narrowing"]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_GHSA_URL = "https://api.github.com/advisories/"
_OSV_URL = "https://api.osv.dev/v1/vulns/"
HOSTS = frozenset({"www.cisa.gov", "api.github.com", "api.osv.dev"})
LIMITS = {"kev": 8 << 20, "ghsa": 256 << 10, "osv": 256 << 10}
TIMEOUT = 10.0  # one request, from the call to the last byte
MAX_FETCHES = 10  # per run
RUN_SECONDS = 30.0
MAX_ALIASES = 3  # aliases of one thread that are read
MAX_NAMES = 50  # ids one response may name; more is a failed read
MAX_CACHE_BYTES = 16 << 20
# The most version ranges one product of one thread can have: a thread counts its first id
# and at most MAX_ALIASES more, and one reading holds at most ruleset.MAX_PACKAGES entries.
# Nothing is ever cut to it: it is only what a cache this reader wrote cannot pass.
MAX_PAIRS = (MAX_ALIASES + 1) * ruleset.MAX_PACKAGES
FILE = "verify.json"
VERSION = 5  # of the cache: raised whenever a stored value changes meaning, so nothing older is reused
BOT = "relay-bot"
CONFIRMED, CONTRADICTED, UNKNOWN = "confirmed", "contradicted", "unknown"
_WHYS = {CONFIRMED: ("match", "withdrawn"), CONTRADICTED: ("unsupported", "above-source", "below-source"),
         UNKNOWN: ("unread", "unauthoritative", "reading", "no-source", "off")}
_LEVELS = (ruleset.NONE, "notice", "high", "critical")
_RANK = {name: i for i, name in enumerate(_LEVELS)}
_ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]{1,128}"')
_HEX = re.compile(r"[0-9a-f]{64}")
_REPO_URL = re.compile(r"https://api\.github\.com/repos/([A-Za-z0-9._-]{1,100})/([A-Za-z0-9._-]{1,100})"
                       r"/security-advisories/(GHSA(?:-[0-9a-z]{4}){3})")
_LEDGER_KEY = re.compile(r"((?:CVE-[0-9]{4}-[0-9]{4,19}|GHSA(?:-[0-9A-Za-z]{4}){3})):[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
                         re.IGNORECASE)
RETRY_S = 86400  # a result that is not "confirmed" is read again after a day
FRESH_S = 2 * RETRY_S  # c1g2: a result older than this confirms no lowering
_CONNECTION = http.client.HTTPSConnection  # tests replace it


# ------------------------------------------------------------------ ids and URLs

def norm_id(text) -> str | None:
    """The id as a lookup uses it, or None: ``CVE-`` in upper case, ``GHSA-``
    then lower case (as the poster writes it), kept only when
    ``ruleset.source_of`` names its source and it is not a synthetic id. A
    thread key of the poster's, ``<CVE or GHSA id>:<scope slug>``, is read as
    its id. Of OSV's ids only ``MAL-`` ones are looked up: the ruleset gives
    no other OSV entry any authority, and an internal key (``LEAD-...``,
    ``AITA-...``) has the same loose shape and must never be sent anywhere."""
    if not isinstance(text, str) or len(text) > 128:
        return None
    key = _LEDGER_KEY.fullmatch(text)
    if key is not None:
        text = key.group(1)
    head = text[:5].upper()
    if head.startswith("CVE-"):
        text = text.upper()
    elif head == "GHSA-":
        text = "GHSA-" + text[5:].lower()
    source = ruleset.source_of(text)
    if source is None or schema.is_synthetic(text) or source == "osv" and not text.startswith("MAL-"):
        return None
    return text


def url_of(lookup_id: str) -> str:
    """The one URL an id is read from. ValueError unless ``norm_id`` returned it."""
    if norm_id(lookup_id) != lookup_id:
        raise ValueError("not a lookup id")
    source = ruleset.source_of(lookup_id)
    if source == "kev":
        return KEV_URL
    return (_GHSA_URL if source == "ghsa" else _OSV_URL) + quote(lookup_id, safe="")


# ------------------------------------------------------------------ the request

def _request(host: str, path: str, etag: str | None, limit: int, timeout: float, held: list, cancelled):
    """One GET inside one deadline. The deadline is checked between the
    phases and before every read, and the socket's timeout is what is left of
    it, so no phase restarts the clock. ``cancelled`` is set by the caller
    when its wait is over: nothing is sent after that."""
    deadline = time.monotonic() + timeout

    def left() -> float:
        rest = deadline - time.monotonic()
        if rest <= 0 or cancelled.is_set():
            raise OSError("out of time")
        if len(held) > 1:
            held[1].settimeout(rest)
        return rest

    conn = _CONNECTION(host, timeout=timeout)
    held.append(conn)
    try:
        headers = {"User-Agent": "aitools-alerts", "Accept": "application/json", "Accept-Encoding": "identity"}
        if etag is not None:
            headers["If-None-Match"] = etag
        conn.connect()  # name lookup, TCP and TLS; the one phase nothing can cut short
        if getattr(conn, "sock", None) is not None:
            # Kept here: http.client forgets the socket (conn.sock is None) once a response
            # that closes the connection takes it over, and the body is still to be read.
            held.append(conn.sock)
        left()  # a lookup that outlived the wait sends nothing
        conn.request("GET", path, headers=headers)
        left()
        r = conn.getresponse()
        left()
        if r.status != 200:
            return r.status, None, b""
        if (r.getheader("Content-Encoding") or "identity").strip().lower() != "identity":
            raise OSError("encoded body")
        chunked = (r.getheader("Transfer-Encoding") or "").strip().lower() == "chunked"
        length = (r.getheader("Content-Length") or "").strip()
        if not chunked and (not length.isascii() or not length.isdigit() or int(length) > limit):
            raise OSError("no usable length")  # nothing says where the body ends, or it is too long
        body = bytearray()
        while piece := r.read(65536):  # a chunk cut short raises in http.client
            body += piece
            if len(body) > limit:
                raise OSError("too large")
            left()
        if not chunked and len(body) != int(length):
            raise OSError("body cut short")  # read(n) returns early at EOF without raising
        return 200, r.getheader("ETag"), bytes(body)
    finally:
        conn.close()


def default_fetch(url: str, etag: str | None, limit: int, timeout: float):
    """(status, ETag header or None, body) of one GET, or OSError. Only
    https to one of the three hosts, no port, no userinfo. No redirect is
    followed (http.client has none) and no proxy variable is read. The whole
    request, name lookup and TLS included, gets ``timeout`` seconds: it runs
    in a daemon thread; when the time is up the thread is told to stop, its
    connection is shut, and it is not waited for (a name lookup cannot be
    interrupted, but nothing is sent once it returns). A 200 body is returned
    only when it arrived whole (see ``_request``). The error never carries
    text from the response."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.netloc not in HOSTS or parts.query or parts.fragment:
        raise OSError("refused URL")
    box: list = []
    held: list = []
    cancelled = threading.Event()

    def go():
        try:
            box.append(_request(parts.netloc, parts.path, etag, limit, timeout, held, cancelled))
        except Exception:  # network, TLS, protocol, framing: a failed read
            box.append(None)

    worker = threading.Thread(target=go, name="aitools-alerts-verify", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        cancelled.set()
        for thing in reversed(list(held)):  # the socket, then the connection: wake a blocked read
            try:
                if thing is not held[0]:
                    thing.shutdown(socket.SHUT_RDWR)
                thing.close()
            except Exception:
                pass
        raise OSError("fetch failed")
    if not box or box[0] is None:
        raise OSError("fetch failed")
    return box[0]


# ------------------------------------------------------------------ typed fields

class _Bad(ValueError):
    """A response that is not what the endpoint's format says."""


def _is(v, kind, nullable=False):
    if v is None and nullable:
        return v
    if type(v) is not kind:
        raise _Bad("wrong type")
    return v


def _strict(body: bytes):
    return json.loads(body.decode("utf-8"), object_pairs_hook=schema._no_duplicates,
                      parse_constant=schema._reject_constant)


def _kev_catalog(catalog) -> dict:
    """{CVE id: [entry, ...]} of a catalog that is whole: a version, and as
    many entries as it says it has, each with its id."""
    _is(catalog, dict)
    _is(catalog.get("catalogVersion"), str)
    items = _is(catalog.get("vulnerabilities"), list)
    if _is(catalog.get("count"), int) != len(items):
        raise _Bad("count")
    out: dict = {}
    for it in items:
        out.setdefault(_is(_is(it, dict).get("cveID"), str), []).append(it)
    return out


def _kev_readings(entries: dict, cve: str) -> list:
    """The readings of one CVE id: one per catalog entry; name null when the
    catalog does not list it."""
    return [{"cve_id": cve, "name": " ".join(x for x in (_is(e.get("vendorProject"), str).strip(),
                                                         _is(e.get("product"), str).strip()) if x)}
            for e in entries.get(cve, [])] or [{"cve_id": cve, "name": None}]


def _ghsa_reading(obj, lookup_id: str):
    """(fields, the ids the response names) of an api.github.com/advisories response."""
    if _is(obj, dict).get("ghsa_id") != lookup_id:
        raise _Bad("another advisory")
    repo = _is(obj.get("repository_advisory_url"), str, True)
    if repo is not None:
        m = _REPO_URL.fullmatch(repo)
        if m is None or m.group(3) != lookup_id:
            raise _Bad("repository_advisory_url")
        repo = f"{m.group(1)}/{m.group(2)}".lower()
    severity = _is(obj.get("severity"), str, True)
    vector = None
    by_version = _is(obj.get("cvss_severities"), dict, True) or {}
    for holder in (by_version.get("cvss_v3"), by_version.get("cvss_v4"), obj.get("cvss")):
        text = _is(_is(holder, dict, True) or {}, dict).get("vector_string")
        if _is(text, str, True) and vector is None:
            vector = text
    packages = []
    for v in _is(obj.get("vulnerabilities"), list, True) or []:
        pkg = _is(_is(v, dict).get("package"), dict)
        packages.append({"ecosystem": _is(pkg.get("ecosystem"), str).lower(), "name": _is(pkg.get("name"), str),
                         "range": _is(v.get("vulnerable_version_range"), str, True) or None,
                         "first_patched": _is(v.get("first_patched_version"), str, True) or None})
    fields = {"ghsa_id": lookup_id, "type": _is(obj.get("type"), str, True),
              "withdrawn_at": _is(obj.get("withdrawn_at"), str, True), "repository": repo,
              "severity": None if severity == "unknown" else severity, "cvss_vector": vector,
              "cwes": sorted({_is(_is(c, dict).get("cwe_id"), str) for c in _is(obj.get("cwes"), list, True) or []}),
              "packages": ruleset.ordered(packages)}
    named = [obj.get("cve_id")] + [i.get("value") for i in _is(obj.get("identifiers"), list, True) or []
                                   if isinstance(i, dict)]
    return fields, named


def _osv_reading(obj, lookup_id: str):
    """(fields, the ids the response names) of an api.osv.dev/v1/vulns response."""
    if _is(obj, dict).get("id") != lookup_id:
        raise _Bad("another entry")
    packages = []
    for a in _is(obj.get("affected"), list, True) or []:
        pkg = _is(_is(a, dict).get("package"), dict, True)
        if pkg is not None:
            packages.append({"ecosystem": _is(pkg.get("ecosystem"), str).lower(), "name": _is(pkg.get("name"), str),
                             "range": None, "first_patched": None})
    fields = {"osv_id": lookup_id, "withdrawn": _is(obj.get("withdrawn"), str, True),
              "packages": ruleset.ordered(packages)}
    return fields, _is(obj.get("aliases"), list, True) or []


def _pair(rng, first_patched) -> list | None:
    """[range, first patched version] as a GitHub advisory states them, the range without
    its spaces, or None when ``versions`` cannot read them: only text of the version
    grammar is ever kept. A missing range states nothing to compare with: None."""
    if not isinstance(rng, str) or not (first_patched is None or isinstance(first_patched, str)):
        return None
    rng = "".join(rng.split())
    ok = len(rng) <= 128 and versions.check("0", rng, first_patched) is not None
    return [rng, first_patched] if ok else None


def _record(rs, source: str, readings: list, named, etag, now: int) -> dict:
    """What is kept of one id's good read: per scope product the level and
    whether the class may lower; the reading's own ``lowers`` (its authority
    about a product it does not name, and about which other ids are the same
    advisory); the ids it names, each only in the exact form ``norm_id``
    returns; the ETag when it has an ETag's shape. No other text of the source.

    ``ranges`` (swfe): per scope product, one item for each package entry of a GitHub
    advisory that binds to it: its ``_pair``, or None when it cannot be read (the
    readable ones still count). [None] for a product an OSV entry names: its ranges are
    not read. The catalog states no version: a KEV record has none.

    KEV not listing a CVE is no authority: the catalog holds what is known to
    be exploited, and says nothing about the rest."""
    support: dict = {}
    ranges: dict = {}
    lowers = True
    for fields in readings:
        found = rs.read(source, fields)
        for name, s in found.items():
            if name not in support or _RANK[s.level] > _RANK[support[name][0]]:
                support[name] = [s.level, s.lowers, s.stop_using]  # 9kgk: stop_using completes this level
        if source == "osv":
            ranges.update((name, [None]) for name in found)
        for pkg in fields["packages"] if source == "ghsa" else ():
            pair = _pair(pkg["range"], pkg["first_patched"])
            for name in rs.read(source, {**fields, "packages": [pkg]}):  # the products this package binds to
                held = ranges.setdefault(name, [])
                if pair not in held:
                    held.append(pair)
        lowers = lowers and rs.lowers(source, fields) and not (source == "kev" and fields["name"] is None)
    if not isinstance(named, list) or len(named) > MAX_NAMES:
        raise _Bad("names")  # cut short, a tied id could silently become untied
    names = sorted({n for n in (norm_id(x) for x in named) if n is not None})
    return {"etag": etag if isinstance(etag, str) and _ETAG.fullmatch(etag) else None, "at": now,
            "lowers": lowers, "support": support, "names": names, "ranges": ranges}


# ------------------------------------------------------------------ results

def judge(level: str, product: str | None, records, complete: bool, rs, actions=(), fixed=None) -> dict:
    """One product's result. ``product``: its scope name, None for a posted product that
    is none (``scope_of``). ``records``: what was kept of each counted id.
    Support from a source its subject's attacker can write (``lowers`` false)
    confirms nothing and contradicts nothing: it only makes the result unknown.
    The source's level is what a post with the thread's ``actions`` and ``fixed``
    version may carry (9kgk, ``Ruleset.action_level``): a KEV listing with no fix
    known supports high, not critical.

    ``level`` may be ``none``, a retraction (c1g2). That is confirmed only when a
    source that may lower names this product and supports nothing for it (a withdrawn
    advisory): a source that is silent about the product confirms no retraction.

    At ``notice``, the lowest level a post carries, the same finding is ``confirmed``,
    why ``withdrawn`` (tavj): the relay bot has no retraction, so an alert whose advisory
    was withdrawn stands at notice, and that is not "the source never supported it"."""
    def out(result, why, source):
        return {"result": result, "why": why, "source": source}
    if product not in rs.products():
        return out(UNKNOWN, "no-source", None)  # not in this reader's scope file: it cannot judge
    s, may_lower = ruleset.NONE, True  # s: the highest level a source that may set one gives
    stop = False  # a source gives s through a stop_using row
    named = False  # a source that may lower states something about this product
    for r in records:
        own = r["support"].get(product)
        named = named or (own is not None and own[1])
        if own is not None and own[1] and _RANK[own[0]] > _RANK[s]:
            s, stop = own[0], False
        if own is not None and own[1] and own[0] == s:
            stop = stop or own[2]
        may_lower = may_lower and (own[1] if own is not None else r["lowers"])
    s = rs.action_level(s, actions, product, fixed, stop_using=stop)
    if _RANK[s] > _RANK[level]:
        return out(CONTRADICTED, "below-source", s)  # rests on bodies that were read: a missing one could only add
    if not complete:
        return out(UNKNOWN, "unread", None)  # one read missing: the source's level is only a lower bound
    if s == level and (level != ruleset.NONE or (named and may_lower)):
        return out(CONFIRMED, "match", s)
    if not may_lower or level == ruleset.NONE:
        return out(UNKNOWN, "unauthoritative", s)
    if s == ruleset.NONE and named and level == _LEVELS[1]:
        return out(CONFIRMED, "withdrawn", s)
    if s == ruleset.NONE:
        return out(CONTRADICTED, "unsupported", s)
    if level == "critical":
        return out(CONTRADICTED, "above-source", s)
    return out(UNKNOWN, "reading", s)


def summary(products: dict) -> tuple[str, str]:
    """A thread's (result, why): the worst any of its products has. One
    supported product never confirms another."""
    for result in (CONTRADICTED, UNKNOWN, CONFIRMED):
        for why in _WHYS[result]:
            if any(p["result"] == result and p["why"] == why for p in products.values()):
                return result, why
    return UNKNOWN, "unread"


def pkey(product) -> str:
    """The key of one product's result: its ecosystem and its name as posted (2mgd).
    Two entries with one name under two ecosystems are two products: neither's result
    stands for the other's. A line feed is in neither field (``schema.validate``)."""
    return f"{product.ecosystem}\n{product.name}"


def scope_of(product) -> str | None:
    """The scope product a posted product is judged as (``check.scope_name``), or None."""
    return check.scope_name(product.name, product.ecosystem)


class _Target:
    """What a thread's published state asks of the sources. ``products``: the keys
    (``pkey``) of its products; ``scope``: per key the scope product it is judged as,
    None for one that is no scope product by the rule an installation is matched with."""

    def __init__(self, adv):
        self.first = norm_id(adv.id)
        seen = {self.first}
        self.aliases = [a for a in (norm_id(x) for x in adv.aliases) if a is not None
                        and not (a in seen or seen.add(a))]
        self.level = adv.level
        self.products = sorted({pkey(p) for p in adv.products})
        self.scope = {pkey(p): scope_of(p) for p in adv.products}
        self.eco = {pkey(p): p.ecosystem for p in adv.products}
        # 9kgk: what the post can be acted on with; the source's level is held to it
        self.fixed = {pkey(p): p.fixed for p in adv.products}
        self.actions = [(a.verb, a.target, a.value) for a in adv.actions]
        # tavj: an asked state whose higher levels are all claimed from the first id's fields
        self.claimed = getattr(adv, "claimed", False) is True
        self.key = hashlib.sha256(json.dumps(
            {"id": self.first, "aliases": sorted(self.aliases), "level": self.level, "products": self.products,
             "fixed": self.fixed, "actions": sorted(self.actions, key=repr),
             **({"claimed": True} if self.claimed else {})},
            sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def ids(self) -> list:
        return [self.first, *self.aliases]

    def judge(self, key, records, complete, rs) -> dict:
        """The result of the product with this key, judged as its scope product. An
        action whose target is that product in another spelling counts as naming it."""
        name = self.scope[key]
        actions = [(v, name if name is not None and check.scope_name(t, self.eco[key]) == name else t, x)
                   if type(t) is str else (v, t, x) for v, t, x in self.actions]
        return judge(self.level, name, records, complete, rs, actions, self.fixed.get(key))


@dataclass(frozen=True)
class Asked(schema.Advisory):
    """A thread's widest state at a published lower level: what the sources are asked
    about. ``claimed``: every level the thread stated above it rests on the first id's
    fields (``claimed``); part of the state's key, because it changes how the catalog's
    silence is read (``_Run.thread``)."""
    claimed: bool = False


def at_level(adv, level: str, claimed: bool = False):
    """``adv`` as a published lowering or retraction would leave it: what the sources
    are asked about (c1g2). ``level`` may be ``none`` (retracted), which no post carries."""
    return Asked(**{**{f.name: getattr(adv, f.name) for f in fields(schema.Advisory)}, "level": level},
                 claimed=claimed is True)


def claimed(adv, level: str, stated, rs=None, pin=None) -> bool:
    """Whether every level above ``level`` that the thread of ``adv`` has stated rests on
    its first id's fields (tavj). ``stated``: ``pull.Thread.stated``, (level, the event's
    claim or None) for the root and each reply that names a level.

    True only when each such statement carries a claim that is well formed, names the
    thread's first id (``norm_id`` of both), that this reader's ruleset reproduces for
    every product of ``adv`` (``ruleset.check_claim`` gives ``ok``, under ``pin``), and
    whose level is at least the stated one. A statement with no claim, a curator's, one
    whose claim names another id (support this reader does not read as the thread's) or
    whose fields give this reader another level, may rest on a reading of prose: False.
    False too with no statement at all, with no product, and for an id that names no
    source. A claim is the relay-bot key's word and proves nothing alone: it decides
    only whether a result this machine read from the source itself may confirm a
    lowering below the ruleset's ``reading_cap``, or read the catalog's silence. Never
    raises."""
    try:
        rs = rs or ruleset.load()
        first = norm_id(adv.id)
        names = [p.name for p in adv.products]
        if first is None or not stated or not names or level not in rs.levels:
            return False  # and never for a retraction ("none"), which no result confirms
        for said, claim in stated:
            if said not in rs.levels:
                return False
            if rs.rank(said) <= rs.rank(level):
                continue
            if claim is None or norm_id(ruleset.parse_claim(claim)["id"]) != first \
                    or rs.rank(claim["level"]) < rs.rank(said) \
                    or any(ruleset.check_claim(claim, n, pin, rs) != "ok" for n in names):
                return False
        return True
    except Exception:  # a hostile claim, a damaged ruleset: nothing is claimed
        return False


def lowering(adv, level: str, cache: dict | None, now: float, rs=None, stated=None, pin=None, *,
             whole: bool = False) -> bool | None:
    """What the cached results say about lowering ``adv`` to ``level`` (c1g2; the
    ``check`` of ``pull.standing``). ``adv`` is ``pull.widest`` of the thread and
    ``stated`` its ``stated``.

    False: a source supports more for some product (``below-source``). It stays False
    however old the result is: too high is the safe side.

    True: every product's sources were read whole, every one of them an authority, none
    gives more than ``level`` (``match``, ``withdrawn``, ``reading``, ``unsupported``),
    and they were read no more than FRESH_S ago by this machine's clock (``run`` reads
    such a state again every day, and a failed read is ``unread`` at once). And either
    ``level`` is not below the ruleset's ``reading_cap``, or the state is ``claimed``
    (tavj): a reading of prose may hold an alert at up to ``reading_cap`` and this reader
    cannot see readings, so fields that give less prove nothing below it unless the
    thread's signed claims say every higher level rested on those fields. A retraction
    (``none``) is never True.

    None: anything else, and ``verify = "off"`` (``cache`` None).

    ``whole`` asks a weaker question, for ending a refusal this machine remembers
    (``cli._note_offers``): True whenever the fresh results rest on whole reads of
    authorities that give no more than ``level``, claimed or not."""
    if cache is None:
        return None
    rs = rs or ruleset.load()
    said = claimed(adv, level, stated, rs, pin)
    asked = at_level(adv, level, said)
    products = result_for(asked, cache)
    if not products:
        return None
    whys = {p["why"] for p in products.values()}
    if "below-source" in whys:
        return False
    held = cache["results"].get(_Target(asked).key)
    if not whys <= {"match", "withdrawn", "reading", "unsupported"} or level not in rs.levels \
            or held is None or not 0 <= now - held["at"] <= FRESH_S:
        return None
    return True if whole or said or rs.rank(level) >= rs.rank(rs.reading_cap) else None


def _states(q, rng, first_patched) -> bool:
    """Product entry ``q`` states what the source does: it matches every version the
    source's range does, and its ``fixed`` is absent or the source's first patched
    version. ``fixed`` is the version an upgrade is sent to (``check.plan``): too low
    hides installations the source calls vulnerable, too high names a version the
    source did not call the fix."""
    return versions.covers(rng, first_patched, q.affected, q.fixed) and (
        q.fixed is None or (first_patched is not None and versions.parse(q.fixed) == versions.parse(first_patched)))


def narrowing(adv, products, cache: dict | None, now: float, shown=None, *, whole: bool = False) -> bool | None:
    """What the cached results say about showing ``products`` in place of the products a
    thread shows (swfe; ``check.narrowing`` of ``pull.standing``). ``adv`` is
    ``pull.widest`` of the thread, the state the sources were asked about; ``products`` its
    ``narrowed``; ``shown`` the entries it shows now (``Thread.wide``'s; default: those of
    ``adv``). Never ``adv``'s where they differ: ``widest`` fills an entry that states no
    ``fixed`` with the first one the thread stated, which the thread's own signer chose,
    and a list equal to that filled state is not "nothing changed".

    Per product, by the matcher's own rule (2mgd, ``scope_of``): entries that are one
    scope product are taken together, whatever their spelling; an entry that is no scope
    product is its own product, by its ecosystem and its name in lower case. Two names
    the matcher tells apart are two products here, so no confirmed list names an
    installation otherwise than the matcher will read it. A product whose entries are the same in
    ``shown`` and ``products``, spelling included, is not asked about. For any other, with
    the version ranges the thread's authorities state for that scope product (``ranges``
    of the result; a None item is one this reader cannot compare; an entry that is no
    scope product has none):

    1. Every readable range must be stated (``_states``), in every ecosystem ``shown``
       holds for the product, by an entry of ``products`` for it in that ecosystem. If one
       is not: False. A shorter range, another ``fixed``, a product dropped that the source
       states versions for, an entry moved to another ecosystem. It rests on bodies that
       arrived whole, so it holds on a partial read and at any age.
    2. Every entry of ``products`` for it that ``shown`` does not hold must be in an
       ecosystem ``shown`` holds for the product and state one of the ranges: a correct
       entry never carries a wrong one through, and neither does a new name. If one
       does not: False when the reads were whole and every range of the product was
       readable; else not settled.
    3. No range, or one that cannot be compared: not settled.

    True: every changed product is settled, the thread's reads were whole, and they were
    made no more than FRESH_S ago by this machine's clock. None: anything else, a failed
    read and ``verify = "off"`` among them.

    ``whole`` asks a weaker question, for a thread one of whose narrowings this machine
    has refused (``cli._note_offers``): True whenever fresh whole reads do not contradict
    the list, settled or not."""
    if cache is None or adv.posted_by != BOT:
        return None
    t = _Target(adv)
    held = cache["results"].get(t.key) if t.first is not None else None
    if held is None or "ranges" not in held:
        return None
    def which(p):
        name = scope_of(p)
        return (None, p.ecosystem, p.name.lower()) if name is None else name

    mine: dict = {}
    theirs: dict = {}
    for p in adv.products if shown is None else shown:
        mine.setdefault(which(p), []).append(p)
    for q in products:
        theirs.setdefault(which(q), []).append(q)
    settled = True
    for name in {*mine, *theirs}:
        own, new = mine.get(name, []), theirs.get(name, [])
        if set(own) == set(new):
            continue
        items = held["ranges"].get(name, []) if type(name) is str else []
        pairs = [x for x in items if x is not None]
        ecosystems = {p.ecosystem for p in own}
        if not all(any(q.ecosystem == e and _states(q, r, f) for q in new) for e in ecosystems for r, f in pairs):
            return False  # rule 1
        comparable = bool(pairs) and len(pairs) == len(items)
        if not all(q in own or (q.ecosystem in ecosystems and any(_states(q, r, f) for r, f in pairs)) for q in new):
            if comparable and held["whole"]:
                return False  # rule 2
            settled = False
        settled = settled and comparable  # rule 3
    return True if (settled or whole) and held["whole"] and 0 <= now - held["at"] <= FRESH_S else None


def state_key(adv) -> str:
    """The published state a result was computed for: the first id, the
    aliases, the level and the products (ecosystem and name)."""
    return _Target(adv).key


# ------------------------------------------------------------------ the cache

def _empty(digest: str) -> dict:
    return {"version": VERSION, "ruleset": digest, "kev": None, "sources": {}, "results": {}}


def _well_formed(c, digest: str) -> bool:
    try:
        return _shape_ok(c, digest)
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):  # e.g. a list where a word belongs
        return False


def _shape_ok(c, digest: str) -> bool:
    if not isinstance(c, dict) or set(c) != set(_empty(digest)) or c["version"] != VERSION or c["ruleset"] != digest:
        return False

    def tag(v):
        return v is None or isinstance(v, str) and _ETAG.fullmatch(v) is not None

    def when(v):
        return type(v) is int and 0 <= v <= schema.MAX_TIMESTAMP

    def stated(v):
        return isinstance(v, dict) and all(
            isinstance(n, str) and isinstance(r, list) and len(r) <= MAX_PAIRS and all(
                x is None or isinstance(x, list) and len(x) == 2 and _pair(*x) == x for x in r) for n, r in v.items())

    k = c["kev"]
    if k is not None and not (isinstance(k, dict) and set(k) == {"etag", "at"} and tag(k["etag"]) and when(k["at"])):
        return False
    if not isinstance(c["sources"], dict) or not isinstance(c["results"], dict):
        return False
    for i, r in c["sources"].items():
        if norm_id(i) != i or not isinstance(r, dict) or set(r) != {"etag", "at", "lowers", "support", "names", "ranges"} \
                or not stated(r["ranges"]) or not tag(r["etag"]) or not when(r["at"]) or type(r["lowers"]) is not bool \
                or not isinstance(r["support"], dict) or not isinstance(r["names"], list) \
                or len(r["names"]) > MAX_NAMES or not all(isinstance(n, str) and norm_id(n) == n for n in r["names"]) \
                or not all(isinstance(n, str) and isinstance(s, list) and len(s) == 3 and type(s[0]) is str and s[0] in _LEVELS
                           and type(s[1]) is bool and type(s[2]) is bool for n, s in r["support"].items()):
            return False
    for key, r in c["results"].items():
        if not (isinstance(key, str) and _HEX.fullmatch(key)) or not isinstance(r, dict) \
                or set(r) - {"ranges", "whole"} != {"at", "products"} or not when(r["at"]) \
                or not isinstance(r["products"], dict) or ("ranges" in r) != ("whole" in r) \
                or "ranges" in r and not (stated(r["ranges"]) and type(r["whole"]) is bool):
            return False
        for name, p in r["products"].items():
            if not isinstance(name, str) or not isinstance(p, dict) or set(p) != {"result", "why", "source"} \
                    or type(p["result"]) is not str or type(p["why"]) is not str \
                    or p["result"] not in _WHYS or p["why"] not in _WHYS[p["result"]] \
                    or not (p["source"] is None or type(p["source"]) is str and p["source"] in _LEVELS):
                return False
    return True


def load(state_dir, rs=None) -> dict:
    """The cache in ``state_dir``, or an empty one when the file is missing,
    unreadable, of another shape, or was written under another ruleset
    digest: nothing computed under other rules is used, ETags included."""
    digest = (rs or ruleset.load()).digest
    try:
        with open(Path(state_dir) / FILE, "rb") as f:
            data = f.read(MAX_CACHE_BYTES + 1)
        cache = _strict(data) if len(data) <= MAX_CACHE_BYTES else None
    except (OSError, ValueError, RecursionError):
        cache = None
    return cache if _well_formed(cache, digest) else _empty(digest)


def result_for(adv, cache: dict | None) -> dict | None:
    """{product key (``pkey``): {result, why, source}} for a thread, from the cache
    only. None for a thread no relay bot posted. ``cache`` None is
    ``verify = "off"``: every product is unknown, and no file was read."""
    if adv.posted_by != BOT:
        return None
    t = _Target(adv)

    def every(why):
        return {p: {"result": UNKNOWN, "why": why, "source": None} for p in t.products}
    if cache is None:
        return every("off")
    if t.first is None:
        return every("no-source")
    held = cache["results"].get(t.key)
    return dict(held["products"]) if held is not None and set(held["products"]) == set(t.products) else every("unread")


# ------------------------------------------------------------------ a run

class _Run:
    def __init__(self, cache, rs, fetch, now, clock, start):
        self.cache, self.rs, self.fetch, self.now, self.clock, self.start = cache, rs, fetch, now, clock, start
        self.requests = 0
        self.exhausted = False
        self.memo: dict = {}  # id -> record or None, for this run
        self.kev: dict | None = None  # the catalog this run read: {CVE id: entries}
        self.kev_asked = self.kev_unchanged = False
        self.stated: dict | None = None  # swfe: ``ranges`` and ``whole`` of the thread last judged

    def spent(self) -> bool:
        """The run's 30 seconds are over."""
        if self.clock() - self.start >= RUN_SECONDS:
            self.exhausted = True
        return self.exhausted

    def _spend(self) -> float | None:
        """Count one request and give its timeout, or None when the run's
        requests or seconds are used up."""
        left = RUN_SECONDS - (self.clock() - self.start)
        if self.requests >= MAX_FETCHES or left <= 0:
            self.exhausted = True
            return None
        self.requests += 1
        return min(TIMEOUT, left)

    def _get(self, url, etag, source):
        """(status, etag, decoded body or None) or None on any failure."""
        timeout = self._spend()
        if timeout is None:
            return None
        try:
            status, tag, body = self.fetch(url, etag, LIMITS[source], timeout)
            if status == 304:
                return (304, None, None) if etag is not None else None
            if status != 200 or type(body) is not bytes or len(body) > LIMITS[source]:
                return None
            return 200, tag, _strict(body)
        except Exception:  # nothing of the failure is kept or shown: its text may quote the response
            return None

    def _ask_kev(self, known: set) -> None:
        """The one request for the catalog. It carries the stored ETag only
        when every CVE id known to be wanted has a record read at that ETag."""
        self.kev_asked = True
        sources, held = self.cache["sources"], self.cache["kev"]
        etag = held["etag"] if held else None
        if etag is None or any(sources.get(i, {}).get("etag") != etag for i in known):
            etag = None  # an id not read at that ETag needs the body
        got = self._get(KEV_URL, etag, "kev")
        if got is None:
            return
        if got[0] == 304:
            self.kev_unchanged = True
            return
        try:
            self.kev = _kev_catalog(got[2])
        except _Bad:
            return
        tag = got[1] if isinstance(got[1], str) and _ETAG.fullmatch(got[1]) else None
        self.cache["kev"] = {"etag": tag, "at": self.now}

    def read(self, lookup_id: str, known_cves=frozenset()) -> dict | None:
        """What is kept of this id's read, asked for at most once a run. None:
        the read failed or was not made. A stored record is never a fallback
        for a failed read; a 304 to its own ETag is the one way it is used."""
        if lookup_id in self.memo:
            return self.memo[lookup_id]
        source, sources = ruleset.source_of(lookup_id), self.cache["sources"]
        held, rec = sources.get(lookup_id), None
        if source == "kev":
            if not self.kev_asked:
                self._ask_kev(set(known_cves) | {lookup_id})
            if self.kev is not None:
                try:
                    tag = self.cache["kev"]["etag"]
                    rec = _record(self.rs, "kev", _kev_readings(self.kev, lookup_id), [], tag, self.now)
                except (_Bad, ruleset.RulesetError, TypeError, AttributeError):
                    rec = None
            elif self.kev_unchanged and held is not None and held["etag"] == self.cache["kev"]["etag"]:
                rec = held
        else:
            got = self._get(url_of(lookup_id), held["etag"] if held else None, source)
            if got is not None and got[0] == 304:
                rec = held
            elif got is not None:
                try:
                    fields, named = (_ghsa_reading if source == "ghsa" else _osv_reading)(got[2], lookup_id)
                    rec = _record(self.rs, source, [fields], named, got[1], self.now)
                except (_Bad, ruleset.RulesetError, TypeError, AttributeError):
                    rec = None
        if rec is not None:
            sources[lookup_id] = rec
        self.memo[lookup_id] = rec
        return rec

    def thread(self, t: _Target, known_cves) -> dict:
        """{product key: result} for one thread.

        Which other ids are the same advisory is the source's word, never the
        bot's. When the first id is a GHSA or MAL id and its response is an
        authority (``lowers``), the ids that response names are read, whether
        or not the thread lists them: dropping an alias takes nothing away.
        When the first id is a CVE (KEV names no other id), each GHSA or MAL
        alias the thread lists is read, and counts only when its own response
        is an authority and names that CVE. Anything else adds nothing.

        The catalog not listing a CVE is no authority, with one exception (tavj): for a
        claimed state (``claimed``) it is. The thread's signed claims then say the
        catalog listed this CVE for this product, this machine's whole read says it
        does not, and nothing the thread stated rests on anything else."""
        self.stated = None
        first = self.read(t.first, known_cves)
        if first is None:
            return {p: t.judge(p, [], False, self.rs) for p in t.products}
        from_kev = ruleset.source_of(t.first) == "kev"
        if t.claimed and from_kev and not first["lowers"] and not first["support"]:
            first = dict(first, lowers=True)  # judged so, stored as it was read
        records = [first]
        held = self.cache["sources"]

        def weight(alias) -> int:
            """What this machine last read ``alias`` to support for the thread's products,
            as a rank; 0 when it did not count. Read first: only MAX_ALIASES are read,
            and a reply that puts other aliases in front must not push out the one
            whose support refused a lowering."""
            r = held.get(alias)
            if r is None or not r["lowers"] or t.first not in r["names"]:
                return 0
            return max((_RANK[r["support"][p][0]] for p in t.scope.values()
                        if p in r["support"] and r["support"][p][1]), default=0)
        if from_kev:
            related = sorted((a for a in t.aliases if ruleset.source_of(a) != "kev"), key=lambda a: -weight(a))
        else:
            related = [n for n in first["names"] if n != t.first] if first["lowers"] else []
        complete = len(related) <= MAX_ALIASES
        for a in related[:MAX_ALIASES]:
            rec = self.read(a, known_cves)
            if rec is None:
                complete = False
            elif not from_kev or (rec["lowers"] and t.first in rec["names"]):
                records.append(rec)

        def pairs(p):
            """The version ranges the counted authorities state for scope product ``p``,
            each once; a None item is one this reader cannot compare."""
            out: list = []
            for r in records:
                if p in r["support"] and r["support"][p][1]:  # only a source that may lower
                    out += [x for x in r["ranges"].get(p, []) if x not in out]
            return out
        self.stated = {"ranges": {p: pairs(p) for p in sorted({n for n in t.scope.values() if n is not None})},
                       "whole": complete}
        return {p: t.judge(p, records, complete, self.rs) for p in t.products}


def _settled(held, products: dict, asked: bool) -> dict:
    """``products``, or for an asked state (c1g2) the held result when that said a source
    supports more and the new one only failed to read: a contradiction of a lowering
    stays until sources read whole say otherwise, so nobody ends it by making a read
    fail or by crowding the run's budget."""
    if asked and held is not None and set(held["products"]) == set(products) \
            and any(p["why"] == "below-source" for p in held["products"].values()) \
            and any(p["why"] == "unread" for p in products.values()) \
            and not any(p["why"] == "below-source" for p in products.values()):
        return held["products"]
    return products


def _entry(now: int, products: dict, stated, held, whole: bool) -> dict:
    """A result entry (swfe). ``stated``: the version ranges this run read for the thread
    and whether its reads were whole (``_Run.stated``); None when it read none, and then
    the ranges ``held`` (the entry before) had are kept, since a contradiction they hold
    stands at any age. ``whole`` False: the products are not what this run computed from
    whole reads (the run was cut short, or an earlier contradiction is kept over a
    failed read), so the entry confirms no narrowing however new its time is."""
    out = {"at": now, "products": products}
    if stated is not None:
        out.update(ranges=stated["ranges"], whole=stated["whole"] and whole)
    elif held is not None and "ranges" in held:
        out.update(ranges=held["ranges"], whole=False)
    return out


def _waits(t: _Target, results: dict, now: int) -> bool:
    """A thread is read when its published state has no result, when a read it
    needed failed, and, a day later, when its result is anything but
    confirmed: a source read minutes before it changed must not stand for good."""
    held = results.get(t.key)
    if held is None or set(held["products"]) != set(t.products):
        return True
    whys = {p["why"] for p in held["products"].values()}
    return "unread" in whys or (whys - {"match", "no-source"} and now - held["at"] >= RETRY_S)


def run(current, wanted, state_dir, fetch=None, now: float | None = None, clock=time.monotonic, rs=None,
        recheck=()) -> dict:
    """Read the sources for the threads of ``wanted`` that need it and save
    the cache; returns it. ``current``: every current advisory (what the
    cache keeps); ``wanted``: the ones this run may read (all of them, or
    those matching this machine). ``recheck``: the states among them whose
    result authorises a lowering (c1g2): each is read again once its result is
    RETRY_S old, a confirmed one too, so a source that changed is seen. Threads waiting (``_waits``) are taken
    longest untried first, then highest level, so no thread that keeps failing
    holds the others back. The 30 seconds run from this call. The state lock
    is not held: a pull must not wait."""
    start = clock()
    rs = rs or ruleset.load()
    fetch = fetch or default_fetch
    now = int(time.time() if now is None else now)
    cache = load(state_dir, rs)
    results = cache["results"]
    targets = {}
    for adv in wanted:
        if adv.posted_by == BOT:
            t = _Target(adv)
            if t.first is not None:
                targets.setdefault(t.key, t)
    again = {_Target(adv).key for adv in recheck}
    waiting = sorted((t for t in targets.values() if _waits(t, results, now)
                      or (t.key in again and now - results[t.key]["at"] >= RETRY_S)),
                     key=lambda t: (results.get(t.key, {}).get("at", 0), -_RANK[t.level], t.key))
    known = {i for t in waiting for i in [t.first, *cache["sources"].get(t.first, {}).get("names", [])]
             if ruleset.source_of(i) == "kev"}
    job = _Run(cache, rs, fetch, now, clock, start)
    for t in waiting:
        if job.spent():
            break
        asked = job.requests
        products = job.thread(t, known)
        if job.exhausted:
            # Not tried in full: its result stays as it was. But a thread that spent
            # requests has had its turn, or it would come first again every run.
            if any(p["why"] == "below-source" for p in products.values()):
                # tavj: what was read before the budget ran out supports more. That rests on
                # bodies that arrived whole, whatever was not read: kept, so the lowering it
                # contradicts is refused and never runs out its 72 hours unchecked.
                results[t.key] = _entry(now, products, job.stated, results.get(t.key), False)
            elif job.requests > asked:
                held = results.get(t.key)
                # c1g2: not for a state whose result authorises a lowering. Kept with a new
                # time, an old ``match`` would read as confirmed today, and would stand in
                # for what the requests this run did make had found. It is unread instead,
                # unless it was a contradiction (``_settled``).
                keep = held is not None and set(held["products"]) == set(t.products) and t.key not in again
                results[t.key] = _entry(now, held["products"] if keep else _settled(
                    results.get(t.key), {p: t.judge(p, [], False, rs) for p in t.products}, t.key in again),
                    job.stated, held, False)  # swfe: what was read still refuses a narrowing, and confirms none
            break
        kept = _settled(results.get(t.key), products, t.key in again)
        results[t.key] = _entry(now, kept, job.stated, results.get(t.key), kept is products)
    live = [_Target(adv) for adv in current if adv.posted_by == BOT and norm_id(adv.id) is not None]
    keys = {t.key for t in live}
    ids = {i for t in live for i in t.ids()}
    ids |= {n for i in list(ids) for n in cache["sources"].get(i, {}).get("names", [])}
    cache["results"] = {k: v for k, v in results.items() if k in keys}
    cache["sources"] = {i: r for i, r in cache["sources"].items() if i in ids}
    write_json(Path(state_dir) / FILE, cache)
    return cache
