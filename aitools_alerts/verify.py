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
changes no level: it reports (ai-tools-alerts#tavj applies the results).

Nothing a response says is printed. What is stored from one: levels and
booleans the ruleset computed, an ETag of an ETag's shape, and SHA-256
digests of the ids the response names. A run makes at most MAX_FETCHES
requests in at most RUN_SECONDS, each bounded as a whole by a worker thread.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

from . import ruleset, schema
from .state import write_json

__all__ = ["KEV_URL", "HOSTS", "LIMITS", "TIMEOUT", "MAX_FETCHES", "RUN_SECONDS", "FILE", "BOT",
           "norm_id", "url_of", "default_fetch", "state_key", "judge", "summary", "load", "run",
           "result_for"]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_GHSA_URL = "https://api.github.com/advisories/"
_OSV_URL = "https://api.osv.dev/v1/vulns/"
HOSTS = frozenset({"www.cisa.gov", "api.github.com", "api.osv.dev"})
LIMITS = {"kev": 8 << 20, "ghsa": 256 << 10, "osv": 256 << 10}
TIMEOUT = 10.0  # one request, from the call to the last byte
MAX_FETCHES = 10  # per run
RUN_SECONDS = 30.0
MAX_ALIASES = 3  # aliases of one thread that are read
MAX_NAMES = 50  # ids one response may tie to its own
MAX_CACHE_BYTES = 16 << 20
FILE = "verify.json"
BOT = "relay-bot"
CONFIRMED, CONTRADICTED, UNKNOWN = "confirmed", "contradicted", "unknown"
_WHYS = {CONFIRMED: ("match",), CONTRADICTED: ("unsupported", "above-source", "below-source"),
         UNKNOWN: ("unread", "unauthoritative", "reading", "no-source", "off")}
_LEVELS = (ruleset.NONE, "notice", "high", "critical")
_RANK = {name: i for i, name in enumerate(_LEVELS)}
_ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]{1,128}"')
_HEX = re.compile(r"[0-9a-f]{64}")
_REPO_URL = re.compile(r"https://api\.github\.com/repos/([A-Za-z0-9._-]{1,100})/([A-Za-z0-9._-]{1,100})"
                       r"/security-advisories/(GHSA(?:-[0-9a-z]{4}){3})")
_CONNECTION = http.client.HTTPSConnection  # tests replace it


# ------------------------------------------------------------------ ids and URLs

def norm_id(text) -> str | None:
    """The id as a lookup uses it, or None: ``CVE-`` in upper case, ``GHSA-``
    then lower case (as the poster writes it), kept only when
    ``ruleset.source_of`` names its source and it is not a synthetic id."""
    if not isinstance(text, str) or len(text) > 128:
        return None
    head = text[:5].upper()
    if head.startswith("CVE-"):
        text = text.upper()
    elif head == "GHSA-":
        text = "GHSA-" + text[5:].lower()
    if ruleset.source_of(text) is None or schema.is_synthetic(text):
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


def _digest(lookup_id: str) -> str:
    return hashlib.sha256(lookup_id.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ the request

def _request(host: str, path: str, etag: str | None, limit: int, timeout: float):
    conn = _CONNECTION(host, timeout=timeout)
    try:
        headers = {"User-Agent": "aitools-alerts", "Accept": "application/json", "Accept-Encoding": "identity"}
        if etag is not None:
            headers["If-None-Match"] = etag
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
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
    in a daemon thread that is abandoned when the time is up. A 200 body is
    returned only when it arrived whole (see ``_request``). The error never
    carries text from the response."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.netloc not in HOSTS or parts.query or parts.fragment:
        raise OSError("refused URL")
    box: list = []

    def go():
        try:
            box.append(_request(parts.netloc, parts.path, etag, limit, timeout))
        except Exception:  # network, TLS, protocol, framing: a failed read
            box.append(None)

    worker = threading.Thread(target=go, name="aitools-alerts-verify", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive() or not box or box[0] is None:
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


def _kev_readings(catalog, wanted) -> dict:
    """{CVE id: [reading, ...]} for each wanted id; an unlisted id reads name null."""
    _is(catalog, dict)
    _is(catalog.get("catalogVersion"), str)
    items = _is(catalog.get("vulnerabilities"), list)
    if _is(catalog.get("count"), int) != len(items):
        raise _Bad("count")
    found: dict = {i: [] for i in wanted}
    for it in items:
        cve = _is(_is(it, dict).get("cveID"), str)
        if cve in found:
            found[cve].append(it)
    out = {}
    for cve, entries in found.items():
        try:
            out[cve] = [{"cve_id": cve, "name": f"{_is(e.get('vendorProject'), str).strip()} "
                                                f"{_is(e.get('product'), str).strip()}"}
                        for e in entries] or [{"cve_id": cve, "name": None}]
        except _Bad:
            out[cve] = None  # this entry cannot be read; the others can
    return out


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


def _record(rs, source: str, readings: list, named, etag, now: int) -> dict:
    """What is kept of one id's good read: per scope product the level and
    whether the class may lower, the reading's own ``lowers``, digests of the
    ids it names, the ETag when it has an ETag's shape. No text of the source."""
    support: dict = {}
    lowers = True
    for fields in readings:
        for name, s in rs.read(source, fields).items():
            if name not in support or _RANK[s.level] > _RANK[support[name][0]]:
                support[name] = [s.level, s.lowers]
        lowers = lowers and rs.lowers(source, fields)
    names = sorted({_digest(n) for n in (norm_id(x) for x in named[:MAX_NAMES * 4]) if n is not None})[:MAX_NAMES]
    return {"etag": etag if isinstance(etag, str) and _ETAG.fullmatch(etag) else None, "at": now,
            "lowers": lowers, "support": support, "names": names}


# ------------------------------------------------------------------ results

def judge(level: str, product: str, records, complete: bool, rs) -> dict:
    """One product's result. ``records``: what was kept of each counted id."""
    def out(result, why, source):
        return {"result": result, "why": why, "source": source}
    if not complete:
        return out(UNKNOWN, "unread", None)  # one read missing: the source's level is only a lower bound
    if product not in rs.products():
        return out(CONTRADICTED, "unsupported", ruleset.NONE)
    s, may_lower = ruleset.NONE, True
    for r in records:
        own = r["support"].get(product)
        if own is not None and _RANK[own[0]] > _RANK[s]:
            s = own[0]
        may_lower = may_lower and (own[1] if own is not None else r["lowers"])
    if _RANK[s] > _RANK[level]:
        return out(CONTRADICTED, "below-source", s)
    if s == level:
        return out(CONFIRMED, "match", s)
    if not may_lower:
        return out(UNKNOWN, "unauthoritative", s)
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


class _Target:
    """What a thread's published state asks of the sources."""

    def __init__(self, adv):
        self.first = norm_id(adv.id)
        seen = {self.first}
        self.aliases = [a for a in (norm_id(x) for x in adv.aliases) if a is not None
                        and not (a in seen or seen.add(a))]
        self.level = adv.level
        self.products = sorted({p.name for p in adv.products})
        self.key = hashlib.sha256(json.dumps(
            {"id": self.first, "aliases": sorted(self.aliases), "level": self.level, "products": self.products},
            sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def ids(self) -> list:
        return [self.first, *self.aliases]


def state_key(adv) -> str:
    """The published state a result was computed for: the first id, the
    aliases, the level and the product names."""
    return _Target(adv).key


# ------------------------------------------------------------------ the cache

def _empty(digest: str) -> dict:
    return {"version": 1, "ruleset": digest, "kev": None, "sources": {}, "results": {}}


def _well_formed(c, digest: str) -> bool:
    if not isinstance(c, dict) or set(c) != set(_empty(digest)) or c["version"] != 1 or c["ruleset"] != digest:
        return False

    def tag(v):
        return v is None or isinstance(v, str) and _ETAG.fullmatch(v) is not None

    def when(v):
        return type(v) is int and 0 <= v <= schema.MAX_TIMESTAMP

    k = c["kev"]
    if k is not None and not (isinstance(k, dict) and set(k) == {"etag", "at"} and tag(k["etag"]) and when(k["at"])):
        return False
    if not isinstance(c["sources"], dict) or not isinstance(c["results"], dict):
        return False
    for i, r in c["sources"].items():
        if norm_id(i) != i or not isinstance(r, dict) or set(r) != {"etag", "at", "lowers", "support", "names"} \
                or not tag(r["etag"]) or not when(r["at"]) or type(r["lowers"]) is not bool \
                or not isinstance(r["support"], dict) or not isinstance(r["names"], list) \
                or not all(isinstance(n, str) and _HEX.fullmatch(n) for n in r["names"]) \
                or not all(isinstance(n, str) and isinstance(s, list) and len(s) == 2 and s[0] in _LEVELS
                           and type(s[1]) is bool for n, s in r["support"].items()):
            return False
    for key, r in c["results"].items():
        if not (isinstance(key, str) and _HEX.fullmatch(key)) or not isinstance(r, dict) \
                or set(r) != {"at", "products"} or not when(r["at"]) or not isinstance(r["products"], dict):
            return False
        for name, p in r["products"].items():
            if not isinstance(name, str) or not isinstance(p, dict) or set(p) != {"result", "why", "source"} \
                    or p["result"] not in _WHYS or p["why"] not in _WHYS[p["result"]] \
                    or not (p["source"] is None or p["source"] in _LEVELS):
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
    """{product name: {result, why, source}} for a thread, from the cache
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
    def __init__(self, cache, rs, fetch, now, clock, wanted_cves):
        self.cache, self.rs, self.fetch, self.now, self.clock = cache, rs, fetch, now, clock
        self.start = clock()
        self.requests = 0
        self.exhausted = False
        self.memo: dict = {}  # id -> record or None, for this run
        self.kev_done = False
        self.wanted_cves = wanted_cves

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

    def _kev(self) -> None:
        """One request for the catalog serves every CVE id of the run."""
        self.kev_done = True
        sources, held = self.cache["sources"], self.cache["kev"]
        etag = held["etag"] if held else None
        if etag is None or any(sources.get(i, {}).get("etag") != etag for i in self.wanted_cves):
            etag = None  # an id not read at that ETag needs the body
        got = self._get(KEV_URL, etag, "kev")
        if got is None:
            return
        if got[0] == 304:
            self.memo.update((i, sources[i]) for i in self.wanted_cves)
            return
        try:
            readings = _kev_readings(got[2], self.wanted_cves)
        except _Bad:
            return
        tag = got[1] if isinstance(got[1], str) and _ETAG.fullmatch(got[1]) else None
        self.cache["kev"] = {"etag": tag, "at": self.now}
        for cve, rd in readings.items():
            try:
                self.memo[cve] = sources[cve] = _record(self.rs, "kev", rd, [], tag, self.now) if rd else None
            except (ruleset.RulesetError, TypeError):
                self.memo[cve] = None
            if self.memo[cve] is None:
                sources.pop(cve, None)

    def read(self, lookup_id: str) -> dict | None:
        """What is kept of this id's read, asked for at most once a run. None:
        the read failed or was not made. A stored record is never a fallback
        for a failed read; a 304 to its own ETag is the one way it is used."""
        if lookup_id in self.memo:
            return self.memo[lookup_id]
        source = ruleset.source_of(lookup_id)
        if source == "kev":
            if not self.kev_done:
                self._kev()
            return self.memo.setdefault(lookup_id, None)
        held = self.cache["sources"].get(lookup_id)
        got = self._get(url_of(lookup_id), held["etag"] if held else None, source)
        rec = None
        if got is not None and got[0] == 304:
            rec = held
        elif got is not None:
            try:
                fields, named = (_ghsa_reading if source == "ghsa" else _osv_reading)(got[2], lookup_id)
                rec = _record(self.rs, source, [fields], named, got[1], self.now)
                self.cache["sources"][lookup_id] = rec
            except (_Bad, ruleset.RulesetError, TypeError, AttributeError):
                rec = None
        self.memo[lookup_id] = rec
        return rec

    def thread(self, t: _Target) -> dict:
        """{product: result} for one thread. An alias counts only when a
        response ties it to the first id: the first id's names it, or its own
        names the first id."""
        records, complete = [], True
        first = self.read(t.first)
        if first is None:
            complete = False
        else:
            records.append(first)
            from_kev = ruleset.source_of(t.first) == "kev"
            eligible = [a for a in t.aliases if _digest(a) in first["names"]
                        or (from_kev and ruleset.source_of(a) != "kev")]
            complete = len(eligible) <= MAX_ALIASES
            for a in eligible[:MAX_ALIASES]:
                rec = self.read(a)
                if rec is None:
                    complete = False
                elif _digest(a) in first["names"] or _digest(t.first) in rec["names"]:
                    records.append(rec)
        return {p: judge(t.level, p, records, complete, self.rs) for p in t.products}


def run(current, wanted, state_dir, fetch=None, now: float | None = None, clock=time.monotonic, rs=None) -> dict:
    """Read the sources for the threads of ``wanted`` that need it and save
    the cache; returns it. ``current``: every current advisory (what the
    cache keeps); ``wanted``: the ones this run may read (all of them, or
    those matching this machine). A thread is read when its published state
    has no result yet, or a read it needed failed; highest level first, then
    longest untried. The state lock is not held: a pull must not wait."""
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
    waiting = [t for t in targets.values()
               if t.key not in results or set(results[t.key]["products"]) != set(t.products)
               or any(p["why"] == "unread" for p in results[t.key]["products"].values())]
    waiting.sort(key=lambda t: (-_RANK[t.level], results.get(t.key, {}).get("at", 0), t.key))
    cves = {i for t in waiting for i in t.ids() if ruleset.source_of(i) == "kev"}
    job = _Run(cache, rs, fetch, now, clock, cves)
    for t in waiting:
        products = job.thread(t)
        if job.exhausted:
            break  # not tried in full: what is left stays as it was
        results[t.key] = {"at": now, "products": products}
    live = [_Target(adv) for adv in current if adv.posted_by == BOT]
    keys, ids = {t.key for t in live}, {i for t in live if t.first is not None for i in t.ids()}
    cache["results"] = {k: v for k, v in results.items() if k in keys}
    cache["sources"] = {i: r for i, r in cache["sources"].items() if i in ids}
    write_json(Path(state_dir) / FILE, cache)
    return cache
