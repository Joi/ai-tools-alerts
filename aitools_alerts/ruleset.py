"""The level of an alert as a function of structured source fields (s6mt).

One module for the poster and the member CLI: it imports nothing from
``aitools_alerts.poster``. ``spec/ruleset.json`` holds the level table, the TTL per
level and the authoritative-source table; ``spec/scope.json`` binds a source's
package or KEV name to a product by exact identity. Both files are inside one
digest, which the trust root pins.

A reading is ``(source, fields)``: what one of three sources states about one
advisory id, as typed fields and nothing else. ``Ruleset.level(readings, product)``
is the level those readings support for that product, or ``NONE``. A claim is the
tuple a poster signs, ``{id, source, fields, ruleset, level, confirmed_at,
checked_at}``; ``canonical`` is its byte form and ``check_claim`` the offline check:
this reader's own ruleset must give the claim's level for the claim's fields.
No function here fetches anything, and no string of a reading is ever printed.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace

from . import schema

__all__ = ["VERSION", "NONE", "RulesetError", "Support", "Ruleset", "Pin", "load", "canonical",
           "parse_claim", "parse_pin", "check_claim", "source_of", "ordered",
           "norm", "tier_of", "index"]

VERSION = 1  # the only ruleset version this reader evaluates
NONE = "none"  # no reading supports the product: unlisted, withdrawn or not bound
SOURCES = ("kev", "ghsa", "osv")
MAX_INT = 2**53 - 1
MAX_TEXT = 1001  # kev.name: two fields of 500 and a space
MAX_LIST = 50
_CLAIM_KEYS = frozenset({"id", "source", "fields", "ruleset", "level", "confirmed_at", "checked_at"})
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
_GHSA = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}")
_OSV = re.compile(r"[A-Za-z][A-Za-z0-9]{0,15}-[A-Za-z0-9][A-Za-z0-9._:-]{0,95}")
_CWE = re.compile(r"CWE-[0-9]{1,6}")
_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}/[a-z0-9._-]{1,100}")
_ECOSYSTEM = re.compile(r"[a-z0-9][a-z0-9-]{0,31}|")
_CVSS = re.compile(r"CVSS:(?:3\.0|3\.1|4\.0)(?:/[A-Za-z]{1,4}:[A-Za-z]{1,4}){1,40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GHSA_TYPES = frozenset({"reviewed", "unreviewed", "malware"})
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_PACKAGE_KEYS = frozenset({"ecosystem", "name", "range", "first_patched"})
_SOURCE_WHEN = frozenset({"type", "vendor_own", "id_prefix"})
_RULE_WHEN = frozenset({"tier", "cwe_any", "severity_in", "cvss_av", "patched"})
_TOP_KEYS = frozenset({"version", "description", "levels", "ttl_days", "tier_cap", "reading_cap",
                       "fields", "sources", "rules"})
_FIELDS = {"kev": ("cve_id", "name"),
           "ghsa": ("ghsa_id", "type", "withdrawn_at", "repository", "severity", "cvss_vector", "cwes", "packages"),
           "osv": ("osv_id", "withdrawn", "packages")}
_DASHES = re.compile("[‐-―−]")
_SPACES = re.compile(r"\s+")


class RulesetError(ValueError):
    """A ruleset, a reading, a claim or a pin is malformed."""


def _fail(why: str):
    raise RulesetError(why)


# ------------------------------------------------------------------ scope identity

def norm(text: str) -> str:
    """NFKC, lowercase, Unicode dashes to "-", whitespace runs to one space, so
    compatibility characters and spacing cannot dodge an identity."""
    return _SPACES.sub(" ", _DASHES.sub("-", unicodedata.normalize("NFKC", text).lower()))


def tier_of(entry) -> int | None:
    t = getattr(entry, "tier", None)
    return t if type(t) is int and t in (1, 2) else None


def index(entries) -> dict[str, schema.ScopeEntry]:
    """{identity: the entry, resolved to its component where the identity is one}. A
    resolved component carries its own name and identities, its own authority or the
    entry's, and no components: the product a post names and the ledger keys."""
    out: dict[str, schema.ScopeEntry] = {}
    for e in entries:
        if tier_of(e) is None:
            continue
        for c in getattr(e, "components", ()):
            own = c.authority if getattr(c, "authority", None) is not None else e.authority
            hit = replace(e, name=c.name, match=list(c.match), authority=tuple(own), components=())
            for m in c.match:
                out.setdefault(norm(m).strip(), hit)
        whole = replace(e, components=())
        for m in e.match:
            out.setdefault(norm(m).strip(), whole)
    return out


# ------------------------------------------------------------------ canonical form

def _plain(v, depth: int = 0) -> None:
    """Refuse anything the canonical form does not define: a float, a non-NFC or
    control-bearing string, a non-ASCII key, an integer JSON readers disagree on."""
    if v is None or type(v) is bool:
        return
    if type(v) is int:
        if abs(v) > MAX_INT:
            _fail("an integer outside the exact range")
        return
    if type(v) is str:
        if not unicodedata.is_normalized("NFC", v) or any(unicodedata.category(c)[0] == "C" for c in v):
            _fail("a string that is not NFC or carries a control character")
        return
    if depth >= 12:  # a claim nests 4 deep; the digest's input (the scope file) 8
        _fail("nested too deeply")
    if type(v) is list:
        for x in v:
            _plain(x, depth + 1)
        return
    if type(v) is dict:
        for k, x in v.items():
            if type(k) is not str or not k.isascii() or not k:
                _fail("an object key that is not ASCII text")
            _plain(k)
            _plain(x, depth + 1)
        return
    _fail(f"a value of type {type(v).__name__}")


def canonical(obj) -> bytes:
    """The one byte form of a claim (or of any object the digest covers): keys sorted
    by code point at every depth, no whitespace, non-ASCII literal, UTF-8."""
    _plain(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------ readings

def source_of(advisory_id) -> str | None:
    """The source an advisory id is looked up in: its shape decides, never a URL."""
    if not isinstance(advisory_id, str):
        return None
    if _CVE.fullmatch(advisory_id):
        return "kev"
    if _GHSA.fullmatch(advisory_id):
        return "ghsa"
    if _OSV.fullmatch(advisory_id) and not advisory_id.upper().startswith(("CVE-", "GHSA-")):
        return "osv"
    return None


def _opt_text(v, what: str, limit: int = MAX_TEXT):
    if v is not None and not (type(v) is str and 1 <= len(v) <= limit and v == v.strip()):
        _fail(f"{what} must be null or trimmed text of at most {limit} characters")
    return v


def _packages(v) -> list[dict]:
    if type(v) is not list or len(v) > MAX_LIST:
        _fail(f"packages must be a list of at most {MAX_LIST}")
    for p in v:
        if type(p) is not dict or set(p) != _PACKAGE_KEYS:
            _fail(f"a package must have exactly the keys {sorted(_PACKAGE_KEYS)}")
        if type(p["ecosystem"]) is not str or not _ECOSYSTEM.fullmatch(p["ecosystem"]):
            _fail("package ecosystem must be lowercase or empty")
        if _opt_text(p["name"], "package name", 214) is None or ":" in p["name"] and not p["ecosystem"]:
            _fail("package name must be text; a name with ':' needs its ecosystem")
        _opt_text(p["range"], "package range", 200)
        _opt_text(p["first_patched"], "package first_patched", 100)
    keys = [(p["ecosystem"], p["name"], p["range"] or "", p["first_patched"] or "") for p in v]
    if keys != sorted(set(keys)):
        _fail("packages must be sorted by ecosystem, name, range, first_patched, each listed once")
    return v


def ordered(packages) -> list[dict]:
    """A builder's packages in the one canonical order, an entry stated twice kept once."""
    seen = {(p["ecosystem"], p["name"], p["range"] or "", p["first_patched"] or ""): p for p in packages}
    return [seen[k] for k in sorted(seen)]


def _reading(source, fields) -> dict:
    """The fields of one reading, checked against the source's exact key set and types."""
    if source not in SOURCES:
        _fail(f"source must be one of {list(SOURCES)}")
    if type(fields) is not dict or tuple(sorted(fields)) != tuple(sorted(_FIELDS[source])):
        _fail(f"{source} fields must be exactly {list(_FIELDS[source])}")
    _plain(fields)
    f = fields
    if source == "kev":
        if type(f["cve_id"]) is not str or not _CVE.fullmatch(f["cve_id"]):
            _fail("cve_id must be a CVE id")
        _opt_text(f["name"], "name")
    elif source == "ghsa":
        if type(f["ghsa_id"]) is not str or not _GHSA.fullmatch(f["ghsa_id"]):
            _fail("ghsa_id must be a GHSA id (GHSA- then lowercase)")
        if f["type"] is not None and f["type"] not in _GHSA_TYPES:
            _fail(f"type must be null or one of {sorted(_GHSA_TYPES)}")
        _opt_text(f["withdrawn_at"], "withdrawn_at", 40)
        if f["repository"] is not None and not (type(f["repository"]) is str and _REPOSITORY.fullmatch(f["repository"])):
            _fail("repository must be null or owner/repo in lowercase")
        if f["severity"] is not None and f["severity"] not in _SEVERITIES:
            _fail(f"severity must be null or one of {sorted(_SEVERITIES)}")
        if f["cvss_vector"] is not None and not (type(f["cvss_vector"]) is str and _CVSS.fullmatch(f["cvss_vector"])):
            _fail("cvss_vector must be null or a CVSS 3.0, 3.1 or 4.0 vector")
        c = f["cwes"]
        if type(c) is not list or len(c) > MAX_LIST or any(type(x) is not str or not _CWE.fullmatch(x) for x in c) \
                or c != sorted(set(c)):
            _fail("cwes must be a sorted list of distinct CWE-<n>")
        _packages(f["packages"])
    else:
        if source_of(f["osv_id"]) != "osv":
            _fail("osv_id must be an OSV id that is not a CVE or GHSA id")
        _opt_text(f["withdrawn"], "withdrawn", 40)
        _packages(f["packages"])
    return f


def _id_of(source: str, fields: dict) -> str:
    return fields[{"kev": "cve_id", "ghsa": "ghsa_id", "osv": "osv_id"}[source]]


def _attack_vector(vector) -> str | None:
    if not isinstance(vector, str):
        return None
    hits = [p[3:] for p in vector.split("/")[1:] if p.startswith("AV:")]
    return hits[0] if len(hits) == 1 else None


# ------------------------------------------------------------------ the ruleset

@dataclass(frozen=True)
class Support:
    """What one reading gives one product. ``level`` is NONE for a withdrawn reading.
    ``lowers``: a change or withdrawal of this source may justify a lowering."""
    level: str
    cls: str
    tier: int
    lowers: bool


class Ruleset:
    """``data`` is spec/ruleset.json decoded, ``scope`` spec/scope.json decoded and
    ``entries`` its validated entries (``schema.load_scope``). Anything this reader
    does not know (a version, a key, a condition, a level) is refused whole."""

    def __init__(self, data, scope, entries):
        if type(data) is not dict or set(data) != _TOP_KEYS:
            _fail(f"a ruleset must have exactly the keys {sorted(_TOP_KEYS)}")
        if type(data["version"]) is not int or data["version"] != VERSION:
            _fail(f"ruleset version must be {VERSION}")
        levels = data["levels"]
        if levels != ["notice", "high", "critical"]:
            _fail('levels must be ["notice", "high", "critical"]')
        self.version: int = data["version"]
        self.levels: tuple[str, ...] = tuple(levels)
        self._rank = {NONE: -1, **{name: i for i, name in enumerate(levels)}}
        ttl = data["ttl_days"]
        if type(ttl) is not dict or set(ttl) != set(levels) \
                or any(type(d) is not int or not 1 <= d <= 3650 for d in ttl.values()):
            _fail("ttl_days must give each level 1..3650 days")
        self.ttl_days: dict[str, int] = dict(ttl)
        cap = data["tier_cap"]
        if type(cap) is not dict or set(cap) != {"1", "2"} or any(v not in levels for v in cap.values()):
            _fail("tier_cap must give tiers 1 and 2 a level")
        self._tier_cap = {int(k): v for k, v in cap.items()}
        if data["reading_cap"] not in ("notice", "high"):
            _fail("reading_cap must be notice or high: a reading never makes a critical")
        self.reading_cap: str = data["reading_cap"]
        if data["fields"] != {s: list(k) for s, k in _FIELDS.items()}:
            _fail("fields must list each source's keys as this reader knows them")
        self._sources = [self._source_row(r) for r in self._rows(data["sources"], "sources")]
        classes = [r["class"] for r in self._sources]
        if len(set(classes)) != len(classes) or \
                {r["source"] for r in self._sources if not r["when"]} != set(SOURCES):
            _fail("sources must name each class once and end every source with a row that has no condition")
        self._rules = [self._rule_row(r, set(classes)) for r in self._rows(data["rules"], "rules")]
        self._index = index(entries)
        self.digest: str = hashlib.sha256(canonical({"ruleset": data, "scope": scope})).hexdigest()

    @staticmethod
    def _rows(v, what: str) -> list:
        if type(v) is not list or not 1 <= len(v) <= 100 or any(type(r) is not dict for r in v):
            _fail(f"{what} must be a list of 1..100 objects")
        return v

    def _source_row(self, r: dict) -> dict:
        need = {"class", "source", "alone", "lowers"}
        if not need <= set(r) <= need | {"when"}:
            _fail("a sources row has unknown or missing keys")
        when = r.get("when", {})
        if type(r["class"]) is not str or r["source"] not in SOURCES or r["alone"] not in self.levels \
                or type(r["lowers"]) is not bool \
                or type(when) is not dict or not set(when) <= _SOURCE_WHEN:
            _fail(f"sources row {r.get('class')!r} is malformed or has an unknown condition")
        if "type" in when and when["type"] not in _GHSA_TYPES or "vendor_own" in when and when["vendor_own"] is not True \
                or "id_prefix" in when and not (type(when["id_prefix"]) is str and when["id_prefix"]):
            _fail(f"sources row {r['class']!r} has a malformed condition")
        if not r["lowers"] and r["alone"] != "notice":
            _fail("a source that cannot lower is attacker-writable: it sets notice at most")
        return dict(r, when=dict(when))

    def _rule_row(self, r: dict, classes: set) -> dict:
        when = r.get("when", {})
        if not {"class", "level"} <= set(r) <= {"class", "level", "when"} or r["class"] not in classes \
                or r["level"] not in self.levels or type(when) is not dict or not set(when) <= _RULE_WHEN:
            _fail(f"rules row {r.get('class')!r} is malformed or has an unknown condition")
        for key in ("tier", "cwe_any", "severity_in", "cvss_av"):
            v = when.get(key, ["x"] if key != "tier" else [1])
            if type(v) is not list or not v or any(type(x) is not (int if key == "tier" else str) for x in v):
                _fail(f"rules row {r['class']!r}: {key} must be a non-empty list")
        if when.get("patched", True) is not True:
            _fail(f"rules row {r['class']!r}: patched must be true")
        return dict(r, when=dict(when))

    # -------------------------------------------------------------- evaluation

    def rank(self, level: str) -> int:
        return self._rank[level]

    def highest(self, *levels: str) -> str:
        return max(levels, key=self.rank)

    def capped(self, level: str, tier: int) -> str:
        """level, held to what the product's scope tier may reach."""
        return min(level, self._tier_cap[tier], key=self.rank)

    def class_level(self, cls: str, tier: int) -> str:
        """The level a live reading of ``cls`` gives a product of ``tier`` when no
        field condition applies (the KEV row: listed is all it states)."""
        row = next(r for r in self._sources if r["class"] == cls)
        rule = next((r for r in self._rules if r["class"] == cls and set(r["when"]) <= {"tier"}
                     and tier in r["when"].get("tier", [tier])), None)
        level = rule["level"] if rule else "notice"
        return self.capped(min(level, row["alone"], key=self.rank), tier)

    def _bound(self, source: str, f: dict) -> dict:
        """{product name: (scope entry, its packages in this reading)}."""
        out: dict = {}
        if source == "kev":
            hit = self._index.get(norm(f["name"]).strip()) if f["name"] is not None else None
            return {hit.name: (hit, [])} if hit is not None else {}
        for p in f["packages"]:
            key = f"{p['ecosystem']}:{p['name']}" if p["ecosystem"] else p["name"]
            hit = self._index.get(norm(key).strip())
            if hit is not None:
                out.setdefault(hit.name, (hit, []))[1].append(p)
        return out

    def _source_matches(self, row: dict, source: str, f: dict, entry) -> bool:
        when = row["when"]
        if row["source"] != source:
            return False
        if "type" in when and f.get("type") != when["type"]:
            return False
        if "vendor_own" in when and (f.get("repository") is None
                                     or f"github.com/{f['repository']}/" not in entry.authority):
            return False
        return "id_prefix" not in when or _id_of(source, f).startswith(when["id_prefix"])

    def _rule_matches(self, when: dict, f: dict, tier: int, packages: list) -> bool:
        if "tier" in when and tier not in when["tier"]:
            return False
        if "cwe_any" in when and not set(when["cwe_any"]) & set(f.get("cwes") or ()):
            return False
        if "severity_in" in when and f.get("severity") not in when["severity_in"]:
            return False
        if "cvss_av" in when and _attack_vector(f.get("cvss_vector")) not in when["cvss_av"]:
            return False
        return "patched" not in when or any(p["first_patched"] is not None for p in packages)

    def read(self, source, fields) -> dict[str, Support]:
        """{product name: Support} for one reading; {} when it binds no scope product
        (another vendor's product, an unlisted CVE). RulesetError when it is malformed."""
        f = _reading(source, fields)
        withdrawn = source != "kev" and f["withdrawn_at" if source == "ghsa" else "withdrawn"] is not None
        out = {}
        for name, (entry, packages) in self._bound(source, f).items():
            tier = tier_of(entry)
            row = next(r for r in self._sources if self._source_matches(r, source, f, entry))
            level = next((r["level"] for r in self._rules if r["class"] == row["class"]
                          and self._rule_matches(r["when"], f, tier, packages)), "notice")
            level = self.capped(min(level, row["alone"], key=self.rank), tier)
            out[name] = Support(level=NONE if withdrawn else level, cls=row["class"], tier=tier,
                                lowers=row["lowers"])
        return out

    def level(self, readings, product: str) -> str:
        """The level the readings support for ``product``: the highest any one of them
        gives, NONE when none supports it. Nothing adds up: two readings never make
        a level neither makes alone."""
        live = [s for source, fields in readings
                if (s := self.read(source, fields).get(product)) is not None and s.level != NONE]
        if not live:
            return NONE
        return self.highest(*(s.level for s in live))

    def claim(self, source, fields, product: str, confirmed_at: int, checked_at: int) -> dict:
        """The claim for one reading about ``product``: its level is this ruleset's."""
        level = self.level([(source, fields)], product)
        return parse_claim({"id": _id_of(source, fields), "source": source, "fields": fields,
                            "ruleset": self.version, "level": level,
                            "confirmed_at": confirmed_at, "checked_at": checked_at})


@functools.lru_cache(maxsize=1)
def load() -> Ruleset:
    """This reader's own ruleset: spec/ruleset.json over spec/scope.json."""
    return Ruleset(schema._load_json(schema.SPEC_DIR / "ruleset.json"),
                   schema._load_json(schema.SPEC_DIR / "scope.json"), schema.load_scope())


# ------------------------------------------------------------------ claims and the pin

def parse_claim(obj) -> dict:
    """obj when it is a well-formed claim; RulesetError otherwise. Checks the shape,
    not the level: ``check_claim`` does that."""
    if type(obj) is not dict or set(obj) != _CLAIM_KEYS:
        _fail(f"a claim must have exactly the keys {sorted(_CLAIM_KEYS)}")
    _reading(obj["source"], obj["fields"])
    if obj["id"] != _id_of(obj["source"], obj["fields"]) or source_of(obj["id"]) != obj["source"]:
        _fail("a claim's id must be its fields' id, of the shape its source is looked up by")
    if type(obj["ruleset"]) is not int or not 1 <= obj["ruleset"] <= MAX_INT:
        _fail("ruleset must be a positive integer version")
    if obj["level"] not in (NONE, "notice", "high", "critical"):
        _fail("level must be critical, high, notice or none")
    c, k = obj["confirmed_at"], obj["checked_at"]
    if type(c) is not int or type(k) is not int or not 0 <= c <= k <= schema.MAX_TIMESTAMP:
        _fail("confirmed_at and checked_at must be Unix seconds, confirmed_at not after checked_at")
    return obj


@dataclass(frozen=True)
class Pin:
    """The ruleset the trust root pins: its version and digest, and the lowest
    version a claim may name."""
    version: int
    sha256: str
    min_version: int


def parse_pin(obj) -> Pin:
    if type(obj) is not dict or set(obj) != {"version", "sha256", "min_version"}:
        _fail("a ruleset pin must have exactly the keys version, sha256, min_version")
    v, m, h = obj["version"], obj["min_version"], obj["sha256"]
    if type(v) is not int or type(m) is not int or not 1 <= m <= v <= MAX_INT:
        _fail("pin versions must be integers with 1 <= min_version <= version")
    if type(h) is not str or not _SHA256.fullmatch(h):
        _fail("pin sha256 must be 64 lowercase hex characters")
    return Pin(version=v, sha256=h, min_version=m)


def check_claim(claim, product: str, pin: Pin | None = None, rs: Ruleset | None = None) -> str:
    """The offline check of a claim about ``product``. One of:

    ``outdated``: this reader's ruleset is below the pin's ``min_version``, or is the
    pinned version with another digest. It judges nothing; say "out of date".
    ``refused``: the claim is malformed, or names a ruleset below ``min_version``.
    ``unknown``: the claim names a ruleset newer than this reader's; say "upgrade".
    ``mismatch``: this reader's ruleset gives the claim's fields another level.
    ``ok``: it gives the claim's level.

    The reader computes with its own ruleset, never the one the claim names, so a
    claim citing an older rule under which the level was lower is a mismatch.
    """
    rs = rs or load()
    if pin is not None and (rs.version < pin.min_version
                            or rs.version == pin.version and rs.digest != pin.sha256):
        return "outdated"
    try:
        claim = parse_claim(claim)
    except RulesetError:
        return "refused"
    if pin is not None and claim["ruleset"] < pin.min_version:
        return "refused"
    if claim["ruleset"] > rs.version:
        return "unknown"
    return "ok" if rs.level([(claim["source"], claim["fields"])], product) == claim["level"] else "mismatch"
