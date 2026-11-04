"""Normalize untrusted advisory inputs into one Candidate shape.

Three adapters feed the poster: the security-watch heartbeat's ``run.json``,
the CISA KEV JSON and the collector run record (schema_version 1). All input is
untrusted: unknown keys are ignored, wrong types are skipped and counted, and
nothing raises past an adapter. Private fleet detail (host names, evidence
paths, kata refs, owners, rationale text) never enters a Candidate.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# Generic fleet names, already public in the fleet's open repos. Each adapter adds
# the host names its own input record names.
FLEET_HOSTS = ("host-a", "host-b", "host-d", "host-e", "host-f", "host-c")
HOST_PLACEHOLDER = "a fleet host"

MAX_ID = 200
MAX_TEXT = 500
MAX_ALIASES = 32
MAX_SOURCES = 8

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?")
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")
_VERSION = re.compile(r"v?\d[0-9A-Za-z.+_-]{0,63}")
_VTOKEN = r"[<>=!~^]{0,2}\s*v?\d[0-9A-Za-z.+_*-]*"
_VERSION_RANGE = re.compile(rf"(?=.{{1,200}}$)\s*{_VTOKEN}(?:\s*(?:,|\|\||\s)\s*{_VTOKEN})*\s*")
# Local paths and kata refs: private fleet detail that must never reach a post.
_PRIVATE = re.compile(
    r"(?:^|[\s\"'(=:,;\[])(?:/Users/|/home/|/private/|/var/|/tmp/|/etc/|~/)"
    r"|\b[A-Za-z]:\\"
    r"|\b[a-z][a-z0-9-]*#[0-9a-z]{4}\b"
)
_PRIVATE_URL_PATH = re.compile(r"/(?:Users|home)/")
HINTS = frozenset({"critical", "high", "medium", "low", "none", "not_affected", "out_of_scope"})


@dataclass(frozen=True)
class Source:
    url: str
    published_at: str | None = None


@dataclass(frozen=True)
class Candidate:
    id: str
    aliases: tuple[str, ...]
    product_text: str
    advisory_severity: str | None
    local_level_hint: str | None
    exploited: bool
    trojanized: bool
    injection_exec: bool
    fixed: str | None
    affected: str | None
    sources: tuple[Source, ...]
    observed_at: str | None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["aliases"] = list(self.aliases)
        d["sources"] = [asdict(s) for s in self.sources]
        return d


class CandidateList(list):
    """A list of Candidates with a count of skipped input items by reason."""

    def __init__(self, *args):
        super().__init__(*args)
        self.skipped: Counter = Counter()


# ---------------------------------------------------------------- helpers


def _str(v, limit: int = MAX_TEXT) -> str | None:
    """A stripped, length-capped string, or None for anything else or empty."""
    if not isinstance(v, str):
        return None
    v = v.strip()
    return v[:limit] if v else None


def _flag(v) -> bool:
    return v is True


def _private(s: str | None) -> bool:
    return s is not None and bool(_PRIVATE.search(s))


def _text(v, limit: int = MAX_TEXT) -> str | None:
    """Free text with private content dropped."""
    s = _str(v, limit)
    return None if _private(s) else s


def _hint(v) -> str | None:
    s = _str(v)
    s = s.lower() if s else None
    return s if s in HINTS else None


def _timestamp(v) -> str | None:
    s = _str(v, 100)
    return s if s and _TIMESTAMP.fullmatch(s) else None


def _version(v, pattern) -> str | None:
    s = _str(v, 201)
    return s if s and pattern.fullmatch(s) else None


def _url(v) -> str | None:
    if not isinstance(v, str) or len(v) > 2000 or _BAD_URL_CHARS.search(v):
        return None
    try:
        parts = urlsplit(v)
        port_ok = parts.port is None or parts.port > 0
    except ValueError:
        return None
    if parts.scheme not in ("https", "http") or not parts.hostname or not port_ok:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if _PRIVATE_URL_PATH.search(parts.path) or _private(parts.query):
        return None
    return parts._replace(fragment="").geturl()


def _host_names(v) -> list[str]:
    """Host names from a hosts / affected_hosts value: strings or {host: ...}."""
    out = []
    if isinstance(v, str):
        out.append(v)
    elif isinstance(v, list):
        for h in v:
            if isinstance(h, str):
                out.append(h)
            elif isinstance(h, dict) and isinstance(h.get("host"), str):
                out.append(h["host"])
    return [h.strip() for h in out if h.strip()]


def _record_hosts(record: dict) -> set[str]:
    hosts = set(FLEET_HOSTS)
    cov = record.get("host_coverage")
    if isinstance(cov, list):
        for h in cov:
            if isinstance(h, dict):
                hosts.update(_host_names([h]))
    return hosts


def _finding_hosts(f: dict) -> set[str]:
    hosts = set()
    for key in ("hosts", "affected_hosts", "host"):
        hosts.update(_host_names(f.get(key)))
    return hosts


class _Scrubber:
    def __init__(self, hosts):
        names = sorted({h for h in hosts if h}, key=len, reverse=True)
        self._re = re.compile("|".join(re.escape(h) for h in names), re.I) if names else None

    def hit(self, s: str) -> bool:
        return bool(self._re and self._re.search(s))

    def text(self, s: str | None) -> str | None:
        if s is None or self._re is None:
            return s
        return self._re.sub(HOST_PLACEHOLDER, s)


def _aliases(values, exclude: str, scrub: _Scrubber) -> tuple[str, ...]:
    out: list[str] = []
    if not isinstance(values, list):
        return ()
    for a in values:
        a = _str(a, MAX_ID + 1)
        if a is None or len(a) > MAX_ID or a == exclude or a in out or scrub.hit(a) or _private(a):
            continue
        out.append(a)
        if len(out) >= MAX_ALIASES:
            break
    return tuple(out)


def _sources(raw: list, scrub: _Scrubber) -> tuple[Source, ...]:
    out: list[Source] = []
    for url, published in raw:
        url = _url(url)
        if url is None or scrub.hit(url) or any(s.url == url for s in out):
            continue
        out.append(Source(url, _timestamp(published)))
        if len(out) >= MAX_SOURCES:
            break
    return tuple(out)


def _build(cid, aliases, product, sources, f: dict, scrub: _Scrubber, out: CandidateList, *,
           exploited: bool = False, fixed: str | None = None, affected: str | None = None) -> None:
    """Shared tail: validate, scrub and append one candidate, or count a skip."""
    if cid is None or len(cid) > MAX_ID:
        out.skipped["no id"] += 1
        return
    if scrub.hit(cid) or _private(cid):
        out.skipped["id names a host or private detail"] += 1
        return
    product = scrub.text(product)
    if product is None or _private(product):
        out.skipped["no product"] += 1
        return
    if not sources:
        out.skipped["no source"] += 1
        return
    c = Candidate(
        id=cid,
        aliases=aliases,
        product_text=product,
        advisory_severity=scrub.text(_text(f.get("advisory_severity"))),
        local_level_hint=_hint(f.get("local_severity")),
        exploited=exploited,
        trojanized=_flag(f.get("trojanized")),
        injection_exec=_flag(f.get("injection_exec")),
        fixed=None if fixed is None or scrub.hit(fixed) else fixed,
        affected=None if affected is None or scrub.hit(affected) else affected,
        sources=sources,
        observed_at=_timestamp(f.get("observed_at")),
    )
    # Backstop: no field, present or future, may carry a host or private detail.
    blob = json.dumps(c.to_dict())
    if scrub.hit(blob) or _private(blob):
        out.skipped["private content"] += 1
        return
    out.append(c)


# ---------------------------------------------------------------- adapters


def from_heartbeat(run_dir: Path) -> CandidateList:
    """Candidates from a heartbeat run directory's ``run.json``."""
    out = CandidateList()
    try:
        record = json.loads((Path(run_dir) / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        out.skipped["run.json unreadable"] += 1
        return out
    if not isinstance(record, dict):
        out.skipped["run.json not an object"] += 1
        return out
    findings = record.get("findings")
    if isinstance(findings, dict):
        items = list(findings.items())
    elif isinstance(findings, list):
        items = [(None, f) for f in findings]
    else:
        out.skipped["findings not a dict or list"] += 1
        return out

    hosts = _record_hosts(record)
    for key, f in items:
        if isinstance(f, dict):
            hosts |= _finding_hosts(f)
        if isinstance(key, str):
            parts = key.split("|")
            hosts.update(p.strip() for p in parts[1:-1] if p.strip())
    scrub = _Scrubber(hosts)

    for key, f in items:
        if not isinstance(f, dict):
            out.skipped["finding not an object"] += 1
            continue
        parts = key.split("|") if isinstance(key, str) else []
        ids = [i.strip() for i in f.get("ids", []) if isinstance(i, str) and i.strip()] \
            if isinstance(f.get("ids"), list) else []
        cid = _str(f.get("id"), MAX_ID + 1) or (ids[0] if ids else None) \
            or (_str(parts[0], MAX_ID + 1) if parts else None)
        product = _str(f.get("product"))
        if product is None and len(parts) >= 3:
            product = _str(parts[-1])
        if product is None and isinstance(key, str) and len(parts) == 1 and key != cid:
            product = _str(key)
        if product is None:
            product = cid
        alias_in = (f.get("aliases") if isinstance(f.get("aliases"), list) else []) + ids
        sources = _sources([(f.get("source"), f.get("published_at"))], scrub)
        _build(cid, _aliases(alias_in, cid, scrub), product, sources, f, scrub, out)
    return out


def _date(v) -> str | None:
    if not isinstance(v, str) or not _DATE.fullmatch(v):
        return None
    try:
        _dt.date.fromisoformat(v)
    except ValueError:
        return None
    return v


def from_kev(kev_json: dict, since_date: str) -> CandidateList:
    """Candidates from CISA KEV entries added on or after ``since_date``.

    Accepts the CISA catalog (``vulnerabilities``) and the heartbeat's
    ``feeds.json`` ``cisa-kev`` block (``items``). ``since_date`` is the
    caller's own value: anything but ``YYYY-MM-DD`` raises ValueError.
    """
    if _date(since_date) is None:
        raise ValueError(f"since_date must be YYYY-MM-DD, got {since_date!r}")
    out = CandidateList()
    if not isinstance(kev_json, dict):
        out.skipped["kev not an object"] += 1
        return out
    items = kev_json.get("vulnerabilities", kev_json.get("items"))
    if not isinstance(items, list):
        out.skipped["kev items not a list"] += 1
        return out
    scrub = _Scrubber(FLEET_HOSTS)
    for it in items:
        if not isinstance(it, dict):
            out.skipped["kev item not an object"] += 1
            continue
        cve = it.get("cveID")
        if not isinstance(cve, str) or not _CVE.fullmatch(cve) or len(cve) > MAX_ID:
            out.skipped["bad cveID"] += 1
            continue
        added = _date(it.get("dateAdded"))
        if added is None:
            out.skipped["bad dateAdded"] += 1
            continue
        if added < since_date:
            continue
        vendor, product = _str(it.get("vendorProject")), _str(it.get("product"))
        if vendor is None or product is None:
            out.skipped["no product"] += 1
            continue
        raw = [(KEV_CATALOG_URL, added)]
        notes = it.get("notes")
        if isinstance(notes, str):
            raw += [(tok.strip(), None) for tok in re.split(r"[;\s]+", notes[:5000]) if tok.strip()]
        f = {"observed_at": added}
        _build(cve, (), f"{vendor} {product}", _sources(raw, scrub), f, scrub, out, exploited=True)
    return out


def from_collector(record: dict) -> CandidateList:
    """Candidates from a collector run record (schema_version 1)."""
    out = CandidateList()
    if not isinstance(record, dict) or record.get("schema_version") != 1 \
            or isinstance(record.get("schema_version"), bool):
        out.skipped["schema_version"] += 1
        return out
    findings = record.get("findings")
    if not isinstance(findings, list):
        out.skipped["findings not a list"] += 1
        return out
    hosts = _record_hosts(record)
    for f in findings:
        if isinstance(f, dict):
            hosts |= _finding_hosts(f)
    scrub = _Scrubber(hosts)
    for f in findings:
        if not isinstance(f, dict):
            out.skipped["finding not an object"] += 1
            continue
        cid = _str(f.get("id"), MAX_ID + 1)
        raw = []
        if isinstance(f.get("sources"), list):
            raw = [(s.get("url"), s.get("published_at")) for s in f["sources"] if isinstance(s, dict)]
        _build(cid, _aliases(f.get("aliases"), cid, scrub), _str(f.get("product")),
               _sources(raw, scrub), f, scrub, out,
               fixed=_version(f.get("fixed"), _VERSION),
               affected=_version(f.get("affected"), _VERSION_RANGE))
    return out
