"""Normalize untrusted advisory inputs into one Candidate shape.

Three adapters feed the poster: the security-watch heartbeat's ``run.json``,
the CISA KEV JSON and the collector run record (schema_version 1). All input is
untrusted: unknown keys are ignored, wrong types are skipped and counted, and
nothing raises past an adapter. Private fleet detail (host names, local paths,
kata refs) never enters a Candidate: a text field that carries one is dropped,
and an id, product or source URL that carries one drops the item.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# Generic fleet names, already public in the fleet's open repos. Each adapter adds
# the host names its own input record names.
FLEET_HOSTS = ("host-a", "host-b", "host-d", "host-e", "host-f", "host-c")

MAX_RUN_BYTES = 16 * 1024 * 1024
MAX_ID = 200
MAX_TEXT = 500
MAX_ALIASES = 32
MAX_SOURCES = 8

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?")
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")
# A concrete release: digits first, no wildcard component ("1.x", "2.*").
_VERSION = re.compile(r"v?\d[0-9A-Za-z.+_-]{0,63}")
_WILDCARD = re.compile(r"(?:^|[.\-+_])[xX*](?:$|[.\-+_])")
# One token of a version range; ranges are split before matching, so no regex
# below has nested or adjacent unbounded repeats (no catastrophic backtracking).
_RANGE_TOKEN = re.compile(r"[<>=!~^]{0,2}v?\d[0-9A-Za-z.+_*-]{0,63}")
_RANGE_SPLIT = re.compile(r",|\|\||\s+")
_OP_SPACE = re.compile(r"([<>=!~^]{1,2}) +")
# Local paths and kata refs, matched anywhere (markdown or quotes around them do
# not hide them). Over-matching drops a field, which is the safe failure.
_PRIVATE = re.compile(
    r"/Users/|/home/|/private/|/var/|/tmp/|/etc/|~/"
    r"|\b[A-Za-z]:\\"
    r"|\b[a-z][a-z0-9-]*#[0-9a-z]{4}\b",
    re.I,
)
# Source hosts that only resolve inside a network: never a public advisory.
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".home.arpa", ".ts.net", ".vm.example", ".localhost")
_PRIVATE_URL_PATH = re.compile(r"/(?:Users|home)/|~/")
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
    v = v.strip()[:limit]
    # Control, format (bidi overrides) and lone surrogate characters never reach a post.
    if not v or any(unicodedata.category(ch) in ("Cc", "Cf", "Cs") for ch in v):
        return None
    return v


def _flag(v) -> bool:
    return v is True


def _private(s: str | None) -> bool:
    return s is not None and bool(_PRIVATE.search(s))


def _hint(v) -> str | None:
    s = _str(v)
    s = s.lower() if s else None
    return s if s in HINTS else None


def _timestamp(v) -> str | None:
    s = _str(v, 100)
    if not s or not _TIMESTAMP.fullmatch(s):
        return None
    try:
        _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return s


def _fixed(v) -> str | None:
    s = _str(v, 65)
    if not s or not _VERSION.fullmatch(s) or _WILDCARD.search(s):
        return None
    return s


def _affected(v) -> str | None:
    s = _str(v, 201)
    if not s or len(s) > 200:
        return None
    tokens = [t for t in _RANGE_SPLIT.split(_OP_SPACE.sub(r"\1", s)) if t]
    if not tokens or not all(_RANGE_TOKEN.fullmatch(t) for t in tokens):
        return None
    return s


def _decoded(s: str) -> str:
    """Percent-decode until stable (bounded), so encoded names are seen."""
    for _ in range(3):
        d = unquote(s)
        if d == s:
            break
        s = d
    return s


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
    if _internal_host(parts.hostname):
        return None
    parts = parts._replace(fragment="")
    if _url_private(parts.geturl()):
        return None
    return parts.geturl()


def _internal_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return "." not in host or host == "localhost" or host.endswith(_INTERNAL_SUFFIXES)


def _url_private(url: str) -> bool:
    # Split first, then decode each part: a decoded %23 must not hide in a fragment.
    parts = urlsplit(url)
    path, query = _decoded(parts.path), _decoded(parts.query)
    return bool(_PRIVATE_URL_PATH.search(path)) or _private(query) or _private(path)


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
    elif isinstance(v, dict) and isinstance(v.get("host"), str):
        out.append(v["host"])
    return [h.strip() for h in out if h.strip()]


def _record_hosts(record: dict) -> set[str]:
    hosts = set(FLEET_HOSTS)
    hosts.update(_host_names(record.get("host_coverage")))
    return hosts


def _finding_hosts(f: dict) -> set[str]:
    hosts = set()
    for key in ("hosts", "affected_hosts", "host"):
        hosts.update(_host_names(f.get(key)))
    return hosts


class _Hosts:
    """Case-insensitive host-name detector; checks percent-decoded text too."""

    def __init__(self, hosts):
        names = sorted({h for h in hosts if h}, key=len, reverse=True)
        self._re = re.compile("|".join(re.escape(h) for h in names), re.I) if names else None

    def hit(self, s: str) -> bool:
        return bool(self._re and (self._re.search(s) or self._re.search(_decoded(s))))


def _clean(s: str | None, hosts: _Hosts) -> str | None:
    """A text field, or None when it names a host or carries private detail."""
    if s is None or hosts.hit(s) or _private(s) or _private(_decoded(s)):
        return None
    return s


def _aliases(values, exclude: str, hosts: _Hosts) -> tuple[str, ...]:
    out: list[str] = []
    if not isinstance(values, list):
        return ()
    for a in values:
        a = _clean(_str(a, MAX_ID + 1), hosts)
        if a is None or len(a) > MAX_ID or a == exclude or a in out:
            continue
        out.append(a)
        if len(out) >= MAX_ALIASES:
            break
    return tuple(out)


def _sources(raw: list, hosts: _Hosts) -> tuple[Source, ...]:
    out: list[Source] = []
    for url, published in raw:
        url = _url(url)
        if url is None or hosts.hit(url) or any(s.url == url for s in out):
            continue
        out.append(Source(url, _timestamp(published)))
        if len(out) >= MAX_SOURCES:
            break
    return tuple(out)


def _build(cid, aliases, product, sources, f: dict, hosts: _Hosts, out: CandidateList, *,
           exploited: bool = False, fixed: str | None = None, affected: str | None = None) -> None:
    """Shared tail: validate and append one candidate, or count a skip."""
    if cid is None or len(cid) > MAX_ID:
        out.skipped["no id"] += 1
        return
    if _clean(cid, hosts) is None:
        out.skipped["id names a host or private detail"] += 1
        return
    if _clean(product, hosts) is None:
        out.skipped["no product"] += 1
        return
    if not sources:
        out.skipped["no source"] += 1
        return
    c = Candidate(
        id=cid,
        aliases=aliases,
        product_text=product,
        advisory_severity=_clean(_str(f.get("advisory_severity")), hosts),
        local_level_hint=_hint(f.get("local_severity")),
        exploited=exploited,
        trojanized=_flag(f.get("trojanized")),
        injection_exec=_flag(f.get("injection_exec")),
        fixed=_clean(fixed, hosts),
        affected=_clean(affected, hosts),
        sources=sources,
        observed_at=_timestamp(f.get("observed_at")),
    )
    # Backstop: no field, present or future, may carry a host or private detail.
    d = c.to_dict()
    urls = [s.pop("url") for s in d["sources"]]
    blob = json.dumps(d, ensure_ascii=False)
    if hosts.hit(blob) or _private(blob) or any(hosts.hit(u) or _url_private(u) for u in urls):
        out.skipped["private content"] += 1
        return
    out.append(c)


def _each(items, out: CandidateList, fn) -> CandidateList:
    """Run fn per item; an unexpected error skips that item, never the call."""
    for item in items:
        try:
            fn(item)
        except Exception:  # untrusted input must never raise past the adapter
            out.skipped["item error"] += 1
    return out


# ---------------------------------------------------------------- adapters


def from_heartbeat(run_dir: Path) -> CandidateList:
    """Candidates from a heartbeat run directory's ``run.json``."""
    out = CandidateList()
    try:
        path = Path(run_dir) / "run.json"
        if path.stat().st_size > MAX_RUN_BYTES:
            out.skipped["run.json too large"] += 1
            return out
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, RecursionError):
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

    names = _record_hosts(record)
    for key, f in items:
        if isinstance(f, dict):
            names |= _finding_hosts(f)
        if isinstance(key, str):
            # <id>|<host>|<component>, or <id>|<host>: every segment after the id
            # but the component is treated as a host (over-scrubbing is safe).
            segs = key.split("|")
            names.update(p.strip() for p in (segs[1:] if len(segs) == 2 else segs[1:-1]) if p.strip())
    hosts = _Hosts(names)

    def one(item):
        key, f = item
        if not isinstance(f, dict):
            out.skipped["finding not an object"] += 1
            return
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
        sources = _sources([(f.get("source"), f.get("published_at"))], hosts)
        # fixed/affected stay None: heartbeat records mix in host-observed versions.
        _build(cid, _aliases(alias_in, cid, hosts), product, sources, f, hosts, out)

    return _each(items, out, one)


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
    hosts = _Hosts(FLEET_HOSTS)

    def one(it):
        if not isinstance(it, dict):
            out.skipped["kev item not an object"] += 1
            return
        cve = it.get("cveID")
        if not isinstance(cve, str) or len(cve) > MAX_ID or not _CVE.fullmatch(cve):
            out.skipped["bad cveID"] += 1
            return
        added = _date(it.get("dateAdded"))
        if added is None:
            out.skipped["bad dateAdded"] += 1
            return
        if added < since_date:
            return
        vendor, product = _str(it.get("vendorProject")), _str(it.get("product"))
        if vendor is None or product is None:
            out.skipped["no product"] += 1
            return
        raw = [(KEV_CATALOG_URL, added)]
        notes = it.get("notes")
        if isinstance(notes, str):
            raw += [(tok, None) for tok in re.split(r"[;\s]+", notes[:5000]) if tok]
        _build(cve, (), f"{vendor} {product}", _sources(raw, hosts), {"observed_at": added},
               hosts, out, exploited=True)

    return _each(items, out, one)


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
    names = _record_hosts(record)
    for f in findings:
        if isinstance(f, dict):
            names |= _finding_hosts(f)
    hosts = _Hosts(names)

    def one(f):
        if not isinstance(f, dict):
            out.skipped["finding not an object"] += 1
            return
        cid = _str(f.get("id"), MAX_ID + 1)
        raw = []
        if isinstance(f.get("sources"), list):
            raw = [(s.get("url"), s.get("published_at")) for s in f["sources"] if isinstance(s, dict)]
        # exploited is ignored here: only from_kev establishes KEV membership.
        _build(cid, _aliases(f.get("aliases"), cid, hosts), _str(f.get("product")),
               _sources(raw, hosts), f, hosts, out,
               fixed=_fixed(f.get("fixed")), affected=_affected(f.get("affected")))

    return _each(findings, out, one)
