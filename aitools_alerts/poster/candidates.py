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

from aitools_alerts.schema import Source, is_primary  # re-exported: candidates.Source is schema.Source

KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# The deployment's own host names (the poster config's ``strip_hosts``) and extra
# internal source-host suffixes (``internal_host_suffixes``), set once per run by
# ``configure``; the public code names none. Each adapter adds the host names its
# own input record names, and compose reads FLEET_HOSTS at call time.
FLEET_HOSTS: tuple[str, ...] = ()
INTERNAL_SUFFIXES: tuple[str, ...] = ()


def configure(strip_hosts=(), internal_suffixes=()) -> None:
    """Set the deployment's host names and internal suffixes for this process."""
    global FLEET_HOSTS, INTERNAL_SUFFIXES
    FLEET_HOSTS = tuple(strip_hosts)
    INTERNAL_SUFFIXES = tuple(internal_suffixes)


MAX_RUN_BYTES = 16 * 1024 * 1024
MAX_ID = 200
MAX_TEXT = 500
MAX_ALIASES = 32
MAX_SOURCES = 8
MAX_TITLE = 160

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?")
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")
# A concrete release: digits first, no wildcard component ("1.x", "2.*").
_VERSION = re.compile(r"v?\d[0-9A-Za-z.+_-]{0,63}")
_WILDCARD = re.compile(r"(?:^|[.\-+_])[xX*](?:$|[.\-+_])")
# The collector's Apple source title, up to the impact text: "APPLE-SA-<id> <release>
# (macOS <major> fixed in <version>): <impact>". Only this prefix may supply a version.
_APPLE_TITLE = re.compile(r"APPLE-SA-[\w.-]{1,40} [^():]{1,120} \(macOS (\d{1,3}) fixed in (\d{1,3}(?:\.\d{1,4}){0,3})\): ")
# One token of a version range; ranges are split before matching, so no regex
# below has nested or adjacent unbounded repeats (no catastrophic backtracking).
_RANGE_TOKEN = re.compile(r"[<>=!~^]{0,2}v?\d[0-9A-Za-z.+_*-]{0,63}")
_RANGE_SPLIT = re.compile(r",|\|\||\s+")
_OP_SPACE = re.compile(r"([<>=!~^]{1,2}) +")
# Local paths and kata refs, matched anywhere (markdown or quotes around them do
# not hide them). Over-matching drops a field, which is the safe failure.
_PRIVATE = re.compile(
    r"/Users/|/home/|/private/|/var/|/tmp/|/etc/|~/"
    r"|/opt/|/srv/|/mnt/|/root/|/usr/local/|/media/|/run/user/"
    r"|/library/(?:logs|caches|preferences|containers|group containers|application support"
    r"|keychains|mobile documents|cloudstorage|launchagents|daemoncontainers)/"
    r"|/applications/[^/\s]+\.app\b"
    # /volumes/ at a path root in any case (a query value, a quoted path): APFS is
    # case-insensitive. Inside a URL path ("/storage/volumes/") it is a doc page.
    r"|(?:^|[=\s\"'(<,;&?:])/volumes/"
    r"|(?<![A-Za-z0-9])[A-Za-z]:[\\/](?!/)|\\\\[A-Za-z0-9]"
    r"|\b[a-z][a-z0-9-]*#[0-9a-z]{4}\b",
    re.I,
)
# Source hosts that only resolve inside a network: never a public advisory.
_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".home.arpa", ".localhost")
_PRIVATE_URL_PATH = re.compile(r"/(?:Users|home)/|~/")
HINTS = frozenset({"critical", "high", "medium", "low", "none", "not_affected", "out_of_scope"})


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
    source_title: str | None = None  # the primary source's own title (r7hr); never identity

    def to_dict(self) -> dict:
        d = asdict(self)
        d["aliases"] = list(self.aliases)
        d["sources"] = [asdict(s) for s in self.sources]
        return d


class CandidateList(list):
    """A list of Candidates with a count of skipped input items by reason.
    ``rejected`` is the reason when the whole input was refused, else None."""

    def __init__(self, *args):
        super().__init__(*args)
        self.skipped: Counter = Counter()
        self.rejected: str | None = None

    def reject(self, reason: str) -> "CandidateList":
        self.skipped[reason] += 1
        self.rejected = reason
        return self


# ---------------------------------------------------------------- helpers


def _str(v, limit: int = MAX_TEXT) -> str | None:
    """A stripped, length-capped string, or None for anything else or empty."""
    if not isinstance(v, str):
        return None
    v = v.strip()[:limit]
    return v if v and _safe(v) else None


def _safe(s: str) -> bool:
    """No control, format (bidi override) or lone surrogate character."""
    return not any(unicodedata.category(ch) in ("Cc", "Cf", "Cs") for ch in s)


_TITLE_URL = re.compile(r"\b(?:[a-z][a-z0-9+.-]*://|www\.)\S*", re.I)


def _title(v, hosts) -> str | None:
    """An upstream title made safe for a post line: NFKC, URLs and control characters
    gone, whitespace collapsed, no code fence, capped; None when nothing is left or it
    names a host or private detail (the title is dropped, never the finding)."""
    if not isinstance(v, str):
        return None
    t = "".join(ch for ch in unicodedata.normalize("NFKC", v[:4 * MAX_TEXT]) if ch.isspace()
                or unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    t = " ".join(_TITLE_URL.sub(" ", t).split())  # controls first: a removed one cannot join a URL
    t = re.sub(r"([`~]){2,}", r"\1", t)[:MAX_TITLE].rstrip()  # no code fence of either kind
    return _clean(t, hosts) if t else None


def _flag(v) -> bool:
    return v is True


# macOS roots matched with their capital, so Apple's /library/ documentation and the
# /volumes/ pages of Docker and Kubernetes stay allowed; a lowercase spelling of the
# local Library subfolders and of an .app bundle is caught by _PRIVATE above.
_PRIVATE_CASED = re.compile(r"/Library/|/Applications/|/System/Volumes/|/Volumes/|/Network/")


def _private(s: str | None) -> bool:
    return s is not None and bool(_PRIVATE.search(s) or _PRIVATE_CASED.search(s))


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
    s = _str(v, MAX_TEXT)  # validate the whole value; never truncate into a new version
    if not s or len(s) > 64 or not _VERSION.fullmatch(s) or _WILDCARD.search(s):
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
    if not isinstance(v, str) or len(v) > 2000 or _BAD_URL_CHARS.search(v) or not _safe(v):
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
    # An encoded hostname would hide an internal suffix or address from the check.
    if "%" in parts.netloc or not _safe(_decoded(v)) or _internal_host(parts.hostname):
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
    return ("." not in host or host == "localhost" or host.endswith(_INTERNAL_SUFFIXES)
            or host.endswith(INTERNAL_SUFFIXES))


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
           exploited: bool = False, fixed: str | None = None, affected: str | None = None,
           title: str | None = None) -> None:
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
        source_title=title,
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
            return out.reject("run.json too large")
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, RecursionError):
        return out.reject("run.json unreadable")
    if not isinstance(record, dict):
        return out.reject("run.json not an object")
    findings = record.get("findings")
    if isinstance(findings, dict):
        items = list(findings.items())
    elif isinstance(findings, list):
        items = [(None, f) for f in findings]
    else:
        return out.reject("findings not a dict or list")

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
        ids = [i for i in (_str(x, MAX_ID + 1) for x in f["ids"]) if i] \
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
        return out.reject("kev not an object")
    items = kev_json.get("vulnerabilities", kev_json.get("items"))
    if not isinstance(items, list):
        return out.reject("kev items not a list")
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


def _apple_fixed(f: dict, kept: tuple[Source, ...]) -> str | None:
    """The fix version an Apple security release names, for a macOS finding: read only
    from the collector's title prefix on retained support.apple.com sources, which must
    all parse and agree. Any other source or shape gives None, never a guess."""
    if not isinstance(f.get("product"), str) or f["product"].lower() != "macos":
        return None
    urls, found = {s.url for s in kept}, set()
    for s in f.get("sources") if isinstance(f.get("sources"), list) else []:
        url = _url(s.get("url")) if isinstance(s, dict) else None
        if url not in urls or urlsplit(url).hostname != "support.apple.com":
            continue
        m = _APPLE_TITLE.match(_str(s.get("title"), MAX_TEXT) or "")
        if not m or m.group(2).split(".")[0] != m.group(1):
            return None
        found.add(m.group(2))
    return _fixed(found.pop()) if len(found) == 1 else None


def _source_title(f: dict, kept: tuple[Source, ...], hosts: _Hosts) -> str | None:
    """The title of the first retained primary source that has one; any other gives None."""
    urls = {s.url for s in kept if is_primary(s.url)}
    for s in f["sources"] if isinstance(f.get("sources"), list) else []:
        if isinstance(s, dict) and _url(s.get("url")) in urls:
            t = _title(s.get("title"), hosts)
            if t:
                return t
    return None


def from_collector(record: dict) -> CandidateList:
    """Candidates from a collector run record (schema_version 1)."""
    out = CandidateList()
    if not isinstance(record, dict) or record.get("schema_version") != 1 \
            or isinstance(record.get("schema_version"), bool):
        return out.reject("schema_version")
    findings = record.get("findings")
    if not isinstance(findings, list):
        return out.reject("findings not a list")
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
        sources = _sources(raw, hosts)
        _build(cid, _aliases(f.get("aliases"), cid, hosts), _str(f.get("product")),
               sources, f, hosts, out,
               fixed=_fixed(f.get("fixed")) or _apple_fixed(f, sources),
               affected=_affected(f.get("affected")), title=_source_title(f, sources, hosts))

    return _each(findings, out, one)
