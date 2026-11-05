"""The advisory contract: vocabularies, the post block parser and the spec files.

A post is a human body followed by a fenced block whose info string is exactly
``aitools-alert``. The LAST such block is authoritative; if it is invalid the
post is unreadable (None), never answered from an earlier block. Validation is
hand-written and strict (standard library only); spec/advisory.schema.json
documents the same contract. Nothing here runs at import time except constant
definitions: spec files are read only when a loader is called.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import asdict, dataclass, fields
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from . import _data_dir

SPEC_DIR = _data_dir("spec")
INFO_STRING = "aitools-alert"
MAX_BLOCK_BYTES = 65536

LEVELS = frozenset({"critical", "high", "notice"})
VERBS = frozenset({"upgrade", "disable_skill", "remove_mcp_server",
                   "rotate_credential", "stop_using", "review_setting"})
ROLES = frozenset({"curator", "relay-bot"})

_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_ECOSYSTEM = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
# Versions: dotted integers with an optional lowercase suffix (9.9p1, 1.0rc1).
# affected: "*" or comparators joined by ","; the grammar A4's compare reads.
_VERSION = r"[0-9]{1,9}(?:\.[0-9]{1,9}){0,4}(?:[a-z][a-z0-9]{0,15})?"
_FIXED = re.compile(_VERSION)
_AFFECTED = re.compile(rf"\*|(?:<=|>=|<|>|=){_VERSION}(?:,(?:<=|>=|<|>|=){_VERSION}){{0,3}}")
# Action target/value: no shell metacharacters, quotes or leading "-".
# No " -" (an option after a space) and no ".." anywhere: checked in _arg.
_ARG = re.compile(r"[A-Za-z0-9~/.@][A-Za-z0-9 ._:/@+~=,-]{0,199}")
# disable_skill / remove_mcp_server: one name, optionally @scope/name; no path.
_NAME = re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._-]{0,63}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_NAME_VERBS = frozenset({"disable_skill", "remove_mcp_server"})
MAX_TIMESTAMP = 253402300799  # 9999-12-31T23:59:59Z
_LINES = re.compile(r"\r\n|\r|\n")  # CommonMark line endings only
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[0-9T:.+Z-]{0,32}")
_BIDI = frozenset("‪‫‬‭‮⁦⁧⁨⁩")


@dataclass(frozen=True)
class Product:
    name: str
    ecosystem: str
    affected: str | None
    fixed: str | None


@dataclass(frozen=True)
class Action:
    verb: str
    target: str
    value: str | None


@dataclass(frozen=True)
class Source:
    url: str
    published_at: str | None


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: list[str]
    level: str
    advisory_severity: str | None
    title: str
    products: list[Product]
    actions: list[Action]
    sources: list[Source]
    posted_by: str
    posted_at: int
    expires_at: int | None


@dataclass(frozen=True)
class ScopeEntry:
    name: str
    ecosystem: str
    tier: int
    match: list[str]
    # How ``match`` patterns are tested: "word" (bounded) or "substring". Set from
    # the scope file's version and match_mode; never a key of a JSON entry.
    match_mode: str = "word"


# ---------------------------------------------------------------- validation

def _fail(path: str, why: str):
    raise ValueError(f"{path}: {why}")


def _obj(v, path: str, cls, want: set[str] | None = None) -> dict:
    if not isinstance(v, dict):
        _fail(path, "not an object")
    want = {f.name for f in fields(cls)} if want is None else want
    extra = set(v) - want
    if extra:
        _fail(path, f"unknown keys {sorted(extra)}")
    missing = want - set(v)
    if missing:
        _fail(path, f"missing keys {sorted(missing)}")
    return v


def _text(v, path: str, lo: int, hi: int, nullable: bool = False):
    if v is None and nullable:
        return None
    if not isinstance(v, str):
        _fail(path, "not a string")
    if not lo <= len(v) <= hi:
        _fail(path, f"length not in {lo}..{hi}")
    for ch in v:
        if ch in _BIDI or unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            _fail(path, "control, format, surrogate or line-separator character")
    return v


def _pattern(v, path: str, rx: re.Pattern, nullable: bool = False):
    if v is None and nullable:
        return None
    if not isinstance(v, str) or not rx.fullmatch(v):
        _fail(path, "does not match the allowed pattern")
    return v


def _int(v, path: str, nullable: bool = False):
    if v is None and nullable:
        return None
    if type(v) is not int or not 0 <= v <= MAX_TIMESTAMP:  # bool is not an int here
        _fail(path, f"not an integer in 0..{MAX_TIMESTAMP}")
    return v


def _list(v, path: str, lo: int, hi: int) -> list:
    if not isinstance(v, list):
        _fail(path, "not an array")
    if not lo <= len(v) <= hi:
        _fail(path, f"item count not in {lo}..{hi}")
    return v


def _enum(v, path: str, allowed: frozenset):
    if not isinstance(v, str) or v not in allowed:
        _fail(path, f"not one of {sorted(allowed)}")
    return v


def _https_url(v, path: str) -> str:
    _text(v, path, 9, 2048)
    parts = urlsplit(v)
    if not v.startswith("https://") or not parts.hostname:
        _fail(path, "not an https URL with a host")
    return v


def _arg(v, path: str, rx: re.Pattern, nullable: bool = False):
    v = _pattern(v, path, rx, nullable)
    if v is not None and (" -" in v or ".." in v):
        _fail(path, "option-like or traversal sequence")
    return v


def _action(a: dict, at: str) -> Action:
    verb = _enum(a["verb"], at + ".verb", VERBS)
    target_rx = _NAME if verb in _NAME_VERBS else _ARG
    value_rx = _FIXED if verb == "upgrade" else _ARG
    return Action(verb=verb,
                  target=_arg(a["target"], at + ".target", target_rx),
                  value=_arg(a["value"], at + ".value", value_rx, nullable=True))


def validate(obj) -> Advisory:
    """Return an Advisory for a decoded block, or raise ValueError naming the field."""
    o = _obj(obj, "$", Advisory)
    products = []
    for i, p in enumerate(_list(o["products"], "$.products", 1, 50)):
        at = f"$.products[{i}]"
        p = _obj(p, at, Product)
        products.append(Product(
            name=_text(p["name"], at + ".name", 1, 200),
            ecosystem=_pattern(p["ecosystem"], at + ".ecosystem", _ECOSYSTEM),
            affected=_pattern(p["affected"], at + ".affected", _AFFECTED, nullable=True),
            fixed=_pattern(p["fixed"], at + ".fixed", _FIXED, nullable=True),
        ))
    actions = []
    for i, a in enumerate(_list(o["actions"], "$.actions", 0, 20)):
        at = f"$.actions[{i}]"
        actions.append(_action(_obj(a, at, Action), at))
    sources = []
    for i, s in enumerate(_list(o["sources"], "$.sources", 1, 20)):
        at = f"$.sources[{i}]"
        s = _obj(s, at, Source)
        sources.append(Source(
            url=_https_url(s["url"], at + ".url"),
            published_at=_pattern(s["published_at"], at + ".published_at", _DATE, nullable=True),
        ))
    posted_at = _int(o["posted_at"], "$.posted_at")
    expires_at = _int(o["expires_at"], "$.expires_at", nullable=True)
    if expires_at is not None and expires_at < posted_at:
        _fail("$.expires_at", "before posted_at")
    return Advisory(
        id=_pattern(o["id"], "$.id", _IDENT),
        aliases=[_pattern(a, f"$.aliases[{i}]", _IDENT)
                 for i, a in enumerate(_list(o["aliases"], "$.aliases", 0, 50))],
        level=_enum(o["level"], "$.level", LEVELS),
        advisory_severity=_text(o["advisory_severity"], "$.advisory_severity", 0, 64, nullable=True),
        title=_text(o["title"], "$.title", 1, 300),
        products=products,
        actions=actions,
        sources=sources,
        posted_by=_enum(o["posted_by"], "$.posted_by", ROLES),
        posted_at=posted_at,
        expires_at=expires_at,
    )


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name}")


def decode_block(text: str) -> Advisory:
    """Decode and validate one block's JSON text; raise ValueError if invalid."""
    if len(text.encode("utf-8")) > MAX_BLOCK_BYTES:
        raise ValueError("block too large")
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicates,
                         parse_constant=_reject_constant)
    except json.JSONDecodeError as e:
        raise ValueError(f"not JSON: {e}") from None
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None
    return validate(obj)


# ------------------------------------------------------------ fenced blocks

_FENCE_OPEN = re.compile(r"( {0,3})(`{3,}|~{3,})(.*)")
MAX_POST_CHARS = 1048576
_NONE, _UNFINISHED, _TOO_LARGE = object(), object(), object()


def _last_block(content: str):
    """Body of the last aitools-alert fence, or a sentinel: _NONE (no block),
    _UNFINISHED (the last one never closed), _TOO_LARGE (over MAX_BLOCK_BYTES).
    Backtick and tilde fences indented up to three spaces are tracked
    (CommonMark), so a block quoted inside another fence is not collected.
    Ours opens only at column 0 with backticks and info string exactly
    INFO_STRING. Only the current candidate's body is held in memory."""
    last = _NONE
    fence = None  # [fence char, length, is ours, body lines, body UTF-8 bytes]
    for line in _LINES.split(content):
        if fence is None:
            m = _FENCE_OPEN.match(line)
            if m:
                ch, n, info = m.group(2)[0], len(m.group(2)), m.group(3)
                if ch == "`" and "`" in info:
                    continue  # not a fence opener
                ours = ch == "`" and m.group(1) == "" and info.strip() == INFO_STRING
                fence = [ch, n, ours, [], 0]
            continue
        body = line.lstrip(" ")
        closer = body.rstrip(" \t")
        if (len(line) - len(body) <= 3 and len(closer) >= fence[1]
                and set(closer) == {fence[0]}):
            if fence[2]:
                last = _TOO_LARGE if fence[3] is None else "\n".join(fence[3])
            fence = None
        elif fence[2] and fence[3] is not None:
            fence[4] += len(line.encode("utf-8", "surrogatepass")) + (1 if fence[3] else 0)
            if fence[4] > MAX_BLOCK_BYTES:
                fence[3] = None  # drop the body; the block is rejected anyway
            else:
                fence[3].append(line)
    if fence is not None and fence[2]:
        last = _UNFINISHED
    return last


def parse_post(content: str) -> Advisory | None:
    """The Advisory in the last aitools-alert block, or None if absent,
    unfinished, too large or invalid. Never raises."""
    if not isinstance(content, str) or len(content) > MAX_POST_CHARS:
        return None
    block = _last_block(content)
    if not isinstance(block, str):
        return None
    try:
        return decode_block(block)
    except ValueError:
        return None


def render_post(adv: Advisory, body: str) -> str:
    """Body, a blank line, then the fenced block. Raises ValueError if the
    result would not parse back to the same Advisory."""
    if not isinstance(adv, Advisory) or not isinstance(body, str):
        raise ValueError("render_post needs an Advisory and a str body")
    adv = validate(asdict(adv))
    block = json.dumps(asdict(adv), indent=2, ensure_ascii=False)
    out = f"{body.rstrip(chr(10))}\n\n```{INFO_STRING}\n{block}\n```\n"
    if parse_post(out) != adv:
        raise ValueError("rendered post does not parse back (unclosed fence in body?)")
    return out


# ---------------------------------------------------------------- spec files

def _load_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_no_duplicates)


SCOPE_VERSION = 2
SCOPE_MATCH_MODES = ("word", "substring")
_SCOPE_KEYS = frozenset({"version", "description", "match_mode", "entries"})
_SCOPE_ENTRY_KEYS = {"name", "ecosystem", "tier", "match"}


def _scope_mode(data) -> str:
    """The match mode a scope file declares, by its version.

    No ``version``: version 1, substring patterns, extra top-level keys ignored.
    ``version`` 2: top-level keys limited to _SCOPE_KEYS, ``match_mode`` one of
    SCOPE_MATCH_MODES, default "word". Any other version is refused.
    """
    if not isinstance(data, dict):
        return "substring"  # the entries check below reports the bad file
    if "version" not in data:
        if "match_mode" in data:
            _fail("scope.match_mode", "needs version 2")
        return "substring"
    if type(data["version"]) is not int or data["version"] != SCOPE_VERSION:
        _fail("scope.version", f"not {SCOPE_VERSION}")
    extra = set(data) - _SCOPE_KEYS
    if extra:
        _fail("scope", f"unknown keys {sorted(extra)}")
    mode = data.get("match_mode", "word")
    if mode not in SCOPE_MATCH_MODES:
        _fail("scope.match_mode", f"not one of {list(SCOPE_MATCH_MODES)}")
    return mode


def load_scope(path: Path | None = None) -> list[ScopeEntry]:
    data = _load_json(path or SPEC_DIR / "scope.json")
    mode = _scope_mode(data)
    entries, names = [], set()
    for i, e in enumerate(_list(data.get("entries") if isinstance(data, dict) else None,
                                "scope.entries", 1, 1000)):
        at = f"scope.entries[{i}]"
        e = _obj(e, at, ScopeEntry, _SCOPE_ENTRY_KEYS)
        name = _text(e["name"], at + ".name", 1, 200)
        if name in names:
            _fail(at + ".name", "duplicate")
        names.add(name)
        if type(e["tier"]) is not int or e["tier"] not in (1, 2):
            _fail(at + ".tier", "not 1 or 2")
        match = _list(e["match"], at + ".match", 1, 100)
        for j, m in enumerate(match):
            _text(m, f"{at}.match[{j}]", 1, 200)
            if m != m.lower() or m != m.strip():
                _fail(f"{at}.match[{j}]", "not lowercase and trimmed")
        entries.append(ScopeEntry(
            name=name,
            ecosystem=_pattern(e["ecosystem"], at + ".ecosystem", _ECOSYSTEM),
            tier=e["tier"],
            match=list(match),
            match_mode=mode,
        ))
    return entries


def load_primary_domains(path: Path | None = None) -> dict[str, dict]:
    """host -> {"paths": [patterns] or None, "owners": set of lowercase owners}."""
    data = _load_json(path or SPEC_DIR / "primary-domains.json")
    out = {}
    for i, d in enumerate(_list(data.get("domains") if isinstance(data, dict) else None,
                                "domains", 1, 1000)):
        at = f"domains[{i}]"
        if not isinstance(d, dict) or set(d) - {"host", "paths", "owners"} or "host" not in d:
            _fail(at, "needs host and optional paths, owners only")
        host = _text(d["host"], at + ".host", 1, 253)
        if host != host.lower() or host.startswith("www.") or host in out:
            _fail(at + ".host", "not a lowercase, unique, www-less host")
        paths = d.get("paths")
        if paths is not None:
            paths = _list(paths, at + ".paths", 1, 20)
            for j, p in enumerate(paths):
                _text(p, f"{at}.paths[{j}]", 2, 200)
                if p != "*/security/advisories/" and (
                        "*" in p or not (p.startswith("/") and p.endswith("/"))):
                    _fail(f"{at}.paths[{j}]", "not /prefix/ or */security/advisories/")
        owners = [_pattern(o, f"{at}.owners[{j}]", _ECOSYSTEM)
                  for j, o in enumerate(_list(d.get("owners", []), at + ".owners", 0, 200))]
        if paths and "*/security/advisories/" in paths and not owners:
            _fail(at + ".owners", "required with */security/advisories/")
        out[host] = {"paths": paths, "owners": set(owners)}
    return out


@lru_cache(maxsize=1)
def _default_domains() -> dict[str, dict]:
    return load_primary_domains()


def _path_matches(path: str, pattern: str, owners: set) -> bool:
    if "%" in path or "\\" in path or not path.startswith("/"):
        return False
    segs = path[1:].split("/")
    if segs[-1] == "":
        segs = segs[:-1]  # one trailing slash
    if not segs or any(s in ("", ".", "..") for s in segs):
        return False
    if pattern == "*/security/advisories/":
        return (len(segs) == 5 and segs[0].lower() in owners
                and segs[2:4] == ["security", "advisories"])
    prefix = [s for s in pattern.split("/") if s]
    return len(segs) > len(prefix) and segs[:len(prefix)] == prefix


def is_primary(url: str, domains: dict[str, dict] | None = None) -> bool:
    """True when url is an https page on an allowlisted primary-source host
    (exact host or www.), and on a path-restricted host, on an allowed path."""
    if not isinstance(url, str) or len(url) > 2048:
        return False
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zs", "Zl", "Zp") for c in url):
        return False
    if domains is None:
        domains = _default_domains()
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "https" or "@" in parts.netloc:
        return False
    if port not in (None, 443):
        return False
    host = parts.hostname or ""  # urlsplit lowercases it
    if host.endswith("."):
        host = host[:-1]  # one trailing dot is the same host
    if host.startswith("www."):
        host = host[4:]
    if host not in domains:
        return False
    rule = domains[host]
    if rule["paths"] is None:
        return True
    return any(_path_matches(parts.path, p, rule["owners"]) for p in rule["paths"])
