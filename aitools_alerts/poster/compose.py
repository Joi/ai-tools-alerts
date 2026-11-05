"""Compose relay-bot posts: a root advisory, a reply carrying only changed fields, the digest.

Post text leaves the fleet, so it is built only from fields that are safe to
publish: the candidate's id, aliases, fixed/affected versions and sources, the
level, and the matched scope entry's display name. ``product_text``,
``advisory_severity``, ``local_level_hint`` and ``observed_at`` are rule inputs
and are never read here (B1: a version in them can be a locally observed one).
Every composed post is refused if it names a fleet host, this machine, a local
path or a kata ref.

Reply patch contract (shared with A5's reader, ``parse_reply``): a reply's last
fenced ``aitools-alert`` block is a JSON object of changed fields only, decoded
as strictly as ``schema.decode_block`` (duplicate keys, NaN and oversized or
unfinished blocks are invalid). A list field is replaced whole, so a writer
sends the full new list; ``{}`` is valid and changes nothing. A key omitted is unchanged; a key set to null
clears a nullable field (``advisory_severity``, ``expires_at``). ``id`` and
``posted_by`` may not appear; an unknown key is invalid. The merged advisory
must pass ``schema.validate``, else the patch is invalid and changes nothing.
"""

from __future__ import annotations

import json
import re
import socket
import time
from dataclasses import asdict

from aitools_alerts import schema
from aitools_alerts.poster import candidates

POSTED_BY = "relay-bot"
_PATCH_KEYS = frozenset(schema.Advisory.__dataclass_fields__) - {"id", "posted_by"}
_REPLY_KEYS = frozenset({"level", "title", "products", "actions", "aliases", "sources",
                         "expires_at", "advisory_severity"})
_NULLABLE = frozenset({"advisory_severity", "expires_at"})
_OPS = {"<": "below", "<=": "up to", ">": "above", ">=": "from", "=": "exactly"}
_COMPARATOR = re.compile(r"(<=|>=|<|>|=)(.+)")
_KINDS = ("known exploited vulnerability", "trojanized release",
          "injection to code execution", "security advisory")
UNVERIFIED = "unverified: no primary source confirmed it"


def schema_fixed(v) -> str | None:
    """A candidate's fixed version in the schema grammar (leading v dropped), or None."""
    if not isinstance(v, str):
        return None
    v = v[1:] if v[:1] in ("v", "V") else v
    return v if schema._FIXED.fullmatch(v) else None


def schema_affected(v) -> str | None:
    """A candidate's range as schema comparators joined by commas, or None when it
    holds anything the schema cannot say (||, !=, ~, ^, a bare version)."""
    if not isinstance(v, str) or "||" in v:
        return None
    if v.strip() == "*":
        return "*"
    out = []
    for t in (t for t in re.split(r"[,\s]+", re.sub(r"([<>=]+)\s+", r"\1", v.strip())) if t):
        m = _COMPARATOR.fullmatch(t)
        ver = schema_fixed(m.group(2)) if m else None
        if ver is None:
            return None
        out.append(m.group(1) + ver)
    s = ",".join(out)
    return s if out and schema._AFFECTED.fullmatch(s) else None


def _words(affected: str | None) -> str:
    if affected is None:
        return ", versions not stated"
    if affected == "*":
        return ", all versions"
    parts = [_COMPARATOR.fullmatch(t).groups() for t in affected.split(",")]
    return " " + " and ".join(f"{_OPS[op]} {ver}" for op, ver in parts)


def _guard(text: str) -> str:
    """Refuse text that names a fleet host or this machine, or holds a local path or kata ref."""
    names = {h.lower() for h in candidates.FLEET_HOSTS}
    try:
        host = socket.gethostname().strip().lower()
    except OSError:
        host = ""
    names.update({host, host.split(".")[0]} if host else set())
    low = text.lower() + "\n" + candidates._decoded(text).lower()
    for name in (n for n in names if len(n) >= 3):
        if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", low):
            raise ValueError("composed post names a host; refusing to publish it")
    # Lowercased for the host names; case-preserved too, for the cased macOS roots.
    if any(candidates._private(t) for t in (low, text, candidates._decoded(text))):
        raise ValueError("composed post holds a local path or kata ref; refusing to publish it")
    return text


def _primary(sources) -> str:
    return next((s.url for s in sources if schema.is_primary(s.url)), sources[0].url)


def _sources(raw) -> list[schema.Source]:
    out, seen = [], set()
    for s in raw:
        s = s if isinstance(s, dict) else {"url": getattr(s, "url", None),
                                           "published_at": getattr(s, "published_at", None)}
        url, pub = s.get("url"), s.get("published_at")
        try:
            url = schema._https_url(url, "source")
        except ValueError:
            continue
        if candidates._url(url) != url:  # B1's checks: credentials, internal hosts, private paths
            continue
        if url not in seen:
            seen.add(url)
            pub = pub if isinstance(pub, str) and schema._DATE.fullmatch(pub) else None
            out.append(schema.Source(url, pub))
    out.sort(key=lambda s: not schema.is_primary(s.url))  # stable: primary first
    return out[:20]


def _kind(c, reason) -> str:
    flags = (c.exploited, c.trojanized, c.injection_exec, True)
    kind = next(k for k, f in zip(_KINDS, flags) if f is True)
    return "unverified " + kind if reason == "unverified" else kind


def _titles(name: str, adv_id: str) -> set[str]:
    return {f"{name}: {pre}{k} ({adv_id})" for k in _KINDS for pre in ("", "unverified ")}


def _ids(raw, exclude: str) -> list[str]:
    out = []
    for a in raw:
        if isinstance(a, str) and a != exclude and a not in out and schema._IDENT.fullmatch(a):
            out.append(a)
    return out


def root_post(c, level, scope, *, posted_at: int | None = None) -> tuple[str, schema.Advisory]:
    """(post text, Advisory) for a new thread: four body lines, then the block.
    ``level`` is ``rules.level_for``'s (level, reason), or a bare level."""
    level, reason = level if isinstance(level, tuple) else (level, None)
    fixed = schema_fixed(c.fixed)
    sources = _sources(c.sources)
    if not sources:
        raise ValueError("no https source the schema accepts: the advisory does not post")
    adv = schema.validate(asdict(schema.Advisory(
        id=c.id, aliases=_ids(c.aliases, c.id)[:50], level=level, advisory_severity=None,
        title=f"{scope.name}: {_kind(c, reason)} ({c.id})",
        products=[schema.Product(scope.name, scope.ecosystem, schema_affected(c.affected), fixed)],
        actions=[schema.Action("upgrade", scope.name, fixed)] if fixed else [],
        sources=sources, posted_by=POSTED_BY,
        posted_at=int(time.time()) if posted_at is None else posted_at, expires_at=None)))
    p = adv.products[0]
    head = adv.level.upper() + (f" ({UNVERIFIED})" if reason == "unverified" else "")
    # A fix the schema cannot express is still a fix: say so, and name no version.
    unexpressed = fixed is None and isinstance(c.fixed, str) and c.fixed.strip() != ""
    body = [f"{head}: {adv.title}",
            f"Affected: {p.name}{_words(p.affected)}."
            + (f" Fixed in {fixed}." if fixed else " A fix is listed upstream; see the source."
               if unexpressed else " No fixed version is known yet."),
            f"Action: upgrade {p.name} to {fixed} or later." if fixed
            else "Action: upgrade as the source describes." if unexpressed
            else "Action: no fix is published yet; watch this thread.",
            f"Source: {_primary(adv.sources)}"]
    return _guard(schema.render_post(adv, "\n".join(body))), adv


def apply_patch(prev: schema.Advisory, patch) -> schema.Advisory:
    """prev with a decoded reply patch applied, by the contract in the module docstring."""
    if not isinstance(patch, dict):
        raise ValueError("patch: not an object")
    bad = set(patch) - _PATCH_KEYS
    if bad:
        raise ValueError(f"patch: keys not allowed {sorted(bad)}")
    for k, v in patch.items():
        if v is None and k not in _NULLABLE:
            raise ValueError(f"patch: {k} cannot be cleared")
    return schema.validate({**asdict(prev), **patch})


def parse_reply(content: str, prev: schema.Advisory) -> schema.Advisory | None:
    """prev updated by the reply's last block, or None if it has none or it is invalid."""
    if not isinstance(content, str) or len(content) > schema.MAX_POST_CHARS:
        return None
    block = schema._last_block(content)
    if not isinstance(block, str):
        return None
    try:
        patch = json.loads(block, object_pairs_hook=schema._no_duplicates,
                           parse_constant=schema._reject_constant)
        return apply_patch(prev, patch)
    except (ValueError, RecursionError):
        return None


def _publishable(prev: schema.Advisory, merged: schema.Advisory, patch: dict) -> None:
    """A relay-bot reply may say only what root_post could have said."""
    bad = set(patch) - _REPLY_KEYS
    if bad or merged.advisory_severity is not None:
        raise ValueError(f"reply: not publishable by the relay bot {sorted(bad) or ['advisory_severity']}")
    p, was = merged.products, prev.products[0]
    if len(p) != 1 or (p[0].name, p[0].ecosystem) != (was.name, was.ecosystem):
        raise ValueError("reply: the product is the scope entry's, one product")
    if merged.title not in _titles(was.name, prev.id):
        raise ValueError("reply: the title is a template title")
    if any((a.verb, a.target, a.value) != ("upgrade", was.name, p[0].fixed) for a in merged.actions):
        raise ValueError("reply: the only action is upgrade to products[0].fixed")
    if {s.url for s in _sources(asdict(s) for s in merged.sources)} != {s.url for s in merged.sources}:
        raise ValueError("reply: a source fails the publication checks")


def _change_line(k: str, adv: schema.Advisory) -> str:
    p = adv.products[0]
    return {
        "level": f"Level is now {adv.level}.",
        "products": f"Affected: {p.name}{_words(p.affected)}." + (f" Fixed in {p.fixed}." if p.fixed else ""),
        "actions": f"Action: upgrade {p.name} to {p.fixed} or later." if adv.actions else "No action listed now.",
        "title": f"Now: {adv.title}",
        "expires_at": "Expiry cleared." if adv.expires_at is None else "This advisory now expires.",
        "aliases": "Also known as: " + ", ".join(adv.aliases) + ".",
        "sources": "New sources listed.",
        "advisory_severity": "Severity rating cleared.",
    }[k]


def reply_post(prev: schema.Advisory, c, changes: dict, *, reason: str | None = None) -> str:
    """A thread reply: one line per changed field, a source line, then a block of the
    changed fields only. Unchanged keys are dropped; aliases and sources are capped
    at the schema's 50 and 20. ``reason`` 'unverified' adds the unverified line.
    Raises ValueError for an empty, invalid or unpublishable patch."""
    if not isinstance(changes, dict):
        raise ValueError("changes: not an object")
    old = asdict(prev)
    patch = {}
    for k, v in changes.items():
        if isinstance(v, (list, tuple)):
            v = [asdict(x) if hasattr(x, "__dataclass_fields__") else x for x in v]
        if k == "aliases" and isinstance(v, list):  # a union with prev, filtered as root_post does
            v = _ids(old["aliases"] + v, prev.id)[:50]
        elif k == "sources" and isinstance(v, list):
            v = [asdict(s) for s in _sources(old["sources"] + v)]
        if k not in old or k in ("id", "posted_by") or old[k] != v:
            patch[k] = v
    prods = patch.get("products")
    if "actions" not in changes and isinstance(prods, list) and prods and isinstance(prods[0], dict):
        fixed = prods[0].get("fixed")  # the upgrade action follows the fixed version
        acts = [{"verb": "upgrade", "target": prev.products[0].name, "value": fixed}] if fixed else []
        if acts != old["actions"]:
            patch["actions"] = acts
    if not patch:
        raise ValueError("reply with no changed field")
    merged = apply_patch(prev, patch)
    _publishable(prev, merged, patch)
    body = [UNVERIFIED[0].upper() + UNVERIFIED[1:] + "."] if reason == "unverified" else []
    body += [_change_line(k, merged) for k in sorted(patch)]
    body.append(f"Source: {_primary(_sources(c.sources) or merged.sources)}")
    block = json.dumps(patch, indent=2, ensure_ascii=False)
    out = "\n".join(body) + f"\n\n```{schema.INFO_STRING}\n{block}\n```\n"
    if parse_reply(out, prev) != merged:
        raise ValueError("reply does not parse back")
    return _guard(out)


def digest(advs_today, date) -> str:
    """The daily digest: every advisory once per id and product (latest posted_at
    wins), critical first. An item that fails the publication guard is withheld
    and counted, never the whole digest."""
    latest: dict[tuple, schema.Advisory] = {}
    for adv in advs_today:
        if not (adv.products and adv.sources):
            continue
        key = (adv.id, adv.products[0].name)
        if key not in latest or adv.posted_at >= latest[key].posted_at:
            latest[key] = adv
    day = date.isoformat() if hasattr(date, "isoformat") else str(date)
    if not latest:
        return f"Daily digest for {day}: no advisories."
    n = len(latest)
    lines, withheld = [f"Daily digest for {day}: {n} advisor{'y' if n == 1 else 'ies'}."], 0
    for level in ("critical", "high", "notice"):
        group = sorted((a for a in latest.values() if a.level == level), key=lambda a: (a.posted_at, a.id))
        if group:
            lines += ["", f"{level.capitalize()} ({len(group)})"]
            for a in group:
                fixed = f"fixed in {a.products[0].fixed}" if a.products[0].fixed else "no fix yet"
                line = f"- {a.title}; {fixed}. {_primary(a.sources)}"
                try:
                    lines.append(_guard(line))
                except ValueError:
                    withheld += 1
    if withheld:
        lines += ["", f"{withheld} item{'s' if withheld > 1 else ''} withheld by the publication check."]
    return _guard("\n".join(lines))
