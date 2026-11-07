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
from urllib.parse import urlsplit

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
# A reserved id (``run --kev-file``) is the provenance: it survives the ledger, the
# digest and every later run, and ``schema.validate`` marks its title.
SYNTHETIC, SYNTHETIC_ID, is_synthetic = schema.SYNTHETIC, schema.SYNTHETIC_ID, schema.is_synthetic
# Japanese templates (``lang: ja`` replies). Names, ids, versions, URLs and the
# SYNTHETIC TEST and unverified marks stay as they are.
_JA_LEVEL = {"critical": "緊急", "high": "重要", "notice": "注意"}
_JA_KINDS = ("悪用が確認された脆弱性", "改ざんされたリリース",
             "コード実行につながるインジェクション", "セキュリティアドバイザリ")  # as _KINDS
_JA_OPS = {"<": "未満", "<=": "以下", ">": "超", ">=": "以上", "=": "のみ"}
_EVENT_ID = re.compile(r"[0-9a-f]{64}")


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


def _words_ja(affected: str | None) -> str:
    if affected is None:
        return "（バージョン不明）"
    if affected == "*":
        return "（全バージョン）"
    parts = [_COMPARATOR.fullmatch(t).groups() for t in affected.split(",")]
    return "（" + "、".join(f"{ver} {_JA_OPS[op]}" for op, ver in parts) + "）"


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
    mark = f"{SYNTHETIC}: " if is_synthetic(adv_id) else ""
    return {f"{mark}{name}: {pre}{k} ({adv_id})" for k in _KINDS for pre in ("", "unverified ")}


def _ids(raw, exclude: str) -> list[str]:
    out = []
    for a in raw:
        if isinstance(a, str) and a != exclude and a not in out and schema._IDENT.fullmatch(a):
            out.append(a)
    return out


def source_title(c) -> str | None:
    """The candidate's upstream title for the second body line, or None: never a bare
    template kind, never text the publication guard refuses. Not in the block, not identity."""
    return _upstream(getattr(c, "source_title", None))


def _upstream(t) -> str | None:
    if not isinstance(t, str) or not t.strip() or "\n" in t or "``" in t or "~~" in t \
            or t.strip().casefold() in {p + k for k in _KINDS for p in ("", "unverified ")}:
        return None
    try:
        return _guard(t)
    except ValueError:
        return None


def root_post(c, level, scope, *, posted_at: int | None = None) -> tuple[str, schema.Advisory]:
    """(post text, Advisory) for a new thread: four body lines (five with the source's
    own title second), then the block.
    ``level`` is ``rules.level_for``'s (level, reason), or a bare level. A reserved
    primary id (a synthetic check, ``run --kev-file``) marks the head line, and
    ``schema.validate`` marks the block's title; nothing else marks either."""
    if getattr(scope, "components", ()):  # rules.scope_of resolves an entry to its component
        raise ValueError("an unresolved scope entry would publish a group name")
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
    head = adv.level.upper() + (f" ({SYNTHETIC})" if is_synthetic(adv.id) else "") \
        + (f" ({UNVERIFIED})" if reason == "unverified" else "")
    unexpressed = fix_unexpressed(c)
    title = source_title(c)
    body = [f"{head}: {adv.title}", *([title] if title else []),
            f"Affected: {p.name}{_words(p.affected)}."
            + (f" Fixed in {fixed}." if fixed else " A fix is listed upstream; see the source."
               if unexpressed else " No fixed version is known yet."),
            f"Action: upgrade {p.name} to {fixed} or later." if fixed
            else "Action: upgrade as the source describes." if unexpressed
            else "Action: no fix is published yet; watch this thread.",
            f"Source: {_primary(adv.sources)}"]
    return _guard(schema.render_post(adv, "\n".join(body))), adv


def fix_unexpressed(c) -> bool:
    """A fix the schema cannot express is still a fix: say so, and name no version."""
    return schema_fixed(c.fixed) is None and isinstance(c.fixed, str) and c.fixed.strip() != ""


def _ja_title(adv: schema.Advisory) -> str:
    """A template title with its kind in Japanese ("unverified" stays); any other as it is."""
    name = adv.products[0].name if adv.products else ""
    mark = f"{SYNTHETIC}: " if is_synthetic(adv.id) else ""
    for k, jk in zip(_KINDS, _JA_KINDS):
        for pre in ("", "unverified "):
            if adv.title == f"{mark}{name}: {pre}{k} ({adv.id})":
                return f"{mark}{name}: {pre}{jk} ({adv.id})"
    return adv.title


def root_post_ja(adv: schema.Advisory, reason: str | None = None, unexpressed: bool = False,
                 title: str | None = None) -> str:
    """root_post's body lines in Japanese, from the Advisory root_post returned; ``title``
    (``source_title``) stays in English on its own line after 原題:."""
    p, fixed = adv.products[0], adv.products[0].fixed
    head = _JA_LEVEL[adv.level] + (f" ({SYNTHETIC})" if is_synthetic(adv.id) else "") \
        + (f" ({UNVERIFIED})" if reason == "unverified" else "")
    return "\n".join([
        f"{head}: {_ja_title(adv)}", *([f"原題: {title}"] if title else []),
        f"影響: {p.name}{_words_ja(p.affected)}。"
        + (f" 修正版: {fixed}。" if fixed else " 修正は上流で公開されています。出典を参照してください。"
           if unexpressed else " 修正版はまだ知られていません。"),
        f"対応: {p.name} を {fixed} 以降に更新してください。" if fixed
        else "対応: 出典の説明に従って更新してください。" if unexpressed
        else "対応: 修正はまだ公開されていません。このスレッドで続報を確認してください。",
        f"出典: {_primary(adv.sources)}"])


def _change_line_ja(k: str, adv: schema.Advisory) -> str:
    p = adv.products[0]
    return {
        "level": f"レベルは{_JA_LEVEL[adv.level]}になりました。",
        "products": f"影響: {p.name}{_words_ja(p.affected)}。" + (f" 修正版: {p.fixed}。" if p.fixed else ""),
        "actions": f"対応: {p.name} を {p.fixed} 以降に更新してください。" if adv.actions
        else "現在、記載された対応はありません。",
        "title": f"件名: {_ja_title(adv)}",
        "expires_at": "有効期限は解除されました。" if adv.expires_at is None
        else "このアドバイザリには有効期限が設定されました。",
        "aliases": "別名: " + ", ".join(adv.aliases) + "。",
        "sources": "新しい出典が追加されました。",
        "advisory_severity": "深刻度の評価は解除されました。",
    }[k]


def reply_post_ja(merged: schema.Advisory, c, keys, *, reason: str | None = None) -> str:
    """reply_post's body lines in Japanese for the changed ``keys``; no block."""
    body = [UNVERIFIED[0].upper() + UNVERIFIED[1:] + "."] if reason == "unverified" else []
    body += [_change_line_ja(k, merged) for k in sorted(keys)]
    body.append(f"出典: {_primary(_sources(c.sources) or merged.sources)}")
    return "\n".join(body)


def lang_reply(body: str, of: str | None = None) -> str:
    """``lang: ja``, an optional ``of: <event id>``, a blank line, the body; never a block."""
    if of is not None and not (isinstance(of, str) and _EVENT_ID.fullmatch(of)):
        raise ValueError("of: must be a 64-hex event id")
    if not isinstance(body, str) or not body.strip():
        raise ValueError("an empty Japanese body")
    text = "lang: ja\n" + (f"of: {of}\n" if of else "") + "\n" + body
    if schema._last_block(text) is not schema._NONE:
        raise ValueError("a lang reply carries no aitools-alert block")
    return _guard(text)


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
    if patch.get("title", merged.title) not in _titles(was.name, prev.id):  # as sent, not as read
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


_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")


_DIGEST = {
    "en": dict(empty=lambda d: f"Daily digest for {d}: no advisories.",
               head=lambda d, n: f"Daily digest for {d}: {n} advisor{'y' if n == 1 else 'ies'}.",
               section=lambda lv, n: f"{lv.capitalize()} ({n})",
               withheld=lambda n: f"{n} item{'s' if n > 1 else ''} withheld by the publication check.",
               fixed=lambda v: f"fixed in {v}", nofix="no fix yet", end=".",
               leads=lambda n: f"{n} unrated leads.", release=lambda seg: f"release {seg}",
               one="one release", cves=lambda n: f"{n} CVEs", update="update available",
               see="see the release", title=lambda a: a.title, upstream=lambda t: f": {t}"),
    "ja": dict(empty=lambda d: f"{d} のデイリーダイジェスト: アドバイザリはありません。",
               head=lambda d, n: f"{d} のデイリーダイジェスト: {n} 件。",
               section=lambda lv, n: f"{_JA_LEVEL[lv]} ({n})",
               withheld=lambda n: f"{n} 件を公開前チェックで保留しました。",
               fixed=lambda v: f"修正版 {v}", nofix="修正版はまだありません", end="。",
               leads=lambda n: f"未評価のリード {n} 件。", release=lambda seg: f"リリース {seg}",
               one="1 件のリリース", cves=lambda n: f"CVE {n} 件", update="更新あり",
               see="リリースを参照", title=_ja_title, upstream=lambda t: f" 原題: {t}"),
}


def _single(a: schema.Advisory, t=_DIGEST["en"], title: str | None = None) -> str:
    fixed = t["fixed"](a.products[0].fixed) if a.products[0].fixed else t["nofix"]
    up = t["upstream"](title) if title else ""
    return f"- {t['title'](a)}{up}; {fixed}{t['end']} {_primary(a.sources)}"


def _group_key(a: schema.Advisory):
    """Advisories that share one digest line, or None for a line of its own. A
    critical is always its own line; so is any title but the plain kind, so a shared
    catalog URL (every KEV entry) never reads as one release and "unverified" stays."""
    name = a.products[0].name
    if a.level == "critical" or a.title != f"{name}: security advisory ({a.id})":
        return None
    if a.id.startswith("LEAD-"):  # "unrated": a lead rated above notice keeps its own line
        return ("lead", name) if a.level == "notice" else None
    if a.id.startswith("CVE-"):
        return ("release", name, _primary(a.sources))
    return None


def _group_line(key, members, t=_DIGEST["en"]) -> str:
    if key[0] == "lead":
        return f"- {key[1]}: {t['leads'](len(members))}"
    url = key[2]
    seg = next((p for p in reversed(urlsplit(url).path.split("/")) if p), "")
    label = t["release"](seg) if _LABEL.fullmatch(seg) else t["one"]
    fixes = {a.products[0].fixed for a in members}
    fix = t["fixed"](fixes.pop()) if len(fixes) == 1 and None not in fixes \
        else t["update"] if schema.is_primary(url) else t["see"]
    return f"- {key[1]}: {label}, {t['cves'](len(members))}; {fix}{t['end']} {url}"


def digest(advs_today, date, lang: str = "en", *, retracted=(), now: int | None = None,
           titles=None) -> str:
    """The daily digest: every advisory once per id and product (latest posted_at
    wins), critical first. Within high and notice, plain CVE advisories sharing a
    primary source URL and product are one line (a vendor release), and leads are one
    line per scope; N counts lines. An item that fails the publication guard is
    withheld and counted, never the whole digest. The ledger and --json keep every
    advisory: this grouping is presentation only. ``lang="ja"``: the same digest from
    the Japanese templates. Left out, and not counted: a synthetic id, an advisory
    whose id or alias is in ``retracted`` (case-folded) and, given ``now``, one whose
    latest version expired before it (``pull.active``'s rule). ``titles`` maps (id,
    product name) to a source title, which a line of its own carries after the id."""
    t = _DIGEST[lang]
    latest: dict[tuple, schema.Advisory] = {}
    for adv in advs_today:
        if not (adv.products and adv.sources):
            continue
        key = (adv.id, adv.products[0].name)
        if key not in latest or adv.posted_at >= latest[key].posted_at:
            latest[key] = adv
    gone = {i.casefold() for i in retracted}
    latest = {k: a for k, a in latest.items() if not (
        is_synthetic(a.id) or not gone.isdisjoint(i.casefold() for i in (a.id, *a.aliases))
        or (now is not None and a.expires_at is not None and a.expires_at < now))}
    day = date.isoformat() if hasattr(date, "isoformat") else str(date)
    if not latest:
        return t["empty"](day)
    sections = {}
    for level in ("critical", "high", "notice"):
        groups: dict = {}
        for a in sorted((a for a in latest.values() if a.level == level), key=lambda a: (a.posted_at, a.id)):
            k = _group_key(a)
            groups.setdefault(k if k is not None else ("single", a.id, a.products[0].name), []).append(a)
        sections[level] = [_single(m[0], t, _upstream((titles or {}).get((m[0].id, m[0].products[0].name))))
                           if k[0] == "single" or len(m) == 1 else _group_line(k, m, t)
                           for k, m in groups.items()]
    n = sum(len(v) for v in sections.values())
    lines, withheld = [t["head"](day, n)], 0
    for level, items in sections.items():
        if items:
            lines += ["", t["section"](level, len(items))]
            for line in items:
                try:
                    lines.append(_guard(line))
                except ValueError:
                    withheld += 1
    if withheld:
        lines += ["", t["withheld"](withheld)]
    return _guard("\n".join(lines))
