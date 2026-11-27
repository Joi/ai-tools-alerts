"""Compose relay-bot posts: a root advisory, a reply carrying only changed fields, the digest.

Post text leaves the fleet, so it is built only from fields that are safe to
publish: the candidate's id, aliases, fixed/affected versions and sources, the
level, the matched scope entry's display name and ``advisory_severity`` only as one
word of SEVERITIES (0dvh). ``product_text``, ``local_level_hint`` and ``observed_at``
are rule inputs and are never read here (B1: a version in them can be a locally
observed one).
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
from collections import Counter
from dataclasses import asdict

from aitools_alerts import schema, wire
from aitools_alerts.config import DEFAULT_MIRROR_URL
from aitools_alerts.poster import candidates

POSTED_BY = "relay-bot"
_PATCH_KEYS = frozenset(schema.Advisory.__dataclass_fields__) - {"id", "posted_by"}
_REPLY_KEYS = frozenset({"level", "title", "products", "actions", "aliases", "sources",
                         "expires_at", "advisory_severity"})
_NULLABLE = frozenset({"advisory_severity", "expires_at"})
_OPS = {"<": "before", "<=": "up to", ">": "after", ">=": "from", "=": "exactly"}
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


def _words(affected: str | None, unexpressed: bool = False) -> str:
    if affected is None:  # 0dvh: "not stated" only when the source gives no range
        return ", affected versions: see the source" if unexpressed else ", versions not stated"
    if affected == "*":
        return ", all versions"
    parts = [_COMPARATOR.fullmatch(t).groups() for t in affected.split(",")]
    return " " + " and ".join(f"{_OPS[op]} {ver}" for op, ver in parts)


def _words_ja(affected: str | None, unexpressed: bool = False) -> str:
    if affected is None:
        return "（影響バージョンは出典を参照）" if unexpressed else "（バージョン不明）"
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


_URL_TOKEN = re.compile(r"https?://\S+")
# The relay reads "@" at the start or after whitespace, then [A-Za-z0-9._-]+, as a
# member mention and refuses an unknown name; it skips inline code.
_MENTION = re.compile(r"(?<!\S)@[A-Za-z0-9._-][!-\[\]-_a-~]*")  # printable ASCII but ` and backslash


def _inline(text: str) -> str:
    """Body text with every mention-shaped @token in inline code, exact and readable.
    The only backticks left are those pairs: one in a URL is percent-encoded (the
    same URL), any other removed, so no text can open or close a span around ours."""
    return _wrap_mentions(_URL_TOKEN.sub(lambda m: m.group().replace("`", "%60"), text).replace("`", ""))


def _wrap_mentions(text: str) -> str:
    def wrap(m):
        tok = m.group()
        core = tok.rstrip(".,;:!?)]}'\"")
        core = core if len(core) > 1 else tok
        return f"`{core}`{tok[len(core):]}"
    return _MENTION.sub(wrap, text)


# An @ the relay could read as a mention once it has replaced each code region with a space.
# No re.M: \s in the lookbehind already covers the character after a newline.
_LIVE_AT = re.compile(r"(?:^|(?<=[\s`]))@[A-Za-z0-9._-]")
# In text with a backtick, where a Markdown reader could pair backticks otherwise than the
# relay: a doubled or escaped backtick, a CR line break, a backtick in a URL, and any < that
# can open an HTML tag or an autolink (one may span lines and hold a backtick in an
# attribute); a version range such as <2.1 or <=2.1 is none of these.
_AMBIGUOUS = re.compile(r"``|\\`|\r|https?://[^\s`]*`|<[A-Za-z!?/]")


def mention_safe(text: str) -> str | None:
    """Text from outside the poster (a curator translation) with every mention-shaped
    @token outside code in inline code, its own code spans untouched; None when that
    cannot be done safely. The relay pairs a backtick with the next one on its line and
    reads no escapes, so only text whose backticks the relay and a Markdown reader pair
    the same way (an even count on every line, none in an _AMBIGUOUS place) is wrapped;
    other text passes only when it holds no @ a code-region strip could leave as a mention."""
    lines = text.split("\n")
    if "`" in text and (_AMBIGUOUS.search(text) or any(line.count("`") % 2 for line in lines)):
        return None if _LIVE_AT.search(text) else text
    out = []
    for line in lines:
        parts = line.split("`")  # even indexes are outside spans
        parts[0::2] = [_wrap_mentions(p) for p in parts[0::2]]
        out.append("`".join(parts))
    text = "\n".join(out)
    return None if "``" in text else text  # a wrapped token touching a span


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
            if isinstance(pub, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2} \d.*", pub):
                pub = pub.replace(" ", "T", 1)  # 0dvh: an accepted input form; the date must survive
            pub = pub if isinstance(pub, str) and schema._DATE.fullmatch(pub) else None
            out.append(schema.Source(url, pub))
    out.sort(key=lambda s: not schema.is_primary(s.url))  # stable: primary first
    return out[:20]


def _kind(c, reason) -> str:
    flags = (c.exploited, c.trojanized, c.injection_exec, True)
    kind = next(k for k, f in zip(_KINDS, flags) if f is True)
    return "unverified " + kind if reason == "unverified" else kind


def _exploited(adv: schema.Advisory) -> bool:
    """The title says known exploited (plain, unverified or synthetic, as _kind built it)."""
    return any(adv.title.endswith(f"{_KINDS[0]} ({i})") for i in {adv.id, public_form(adv.id)})


def _titles(name: str, adv_id: str) -> set[str]:
    """Every template title for this id: under its public form (0dvh) and, for a
    thread posted before 0dvh, under the ledger key it was titled with."""
    mark = f"{SYNTHETIC}: " if is_synthetic(adv_id) else ""
    return {f"{mark}{name}: {pre}{k} ({i})" for k in _KINDS for pre in ("", "unverified ")
            for i in {adv_id, public_form(adv_id)}}


# A poster ledger key (an id, a colon, a scope slug: CVE-2026-123158:openssh) is
# identity, never a public alias (8ke5).
_LEDGER_KEY = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}):", re.I)


def public_form(adv_id: str) -> str:
    """The id a title names: a ledger key's id without its scope slug, else the id."""
    m = _LEDGER_KEY.match(adv_id) if isinstance(adv_id, str) else None
    return adv_id[:m.end() - 1] if m else adv_id


# The upstream severity words the block may carry (0dvh), loudest first; any other value stays null.
_SEVERITY_ORDER = ("critical", "high", "medium", "moderate", "low")
SEVERITIES = frozenset(_SEVERITY_ORDER)


def severity(v) -> str | None:
    """The loudest allowed word of a candidate's severity (ledger.merge joins members' with "; ")."""
    words = {w.strip().casefold() for w in v.split(";")} if isinstance(v, str) else set()
    return next((w for w in _SEVERITY_ORDER if w in words), None)


def range_unexpressed(c) -> bool:
    """A range the schema cannot say is still a range: never "versions not stated"."""
    return schema_affected(c.affected) is None and isinstance(c.affected, str) and c.affected.strip() != ""


def public_id(a) -> bool:
    """An id a post may name as an alias: a bare CVE or GHSA id (h340). A ledger key
    (CVE-2026-123158:openssh) is identity, never an alias (8ke5); any other shape is
    text someone upstream chose."""
    return isinstance(a, str) and candidates.ADVISORY_ID.fullmatch(a) is not None


def _ids(raw, exclude: str) -> list[str]:
    out = []
    for a in raw:
        if a != exclude and a not in out and public_id(a):
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
        return _guard(" ".join(t.replace("`", "").split()))  # no backtick to pair with ours
    except ValueError:
        return None


HEADLINE_MAX = 90  # design section 6: level, package, what goes wrong
_REGISTRY = {"pypi": "PyPI", "npm": "npm", "cargo": "crates.io", "crates": "crates.io", "go": "Go",
             "gem": "RubyGems", "rubygems": "RubyGems", "maven": "Maven", "nuget": "NuGet"}


def package_of(scope) -> tuple[str, str | None]:
    """(the package a member types, its registry's name) from the scope entry's
    ``package`` (``pypi:mcp-server-git``); the product name and None without one."""
    pkg = getattr(scope, "package", None)
    if isinstance(pkg, str) and ":" in pkg:
        eco, name = pkg.split(":", 1)
        return name, _REGISTRY.get(eco, eco)
    return scope.name, None


def headline(head: str, name: str, title: str | None, fallback: str) -> str:
    """The first line: ``head``, a colon, then what goes wrong in at most HEADLINE_MAX
    characters. In this slice the text is the source's own title, after the product name
    when the title does not name it; with no title, ``fallback``. No id. The title is cut
    at a word boundary to fit; the markers in ``head`` are never cut."""
    text = title if title else fallback
    if title and not re.search(rf"(?<![\w@/-]){re.escape(name)}(?![\w-])", title, re.I):
        text = f"{name}: {title}"
    # _inline later wraps each mention-shaped token in two backticks
    room = max(HEADLINE_MAX - len(head) - 2 - 2 * len(_MENTION.findall(text)), 20)
    if len(text) > room:
        cut = text[:room - 1]
        cut = cut[:cut.rfind(" ")] if " " in cut[len(name) + 2:] else cut
        text = cut.rstrip(" ,;:-") + "…"
    return f"{head}: {text}"


def covers(adv: schema.Advisory) -> tuple[int | None, list[str]]:
    """(how many advisories, their public ids): the id's public form, then the public
    aliases, once each. A GHSA is one advisory and a CVE usually an alias of one, so with
    no more CVE ids than GHSA ids the count is the GHSA ids; with none of one kind it is
    every id; otherwise (a group mixing GHSA advisories and CVE-only entries) the flat
    list cannot say, and the count is None."""
    ids, seen = [], set()
    for i in (public_form(adv.id), *adv.aliases):
        if public_id(i) and i.casefold() not in seen:
            seen.add(i.casefold())
            ids.append(i)
    ghsa = sum(i.upper().startswith("GHSA-") for i in ids)
    cve = len(ids) - ghsa
    return (len(ids) if not ghsa or not cve else ghsa if cve <= ghsa else None), ids


def _covers_line(adv, ja=False) -> list[str]:
    n, ids = covers(adv)
    if not ids:
        return []
    if n is None:
        return [f"対象: {', '.join(ids)}" if ja else f"Covers: {', '.join(ids)}"]
    return [f"対象: アドバイザリ {n} 件: {', '.join(ids)}" if ja
            else f"Covers {n} advisor{'y' if n == 1 else 'ies'}: {', '.join(ids)}"]


def _do(name, fixed, *, stop=False, unexpressed=False, exploited=False, ja=False) -> str:
    """The one action sentence (design section 6): never "check the vendor"."""
    if ja:
        if fixed:
            return f"対応: {name} を {fixed} 以降に更新してください。"
        if stop:
            return f"対応: 修正版はまだありません。修正版が出るまで {name} の使用を停止してください。"
        if unexpressed:
            return f"対応: {name} を出典に記載された修正版に更新してください。"
        return ("対応: 悪用が確認されています。" if exploited else "対応: ") \
            + "出典に回避策があれば適用し、修正版が出るまで続けてください。"
    if fixed:
        return f"Do: upgrade {name} to {fixed} or later."
    if stop:
        return f"Do: no fix yet. Stop using {name} until one ships."
    if unexpressed:
        return f"Do: upgrade {name} to the fixed release the source names."
    return ("Do: this is exploited in the wild. Apply" if exploited else "Do: apply") \
        + " the source's workaround, if it gives one, until a fixed release ships."


def worded(head: str, name: str, wording) -> bool:
    """The model's headline fits beside ``head`` whole: a model line is never cut (c6ak)."""
    return wording is not None and "…" not in headline(head, name, wording.headline, wording.headline)


def head_of(level: str, adv_id: str, reason: str | None = None) -> str:
    """The head line's level and markers, as root_post writes them."""
    return level.upper() + (f" ({SYNTHETIC})" if is_synthetic(adv_id) else "") \
        + (f" ({UNVERIFIED})" if reason == "unverified" else "")


def root_post(c, level, scope, *, posted_at: int | None = None, wording=None) -> tuple[str, schema.Advisory]:
    """(post text, Advisory) for a new thread: five body lines (headline, Affected, Do,
    Covers, Source; design section 6), then the block on one line.
    ``c.id`` must be a CVE or GHSA id, bare or as a thread key (``candidates.BOT_ID``).
    ``level`` is ``rules.level_for``'s (level, reason), or a bare level. A reserved
    primary id (a synthetic check, ``run --kev-file``) marks the head line, and
    ``schema.validate`` marks the block's title; nothing else marks either. A critical
    carries a complete action (9kgk): an upgrade to a stated version, or, with reason
    ``stop-using`` (``rules.level_for``), stop_using the product; any other critical
    raises ValueError and does not post, except a bare level (reason None): the level a
    thread already stands at, which ``plan_known`` keeps. ``wording`` (``wording.Wording``,
    c6ak) replaces the source title in the headline and adds a ``Who:`` line after it,
    when its headline fits whole; it is body text only and never reaches the block."""
    if getattr(scope, "components", ()):  # rules.scope_of resolves an entry to its component
        raise ValueError("an unresolved scope entry would publish a group name")
    if not (isinstance(c.id, str) and candidates.BOT_ID.fullmatch(c.id)):
        raise ValueError("the id is not a CVE or GHSA id: the advisory does not post")  # h340
    level, reason = level if isinstance(level, tuple) else (level, None)
    fixed = schema_fixed(c.fixed)
    stop = level == "critical" and not fixed and reason == "stop-using"
    if level == "critical" and not fixed and reason is not None and not stop:
        # reason None is a thread's standing level, which a run never lowers (plan_known)
        raise ValueError("a critical needs a complete action: no fixed version and no stop_using basis")
    sources = _sources(c.sources)
    if not sources:
        raise ValueError("no https source the schema accepts: the advisory does not post")
    adv = schema.validate(asdict(schema.Advisory(
        id=c.id, aliases=_ids(c.aliases, c.id)[:50], level=level, advisory_severity=severity(c.severity_word),
        title=f"{scope.name}: {_kind(c, reason)} ({public_form(c.id)})",
        products=[schema.Product(scope.name, scope.ecosystem, schema_affected(c.affected), fixed)],
        actions=[schema.Action("upgrade", scope.name, fixed)] if fixed
        else [schema.Action("stop_using", scope.name, None)] if stop else [],
        sources=sources, posted_by=POSTED_BY,
        posted_at=int(time.time()) if posted_at is None else posted_at, expires_at=None)))
    p = adv.products[0]
    head = head_of(adv.level, adv.id, reason)
    wording = wording if worded(head, p.name, wording) else None
    # No version is not no fix: a KEV entry carries no version data at all (4yr1). A fix
    # the schema cannot express is named by the source, never by a version here (h340).
    body = _root_lines(adv, head, wording.headline if wording else source_title(c),
                       f"{p.name}: {_kind(c, None)}", scope,  # the head marks unverified
                       who=wording.who if wording else None, stop=stop, unexpressed=fix_unexpressed(c),
                       range_unexpressed=range_unexpressed(c), exploited=c.exploited is True)
    return _guard(schema.render_post(adv, _inline("\n".join(body)))), adv


def _root_lines(adv, head, title, fallback, scope, *, who=None, stop=False, unexpressed=False,
                range_unexpressed=False, exploited=False) -> list[str]:
    """A root's body lines (design section 6), for ``root_post`` and ``copy_post``."""
    p = adv.products[0]
    pkg, registry = package_of(scope)
    return [headline(head, p.name, title, fallback),
            *([f"Who: {who}"] if who else []),
            f"Affected: {pkg}{_words(p.affected, range_unexpressed)}" + (f" ({registry})." if registry else "."),
            _do(p.name, p.fixed, stop=stop, unexpressed=unexpressed, exploited=exploited or _exploited(adv)),
            *_covers_line(adv), f"Source: {_primary(adv.sources)}"]


def title_reason(adv: schema.Advisory) -> str | None:
    """"unverified" when the block's template title says so, else None: the reason a
    root composed from the block alone marks its head with (``copy_post``)."""
    name = adv.products[0].name if adv.products else ""
    return "unverified" if adv.title in _titles(name, adv.id) and f"{name}: unverified " in adv.title else None


def copy_post(adv: schema.Advisory, scope, *, title: str | None = None, exploited: bool = False) -> str:
    """The post text of a root for a thread that already exists, in a channel of its
    level that has none (ai-tools-alerts#3t4p): ``root_post``'s body lines over the
    thread's advisory as the ledger holds it. The block is ``adv`` and nothing else, so
    every channel of the thread states the same advisory; ``root_post`` builds its block
    from a candidate's flags, which the ledger does not keep. ``title`` is the ledger's
    source title; ``exploited`` the ledger's mark. The head says unverified when the
    block's title does. No model wording: the ledger keeps no source prose.

    Raises ValueError, and nothing posts, for an unresolved scope entry, an id that is
    not a CVE or GHSA id, a product that is not the scope's, no source, a critical with
    no complete action (9kgk: a fixed version, or stop_using the product), text that does
    not parse back to ``adv`` (``schema.render_post``) and text the guard refuses."""
    adv = schema.validate(asdict(adv))
    if getattr(scope, "components", ()):
        raise ValueError("an unresolved scope entry would publish a group name")
    if not candidates.BOT_ID.fullmatch(adv.id):
        raise ValueError("the id is not a CVE or GHSA id: the advisory does not post")
    if len(adv.products) != 1 or adv.products[0].name != scope.name or not adv.sources:
        raise ValueError("a copy needs the scope's own product and a source")
    p = adv.products[0]
    stop_using = any(a.verb == "stop_using" and a.target == p.name for a in adv.actions)
    upgrade = bool(p.fixed) and any(a.verb == "upgrade" and a.target == p.name for a in adv.actions)
    if adv.level == "critical" and not (stop_using or upgrade):  # as main._complete reads a journaled block
        raise ValueError("a critical needs a complete action: no fixed version and no stop_using")
    stop = stop_using and not p.fixed
    head = head_of(adv.level, adv.id, title_reason(adv))
    kind = _headline_kind(adv).removeprefix(f"{SYNTHETIC}: ").replace(": unverified ", ": ", 1)
    body = _root_lines(adv, head, _upstream(title), kind, scope, stop=stop, exploited=exploited is True)
    return _guard(schema.render_post(adv, _inline("\n".join(body))))  # render_post: it parses back to adv


def catalog_post(adv) -> str:
    """A catalog root (q03f): the level and title, the primary source, then the whole
    block. Machines read the block; the two lines are for a person who opens the
    channel. A synthetic advisory never reaches the catalog (ValueError)."""
    a = schema.validate(adv if isinstance(adv, dict) else asdict(adv))
    if is_synthetic(a.id) or not a.sources:
        raise ValueError("a synthetic advisory, or one with no source, is not catalogued")
    body = [f"{a.level.upper()}: {a.title}", f"Source: {_primary(a.sources)}"]
    return _guard(schema.render_post(a, _inline("\n".join(body))))


def fix_unexpressed(c) -> bool:
    """A fix the schema cannot express is still a fix: say so, and name no version."""
    return schema_fixed(c.fixed) is None and isinstance(c.fixed, str) and c.fixed.strip() != ""


def _ja_title(adv: schema.Advisory) -> str:
    """A template title with its kind in Japanese ("unverified" stays); any other as it is."""
    name = adv.products[0].name if adv.products else ""
    mark = f"{SYNTHETIC}: " if is_synthetic(adv.id) else ""
    for k, jk in zip(_KINDS, _JA_KINDS):
        for pre in ("", "unverified "):
            for i in {adv.id, public_form(adv.id)}:
                if adv.title == f"{mark}{name}: {pre}{k} ({i})":
                    return f"{mark}{name}: {pre}{jk} ({i})"
    return adv.title


def _ja_kind(adv: schema.Advisory) -> str:
    """The template title's product and kind in Japanese, without the id: the headline
    when there is no source title."""
    t = re.sub(r" \([^()]*\)$", "", _ja_title(adv))
    t = t.removeprefix(f"{SYNTHETIC}: ")  # the head marks both
    return t.replace(": unverified ", ": ", 1)


def root_post_ja(adv: schema.Advisory, reason: str | None = None, unexpressed: bool = False,
                 title: str | None = None, *, exploited: bool = False, range_unexpressed: bool = False,
                 package: tuple[str, str | None] | None = None, wording=None) -> str:
    """root_post's five body lines in Japanese, from the Advisory root_post returned. The
    headline is the same ``title`` (``source_title``), in English as the source wrote it.
    ``exploited`` is the candidate's: a thread keeps its first title unless its level
    rises, so the title alone can miss a KEV entry learned later. ``package`` is
    ``package_of(scope)``; without it the product name and no registry. ``wording``
    is the one root_post used: its headline, in English; its Who line is not put
    in the Japanese post, whose other lines are all the template's (c6ak)."""
    exploited = exploited or _exploited(adv)
    p, fixed = adv.products[0], adv.products[0].fixed
    head = _JA_LEVEL[adv.level] + (f" ({SYNTHETIC})" if is_synthetic(adv.id) else "") \
        + (f" ({UNVERIFIED})" if reason == "unverified" else "")
    stop = not fixed and any(a.verb == "stop_using" for a in adv.actions)
    pkg, registry = package or (p.name, None)
    return _inline("\n".join([
        headline(head, p.name, wording.headline if worded(head, p.name, wording) else _upstream(title),
                 _ja_kind(adv)),
        f"影響: {pkg}{_words_ja(p.affected, range_unexpressed)}" + (f"（{registry}）。" if registry else "。"),
        _do(p.name, fixed, stop=stop, unexpressed=unexpressed and not fixed, exploited=exploited, ja=True),
        *_covers_line(adv, ja=True), f"出典: {_primary(adv.sources)}"]))


def _change_line_ja(k: str, adv: schema.Advisory, unexpressed: bool = False) -> str:
    p = adv.products[0]
    return {
        "level": f"レベルは{_JA_LEVEL[adv.level]}になりました。",
        "products": f"影響: {p.name}{_words_ja(p.affected, unexpressed)}。" + (f" 修正版: {p.fixed}。" if p.fixed else ""),
        "actions": _do(p.name, p.fixed, ja=True) if p.fixed and adv.actions
        else _do(p.name, None, stop=True, ja=True) if adv.actions else "現在、記載された対応はありません。",
        "title": "",  # it changes with the level, whose line says so (faxq)
        "expires_at": "有効期限は解除されました。" if adv.expires_at is None
        else "このアドバイザリには有効期限が設定されました。",
        "aliases": "別名: " + ", ".join(a for a in adv.aliases if public_id(a)) + "。",
        "sources": "新しい出典が追加されました。",
        "advisory_severity": "深刻度の評価は解除されました。" if adv.advisory_severity is None
        else f"上流の深刻度: {adv.advisory_severity}。",
    }[k]


def reply_post_ja(merged: schema.Advisory, c, keys, *, reason: str | None = None) -> str:
    """reply_post's body lines in Japanese for the changed ``keys``; no block."""
    body = [UNVERIFIED[0].upper() + UNVERIFIED[1:] + "."] if reason == "unverified" else []
    body += [line for k in sorted(keys) if (line := _change_line_ja(k, merged, range_unexpressed(c))
                                             or k == "title" and "level" not in keys and f"件名: {_ja_kind(merged)}")]
    body.append(f"出典: {_primary(_sources(c.sources) or merged.sources)}")
    return _inline("\n".join(body))


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
    if bad or merged.advisory_severity not in (None, *SEVERITIES):  # 0dvh: an upstream word may be published
        raise ValueError(f"reply: not publishable by the relay bot {sorted(bad) or ['advisory_severity']}")
    p, was = merged.products, prev.products[0]
    if len(p) != 1 or (p[0].name, p[0].ecosystem) != (was.name, was.ecosystem):
        raise ValueError("reply: the product is the scope entry's, one product")
    if patch.get("title", merged.title) not in _titles(was.name, prev.id):  # as sent, not as read
        raise ValueError("reply: the title is a template title")
    # 9kgk: a stop_using the root carried stays while no fix is stated; nothing else is an action
    kept = ("stop_using", was.name, None) if p[0].fixed is None and any(
        (a.verb, a.target) == ("stop_using", was.name) for a in prev.actions) else None
    if any((a.verb, a.target, a.value) not in (("upgrade", was.name, p[0].fixed), kept) for a in merged.actions):
        raise ValueError("reply: the only action is upgrade to products[0].fixed")
    if {s.url for s in _sources(asdict(s) for s in merged.sources)} != {s.url for s in merged.sources}:
        raise ValueError("reply: a source fails the publication checks")


def _headline_kind(adv: schema.Advisory) -> str:
    """The block's template title without its id: what a title-only reply says."""
    return re.sub(r" \([^()]*\)$", "", adv.title)


def _change_line(k: str, adv: schema.Advisory, unexpressed: bool = False) -> str:
    p = adv.products[0]
    return {
        "level": f"Level is now {adv.level}.",
        "products": f"Affected: {p.name}{_words(p.affected, unexpressed)}." + (f" Fixed in {p.fixed}." if p.fixed else ""),
        "actions": _do(p.name, p.fixed) if p.fixed and adv.actions
        else _do(p.name, None, stop=True) if adv.actions else "No action listed now.",
        "title": "",  # it changes with the level, whose line says so (faxq)
        "expires_at": "Expiry cleared." if adv.expires_at is None else "This advisory now expires.",
        "aliases": "Also known as: " + ", ".join(a for a in adv.aliases if public_id(a)) + ".",
        "sources": "New sources listed.",
        "advisory_severity": "Severity rating cleared." if adv.advisory_severity is None
        else f"Upstream severity: {adv.advisory_severity}.",
    }[k]


def reply_post(prev: schema.Advisory, c, changes: dict, *, reason: str | None = None,
               lowered: bool = False) -> str:
    """A thread reply: one line per changed field, a source line, then a block of the
    changed fields only. Unchanged keys are dropped; aliases and sources are capped
    at the schema's 50 and 20. ``reason`` 'unverified' adds the unverified line.
    ``lowered``: the thread has had a lowering (the caller's ledger knows); then no
    level change at all may ride here, a raise included (spec/wire.md, rule 2).
    Raises ValueError for an empty, invalid or unpublishable patch."""
    if not isinstance(changes, dict):
        raise ValueError("changes: not an object")
    old = asdict(prev)
    patch = {}
    for k, v in changes.items():
        if isinstance(v, (list, tuple)):
            v = [asdict(x) if hasattr(x, "__dataclass_fields__") else x for x in v]
        if k == "aliases" and isinstance(v, list):  # prev's list as published, then new public ids
            have = {a.casefold() for a in old["aliases"]}  # a reply never removes an alias
            v = (old["aliases"] + [a for a in _ids(v, prev.id) if a.casefold() not in have])[:50]
        elif k == "sources" and isinstance(v, list):
            v = [asdict(s) for s in _sources(old["sources"] + v)]
        if k not in old or k in ("id", "posted_by") or old[k] != v:
            patch[k] = v
    prods = patch.get("products")
    if "actions" not in changes and isinstance(prods, list) and prods and isinstance(prods[0], dict):
        fixed = prods[0].get("fixed")  # the upgrade action follows the fixed version
        acts = [{"verb": "upgrade", "target": prev.products[0].name, "value": fixed}] if fixed else \
            [a for a in old["actions"] if a["verb"] == "stop_using"]  # 9kgk: a malicious release's action stays
        if acts != old["actions"]:
            patch["actions"] = acts
    if not patch:
        raise ValueError("reply with no changed field")
    if "expires_at" in patch:
        # Every reader refuses a relay-bot reply that sets expires_at, and a finite one in a
        # root ends the alert on released readers with no renewal: root_post writes null, a
        # reply leaves the key out (spec/wire.md).
        raise ValueError("reply: a relay-bot reply carries no expires_at")
    if wire.is_lowering(patch, prev.level):
        # Readers at 0.1.7 and earlier skip a relay-bot reply that lowers the level: before
        # 0.1.7 a fix or a source in the same reply is lost with it (spec/wire.md).
        raise ValueError("reply: a lowering travels alone (level_post)")
    if lowered and "level" in patch:
        # Those readers kept the higher level, so this raise may be a lowering to them.
        raise ValueError("reply: on a thread that was lowered, a level change travels alone (level_post)")
    merged = apply_patch(prev, patch)
    _publishable(prev, merged, patch)
    body = [UNVERIFIED[0].upper() + UNVERIFIED[1:] + "."] if reason == "unverified" else []
    body += [line for k in sorted(patch) if (line := _change_line(k, merged, range_unexpressed(c))
                                              or k == "title" and "level" not in patch and f"Now: {_headline_kind(merged)}.")]
    body.append(f"Source: {_primary(_sources(c.sources) or merged.sources)}")
    block = json.dumps(patch, ensure_ascii=False, separators=(",", ":"))  # one line (faxq)
    out = _inline("\n".join(body)) + f"\n\n```{schema.INFO_STRING}\n{block}\n```\n"
    if parse_reply(out, prev) != merged:
        raise ValueError("reply does not parse back")
    return _guard(out)


RENEWAL = "Sources checked. No change to this alert."
UNCONFIRMED = "No source has confirmed the higher level for {days} days."


def renewal_post() -> str:
    """A renewal (gtw9, spec/wire.md): a thread reply whose only news is its event's
    claim tag. One fixed line and no block, so every reader takes it as discussion."""
    return _guard(RENEWAL)


WITHDRAWAL = "The source withdrew this advisory."


def withdrawal_post() -> str:
    """The withdrawal (kk2q, spec/wire.md "A withdrawal"): one fixed line and a block of
    exactly ``{"level":"withdrawn"}``, alone in its reply like every lowering. The word
    is no level: released readers skip the reply and keep the alert. Its claim, the
    withdrawn reading's, travels in the event's tag."""
    patch = {"level": wire.WITHDRAWN}
    out = WITHDRAWAL + f"\n\n```{schema.INFO_STRING}\n{json.dumps(patch, separators=(',', ':'))}\n```\n"
    if not wire.is_withdrawal(json.loads(schema._last_block(out))) or schema.parse_post(out) is not None:
        raise ValueError("withdrawal does not parse back")
    return _guard(out)


def level_post(prev: schema.Advisory, level: str, reason: str | None = None, again: bool = False) -> str:
    """A thread reply that changes the level and nothing else: one line and a block of
    exactly ``{"level": ...}``. What justifies it travels in the event's claim tag
    (``wire.claim_tag``), never in the block. ``reason``: one more sentence on the
    line (gtw9: why a level nothing confirmed was stepped down).

    Every lowering is sent this way, and so is every level change on a thread that
    has had a lowering (spec/wire.md). Readers at 0.1.7 and earlier refuse a
    relay-bot lowering and keep the higher level; from then on they hold a higher
    level than the poster does, so a later raise can be a lowering to them too.
    Alone, a refused level change costs them nothing else. Raises ValueError unless
    ``level`` is a known level other than the thread's. ``again`` (kk2q): the thread
    is withdrawn, and the reply that ends that may name the level the thread kept."""
    patch = {"level": level}
    if not isinstance(level, str) or level not in wire.LEVELS or (level == prev.level and not again):
        raise ValueError("level change: the level must be a known level other than the thread's")
    merged = apply_patch(prev, patch)
    line = _change_line("level", merged) + (f" {reason}" if reason else "")
    out = _inline(line) + f"\n\n```{schema.INFO_STRING}\n{json.dumps(patch, separators=(',', ':'))}\n```\n"
    if parse_reply(out, prev) != merged or json.loads(schema._last_block(out)) != patch:
        raise ValueError("level change does not parse back")
    return _guard(out)


def level_report(lowered, tripped, lang: str = "en") -> str:
    """The lines a digest adds for the recompute (ny5g, D15), or "": one listing the
    ids lowered since the last digest, ``[[id, level]]`` (kk2q: or ``[id, "withdrawn"]``,
    printed as withdrawn), and one while the circuit
    breaker holds lowerings back (``tripped``: ``{"due": n}`` or None; n is how many wait). Only a bare
    CVE or GHSA id is printed, at most 50."""
    ja = lang == "ja"
    done = [(i, lv) for i, lv in lowered if public_id(i) and (lv in wire.LEVELS or lv == wire.WITHDRAWN)]
    lines = []
    if done:
        shown = "; ".join((f"{i} (取り下げ)" if ja else f"{i} withdrawn") if lv == wire.WITHDRAWN
                          else f"{i} ({_JA_LEVEL[lv]})" if ja else f"{i} to {lv}" for i, lv in done[:50])
        more = len(done) - 50
        if ja:
            lines.append(f"前回のダイジェスト以降に引き下げ: {shown}" + (f"、ほか {more} 件" if more > 0 else "") + "。")
        else:
            lines.append(f"Lowered since the last digest: {shown}" + (f"; and {more} more" if more > 0 else "") + ".")
    if tripped:
        n = tripped["due"]
        lines.append(f"レベル確認: 1 日のうちに引き下げの対象が上限を超えたため、保留しています (保留中: {n} 件)。" if ja
                     else f"Level check: more threads fell due to be lowered within a day than the limit allows; "
                          f"held back: {n}.")
    return _guard("\n\n" + "\n".join(lines)) if lines else ""


_DIGEST = {
    "en": dict(head=lambda d, n: f"Daily digest for {d}: {n} new alert{'' if n == 1 else 's'}.",
               quiet=lambda d, n, url: f"Daily digest for {d}: no new alerts. "
                                       f"{n} notice{'' if n == 1 else 's'} added to the catalog this week: {url}",
               bare=lambda d: f"Daily digest for {d}: no new alerts.",
               level=lambda lv: lv.upper(),
               withheld=lambda n: f"{n} item{'s' if n > 1 else ''} withheld by the publication check.",
               foreign="Warning: an event signed with this service's key was not sent by this service. "
                       "No checkpoint lists it, so the CLI does not apply it.",
               fixed=lambda v: f"fixed in {v}", nofix="fixed version not stated, check the vendor", end=".",
               title=lambda a: a.title, upstream=lambda t: f": {t}",
               w_head=lambda n: f"Weekly summary: {n} notice{'' if n == 1 else 's'} added to the catalog this week.",
               w_line=lambda name, n: f"- {name}: {n}",
               w_more=lambda k, n: f"- {k} more product{'' if k == 1 else 's'}: {n}",
               w_link=lambda url: f"Catalog: {url}"),
    "ja": dict(head=lambda d, n: f"{d} のデイリーダイジェスト: 新しいアラート {n} 件。",
               quiet=lambda d, n, url: f"{d} のデイリーダイジェスト: 新しいアラートはありません。"
                                       f"今週カタログに追加された注意は {n} 件です: {url}",
               bare=lambda d: f"{d} のデイリーダイジェスト: 新しいアラートはありません。",
               level=lambda lv: _JA_LEVEL[lv],
               withheld=lambda n: f"{n} 件を公開前チェックで保留しました。",
               foreign="警告: このサービスの鍵で署名され、このサービスが送信していないイベントがあります。"
                       "チェックポイントに載せていないため、CLI はこれを適用しません。",
               fixed=lambda v: f"修正版 {v}", nofix="修正版の記載なし、ベンダーの情報を確認してください", end="。",
               title=_ja_title, upstream=lambda t: f" 原題: {t}",
               w_head=lambda n: f"週間まとめ: 今週カタログに追加された注意は {n} 件です。",
               w_line=lambda name, n: f"- {name}: {n} 件",
               w_more=lambda k, n: f"- ほか {k} 製品: {n} 件",
               w_link=lambda url: f"カタログ: {url}"),
}

_RANK = {"critical": 2, "high": 1, "notice": 0}
WEEKLY_LINES = 30  # products named in a weekly summary; the rest are one line


def listable(a: schema.Advisory) -> bool:
    """A digest may list it: not a lead, and a primary source says it (8ke5)."""
    return not a.id.startswith("LEAD-") and any(schema.is_primary(s.url) for s in a.sources)


def withdrawn(a: schema.Advisory, gone, now: int | None = None) -> bool:
    """A digest never lists it: a synthetic id, an id or alias in ``gone`` (case-folded
    retracted ids) or, given ``now``, a version that expired before it (``pull.active``)."""
    return (is_synthetic(a.id) or not {i.casefold() for i in (a.id, *a.aliases)}.isdisjoint(gone)
            or (now is not None and a.expires_at is not None and a.expires_at < now))


def _single(a: schema.Advisory, t=_DIGEST["en"], title: str | None = None) -> str:
    fixed = t["fixed"](a.products[0].fixed) if a.products[0].fixed else t["nofix"]
    up = t["upstream"](title) if title else ""
    return f"- {t['level'](a.level)}: {t['title'](a)}{up}; {fixed}{t['end']} {_primary(a.sources)}"


def weekly(products, link: str, lang: str = "en") -> str:
    """The weekly summary (qwpw, v2 design section 7): the notices of the week counted by
    product, one product name per notice in ``products``, most first then by name, at
    most WEEKLY_LINES lines and one for the rest; counts only, then the catalog link."""
    t = _DIGEST[lang]
    counts = sorted(Counter(products).items(), key=lambda kv: (-kv[1], kv[0]))
    lines = [t["w_head"](sum(n for _, n in counts))]
    lines += [t["w_line"](name, n) for name, n in counts[:WEEKLY_LINES]]
    rest = counts[WEEKLY_LINES:]
    if rest:
        lines.append(t["w_more"](len(rest), sum(n for _, n in rest)))
    lines.append(t["w_link"](link))
    return _guard(_inline("\n".join(lines)))


def digest(advs_today, date, lang: str = "en", *, retracted=(), now: int | None = None,
           titles=None, held: int = 0, link: str = DEFAULT_MIRROR_URL, summary: str | None = None,
           dropped: int = 0, foreign: bool = False) -> str:
    """The daily digest (qwpw, v2 design section 7): the day's new relay-bot posts, one
    line each, loudest first then oldest first, and nothing else. ``advs_today`` is
    the advisory of each thread whose root was posted since the last digest; one
    line per id and product (latest posted_at wins). An item that fails the
    publication guard is withheld and counted, never the whole digest. Left out, and
    not counted: a lead (a ``LEAD-`` id) and any advisory with no primary source (8ke5),
    a synthetic id, an advisory whose id or alias is in ``retracted`` (case-folded) and,
    given ``now``, one whose latest version expired before it (``pull.active``'s rule).
    ``titles`` maps (id, product name) to a source title, which the line carries.

    With nothing to list, one line: no new alerts, ``held`` notices added to the
    catalog this week and ``link``; without the count when ``summary`` (the weekly
    summary, ``weekly``) follows, which carries it. ``lang="ja"``: the Japanese templates.
    ``dropped`` (jsje): posts the relay refused that the poster has since dropped; they
    join the withheld count, which a quiet day then prints too. ``foreign`` (m729): the
    poster found a relay-bot event it did not sign; one fixed line says so, on any day."""
    t = _DIGEST[lang]
    latest: dict[tuple, schema.Advisory] = {}
    for adv in advs_today:
        if not (adv.products and adv.sources):
            continue
        key = (adv.id, adv.products[0].name)
        if key not in latest or adv.posted_at >= latest[key].posted_at:
            latest[key] = adv
    gone = {i.casefold() for i in retracted}
    shown = sorted((a for a in latest.values() if listable(a) and not withdrawn(a, gone, now)),
        key=lambda a: (-_RANK[a.level], a.posted_at, a.id))
    day = date.isoformat() if hasattr(date, "isoformat") else str(date)
    tail = (["", t["foreign"]] if foreign else []) + ([] if summary is None else ["", summary])
    if not shown:
        gone_too = ["", t["withheld"](dropped)] if dropped > 0 else []
        return _guard("\n".join([t["quiet"](day, held, link) if summary is None else t["bare"](day)]
                                + gone_too + tail))
    lines, withheld = [t["head"](day, len(shown))], max(dropped, 0)
    for a in shown:
        try:
            lines.append(_guard(_inline(_single(a, t, _upstream((titles or {}).get((a.id, a.products[0].name)))))))
        except ValueError:
            withheld += 1
    if withheld:
        lines += ["", t["withheld"](withheld)]
    return _guard("\n".join(lines + tail))
