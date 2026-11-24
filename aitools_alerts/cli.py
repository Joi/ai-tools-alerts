"""aitools-alerts: the member CLI.

    aitools-alerts init [--make-key] [--force]
    aitools-alerts keygen
    aitools-alerts pull [--mirror-url URL]
    aitools-alerts check [--json]
    aitools-alerts notify
    aitools-alerts plan <advisory-id>
    aitools-alerts run
    aitools-alerts verify
    aitools-alerts curator post|amend|retract|renew ...   (needs the curator extra)

Nothing here executes a string from a post. ``plan`` prints commands built
from fixed templates keyed by the product's ecosystem; it runs none of them.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shlex
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, replace
from urllib.parse import quote

from . import TRUST_ROOT_PUBKEY, __version__, check, config, curator, inventory, nostr, notify, pull, relay, ruleset, schema, verify, versions
from .state import State, StateError

TRUST_ROOT_ENV = "AITOOLS_ALERTS_TRUST_ROOT"
EXIT_UNSEEN_CRITICAL = 2
STALE_LINE = ("warning: alerts may be stale since {since}: no fresh signed checkpoint; "
              "the mirror may be frozen, replayed or cut off from its signer")
UNVERIFIED_LINE = "warning: alerts are unverified ({reason}); nothing is auto-applied"
OTHER_ROOT = "no pull yet under this trust root"
UPGRADE_LINE = ("upgrade: this aitools-alerts is {have}; the feed needs {need} or later. "
                "Newer alerts may be missing or shown at an older level here. See the README to upgrade.")
OUTDATED_LINE = ("out of date: this aitools-alerts has ruleset {have}; the trust root pins ruleset {pinned} "
                 "and accepts none below {min_version}. {tail}")
OUTDATED_DIGEST_LINE = ("out of date: this aitools-alerts has a ruleset {have} that differs from the ruleset {pinned} "
                        "the trust root pins. {tail}")
OUTDATED_UNREADABLE_LINE = ("out of date: the trust root pins a ruleset in a form this aitools-alerts "
                            "(ruleset {have}) cannot read. {tail}")
# tavj (finding D8): an alert this machine could not verify interrupts at most this often per poster key
MAX_UNVERIFIED = 2
UNVERIFIED_WINDOW_S = 86400
NOT_VERIFIED = "Not verified from this machine"
UNVERIFIED_LINE_IDS = "not verified from this machine: {ids}"
HELD_LINE = ("held, not notified (not verified from this machine; at most {n} unverified alerts from one poster "
             "interrupt in 24 hours): CRITICAL: {title} (id {id})")
WAITING_LINE = ("a lowering of {id} to {level} is published and not verified from this machine: "
                "it applies once signed checkpoints 72 hours apart have listed it")
OUTDATED_TAIL = ("It judges no level until it is upgraded: no source check, no computed expiry; "
                 "alerts are shown as posted. See the README to upgrade.")

# ecosystem -> argv template for an upgrade; "{fixed}" is products[].fixed,
# which the schema restricts to digits, dots and a lowercase suffix.
UPGRADE_TEMPLATES = {
    "claude-code": ("npm", "install", "-g", "@anthropic-ai/claude-code@{fixed}"),
    "codex": ("npm", "install", "-g", "@openai/codex@{fixed}"),
    "gemini-cli": ("npm", "install", "-g", "@google/gemini-cli@{fixed}"),
}

PAIRING_STEPS = """\
To post or discuss on the ai-tools Buzz relay (reading alerts needs no account):
  1. Send the npub above to the ai-tools relay admin and ask to be added.
  2. In the Buzz app, sign in with the key in {path} (keep that file private;
     it is your secret key and is never printed).
  3. Open #security-feed and #security-critical once you are added."""


def _err(msg: str) -> None:
    print(f"aitools-alerts: {msg}", file=sys.stderr)


def _root(s: config.Settings) -> tuple[str, list[str]]:
    """(root, ignored env vars). The variable counts only with trust_root_override:
    a project's environment reaches the hook and must not silence alerts."""
    env = os.environ.get(TRUST_ROOT_ENV)
    if env is None:
        return TRUST_ROOT_PUBKEY, []
    if not s.trust_root_override:
        _err(f"ignoring {TRUST_ROOT_ENV}: trust_root_override is not set in config.toml")
        return TRUST_ROOT_PUBKEY, [TRUST_ROOT_ENV]
    if not nostr._is_hex(env, 32):
        raise SystemExit(f"aitools-alerts: {TRUST_ROOT_ENV} must be 64 lowercase hex characters")
    _err(f"warning: trust root overridden by {TRUST_ROOT_ENV} (for tests only)")
    return env, []


def upgrade_command(ecosystem: str, fixed: str | None) -> list[str] | None:
    t = UPGRADE_TEMPLATES.get(ecosystem)
    if t is None or not fixed:
        return None
    return [a.format(fixed=fixed) for a in t]


# ------------------------------------------------------------------ commands

def _make_key() -> int:
    path = config.key_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    sec, pub = nostr.keygen()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _err(f"{path} exists; not replacing a key")
        return 1
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(nostr.nsec(sec) + "\n")
    print(f"wrote {path} (mode 600)")
    print(f"npub: {nostr.npub(pub)}")
    print(PAIRING_STEPS.format(path=path))
    return 0


def cmd_init(a) -> int:
    path = config.config_path()
    if a.make_key and config.key_path().exists():
        _err(f"{config.key_path()} exists; not replacing a key")
        return 1
    if path.exists() and not a.force:
        if not a.make_key:
            _err(f"{path} exists; use --force to overwrite it")
            return 1
        print(f"kept {path}")
    else:
        config.write_default(force=a.force)
        print(f"wrote {path}")
    return _make_key() if a.make_key else 0


def cmd_keygen(a) -> int:
    a.force = False
    a.make_key = True
    return cmd_init(a)


AHEAD_LINE = ("warning: {n} event(s) dated ahead of this machine's clock were not read; "
              "if the clock is wrong, alerts are missing until it is set")


def _second_origin(a, s: config.Settings) -> str | None:
    """The second origin for this pull: the configured one; by default the
    project's repository, for the pinned root only (it serves no test root)."""
    if s.second_origin is not None:
        return s.second_origin or None
    return config.DEFAULT_SECOND_ORIGIN if a.root == TRUST_ROOT_PUBKEY else None


def _pull(a, st: State, url: str, s: config.Settings) -> pull.PullResult:
    res = pull.fetch(url, st, root_pubkey=a.root, second_origin=_second_origin(a, s))
    if res.dropped.get("future-dated"):  # a slow clock refuses genuine news: never silent
        _err(AHEAD_LINE.format(n=res.dropped["future-dated"]))
    return res


def cmd_pull(a, st: State, s: config.Settings) -> int:
    url = config.check_mirror_url(a.mirror_url) if a.mirror_url else s.mirror_url
    res = _pull(a, st, url, s)
    if res.error:
        _err(res.error)
        return 1
    dropped = ", ".join(f"{k} {v}" for k, v in sorted(res.dropped.items())) or "none"
    cp = st.checkpoint_for(a.root)
    if reason := _unverified(a, st):  # the pull went through, but e.g. the mirror's checkpoint is out of date
        _err(UNVERIFIED_LINE.format(reason=reason))
    print(f"pulled manifest v{res.manifest.version}: {len(res.new_events)} new events, "
          f"{len(st.events)} stored, dropped: {dropped}; checkpoint {cp.seq} lists {len(cp.events)} events")
    return 0


@dataclass(frozen=True)
class Entry:
    """One advisory as check, plan and notify show it: every current root
    (thread) a poster role posted under one advisory id with equal content.
    A critical has one root per channel. ``root_id`` is the first root."""
    root_id: str
    root_ids: tuple[str, ...]
    adv: schema.Advisory
    translations: dict  # lang -> text, of the first root
    refused: str | None = None  # c1g2: a lowering to this level was not applied (pull.standing)
    waiting: str | None = None  # tavj: a relay-bot lowering to this level waits its 72 hours


def _entries(threads: list, warned: set) -> list[Entry]:
    """Group threads by (advisory id, poster role), in reader order; the first
    root is shown. Only copies whose advisories are equal merge: copies that
    differ (an update one root has not had yet) stay apart, so no copy's match
    or notification is dropped, and stderr says so once per advisory."""
    groups: dict[tuple[str, str], list[list]] = {}
    for t in threads:
        copies = groups.setdefault((t.adv.id.casefold(), t.adv.posted_by), [])
        same = next((c for c in copies if c[0].adv == t.adv), None)
        if same is None:
            copies.append([t])
        else:
            same.append(t)
    out = []
    for key, copies in groups.items():
        if len(copies) > 1 and key not in warned:
            warned.add(key)
            _err(f"copies of {copies[0][0].adv.id} differ; listing each")
        out += [Entry(c[0].root_id, tuple(t.root_id for t in c), c[0].adv, _merged(c),
                      next((t.refused for t in c if t.refused), None),
                      next((t.waiting for t in c if t.waiting), None)) for c in copies]
    return out


def _merged(copies: list) -> dict:
    """Per language, the latest translation on any copy (root) of an advisory."""
    best: dict[str, tuple] = {}
    for t in copies:
        for lang, text in t.translations.items():
            key = (t.translated_at[lang], t.root_id)
            if lang not in best or key > best[lang][0]:
                best[lang] = (key, text)
    return {lang: v[1] for lang, v in best.items()}


def _seen(t: Entry, st: State) -> bool:
    return not st.seen.isdisjoint(t.root_ids)


def _tr(t: Entry, s: config.Settings) -> str | None:
    """The translation to show for ``t``, or None: English."""
    return t.translations.get(s.lang) if s.lang != "en" else None


def _title(t: Entry, s: config.Settings) -> str:
    tr = _tr(t, s)
    return pull.translation_title(tr, t.adv.id) if tr else t.adv.title


def _thread_ref(t: Entry) -> str:
    if len(t.root_ids) == 1:
        return f"thread {t.root_id[:12]}"
    return "threads " + ", ".join(r[:12] for r in t.root_ids)


def _matches(a, st: State) -> tuple[list, list]:
    """Current advisories (one Entry per advisory id and poster role), and
    (entry, Match) pairs for this machine. State pulled under another trust
    root is not used."""
    a.raw, a.asked = [], []
    if st.manifest is not None and st.manifest_root != a.root:
        _err("the stored state was pulled under another trust root; run: aitools-alerts pull")
        return [], []
    a.raw = pull.advisories(st)
    now, listed = pull.head_clock(st)
    said = _lowering_check(a, st)
    threads = _entries(pull.active(a.raw, now, listed, said, decay=_ruleset_outdated(a, st) is None,
                                   since=_note_offers(a, st, now, listed, said)),
                       a.__dict__.setdefault("warned", set()))
    inv = inventory.collect()
    ms = check.match([t.adv for t in threads], inv)
    by_adv = {id(t.adv): t for t in threads}
    # c1g2: the states a published lowering or a curator's hold asks the sources about,
    # each with whether its widest state matches this machine (``verify = "matched"``).
    wide = [(t, pull.widest(t)) for t in a.raw if pull.asks(t)]
    here = {id(m.adv) for m in check.match([w for _, w in wide], inv)}
    a.asked = [(_asked(a, st, t, level, w), id(w) in here) for t, w in wide for level in pull.asks(t)]
    return threads, [(by_adv[id(m.adv)], m) for m in ms]


def _pin(a, st: State):
    """The ruleset pin of the stored certificate, or None."""
    return getattr(st.cert_for(a.root), "ruleset", None)


def _asked(a, st: State, t, level: str, wide=None):
    """The state the sources are asked about for lowering thread ``t`` to ``level``:
    its widest state, marked claimed when the thread's signed claims say every higher
    level rested on the first id's fields (``verify.claimed``)."""
    wide = wide if wide is not None else pull.widest(t)
    return verify.at_level(wide, level, verify.claimed(wide, level, t.stated, None, _pin(a, st)))


def _note_offers(a, st: State, now, listed, check):
    """Bring the record of unchecked relay-bot lowerings (``pull.offers``) up to the
    stored checkpoint, and return what ``pull.active`` may count: None for a CLI the
    trust root calls too old or whose ruleset is out of date, which applies no lowering
    unchecked.

    A thread whose lowering this machine's check has refused is remembered by its root's
    id (``State.refused``), and while it is remembered no wait of that thread runs. The
    refusal ends only when the check confirms the thread's standing lowering, or when
    whole reads of authorities give no more than its level
    (``verify.lowering(whole=True)``). A state the sources were not yet asked about, a
    failed read, a crowded request budget, a turned-off check, a raise and a new
    lowering reply all leave it standing, so nothing the thread's signer posts turns a
    known refusal into an unchecked lowering. A state directory that cannot be written
    records nothing.

    The record is rewritten under the state lock from the record and the source-check
    results as they are on disk then, never from what this command read before it had
    the lock: a command that started earlier must not write its older view over a
    refusal, or a later start of a wait, that another command has saved since."""
    def step(check) -> tuple[dict, set]:
        want = pull.offers(a.raw, st.lowerings, now, listed)
        refused = set(st.refused)
        if now is not None and listed is not None:
            refused &= {t.root_id for t in a.raw}
            for t in a.raw:
                if t.offered_by not in want:
                    continue
                said = check(pull.widest(t), t.offered, t.stated) if check is not None else None
                if said is False:
                    refused.add(t.root_id)
                elif said is True or (check is not None and check.whole(pull.widest(t), t.offered, t.stated)):
                    refused.discard(t.root_id)
                if t.root_id in refused:
                    want[t.offered_by] = int(now)  # the 72 hours start when the refusal ends
        return want, refused

    want, refused = step(check)
    if (want, refused) != (st.lowerings, st.refused):
        try:
            with st.locked():
                st.lowerings, st.refused = step(_lowering_check(a, st))
                st.save_unverified()
        except OSError:
            st.lowerings, st.refused = want, refused  # for this command; nothing applies sooner for it
    if _min_cli(a, st) is not None or _ruleset_outdated(a, st) is not None:
        return None
    held = {t.offered_by for t in a.raw if t.root_id in st.refused}
    return {i: at for i, at in st.lowerings.items() if i not in held}


class _Check:
    """The ``check`` of pull.standing over the source-check results on disk."""

    def __init__(self, cache, rs, pin):
        self.cache, self.rs, self.pin = cache, rs, pin

    def __call__(self, adv, level, stated=()):
        return verify.lowering(adv, level, self.cache, time.time(), self.rs, stated, self.pin)

    def whole(self, adv, level, stated=()) -> bool:
        return verify.lowering(adv, level, self.cache, time.time(), self.rs, stated, self.pin, whole=True) is True


def _lowering_check(a, st: State):
    """The ``check`` of pull.standing from the source-check results on disk, or None:
    with ``verify = "off"``, without settings, and for a CLI the trust root calls too
    old or whose ruleset the trust root calls out of date (its ruleset may be the
    one that is wrong). None settles nothing: a relay-bot
    lowering is not applied and a curator's holds its 14 days."""
    s = getattr(a, "settings", None)
    if s is None or s.verify == "off" or _min_cli(a, st) is not None or _ruleset_outdated(a, st) is not None \
            or not any(pull.asks(t) for t in getattr(a, "raw", ())):
        return None  # and with no lowering to judge, no cache and no ruleset is loaded
    try:
        cache, rs = _cache(a, st, s), ruleset.load()
    except Exception:  # a damaged ruleset: nothing is settled, and every alert is still shown and notified
        return None
    return _Check(cache, rs, _pin(a, st))


def _mend(st: State) -> None:
    """Rebuild a damaged unverified.json, with nobody's help and on the safe side: every
    wait starts again, every remembered refusal is asked again, and for one window no
    unverified alert takes a slot (``State.reset_at``), since how many were used is
    unknown. When the directory cannot be written the same holds for this command."""
    if not st.unverified_damaged:
        return
    fresh = ({}, set(), {}, {}, int(time.time()))
    try:
        with st.locked():
            if st.unverified_damaged:  # else a concurrent run has mended it
                st.lowerings, st.refused, st.interrupts, st.held, st.reset_at = fresh
                st.save_unverified()
    except OSError:
        st.lowerings, st.refused, st.interrupts, st.held, st.reset_at = fresh
    _err("the record of unverified alerts was unreadable and has been started again")


def _source(adv) -> tuple[str, bool]:
    """The link to give the person, and whether it is a primary source: the
    first primary source, else the first. Percent-encoded to URL ASCII, so a
    space in a posted URL cannot put more text on the line that carries it."""
    domains = schema.load_primary_domains()
    url = next((s.url for s in adv.sources if schema.is_primary(s.url, domains)), None)
    primary = url is not None
    return quote(url if primary else adv.sources[0].url, safe=":/?#[]@!$&'()*+,;=%~"), primary


def _source_line(adv) -> str:
    url, primary = _source(adv)
    return f"  source: {url}" if primary else f"  source: {url} (not a primary source)"


# -------------------------------------------------------------- source check

SOURCE_CHECK_FAILED = "source check failed"  # fixed: an exception's text may quote a response


def _cache(a, st: State, s: config.Settings) -> dict | None:
    """The source-check results on disk; None with ``verify = "off"`` (no file is
    read), and None while this CLI's ruleset is out of date: it judges no level."""
    return None if s.verify == "off" or _ruleset_outdated(a, st) is not None else verify.load(st.dir)


def _source_check(a, st: State, s: config.Settings, threads: list, pairs: list, asked=()) -> None:
    """Read the primary sources (aitools_alerts.verify) for the threads the
    ``verify`` setting names, and for the lowered states of ``asked`` (``_matches``).
    Never in ``run --json``, which the session-start hook runs, and never while
    this CLI's ruleset is out of date. It changes no exit status; what it finds
    about a lowering is applied by the next ``_matches``."""
    if s.verify == "off" or _ruleset_outdated(a, st) is not None:
        return
    wanted = [t.adv for t in threads] if s.verify == "all" else [t.adv for t, _ in pairs]
    wanted += [adv for adv, here in asked if here or s.verify == "all"]
    # tavj: a confirmation a critical on this machine rests on is read again daily too: it
    # exempts the alert from the cap on unverified interrupts only while it is fresh.
    critical = [t.adv for t, _ in pairs if t.adv.level == "critical"]
    try:
        verify.run([t.adv for t in threads] + [adv for adv, _ in asked], wanted, st.dir,
                   recheck=[adv for adv, _ in asked] + critical)
    except Exception:
        _err(SOURCE_CHECK_FAILED)


def _source_lines(a, st: State, s: config.Settings, threads: list) -> list[str]:
    """One line per product whose source contradicts the post, from the cache.
    Printed: the id as verify.norm_id returned it, a scope product name, and
    level words. A CLI the trust root calls too old prints none: its ruleset
    and scope file may be the ones that are wrong."""
    cache = _cache(a, st, s)
    if cache is None or _min_cli(a, st) is not None:
        return []
    scope, out = ruleset.load().products(), []
    for t in threads:
        for name, r in sorted((verify.result_for(t.adv, cache) or {}).items()):
            ident = verify.norm_id(t.adv.id)
            if r["result"] != verify.CONTRADICTED or ident is None or name not in scope:
                continue
            if r["why"] == "unsupported":
                out.append(f"source check: the source does not support {ident} for {name}")
            else:
                out.append(f"source check: {ident} is published at {t.adv.level} for {name}; "
                           f"the source supports {r['source']}")
    # c1g2: a lowering or retraction the member's source contradicts, from the results as
    # they are now (this run's source check may have just read them).
    shown = {r for t in threads for r in t.root_ids}
    for t in pull.active(getattr(a, "raw", ()), *pull.head_clock(st), _lowering_check(a, st)):
        ident = verify.norm_id(t.adv.id)
        if t.refused is None or ident is None or t.root_id not in shown:
            continue
        what = f"a retraction of {ident}" if t.refused == pull.NONE else f"a lowering of {ident} to {t.refused}"
        found = verify.result_for(_asked(a, st, t, t.refused), cache) or {}
        out += [f"source check: {what} is not applied: the source supports {r['source']} for {name}"
                for name, r in sorted(found.items()) if r["why"] == "below-source" and name in scope]
    return list(dict.fromkeys(out))


def _check_json(t, m, cache, judged: bool = True) -> dict | None:
    """``source_check`` of one match. None when not ``judged``: an out-of-date CLI
    gives no result at all, not the "unknown, off" a missing cache means."""
    if not judged:
        return None
    r = (verify.result_for(t.adv, cache) or {}).get(m.product.name) if m.product is not None else None
    return None if r is None else {"result": r["result"], "why": r["why"], "source_level": r["source"]}


def cmd_verify(a, st: State, s: config.Settings) -> int:
    """The source check on the stored state, then what it found."""
    if _ruleset_outdated(a, st) is not None:
        print("the source check did not run: this aitools-alerts is out of date")
        return 0
    threads, pairs = _matches(a, st)
    _source_check(a, st, s, threads, pairs, a.asked)
    if a.asked:  # c1g2: the alerts as they stand after what the sources just said about a lowering
        threads, pairs = _matches(a, st)
    cache = _cache(a, st, s)
    found = [verify.summary(r)[0] for t in threads if (r := verify.result_for(t.adv, cache)) is not None]
    print(f"source check: {found.count(verify.CONFIRMED)} confirmed, {found.count(verify.CONTRADICTED)} "
          f"contradicted, {found.count(verify.UNKNOWN)} not verified")
    if a.asked and (check := _lowering_check(a, st)) is not None:
        said = [check(pull.widest(t), level, t.stated) for t in a.raw for level in pull.asks(t)]
        print(f"source check: {len(said)} lowerings or retractions asked about: {said.count(True)} confirmed, "
              f"{said.count(False)} contradicted, {said.count(None)} not settled")
    for line in _source_lines(a, st, s, threads):
        print(line)
    return 0


def _match_json(t, m, cache=None, judged: bool = True) -> dict:
    source, primary = _source(t.adv)
    return {"thread": t.root_id, "threads": list(t.root_ids), "id": t.adv.id, "level": t.adv.level, "title": t.adv.title,
            "posted_by": t.adv.posted_by, "reason": m.reason, "source": source,
            "source_primary": primary, "sources": [asdict(x) for x in t.adv.sources],
            "installed": asdict(m.installed), "product": asdict(m.product) if m.product else None,
            "actions": [asdict(x) for x in m.actions_allowed],
            "translations": dict(t.translations), "source_check": _check_json(t, m, cache, judged),
            "lowering_refused": t.refused, "lowering_waits": t.waiting}


def _unverified(a, st: State) -> str | None:
    """pull.unverified for this trust root. State pulled under another root,
    or none, is no verification under this one."""
    if st.manifest_root != a.root:
        return OTHER_ROOT if st.manifest_root is not None else pull.unverified(st) or OTHER_ROOT
    return pull.unverified(st)


def _min_cli(a, st: State) -> str | None:
    """The release the trust root says this feed needs, when this CLI is older
    than it; else None. From the stored certificate of the current root, whose
    signature State.load checked; expired or not, it is the root's newest word.
    Reported only: nothing is refused or hidden because of it."""
    cert = st.cert_for(a.root)
    need = cert.min_cli if cert is not None else None
    have, want = versions.parse(__version__), versions.parse(need)
    return need if have is not None and want is not None and have < want else None


def _ruleset_outdated(a, st: State) -> dict | None:
    """``{"have", "pinned", "min_version"}`` when the trust root pins a ruleset and
    this CLI's own is out of date under the pin (``ruleset.outdated``); else None.
    The pin is in the stored certificate of the current root, like ``min_cli``. A
    pin this CLI cannot read (a later form) is out of date too: ``pinned`` and
    ``min_version`` are then None. While the result is not None this CLI judges no
    level: no source check and no computed expiry. Nothing is refused or hidden
    because of it. With a readable pin, a ruleset that cannot be loaded gives None
    here: the command that needs it reports the damage."""
    cert = st.cert_for(a.root)
    if cert is None or (cert.ruleset is None and not cert.ruleset_unreadable):
        return None
    try:
        rs = ruleset.load()
    except Exception:
        rs = None
    if cert.ruleset_unreadable:
        return {"have": rs.version if rs is not None else None, "pinned": None, "min_version": None}
    try:
        if rs is None or not ruleset.outdated(cert.ruleset, rs):
            return None
    except Exception:
        return None
    return {"have": rs.version, "pinned": cert.ruleset.version, "min_version": cert.ruleset.min_version}


def _outdated_line(o: dict) -> str:
    line = (OUTDATED_UNREADABLE_LINE if o["pinned"] is None
            else OUTDATED_DIGEST_LINE if o["have"] == o["pinned"] else OUTDATED_LINE)
    return line.format(tail=OUTDATED_TAIL, **{**o, "have": "unknown" if o["have"] is None else o["have"]})


def _stale_since(a, st: State) -> str | None:
    """pull.stale_since as an ISO time: null only while this root's state is
    verified. With no state under this root, the time of the last attempt."""
    if _unverified(a, st) is None:
        return None
    if st.manifest_root == a.root:
        since = pull.stale_since(st)
    else:
        since = st.last_pull.get("at")
    since = since if isinstance(since, int) else int(time.time())
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(since, schema.MAX_TIMESTAMP)))


def cmd_check(a, st: State, s: config.Settings, source_lines: bool = True) -> int:
    threads, pairs = _matches(a, st)
    if a.json:
        cache = _cache(a, st, s)
        judged = _ruleset_outdated(a, st) is None
        print(json.dumps([_match_json(t, m, cache, judged) for t, m in pairs], indent=2))
        return 0
    if not st.last_pull.get("last_ok_at"):
        print("no successful pull yet; run: aitools-alerts pull")
    if reason := _unverified(a, st):
        print(UNVERIFIED_LINE.format(reason=reason))
        if reason == "checkpoint out of date":
            print(STALE_LINE.format(since=_stale_since(a, st)))
    for t, m in pairs:
        ver = m.installed.version or "unknown version"
        print(f"{t.adv.level.upper()}: {_title(t, s)} [{m.installed.name} {ver}: {m.reason}] "
              f"(id {t.adv.id}, {_thread_ref(t)})")
    cache = _results(a, st, s)
    loose = [t.adv.id for t, m in pairs if _result(t, m, cache) == verify.UNKNOWN]
    if loose:
        print(UNVERIFIED_LINE_IDS.format(ids=", ".join(dict.fromkeys(loose))))
    once = {t.root_id: t for t, _ in pairs}  # an entry matched through two installations is said once
    for t in {t.root_id: t for t, _ in _interrupts(a, st, s, pairs)[1]}.values():
        print(HELD_LINE.format(n=MAX_UNVERIFIED, title=_title(t, s), id=t.adv.id))
    for t in once.values():
        if t.waiting:
            print(WAITING_LINE.format(id=t.adv.id, level=t.waiting))
    matched = {t.root_id for t, _ in pairs}
    other = [t for t in threads if t.adv.level == "critical" and t.root_id not in matched]
    if other:
        print("Critical advisories not installed here:")
        for t in other:
            print(f"  CRITICAL: {_title(t, s)} (id {t.adv.id}, {_thread_ref(t)})")
    for line in _source_lines(a, st, s, threads) if source_lines else ():
        print(line)
    print(f"{len(threads)} advisories, {len(pairs)} matches on this machine")
    return 0


def _unseen_critical(a, st: State, pairs: list | None = None) -> list:
    if pairs is None:
        _, pairs = _matches(a, st)
    return [(t, m) for t, m in pairs if t.adv.level == "critical" and m.reason != check.MAY_APPLY
            and not _seen(t, st)]


def _results(a, st: State, s: config.Settings) -> dict | None:
    """The source-check results an interrupt is judged by; None when this CLI verifies
    nothing: ``verify = "off"``, a CLI the trust root calls too old or out of date, a
    ruleset or cache that cannot be loaded. Never raises: an alert is still sent."""
    try:
        return None if _min_cli(a, st) is not None else _cache(a, st, s)
    except Exception:
        return None


def _result(t: Entry, m, cache) -> str | None:
    """The source-check result of the product a match rests on: None for an alert no
    relay bot posted (it is not checked), unknown for a match with no product."""
    if t.adv.posted_by != verify.BOT:
        return None
    r = (verify.result_for(t.adv, cache) or {}).get(m.product.name) if m.product is not None else None
    return r["result"] if r is not None else verify.UNKNOWN


def _confirmed_now(t: Entry, m, cache, now: int) -> bool:
    """This machine read the source of the matched product no more than verify.FRESH_S
    ago and it confirmed the alert. An older confirmation verifies nothing: the result
    belongs to the published state, not to the post, and a new post that copies a state
    confirmed last month must not pass as checked."""
    if cache is None or _result(t, m, cache) != verify.CONFIRMED:
        return False
    held = cache["results"].get(verify.state_key(t.adv))
    return held is not None and 0 <= now - held["at"] <= verify.FRESH_S


def _poster(t: Entry, st: State) -> str:
    """The key that signed the alert's root."""
    ev = st.events.get(t.root_id)
    return ev["pubkey"] if ev else "0" * 64


def _slots(st: State, bucket: str, now: int) -> dict:
    """{root id: time} of the interrupts counted against ``bucket`` inside the window, by
    this machine's clock. One dated after the clock is not counted: a clock set back
    must not silence alerts."""
    return {r: at for r, at in st.interrupts.get(bucket, {}).items() if now - UNVERIFIED_WINDOW_S < at <= now}


def _verified_bucket(t: Entry, m) -> str:
    """The bucket of the one slot a confirmed alert takes: the advisory's first id as the
    source is asked for it and the matched product, and nothing else of the post. The
    aliases, the level, the title and the root are the signer's to vary; what this
    machine read and confirmed is that id for that product."""
    name = m.product.name if m.product is not None else ""
    return hashlib.sha256(json.dumps([verify.norm_id(t.adv.id), name]).encode("utf-8")).hexdigest()


def _interrupts(a, st: State, s: config.Settings, pairs: list | None = None) -> tuple[list, list, list, set]:
    """(pending, held, grants, the root ids of the unverified among pending) of the
    unseen critical matches (tavj, finding D8). Each alert is decided once, whatever
    number of installations or products it matches through.

    A relay-bot alert interrupts on a slot. One this machine's own read of the source
    confirms, freshly (``_confirmed_now``, for any product it matches), takes the one
    slot of that advisory and product (``_verified_bucket``) per UNVERIFIED_WINDOW_S:
    copies of a confirmed post are not each confirmed. Any other is unverified and takes
    one of the MAX_UNVERIFIED slots of its poster key per window. An alert that holds a
    slot keeps interrupting until it is seen, so a notification that failed is tried
    again; one that finds no slot is held: listed, not notified, not marked seen, no
    exit 2, until its source confirms it or a slot is free. A free slot goes to the alert
    held longest (``State.held``), before one never held and before one whose own slot
    ran out, so nothing dated earlier or posted later keeps a held alert out for good.
    ``grants``: (bucket, capacity, root id) for ``_reserve`` to record. Nothing is
    written here: what a caller reports as an interrupt is what ``_reserve`` returns.
    While a record rebuilt after damage is younger than the window, no poster-key slot
    is free (``State.reset_at``). A curator's alert needs no slot."""
    cache, now, taken = _results(a, st, s), int(time.time()), Counter()
    pending, held, grants, loose = [], [], [], set()
    rebuilt = st.reset_at is not None and now - UNVERIFIED_WINDOW_S < st.reset_at <= now

    def take(bucket: str, cap: int, t: Entry) -> bool:
        have = _slots(st, bucket, now)
        if not have.keys().isdisjoint(t.root_ids):
            return True
        if len(have) + taken[bucket] >= cap:
            return False
        taken[bucket] += 1
        grants.append((bucket, cap, t.root_id))
        return True

    groups: dict = {}
    for t, m in _unseen_critical(a, st, pairs):
        groups.setdefault(t.root_id, (t, []))[1].append(m)
    never = float("inf")
    for t, ms in sorted(groups.values(), key=lambda g: min(st.held.get(r, never) for r in g[0].root_ids)):
        # the first confirmed match whose advisory-and-product slot this alert holds or can take
        sure = next((m for m in ms if _confirmed_now(t, m, cache, now) and take(_verified_bucket(t, m), 1, t)), None)
        if sure is not None:  # the confirming match first: it is the one a notification describes
            pending += [(t, sure)] + [(t, m) for m in ms if m is not sure]
        elif _result(t, ms[0], cache) is None:
            pending += [(t, m) for m in ms]
        elif not rebuilt and take(_poster(t, st), MAX_UNVERIFIED, t):
            loose.update(t.root_ids)
            pending += [(t, m) for m in ms]
        else:
            held += [(t, m) for m in ms]
    return pending, held, grants, loose


def _reserve(st: State, pending: list, held: list, grants: list) -> tuple[list, list]:
    """Record the slots ``_interrupts`` granted, under the state lock and against the
    record as it is then, and return (pending, held) as they stand after: an alert whose
    slot a concurrent run took meanwhile is held, not pending. Called before a command
    reports anything, so exit 2 and ``unseen_critical`` name only alerts that hold a
    slot, and the slot is used by the report, whether or not a channel then delivers.
    Also records since when each held alert has been held (``State.held``). Of the
    alerts this command looked at (``pending`` and ``held``), one no longer held is
    dropped from it; an entry for an alert this command did not look at (another command
    pulled it since) is kept with its time, unless that alert is seen or its root is no
    longer stored. Slots outside the window are dropped on the way. A state directory
    that cannot be written grants them for this command: a critical is never lost to a
    full disk."""
    denied = set()
    waiting = {t.root_id for t, _ in held}
    looked = waiting | {t.root_id for t, _ in pending}
    if not grants and not waiting and not st.held:
        return pending, held
    try:
        with st.locked():
            now, slots = int(time.time()), dict(st.interrupts)
            for bucket, cap, root in grants:
                have = _slots(st, bucket, now)
                if root in have:
                    continue
                if len(have) >= cap:
                    denied.add(root)
                    continue
                st.interrupts[bucket] = {**have, root: now}
            if st.interrupts != slots:
                st.interrupts = {b: live for b in st.interrupts if (live := _slots(st, b, now))}
            was = dict(st.held)
            others = {r: at for r, at in st.held.items()
                      if r not in looked and r not in st.seen and r in st.events}
            st.held = {**others, **{r: st.held[r] if 0 <= st.held.get(r, -1) <= now else now
                                    for r in sorted(waiting | denied)}}
            if st.interrupts != slots or st.held != was:
                st.save_unverified()
    except OSError:
        pass
    return ([x for x in pending if x[0].root_id not in denied],
            held + [x for x in pending if x[0].root_id in denied])


def _notify(st: State, s: config.Settings, pending, loose=frozenset()) -> int:
    """Send each pending advisory once, under the state lock: a concurrent
    run waits, then re-reads seen and skips what this one already sent. Every
    root of an advisory is marked seen; one seen root makes it seen. An unverified
    alert (its roots are in ``loose``) says so in the last line of its text."""
    if not pending:
        return 0
    if not s.notify:
        _err("no notify channel configured")
        return 1
    status = 0
    with st.locked():
        for t, m in pending:
            if _seen(t, st):
                continue  # sent already (by this run, or a concurrent one)
            text = notify.format_text(t.adv, m, _tr(t, s))
            if not loose.isdisjoint(t.root_ids):
                text += f"\n{NOT_VERIFIED}"
            accepted = False
            for ch in s.notify:
                r = notify.send(ch, text, s)
                print(f"{ch}: {r.detail}")
                accepted = accepted or r.accepted
            if accepted:
                st.seen.update(t.root_ids)
                st.save_seen()
            else:
                status = 1
    return status


def cmd_notify(a, st: State, s: config.Settings) -> int:
    pending, held, grants, loose = _interrupts(a, st, s)
    return _notify(st, s, _reserve(st, pending, held, grants)[0], loose)  # loose roots that end up held are not sent


def cmd_plan(a, st: State, s: config.Settings) -> int:
    threads, pairs = _matches(a, st)
    wanted = [t for t in threads if a.advisory_id in (*t.root_ids, t.adv.id)]
    if not wanted:
        _err(f"no current advisory {a.advisory_id!r}")
        return 1
    hits = [(t, m) for t, m in pairs if t in wanted]
    if not hits:
        print(f"{_title(wanted[0], s)}: nothing installed here is affected")
        return 0
    cfg = s.check_config()
    reason = _unverified(a, st)
    if reason:  # completeness is not established: a retraction may be missing
        print(UNVERIFIED_LINE.format(reason=reason))
    for t, m in hits:
        p = check.plan(m, cfg)
        if reason:
            p = replace(p, auto_apply=[], prepare=[*p.auto_apply, *p.prepare])
        print(f"{t.adv.level.upper()}: {_title(t, s)} [{m.installed.name} "
              f"{m.installed.version or 'unknown version'}] posted by {t.adv.posted_by}")
        tr = _tr(t, s)  # quoted with "> ": translated text, never a section or a command
        for line in (tr.split("\n")[1:] if tr else []):
            print(f"    > {line}".rstrip())
        print(_source_line(t.adv))
        for title, actions in (("auto-apply (opted in)", p.auto_apply),
                               ("prepare (ask first)", p.prepare)):
            if not actions:
                continue
            print(f"  {title}:")
            for x in actions:
                print(f"    {check.describe(x)}")
                if x.verb == "upgrade" and m.product is not None:
                    argv = upgrade_command(m.product.ecosystem, x.value)
                    if argv:
                        print(f"      command: {shlex.join(argv)}")
                    elif not x.value:
                        print("      no fixed version given: notify only, no command")
                    else:
                        print("      no command template; upgrade with your package manager")
    for line in _source_lines(a, st, s, wanted):
        print(line)
    print("nothing was executed")
    return 0


def cmd_run(a, st: State, s: config.Settings) -> int:
    """pull, check, notify. --json prints one object; --quiet prints nothing
    on stdout. Exit 2 when a critical match was unseen at the start."""
    res = _pull(a, st, s.mirror_url, s)
    if res.error:
        _err(f"{res.error} (using the last good state)")
    threads, pairs = _matches(a, st)  # one inventory collection per run (the hook's time budget)
    pending, held, grants, loose = _interrupts(a, st, s, pairs)
    pending, held = _reserve(st, pending, held, grants)  # before anything is reported
    if a.json:
        cache, old = _cache(a, st, s), _ruleset_outdated(a, st)
        out = {"pull_error": res.error, "ignored_env": a.ignored_env,
               "stale_since": _stale_since(a, st), "unverified": _unverified(a, st),
               "min_cli": _min_cli(a, st), "ruleset_outdated": old,
               "matches": [_match_json(t, m, cache, old is None) for t, m in pairs],
               "unseen_critical": sorted({r for t, _ in pending for r in t.root_ids}),
               "held_critical": sorted({r for t, _ in held for r in t.root_ids})}
    elif not a.quiet:
        a.json = False
        cmd_check(a, st, s, source_lines=False)  # printed below, once the sources are read
    def send(them, loose) -> int:
        if a.quiet or a.json:
            with contextlib.redirect_stdout(io.StringIO()):
                return _notify(st, s, them, loose)
        return _notify(st, s, them, loose)
    status = send(pending, loose)
    if not a.json:  # the hourly job's form; the hook runs --json and must read no source.
        # After the notification: a critical never waits for a source.
        _source_check(a, st, s, threads, pairs, a.asked)
        if s.verify != "off":
            # c1g2: what the sources just said about a lowering counts in this run. A
            # critical that a contradicted lowering had hidden is notified now, and so is
            # one that was held unverified and that its source has just confirmed (tavj).
            before = sorted((t.root_id, t.adv.level) for t in threads)
            if a.asked:
                threads, pairs = _matches(a, st)
            tried = {r for t, _ in pending for r in t.root_ids}
            again, held, grants, loose = _interrupts(a, st, s, pairs)
            again, held = _reserve(st, again, held, grants)
            late = [x for x in again if tried.isdisjoint(x[0].root_ids)]
            status = send(late, loose) or status
            pending = pending + late
            if not a.quiet and before != sorted((t.root_id, t.adv.level) for t in threads):
                print("After the source check:")  # what was listed above is no longer what stands
                cmd_check(a, st, s, source_lines=False)
        for line in () if a.quiet else _source_lines(a, st, s, threads):
            print(line)
    if a.json:
        print(json.dumps(out, indent=2))
    return EXIT_UNSEEN_CRITICAL if pending else status


# ---------------------------------------------------------------------- main

def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="aitools-alerts", description="ai-tools security alerts")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="write the config; --make-key also makes a Buzz key")
    p.add_argument("--make-key", action="store_true")
    p.add_argument("--force", action="store_true", help="overwrite an existing config")
    sub.add_parser("keygen", help="same as init --make-key")
    p = sub.add_parser("pull", help="fetch and verify the signed mirror")
    p.add_argument("--mirror-url")
    p = sub.add_parser("check", help="match advisories against this machine")
    p.add_argument("--json", action="store_true")
    sub.add_parser("notify", help="send unseen critical matches")
    p = sub.add_parser("plan", help="print the actions and commands for one advisory")
    p.add_argument("advisory_id")
    p = sub.add_parser("run", help="pull, check and notify; exit 2 on an unseen critical")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true", help="print one JSON object")
    g.add_argument("--quiet", action="store_true", help="print nothing on stdout")
    sub.add_parser("verify", help="check alerts against their primary source (CISA KEV, GitHub, OSV)")
    curator.add_parser(sub)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
        if a.cmd == "init":
            return cmd_init(a)
        if a.cmd == "keygen":
            return cmd_keygen(a)
        s = config.load()
        a.root, a.ignored_env = _root(s)
        a.settings = s
        if a.cmd == "curator":
            return curator.cmd_curator(a, State.load())
        pull.channel_ids()  # a damaged package: one error line, before any command half-runs
        st = State.load()
        _mend(st)
        try:
            return {"pull": cmd_pull, "check": cmd_check, "notify": cmd_notify,
                    "plan": cmd_plan, "run": cmd_run, "verify": cmd_verify}[a.cmd](a, st, s)
        finally:  # every command that reads the feed, whatever it returned: an old CLI never goes quiet
            try:
                if need := _min_cli(a, st):
                    _err(UPGRADE_LINE.format(have=__version__, need=need))
                if old := _ruleset_outdated(a, st):
                    _err(_outdated_line(old))
            except OSError:  # stderr is gone: the command's own result still stands
                pass
    except (config.ConfigError, StateError, curator.CuratorError, relay.RelayError,
            pull.ChannelSpecError) as e:
        _err(str(e))
        return 1
    except OSError as e:  # e.g. the state directory is not writable
        _err(f"{type(e).__name__}: {e.strerror or e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
