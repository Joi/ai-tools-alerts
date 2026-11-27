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
from .state import MAX_STRIKE_ROOTS, MAX_STRIKES, State, StateError, no_probation, no_support

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
# cftg (finding D14): two alerts of one poster key that this machine's source check found
# unsupported inside STRIKE_WINDOW_S put the key on probation here for PROBATION_S.
STRIKE_WINDOW_S = 7 * 86400
PROBATION_S = 30 * 86400
PROBATION_LINE = ("probation: poster key {key} is on probation on this machine until {until}: its sources did not "
                  "support two of its alerts within seven days. Its alerts that this machine has not verified do "
                  "not notify, and its lowerings apply only when this machine's source check confirms them")
PROBATION_HELD_LINE = ("held, not notified (not verified from this machine; its poster key is on probation here): "
                       "CRITICAL: {title} (id {id})")
UNJUDGED_LINE = "source check: {id} names a product or an id this check cannot judge: no interrupt"
WAITING_LINE = ("a lowering of {id} to {level} is published and not verified from this machine: "
                "it applies once signed checkpoints 72 hours apart have listed it")
NARROW_WAITING_LINE = ("a narrowing of {id} is published and not verified from this machine: "
                       "it applies once signed checkpoints 72 hours apart have listed it")
NARROW_REFUSED_LINE = "source check: a narrowing of {id} is not applied: its products are not what the source states"
# 0z4e (finding D8): a relay-bot match whose product this machine's reads never found a source to
# support is shown at notice; one whose support was read earlier keeps its level, and is flagged
# once a read more than this long after the first without support still finds none
NOTICE = "notice"
SUPPORT_GAP_S = verify.FRESH_S
UNSUPPORTED_LINE = "source check: the source does not support {id} for {name}"
LOST_LINE = "source check: the source has not supported {id} for {name} for more than 48 hours"
# 53fy: a relay-bot entry whose ``fixed`` no range of the advisory states (``verify.fixed_stated``)
# still matches and interrupts; its upgrade is shown with no version
FIXED_LINE = "source check: the fixed version {id} gives for {name} is not the advisory's: no upgrade version is shown"
CORRECTION_LINE = "Correction: the fixed version this alert gave is not the advisory's; no upgrade version is shown"
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
    narrow_refused: bool = False  # swfe: a published narrowing of its products was not applied
    narrow_waiting: bool = False  # swfe: one waits its 72 hours
    # 0z4e. ``judged``: the state whose source-check result feeds the memory of support
    # (``_judged``); None for a thread that is not judged. ``published``: the level the
    # alert is published at, on an entry shown at notice because no source ever supported
    # the product (``_shown``); ``adv`` then carries notice. ``also``: the other states
    # the sources are asked about for the thread (its lowered states, ``_matches``).
    judged: schema.Advisory | None = None
    published: str | None = None
    also: tuple = ()


def _judged(t):
    """What the sources are asked about to learn whether they support the alert of thread
    ``t`` (as it stands): its widest state (``pull.widest``) at the level it stands at. The
    aliases are the relay bot's to replace, and beside a CVE support comes only through
    an alias the thread lists, so a reply that drops one must not make a true alert read
    as unsupported. None for a thread a curator posted, one a curator's hold is in force
    on and one the manifest retracts: a curator's word is not the relay bot's."""
    if t.wide is None or t.curated or t.adv.posted_by != verify.BOT:
        return None
    return replace(pull.widest(t), level=t.adv.level)


def _entries(threads: list, warned: set) -> list[Entry]:
    """Group threads by (advisory id, poster role), in reader order; the first
    root is shown. Only copies whose advisories are equal merge: copies that
    differ (an update one root has not had yet) stay apart, so no copy's match
    or notification is dropped, and stderr says so once per advisory."""
    groups: dict[tuple[str, str], list[list]] = {}
    for t in threads:
        copies = groups.setdefault((t.adv.id.casefold(), t.adv.posted_by), [])
        # 0z4e: and whose judged states are equal. Copies with one current content and
        # another history (an alias one of them held) are asked about different states.
        same = next((c for c in copies if c[0].adv == t.adv and _judged(c[0]) == _judged(t)), None)
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
                      next((t.waiting for t in c if t.waiting), None),
                      any(t.narrow_refused for t in c), any(t.narrow_waiting for t in c), _judged(c[0])) for c in copies]
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


def _title(t: Entry, s: config.Settings, plain: bool = False) -> str:
    """``plain`` (53fy): for an entry with a match whose ``fixed`` the source contradicts,
    the id stands for the title, translated or not: a title is the signer's prose and
    can name that version."""
    if plain:
        return notify.plain_title(t.adv)
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
    since = _note_offers(a, st, now, listed, _lowering_check(a, st))
    # the threads, the checkpoint and the check the record was brought up to date with: when
    # another command had saved since this one began, they are the newer ones (``_note_offers``)
    (now, listed), said = a.clock, a.check
    active = pull.active(a.raw, now, listed, said, decay=_ruleset_outdated(a, st) is None, since=since)
    # swfe: a list this machine's check refused stays reported, whatever the check reads today
    active = [replace(t, narrow_refused=True) if _narrow_refused(t, st) else t for t in active]
    threads = _entries(active, a.__dict__.setdefault("warned", set()))
    inv = inventory.collect()
    ms = check.match([t.adv for t in threads], inv)
    by_adv = {id(t.adv): t for t in threads}
    # c1g2: the states a published lowering or a curator's hold asks the sources about,
    # each with whether its widest state matches this machine (``verify = "matched"``).
    wide = [(t, pull.widest(t)) for t in a.raw if pull.asks(t) or t.narrowed is not None]
    here = {id(m.adv) for m in check.match([w for _, w in wide], inv)}
    a.asked = [(_asked(a, st, t, level, w), id(w) in here) for t, w in wide for level in pull.asks(t)]
    # swfe: a published narrowing asks about the widest state as it is, and the state it would
    # leave is read in the same run (the same ids: no request more), so the alert is not
    # "not verified" for an hour after the narrowing applied
    a.asked += [(x, id(w) in here) for t, w in wide if t.narrowed is not None
                for x in (w, replace(t.wide, products=list(t.narrowed)))]
    # 0z4e: support read while a lowering was asked about is support for the thread
    lowered: dict = {}
    for t, w in wide:
        lowered[t.root_id] = tuple(_asked(a, st, t, level, w) for level in pull.asks(t))
    threads = [replace(t, also=tuple(x for r in t.root_ids for x in lowered.get(r, ()))) if t.judged is not None else t
               for t in threads]
    by_adv = {id(t.adv): t for t in threads}
    _note_support(a, st, threads)
    threads, pairs = _shown(a, st, threads, [(by_adv[id(m.adv)], m) for m in ms])
    return threads, _flag(a, st, pairs)


# ------------------------------------------------- 53fy: a fixed version the advisory does not state

def _flag(a, st: State, pairs: list, fresh: dict | None = None) -> list:
    """``pairs`` with ``Match.fixed_contradicted`` set on each match whose product's
    ``fixed`` no range of the advisory states (``verify.fixed_stated`` is False), and
    cleared on every other. From the source-check results on disk, or from ``fresh``, the
    results this command's own source check returned (they may not have been written).

    Nothing is flagged where this CLI verifies nothing (``_results`` is None:
    ``verify = "off"``, a CLI the trust root calls too old or out of date), whatever
    ``fresh`` holds: a too-old CLI still reads sources. Nor an entry shown at notice
    because no source supports its product (0z4e, ``published``): no range is counted
    for it, and its ``adv`` carries a level nobody published."""
    s = getattr(a, "settings", None)
    cache = _results(a, st, s) if s is not None else None
    if cache is not None and fresh is not None:
        cache = fresh
    return [(t, replace(m, fixed_contradicted=cache is not None and not t.published and m.product is not None
                        and verify.fixed_stated(t.adv, m.product, cache) is False)) for t, m in pairs]


def _correction_key(root_id: str, product, fixed) -> str:
    """What ``seen.json`` holds, beside the root ids, for "the member was told that this
    root's ``fixed`` for this product is not the advisory's": a hash no event id equals
    by chance (as ``pull.narrow_key`` sits beside root ids in ``State.refused``)."""
    return hashlib.sha256(json.dumps(["fixed-correction", root_id, verify.pkey(product), fixed]).encode("utf-8")).hexdigest()


def _flagged(pairs: list) -> dict:
    """{root id: the correction keys of the flagged matches of its entry}, for every root
    of an entry with a flagged match. An entry in it is shown with no translation and
    with its id for its title, for any of its matches: both belong to the entry, are the
    signer's prose, and can name the version of the flagged product."""
    out: dict = {}
    for t, m in pairs:
        for r in t.root_ids if m.fixed_contradicted else ():
            key = _correction_key(r, m.product, m.product.fixed)
            if key not in out.setdefault(r, []):
                out[r].append(key)
    return out


def _corrections(st: State, pairs: list) -> list:
    """The (entry, match) pairs a correction is due for: a critical this machine was
    notified of (it is seen), matched as more than "may apply", whose ``fixed`` was found
    not to be the advisory's after that, and nobody was told yet. ``run`` notifies before
    it reads a source, so the notification of a critical whose ``fixed`` a reply just
    raised names the raised version; without this it would be the only word sent."""
    out, told = [], set()
    for t, m in pairs:
        if t.adv.level != "critical" or m.reason == check.MAY_APPLY or not m.fixed_contradicted or not _seen(t, st):
            continue
        keys = {_correction_key(r, m.product, m.product.fixed) for r in t.root_ids}
        if st.seen.isdisjoint(keys) and told.isdisjoint(keys):
            told |= keys
            out.append((t, m))
    return out


def _correct(st: State, s: config.Settings, due: list) -> int:
    """Send each due correction once, under the state lock like ``_notify``, and remember
    it in ``seen.json``. A correction is no interrupt of its own: no slot, no exit 2.
    One no channel accepted is due again at the next ``run`` or ``notify``: status 1.
    With no channel configured nothing is said here: ``_notify`` reports that."""
    if not due or not s.notify:
        return 0
    status = 0
    with st.locked():
        for t, m in due:
            keys = {_correction_key(r, m.product, m.product.fixed) for r in t.root_ids}
            if not st.seen.isdisjoint(keys):
                continue  # sent already, by a concurrent run
            text = f"{CORRECTION_LINE}\n{notify.format_text(t.adv, m)}"
            accepted = False
            for ch in s.notify:
                r = notify.send(ch, text, s)
                print(f"{ch}: {r.detail}")
                accepted = accepted or r.accepted
            if accepted:
                st.seen.update(keys)
                st.save_seen()
            else:
                status = 1
    return status


# ------------------------------------------------- 0z4e: the memory of support

def _support_step(record: dict, entries: list, cache: dict, digest: str, now: int, roots) -> dict:
    """``State.supported`` after the results of ``cache`` (source-check results, from disk or
    as a run of this command returned them) for the judged states of ``entries``.

    Per thread root and product, [last, gone, seen] in this machine's time: the last read
    that found a source supporting the product (the result names a level above none: a
    whole read, or what an incomplete one did read), the first read not before it whose
    result was contradicted, unsupported (every source read whole, every one an authority,
    none supports the product), and the latest such read. Support at or after ``gone``
    clears ``gone``; "unsupported" read before ``last`` is ignored: the reads are ordered
    by their own times, so a command that reports late changes nothing a later read
    found. A result that confirms the alert as it stands with nothing supported (a
    withdrawn advisory at notice) clears ``gone`` the same way: the source and the alert
    agree. Any other result (a failed read above all) changes nothing.

    Support counts from every state the sources are asked about for the thread: the
    judged one, the alert as shown and its lowered states (``Entry.also``). Support does
    not depend on the level asked about, and a read made to check a lowering must end a
    demotion like any other. But only the judged state's own result clears ``gone``, and
    not when it is "below-source": that result is kept through a failed read under a new
    time (``verify._settled``), so it can set ``last`` (which ends a demotion: too high is
    the safe side) and cannot erase since when no support was read. "No support" counts only from the judged state, and only
    from a read made since this machine first saw the root (``first``): results are kept
    per published state, and a thread posted with the state of an older one must not
    inherit what was read before it existed. Nor from a result dated after ``now``: it
    is read again (``verify._due``), and counted as one read then, not at every command.

    Every stored time is cut to ``now``: one written while the clock was ahead counts from
    now. Under another ruleset digest every ``gone`` is dropped: "no support" found under
    other rules or another scope file is not reused (``last`` is kept: too high is the
    safe side). Roots not in ``roots`` (the ids of the stored events) are dropped."""
    same = record["ruleset"] == digest
    first = {root: min(at, now) for root, at in record["first"].items() if root in roots}
    threads: dict = {}
    for root, names in record["threads"].items():
        for name, (last, gone, seen) in names.items() if root in roots else ():
            last = None if last is None else min(last, now)
            gone, seen = (min(gone, now), min(seen, now)) if same and gone is not None else (None, None)
            if last is not None or gone is not None:
                threads.setdefault(root, {})[name] = [last, gone, seen]
    for t in entries:
        if t.judged is None:
            continue
        mine = [r for r in t.root_ids if r in roots]
        for root in mine:
            first.setdefault(root, now)
        keys = list(dict.fromkeys(verify.state_key(x) for x in (t.judged, t.adv, *t.also)))
        for key in keys:
            held = cache["results"].get(key)
            for name, r in held["products"].items() if held is not None else ():
                whole = key == keys[0] and held["at"] <= now  # the judged state's, and not dated ahead
                up = r["source"] not in (None, ruleset.NONE)
                agreed = whole and r["result"] == verify.CONFIRMED
                down = whole and (r["result"], r["why"]) == (verify.CONTRADICTED, "unsupported")
                at = min(held["at"], now)
                for root in mine if up or agreed or down else ():
                    last, gone, seen = threads.get(root, {}).get(name, (None, None, None))
                    if up:
                        last = at if last is None else max(last, at)
                    if (up and whole and r["why"] != "below-source") or agreed:
                        if gone is not None and at >= gone:
                            gone = seen = None
                    elif down and at >= first[root] and (last is None or at >= last):
                        gone, seen = (at, at) if gone is None else (gone, max(seen, at))
                    if last is None and gone is None:
                        threads.get(root, {}).pop(name, None)
                    else:
                        threads.setdefault(root, {})[name] = [last, gone, seen]
    return {"ruleset": digest, "first": first, "threads": {root: names for root, names in threads.items() if names}}


# ------------------------------------------------- cftg: strikes and probation (finding D14)

def _strikes(st: State, entries: list, supported: dict, now: int) -> list:
    """[(poster key, root ids, time)]: the relay-bot alerts of ``entries`` that the memory
    ``supported`` says no source this machine read ever supported, for one product of the
    judged state at least (``_never``: no root of the entry has ``last`` and every one has
    ``gone``). One alert is one entry: copies of an advisory count once, two unsupported
    products count once. The time is the earliest such product's ``gone``. The key is
    the pubkey of the stored root; roots signed by different keys are an alert for each.
    None while a record rebuilt from damage is younger than SUPPORT_GAP_S, as in ``_never``."""
    if st.reset_at is not None and st.reset_at > now - SUPPORT_GAP_S:
        return []
    out = []
    for t in entries:
        ats = []
        for p in t.judged.products if t.judged is not None else ():
            got = [supported["threads"].get(r, {}).get(verify.pkey(p)) for r in t.root_ids]
            if all(e is not None and e[0] is None and e[1] is not None for e in got):
                ats.append(max(e[1] for e in got))
        keys: dict = {}
        for r in t.root_ids if ats else ():
            if r in st.events:
                keys.setdefault(st.events[r]["pubkey"], []).append(r)
        out += [(key, tuple(roots), min(ats)) for key, roots in keys.items()]
    return out


def _probation_step(record: dict, found: list, now: int) -> dict:
    """``State.probation`` after the alerts struck now (``found``, from ``_strikes``).

    A strike, once found, is written down and stands STRIKE_WINDOW_S from its time whatever
    becomes of its thread: a thread leaves the entries when a relay-bot withdrawal of it
    applies, and the memory of support forgets since when no support was read when the
    ruleset changes, so strikes read from the memory alone could be shed one by one.

    A found alert takes the place of every recorded strike of its key that shares a root
    with it, at the earliest of their times: one alert read again is one strike, and
    copies that have become one alert are one. A recorded strike that two found alerts
    share roots with becomes two: copies whose content now differs are two alerts, so
    nobody keeps a series of fabrications inside one strike by posting each as a copy
    first. A recorded strike no found alert shares a root with stands as it is. Per key
    the MAX_STRIKES latest are kept, each with MAX_STRIKE_ROOTS roots at most: nothing a
    key holder posts grows the record.

    A key with MAX_STRIKES strikes and no probation younger than PROBATION_S is put on
    probation from the time of its latest strike. The entry is not moved while it is
    that young, and one that has run out is left for ``_note_offers`` to remove, which
    starts the waits of the key's lowerings in the same write.

    A stored time is compared as ``min(time, now)`` and kept as it was written. One
    written while the clock was ahead counts as now until the clock reaches it. None is
    cut and written back: a single command run while the clock was set back (a machine
    that starts before its time is set) would otherwise date a probation in the past
    and end it, which is the open side."""
    strikes: dict = {}
    for key, ss in record["strikes"].items():
        live = [[at, list(roots)] for at, roots in ss if min(at, now) > now - STRIKE_WINDOW_S]
        if live:
            strikes[key] = live
    fresh: dict = {}
    replaced: set = set()
    for key, roots, at in found:
        at = min(at, now)
        if at <= now - STRIKE_WINDOW_S:
            continue
        same = [s for s in strikes.get(key, []) if not set(s[1]).isdisjoint(roots)]
        replaced.update(id(s) for s in same)
        fresh.setdefault(key, []).append([min([at, *(s[0] for s in same)]), list(roots)[:MAX_STRIKE_ROOTS]])
    out = {}
    for key in {*strikes, *fresh}:
        ss = [s for s in strikes.get(key, []) if id(s) not in replaced] + fresh.get(key, [])
        out[key] = sorted(ss, key=lambda s: (s[0], sorted(s[1])))[-MAX_STRIKES:]
    since = dict(record["since"])
    for key, ss in out.items():
        if len(ss) >= MAX_STRIKES and not min(since.get(key, -PROBATION_S), now) > now - PROBATION_S:
            since[key] = ss[-1][0]
    return {"strikes": out, "since": since}


def _on_probation(st: State, key: str, now: int) -> bool:
    """The poster key is on probation on this machine: its entry is younger than
    PROBATION_S by this clock (one dated ahead of the clock counts). Read whatever the
    ``verify`` setting is now, as the cap on unverified interrupts is."""
    at = st.probation["since"].get(key)
    return at is not None and min(at, now) > now - PROBATION_S


def _note_support(a, st: State, entries: list, cache: dict | None = None) -> bool:
    """Bring the memory of support (``State.supported``, ``_support_step``) up to the
    source-check results: those of ``cache`` when this command's own source check just
    returned them, else those on disk. With it the record of strikes and probations
    (``State.probation``, ``_probation_step``), from the memory as it then is. True when
    either changed.

    Both are needed. A command hands over its own results because another command may
    write its view of verify.json over them before anyone reads the file again. And every
    command that reads the feed applies what is on disk, so a read whose command died
    before the hand-over is not lost. The record is rewritten under the state lock from
    the record and the stored events as they are on disk then: a thread another command
    pulled meanwhile keeps what that command recorded for it. A state directory that
    cannot be written: this command uses what it computed.

    Sets ``a.judging``: False for a CLI that verifies nothing (``_results`` is None) or
    whose ruleset cannot be loaded. Such a CLI writes no memory and acts on none."""
    a.judging = False
    s = getattr(a, "settings", None)
    try:
        disk = _results(a, st, s) if s is not None else None
        if disk is None:
            return False
        digest = ruleset.load().digest
    except Exception:
        return False
    a.judging = True
    now = int(time.time())
    want = _support_step(st.supported, entries, cache or disk, digest, now, set(st.events))
    # cftg: the strikes and probations, from the memory as just computed
    marks = _probation_step(st.probation, _strikes(st, entries, want, now), now)
    if want == st.supported and marks == st.probation:
        return False
    try:
        with st.locked():
            if st.unverified_damaged:  # damaged since this command began: started again, on the safe side
                _start_again(st)
                return True
            now = int(time.time())
            st.supported = _support_step(st.supported, entries, cache or _results(a, st, s) or disk, digest,
                                         now, set(st.events))
            st.probation = _probation_step(st.probation, _strikes(st, entries, st.supported, now), now)
            st.save_unverified()
    except OSError:
        st.supported, st.probation = want, marks
    return True


def _memory(st: State, t: Entry, name: str) -> tuple:
    """(last, gone, seen) of a product (``name``: its key, ``verify.pkey``, as the results
    are kept) of an entry over its roots (copies of one advisory):
    the latest support any of them recorded; ``gone`` only when every root has one."""
    got = [st.supported["threads"].get(r, {}).get(name) for r in t.root_ids]
    last = max((e[0] for e in got if e is not None and e[0] is not None), default=None)
    if any(e is None or e[1] is None for e in got):
        return last, None, None
    return last, max(e[1] for e in got), max(e[2] for e in got)


def _never(a, st: State, t: Entry, name: str, now: int) -> bool:
    """No source this machine read ever supported product ``name`` of the alert, and whole
    reads of authorities found that none does. Not while the record is younger than
    SUPPORT_GAP_S after it was rebuilt from damage: what it held is unknown."""
    if t.judged is None or not getattr(a, "judging", False):
        return False
    if st.reset_at is not None and st.reset_at > now - SUPPORT_GAP_S:  # and when it is ahead of the clock
        return False
    last, gone, _ = _memory(st, t, name)
    return last is None and gone is not None


def _lost(a, st: State, t: Entry, name: str) -> bool:
    """A source supported the product earlier, and reads more than SUPPORT_GAP_S apart have
    found none since. From the memory alone: a failed read neither brings nor ends it."""
    if t.judged is None or not getattr(a, "judging", False):
        return False
    last, gone, seen = _memory(st, t, name)
    return last is not None and gone is not None and seen - gone > SUPPORT_GAP_S


def _shown(a, st: State, threads: list, pairs: list) -> tuple[list, list]:
    """``threads`` and ``pairs`` with what was never supported shown at notice (finding D8).
    Per match: an alert that names a supported product beside an unsupported one keeps its
    level for the first and loses it for the second. A thread's own entry is lowered when
    every product of its judged state was never supported."""
    now = int(time.time())

    def never(t, names) -> bool:
        return t.adv.level != NOTICE and bool(names) and all(_never(a, st, t, n, now) for n in names)

    def low(t) -> Entry:
        return replace(t, adv=replace(t.adv, level=NOTICE), published=t.adv.level)

    whole = {t.root_id: low(t) for t in threads
             if never(t, [verify.pkey(p) for p in t.judged.products] if t.judged is not None else [])}
    return ([whole.get(t.root_id, t) for t in threads],
            [(whole.get(t.root_id) or (low(t) if m.product is not None and never(t, [verify.pkey(m.product)]) else t), m)
             for t, m in pairs])


def _read_as(t: Entry):
    """The state whose cached result describes an entry: its judged state when it is shown
    at notice (``adv`` then carries a level nobody published), else the alert as shown."""
    return t.judged if t.published else t.adv


def _states(t: Entry) -> list:
    """The states the sources are asked about for an entry: the alert as shown, and its
    judged state when that is another one."""
    if t.judged is None or (not t.published and verify.state_key(t.judged) == verify.state_key(t.adv)):
        return [t.adv]
    return [t.judged] if t.published else [t.adv, t.judged]


def _pin(a, st: State):
    """The ruleset pin of the stored certificate, or None."""
    return getattr(st.cert_for(a.root), "ruleset", None)


def _asked(a, st: State, t, level: str, wide=None):
    """The state the sources are asked about for lowering thread ``t`` to ``level``:
    its widest state, marked claimed when the thread's signed claims say every higher
    level rested on the first id's fields (``verify.claimed``)."""
    wide = wide if wide is not None else pull.widest(t)
    return verify.at_level(wide, level, verify.claimed(wide, level, t.stated, None, _pin(a, st)))


def _narrow_refused(t, st: State) -> bool:
    """The thread's standing narrowing is one this machine's check has refused, and it
    is not applied (the check can confirm a list before the record is brought up to date)."""
    return (t.narrowed is not None and tuple(t.adv.products) != t.narrowed
            and pull.narrow_key(t.root_id, t.narrowed) in st.refused)


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

    cftg: no wait runs either for a lowering or a narrowing when the key that signed the
    reply, or the key that signed the thread's root, has an entry in the record of
    probations (``State.probation``). Its time is kept at the checkpoint's and it is left
    out of what is returned: only the check's own confirmation applies it. An entry that
    has run out by this machine's clock is removed here and nowhere else, under the lock
    and in the write that set the times once more, and only when the checkpoint held was
    issued at or after the probation's end. So the 72 hours of each such reply start at
    the first checkpoint issued after the probation ended that this machine holds,
    however long the machine was off and whatever older checkpoint it still stored.

    A refused narrowing (swfe) is remembered by its content, ``pull.narrow_key`` of the
    root and the list, beside the root ids: added when the check contradicts the
    thread's standing list, and while it is remembered no wait of that list runs. It is
    forgotten only when the check confirms that same list, or when no stored thread has
    published it (``Thread.narrowings``). So it outlives the offer: the list sent again
    after another was confirmed, after the cache was lost, with every read failing, is
    still refused, in whatever order and however often its entries are written. With it
    the thread is marked (``pull.narrow_key`` of the root alone), for as long as it is
    stored: from then on no other list of that thread waits either until fresh whole
    reads of its authorities do not contradict it (``verify.narrowing(whole=True)``), so
    a refused list respelled does not run out 72 hours behind failing reads. A refused
    narrowing stops no lowering of the thread, and a refused lowering stops no narrowing.

    The record is rewritten under the state lock from the events, the checkpoint, the
    record and the source-check results as they are on disk then, never from what this
    command read before it had the lock: a command that started earlier must not write
    its older view over a refusal, or a later start of a wait, that another command has
    saved since, nor drop the memory of a list it has not yet seen published. What it
    decided on is left in ``a.raw``, ``a.clock`` and ``a.check`` for ``_matches``, which
    shows the threads by the same threads, checkpoint and check."""
    def barred(t, reply) -> bool:
        # cftg: the thread's root or the reply was signed by a key with an entry in the record
        # of probations. By the record, not the clock: an entry that has run out bars until
        # this function removes it, in the write that starts the wait again (``over``).
        return reply is not None and any(
            ev is not None and ev["pubkey"] in st.probation["since"] for ev in map(st.events.get, (t.root_id, reply)))

    def over(now) -> set:
        # The probations that have run out by this machine's clock and that the checkpoint
        # issued at ``now`` is not older than: a stored checkpoint from before the end must
        # not become the start of the wait, or the next pull would find the 72 hours over.
        at = int(time.time())
        return {key for key, since in st.probation["since"].items()
                if not _on_probation(st, key, at) and now >= min(since, at) + PROBATION_S}

    def step(check, raw, now, listed) -> tuple[dict, set]:
        want = pull.offers(raw, st.lowerings, now, listed)
        refused = set(st.refused)
        if now is not None and listed is not None:
            refused &= ({t.root_id for t in raw} | {k for t in raw for k in t.narrowings}
                        | {pull.narrow_key(t.root_id) for t in raw if t.narrowings})
            for t in raw:
                if t.offered_by in want:
                    said = check(pull.widest(t), t.offered, t.stated) if check is not None else None
                    if said is False:
                        refused.add(t.root_id)
                    elif said is True or (check is not None and check.whole(pull.widest(t), t.offered, t.stated)):
                        refused.discard(t.root_id)
                    if t.root_id in refused or (said is not True and barred(t, t.offered_by)):
                        # the 72 hours start when the refusal ends, and when the probation does
                        want[t.offered_by] = int(now)
                if t.narrowed_by in want:
                    key, mark, wide = pull.narrow_key(t.root_id, t.narrowed), pull.narrow_key(t.root_id), pull.widest(t)
                    said = check.narrowing(wide, t.narrowed, t.wide.products) if check is not None else None
                    if said is False:
                        refused |= {key, mark}
                    elif said is True:
                        refused.discard(key)
                    if key in refused or (mark in refused and said is not True and not (
                            check is not None and check.narrowing(wide, t.narrowed, t.wide.products, whole=True))) \
                            or (said is not True and barred(t, t.narrowed_by)):
                        want[t.narrowed_by] = int(now)
        return want, refused

    want, refused = step(check, a.raw, now, listed)
    if (want, refused) != (st.lowerings, st.refused) or (now is not None and listed is not None and over(now)):
        fresh = False  # the record was computed again from the refreshed state
        try:
            with st.locked():
                if st.manifest is None or st.manifest_root == a.root:  # else another root's state: not this command's
                    # the events, the checkpoint, the record and the results as they are on disk now
                    a.raw = pull.advisories(st)
                    now, listed = pull.head_clock(st)
                    check = _lowering_check(a, st)
                    st.lowerings, st.refused = step(check, a.raw, now, listed)
                    fresh = True
                    if now is not None and listed is not None:  # the waits were just started again
                        live = {key: at for key, at in st.probation["since"].items() if key not in over(now)}
                        st.probation = {**st.probation, "since": live}
                    st.save_unverified()
        except OSError:
            # Not saved. What was computed under the lock stands for this command: it goes
            # on with the refreshed threads and check, and must not put its older record,
            # without a refusal another command saved, beside them. Before the refresh
            # (the lock itself failed) its own view is all it has.
            if not fresh:
                st.lowerings, st.refused = want, refused
    a.clock, a.check = (now, listed), check  # what was decided on: ``_matches`` shows the threads by the same
    if _min_cli(a, st) is not None or _ruleset_outdated(a, st) is not None:
        return None
    held = {t.offered_by for t in a.raw if t.root_id in st.refused}
    held |= {t.narrowed_by for t in a.raw if _narrow_refused(t, st)}
    # cftg: no wait of a key on probation runs; only this machine's confirmation applies its word
    held |= {i for t in a.raw for i in (t.offered_by, t.narrowed_by) if barred(t, i)}
    return {i: at for i, at in st.lowerings.items() if i not in held}


class _Check:
    """The ``check`` of pull.standing over the source-check results on disk."""

    def __init__(self, cache, rs, pin):
        self.cache, self.rs, self.pin = cache, rs, pin

    def __call__(self, adv, level, stated=()):
        return verify.lowering(adv, level, self.cache, time.time(), self.rs, stated, self.pin)

    def whole(self, adv, level, stated=()) -> bool:
        return verify.lowering(adv, level, self.cache, time.time(), self.rs, stated, self.pin, whole=True) is True

    def narrowing(self, adv, products, shown=None, whole: bool = False):
        return verify.narrowing(adv, products, self.cache, time.time(), shown, whole=whole)


def _lowering_check(a, st: State):
    """The ``check`` of pull.standing from the source-check results on disk, or None:
    with ``verify = "off"``, without settings, and for a CLI the trust root calls too
    old or whose ruleset the trust root calls out of date (its ruleset may be the
    one that is wrong). None settles nothing: a relay-bot
    lowering is not applied and a curator's holds its 14 days."""
    s = getattr(a, "settings", None)
    if s is None or s.verify == "off" or _min_cli(a, st) is not None or _ruleset_outdated(a, st) is not None \
            or not any(pull.asks(t) or t.narrowed is not None for t in getattr(a, "raw", ())):
        return None  # and with no lowering or narrowing to judge, no cache and no ruleset is loaded
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
    try:
        with st.locked():
            if st.unverified_damaged:  # else a concurrent run has mended it
                _start_again(st)
    except OSError:
        _start_again(st, save=False)


def _start_again(st: State, save: bool = True) -> None:
    """The record of ``_mend``, emptied and dated; saved when the caller holds the lock.
    0z4e: the memory of support goes with it, and nothing shows at notice for SUPPORT_GAP_S."""
    st.lowerings, st.refused, st.interrupts, st.held, st.reset_at = {}, set(), {}, {}, int(time.time())
    st.supported, st.probation = no_support(), no_probation()  # cftg: what cannot be read cannot be kept
    _err("the record of unverified alerts was unreadable and has been started again")
    if save:
        st.save_unverified()


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


def _source_check(a, st: State, s: config.Settings, threads: list, pairs: list, asked=()) -> dict | None:
    """Read the primary sources (aitools_alerts.verify) for the threads the
    ``verify`` setting names, and for the lowered states of ``asked`` (``_matches``).
    Never in ``run --json``, which the session-start hook runs, and never while
    this CLI's ruleset is out of date. It changes no exit status; what it finds
    about a lowering is applied by the next ``_matches``. Returns the results it read
    (for ``_note_support``), or None."""
    if s.verify == "off" or _ruleset_outdated(a, st) is not None:
        return None
    wanted = [x for t in (threads if s.verify == "all" else [t for t, _ in pairs]) for x in _states(t)]
    wanted += [adv for adv, here in asked if here or s.verify == "all"]
    # tavj: a confirmation a critical on this machine rests on is read again daily too: it
    # exempts the alert from the cap on unverified interrupts only while it is fresh.
    # 0z4e: and so is every relay-bot match here, at any level: a source that stops
    # supporting an alert this machine confirmed must be seen.
    matched = [x for t, _ in pairs if t.adv.posted_by == verify.BOT for x in _states(t)]
    try:
        return verify.run([x for t in threads for x in _states(t)] + [adv for adv, _ in asked], wanted, st.dir,
                          recheck=[adv for adv, _ in asked] + matched)
    except verify.Unsaved as e:  # read, and not written: what was read still counts in this command
        _err(SOURCE_CHECK_FAILED)
        return e.cache
    except Exception:
        _err(SOURCE_CHECK_FAILED)
        return None


def _source_lines(a, st: State, s: config.Settings, threads: list, fresh: dict | None = None) -> list[str]:
    """One line per product whose source contradicts the post, from the cache.
    Printed: the id as verify.norm_id returned it, a scope product name or a former one, and
    level words. A CLI the trust root calls too old prints none: its ruleset
    and scope file may be the ones that are wrong. ``fresh``: the results this
    command's own source check returned, for the 53fy line (``_flag``)."""
    cache = _cache(a, st, s)
    if _min_cli(a, st) is not None or _ruleset_outdated(a, st) is not None:
        return []
    # swfe: a narrowing this machine's check refused, now or earlier (``_matches`` marks a
    # remembered one): said whatever the check can read today, with ``verify = "off"`` too
    out = list(dict.fromkeys(NARROW_REFUSED_LINE.format(id=i) for t in threads
                             if t.narrow_refused and (i := verify.norm_id(t.adv.id)) is not None))
    if cache is None:
        return out
    rs, now = ruleset.load(), int(time.time())

    def known(name) -> bool:
        """A name of this reader's scope file: a product, or a former name (aabw), which is
        judged as the products that list it and printed in the scope file's spelling."""
        return bool(rs.stands_for(name))

    def named(adv, found: dict) -> list:
        """(the scope product a result is about, the result), by scope name. A product
        that is no scope product has no line: its name is the signer's text."""
        return sorted(((name, found[key]) for key, name in ((verify.pkey(p), verify.scope_of(p)) for p in adv.products)
                       if key in found and known(name)), key=lambda x: x[0])
    for t in threads:
        ident = verify.norm_id(t.adv.id)
        found = {} if t.published else verify.result_for(t.adv, cache) or {}
        # 53fy: every entry the thread shows, matched here or not
        for p in () if t.published or ident is None else t.adv.products:
            if known(name := verify.scope_of(p)) and verify.fixed_stated(t.adv, p, fresh or cache) is False:
                out.append(FIXED_LINE.format(id=ident, name=name))
        # 0z4e: every product of the judged state, with or without a result on disk now
        both = {verify.pkey(p): verify.scope_of(p) for p in (*t.adv.products, *(t.judged.products if t.judged else ()))}
        for name, key in sorted((name, key) for key, name in both.items() if known(name)):
            if ident is None:
                continue
            # 0z4e: from the memory, so a failed read neither brings nor ends either line
            if _never(a, st, t, key, now):
                out.append(UNSUPPORTED_LINE.format(id=ident, name=name))
                continue
            if _lost(a, st, t, key):
                out.append(LOST_LINE.format(id=ident, name=name))
                continue
            r = found.get(key)
            if r is None or r["result"] != verify.CONTRADICTED:
                continue
            if r["why"] == "unsupported":
                # supported earlier: not fabrication; said only past SUPPORT_GAP_S (``_lost``)
                if not (t.judged is not None and getattr(a, "judging", False) and _memory(st, t, key)[0] is not None):
                    out.append(UNSUPPORTED_LINE.format(id=ident, name=name))
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
        what = f"a retraction of {ident}" if t.refused == pull.NONE else f"a withdrawal of {ident}" \
            if t.refused == pull.WITHDRAWN else f"a lowering of {ident} to {t.refused}"
        asked = _asked(a, st, t, t.refused)
        out += [f"source check: {what} is not applied: the source supports {r['source']} for {name}"
                for name, r in named(asked, verify.result_for(asked, cache) or {}) if r["why"] == "below-source"]
    return list(dict.fromkeys(out))


def _check_json(t, m, cache, judged: bool = True) -> dict | None:
    """``source_check`` of one match. None when not ``judged``: an out-of-date CLI
    gives no result at all, not the "unknown, off" a missing cache means."""
    if not judged:
        return None
    if t.published:  # 0z4e: from the memory of support, whatever a later failed read left in the cache
        return {"result": verify.CONTRADICTED, "why": "unsupported", "source_level": ruleset.NONE}
    r = (verify.result_for(t.adv, cache) or {}).get(verify.pkey(m.product)) if m.product is not None else None
    if r is not None and _installed_as(m.product) is None and verify.scope_of(m.product) is not None:
        # aabw: a former name's result is the thread's, not this installation's (``_installed_as``)
        return {"result": verify.UNKNOWN, "why": "no-source", "source_level": None}
    return None if r is None else {"result": r["result"], "why": r["why"], "source_level": r["source"]}


def cmd_verify(a, st: State, s: config.Settings) -> int:
    """The source check on the stored state, then what it found."""
    if _ruleset_outdated(a, st) is not None:
        print("the source check did not run: this aitools-alerts is out of date")
        return 0
    threads, pairs = _matches(a, st)
    got = _source_check(a, st, s, threads, pairs, a.asked)
    changed = got is not None and _note_support(a, st, threads, got)
    if a.asked or changed:  # c1g2, 0z4e: the alerts as they stand after what the sources just said
        threads, pairs = _matches(a, st)
    cache = _cache(a, st, s)
    found = [verify.summary(r)[0] for t in threads if (r := verify.result_for(_read_as(t), cache)) is not None]
    print(f"source check: {found.count(verify.CONFIRMED)} confirmed, {found.count(verify.CONTRADICTED)} "
          f"contradicted, {found.count(verify.UNKNOWN)} not verified")
    if a.asked and (check := _lowering_check(a, st)) is not None:
        said = [check(pull.widest(t), level, t.stated) for t in a.raw for level in pull.asks(t)]
        if said:
            print(f"source check: {len(said)} lowerings, withdrawals or retractions asked about: "
                  f"{said.count(True)} confirmed, {said.count(False)} contradicted, {said.count(None)} not settled")
        said = [False if _narrow_refused(t, st) else check.narrowing(pull.widest(t), t.narrowed, t.wide.products)
                for t in a.raw if t.narrowed is not None]
        if said:
            print(f"source check: {len(said)} narrowings asked about: {said.count(True)} confirmed, "
                  f"{said.count(False)} contradicted, {said.count(None)} not settled")
    for line in _source_lines(a, st, s, threads, got):
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
            "lowering_refused": t.refused, "lowering_waits": t.waiting,
            "narrowing_refused": t.narrow_refused, "narrowing_waits": t.narrow_waiting,
            "published_level": t.published, "fixed_contradicted": m.fixed_contradicted}


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
    flagged = _flagged(pairs)  # 53fy: such an entry is listed by its id, here and in the held line

    def plain(t) -> bool:
        return not flagged.keys().isdisjoint(t.root_ids)
    for t, m in pairs:
        ver = m.installed.version or "unknown version"
        print(f"{t.adv.level.upper()}: {_title(t, s, plain(t))} [{m.installed.name} {ver}: {m.reason}] "
              f"(id {t.adv.id}, {_thread_ref(t)}{_published(t)})")
    cache = _results(a, st, s)
    loose = [t.adv.id for t, m in pairs if _result(t, m, cache) == verify.UNKNOWN]
    if loose:
        print(UNVERIFIED_LINE_IDS.format(ids=", ".join(dict.fromkeys(loose))))
    once = {t.root_id: t for t, _ in pairs}  # an entry matched through two installations is said once
    now = int(time.time())
    for t in {t.root_id: t for t, _ in _interrupts(a, st, s, pairs)[1]}.values():
        line = PROBATION_HELD_LINE if _on_probation(st, _poster(t, st), now) else HELD_LINE
        print(line.format(n=MAX_UNVERIFIED, title=_title(t, s, plain(t)), id=t.adv.id))
    for key, at in sorted(st.probation["since"].items()):
        if _on_probation(st, key, now):
            until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(at, now) + PROBATION_S))
            print(PROBATION_LINE.format(key=key[:12], until=until))
    for t in _unjudged(a, st, s, pairs):
        print(UNJUDGED_LINE.format(id=t.adv.id))
    for t in once.values():
        if t.waiting:
            print(WAITING_LINE.format(id=t.adv.id, level=t.waiting))
        if t.narrow_waiting:
            print(NARROW_WAITING_LINE.format(id=t.adv.id))
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


def _published(t: Entry) -> str:
    """What a line about an entry shown at notice adds (0z4e)."""
    return f"; published at {t.published}" if t.published else ""


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


def _installed_as(product) -> str | None:
    """The scope product a matched installation is judged as: a current product
    (``check.scope_name``), or None. Not a former name (aabw), though the thread's own
    level is judged under one (``verify.scope_of``): a former name stands for several
    products, some threads under it are about none of them, and an installation matches
    it by a configured key, which says nothing about its package. So what the sources
    confirm for the name is not confirmed for the installation, and a match on a former
    name is, for interrupts, the match no check can judge that it was before."""
    return check.scope_name(product.name, product.ecosystem)


def _result(t: Entry, m, cache) -> str | None:
    """The source-check result of the product a match rests on (its ecosystem and name,
    ``verify.pkey``): None for an alert no relay bot posted (it is not checked), unknown
    for a match with no product and for one whose product is no scope product."""
    if t.adv.posted_by != verify.BOT:
        return None
    if t.published:
        return verify.CONTRADICTED
    if m.product is None or _installed_as(m.product) is None:
        return verify.UNKNOWN
    r = (verify.result_for(t.adv, cache) or {}).get(verify.pkey(m.product))
    return r["result"] if r is not None else verify.UNKNOWN


def _pinned_exactly(a, st: State) -> bool:
    """The trust root pins a ruleset and this CLI's own is that one: the same version
    and the same digest, which covers the scope file. Only then does "this product is
    no scope product" say something about a post and not about this reader: a reader
    the pin still permits below its version, one above it, and one with no pin may
    hold another scope file. Never raises."""
    try:
        cert = st.cert_for(a.root)
        pin = cert.ruleset if cert is not None and not cert.ruleset_unreadable else None
        rs = ruleset.load() if pin is not None else None
        return rs is not None and (rs.version, rs.digest) == (pin.version, pin.sha256)
    except Exception:
        return False


def _unjudgeable(t: Entry, m) -> bool:
    """A relay-bot match the source check cannot judge by construction (2mgd): its
    product is no scope product (``_installed_as``), or the alert's first id names no
    source. Read from the post alone, never from a result: it holds before any source
    was read. Either is the signer's choice, and neither is a failed read."""
    return t.adv.posted_by == verify.BOT and (
        verify.norm_id(t.adv.id) is None or m.product is None or _installed_as(m.product) is None)


def _judged_here(a, st: State, s: config.Settings) -> bool:
    """This CLI may leave an unjudgeable match out of the interrupts: the check is on,
    the trust root does not call this CLI too old, and its ruleset is the pinned one."""
    try:
        # and the scope products were read: with none, every product would look like no scope product
        return (s.verify != "off" and _min_cli(a, st) is None and _pinned_exactly(a, st)
                and bool(check.scope_products()))
    except Exception:
        return False


def _unjudged(a, st: State, s: config.Settings, pairs: list | None = None) -> list:
    """The unseen critical alerts that do not interrupt because no match of theirs can
    be judged (``_interrupts``), each once."""
    if not _judged_here(a, st, s):
        return []
    groups: dict = {}
    for t, m in _unseen_critical(a, st, pairs):
        groups.setdefault(t.root_id, (t, []))[1].append(m)
    return [t for t, ms in groups.values() if all(_unjudgeable(t, m) for m in ms)]


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
    source is asked for it and the scope product the match was judged as, and nothing
    else of the post. The aliases, the level, the title, the root and the spelling of
    the product are the signer's to vary; what this machine read and confirmed is that
    id for that product."""
    name = (_installed_as(m.product) or m.product.name) if m.product is not None else ""
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
    is free (``State.reset_at``). A curator's alert needs no slot.

    cftg: nor is one free for a poster key on probation on this machine
    (``_on_probation``): its unverified alerts are held, those that took a slot before
    the probation began too. One the source confirms interrupts as above.

    A relay-bot match that cannot be judged by construction (``_unjudgeable``) is left
    out when this CLI's ruleset is the pinned one (``_judged_here``): an alert with no
    other match is neither pending nor held and takes no slot (2mgd). Two unverified
    interrupts a day, for good, is what a respelled product would otherwise buy."""
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
    strict = _judged_here(a, st, s)
    for t, m in _unseen_critical(a, st, pairs):
        if not (strict and _unjudgeable(t, m)):
            groups.setdefault(t.root_id, (t, []))[1].append(m)
    never = float("inf")
    for t, ms in sorted(groups.values(), key=lambda g: min(st.held.get(r, never) for r in g[0].root_ids)):
        # the first confirmed match whose advisory-and-product slot this alert holds or can take
        sure = next((m for m in ms if _confirmed_now(t, m, cache, now) and take(_verified_bucket(t, m), 1, t)), None)
        if sure is not None:  # the confirming match first: it is the one a notification describes
            pending += [(t, sure)] + [(t, m) for m in ms if m is not sure]
        elif _result(t, ms[0], cache) is None:
            pending += [(t, m) for m in ms]
        elif not rebuilt and not _on_probation(st, _poster(t, st), now) and take(_poster(t, st), MAX_UNVERIFIED, t):
            loose.update(t.root_ids)
            pending += [(t, m) for m in ms]
        else:
            held += [(t, m) for m in ms]
    return pending, held, grants, loose


def _reserve(st: State, pending: list, held: list, grants: list, loose=frozenset()) -> tuple[list, list]:
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
    full disk.

    cftg: an unverified alert among ``pending`` (its roots are in ``loose``) whose poster
    key is on probation in the record as it is under the lock is held too, with or
    without a grant: a probation another command began meanwhile counts."""
    denied = set()
    waiting = {t.root_id for t, _ in held}
    looked = waiting | {t.root_id for t, _ in pending}
    unsure = [t for t, _ in pending if not loose.isdisjoint(t.root_ids)]
    if not grants and not waiting and not st.held and not unsure:
        return pending, held
    try:
        with st.locked():
            now, slots = int(time.time()), dict(st.interrupts)
            denied |= {t.root_id for t in unsure if _on_probation(st, _poster(t, st), now)}
            for bucket, cap, root in grants:
                have = _slots(st, bucket, now)
                if root in have or root in denied:
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


def _notify(st: State, s: config.Settings, pending, loose=frozenset(), flagged=None, withheld=None) -> int:
    """Send each pending advisory once, under the state lock: a concurrent
    run waits, then re-reads seen and skips what this one already sent. Every
    root of an advisory is marked seen; one seen root makes it seen. An unverified
    alert (its roots are in ``loose``) says so in the last line of its text.

    ``flagged`` (53fy, ``_flagged`` of the command's pairs): an entry in it is sent with
    no translation, whichever match the text describes, and once it is accepted every
    flagged match of the entry counts as told: no correction follows a notification
    that named no version.

    cftg: an unverified alert whose poster key is on probation in the record as it is
    under this lock is not sent and not marked seen: a probation another command began
    after ``_reserve`` counts. Its root ids are added to ``withheld`` (a set), so the
    caller reports it as held and not as an interrupt. With no channel configured the
    same is decided under a lock of its own."""
    flagged = flagged or {}
    withheld = set() if withheld is None else withheld

    def barred(t) -> bool:  # under the lock
        if loose.isdisjoint(t.root_ids) or not _on_probation(st, _poster(t, st), int(time.time())):
            return False
        withheld.update(t.root_ids)
        return True
    if not pending:
        return 0
    if not s.notify:
        try:
            if not loose.isdisjoint(r for t, _ in pending for r in t.root_ids):
                with st.locked():
                    pending = [(t, m) for t, m in pending if not barred(t)]
        except OSError:
            pass
        if not pending:
            return 0
        _err("no notify channel configured")
        return 1
    status = 0
    with st.locked():
        for t, m in pending:
            if _seen(t, st):
                continue  # sent already (by this run, or a concurrent one)
            if barred(t):
                continue
            told = {k for r in t.root_ids for k in flagged.get(r, ())}
            text = notify.format_text(t.adv, m, None if told else _tr(t, s), plain=bool(told))
            if not loose.isdisjoint(t.root_ids):
                text += f"\n{NOT_VERIFIED}"
            accepted = False
            for ch in s.notify:
                r = notify.send(ch, text, s)
                print(f"{ch}: {r.detail}")
                accepted = accepted or r.accepted
            if accepted:
                st.seen.update(t.root_ids)
                st.seen.update(told)
                st.save_seen()
            else:
                status = 1
    return status


def cmd_notify(a, st: State, s: config.Settings) -> int:
    _, pairs = _matches(a, st)
    pending, held, grants, loose = _interrupts(a, st, s, pairs)
    # loose roots that end up held are not sent
    status = _notify(st, s, _reserve(st, pending, held, grants, loose)[0], loose, _flagged(pairs))
    return _correct(st, s, _corrections(st, pairs)) or status  # 53fy


def cmd_plan(a, st: State, s: config.Settings) -> int:
    threads, pairs = _matches(a, st)
    wanted = [t for t in threads if a.advisory_id in (*t.root_ids, t.adv.id)]
    if not wanted:
        _err(f"no current advisory {a.advisory_id!r}")
        return 1
    roots = {t.root_id for t in wanted}  # by root: a match may carry its own entry, shown at notice (0z4e)
    hits = [(t, m) for t, m in pairs if t.root_id in roots]
    if not hits:
        print(f"{_title(wanted[0], s)}: nothing installed here is affected")
        return 0
    cfg = s.check_config()
    reason = _unverified(a, st)
    if reason:  # completeness is not established: a retraction may be missing
        print(UNVERIFIED_LINE.format(reason=reason))
    flagged = _flagged(pairs)
    for t, m in hits:
        p = check.plan(m, cfg)
        if reason:
            p = replace(p, auto_apply=[], prepare=[*p.auto_apply, *p.prepare])
        # 53fy: no translation and no title for an entry one of whose matches has a ``fixed``
        # the source contradicts: they are the signer's prose and can name that version
        plain = not flagged.keys().isdisjoint(t.root_ids)
        print(f"{t.adv.level.upper()}: {_title(t, s, plain)} [{m.installed.name} "
              f"{m.installed.version or 'unknown version'}] posted by {t.adv.posted_by}{_published(t)}")
        tr = None if plain else _tr(t, s)  # quoted with "> ": translated text, never a section or a command
        for line in (tr.split("\n")[1:] if tr else []):
            print(f"    > {line}".rstrip())
        print(_source_line(t.adv))
        for title, actions in (("auto-apply (opted in)", p.auto_apply),
                               ("prepare (ask first)", p.prepare)):
            if not actions:
                continue
            print(f"  {title}:")
            for x in actions:
                print(f"    {check.describe(x, m.fixed_contradicted)}")
                if x.verb == "upgrade" and m.product is not None:
                    argv = upgrade_command(m.product.ecosystem, x.value)
                    if argv:
                        print(f"      command: {shlex.join(argv)}")
                    elif not x.value and m.fixed_contradicted:
                        print(f"      {check.NOT_THE_ADVISORYS}: notify only, no command")
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
    pending, held = _reserve(st, pending, held, grants, loose)  # before anything is reported
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
    withheld: set = set()  # cftg: what a probation begun since ``_reserve`` kept from being sent

    def send(them, loose, pairs) -> int:
        if a.quiet or a.json:
            with contextlib.redirect_stdout(io.StringIO()):
                return _notify(st, s, them, loose, _flagged(pairs), withheld)
        return _notify(st, s, them, loose, _flagged(pairs), withheld)
    def correct(pairs, fresh=None) -> int:  # 53fy
        due = _corrections(st, _flag(a, st, pairs, fresh))
        if a.quiet or a.json:
            with contextlib.redirect_stdout(io.StringIO()):
                return _correct(st, s, due)
        return _correct(st, s, due)
    status = send(pending, loose, pairs)
    got = None
    if not a.json:  # the hourly job's form; the hook runs --json and must read no source.
        # After the notification: a critical never waits for a source.
        got = _source_check(a, st, s, threads, pairs, a.asked)
        if s.verify != "off":
            # c1g2: what the sources just said about a lowering counts in this run. A
            # critical that a contradicted lowering had hidden is notified now, and so is
            # one that was held unverified and that its source has just confirmed (tavj).
            # 0z4e: and an alert the sources just read never supported shows at notice.
            def levels():
                # swfe: a confirmed narrowing changes the products, and may end this machine's match
                return (sorted((t.root_id, t.adv.level, repr(t.adv.products)) for t in threads),
                        sorted((t.root_id, t.adv.level, repr(m.product)) for t, m in pairs))
            before = levels()
            changed = got is not None and _note_support(a, st, threads, got)
            if a.asked or changed:
                threads, pairs = _matches(a, st)
            tried = {r for t, _ in pending for r in t.root_ids}
            pairs = _flag(a, st, pairs, got)  # 53fy: by what this run just read, written or not
            again, held, grants, loose = _interrupts(a, st, s, pairs)
            again, held = _reserve(st, again, held, grants, loose)
            late = [x for x in again if tried.isdisjoint(x[0].root_ids)]
            status = send(late, loose, pairs) or status
            pending = pending + late
            if not a.quiet and before != levels():
                print("After the source check:")  # what was listed above is no longer what stands
                cmd_check(a, st, s, source_lines=False)
        for line in () if a.quiet else _source_lines(a, st, s, threads, got):
            print(line)
    # 53fy: a critical this machine was notified of whose fixed version the source contradicts
    status = correct(pairs, got) or status
    pending = [x for x in pending if x[0].root_id not in withheld]  # held, not an interrupt
    if a.json:
        out["held_critical"] = sorted({*out["held_critical"], *(r for r in out["unseen_critical"] if r in withheld)})
        out["unseen_critical"] = [r for r in out["unseen_critical"] if r not in withheld]
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
