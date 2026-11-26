"""When a posted thread's level may fall (ai-tools-alerts#ny5g; findings D4 and D13).

The poster recomputes the level of every open thread the ledger marks exploited, and
of every thread that carries a GHSA id (ai-tools-alerts#3qyq), from the KEV catalog
and the advisory responses it read, each run. A read of a source, for one thread, has one
of three results: ``confirmed`` (the source states it), ``contradicted`` (a complete
read that does not) or ``unknown``. Only evidence moves a level:

- ``unknown`` changes nothing, starts no wait and adds no time to one. A fetch that
  failed and a body that did not parse give no copy at all. A copy reached through a
  redirect, one with no version,
  one that disagrees with its own count, and one with fewer entries than ``SHRINK``
  of the largest complete copy ever read are not complete (``kev_copy``): what such
  a copy lists still counts, what it lacks proves nothing. An advisory id whose
  response was not read this run (``sources.Reader``: any failure, a 404 too, and a
  spent share), one the source does not tie to the thread's first id
  (``sources.tied``), and one whose class cannot lower (``Support.lowers``: an
  unreviewed advisory that is not the vendor's own) are unknown as well.
- A raise publishes in the run that sees the entry, from any copy that parses.
- A lowering needs every source of the thread read whole; the same lower level
  held for ``DWELL``, counted only from one complete read to the next when no
  more than ``MAX_GAP`` and no unknown read lies between them, the last read of
  a later ``catalogVersion`` than the first (``judge``); for each CVE that is gone,
  a complete copy that listed it for this product before; no level change on the
  thread in the seven days before (``ledger.QUIET``); and a run in which no more
  than ``TRIP_MIN`` threads or ``TRIP_SHARE`` of the threads judged fall due
  within a day (``select``).

A level that rests on a reading of prose is never recomputed below it (the
ledger's ``floor``), and ``notice`` is the lowest result: there is no withdrawn
state and no retraction here. Nothing in this module sends or fetches.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from aitools_alerts import ruleset
from aitools_alerts.poster import inputs, sources
from aitools_alerts.poster.candidates import BOT_ID
from aitools_alerts.poster.ledger import QUIET

DWELL = 24 * 3600  # a lower level must be held this long, over complete reads
MAX_GAP = 2 * 3600  # two complete reads further apart than this add nothing to that time
SHRINK = 0.98  # a KEV copy with fewer entries than this share of the largest complete one is not complete
TRIP_MIN, TRIP_SHARE = 2, 0.2  # more than both due in one run, counting the last TRIP_WINDOW's: lower none
TRIP_WINDOW = 24 * 3600
RELEASE_AFTER = 7 * 86400  # a trip this long without a break lets RELEASE lowerings a run through
RELEASE = 2
_VERSION = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){1,4}")  # CISA's catalogVersion: 2026.11.24
MAX_LOWERED = 200  # ids waiting for the digest line
_LEVELS = ("notice", "high", "critical")
_DWELL = {"level": str, "held": int}  # "last": the complete read before, or None; "version": the KEV copy's, or None
_KEV = {"version": str, "peak": int, "at": int}  # the latest version and the largest size of a complete copy
_TRIP = {"since": int, "due": int}


@dataclass(frozen=True)
class Copy:
    """One run's KEV read. ``complete``: its absences are evidence too."""
    version: str | None
    index: dict
    complete: bool


def new_state() -> dict:
    return {"kev": None, "direct": None, "listed": {}, "dwell": {}, "lowered": [], "reported": None,
            "recent": [], "tripped": None, "open": None, "exploited": {}}


def _shaped(v, shape: dict) -> bool:
    return isinstance(v, dict) and set(v) == set(shape) and all(type(v[k]) is t for k, t in shape.items())


def _ok(st) -> bool:
    return (isinstance(st, dict) and set(st) == set(new_state())
            and (st["kev"] is None or _shaped(st["kev"], _KEV))
            and isinstance(st["listed"], dict)
            and all(isinstance(k, str) and isinstance(v, list) and all(isinstance(i, str) for i in v)
                    for k, v in st["listed"].items())
            and isinstance(st["dwell"], dict)
            and isinstance(st["exploited"], dict)
            and all(isinstance(k, str) and isinstance(v, list) and v and all(isinstance(i, str) for i in v)
                    for k, v in st["exploited"].items())
            and all(isinstance(k, str) and isinstance(v, dict) and (v.get("last") is None or type(v["last"]) is int)
                    and "last" in v and "version" in v and (v["version"] is None or isinstance(v["version"], str))
                    and _shaped({x: v[x] for x in v if x not in ("last", "version")}, _DWELL) and v["level"] in _LEVELS
                    for k, v in st["dwell"].items())
            and isinstance(st["lowered"], list)
            and all(isinstance(x, list) and len(x) == 2 and isinstance(x[0], str) and x[1] in _LEVELS
                    for x in st["lowered"])
            and (st["direct"] is None or isinstance(st["direct"], str))
            and isinstance(st["recent"], list)
            and all(isinstance(x, list) and len(x) == 2 and type(x[0]) is int and isinstance(x[1], str)
                    for x in st["recent"])
            and (st["reported"] is None or isinstance(st["reported"], str))
            and (st["open"] is None or type(st["open"]) is int)
            and (st["kev"] is None or version_of(st["kev"]["version"]) is not None)
            and all(v["version"] is None or version_of(v["version"]) is not None for v in st["dwell"].values())
            and (st["tripped"] is None or _shaped(st["tripped"], _TRIP)))


def load(path: Path) -> tuple[dict, bool]:
    """(state, replaced). A missing file is the empty state. One that does not read or
    is malformed is replaced by the empty state: every wait starts over, and a CVE's
    absence proves nothing again until a complete copy has listed it, so a lost file
    can only delay a lowering."""
    try:
        st = inputs.read_json(path, inputs.MAX_RECORD)
    except FileNotFoundError:
        return new_state(), False
    except (OSError, ValueError, RecursionError):
        return new_state(), True
    try:
        if isinstance(st, dict):
            st.setdefault("exploited", {})  # 3qyq: a state written before it has none
        return (st, False) if _ok(st) else (new_state(), True)
    except Exception:  # noqa: BLE001 - whatever the file holds, it is one that does not read
        return new_state(), True


def save(path: Path, st: dict) -> None:
    inputs.write_json(path, st)


def version_of(text) -> tuple | None:
    """A catalogVersion as numbers that order (CISA writes the date: 2026.11.24), or
    None for any other text: "advanced" has no meaning for a version that does not order."""
    if not isinstance(text, str) or not _VERSION.fullmatch(text.strip()):
        return None
    return tuple(int(x) for x in text.strip().split("."))


def begin(st: dict, now: int) -> None:
    """A run starts observing. If the run before never finished (it stopped between
    here and the save that ends ``Run.observe``), what it read is not known: every
    wait takes nothing for the stretch up to the next complete read."""
    if st["open"] is not None:
        for root in st["dwell"]:
            pause(st, root)
    st["open"] = now


def kev_copy(catalog, status, st: dict, now: int, redirected: bool | None = None) -> Copy | None:
    """This run's KEV read, or None when there is none to use: not fetched (any status
    but ``ok`` and ``304``; never the synthetic ``--kev-file``), not the CISA shape, or
    an entry that is not an object with a ``cveID``.

    The copy is complete only when this run's answer was not reached through a
    redirect (a 3xx is not an answer from the catalog's own address; ``redirected`` is
    what the fetch said, for a 200 and for a 304 alike. A 304 stands for whatever copy
    the cache holds, so ``st["direct"]`` keeps the digest of the last body that came
    direct, and a cached body is direct only when it is that very body: a redirected
    one cached by a run that stopped before saying so never matches), has a version
    that orders and is not older than the latest complete copy's (an old catalog served
    again says nothing about now), a ``count`` equal to its number
    of entries (a catalog that disagrees with its own count is cut short), and no
    fewer entries than ``SHRINK`` of the peak: the largest complete copy this state
    has read. The peak never falls, so no run of small copies, however long, becomes
    the measure. If CISA ever prunes more than 2% the poster stops lowering on KEV
    absences and says so each run; it still raises."""
    if status not in ("ok", "304") or not inputs._catalog_ok(catalog):
        return None
    version, items = catalog.get("catalogVersion"), catalog["vulnerabilities"]
    if not all(isinstance(it, dict) and isinstance(it.get("cveID"), str) for it in items):
        return None
    index = {it["cveID"].strip().upper(): it for it in items}  # as bare_ids writes a CVE
    version = version.strip() if version_of(version) is not None else None
    try:
        digest = hashlib.sha256(json.dumps(catalog, sort_keys=True).encode("utf-8")).hexdigest()
    except (TypeError, ValueError):
        return None
    if status == "ok":
        st["direct"] = digest if redirected is False else None
    whole = redirected is False and st["direct"] == digest and version is not None and bool(items) \
        and type(catalog.get("count")) is int and catalog["count"] == len(items) == len(index)
    peak = st["kev"]["peak"] if st["kev"] else 0
    latest = version_of(st["kev"]["version"]) if st["kev"] else None
    if not whole or len(items) < SHRINK * peak or (latest is not None and version_of(version) < latest):
        return Copy(version, index, False)
    st["kev"] = {"version": version, "peak": max(peak, len(items)), "at": now}
    return Copy(version, index, True)


def bare_ids(entry) -> set[str] | None:
    """The thread's ids as sources are looked up by them (CVE upper case, GHSA as the
    API writes it), from its published advisory and the ledger's identity set; None
    when any id has another shape, which no reader here can look up."""
    adv = entry.advisory
    out = set()
    for i in [adv.get("id"), *(adv.get("aliases") or ()), *entry.aliases]:
        m = BOT_ID.fullmatch(i) if isinstance(i, str) else None
        if m is None:
            return None
        base = m.group(1)
        out.add(base.upper() if base[:3].upper() == "CVE" else "GHSA" + base[4:].lower())
    return out


def floor(entry, rs) -> str:
    """The level the recompute never goes below: what readings of prose alone gave
    the thread, as the ledger recorded it when the thread was planned (``Entry.floor``).
    A reading never justifies a lowering. An entry written before the ledger kept it
    cannot say what its level rested on, so it is taken to rest on a reading as far as
    a reading can reach: its own level, or ``reading_cap`` when that is lower."""
    if entry.floor in _LEVELS:
        return entry.floor
    return min(entry.level, rs.reading_cap, key=rs.rank)


def lookup_id(i) -> str | None:
    """A thread's id as a source is looked up by it (CVE upper case, ``GHSA-`` then
    lower case, a thread key's slug dropped), or None for another shape."""
    m = BOT_ID.fullmatch(i) if isinstance(i, str) else None
    if m is None:
        return None
    base = m.group(1)
    return base.upper() if base[:3].upper() == "CVE" else "GHSA" + base[4:].lower()


def judged(entry) -> bool:
    """Whether the thread has a source a lowering could rest on: the ledger marks it
    exploited (KEV), or one of its ids is looked up in an advisory database."""
    return entry.exploited is True or any(sources.advisory_id(i) for i in bare_ids(entry) or ())


def published_aliases(entry) -> list:
    """The thread's published aliases as lookups write them, in order: what a member's
    check sees of it."""
    return [x for x in (lookup_id(a) for a in entry.advisory.get("aliases") or ()) if x is not None]


def support(entry, scope, copy: Copy | None, rs, read=None, counted: list | None = None) -> tuple[str, bool, set, set, bool]:
    """(found, known, listed, gone, stop): the level the thread's sources state for its
    product by their fields (``ruleset.NONE`` when none does); whether every source
    was read whole; the CVEs the copy lists as this product, and those it does not
    list; whether a read gives ``found`` through a stop_using row.

    The ids that count are the ones a member's check reads (``sources.chosen``,
    ``verify._Run.thread``), so no level is published that it could not confirm: the
    first id; beside a CVE first id, the first three advisory ids among the published
    aliases, each only when its own response may lower and names that CVE, and (as
    ny5g) the thread's other CVEs; beside a GHSA first id whose response may lower,
    the first three ids that response names, CVEs among them, carried by the thread
    or not. That is how an OSV entry is reached. ``read``: advisory id ->
    ``sources.Read`` or None (None: every advisory id is unread).

    Not known: an id of another shape; with a CVE among the ids that count, no
    complete KEV copy; a CVE the catalog lists under a name that is not this product
    (a rename is not a removal) or that is not a reading; an advisory id that was not
    read; any id of the thread a member's check does not read or the source does not
    tie (it is not counted either: neither a listing nor an absence of it says
    anything about this thread); a response whose class for this product cannot
    lower (3qyq: its support, a notice at most, is not counted); a first response
    that names more ids than a member reads.

    ``counted``, when given, receives each reading counted, as ``(source, fields)``:
    an advisory response that was read, is tied and may lower, whatever it supports
    (a withdrawal too), and each KEV entry read as this product's. They are what a
    level change of this run rests on (hh5s: its claim)."""
    ids = bare_ids(entry)
    counted = [] if counted is None else counted
    read = read or (lambda i: None)
    found, listed, gone, stop = ruleset.NONE, set(), set(), False
    if ids is None:
        return found, False, listed, gone, stop
    first = lookup_id(entry.advisory.get("id"))
    aliases = published_aliases(entry)
    picked, known = sources.chosen(first, aliases, read)
    first_kev = ruleset.source_of(first) == "kev"
    for i in sorted(ids | set(picked)):
        if ruleset.source_of(i) != "kev":
            # tied first: an id a member's check does not read is not asked for either
            r = read(i) if sources.tied(first, i, read, aliases) else None
            if r is None:
                known = False
                continue
            own = r.support.get(scope.name)
            if not (own[1] if own is not None else r.lowers):
                known = False  # a source its subject's attacker can write justifies no lowering
            else:
                counted.append((r.source, r.fields))
                if own is not None and own[0] != ruleset.NONE:
                    if rs.rank(own[0]) > rs.rank(found):
                        found, stop = own[0], False
                    stop = stop or (own[0] == found and own[2])
            continue
        if not first_kev and i not in picked:
            known = False  # a CVE the first id's response does not name, or names past what a member reads
            continue
        if copy is None or not copy.complete:
            known = False
        item = copy.index.get(i) if copy is not None else None
        if item is None:
            gone.add(i)  # a contradiction when the copy is complete, nothing otherwise
            continue
        try:
            vendor, product = item.get("vendorProject"), item.get("product")
            fields = {"cve_id": i, "name": f"{vendor.strip()} {product.strip()}"}
            got = rs.read("kev", fields).get(scope.name)
        except (ruleset.RulesetError, AttributeError):
            got = None
        if got is None or got.level == ruleset.NONE:
            known = False
        else:
            counted.append(("kev", fields))
            if rs.rank(got.level) > rs.rank(found):
                found, stop = got.level, False
            listed.add(i)
    return found, known, listed, gone, stop


def held(entry, scope, found: str, rs, stop: bool = False, infer: bool = True) -> str:
    """``found`` as the thread can carry it (9kgk, ``Ruleset.action_level``): with its
    published actions and the fix its root stated, the one every reader keeps (tyje). A
    KEV listing of a thread with no such fix supports high, not critical. ``stop``: a
    read of this run gives ``found`` through a stop_using row (3qyq), so a published
    stop_using completes it again after the advisory was withdrawn and came back.
    ``infer``: some source was not read whole, so a thread standing at ``found`` by a
    published stop_using is taken to stand there by a reading that said so. With
    every source read (``infer`` false) only what this run read says so: an advisory
    that now states a patched version no longer completes the level by stop_using,
    as a member's check of the same response finds."""
    acts = [(a.get("verb"), a.get("target"), a.get("value")) for a in entry.advisory.get("actions") or []
            if isinstance(a, dict)]
    stop = stop or (infer and found == entry.level and any(v == "stop_using" and t == scope.name for v, t, _ in acts))
    capped = rs.action_level(found, acts, scope.name, entry.fix_at_root, stop_using=stop or None)
    if not entry.root_known:  # an entry from before root_fixed, already replied to: raise-only
        return rs.highest(capped, min(found, entry.level, key=rs.rank))
    return capped


def raised(entry, scope, copy: Copy | None, rs, read=None) -> str | None:
    """The level ``judge`` would raise the thread to on this read, or None. It reads
    only: the thread's wait is ``judge``'s to keep (jsje: asked of a thread with work
    in flight, which is not judged)."""
    found, known, _, _, stop = support(entry, scope, copy, rs, read)
    found = held(entry, scope, found, rs, stop, infer=not known)
    return found if rs.rank(found) > rs.rank(entry.level) else None


def judge(entry, scope, copy: Copy | None, rs, st: dict, now: int, read=None, info: dict | None = None):
    """("raise", level), ("due", level) or None for one thread; keeps its wait in
    ``st["dwell"]``. A raise rests on a source's fields alone and needs no complete
    read: an unread source can only add. ``info``, when given, receives ``known``
    (every source read whole this run) and ``listed``.

    The two rules about a CVE's absence from KEV (it must have been seen listed by a
    complete copy; the wait must end on a later catalog) govern a thread the ledger
    marks exploited, and one a copy, complete or not, has ever listed for this product
    (``info["readings"]``: the readings counted, ``support``'s ``counted``.)
    (``st["exploited"]``: per thread the CVEs listed, recorded here whether or not a
    level changes; ``Run.recompute`` then marks the ledger). Such a thread is not
    known without a complete copy, while a CVE once listed is no longer among the ids
    judged (an advisory that stopped naming it says nothing about KEV), and when no
    CVE of it is judged at all. A thread KEV never listed does not rest on it: that
    absence is not what lowers it (3qyq)."""
    counted: list = []
    found, known, listed, gone, stop = support(entry, scope, copy, rs, read, counted)
    root, dwell = entry.root_event_id, st["dwell"]
    ever = set(st["exploited"].get(root, ()))
    if listed - ever:
        ever |= listed
        st["exploited"][root] = sorted(ever)
    kev = entry.exploited is True or bool(ever)
    if kev and (copy is None or not copy.complete or ever - (listed | gone) or not (listed | gone)):
        known = False
    if info is not None:
        info.update(known=known, listed=listed, readings=counted)
    found = held(entry, scope, found, rs, stop, infer=not known)
    if rs.rank(found) > rs.rank(entry.level):
        dwell.pop(root, None)
        return "raise", found
    seen = set(st["listed"].get(root, ()))
    if known and listed - seen:
        st["listed"][root] = sorted(seen | listed)
    level = rs.highest(found, floor(entry, rs), "notice")
    if rs.rank(level) >= rs.rank(entry.level):
        # What the copy lists holds the level, complete or not: evidence for the level needs
        # no completeness, and it ends a wait for a lower one.
        dwell.pop(root, None)
        return None
    if not known or (kev and gone - seen):
        # Unknown, or gone from the catalog without this state ever having seen it there
        # (absence proves nothing yet): nothing moves. A wait already running keeps its
        # time and takes none for the stretch up to the next complete read.
        pause(st, root)
        return None
    version = copy.version if copy is not None and copy.complete else None
    rec = dwell.get(root)
    if rec is None or rec["level"] != level or (kev and rec["version"] is None):
        dwell[root] = {"level": level, "version": version, "last": now, "held": 0}
        return None
    if rec["last"] is not None and 0 <= now - rec["last"] <= MAX_GAP:
        rec["held"] += now - rec["last"]  # from one complete read to the next, nothing unknown between
    rec["last"] = now
    if rec["held"] >= DWELL and (not kev or version_of(version) > version_of(rec["version"])):
        return "due", level  # a later catalog than the one the wait began with still says so
    return None


def note(st: dict, root: str, now: int) -> None:
    """A lowering of this thread was recorded: the breaker counts it for ``TRIP_WINDOW``.
    Once a thread: a replay of the journal after a failed ledger write comes here again
    for the same lowering, and a thread is lowered at most once in seven days."""
    if not any(r == root and 0 <= now - t < TRIP_WINDOW for t, r in st["recent"]):
        st["recent"].append([now, root])


def pause(st: dict, root: str) -> None:
    """The thread was not judged this run: its wait keeps what it holds and takes
    nothing for the stretch up to the next complete read."""
    if root in st["dwell"]:
        st["dwell"][root]["last"] = None


def quiet(entry, now: int) -> bool:
    """No level change on the thread in the last seven days: it may be lowered."""
    return not any(now - t < QUIET for t in entry.changed or ())


def select(due: list, open_count: int, st: dict, now: int) -> list:
    """The circuit breaker over ``due``, [(entry, level)]; what it returns is lowered
    now. The count is of the threads due plus those lowered in the last ``TRIP_WINDOW``
    (``st["recent"]``: ``note`` adds a thread when its lowering is recorded, never for
    one that did not send), so a source that sheds its entries a few an hour
    trips it as one that sheds them at once does. More than ``TRIP_MIN`` and more than
    ``TRIP_SHARE`` of the ``open_count`` threads judged: none is lowered and
    ``st["tripped"]`` says since when, for the digest; once that has lasted
    ``RELEASE_AFTER``, ``RELEASE`` a run go through, oldest thread first. Otherwise all
    of them."""
    st["recent"] = [x for x in st["recent"] if 0 <= now - x[0] < TRIP_WINDOW][-1000:]
    count = len(due) + len(st["recent"])
    if not due or count <= TRIP_MIN or count <= TRIP_SHARE * open_count:
        st["tripped"] = None
        out = due
    else:
        since = st["tripped"]["since"] if st["tripped"] else now
        st["tripped"] = {"since": since, "due": len(due)}
        out = [] if now - since < RELEASE_AFTER else \
            sorted(due, key=lambda d: (d[0].posted_at, d[0].root_event_id))[:RELEASE]
    return out
