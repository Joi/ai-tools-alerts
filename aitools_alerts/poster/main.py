"""``aitools-alerts-poster``: the hourly run that turns watch output into relay posts.

A run drains the journal left by earlier runs, then reads candidates (heartbeat
run dirs newer than the watermark, the newest validated collector record, the
CISA KEV catalog this run fetched itself), keeps those in scope, merges them per
scope, rates them and plans their messages: a new critical posts to ``critical``
then ``feed``, a new high to ``feed``, a new notice waits for the daily digest
(09:00 Asia/Tokyo), and a known advisory with something new gets a reply in each
of its threads.

Every message of a plan is composed before any is journaled, so a ValueError
from compose withholds the whole advisory. Journaled messages (the state file's
``outbox``) are sent in order, each marked pending in the ledger first; a sent
message's event id is journaled before the ledger records it, so a crash after
that point is finished on the next run without sending again. After one failed
or unknown send, or any LedgerError, the run sends nothing more and exits 1, and
watermarks advance only when every send of the run succeeded.

Every post is relay-bot and composed by ``compose``, which refuses text naming a
host, a local path or a kata ref; this module adds nothing to post text.

The summary line ends with ``inputs=kev:<ok|304|file|unavailable>,
collector:<off|none|ok|rejected>,heartbeat:<off|accepted/read>``; a rejected input
sets no watermark past itself and is named on stderr. ``run --digest-now`` sends
today's digest whatever the hour, once per Tokyo date; ``run --kev-file PATH``
reads a synthetic KEV catalog instead of fetching (every post from it carries
SYNTHETIC TEST in its head line, and ``kev_since`` does not move).

After an unknown send, ``pending`` lists what is in flight and ``resolve <key>
--delivered <event id> | --not-delivered --reason <text>`` settles it, both under
the ledger lock: delivered records as a successful send would; not delivered
expires the pending entry (24 h after the attempt) so the next run sends again.

Every sent post also gets a Japanese ``lang: ja`` reply (docs/design.md "Post format"),
journaled as its own item ``<key>:ja`` once the original is recorded and sent after
every English send; its failure waits for the next run and never holds English work.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import time
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path
from zoneinfo import ZoneInfo

from aitools_alerts import schema
from aitools_alerts.poster import candidates, compose, inputs, ledger, rules, transport
from aitools_alerts.poster.inputs import Config, ConfigError
from aitools_alerts.poster.ledger import Ledger, LedgerError

TOKYO = ZoneInfo("Asia/Tokyo")
RANK = {"notice": 0, "high": 1, "critical": 2}
CHANNELS_FOR = {"critical": ("critical", "feed"), "high": ("feed",), "notice": ()}
MAX_DIGESTED = 5000
MAX_JA = 200  # Japanese replies waiting in the journal; past it the oldest unsent one is dropped
MAX_JA_BYTES = 4 * 1024 * 1024  # and their text as JSON-escaped: well inside load_state's 16 MiB
SUMMARY = ("candidates", "in_scope", "old", "roots", "copies", "replies", "held", "withheld",
           "busy", "digest", "failed", "unknown", "ja", "ja_failed")


class _Stop(Exception):
    """A send failed or its outcome is unknown: send nothing more this run."""


def _fold(ids) -> set[str]:
    return {i.casefold() for i in ids if isinstance(i, str)}


class Run:
    def __init__(self, now, config: Config, led: Ledger, state: dict, channels, ssh, http_status,
                 *, digest_now=False):
        self.now, self.config, self.led, self.state = now, config, led, state
        self.channels, self.ssh, self.http_status = channels, ssh, http_status
        self.digest_now = digest_now  # run --digest-now: today's digest whatever the hour
        self.n = Counter()
        self.deferred: dict[tuple, dict] = {}  # (scope, id) -> candidate dict, for the next run

    def save(self):
        inputs.save_state(self.config.state, self.state)

    # ------------------------------------------------------------ the journal

    def _item(self, kind, scope, ids, channel, text, *, key_id, adv=None, exploited=False, date=None,
              root=None, ja=None):
        """One journal item. ``root`` fixes a reply's or copy's thread at planning time, so a
        later alias bridge cannot move it to another thread. Raises ValueError (withheld)
        for a message the transport would refuse."""
        if not text or len(text) > transport.MAX_CONTENT or "\x00" in text:
            raise ValueError("message too large or not sendable")
        return {"key": f"{kind}:{scope}:{key_id}:{channel}", "kind": kind, "scope": scope,
                "ids": list(dict.fromkeys(ids)), "channel": channel, "text": text, "adv": adv,
                "exploited": exploited is True, "date": date, "sent": None, "root": root,
                **({"ja": ja} if ja else {})}  # no key without a body: the poster before rd8t loads it

    def _ja(self, fn, *a, **kw):
        """A Japanese body, or None: a Japanese failure never withholds the English post."""
        try:
            return fn(*a, **kw)
        except (ValueError, KeyError, TypeError):
            self.n["ja_failed"] += 1
            return None

    def drain(self):
        """Send every journaled item, oldest first; a pending one (and anything after it
        that shares its ids) waits for a human."""
        held_back: set[str] = set()
        for it in list(self.state["outbox"]):
            if it not in self.state["outbox"] or it["kind"] == "ja":
                continue  # dropped with a superseded root; Japanese replies go last (drain_ja)
            keys = _fold(it["ids"])
            if it["sent"] is None and (keys & held_back or self.led.pending_for(it["ids"])):
                held_back |= keys
                self.n["busy"] += 1
                continue
            self.deliver(it)

    def _drop(self, items):
        for it in items:
            if it in self.state["outbox"]:
                self.state["outbox"].remove(it)
        self.save()

    def deliver(self, it) -> bool:
        ja = it["kind"] == "ja"  # a Japanese reply: a failure ends only the Japanese sends
        if it["sent"] is None:
            if it["kind"] == "root" and self.led.lookup(it["ids"], scope=it["scope"]) is not None:
                # Its ids were widened into a known thread while it waited: never a second
                # thread. Drop it and its copies; the candidate is planned as known next run.
                self._drop([it] + [o for o in self.state["outbox"] if o["kind"] == "copy"
                                   and o["root"] is None and _fold(o["ids"]) & _fold(it["ids"])])
                self.n["withheld"] += 1
                return
            reply_to = it["root"] if ja else \
                self._entry(it).channel_ids.get(it["channel"]) if it["kind"] == "reply" else None
            if it["kind"] == "reply" and reply_to is None:
                raise LedgerError(f"{it['key']}: no root in {it['channel']}")
            try:  # every check the transport makes, before anything is marked pending
                transport.remote_argv(self.channels[it["channel"]], reply_to,
                                      wrapper=self.config.relay_send_wrapper)
            except (ValueError, KeyError):
                self._drop([it])
                self.n["ja_failed" if ja else "withheld"] += 1
                print(f"aitools-alerts-poster: {it['kind']} not sendable (bad channel or root id)",
                      file=sys.stderr)
                if ja:
                    return False
                raise _Stop from None
            self.led.pending(it["key"], [] if ja else it["ids"], now=self.now)  # ja: matches no advisory
            r = transport.send(self.channels[it["channel"]], it["text"], reply_to, ssh=self.ssh,
                               host=self.config.relay_ssh_host, wrapper=self.config.relay_send_wrapper)
            if r.outcome != "ok":
                if r.outcome == "failed":
                    self.led.clear_pending(it["key"])  # it certainly did not post: next hour
                    if ja:  # last in line, so one refused translation never holds the others
                        self.state["outbox"].remove(it)
                        self.state["outbox"].append(it)
                        self.save()
                self.n["ja_failed" if ja else r.outcome] += 1
                print(f"aitools-alerts-poster: {it['kind']} send {r.outcome} (exit {r.exit_code}): "
                      f"{r.stderr[-300:]}", file=sys.stderr)
                if ja:
                    return False
                raise _Stop
            it["sent"] = r.event_id
            self.save()  # the journal holds the id before the ledger records it
        if not ja:  # a Japanese reply has no thread record: the journal is its record
            self._record(it)
        if self.led.has_pending(it["key"]):  # while the sent item still exists to finish it
            self.led.clear_pending(it["key"])
        self.state["outbox"].remove(it)
        self._queue_ja(it)  # in the same save as the removal: a replay queues it once
        self.save()
        self.n[{"root": "roots", "copy": "copies", "reply": "replies", "digest": "digest", "ja": "ja"}[it["kind"]]] += 1
        return True

    def _queue_ja(self, it):
        """Journal a recorded item's Japanese reply, to this channel's root (of: names a reply)."""
        if not it.get("ja"):
            return
        target, of, key = it["sent"], None, it["key"] + ":ja"
        if it["kind"] == "reply":
            target, of, key = self._entry(it).channel_ids.get(it["channel"]), it["sent"], f"{key}:{it['sent']}"
        if any(o["key"] == key for o in self.state["outbox"]):
            return
        try:
            text = compose.lang_reply(it["ja"], of)
            if len(text) > transport.MAX_CONTENT or "\x00" in text or not transport._HEX64.fullmatch(target or ""):
                raise ValueError("message too large or not sendable")
        except ValueError:
            self.n["ja_failed"] += 1
            return
        def size(o):  # an upper bound on its JSON size (every character escaped)
            return len(json.dumps(o["text"], ensure_ascii=True))
        waiting = [o for o in self.state["outbox"] if o["kind"] == "ja"]
        # A backlog never grows the journal past its limit: drop the oldest unsent, unpending
        # item; when every one is in flight or sent, this translation is not journaled.
        while len(waiting) >= MAX_JA or sum(map(size, waiting)) + len(json.dumps(text)) > MAX_JA_BYTES:
            idle = [o for o in waiting if o["sent"] is None and not self.led.has_pending(o["key"])]
            drop = idle[0] if idle else None
            self.n["ja_failed"] += 1
            _say(f"ja backlog full: dropped {(drop or {'key': key})['key']}")
            if drop is None:
                return
            self.state["outbox"].remove(drop)
            waiting.remove(drop)
        self.state["outbox"].append({"key": key, "kind": "ja", "scope": it["scope"], "ids": [f"ja {key}"],
                                     "channel": it["channel"], "text": text, "adv": None,
                                     "exploited": False, "date": None, "sent": None, "root": target})

    def drain_ja(self):
        """Send the Japanese replies, oldest first; the first failure ends them, nothing else."""
        try:
            for it in [o for o in self.state["outbox"] if o["kind"] == "ja"]:
                if it["sent"] is None and self.led.has_pending(it["key"]):
                    self.n["busy"] += 1  # unknown outcome: `pending` / `resolve`, as for English
                    continue
                if not self.deliver(it):
                    return
        except Exception as e:  # noqa: BLE001 - nothing here may reach the run's exit code
            self.n["ja_failed"] += 1
            _say(f"ja replies stopped: {e}")


    def _entry(self, it):
        e = self.led.thread(it["root"]) if it["root"] else self.led.lookup(it["ids"], scope=it["scope"])
        if e is None:
            raise LedgerError(f"{it['key']}: no thread recorded")
        return e

    def _record(self, it):
        """Record a sent item in the ledger, idempotently (a replay after a crash)."""
        eid, ch = it["sent"], it["channel"]
        if it["kind"] == "root":
            e = self.led.lookup(it["ids"], scope=it["scope"])
            if e is not None and e.root_event_id != eid:
                raise LedgerError(f"{it['key']}: sent as {eid} but {e.root_event_id} holds these ids")
            if e is None:
                self.led.record_root(schema.validate(it["adv"]), eid, {ch: eid}, scope=it["scope"],
                                     exploited=it["exploited"], now=self.now, ids=it["ids"])
            for o in self.state["outbox"]:  # its copies now name this thread, never a lookup
                if o["kind"] == "copy" and o["root"] is None and o["scope"] == it["scope"] \
                        and _fold(o["ids"]) & _fold(it["ids"]):
                    o["root"] = eid
        elif it["kind"] == "copy":
            e = self._entry(it)
            if ch not in e.channel_ids:
                self.led.add_channel(e.root_event_id, ch, eid)
        elif it["kind"] == "reply":
            e = self._entry(it)
            if not any(r.get(ch) == eid for r in e.replies):
                self.led.record_reply(e.root_event_id, schema.validate(it["adv"]), {ch: eid},
                                      now=self.now, exploited=it["exploited"], ids=it["ids"])
        else:  # digest: acknowledge exactly the notices and ledger cutoff it was built from
            snap = set(it["adv"]["held"])
            keep = [h for h in self.state["held"] if not set(self._notice_keys(h["scope"], h["adv"])) <= snap]
            ids = self.state["digest_ids"]
            if eid not in ids:  # a replay after a crash records it once
                ids = (ids + [eid])[-inputs.MAX_DIGEST_IDS:]
            self.state.update(digest_date=it["date"], digest_at=it["adv"]["cutoff"],
                              digest_roots=it["adv"]["roots"], digest_ids=ids,
                              held=keep, digested=(self.state["digested"] + sorted(snap))[-MAX_DIGESTED:])
            _say(f"digest {it['date']} sent: {eid}")

    def busy(self, ids, scope) -> bool:
        """True when this advisory has journaled work or a send in flight. Its ids are
        learned by the overlapping items, so a later candidate under any of them waits too."""
        want = _fold(ids)
        hits = [it for it in self.state["outbox"]
                if it["kind"] != "ja" and it["scope"] == scope and _fold(it["ids"]) & want]
        for it in hits:
            it["ids"] = list(dict.fromkeys(it["ids"] + [i for i in ids if i.casefold() not in _fold(it["ids"])]))
        if hits:
            self.save()
        return bool(hits) or bool(self.led.pending_for(ids))

    def enqueue(self, items):
        self.state["outbox"].extend(items)
        self.save()
        for it in items:
            self.deliver(it)

    # ------------------------------------------------------------ planning

    def level(self, c, scope):
        level, reason = rules.level_for(c, scope, False)
        if reason == "unverified":  # only the clauses that need a primary source fetch one
            level, reason = rules.level_for(c, scope, rules.source_ok(c, self.http_status))
        return level, reason

    def defer(self, pairs):
        """Keep candidates for the next run: a source record can be replaced before then."""
        for c, scope in pairs:
            if self.is_synthetic(c):
                continue  # never kept: a later run would post it without its marker
            self.deferred[(scope.name, c.id.casefold())] = c.to_dict()

    @staticmethod
    def is_synthetic(c) -> bool:
        """A candidate whose primary id is a reserved synthetic id (compose.SYNTHETIC_ID)."""
        return compose.is_synthetic(c.id)

    def one(self, c, scope):
        ids = [c.id, *c.aliases]
        if self.busy(ids, scope.name):
            self.n["busy"] += 1
            self.defer([(c, scope)])  # its update (a fix, a promotion) is planned once the send resolves
            return
        level, reason = self.level(c, scope)
        entry = self.led.lookup(ids, scope=scope.name)
        if entry is not None and (self.is_synthetic(c) or compose.is_synthetic(entry.advisory.get("id"))):
            # A synthetic entry only ever starts a thread, and a synthetic thread takes no
            # update (copy or reply) from any input: plan_known would compose it unmarked.
            self.n["withheld"] += 1
            return
        try:
            items = self.plan_new(c, scope, level, reason, ids) if entry is None \
                else self.plan_known(c, scope, level, reason, ids, entry)
        except ValueError:  # compose refused something: the whole advisory is withheld
            self.n["withheld"] += 1
            return
        if items:
            self.enqueue(items)

    def plan_new(self, c, scope, level, reason, ids):
        test = self.is_synthetic(c)
        text, adv = compose.root_post(c, (level, reason), scope, posted_at=self.now)
        if level == "notice":
            if test:  # the digest would list it without its marker
                raise ValueError("a synthetic entry is never held for the digest")
            self.hold(scope.name, adv)
            return []
        chans = CHANNELS_FOR[level]
        ja = self._ja(compose.root_post_ja, adv, reason, compose.fix_unexpressed(c))
        return [self._item("root" if i == 0 else "copy", scope.name, ids, ch, text, key_id=c.id,
                           adv=asdict(adv), exploited=c.exploited, ja=ja)
                for i, ch in enumerate(chans)]

    @staticmethod
    def _notice_keys(scope, adv: dict) -> list[str]:
        return [f"{scope}|{i.casefold()}" for i in [adv.get("id"), *adv.get("aliases", [])] if isinstance(i, str)]

    def hold(self, scope, adv):
        a = asdict(adv)
        known = set(self.state["digested"])
        for h in self.state["held"]:
            known.update(self._notice_keys(h["scope"], h["adv"]))
        if known & set(self._notice_keys(scope, a)):
            return
        self.state["held"].append({"scope": scope, "adv": a})
        self.save()
        self.n["held"] += 1

    def plan_known(self, c, scope, level, reason, ids, entry):
        prev = schema.validate(entry.advisory)
        if RANK[level] <= RANK[entry.level]:  # a run never lowers a level; a curator does
            level, reason = entry.level, None
        was = prev.products[0]
        stored = _fold(entry.aliases)
        fresh = [i for i in dict.fromkeys(ids) if i.casefold() not in stored and i != prev.id]
        if fresh:  # identity is learned whether or not a reply can say so (the 50-alias cap)
            self.led.add_ids(entry.root_event_id, fresh)
        own_fix = compose.schema_fixed(c.fixed) is not None
        prev_ids = _fold([prev.id, *prev.aliases])
        prev_urls = {s.url for s in prev.sources}
        k = replace(  # the thread's identity and everything already known, plus what is new
            c, id=prev.id,
            aliases=tuple(prev.aliases) + tuple(i for i in dict.fromkeys(ids) if i.casefold() not in prev_ids),
            fixed=c.fixed if own_fix else was.fixed,
            affected=c.affected if compose.schema_affected(c.affected) else was.affected,
            sources=tuple(prev.sources) + tuple(s for s in c.sources if s.url not in prev_urls))
        text, new = compose.root_post(k, (level, reason), scope, posted_at=prev.posted_at)
        changes = {}
        if RANK[level] > RANK[prev.level]:
            changes.update(level=new.level, title=new.title)
        if new.products != prev.products:  # a fix, or a corrected range with or without one
            changes["products"] = new.products
        # Published aliases are compared with prev's, not with the ledger's full set, which
        # add_ids may already hold from a run that stopped before journaling the reply.
        unpublished = [i for i in dict.fromkeys(ids) if i.casefold() not in prev_ids]
        if unpublished and len(prev.aliases) < 50:
            changes["aliases"] = unpublished
        if any(s.url not in prev_urls for s in new.sources) and len(prev.sources) < 20:
            changes["sources"] = new.sources
        copies = [ch for ch in CHANNELS_FOR[level] if ch not in entry.channel_ids]
        ja = self._ja(compose.root_post_ja, new, reason, compose.fix_unexpressed(k)) if copies else None
        items = [self._item("copy", scope.name, ids, ch, text, key_id=prev.id, exploited=c.exploited,
                            root=entry.root_event_id, ja=ja)
                 for ch in copies]
        if changes:
            reply = compose.reply_post(prev, k, changes, reason=reason)
            merged = compose.parse_reply(reply, prev)
            if merged is None:
                raise ValueError("reply does not parse back")
            # The changed lines, then the whole current advisory: readers show the latest translation.
            ja = self._ja(lambda: compose.reply_post_ja(merged, k, json.loads(schema._last_block(reply)),
                          reason=reason) + "\n\n" + compose.root_post_ja(merged, reason, compose.fix_unexpressed(k)))
            items += [self._item("reply", scope.name, ids, ch, reply, key_id=prev.id,
                                 adv=asdict(merged), exploited=c.exploited, root=entry.root_event_id, ja=ja)
                      for ch in entry.channel_ids]
        return items

    def digest(self):
        local = _dt.datetime.fromtimestamp(self.now, TOKYO)
        today = local.date().isoformat()
        if self.state["digest_date"] == today:
            if self.digest_now:
                _say(f"digest for {today} already sent; --digest-now does nothing")
            return
        if local.hour < self.config.digest_hour and not self.digest_now:
            return
        if any(it["kind"] == "digest" for it in self.state["outbox"]):
            if self.digest_now:
                _say("a digest is journaled and waits to send; --digest-now does nothing")
            return  # today's (or an earlier) digest is journaled and drains first
        # Ledger posts oldest change first (so a backlog larger than one post moves forward
        # day by day), then held notices loudest first: (advisory, held entry, last_change).
        posted = [h for h in self.state["held"]  # a notice that has since posted is listed once, as posted
                  if self.led.lookup([h["adv"]["id"], *h["adv"]["aliases"]], scope=h["scope"]) is not None]
        led_items, held_items = [], []
        at, done = self.state["digest_at"], set(self.state["digest_roots"])
        for e in self.led.entries_since(at - 1):
            if e.last_change == at and e.root_event_id in done:
                continue  # listed by the last digest
            try:
                led_items.append((schema.validate(e.advisory), None, (e.last_change, e.root_event_id)))
            except ValueError:
                self.n["withheld"] += 1
        for h in self.state["held"]:
            if h not in posted:
                try:
                    held_items.append((schema.validate(h["adv"]), h, None))
                except ValueError:
                    self.n["withheld"] += 1
        led_items.sort(key=lambda x: x[2])
        held_items.sort(key=lambda x: (-RANK[x[0].level], -x[0].posted_at))
        items = led_items + held_items
        keep = len(items)
        while True:  # the largest prefix that fits one post; the rest waits for tomorrow
            try:
                text = compose.digest([x[0] for x in items[:keep]], local.date())
            except ValueError:
                self.n["withheld"] += 1
                return
            if len(text) <= transport.MAX_CONTENT or keep == 0:
                break
            keep //= 2
        taken = items[:keep]
        led_taken = [x[2] for x in taken if x[2] is not None]
        if len(led_taken) == len(led_items):
            cutoff, roots = self.now, []
        elif led_taken:  # acknowledged: every change up to the last one listed, by root at that time
            cutoff = led_taken[-1][0]
            roots = [r for t, r in led_taken if t == cutoff] + (sorted(done) if cutoff == at else [])
        else:
            cutoff, roots = at, sorted(done)
        snap = {"held": sorted({k for _, h, _ in taken if h is not None
                                for k in self._notice_keys(h["scope"], h["adv"])}),
                "cutoff": cutoff, "roots": roots}
        ja = self._ja(compose.digest, [x[0] for x in taken], local.date(), lang="ja")
        self.enqueue([self._item("digest", None, [f"digest:{today}"], "feed", text,
                                 key_id=today, adv=snap, date=today, ja=ja)])


def _observed(c) -> int | None:
    if not c.observed_at:
        return None
    try:
        t = _dt.datetime.fromisoformat(c.observed_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    if len(c.observed_at) == 10:  # a date only (KEV dateAdded): judged at its day's end, so an
        return int(t.timestamp()) + 86399  # entry added on the floor's own day is never "old"
    return int(t.timestamp())


def _utc_date(t: int) -> str:
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).date().isoformat()


def _real(got, counts: Counter):
    """Heartbeat and collector candidates never carry a reserved synthetic id: one whose
    primary id is reserved is dropped, a reserved alias is removed. Only KEV entries
    (which have no aliases) can be synthetic, so ledger.merge can never join a
    synthetic entry and a real one, in either order."""
    out = []
    for c in got:
        if compose.is_synthetic(c.id):
            counts["reserved synthetic id"] += 1
            continue
        out.append(replace(c, aliases=tuple(a for a in c.aliases if not compose.SYNTHETIC_ID.fullmatch(a))))
    return out


def _say(msg: str) -> None:
    print(f"aitools-alerts-poster: {msg}", file=sys.stderr)


def gather(config: Config, state: dict, now: int, kev_fetch, counts: Counter, kev_catalog=None):
    """(candidates, watermarks to set when the run succeeds, input status).

    A rejected input sets no watermark past itself, so the next run reads it again
    (re-reading is idempotent: ledger lookup and held-notice dedup). The status dict
    is the summary's ``inputs=`` field."""
    out, marks = [], {}
    status = {"kev": "unavailable", "collector": "off", "heartbeat": "off"}
    if config.heartbeat_runs is not None:
        dirs = inputs.heartbeat_dirs(config.heartbeat_runs, state["heartbeat"])
        ok, held = 0, False
        for d in dirs:
            got = candidates.from_heartbeat(d)
            counts.update(got.skipped)
            if got.rejected is not None:
                _say(f"heartbeat {d.name} rejected: {got.rejected}")
                held = True  # the mark stops before the first rejected dir
                continue
            ok += 1
            out += _real(got, counts)
            if not held:
                marks["heartbeat"] = d.name
        status["heartbeat"] = f"{ok}/{len(dirs)}"
    if config.collector_runs is not None:
        refused: list = []
        rec = inputs.collector_record(config.collector_runs, state["collector"], counts, refused)
        status["collector"] = "none"
        if refused:  # no mark: the record is read again unless a newer one supersedes it
            status["collector"] = "rejected"
            _say(f"collector {refused[0][0]} rejected: {refused[0][1]}")
        elif rec is not None:
            got = candidates.from_collector(rec[1])
            counts.update(got.skipped)
            if got.rejected is not None:
                status["collector"] = "rejected"
                _say(f"collector {rec[0]} rejected: {got.rejected}")
            else:
                status["collector"] = "ok"
                out += _real(got, counts)
                marks["collector"] = rec[0]
    # B1 c:6mnrdz: from_kev marks every entry exploited, so only the catalog this
    # run fetched from CISA (or the operator's --kev-file) reaches it, never the
    # heartbeat's feeds.json.
    if kev_catalog is not None:
        # Every entry of the file, whatever kev_since says; kev_since stays where it
        # is, since the real catalog was not read this run.
        got = candidates.from_kev(kev_catalog, "0001-01-01")
        counts.update(got.skipped)
        out += got
        status["kev"] = "file"
    else:
        catalog, status["kev"] = inputs.fetch_kev(config.kev_cache, kev_fetch)
        if catalog is None:
            _say("kev unavailable: fetch failed or the catalog was refused")
        else:
            # With no KEV watermark yet, the floor is the state's own (fixed at its first
            # run), so a KEV outage from the first run on loses no entries.
            got = candidates.from_kev(catalog, state["kev_since"] or _utc_date(state["since"]))
            counts.update(got.skipped)
            out += got
            marks["kev_since"] = _utc_date(now - 86400)
    return out, marks, status


def _inputs_field(status) -> str:
    if status is None:
        return "-"  # the run stopped before reading its inputs
    return ",".join(f"{k}:{status[k]}" for k in ("kev", "collector", "heartbeat"))


def run(now: int, config, *, ssh=None, kev_fetch=inputs.urllib_fetch,
        http_status=rules.http_status, channels: dict | None = None,
        digest_now: bool = False, kev_catalog: dict | None = None) -> tuple[int, str]:
    """One poster run. Returns (exit code, one-line summary). ``digest_now`` sends
    today's digest whatever the hour (once per date); ``kev_catalog`` replaces the
    KEV fetch with a synthetic catalog (``inputs.read_kev_file``)."""
    if not isinstance(config, Config):
        config = inputs.load_config(config)
    try:
        config.check_relay()  # before the ledger opens: a run without a route sends nothing
    except ConfigError as e:
        print(f"aitools-alerts-poster: config error: {e}", file=sys.stderr)
        return 2, "aitools-alerts-poster: " + " ".join(f"{k}=0" for k in SUMMARY) \
            + " inputs=- error=config"
    candidates.configure(config.strip_hosts, config.internal_host_suffixes)
    channels = channels or inputs.load_channels()
    n, code, err, status, skipped = Counter(), 0, None, None, Counter()
    try:
        with Ledger(config.ledger) as led:
            state = inputs.load_state(config.state, now, config.backfill_days)
            r = Run(now, config, led, state, channels, ssh, http_status, digest_now=digest_now)
            n = r.n
            merged, english_ok = None, False  # merged: set once the old deferred list is folded in
            try:
                cands, marks, status = gather(config, state, now, kev_fetch, skipped, kev_catalog)
                deferred = [inputs.candidate_from(d) for d in state["deferred"]]
                n["candidates"] = len(cands) + len(deferred)
                review, pairs, later = [], [], []
                for c in deferred:  # already past the backfill floor once
                    scope = rules.scope_of(c.product_text, log=review)  # a scope change can drop it
                    if scope is not None:
                        later.append((c, scope))
                for c in cands:
                    t = _observed(c)
                    if t is not None and t < state["since"] and not r.is_synthetic(c) \
                            and led.lookup([c.id, *c.aliases]) is None:
                        n["old"] += 1
                        continue
                    scope = rules.scope_of(c.product_text, log=review)
                    if scope is not None:
                        pairs.append((c, scope))
                pairs += later  # after the fresh ones: merge takes the first member's fix, so a correction wins
                n["in_scope"] = len(pairs)
                if review:
                    led.add_review(review, now=now)
                merged = ledger.merge(pairs, led)  # merge BEFORE level_for
                r.drain()
                for i, (c, scope) in enumerate(merged):
                    r.one(c, scope)
                    merged[i] = None  # planned (or deferred by one() itself)
                r.digest()
                state.update(marks)  # every send of this run succeeded; busy work is deferred
                english_ok = True
            except (_Stop, LedgerError) as e:
                code = 1
                if isinstance(e, LedgerError):
                    err = str(e)
                if merged is not None:
                    r.defer([p for p in merged if p is not None])  # unplanned: they wait in the state
            if merged is not None:
                state["deferred"] = list(r.deferred.values())  # replaces last run's list only now
            r.save()
            if english_ok:  # last, after marks and deferred are saved together
                r.drain_ja()  # a Japanese reply never delays or stops an English post
    except LedgerError as e:
        code, err = 1, str(e)
    except Exception as e:  # never die without the summary line
        code, err = 1, f"internal error: {type(e).__name__}: {e}"
    if skipped:
        _say("skipped: " + ", ".join(f"{k}={v}" for k, v in sorted(skipped.items())))
    summary = "aitools-alerts-poster: " + " ".join(f"{k}={n[k]}" for k in SUMMARY) \
        + " inputs=" + _inputs_field(status)
    if err:
        print(f"aitools-alerts-poster: {err}", file=sys.stderr)
        summary += " error=" + ("internal" if err.startswith("internal error") else "ledger")
    return code, summary


def _iso(t: int) -> str:
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pending(now: int, config) -> tuple[int, list[str]]:
    """Every send in flight with its journal item, under the ledger lock; never writes.
    Prints no post text: key, kind, channel, times and outcome only."""
    lines, n = [], Counter()
    try:
        with Ledger(config.ledger) as led:
            items = {it["key"]: it for it in inputs.load_state(config.state, now, config.backfill_days)["outbox"]}
            for p in led.pending_entries():
                it = items.get(p["key"])
                outcome = "no-journal-item" if it is None else f"sent:{it['sent']}" if it["sent"] else "unknown"
                n[{"no-journal-item": "orphan", "unknown": "unknown"}.get(outcome, "sent")] += 1
                lines.append(f"{p['key']} kind={it['kind'] if it else '-'} channel={it['channel'] if it else '-'} "
                             f"attempted_at={_iso(p['at'])} expires_at={_iso(p['at'] + ledger.PENDING_EXPIRY)} "
                             f"outcome={outcome}")
    except LedgerError as e:
        return 1, [f"aitools-alerts-poster: {e}"]
    except Exception as e:  # never a traceback: say what failed
        return 1, [f"aitools-alerts-poster: internal error: {type(e).__name__}: {e}"]
    total = n["unknown"] + n["sent"] + n["orphan"]
    lines.append(f"aitools-alerts-poster: pending={total} unknown={n['unknown']} sent={n['sent']} orphan={n['orphan']}")
    return 0, lines


def resolve(now: int, config, key: str, *, delivered: str | None = None,
            reason: str | None = None) -> tuple[int, list[str]]:
    """Settle one send whose outcome was unknown, under the ledger lock. ``delivered``:
    the post's event id, recorded exactly as a successful send records it (Run.deliver
    with ``sent`` set). Otherwise expire the pending entry (24 h rule) so it sends again.
    Returns 2, changing nothing, when the request cannot apply."""
    def refuse(msg):
        return 2, [f"aitools-alerts-poster: resolve {key}: {msg}"]
    if delivered is not None and not transport._HEX64.fullmatch(delivered):
        return refuse("event id must be 64 lowercase hex characters")
    if delivered is None and not (reason or "").strip():
        return refuse("--not-delivered needs a non-blank --reason")
    try:
        with Ledger(config.ledger) as led:
            p = next((p for p in led.pending_entries() if p["key"] == key), None)
            if p is None:
                return refuse("not pending")
            state = inputs.load_state(config.state, now, config.backfill_days)
            it = next((it for it in state["outbox"] if it["key"] == key), None)
            if delivered is not None:
                if it is None:
                    return refuse("no journal item to record")
                if it["sent"] not in (None, delivered):
                    return refuse(f"the journal already holds event id {it['sent']}")
                r = Run(now, config, led, state, {}, None, None)
                if it["sent"] is None:  # the checks _record makes, before anything is written
                    if led.has_event(delivered) or delivered in state["digest_ids"] \
                            or any(o["sent"] == delivered for o in state["outbox"]):  # journaled, unrecorded
                        return refuse("that event id is already recorded for another post")
                    if it["kind"] == "root":
                        e = led.lookup(it["ids"], scope=it["scope"])
                        if e is not None:
                            return refuse(f"thread {e.root_event_id} already holds these ids")
                    elif it["kind"] in ("copy", "reply"):
                        try:
                            r._entry(it)
                        except LedgerError:
                            return refuse("no thread recorded for it yet; resolve its root first")
                it["sent"] = delivered
                r.save()  # the journal holds the id before the ledger records it, as after a send
                r.deliver(it)
                return 0, [f"aitools-alerts-poster: resolved {key}: delivered as {delivered}, recorded"]
            if it is not None and it["sent"]:
                return refuse(f"the journal says it was delivered as {it['sent']}; use --delivered")
            if now - p["at"] < ledger.PENDING_EXPIRY:
                return refuse(f"pending under 24 hours; --not-delivered is allowed from "
                              f"{_iso(p['at'] + ledger.PENDING_EXPIRY)}")
            led.expire_pending(key, reason, now=now)
            return 0, [f"aitools-alerts-poster: resolved {key}: expired; the next run sends it again"]
    except LedgerError as e:
        return 1, [f"aitools-alerts-poster: {e}"]
    except Exception as e:  # never a traceback: say what failed
        return 1, [f"aitools-alerts-poster: internal error: {type(e).__name__}: {e}"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="aitools-alerts-poster",
                                description="Post ai-tools security alerts to the relay (hourly).")
    sub = p.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("run", help="one poster run")
    rp.add_argument("--config", type=Path, default=inputs.DEFAULT_CONFIG)
    rp.add_argument("--digest-now", action="store_true",
                    help="send today's digest (Asia/Tokyo) now, whatever the hour; once per date")
    rp.add_argument("--kev-file", type=Path, metavar="PATH",
                    help="read KEV from this local file instead of fetching (synthetic checks: "
                         "every entry must say SYNTHETIC TEST, and every post from it is marked so)")
    pp = sub.add_parser("pending", help="list sends in flight (outcome unknown); no post text")
    pp.add_argument("--config", type=Path, default=inputs.DEFAULT_CONFIG)
    sp = sub.add_parser("resolve", help="settle one unknown send after checking the channel")
    sp.add_argument("key", help="a key printed by 'pending'")
    sp.add_argument("--config", type=Path, default=inputs.DEFAULT_CONFIG)
    how = sp.add_mutually_exclusive_group(required=True)
    how.add_argument("--delivered", metavar="EVENT_ID", help="it posted: record it, never resend")
    how.add_argument("--not-delivered", action="store_true",
                     help="it did not post: send it again on the next run (24 h after the attempt)")
    sp.add_argument("--reason", help="why it is known not delivered (required with --not-delivered)")
    a = p.parse_args(argv)
    if a.cmd in ("pending", "resolve"):
        try:
            cfg = inputs.load_config(a.config)
        except ConfigError as e:
            print(f"aitools-alerts-poster: config error: {e}", file=sys.stderr)
            return 2
        if a.cmd == "pending":
            code, lines = pending(int(time.time()), cfg)
        else:
            code, lines = resolve(int(time.time()), cfg, a.key, delivered=a.delivered, reason=a.reason)
        print("\n".join(lines), file=sys.stdout if code == 0 else sys.stderr)
        return code
    try:
        cfg = inputs.load_config(a.config)
        cfg.check_relay()
        channels = inputs.load_channels()
        kev_catalog = inputs.read_kev_file(a.kev_file) if a.kev_file is not None else None
    except ConfigError as e:
        print(f"aitools-alerts-poster: config error: {e}", file=sys.stderr)
        return 2
    code, summary = run(int(time.time()), cfg, channels=channels, digest_now=a.digest_now,
                        kev_catalog=kev_catalog)
    print(summary)
    return code


if __name__ == "__main__":
    sys.exit(main())
