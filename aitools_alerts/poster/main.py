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
"""

from __future__ import annotations

import argparse
import datetime as _dt
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
SUMMARY = ("candidates", "in_scope", "old", "roots", "copies", "replies", "held", "withheld",
           "busy", "digest", "failed", "unknown")


class _Stop(Exception):
    """A send failed or its outcome is unknown: send nothing more this run."""


def _fold(ids) -> set[str]:
    return {i.casefold() for i in ids if isinstance(i, str)}


class Run:
    def __init__(self, now, config: Config, led: Ledger, state: dict, channels, ssh, http_status):
        self.now, self.config, self.led, self.state = now, config, led, state
        self.channels, self.ssh, self.http_status = channels, ssh, http_status
        self.n = Counter()

    def save(self):
        inputs.save_state(self.config.state, self.state)

    # ------------------------------------------------------------ the journal

    def _item(self, kind, scope, ids, channel, text, *, key_id, adv=None, exploited=False, date=None):
        return {"key": f"{kind}:{scope}:{key_id}:{channel}", "kind": kind, "scope": scope,
                "ids": list(dict.fromkeys(ids)), "channel": channel, "text": text, "adv": adv,
                "exploited": exploited is True, "date": date, "sent": None}

    def drain(self):
        """Send every journaled item, oldest first; a pending one (and anything after it
        that shares its ids) waits for a human."""
        held_back: set[str] = set()
        for it in list(self.state["outbox"]):
            keys = _fold(it["ids"])
            if keys & held_back or (it["sent"] is None and self.led.pending_for(it["ids"])):
                held_back |= keys
                self.n["busy"] += 1
                continue
            self.deliver(it)

    def deliver(self, it):
        if it["sent"] is None:
            reply_to = self._entry(it).channel_ids.get(it["channel"]) if it["kind"] == "reply" else None
            if it["kind"] == "reply" and reply_to is None:
                raise LedgerError(f"{it['key']}: no root in {it['channel']}")
            self.led.pending(it["key"], it["ids"], now=self.now)
            r = transport.send(self.channels[it["channel"]], it["text"], reply_to, ssh=self.ssh)
            if r.outcome != "ok":
                if r.outcome == "failed":
                    self.led.clear_pending(it["key"])  # it certainly did not post: next hour
                self.n[r.outcome] += 1
                print(f"aitools-alerts-poster: {it['kind']} send {r.outcome} (exit {r.exit_code}): "
                      f"{r.stderr[-300:]}", file=sys.stderr)
                raise _Stop
            it["sent"] = r.event_id
            self.save()  # the journal holds the id before the ledger records it
        self._record(it)
        if self.led.has_pending(it["key"]):  # while the sent item still exists to finish it
            self.led.clear_pending(it["key"])
        self.state["outbox"].remove(it)
        self.save()
        self.n[{"root": "roots", "copy": "copies", "reply": "replies", "digest": "digest"}[it["kind"]]] += 1

    def _entry(self, it):
        e = self.led.lookup(it["ids"], scope=it["scope"])
        if e is None:
            raise LedgerError(f"{it['key']}: no thread recorded")
        return e

    def _record(self, it):
        """Record a sent item in the ledger, idempotently (a replay after a crash)."""
        eid, ch = it["sent"], it["channel"]
        if it["kind"] == "root":
            if self.led.lookup(it["ids"], scope=it["scope"]) is None:
                self.led.record_root(schema.validate(it["adv"]), eid, {ch: eid}, scope=it["scope"],
                                     exploited=it["exploited"], now=self.now, ids=it["ids"])
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
            self.state.update(digest_date=it["date"], digest_at=max(self.state["digest_at"], it["adv"]["cutoff"]),
                              held=keep, digested=(self.state["digested"] + sorted(snap))[-MAX_DIGESTED:])

    def busy(self, ids, scope) -> bool:
        """True when this advisory has journaled work or a send in flight. Its ids are
        learned by the overlapping items, so a later candidate under any of them waits too."""
        want = _fold(ids)
        hits = [it for it in self.state["outbox"]
                if it["scope"] == scope and _fold(it["ids"]) & want]
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

    def one(self, c, scope):
        ids = [c.id, *c.aliases]
        if self.busy(ids, scope.name):
            self.n["busy"] += 1
            return
        level, reason = self.level(c, scope)
        entry = self.led.lookup(ids, scope=scope.name)
        try:
            items = self.plan_new(c, scope, level, reason, ids) if entry is None \
                else self.plan_known(c, scope, level, reason, ids, entry)
        except ValueError:  # compose refused something: the whole advisory is withheld
            self.n["withheld"] += 1
            return
        if items:
            self.enqueue(items)

    def plan_new(self, c, scope, level, reason, ids):
        text, adv = compose.root_post(c, (level, reason), scope, posted_at=self.now)
        if level == "notice":
            self.hold(scope.name, adv)
            return []
        chans = CHANNELS_FOR[level]
        return [self._item("root" if i == 0 else "copy", scope.name, ids, ch, text, key_id=c.id,
                           adv=asdict(adv), exploited=c.exploited)
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
        items = [self._item("copy", scope.name, ids, ch, text, key_id=prev.id, exploited=c.exploited)
                 for ch in CHANNELS_FOR[level] if ch not in entry.channel_ids]
        if changes:
            reply = compose.reply_post(prev, k, changes, reason=reason)
            merged = compose.parse_reply(reply, prev)
            if merged is None:
                raise ValueError("reply does not parse back")
            items += [self._item("reply", scope.name, ids, ch, reply, key_id=prev.id,
                                 adv=asdict(merged), exploited=c.exploited)
                      for ch in entry.channel_ids]
        return items

    def digest(self):
        local = _dt.datetime.fromtimestamp(self.now, TOKYO)
        today = local.date().isoformat()
        if local.hour < self.config.digest_hour or self.state["digest_date"] == today:
            return
        if any(it["kind"] == "digest" for it in self.state["outbox"]):
            return  # today's (or an earlier) digest is journaled and drains first
        advs = []
        for raw in [h["adv"] for h in self.state["held"]] + \
                   [e.advisory for e in self.led.entries_since(self.state["digest_at"])]:
            try:
                advs.append(schema.validate(raw))
            except ValueError:
                self.n["withheld"] += 1
        try:
            text = compose.digest(advs, local.date())
        except ValueError:
            self.n["withheld"] += 1
            return
        snap = {"held": sorted({k for h in self.state["held"] for k in self._notice_keys(h["scope"], h["adv"])}),
                "cutoff": self.now}
        self.enqueue([self._item("digest", None, [f"digest:{today}"], "feed", text,
                                 key_id=today, adv=snap, date=today)])


def _observed(c) -> int | None:
    if not c.observed_at:
        return None
    try:
        t = _dt.datetime.fromisoformat(c.observed_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    return int(t.timestamp())


def _utc_date(t: int) -> str:
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).date().isoformat()


def gather(config: Config, state: dict, now: int, kev_fetch, counts: Counter):
    """(candidates, watermarks to set when the run succeeds)."""
    out, marks = [], {}
    if config.heartbeat_runs is not None:
        dirs = inputs.heartbeat_dirs(config.heartbeat_runs, state["heartbeat"])
        for d in dirs:
            got = candidates.from_heartbeat(d)
            counts.update(got.skipped)
            out += got
        if dirs:
            marks["heartbeat"] = dirs[-1].name
    if config.collector_runs is not None:
        rec = inputs.collector_record(config.collector_runs, state["collector"], counts)
        if rec is not None:
            got = candidates.from_collector(rec[1])
            counts.update(got.skipped)
            out += got
            marks["collector"] = rec[0]
    # B1 c:6mnrdz: from_kev marks every entry exploited, so only the catalog this
    # run fetched from CISA reaches it, never the heartbeat's feeds.json.
    catalog = inputs.load_kev(config.kev_cache, kev_fetch)
    if catalog is None:
        counts["kev unavailable"] += 1
    else:
        got = candidates.from_kev(catalog, state["kev_since"] or _utc_date(now - config.backfill_days * 86400))
        counts.update(got.skipped)
        out += got
        marks["kev_since"] = _utc_date(now - 86400)
    return out, marks


def run(now: int, config, *, ssh=None, kev_fetch=inputs.urllib_fetch,
        http_status=rules.http_status, channels: dict | None = None) -> tuple[int, str]:
    """One poster run. Returns (exit code, one-line summary)."""
    if not isinstance(config, Config):
        config = inputs.load_config(config)
    channels = channels or inputs.load_channels()
    n, code, err = Counter(), 0, None
    try:
        with Ledger(config.ledger) as led:
            state = inputs.load_state(config.state, now, config.backfill_days)
            r = Run(now, config, led, state, channels, ssh, http_status)
            n = r.n
            try:
                r.drain()
                cands, marks = gather(config, state, now, kev_fetch, Counter())
                n["candidates"] = len(cands)
                review, pairs = [], []
                for c in cands:
                    t = _observed(c)
                    if t is not None and t < state["since"] and led.lookup([c.id, *c.aliases]) is None:
                        n["old"] += 1
                        continue
                    scope = rules.scope_of(c.product_text, log=review)
                    if scope is not None:
                        pairs.append((c, scope))
                n["in_scope"] = len(pairs)
                if review:
                    led.add_review(review, now=now)
                for c, scope in ledger.merge(pairs, led):  # merge BEFORE level_for
                    r.one(c, scope)
                r.digest()
                if not r.n["busy"]:  # a busy candidate is read again once its send resolves
                    state.update(marks)  # and every send of this run succeeded
                r.save()
            except _Stop:
                code = 1
    except LedgerError as e:
        code, err = 1, str(e)
    summary = "aitools-alerts-poster: " + " ".join(f"{k}={n[k]}" for k in SUMMARY)
    if err:
        print(f"aitools-alerts-poster: {err}", file=sys.stderr)
        summary += " error=ledger"
    return code, summary


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="aitools-alerts-poster",
                                description="Post ai-tools security alerts to the relay (hourly).")
    sub = p.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("run", help="one poster run")
    rp.add_argument("--config", type=Path, default=inputs.DEFAULT_CONFIG)
    a = p.parse_args(argv)
    try:
        cfg = inputs.load_config(a.config)
        channels = inputs.load_channels()
    except ConfigError as e:
        print(f"aitools-alerts-poster: config error: {e}", file=sys.stderr)
        return 2
    code, summary = run(int(time.time()), cfg, channels=channels)
    print(summary)
    return code


if __name__ == "__main__":
    sys.exit(main())
