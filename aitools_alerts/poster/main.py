"""``aitools-alerts-poster``: the hourly run that turns watch output into relay posts.

A run drains the journal left by earlier runs, then reads candidates (heartbeat
run dirs newer than the watermark, the newest validated collector record, the
CISA KEV catalog this run fetched itself), keeps those in scope that an authoritative
source confirms (``Run.admit``), merges them per scope, rates them and plans their messages: a new critical posts to ``critical``
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

A ``refused`` send never stops the run (a second one does): it waits in ``withheld`` (``pending``) for ``resolve``.

Every sent post also gets a Japanese ``lang: ja`` reply (docs/design.md "Post format"),
journaled as its own item ``<key>:ja`` once the original is recorded and sent after
every English send; its failure waits for the next run and never holds English work.

Every run also recomputes the level of each open thread the ledger marks exploited
from the KEV catalog it read (``recompute``, ai-tools-alerts#ny5g): a raise posts at
once; a lowering needs the same lower level held through 24 hours of complete reads
and seven days without a level change on the thread, and is a level-only reply
(``compose.level_post``) in each of its channels. A catalog that could not be read
lowers nothing, and neither does what a cut one lacks. The next digest lists what
was lowered in one line.

With spec/catalog-channel.json present, every in-scope advisory (each ledger thread
whose product starts at its level, and each held notice) is also posted, whole, as a
root to the catalog channel when it differs from what was last posted there
(``catalog``, ai-tools-alerts#q03f). What is in scope is read in memory under the
ledger lock, before the digest; the catalog's files and sends come after the lock is
released and the checkpoint is signed, at most 20 sends a run, and never reach the
exit code or the checkpoint.

With ``translate_curator`` on, a curator's post or amendment read from the mirror gets
a machine translation (``translate``), journaled as ``curator:<event id>:<channel>:ja``
after the English work of the run is saved. A 401/403 holds it until
``translate-clear-hold``; nothing in that pass reaches the exit code.
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
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from aitools_alerts import TRUST_ROOT_PUBKEY, check, manifest, pull, ruleset, schema, versions
from aitools_alerts.poster import (candidates, catalog, compose, inputs, ledger, recompute, rules, signer, translate,
                                   wording,
                                   transport)
from aitools_alerts.poster.inputs import Config, ConfigError
from aitools_alerts.poster.ledger import Ledger, LedgerError
from aitools_alerts.state import State

TOKYO = ZoneInfo("Asia/Tokyo")
RANK = {"notice": 0, "high": 1, "critical": 2}
CHANNELS_FOR = {"critical": ("critical", "feed"), "high": ("feed",), "notice": ()}
MAX_DIGESTED = 5000
HOLD_SECONDS = 6 * 3600  # 0dvh: a high with no fix and no range waits this long from first sight
AGE_LIMIT = 7 * 86400  # 0dvh: a primary source older than this at first sight posts no root
MAX_JA = 200  # Japanese replies waiting in the journal; past it the oldest unsent one is dropped
MAX_JA_BYTES = 4 * 1024 * 1024  # and their text as JSON-escaped: well inside load_state's 16 MiB
SUMMARY = ("candidates", "in_scope", "old", "roots", "copies", "replies", "held", "withheld",
           "busy", "digest", "digest_held", "failed", "unknown", "ja", "ja_failed", "untranslated", "translate_failed", "waiting", "aged", "out")
MAX_TRIES = 3  # failed calls (network, 5xx) before an event counts as untranslated
PASS_DEADLINE = 300  # seconds of curator translation per run (the ledger lock is held)
WORDING_CALLS = 4  # model calls for headlines a run (c6ak): roots are high or critical, about one a day
WORDING_SECONDS = 60  # no wording call starts after this many seconds of them in a run
MAX_RUN_PAGES = 40  # authoritative pages fetched per run; a candidate past it waits for the next
RETRY_DAYS = 7  # a candidate whose source could not be fetched is tried again this long
_LEVEL_LINE = ("level: high", "level: notice")


class _Stop(Exception):
    """A send failed or its outcome is unknown: send nothing more this run."""


def _block(text):
    """The advisory a journaled copy carries, as a dict (a copy keeps no ``adv``)."""
    adv = schema.parse_post(text) if isinstance(text, str) else None
    return asdict(adv) if adv is not None else None


def _complete(adv) -> bool:
    """False for a journaled critical whose block holds no complete action (9kgk): no
    upgrade while its product states a fixed version, and no stop_using. A stop_using in
    the journal was written by level_for under this rule, which a reading gave."""
    if not isinstance(adv, dict) or adv.get("level") != "critical":
        return True
    prods, acts = adv.get("products") or [{}], adv.get("actions") or []
    fixed = prods[0].get("fixed") if isinstance(prods[0], dict) else None
    return any(isinstance(a, dict) and (a.get("verb") == "stop_using" or a.get("verb") == "upgrade" and fixed)
               for a in acts)


def _fold(ids) -> set[str]:
    return {i.casefold() for i in ids if isinstance(i, str)}


class Run:
    def __init__(self, now, config: Config, led: Ledger, state: dict, channels, send, page,
                 *, digest_now=False, skipped: Counter | None = None, wording_call=None):
        self.now, self.config, self.led, self.state = now, config, led, state
        # c6ak: the wording call (None: read the key at the first root to word), its use
        # this run, and the summary's wording= status ("off" unless model_wording is on).
        self._wcall, self._wasked, self._wspent = wording_call, 0, 0.0
        self.key_refused = False  # the API refused the key this run: no call of either kind follows
        self.w_status = "ok" if config.model_wording else "off"
        if isinstance(state.get("held"), list):  # wa6n: an out product's saved notice is never digested
            state["held"] = [h for h in state["held"] if h.get("scope") not in rules.out_names()]
        # send(channel_id, text, reply_to) -> transport.SendResult (transport.Relay.send)
        self.channels, self.send, self.fetch_page = channels, send, page
        self.skipped = Counter() if skipped is None else skipped
        self.pages: dict[str, tuple] = {}  # url -> (status, body), one fetch a run
        self.confirmed: dict[str, set] = {}  # url -> the advisory ids its page confirmed
        self.digest_now = digest_now  # run --digest-now: today's digest whatever the hour
        self.n = Counter()
        self.deferred: dict[tuple, dict] = {}  # (scope, id) -> candidate dict, for the next run
        self.groups: dict[tuple, list] = {}  # faxq: (scope, id) -> a fix group's members (ledger.merge)

    def save(self):
        inputs.save_state(self.config.state, self.state)

    @property
    def rc(self) -> dict:
        """The recompute's own state (``recompute.load``), read once a run."""
        if getattr(self, "_rc", None) is None:
            self._rc, replaced = recompute.load(self.config.recompute_state)
            if replaced:
                _say(f"recompute state {self.config.recompute_state} unreadable; every wait before a lowering starts over")
        return self._rc

    def save_rc(self):
        try:
            recompute.save(self.config.recompute_state, self.rc)
        except (OSError, TypeError, ValueError) as e:  # as the journal: a state that cannot be written stops the run
            raise LedgerError(f"cannot write recompute state {self.config.recompute_state}: {e}") from None

    # ------------------------------------------------------------ the journal

    def _item(self, kind, scope, ids, channel, text, *, key_id, adv=None, exploited=False, date=None,
              root=None, ja=None, source_title=None, floor=None):
        """One journal item. ``root`` fixes a reply's or copy's thread at planning time, so a
        later alias bridge cannot move it to another thread. Raises ValueError (withheld)
        for a message the transport would refuse."""
        if not text or len(text) > transport.MAX_CONTENT or "\x00" in text:
            raise ValueError("message too large or not sendable")
        return {"key": f"{kind}:{scope}:{key_id}:{channel}", "kind": kind, "scope": scope,
                "ids": list(dict.fromkeys(ids)), "channel": channel, "text": text, "adv": adv,
                "exploited": exploited is True, "date": date, "sent": None, "root": root,
                **({"ja": ja} if ja else {}),  # no key without a body: the poster before rd8t loads it
                **({"source_title": source_title} if source_title else {}),
                **({"floor": floor} if floor else {})}  # ny5g: a root's prose floor, for the ledger

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
            if not _complete(it.get("adv") or _block(it["text"])) and (
                    it["kind"] in ("root", "copy") or self._entry(it).level != "critical"):
                # 9kgk: a critical journaled before this rule (no fix, no action) never posts, nor
                # does a reply that would raise a thread to one; a reply on a thread already
                # critical keeps its standing level, which a run never lowers (h29n does);
                # the candidate is planned again from its sources next run. Its copies go too.
                self._drop([it] + [o for o in self.state["outbox"] if o["kind"] == "copy"
                                   and o["root"] is None and _fold(o["ids"]) & _fold(it["ids"])])
                self.n["withheld"] += 1
                return
            reply_to = it["root"] if ja else \
                self._entry(it).channel_ids.get(it["channel"]) if it["kind"] == "reply" else None
            if it["kind"] == "reply" and reply_to is None:
                raise LedgerError(f"{it['key']}: no root in {it['channel']}")
            try:  # every check the transport makes, before anything is marked pending
                transport.check_send(self.channels[it["channel"]], it["text"], reply_to)
            except (ValueError, KeyError):
                self._drop([it])
                self.n["ja_failed" if ja else "withheld"] += 1
                print(f"aitools-alerts-poster: {it['kind']} not sendable (bad channel or root id)",
                      file=sys.stderr)
                if ja:
                    return False
                raise _Stop from None
            self.led.pending(it["key"], [] if ja else it["ids"], now=self.now)  # ja: matches no advisory
            r = self.send(self.channels[it["channel"]], it["text"], reply_to)
            if r.outcome == "refused":  # never sent again unchanged; the run goes on
                self._withhold(it, r.message)  # saved before the mark clears: a crash between holds it
                self.led.clear_pending(it["key"])
                self.n["refused"] += not ja
                if self.n["refused"] > 1:  # a relay refusing everything stops the run as before
                    raise _Stop
                return True
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
        self._owe(it)  # here, so a replay of an item whose send was journaled records it too
        if not ja:  # a Japanese reply has no thread record: the journal is its record
            self._record(it)
        if self.led.has_pending(it["key"]):  # while the sent item still exists to finish it
            self.led.clear_pending(it["key"])
        self.state["outbox"].remove(it)
        self._queue_ja(it)  # in the same save as the removal: a replay queues it once
        self.save()
        self.n[{"root": "roots", "copy": "copies", "reply": "replies", "digest": "digest", "ja": "ja"}[it["kind"]]] += 1
        return True

    def _owe(self, it):
        """The relay acknowledged this post: every checkpoint owes it until the mirror
        shows it (signer.record_sent), written now, before the journal lets the item go."""
        if self.config.checkpoint_key_file is None or it.get("sent") is None:
            return
        root = it.get("root") if it["kind"] == "ja" else None
        if it["kind"] == "reply":  # the root it replied to in ITS channel (a critical has one per channel)
            e = self.led.lookup(it["ids"], scope=it.get("scope"))
            root = (getattr(e, "channel_ids", {}).get(it["channel"]) if e is not None else None) or it.get("root")
        try:
            signer.record_sent(self.config.owed_state, it["sent"], len(it["text"].encode("utf-8")), root, self.now)
        except OSError as e:  # a debt that cannot be written down must stop the run, not be forgotten
            self.owe_failed = True  # and this run signs no checkpoint: it would omit the post
            raise LedgerError(f"checkpoint state {self.config.owed_state}: {e.strerror or e}") from None

    def _withhold(self, it, message):  # a refused item, with a root's copies that need it, leaves the journal
        group = [it] + [o for o in self.state["outbox"] if it["kind"] == "root" and o["kind"] == "copy"
                        and o["root"] is None and o["scope"] == it["scope"] and _fold(o["ids"]) & _fold(it["ids"])]
        for o in group:
            self.state["outbox"].remove(o)
        keep = it["kind"] != "ja" and len(json.dumps(group + self._withheld_items())) <= MAX_JA_BYTES  # else dropped
        if keep:  # a Japanese reply never grows the list; neither does one past the backlog bound
            self.state["withheld"].append({"key": it["key"], "items": group, "message": message, "at": self.now})
        self.save()
        self.n["ja_failed" if it["kind"] == "ja" else "withheld"] += 1
        _say(f"{it['key']} refused by the relay, {'withheld' if keep else 'dropped'}: {message}")

    def _withheld_items(self):
        return [o for w in self.state["withheld"] for o in w["items"]]

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
        except ValueError:
            self.n["ja_failed"] += 1
            return
        self._journal_ja(key, it["scope"], it["channel"], text, target)

    def _journal_ja(self, key, scope, channel, text, target) -> bool:
        """Append one Japanese reply to the journal, inside the backlog bound (not saved here)."""
        if len(text) > transport.MAX_CONTENT or "\x00" in text or not transport._HEX64.fullmatch(target or ""):
            self.n["ja_failed"] += 1
            return False
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
                return False
            self.state["outbox"].remove(drop)
            waiting.remove(drop)
        self.state["outbox"].append({"key": key, "kind": "ja", "scope": scope, "ids": [f"ja {key}"],
                                     "channel": channel, "text": text, "adv": None,
                                     "exploited": False, "date": None, "sent": None, "root": target})
        return True

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

    # ------------------------------------------------------------ curator translation

    def curator_events(self, fetch=None, root=TRUST_ROOT_PUBKEY, done=(), start=None):
        """(event, root id, of, channel) for each curator root or amendment in the mirror,
        oldest first, from after the backfill floor. None when the mirror cannot be read."""
        try:
            st = State.load(self.config.mirror_dir)
            if translate.bounded(lambda: pull.fetch(self.config.translate_mirror_url, st, fetch=fetch,
                                                    root_pubkey=root, now=self.now, checkpoint=False), 120).error is not None:
                return None
        except (translate.CallError, ValueError, OSError):  # a timeout, an unreadable mirror state
            return None
        m, evs = st.manifest, st.events
        names = {self.channels[c]: c for c in ("feed", "critical")}  # the journal takes no other channel
        self.mirror_ids, out = set(evs), []
        # What the bot has already translated, (thread root, of), so a lost translate file never reposts.
        posted = {(pull._thread_ref(e), tr[1]) for e in evs.values()
                  if manifest.role_of(m, e["pubkey"]) == "relay-bot"
                  and (tr := pull.parse_translation(e["content"])) is not None and tr[0] == "ja"}
        replays, start = 0, time.monotonic() if start is None else start
        for ev in sorted(evs.values(), key=lambda e: (e["created_at"], e["id"])):
            if replays >= 2 * translate.DAILY_CALLS or time.monotonic() - start > PASS_DEADLINE:
                break  # more cannot be translated today anyway; the lock is never held long
            h = [t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "h"]
            if (manifest.role_of(m, ev["pubkey"]) != "curator" or ev["created_at"] < self.state["since"]
                    or len(h) != 1 or h[0] not in names):
                continue
            ref = pull._thread_ref(ev)
            if ev["id"] in done or ((ref or ev["id"]), None if ref is None else ev["id"]) in posted:
                continue
            if ref is None and pull._is_root(ev) and schema.parse_post(ev["content"]) is not None:
                out.append((ev, ev["id"], None, names[h[0]], None))
            elif ref in evs and (pull._first_line(ev["content"]) in _LEVEL_LINE or pull._patch(ev["content"]) is not None):
                # An amendment's text says what changed, then the whole advisory as amended
                # (readers show the root's translation and every change's, in order).
                upto, replays = (ev["created_at"], ev["id"]), replays + 1
                t = next((t for t in pull.threads_from([e for e in evs.values()
                                                        if (e["created_at"], e["id"]) <= upto], m)
                          if t.root_id == ref and not t.retracted), None)
                if t is not None:
                    out.append((ev, ref, ev["id"], names[h[0]], t.adv))
            if len(out) >= 2 * translate.DAILY_CALLS:
                break
        return out

    def translate_curator(self, fetch=None, call=None, read_key=translate.read_key, root=TRUST_ROOT_PUBKEY):
        """Translate new curator events; returns the summary's translate= status. Each call
        is counted (20 a UTC day) and its outcome cached by event id before anything is sent."""
        if not self.config.translate_curator:
            return "off"
        path = self.config.translate_state
        try:
            tr = _translate_state(path)
        except (OSError, ValueError, RecursionError):
            _say(f"translate state {path} unreadable; translating nothing")
            return "state-error"
        if tr["hold"] is not None or self.key_refused:  # c6ak: a wording 401/403 this run holds it too
            return "held"
        start = time.monotonic()  # the pass deadline covers the mirror and the replay too
        evs = self.curator_events(fetch, root, {k for k, v in tr["done"].items() if v in ("ok", "untranslated")}, start)
        if evs is None:
            return "mirror-error"
        today, memo = _utc_date(self.now), {}
        tr["done"] = {k: v for k, v in tr["done"].items() if k in self.mirror_ids}  # bounded by the mirror
        journaled = {o["key"] for o in self.state["outbox"]}
        recovered = [e for e in evs if f"curator:{e[0]['id']}:{e[3]}:ja" in journaled]
        for e in recovered:  # journaled by a run that stopped before recording it: record it
            tr["done"][e[0]["id"]] = "ok"  # now, before any early return lets drain_ja drop the item
        if recovered:
            inputs.write_json(path, tr)
        evs = [e for e in evs if e not in recovered]
        if call is None:  # the key is read once, only when there is something to translate
            if not evs or (tr["day"] == _utc_date(self.now) and tr["calls"] >= translate.DAILY_CALLS):
                return "ok"
            try:
                call = translate.api_call(read_key(self.config.secrets_helper))
            except translate.CallError as e:  # a local problem: never charged to an event
                _say(f"translation skipped: {e}")
                return "key-error"
        if tr["day"] != today:
            tr.update(day=today, calls=0)
        for ev, target, of, channel, adv in evs:
            key = f"curator:{ev['id']}:{channel}:ja"
            if tr["done"].get(ev["id"]) in ("ok", "untranslated"):
                continue
            text = ev["content"].split("\n```" + schema.INFO_STRING)[0].strip()
            if adv is not None:
                text += "\n\n" + _advisory_text(adv)
            if len(text) > translate.MAX_SOURCE:
                memo[text] = None  # untranslated without a call, never charged to the budget
            if text not in memo:
                if tr["calls"] >= translate.DAILY_CALLS or time.monotonic() - start > PASS_DEADLINE:
                    break
                try:
                    tr["calls"] += 1
                    inputs.write_json(path, tr)  # counted before the call: a crash never re-spends it
                    memo[text] = translate.translate(text, call=call)
                except translate.AuthError as e:
                    tr["hold"] = {"at": self.now, "why": str(e)}
                    inputs.write_json(path, tr)
                    _say(f"translation held: the API refused the key ({e}); "
                         "a human clears it with: aitools-alerts-poster translate-clear-hold")
                    return "held"
                except translate.CallError as e:
                    self.n["translate_failed"] += 1
                    tries = tr["done"].get(ev["id"], 0) + 1
                    tr["done"][ev["id"]] = tries if tries < MAX_TRIES else "untranslated"
                    self.n["untranslated"] += tries >= MAX_TRIES
                    inputs.write_json(path, tr)
                    _say(f"translation failed: {e}")
                    break  # a service failure: the next run tries again
            ok = False
            if memo[text] is not None:
                try:
                    safe = compose.mention_safe(memo[text])  # the relay refuses a bare @token
                    if safe is None:
                        raise ValueError("a mention that cannot be put in inline code safely")
                    body = safe + "\n\n" + translate.MARK
                    if len(body) > pull.MAX_TRANSLATION_CHARS:  # readers would cut the end off
                        raise ValueError("translation too long")
                    reply = compose.lang_reply(body, of)
                    ok = self._journal_ja(key, None, channel, reply, target)
                except ValueError:
                    pass
            if not ok:
                self.n["untranslated"] += 1
            tr["done"][ev["id"]] = "ok" if ok else "untranslated"
            self.save()  # the journal first: a crash before the next write is reconciled above
            inputs.write_json(path, tr)
        return "ok"

    def wording(self, c, scope, level, reason):
        """The model's headline and Who line for a root post (c6ak), or None: the post
        then keeps the source title. Nothing here reaches planning: any failure turns
        wording off for the run and the post goes out as it would have. The key read and
        the calls share one budget of WORDING_SECONDS a run, so wording delays a run's
        posts by at most that."""
        if self.w_status != "ok" or level == "notice" or self.is_synthetic(c) or not wording.usable(c) \
                or self._wasked >= WORDING_CALLS or self._wspent >= WORDING_SECONDS:
            return None
        start = time.monotonic()
        try:
            path = self.config.translate_state
            # The translate hold: the same key, refused once, is not tried again. A state the
            # translation pass would refuse is refused here too, and never rewritten.
            if _translate_state(path)["hold"] is not None:
                self.w_status = "held"
                return None
            if self._wcall is None:
                try:
                    self._wcall = translate.api_call(translate.read_key(self.config.secrets_helper))
                except translate.CallError as e:  # never retried this run; its message carries no key
                    self.w_status = "key-error"
                    _say(f"wording off for this run: {e}")
                    return None
            left = WORDING_SECONDS - self._wspent - (time.monotonic() - start)
            if left <= 1:
                return None
            self._wasked += 1
            self.n["word_asked"] += 1
            call = self._wcall
            try:
                w, outcome = wording.draft(c, scope, call=lambda s, t: translate.bounded(lambda: call(s, t), left))
            except translate.AuthError as e:
                self.w_status, self.key_refused = "held", True  # first, in memory: nothing calls again this run
                _say(f"wording held: the API refused the key ({e}); posts keep the source title; "
                     "a human clears it with: aitools-alerts-poster translate-clear-hold")
                tr = _translate_state(path)
                tr["hold"] = {"at": self.now, "why": f"wording: {e}"}
                inputs.write_json(path, tr)
                return None
            if w is not None and not compose.worded(compose.head_of(level, c.id, reason), scope.name, w):
                w, outcome = None, "refused"  # a model line is never cut
            self.n["worded" if w else "word_" + outcome] += 1
            return w
        except Exception as e:  # noqa: BLE001 - the post never waits on, or fails by, its wording
            if self.w_status == "ok":
                self.w_status = "error"
            _say(f"wording off for this run: {type(e).__name__}")
            return None
        finally:
            self._wspent += time.monotonic() - start

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
                                     exploited=it["exploited"], now=self.now, ids=it["ids"],
                                     source_title=it.get("source_title"), floor=it.get("floor"))
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
                adv = schema.validate(it["adv"])
                m = candidates.BOT_ID.fullmatch(adv.id)
                low = [m.group(1) if m else adv.id, adv.level]
                if RANK[adv.level] < RANK[e.level]:  # ny5g: a lowering, recorded for its first channel
                    if low not in self.rc["lowered"]:  # for the digest; once, though a replay comes here again
                        self.rc["lowered"] = (self.rc["lowered"] + [low])[-recompute.MAX_LOWERED:]
                    recompute.note(self.rc, e.root_event_id, self.now)  # the breaker counts what was sent, once
                    self.save_rc()
                self.led.record_reply(e.root_event_id, adv, {ch: eid},
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
        want, root = _fold(ids), getattr(self.led.lookup(ids, scope=scope), "root_event_id", None)
        hits = [it for it in self.state["outbox"] + self._withheld_items()  # withheld: waits for a human
                if it["kind"] != "ja" and it["scope"] == scope and (_fold(it["ids"]) & want or root and it["root"] == root)]
        for it in hits:
            it["ids"] = list(dict.fromkeys(it["ids"] + [i for i in ids if i.casefold() not in _fold(it["ids"])]))
        if hits:
            self.save()
        return bool(hits) or bool(self.led.pending_for(ids))

    def enqueue(self, items):
        self.state["outbox"].extend(items)
        self.save()
        for it in items:
            if it in self.state["outbox"]:  # not withheld with a refused root
                self.deliver(it)

    # ------------------------------------------------------------ planning

    def page(self, url, allow):
        """One fetch per URL per run, MAX_RUN_PAGES in all (the ledger lock is held)."""
        if url not in self.pages:
            if len(self.pages) >= MAX_RUN_PAGES:
                raise rules.PageBudget
            self.pages[url] = self.fetch_page(url, allow, rules.FETCH_TIMEOUT)
        return self.pages[url]

    def admit(self, c, scope):
        """c as an authoritative source states it, or None (h340). The candidate is a
        pointer (an id, a product, URLs); what goes on to the merge, a level, the held
        list and a post is what ``rules.evidence`` read from CISA's catalog or from the
        vendor's own page: the ids that source assigns, its fixed version, range, title
        and severity word, and as sources only the page that confirmed it, CISA's for a
        KEV entry and the global page of the vendor's own GHSA. A record's own severity
        text and model-read flags count only when a repository advisory page confirmed
        it and the record cites nothing else; a vendor site page alone makes a notice. Nothing confirmed and a fetch failed, a page did not parse or
        the page budget ran out: deferred to the next run, never dropped for that."""
        if not candidates.BOT_ID.fullmatch(c.id):
            self.skipped["id shape"] += 1
            return None
        ev = rules.evidence(c, scope, self.page)
        if not ev.ok:
            if ev.retry:
                self.skipped["advisory page not parsed, deferred" if ev.unparsed
                             else "page budget, deferred" if ev.budget else "source fetch failed, deferred"] += 1
                self.defer([(c, scope)])
                self.saw(scope.name, c.id)  # dmmf: first sight is now, not when a page answers
            else:  # the second: harvest it for a package key the scope file lacks
                self.skipped["vendor page names another package" if ev.other_package
                             else "no authoritative source"] += 1
            return None
        if ev.url is not None:
            self.confirmed.setdefault(ev.url, set()).update(ev.ids)
        known = _fold([c.id])
        aliases = []
        for a in [*c.aliases, *sorted(i.upper() if i.startswith("cve-") else "GHSA" + i[4:] for i in ev.ids)]:
            m = candidates.BOT_ID.fullmatch(a)
            if m and m.group(1).lower() in ev.ids and a.casefold() not in known \
                    and not compose.SYNTHETIC_ID.fullmatch(m.group(1)):  # reserved: never an alias (_real)
                known.add(a.casefold())
                aliases.append(a)

        def kind(url):
            parts, host = urlsplit(url), rules.host_of(url)
            if url == ev.url:  # the page that confirmed it: no other vendor-host URL is taken on trust
                return 0
            if ev.kev and host == "cisa.gov" and schema.is_primary(url):
                return 2
            if host == "github.com" and schema.is_primary(url) and parts.path.lower().rstrip("/") in {
                    f"/advisories/{i}" for i in ev.ids if i.startswith("ghsa-")}:
                return 3  # the global page of the vendor's own advisory
            return None

        kept = sorted((s for s in c.sources if kind(s.url) is not None), key=lambda s: kind(s.url))
        # A record's own level inputs count only when the vendor's advisory page bound the id
        # to the product by its fields and the record cites nothing but what is kept here.
        trusted = ev.structured and len(kept) == len(c.sources)
        title = candidates._title(ev.title, candidates._Hosts(candidates.FLEET_HOSTS)) if ev.title \
            else c.source_title if ev.kev else None
        severity = "; ".join(x for x in (ev.severity, title if ev.url else None) if x) or None
        text = candidates._title(ev.text, candidates._Hosts(candidates.FLEET_HOSTS), candidates.MAX_SOURCE_TEXT) \
            if ev.url and ev.text else c.source_text if ev.kev else None  # c6ak: wording only
        return replace(c, aliases=tuple(aliases), fixed=ev.fixed, affected=ev.affected, sources=tuple(kept),
                       source_title=title, source_text=text,
                       severity_word=ev.severity,  # dmmf: the page's word, alone
                       readings=rules.readings_for(c, ev),  # s6mt: what the level can rest on, as fields
                       advisory_severity=severity or (c.advisory_severity if trusted else None),
                       trojanized=c.trojanized is True and trusted, injection_exec=c.injection_exec is True and trusted)

    def level(self, c, scope):
        """``source_ok`` is "a page confirmed this advisory this run": KEV alone never
        verifies the trojanized or injection clause."""
        ids = rules.advisory_ids(c)
        return rules.level_for(c, scope, any(self.confirmed.get(s.url, set()) & ids for s in c.sources))

    def defer(self, pairs):
        """Keep candidates for the next run: a source record can be replaced before then."""
        for c, scope in pairs:
            if self.is_synthetic(c):
                continue  # never kept: a later run would post it without its marker
            # faxq: a fix group is kept as its members, each re-admitted alone next run
            # (admit keeps only the ids the primary's own page assigns), then grouped again.
            for m in self.groups.get((scope.name, c.id.casefold()), [c]):  # merge keys former names too
                self.deferred[(scope.name, m.id.casefold())] = m.to_dict()

    @staticmethod
    def is_synthetic_id(i) -> bool:
        return compose.is_synthetic(i)

    @staticmethod
    def is_synthetic(c) -> bool:
        """A candidate whose primary id is a reserved synthetic id (compose.SYNTHETIC_ID)."""
        return compose.is_synthetic(c.id)

    def _former(self, scope, ids):
        """wa6n: the scope under the product's earlier name when that name holds this
        advisory's thread or journaled work; else ``scope``. The update then keeps the
        thread's name, as the reply check requires, and no second root starts. Anything
        not yet posted keeps the current name, the one a member's installation matches."""
        if self.led.lookup(ids, scope=scope.name) is not None:
            return scope
        keys = _fold(ids)
        journal = [it for it in self.state["outbox"] + self._withheld_items() if it["kind"] != "ja"]
        for old in getattr(scope, "formerly", ()):
            if self.led.lookup(ids, scope=old) is not None \
                    or any(it["scope"] == old and _fold(it["ids"]) & keys for it in journal):
                return replace(scope, name=old, formerly=())
        return scope

    def _noticed_formerly(self, scope, ids) -> bool:
        """wa6n: a notice for these ids is held, or was digested, under a former name."""
        keys = _fold(ids)
        return any(self._held_for(old, ids) is not None or any(f"{old}|{k}" in self.state["digested"] for k in keys)
                   for old in getattr(scope, "formerly", ()))

    def one(self, c, scope):
        ids = [c.id, *c.aliases]
        scope = self._former(scope, ids)
        if self.busy(ids, scope.name):
            self.n["busy"] += 1
            self.defer([(c, scope)])  # its update (a fix, a promotion) is planned once the send resolves
            return
        entry = self.led.lookup(ids, scope=scope.name)
        if entry is not None and entry.lowered and c.exploited is True \
                and not any(r[0] == "kev" for r in c.readings):
            # ny5g: on a lowered thread the recompute holds the KEV level. A mark that no
            # KEV entry read this run stands behind (lent by the ledger when candidates were
            # merged, before the journal drained, or kept in the state file) raises nothing.
            c = replace(c, exploited=False)
        level, reason = self.level(c, scope)
        # 9kgk: a fix the thread already states counts as this candidate's (plan_known keeps it)
        was = (entry.advisory.get("products") or [{}])[0].get("fixed") if entry is not None else None
        known_fix = c.fixed if compose.schema_fixed(c.fixed) is not None else was
        # ny5g: what readings of prose alone give it, kept by the ledger at its highest: a
        # reading never justifies a lowering, so the recompute never goes below this.
        rs = ruleset.load()
        floor = rules._prose_level(replace(c, exploited=False, fixed=known_fix), scope,
                                   any(self.confirmed.get(s.url, set()) & rules.advisory_ids(c) for s in c.sources), rs)[0]
        if entry is not None:
            self.led.learn_floor(entry.root_event_id, rs.highest(floor, recompute.floor(entry, rs)))
        if entry is not None and reason in ("no-action", "stop-using") and compose.schema_fixed(c.fixed) is None:
            # 9kgk: the thread already states a fix, which plan_known keeps; the upgrade is complete.
            if compose.schema_fixed(was):
                level, reason = self.level(replace(c, fixed=was), scope)
        if entry is None and not rules.starts(scope, level):  # wa6n: out of the community service
            self.n["out"] += 1
            return
        if entry is None and level == "notice" and self._noticed_formerly(scope, ids):
            return  # wa6n: held or listed under its earlier name already; once is enough
        if entry is not None and (self.is_synthetic(c) or compose.is_synthetic(entry.advisory.get("id"))):
            # A synthetic entry only ever starts a thread, and a synthetic thread takes no
            # update (copy or reply) from any input: plan_known would compose it unmarked.
            self.n["withheld"] += 1
            return
        try:
            items = self.plan_new(c, scope, level, reason, ids, floor) if entry is None \
                else self.plan_known(c, scope, level, reason, ids, entry)
        except ValueError:  # compose refused something: the whole advisory is withheld
            self.n["withheld"] += 1
            return
        if items:
            self.enqueue(items)
            if any(it in self._withheld_items() for it in items):  # waits for resolve; after --drop, planned anew
                self.defer([(c, scope)])

    def _held_for(self, scope, ids) -> dict | None:
        keys = set(self._notice_keys(scope, {"id": ids[0], "aliases": ids[1:]}))
        return next((h for h in self.state["held"]
                     if h["scope"] == scope and keys & set(self._notice_keys(scope, h["adv"]))), None)

    def _seen_key(self, scope, ids, default) -> str:
        """The ``waiting`` key already recorded under any of the ids, else ``default``."""
        w = self.state["waiting"]
        return next((k for k in (f"{scope}|{i.casefold()}" for i in ids) if k in w), default)

    def saw(self, scope, cid) -> None:
        """Record first sight for a candidate deferred before it could be judged (a page
        not read), while the map is under half full, as for a notice: the age limit and
        the hold then count from this run, not from the run that reads the page (dmmf).
        Keyed by the primary id alone: the record's aliases are not yet confirmed, and
        one claiming another advisory's id must not borrow or block that one's entry."""
        w = self.state["waiting"]
        key = f"{scope}|{cid.casefold()}"
        if not self.is_synthetic_id(cid) and key not in w and len(w) < inputs.MAX_WAITING // 2:
            w[key] = self.now

    def first_seen(self, scope, ids, held=None) -> int:
        """When the state first saw the candidate under any of its ids (``waiting``: a high
        waiting for its fix, or a notice in its first AGE_LIMIT; a held notice's stamp), else now."""
        w = self.state["waiting"]
        seen = [w[k] for k in (f"{scope}|{i.casefold()}" for i in ids) if k in w]
        return min(seen + ([held["adv"]["posted_at"]] if held else []) + [self.now])

    def plan_new(self, c, scope, level, reason, ids, floor=None):
        test = self.is_synthetic(c)
        held = self._held_for(scope.name, ids)
        seen = self.first_seen(scope.name, ids, held)
        published = _published(c.sources) or (_published(schema.validate(h["adv"]).sources) if (h := held) else None)
        w, key = self.state["waiting"], self._seen_key(scope.name, ids, f"{scope.name}|{c.id.casefold()}")
        # A KEV entry is exempt: the day CISA lists it is the news, whatever the advisory's age.
        if level != "notice" and not test and c.exploited is not True and published is not None \
                and seen - published > AGE_LIMIT:
            level = "notice"  # 0dvh: old news when first seen goes to the digest, never a root
            self.n["aged"] += 1
            if not rules.starts(scope, level):  # wa6n: an out product's old news goes nowhere
                return []
        elif level == "high" and not test and c.exploited is not True and not _stated(c.fixed) \
                and not _stated(c.affected) and self.now - seen < HOLD_SECONDS \
                and (key in w or len(w) < inputs.MAX_WAITING):
            # 0dvh: wait for the fix or the range; the deferred candidate is planned again
            # next run, merged with any new sighting, and posts with what is known at the end.
            # A full map holds nothing new: the candidate posts now, as before 0dvh.
            w[key] = min(seen, w.get(key, seen))
            self.defer([(c, scope)])
            if c.to_dict() not in self.state["deferred"]:  # on disk with its time: a crash keeps it
                self.state["deferred"].append(c.to_dict())
            self.save()
            self.n["waiting"] += 1
            return []
        if level == "notice" and not test and key not in w and len(w) < inputs.MAX_WAITING // 2:
            w[key] = seen  # first sight outlives the digest that lists it, for AGE_LIMIT (0dvh)
        w = self.wording(c, scope, level, reason)  # c6ak: None for a notice, which posts no root
        text, adv = compose.root_post(c, (level, reason), scope, posted_at=self.now, wording=w)
        title = compose.source_title(c)
        if level == "notice":
            if test:  # the digest would list it without its marker
                raise ValueError("a synthetic entry is never held for the digest")
            self.hold(scope.name, adv, title)
            return []
        chans = CHANNELS_FOR[level]
        ja = self._ja(compose.root_post_ja, adv, reason, compose.fix_unexpressed(c), title,
                      exploited=c.exploited is True, range_unexpressed=compose.range_unexpressed(c),
                      package=compose.package_of(scope), wording=w)
        return [self._item("root" if i == 0 else "copy", scope.name, ids, ch, text, key_id=c.id,
                           adv=asdict(adv), exploited=c.exploited, ja=ja,
                           source_title=title if i == 0 else None, floor=floor if i == 0 else None)
                for i, ch in enumerate(chans)]

    @staticmethod
    def _notice_keys(scope, adv: dict) -> list[str]:
        return [f"{scope}|{i.casefold()}" for i in [adv.get("id"), *adv.get("aliases", [])] if isinstance(i, str)]

    def hold(self, scope, adv, title=None):
        a = asdict(adv)
        known = set(self.state["digested"])
        for h in self.state["held"]:
            known.update(self._notice_keys(h["scope"], h["adv"]))
        if known & set(self._notice_keys(scope, a)):
            for h in self.state["held"]:
                if h["scope"] != scope or not set(self._notice_keys(scope, h["adv"])) & set(self._notice_keys(scope, a)):
                    continue
                if title and not h.get("source_title"):  # a title learned while held reaches the digest
                    h["source_title"] = title
                    self.save()
                was_src = schema.validate(h["adv"]).sources
                if _published(was_src) is None and _published(adv.sources) is not None:
                    # dmmf: a publication date learned while held stays, so a later undated
                    # sighting is still judged by it (the age limit never forgets a date).
                    h["adv"] = {**h["adv"], "sources": [asdict(s) for s in compose._sources([*adv.sources, *was_src])]}
                    self.save()
                new, was = a["products"][0], h["adv"]["products"][0]
                got = {**was, **{k: new[k] for k in ("fixed", "affected") if new[k]}}
                if got != was:  # 0dvh: a fix or range read later reaches the digest; none is lost
                    h["adv"] = {**h["adv"], "products": [got], "actions": [
                        {"verb": "upgrade", "target": got["name"], "value": got["fixed"]}] if got["fixed"] else []}
                    self.save()
                if compose.listable(adv) and not compose.listable(schema.validate(h["adv"])):
                    # 8ke5: a primary source learned while held: the digest lists that, under
                    # every id either sighting knew (digested and retracted match by them).
                    # 0dvh: the merged fix and range and the first sight's stamp stay.
                    old = [h["adv"]["id"], *h["adv"]["aliases"]]
                    h["adv"] = {**a, "aliases": compose._ids([*a["aliases"], *old], a["id"])[:50],
                                **{k: h["adv"][k] for k in ("products", "actions", "posted_at")}}
                    self.save()
                ids = compose._ids([*h["adv"]["aliases"], a["id"], *a["aliases"]], h["adv"]["id"])[:50]
                if ids != h["adv"]["aliases"]:  # faxq: a fix group's new members are listed with it,
                    p = dict(h["adv"]["products"][0])  # under a range that covers them too
                    if p["affected"] != a["products"][0]["affected"]:
                        p["affected"] = None if None in (p["affected"], a["products"][0]["affected"]) \
                            or not p["fixed"] else f"<{p['fixed']}"
                    h["adv"] = {**h["adv"], "aliases": ids, "products": [p]}
                    self.save()
            # Members, not ids: an id new to a listed advisory (a CVE assigned later) is not news.
            fresh = [i for m in self.groups.get((scope, a["id"].casefold()), ())
                     if not any(f"{scope}|{k.casefold()}" in known for k in (m.id, *m.aliases))
                     for i in compose._ids([m.id, *m.aliases], None)]
            fresh = list(dict.fromkeys(fresh))
            if fresh and not any(h["scope"] == scope and set(self._notice_keys(scope, h["adv"]))
                                 & set(self._notice_keys(scope, a)) for h in self.state["held"]):
                # faxq: a fix group met a member a digest already listed: the members it has
                # not listed are held under their own ids, so each is listed once.
                old = compose.public_form(a["id"])
                a = {**a, "id": fresh[0], "aliases": fresh[1:50],
                     "title": a["title"].replace(f"({old})", f"({fresh[0]})")}
                self.state["held"].append({"scope": scope, "adv": a, **({"source_title": title} if title else {})})
                self.save()
                self.n["held"] += 1
            return
        self.state["held"].append({"scope": scope, "adv": a, **({"source_title": title} if title else {})})
        self.save()
        self.n["held"] += 1

    def plan_known(self, c, scope, level, reason, ids, entry):
        prev = schema.validate(entry.advisory)
        if level == "critical" and entry.level != "critical" and (
                reason == "stop-using" or not compose.schema_fixed(entry.fix_at_root)):
            # 9kgk: a reply cannot add stop_using, and a fix a reply adds where the root had
            # none is held by every reader (tyje): the member would hold a critical with no
            # version. A thread is raised to critical only when its root stated the fix.
            level, reason = ruleset.load().action_cap, "no-action"
        if RANK[level] <= RANK[entry.level]:  # a run never lowers a level; a curator does
            level, reason = entry.level, None
        was = prev.products[0]
        stored = _fold(entry.aliases)
        fresh = [i for i in dict.fromkeys(ids) if i.casefold() not in stored and i != prev.id]
        if fresh:  # identity is learned whether or not a reply can say so (the 50-alias cap)
            self.led.add_ids(entry.root_event_id, fresh)
        title = compose.source_title(c)
        if title and not entry.source_title:  # learned late: the digest carries it; no reply says it
            self.led.learn_title(entry.root_event_id, title)
        own_fix = compose.schema_fixed(c.fixed) is not None
        older = versions.parse(compose.schema_fixed(c.fixed)), versions.parse(was.fixed)
        if own_fix and None not in older and older[0] < older[1]:
            # faxq: a member of a fix group sighted again says its own, older fix; the thread
            # keeps the later one, which fixes every member. A run never lowers a fix.
            own_fix = False
        prev_ids = _fold([prev.id, *prev.aliases])
        prev_urls = {s.url for s in prev.sources}
        # Ids and sources learned by earlier runs that posted nothing (8ke5) come along.
        # (h340: learned before the gate, or by it; only the product's own sources are ever listed.)
        learned = [schema.Source(x["url"], x.get("published_at")) for x in entry.learned_sources or ()
                   if rules.authoritative(x["url"], scope)]
        seen_urls = set(prev_urls)
        extra = []
        for s in [*learned, *c.sources]:
            if s.url not in seen_urls:
                seen_urls.add(s.url)
                extra.append(s)
        unpublished = [i for i in dict.fromkeys([*ids, *entry.aliases])
                       if i.casefold() not in prev_ids and compose.public_id(i)]
        k = replace(  # the thread's identity and everything already known, plus what is new
            c, id=prev.id, aliases=tuple(prev.aliases) + tuple(unpublished),
            fixed=c.fixed if own_fix else was.fixed,
            # a range the schema cannot say is kept raw when none is known: no "not stated" (0dvh)
            # faxq: one member's sighting never narrows a fix group's range, which covers them
            # all; a range that differs widens it to everything before the fix
            affected=_group_range(was, c, c.fixed if own_fix else was.fixed) if compose.covers(prev)[0] not in (0, 1)
            else c.affected if compose.schema_affected(c.affected) else (was.affected or c.affected),
            sources=tuple(prev.sources) + tuple(extra),
            source_title=compose.source_title(c) or entry.source_title)  # faxq: a copy's headline
        text, new = compose.root_post(k, (level, reason), scope, posted_at=prev.posted_at)
        changes = {}
        if RANK[level] > RANK[prev.level]:
            changes.update(level=new.level, title=new.title)
        if new.products != prev.products:  # a fix, or a corrected range with or without one
            changes["products"] = new.products
        # Published aliases are compared with prev's, not with the ledger's full set, which
        # add_ids may already hold from a run that stopped before journaling the reply.
        if unpublished and len(prev.aliases) < 50:
            changes["aliases"] = unpublished
        if any(s.url not in prev_urls for s in new.sources) and len(prev.sources) < 20:
            changes["sources"] = new.sources
        if changes and set(changes) <= {"aliases", "sources"} and not (c.exploited is True and not entry.exploited):
            # 8ke5: no reply says only "New sources listed." or "Also known as": the ids
            # are learned above, the sources here, and the next real reply carries both.
            # Exploitation learned at the same level still replies (design section 5;
            # its Japanese action turns urgent, 4yr1).
            self.led.learn_sources(entry.root_event_id, compose._sources(extra))  # publishable ones only
            changes = {}
        if changes and new.advisory_severity not in (None, prev.advisory_severity):
            changes["advisory_severity"] = new.advisory_severity  # 0dvh: never a reply on its own
        copies = [ch for ch in CHANNELS_FOR[level] if ch not in entry.channel_ids]
        w = self.wording(k, scope, level, reason) if copies else None  # c6ak: a copy is a post
        if w is not None:
            text = compose.root_post(k, (level, reason), scope, posted_at=prev.posted_at, wording=w)[0]
        ja = self._ja(compose.root_post_ja, new, reason, compose.fix_unexpressed(k), title or entry.source_title,
                      exploited=k.exploited is True, range_unexpressed=compose.range_unexpressed(k),
                      package=compose.package_of(scope), wording=w) if copies else None
        items = [self._item("copy", scope.name, ids, ch, text, key_id=prev.id, exploited=c.exploited,
                            root=entry.root_event_id, ja=ja)
                 for ch in copies]
        if changes and entry.lowered and "level" in changes:
            # ny5g, spec/wire.md rule 2: on a thread that has had a lowering a level change
            # travels alone; whatever else this run learned follows in a reply without it.
            items += self._level_items(entry, changes.pop("level"))
            prev = replace(prev, level=level)
            if changes.get("title") == prev.title:  # it came with the level; unchanged, it is no reply
                del changes["title"]
            if set(changes) <= {"aliases", "sources", "advisory_severity"}:
                # 8ke5 and 0dvh again, now that the level has gone its own way: ids, sources
                # and a severity word alone make no reply; the sources wait for the next one.
                self.led.learn_sources(entry.root_event_id, compose._sources(extra))
                changes = {}
        if changes:
            reply = compose.reply_post(prev, k, changes, reason=reason, lowered=bool(entry.lowered))
            merged = compose.parse_reply(reply, prev)
            if merged is None:
                raise ValueError("reply does not parse back")
            # The changed lines, then the whole current advisory: readers show the latest translation.
            ja = self._ja(lambda: compose.reply_post_ja(merged, k, json.loads(schema._last_block(reply)),
                          reason=reason) + "\n\n" + compose.root_post_ja(merged, reason, compose.fix_unexpressed(k),
                                                          title or entry.source_title,
                                                          exploited=k.exploited is True,
                                                          range_unexpressed=compose.range_unexpressed(k),
                                                          package=compose.package_of(scope)))
            items += [self._item("reply", scope.name, ids, ch, reply, key_id=prev.id,
                                 adv=asdict(merged), exploited=c.exploited, root=entry.root_event_id, ja=ja)
                      for ch in entry.channel_ids]
        return items

    def _level_items(self, entry, level):
        """A level change and nothing else (``compose.level_post``), one reply for each
        channel the thread has a root in. No Japanese copy: the digest reports it."""
        prev = schema.validate(entry.advisory)
        text = compose.level_post(prev, level)
        return [self._item("reply", entry.scope, entry.aliases, ch, text, key_id=f"{prev.id}#level",
                           adv=asdict(replace(prev, level=level)), exploited=entry.exploited,
                           root=entry.root_event_id) for ch in entry.channel_ids]

    def drop_unsent_lowerings(self):
        """Before the journal drains: a lowering no channel has yet is not sent on the
        evidence of an earlier run. It leaves the journal, and this run sends it again
        only if a complete read still supports it (its wait is kept). One a channel
        already has stays, whatever this run reads: the thread's channels must agree. A
        channel has it when the relay acknowledged it (journaled as sent, though the
        ledger may not say so yet: a run that stopped between the two), when its outcome
        is unknown, or when the ledger already holds the lower level."""
        level_items = [it for it in self.state["outbox"] if it["kind"] == "reply" and "#level:" in it["key"]]
        had = {it["root"] for it in level_items if it["sent"] is not None or self.led.has_pending(it["key"])}
        gone = []
        for it in level_items:
            e = self.led.thread(it["root"])
            if it["root"] not in had and (e is None or RANK[it["adv"]["level"]] < RANK[e.level]):
                gone.append(it)
        if gone:
            self._drop(gone)

    def observe(self, kev_out: dict):
        """Judge every open thread the ledger marks exploited against this run's KEV
        copy, and save what that does to each wait, before anything is sent (ny5g). A
        run that then stops at a failed send has still recorded what it read: an unknown
        read has broken the wait, another level has started it over. What the verdicts
        send is ``recompute``'s, later in the run. Also settles the digest report of a
        run that stopped between journaling the digest and clearing the list."""
        st, rs = self.rc, ruleset.load()
        if st["reported"] is not None:
            journaled = any(it["kind"] == "digest" and it["date"] == st["reported"]
                            for it in self.state["outbox"] + self._withheld_items())
            if journaled or self.state["digest_date"] == st["reported"]:
                st["lowered"] = []  # that digest carries them
            st["reported"] = None
        copy = self.copy = recompute.kev_copy(kev_out.get("catalog"), kev_out.get("status"), st, self.now,
                                              kev_out.get("redirected"))
        if copy is not None and copy.version and not copy.complete:
            _say("kev copy is not complete (a redirect, its count, fewer entries than 98% of the largest read, "
                 "or a version older than the latest read): its absences lower nothing")
        self.drop_unsent_lowerings()  # first: what it removes no longer makes its thread busy
        entries = [e for e in self.led.entries() if not compose.is_synthetic(e.advisory.get("id"))]
        self.observed = {e.root_event_id for e in entries}
        for k in ("dwell", "listed"):
            st[k] = {r: v for r, v in st[k].items() if r in self.observed}
        self.verdicts, self.judged = {}, set()
        self._judge(entries, rs)
        st["open"] = None  # the observation is whole and saved: the next run may count from it
        self.save_rc()

    def _judge(self, entries, rs):
        """Judge each entry and keep its verdict by root: ("raise" | "due", level) or
        nothing. An entry that is not KEV's, out of scope now or has work in flight is
        not judged, and its wait takes no time for a run that did not look at it."""
        st = self.rc
        for e in entries:  # with no copy every read is unknown, and judge says so to each wait
            root = e.root_event_id
            self.verdicts.pop(root, None)
            scope = rules.scope_of(e.scope) if e.exploited else None
            if scope is None or scope.name != e.scope or self.busy(e.aliases, e.scope):
                self.judged.discard(root)
                recompute.pause(st, root)
                continue
            self.judged.add(root)
            verdict = recompute.judge(e, scope, self.copy, rs, st, self.now)
            if verdict is not None:
                self.verdicts[root] = (e, *verdict)

    def recompute(self):
        """Send what the verdicts say (ny5g): a raise now; a lowering when the thread
        has had seven quiet days and the circuit breaker lets it through. The run has
        drained the journal and planned its candidates since ``observe``, so every
        thread that was not judged there (posted by this run, or busy then), and every
        thread whose ledger entry is no longer the one judged (a candidate added an id,
        a floor, a fix, another level), is judged again now, from the entry as it is:
        no verdict outlives the entry it was reached on, and the reply is composed from
        the current advisory. The breaker's share is of the threads judged, the only
        ones that can be lowered: a ledger full of other threads must not make a mass
        lowering look small."""
        st = self.rc
        now = [e for e in self.led.entries() if not compose.is_synthetic(e.advisory.get("id"))]
        self._judge([e for e in now if e.root_event_id not in self.judged
                     or (e.root_event_id in self.verdicts and self.verdicts[e.root_event_id][0] != e)],
                    ruleset.load())
        live = {e.root_event_id for e in now}
        # Not busy when judged, and not busy now: a candidate of this run can leave work in
        # flight under a thread's ids without touching its entry (a refused item of a thread
        # that shares an id), and nothing is sent on top of work in flight.
        found = [v for root, v in self.verdicts.items() if root in live and not self.busy(v[0].aliases, v[0].scope)]
        raises = [(e, level) for e, kind, level in found if kind == "raise"]
        due = recompute.select([(e, level) for e, kind, level in found
                                if kind == "due" and recompute.quiet(e, self.now)], len(self.judged), st, self.now)
        self.save_rc()
        for e, level in raises + due:
            try:
                items = self._level_items(e, level)
            except ValueError:  # compose refused it: this thread's change is withheld
                self.n["withheld"] += 1
                continue
            self.enqueue(items)  # its wait stays until the ledger shows the level: see drop_unsent_lowerings

    def _withdrawn(self, root, fetch=None) -> tuple[set, set]:
        """(case-folded advisory ids, root event ids) withdrawn under ``root`` as of a
        mirror pull made now: the manifest's retracted ids (whoever posted them), and the
        root of every thread that is retracted or, as amended, expired (that thread only:
        another product's post of the same id stays). Raises when the pull fails."""
        st = State.load(self.config.mirror_dir)
        res = translate.bounded(lambda: pull.fetch(self.config.translate_mirror_url, st, fetch=fetch,
                                                   root_pubkey=root, now=self.now, checkpoint=False), 120)
        if res.error is not None:
            raise ValueError(f"mirror pull: {res.error}")
        m = st.accepted(root)
        roots = set()
        for t in pull.threads_from(list(st.events_for(root).values()), m):
            t = pull.standing(t, self.now)  # c1g2: a curator's retraction of a bot thread lapses
            if t.retracted or (t.adv.expires_at is not None and t.adv.expires_at < self.now):
                roots.add(t.root_id)
        return {i.casefold() for i in m.retracted}, roots

    def digest(self, root=TRUST_ROOT_PUBKEY, fetch=None):
        local = _dt.datetime.fromtimestamp(self.now, TOKYO)
        today = local.date().isoformat()
        if self.state["digest_date"] == today:
            if self.digest_now:
                _say(f"digest for {today} already sent; --digest-now does nothing")
            return
        if local.hour < self.config.digest_hour and not self.digest_now:
            return
        if any(it["kind"] == "digest" for it in self.state["outbox"] + self._withheld_items()):
            if self.digest_now:
                _say("a digest is journaled and waits to send; --digest-now does nothing")
            return  # today's (or an earlier) digest is journaled and drains first
        try:  # a withdrawn advisory is never announced again: no pull, no digest this run
            gone, gone_roots = self._withdrawn(root, fetch)
        except (translate.CallError, OSError, ValueError) as e:  # StateError is a ValueError
            _say(f"digest held: {e}")
            self.n["digest_held"] += 1
            return
        # Ledger posts oldest change first (so a backlog larger than one post moves forward
        # day by day), then held notices loudest first: (advisory, held entry, (listed, root)).
        posted = [h for h in self.state["held"]  # a notice that has since posted is listed once, as posted
                  if self.led.lookup([h["adv"]["id"], *h["adv"]["aliases"]], scope=h["scope"]) is not None]
        led_items, held_items, titles = [], [], {}
        at, done = self.state["digest_at"], set(self.state["digest_roots"])
        for e in self.led.entries_since(at - 1):
            if e.listed == at and e.root_event_id in done:
                continue  # listed by the last digest
            try:
                adv = schema.validate(e.advisory)
            except ValueError:
                self.n["withheld"] += 1
                continue
            if gone_roots.isdisjoint({e.root_event_id, *e.channel_ids.values()}):  # else its thread is withdrawn
                led_items.append((adv, None, (e.listed, e.root_event_id)))
                if adv.products:
                    titles[(adv.id, adv.products[0].name)] = e.source_title
        unlisted = []
        for h in self.state["held"]:
            if h not in posted:
                try:
                    a = schema.validate(h["adv"])
                    if not compose.listable(a):
                        # 8ke5: a lead, or no primary source. It leaves the held list but is
                        # never marked digested, so a sighting with a primary source is held
                        # again and listed.
                        unlisted.append(h)
                        continue
                    held_items.append((a, h, None))
                    if a.products:
                        titles.setdefault((a.id, a.products[0].name), h.get("source_title"))
                except ValueError:
                    self.n["withheld"] += 1
        if unlisted:
            self.state["held"] = [h for h in self.state["held"] if h not in unlisted]
            self.save()
        led_items.sort(key=lambda x: x[2])
        held_items.sort(key=lambda x: (-RANK[x[0].level], -x[0].posted_at))
        items = led_items + held_items
        keep = len(items)
        while True:  # the largest prefix that fits one post; the rest waits for tomorrow
            try:
                text = compose.digest([x[0] for x in items[:keep]], local.date(), retracted=gone, now=self.now,
                                      titles=titles) + compose.level_report(self.rc["lowered"], self.rc["tripped"])
            except ValueError:
                self.n["withheld"] += 1
                return
            if len(text) <= transport.MAX_CONTENT or keep == 0:
                break
            keep //= 2
        taken = items[:keep]
        led_taken = [x[2] for x in taken if x[2] is not None]
        if len(led_taken) == len(led_items):  # the roots at the cutoff are listed: never again (8ke5)
            cutoff = self.now
            roots = [r for t, r in led_taken if t == cutoff]
        elif led_taken:  # acknowledged: every change up to the last one listed, by root at that time
            cutoff = led_taken[-1][0]
            roots = [r for t, r in led_taken if t == cutoff] + (sorted(done) if cutoff == at else [])
        else:
            cutoff, roots = at, sorted(done)
        snap = {"held": sorted({k for _, h, _ in taken if h is not None
                                for k in self._notice_keys(h["scope"], h["adv"])}),
                "cutoff": cutoff, "roots": roots}
        ja = self._ja(lambda: compose.digest([x[0] for x in taken], local.date(), lang="ja", retracted=gone,
                                             now=self.now, titles=titles)
                      + compose.level_report(self.rc["lowered"], self.rc["tripped"], "ja"))
        item = self._item("digest", None, [f"digest:{today}"], "feed", text, key_id=today, adv=snap, date=today, ja=ja)
        if self.rc["lowered"]:
            # ny5g: listed once. The date is written first, so a run that stops between the
            # two files is settled by the next one (observe): the list goes if this digest
            # was journaled and stays if it was not.
            self.rc["reported"] = today
            self.save_rc()
        self.state["outbox"].append(item)
        self.save()
        if self.rc["reported"] is not None:
            self.rc.update(lowered=[], reported=None)
            self.save_rc()
        self.deliver(item)


def _observed(c) -> int | None:
    return _epoch(c.observed_at)


def _epoch(v) -> int | None:
    if not v or not isinstance(v, str):
        return None
    try:
        t = _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    if len(v) == 10:  # a date only (KEV dateAdded): judged at its day's end, so an
        return int(t.timestamp()) + 86399  # entry added on the floor's own day is never "old"
    return int(t.timestamp())


def _group_range(was, c, fixed) -> str | None:
    """A fix group thread's range after one member's sighting: the thread's when they
    agree or the sighting states none, none stated when the thread states none, else
    everything before the fix (which covers both)."""
    new = compose.schema_affected(c.affected)
    if new is None or new == was.affected or was.affected is None:
        return was.affected
    fixed = compose.schema_fixed(fixed)
    return f"<{fixed}" if fixed else None


def _published(sources) -> int | None:
    """When the primary source (the one a post names) was published, if it says: read from
    the input's own timestamp, which the wire form may drop (a space before the time)."""
    src = next((s for s in compose._sources(sources) if schema.is_primary(s.url)), None)
    raw = next((getattr(s, "published_at", None) for s in sources if getattr(s, "url", None) == src.url),
               None) if src is not None else None
    return _epoch(raw.replace(" ", "T", 1) if isinstance(raw, str) else raw)


def _stated(v) -> bool:
    return isinstance(v, str) and v.strip() != ""


def _translate_state(path) -> dict:
    """The translate state (hold, daily calls, translated ids), the default when there is
    none; ValueError (or OSError) when it is not one. Curator translation and wording
    (c6ak) read it alike."""
    tr = inputs.read_json(path, inputs.MAX_RECORD) if path.exists() \
        else {"hold": None, "day": None, "calls": 0, "done": {}}
    if not (isinstance(tr, dict) and set(tr) == {"hold", "day", "calls", "done"}
            and type(tr["calls"]) is int and tr["calls"] >= 0
            and (tr["day"] is None or inputs._date_ok(tr["day"]))
            and isinstance(tr["done"], dict) and (tr["hold"] is None or isinstance(tr["hold"], dict))
            and all(v in ("ok", "untranslated") or type(v) is int for v in tr["done"].values())):
        raise ValueError("not a translate state")
    return tr


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


def _gate(state: dict, led: Ledger) -> None:
    """Once, on the first run with the h340 gate: nothing composed or kept before it is
    sent after it. The deferred, held and withheld lists are emptied, and every journal
    item not yet sent is removed unless it is a Japanese reply (its original is public)
    or a send whose outcome is unknown (``pending`` / ``resolve`` still settle it). Threads
    forget the ids, sources and title they learned without publishing (``forget_unpublished``)."""
    if state["gate"] == inputs.GATE:
        return
    drop = [it for it in state["outbox"] if it["sent"] is None and it["kind"] != "ja"
            and not led.has_pending(it["key"])]
    _say(f"gate: first run under the authoritative-source rule; removed {len(state['deferred'])} deferred, "
         f"{len(state['held'])} held, {len(state['withheld'])} withheld, {len(drop)} unsent; "
         f"{led.forget_unpublished()} thread(s) forgot unpublished ids, sources and titles")
    # The inputs are read again from the backfill floor, so a genuine notice that was
    # held or deferred comes back through the gate (re-reading is idempotent).
    state.update(deferred=[], held=[], withheld=[], gate=inputs.GATE, collector=None, heartbeat=None, kev_since=None,
                 outbox=[it for it in state["outbox"] if it not in drop])


def _advisory_text(adv) -> str:
    """The whole advisory in English lines, as a curator root's body reads."""
    lines = [f"{adv.level.upper()}: {adv.title}"]
    lines += [f"Affected: {p.name} {p.affected or '(all versions)'}." + (f" Fixed in {p.fixed}." if p.fixed
              else " No fixed version stated.") for p in adv.products]
    lines += [f"Action: {check.describe(a)}." for a in adv.actions]
    return "\n".join(lines + [f"Source: {x.url}" for x in adv.sources])


def _say(msg: str) -> None:
    print(f"aitools-alerts-poster: {msg}", file=sys.stderr)


def gather(config: Config, state: dict, now: int, kev_fetch, counts: Counter, kev_catalog=None,
           kev_out: dict | None = None):
    """(candidates, watermarks to set when the run succeeds, input status).

    A rejected input sets no watermark past itself, so the next run reads it again
    (re-reading is idempotent: ledger lookup and held-notice dedup). The status dict
    is the summary's ``inputs=`` field. ``kev_out``, when given, receives the catalog this
    run fetched from CISA and its status, for the recompute; a synthetic file never does."""
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
        info: dict = {}
        catalog, status["kev"] = inputs.fetch_kev(config.kev_cache, kev_fetch, info=info)
        if kev_out is not None:
            kev_out.update(catalog=catalog, status=status["kev"], redirected=info.get("redirected"))
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


def relay_sender(config: Config):
    """The real ``send``: jibot's key from the secrets helper, read on the first send,
    and checked against the relay-bot key of the bundled trust manifest. ConfigError
    when the bundled manifest names no relay-bot key."""
    m = pull.bundled_manifest()
    bots = [p.pubkey for p in (m.posters if m else ()) if p.role == "relay-bot"]
    if len(bots) != 1:
        raise ConfigError("the bundled trust manifest does not name exactly one relay-bot key")

    def key_source():
        try:
            return translate.read_key(config.secrets_helper, name=config.relay_key_secret)
        except translate.CallError as e:  # its messages never carry the key
            raise transport.KeyUnavailable(str(e)) from None
    return transport.Relay(config.relay_url, key_source, expected_pubkey=bots[0]).send


def run(now: int, config, *, send=None, ssh=None, kev_fetch=inputs.urllib_fetch,
        page=rules.http_page, channels: dict | None = None,
        digest_now: bool = False, kev_catalog: dict | None = None,
        mirror_fetch=None, translate_call=None, catalog_channel=None, wording_call=None,
        **translate_kw) -> tuple[int, str]:
    """One poster run. Returns (exit code, one-line summary). ``digest_now`` sends
    today's digest whatever the hour (once per date); ``kev_catalog`` replaces the
    KEV fetch with a synthetic catalog (``inputs.read_kev_file``). ``catalog_channel``:
    None reads spec/catalog-channel.json, False turns the catalog lane off, a string is
    the channel id (q03f)."""
    if not isinstance(config, Config):
        config = inputs.load_config(config)
    try:
        config.check_relay()  # before the ledger opens: a run without a route sends nothing
        send = send if send is not None else relay_sender(config)
    except ConfigError as e:
        print(f"aitools-alerts-poster: config error: {e}", file=sys.stderr)
        return 2, "aitools-alerts-poster: " + " ".join(f"{k}=0" for k in SUMMARY) \
            + " inputs=- error=config"
    candidates.configure(config.strip_hosts, config.internal_host_suffixes)
    if not config.strip_hosts:  # the candidate filter then knows only the input's own host names
        print("aitools-alerts-poster: warning: strip_hosts is empty", file=sys.stderr)
    channels = channels or inputs.load_channels()
    n, code, err, status, skipped, tr_status, cp_status = Counter(), 0, None, None, Counter(), "-", "off"
    cat_id, cat_status, english_ok = catalog_channel or None, None, False
    if catalog_channel is None:  # q03f: no file, no lane, and the summary line is unchanged
        try:
            cat_id = inputs.load_catalog_channel(channels)
        except ConfigError as e:
            cat_status = "off-bad-spec"
            _say(f"catalog lane off: {e}")
    if cat_id:
        cat_status = "0/0"
        try:
            config.check_catalog_paths()
        except ConfigError as e:
            cat_id, cat_status = None, "off-bad-paths"
            _say(f"catalog lane off: {e}")
    cat_snap, cat_at = None, 0
    w_run = None  # c6ak: the run whose wording status the summary reports
    try:
        with Ledger(config.ledger) as led:
            state = inputs.load_state(config.state, now, config.backfill_days)
            r = Run(now, config, led, state, channels, send, page, digest_now=digest_now, skipped=skipped,
                    wording_call=wording_call)
            n, w_run = r.n, r
            _gate(state, led)
            recompute.begin(r.rc, now)  # ny5g: before anything is read, so a run that stops is known to have
            r.save_rc()
            merged, english_ok = None, False  # merged: set once the old deferred list is folded in
            try:
                kev_out: dict = {}
                cands, marks, status = gather(config, state, now, kev_fetch, skipped, kev_catalog, kev_out)
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
                if later:  # a different one first each hour, over one stable order: failing pages
                    later.sort(key=lambda p: (p[1].name, p[0].id.casefold()))  # ahead never starve one
                    k = (now // 3600) % len(later)
                    later = later[k:] + later[:k]
                pairs += later  # after the fresh ones: merge takes the first member's fix, so a correction wins
                n["in_scope"] = len(pairs)
                # h340: only what an authoritative source states goes on, each candidate
                # judged alone, before a merge could lend it another's sources.
                pairs = [(a, scope) for c, scope in pairs if (a := r.admit(c, scope)) is not None]
                if review:
                    led.add_review(review, now=now)
                # faxq: in flight, an id joins no fix group (that send would record the group's ids)
                settled = {f"{it['scope']}|{i.casefold()}" for it in state["outbox"] + r._withheld_items()
                           for i in it["ids"]}
                merged = ledger.merge(pairs, led, r.groups, settled=settled)  # BEFORE level_for
                r.observe(kev_out)
                r.drain()
                for i, (c, scope) in enumerate(merged):
                    r.one(c, scope)
                    merged[i] = None  # planned (or deferred by one() itself)
                r.recompute()
                if cat_id:  # q03f: before the digest, which drops the notices it lists from held.
                    try:  # In memory only: no catalog file is touched under the ledger lock.
                        cat_snap, cat_at = catalog.snapshot(led, state["held"]), catalog.stamp()
                    except Exception as e:  # noqa: BLE001 - the catalog never touches alert work
                        cat_status = "error"
                        _say(f"catalog snapshot failed: {type(e).__name__}: {e}")
                r.digest(root=translate_kw.get("root", TRUST_ROOT_PUBKEY), fetch=mirror_fetch)
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
                live = {f"{sc}|{i.casefold()}" for (sc, _), d in r.deferred.items() for i in [d["id"], *d["aliases"]]}
                state["waiting"] = {k: t for k, t in state["waiting"].items()  # 0dvh
                                    if k in live or now - t < AGE_LIMIT}
            r.save()
            if english_ok:  # last, after marks and deferred are saved together
                try:
                    tr_status = r.translate_curator(mirror_fetch, translate_call, **translate_kw)
                except Exception as e:  # noqa: BLE001 - nothing here may reach the run's exit code
                    tr_status = "error"
                    _say(f"curator translation stopped: {type(e).__name__}")
                r.drain_ja()  # a Japanese reply never delays or stops an English post
            # Last, whatever the outcome above: a run whose posts failed still vouches for what exists.
            try:
                if getattr(r, "owe_failed", False):
                    # An acknowledged post could not be written down. It is still in the send
                    # journal; the next run records it before it signs. This one must not sign.
                    cp_status = "owed-unrecorded"
                else:
                    cp_status = signer.run_checkpoint(config, now, ssh=ssh, fetch=mirror_fetch,
                                                      root=translate_kw.get("root", TRUST_ROOT_PUBKEY))
            except Exception as e:  # noqa: BLE001 - nothing here may reach the run's exit code
                cp_status = "error"
                _say(f"checkpoint stopped: {type(e).__name__}")
            if state["withheld"]:  # every run says so until a human settles them
                _say(f"withheld={len(state['withheld'])} refused by the relay; see pending, resolve --requeue|--drop")
        # q03f: catalog sends, with the ledger lock released and the checkpoint signed, so
        # they cannot delay an alert post, the checkpoint or the next run.
        if cat_id and english_ok and cat_status != "error":
            try:
                cat_status = catalog.send_pass(config, cat_id, send, cat_snap, cat_at)
            except Exception as e:  # noqa: BLE001 - nothing here may reach the run's exit code
                cat_status = "error"
                _say(f"catalog pass stopped: {type(e).__name__}: {e}")
    except LedgerError as e:
        code, err = 1, str(e)
    except Exception as e:  # never die without the summary line
        code, err = 1, f"internal error: {type(e).__name__}: {e}"
    if skipped:
        _say("skipped: " + ", ".join(f"{k}={v}" for k, v in sorted(skipped.items())))
    summary = "aitools-alerts-poster: " + " ".join(f"{k}={n[k]}" for k in SUMMARY) \
        + " translate=" + tr_status + " inputs=" + _inputs_field(status)
    if cp_status != "off":  # unset, the line is byte for byte what it was (others parse it)
        summary += " checkpoint=" + cp_status
    if cat_status is not None:  # likewise: only once spec/catalog-channel.json exists
        summary += " catalog=" + cat_status
    if config.model_wording:  # c6ak: likewise, only with model_wording on
        st = w_run.w_status if w_run is not None else "error"
        summary += " wording=" + (f"{n['worded']}/{n['word_asked']}" if st == "ok" else st)
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
            state = inputs.load_state(config.state, now, config.backfill_days)
            items = {it["key"]: it for it in state["outbox"]}
            for w, it in ((w, w["items"][0]) for w in state["withheld"]):  # the relay's message, never the text
                lines.append(f"{w['key']} kind={it['kind']} channel={it['channel']} withheld_at={_iso(w['at'])} "
                             f"outcome=refused message={w['message']}")
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
    lines.append(f"aitools-alerts-poster: pending={total} unknown={n['unknown']} sent={n['sent']} orphan={n['orphan']}"
                 + (f" withheld={len(state['withheld'])}" if state["withheld"] else ""))
    return 0, lines


def resolve(now: int, config, key: str, *, delivered: str | None = None,
            reason: str | None = None, requeue: bool = False, drop: bool = False,
            text: str | None = None) -> tuple[int, list[str]]:
    """Settle one send whose outcome was unknown, under the ledger lock. ``delivered``:
    the post's event id, recorded exactly as a successful send records it (Run.deliver
    with ``sent`` set). Otherwise expire the pending entry (24 h rule) so it sends again.
    A withheld group goes back to the journal's end (``requeue``) or away (``drop``: its advisory is planned anew).
    Returns 2, changing nothing, when the request cannot apply."""
    def refuse(msg):
        return 2, [f"aitools-alerts-poster: resolve {key}: {msg}"]
    if delivered is not None and not transport._HEX64.fullmatch(delivered):
        return refuse("event id must be 64 lowercase hex characters")
    if delivered is None and not (requeue or drop or (reason or "").strip()):
        return refuse("--not-delivered needs a non-blank --reason")
    try:
        with Ledger(config.ledger) as led:
            if requeue or drop:
                state = inputs.load_state(config.state, now, config.backfill_days)
                w = next((w for w in state["withheld"] if w["key"] == key), None)
                if w is None:
                    return refuse("not withheld")
                live = {o["key"] for o in state["outbox"]}  # journaled again: its pending mark is its own
                if requeue and live & {it["key"] for it in w["items"]}:
                    return refuse("its key is journaled again; --drop it")
                state["withheld"].remove(w)
                if text is not None and (drop or not 0 < len(text) <= transport.MAX_CONTENT or "\x00" in text
                                         or schema._last_block(text) != schema._last_block(w["items"][0]["text"])):
                    return refuse("--text-file needs --requeue and sendable text with the aitools-alert block unchanged")
                if requeue:  # the new text replaces the refused one wherever the group carried it
                    state["outbox"] += [dict(it, text=text) if text and it["text"] == w["items"][0]["text"] else it
                                        for it in w["items"]]
                if len(json.dumps(state, indent=1, sort_keys=True)) > inputs.MAX_RECORD:  # as write_json writes it
                    return refuse("the new text would make the state too large to load")
                for it in w["items"]:  # a crash between withholding and clearing left the mark; never a live item's
                    if it["key"] not in live and led.has_pending(it["key"]):
                        led.clear_pending(it["key"])  # first: a withheld item never sends, so this order is safe
                inputs.save_state(config.state, state)
                return 0, [f"aitools-alerts-poster: resolved {key}: " + ("requeued; the next run sends it"
                                                                          if requeue else f"dropped {len(w['items'])} item(s)")]
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


def clear_hold(config) -> tuple[int, list[str]]:
    """Remove the translation hold a 401/403 set, under the ledger lock."""
    try:
        with Ledger(config.ledger):
            path = config.translate_state
            tr = inputs.read_json(path, inputs.MAX_RECORD) if path.exists() else {}
            if not isinstance(tr, dict) or not tr.get("hold"):
                return 0, ["aitools-alerts-poster: no translation hold"]
            hold, tr["hold"] = tr["hold"], None
            inputs.write_json(path, tr)
            return 0, [f"aitools-alerts-poster: translation hold cleared (set at {_iso(hold.get('at', 0))}, "
                       f"{hold.get('why')})"]
    except (LedgerError, OSError, ValueError, TypeError) as e:
        return 1, [f"aitools-alerts-poster: {type(e).__name__}: {e}"]


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
    how.add_argument("--requeue", action="store_true", help="a withheld (refused) item: send it again next run")
    how.add_argument("--drop", action="store_true", help="a withheld (refused) item: discard it")
    sp.add_argument("--text-file", type=Path, metavar="PATH", help="with --requeue: the corrected post text")
    sp.add_argument("--reason", help="why it is known not delivered (required with --not-delivered)")
    hp = sub.add_parser("translate-clear-hold", help="resume curator translation after an auth failure")
    hp.add_argument("--config", type=Path, default=inputs.DEFAULT_CONFIG)
    kp = sub.add_parser("checkpoint-keygen", help="create the checkpoint key file named in the config; prints the npub")
    kp.add_argument("--config", type=Path, default=inputs.DEFAULT_CONFIG)
    a = p.parse_args(argv)
    if a.cmd == "checkpoint-keygen":
        try:
            cfg = inputs.load_config(a.config)
            if cfg.checkpoint_key_file is None:
                raise ConfigError("set checkpoint_key_file (and relay_put_wrapper) in the config first")
            npub = signer.keygen(cfg.checkpoint_key_file)
            signer.init_owed(cfg.owed_state)  # a new key owes nothing: signing may start at once
            print(npub)  # the public key only
        except OSError as e:
            print(f"aitools-alerts-poster: {e.strerror or type(e).__name__}", file=sys.stderr)
            return 2
        except (ConfigError, signer.KeyFileError) as e:
            print(f"aitools-alerts-poster: {e}", file=sys.stderr)
            return 2
        return 0
    if a.cmd in ("pending", "resolve", "translate-clear-hold"):
        try:
            cfg = inputs.load_config(a.config)
            text = a.text_file.read_text(encoding="utf-8") if getattr(a, "text_file", None) else None
        except (ConfigError, OSError, UnicodeError) as e:  # OSError, UnicodeError: --text-file
            print(f"aitools-alerts-poster: config error: {e}", file=sys.stderr)
            return 2
        if a.cmd == "translate-clear-hold":
            code, lines = clear_hold(cfg)
        elif a.cmd == "pending":
            code, lines = pending(int(time.time()), cfg)
        else:
            code, lines = resolve(int(time.time()), cfg, a.key, delivered=a.delivered, reason=a.reason,
                                  requeue=a.requeue, drop=a.drop, text=text)
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
