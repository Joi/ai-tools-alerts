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

No send waits for a person (ai-tools-alerts#jsje). A send whose outcome is unknown is
settled by a later run from the mirror (``Run.settle``): an event under the relay bot's
key with the item's text and thread is its delivery; one that a fresh mirror does not
show 24 hours after the attempt, or that no mirror has shown after 72, is sent again.
A ``refused`` send never stops the run (a second one does): it waits in ``withheld``
for three days; then a root, copy or digest is dropped and its advisory planned anew,
and a reply is sent once more and dropped only when refused again (``Run.expire_withheld``).
A raise never waits behind an unsent lowering or source-only reply of its own thread:
that work leaves the journal in the save that journals the raise (``Run.yields``,
``Run.enqueue``). It does wait while a send of the thread is unknown. A level reply the
journal gave up in one channel is not lost: the ledger names the channel as lacking the
thread's standing reply (``Entry.lacks``) and a later run sends it again (``Run.reconcile``,
ai-tools-alerts#aqtf). ``pending`` lists
what is in flight and ``resolve <key> --delivered <event id> | --not-delivered --reason
<text> | --requeue | --drop`` settles one sooner, both under the ledger lock.

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

So it does for each thread that carries a GHSA id, from this run's reads of GitHub's
advisory database and of OSV (``sources``, ai-tools-alerts#3qyq): a failed read is
unknown and moves nothing. A new candidate's ``ghsa`` reading is that API's answer
too (``Run.admit``); one whose advisory could not be read is admitted again each
run for RETRY_DAYS. At most 30 advisory requests a run, in three lanes. Admission's
ten go to the candidates in turn (``Run.admit_all``, ai-tools-alerts#vszx): first to
one never asked for, then on from where the last run's requests ended, so with n
standing candidates and ten requests made a run, each is asked for within
ceil(n / 10) runs.

A reply that changes a thread's level carries the claim tag of the reading the change
rests on (``Run._claim``, ``rules.claim_text``; ai-tools-alerts#hh5s, spec/wire.md); the
journal item keeps its text. So does a root and its copy (``ROOT_CLAIMS``), and the ledger
keeps the newest claim of a level sent for such a thread, its standing claim.

Every run ends by renewing what readers would otherwise let decay (``Run.renew``,
ai-tools-alerts#gtw9): a thread with a standing claim whose life on a reader is under
half its level's TTL gets a reply with no block and a claim tag in each of its channels,
confirmed now when this run's reads state the claim's level again, else with the old
confirmation and checked now. A level no read has confirmed for 45 days (less a day) is
lowered one step, the reply saying why. A renewal is not journaled: one not acknowledged
is sent by the next run.

A thread is renewed for ``RENEW_DAYS`` after its level last changed (ai-tools-alerts#65xv).
Then it has ended: no renewal is sent, each level is stepped down a day before its life
on readers runs out, the reply saying why, and at notice it leaves them. Only a level
above the one it ended at raises it again, and then it is renewed like any thread.

The recompute ends by posting the copy a thread's level lacks (``Run.copies``,
ai-tools-alerts#3t4p): a thread it raised to critical that has a root in ``feed``
alone gets its root in ``critical`` in that run, composed from the ledger with no
candidate (``compose.copy_post``), and so does a thread whose copy was dropped.

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
``translate-clear-hold``; nothing in that pass reaches the exit code. With a
checkpoint key the pass reads the mirror without the relay-bot events this poster did
not sign, and does not run (``translate=no-record``) until the sent record is started
(ai-tools-alerts#9cch).
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
from types import SimpleNamespace
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from aitools_alerts import TRUST_ROOT_PUBKEY, check, manifest, pull, ruleset, schema, verify, versions, wire
from aitools_alerts import config as _member_config
from aitools_alerts.poster import (candidates, catalog, compose, inputs, ledger, recompute, rules, sent, signer, sources,
                                   translate, wording,
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
RETIRE_PAGES = 10  # z360: new pages a run may read judging a retired thread's ids; the rest wait
RETRY_DAYS = 7  # 3qyq: a candidate whose advisory the API did not give is admitted again this long
UNREAD_NAMED = 40  # vszx: the ids one run's "not read" line names; the rest are counted
# jsje: a run settles what used to wait for `resolve`.
SETTLE_SKEW = 600  # an event dated this long before the attempt is still its delivery (a clock step)
MIRROR_FRESH = 3600  # a channel file generated longer ago proves no absence
GIVE_UP = 72 * 3600  # an unknown send is sent again after this whatever the mirror says (signer.OWED_S)
WITHHELD_SECONDS = 3 * 86400  # a refused item is dropped, and its advisory planned anew, after this
# hh5s: whether a root and its copies carry a claim tag. Readers 0.1.8 and later decay a
# thread whose root carries a claim (critical for 14 days) unless a later claim renews it,
# and a thread whose root carries none never expires, whatever its replies carry
# (spec/wire.md). On since the poster renews (``Run.renew``, ai-tools-alerts#gtw9) and the
# signer keeps a renewal the mirror hides (``signer.settle_gone``): never on without both.
ROOT_CLAIMS = True
MAX_RENEWALS = 20  # gtw9: renewal sends a run, the thread with the least life left first
STEP_EARLY = 86400  # gtw9: an unconfirmed level is stepped down this long before readers drop it
# 65xv: a thread is renewed this long after its level last changed (after its root, when it
# never did), then runs down. Every thread must end: a checkpoint lists 990 events and a
# reader stores 20,000. With its Japanese reply an open thread costs a checkpoint three
# events in a channel; at one new high a day, 90 days is about 800 of the 990.
RENEW_DAYS = 90
_CLAIM_RANK = {ruleset.NONE: -1, **RANK}
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


def _base(i) -> str:
    """An id without a thread key's slug, case-folded (z360): what an advisory page assigns."""
    m = candidates.BOT_ID.fullmatch(i) if isinstance(i, str) else None
    return m.group(1).casefold() if m else i.casefold() if isinstance(i, str) else ""


def _fold(ids) -> set[str]:
    return {i.casefold() for i in ids if isinstance(i, str)}


class Run:
    def __init__(self, now, config: Config, led: Ledger, state: dict, channels, send, page,
                 *, digest_now=False, skipped: Counter | None = None, wording_call=None, reader=None):
        self.now, self.config, self.led, self.state = now, config, led, state
        self.api = reader if reader is not None else sources.Reader()  # 3qyq: this run's advisory reads
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
        self.page_cap = MAX_RUN_PAGES  # yd1y: lower while ``part`` reads a member's pages
        self.confirmed: dict[str, set] = {}  # url -> the advisory ids its page confirmed
        self.digest_now = digest_now  # run --digest-now: today's digest whatever the hour
        self.n = Counter()
        self.deferred: dict[tuple, dict] = {}  # (scope, id) -> candidate dict, for the next run
        self.groups: dict[tuple, list] = {}  # faxq: (scope, id) -> a fix group's members (ledger.merge)
        # jsje: thread root -> (journal items, withheld groups) a raise of that thread will
        # replace (yields). They stay where they are until the raise is journaled (enqueue).
        self.passed: dict[str, tuple] = {}
        self.unrenewed: set[str] = set()  # gtw9: roots this run's checkpoint leaves out (renew)
        # kk2q: thread roots whose withdrawal this run recorded in some channel. No reply
        # that ends the state follows in the same run: the two could carry one second.
        self.withdrew: set[str] = set()
        # aqtf: thread roots a reply of which the relay refused in this run. ``reconcile``
        # plans nothing for them now: the next run does, at the journal's own pace.
        self.refused: set[str] = set()
        self.again: set[str] = set()  # aqtf: thread roots ``reconcile`` planned a reply for in this run
        self.gone: frozenset = frozenset()  # z360: the stored manifest's retracted ids, case-folded
        self._released = None  # z360: the base ids retired threads released (``released``)
        # btqg: the mirror a join by fix reads (``_gone``): (trust root, fetch), set by ``run``.
        self.mirror = (TRUST_ROOT_PUBKEY, None)

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
              root=None, ja=None, source_title=None, floor=None, claim=None):
        """One journal item. ``root`` fixes a reply's or copy's thread at planning time, so a
        later alias bridge cannot move it to another thread. ``claim``: the text of its
        claim tag (``_claim``), kept so a replay signs the same one. Raises ValueError
        (withheld) for a message the transport would refuse."""
        if not text or len(text) > transport.MAX_CONTENT or "\x00" in text:
            raise ValueError("message too large or not sendable")
        return {"key": f"{kind}:{scope}:{key_id}:{channel}", "kind": kind, "scope": scope,
                "ids": list(dict.fromkeys(ids)), "channel": channel, "text": text, "adv": adv,
                "exploited": exploited is True, "date": date, "sent": None, "root": root,
                **({"ja": ja} if ja else {}),  # no key without a body: the poster before rd8t loads it
                **({"source_title": source_title} if source_title else {}),
                **({"floor": floor} if floor else {}),  # ny5g: a root's prose floor, for the ledger
                **({"claim": claim} if claim else {})}  # hh5s: no key without one, as above

    @staticmethod
    def _tag(it):
        """The claim tag a journal item is sent with, or None."""
        return [wire.CLAIM_TAG, it["claim"]] if it.get("claim") else None

    @staticmethod
    def _patch(it) -> dict:
        """What a reply item's block says on the wire ({} when it has none that reads)."""
        try:
            patch = json.loads(schema._last_block(it["text"]))
        except (TypeError, ValueError, KeyError):
            return {}
        return patch if isinstance(patch, dict) else {}

    @staticmethod
    def _stated(entry, adv, also=()) -> list:
        """The ids every channel of the thread has been sent, its first id first: what a
        claim on a reply may name. The first id is in every root. The ledger keeps one
        advisory for the thread, and an alias in it was sent to every channel only when
        each channel was sent as many replies as the others: a reply that one channel
        took and another refused for good (``_withhold``) leaves them apart, and so
        does a copy added after a reply. Then only the first id counts, with ``also``:
        the aliases this very reply states, in every channel."""
        sent = [sum(1 for r in entry.replies or () if ch in r) for ch in entry.channel_ids]
        # aqtf: nor are they level once a reply was sent again: it names the level alone
        level = len(set(sent)) <= 1 and not entry.uneven
        return [adv.id, *(adv.aliases if level else also)]

    def _claim(self, readings, ids, scope) -> str | None:
        """The text of the claim tag for an event about the thread with ``ids`` (its
        first id first), from the readings its level rested on (``rules.claim_text``)."""
        readings = list(readings)
        text = rules.claim_text(readings, ids, scope, self.now)
        if text is None and rules.claim_text(readings, ids, scope, self.now, limit=False) is not None:
            _say(f"{compose.public_form(ids[0])}: its claim is larger than {wire.MAX_CLAIM_BYTES} bytes; sent without one")
        return text

    def _ja(self, fn, *a, **kw):
        """A Japanese body, or None: a Japanese failure never withholds the English post."""
        try:
            return fn(*a, **kw)
        except (ValueError, KeyError, TypeError):
            self.n["ja_failed"] += 1
            return None

    def drain(self):
        """Send every journaled item, oldest first; a pending one (and anything after it
        that shares its ids) waits until its outcome is settled (``settle``)."""
        held_back: set[str] = set()
        for it in list(self.state["outbox"]):
            if it not in self.state["outbox"] or it["kind"] == "ja":
                continue  # dropped with a superseded root; Japanese replies go last (drain_ja)
            keys = _fold(it["ids"])
            if it["sent"] is None and (keys & held_back or self.led.pending_for(it["ids"]) or self._passing(it)):
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
                transport.check_send(self.channels[it["channel"]], it["text"], reply_to, self._tag(it))
            except (ValueError, KeyError):
                self._drop([it])
                self.n["ja_failed" if ja else "withheld"] += 1
                print(f"aitools-alerts-poster: {it['kind']} not sendable (bad channel or root id)",
                      file=sys.stderr)
                if ja:
                    return False
                raise _Stop from None
            self.led.pending(it["key"], [] if ja else it["ids"], now=self.now)  # ja: matches no advisory
            # with no claim, exactly the call it was: a sender that knows none still serves
            r = self.send(self.channels[it["channel"]], it["text"], reply_to, *([tag] if (tag := self._tag(it)) else []))
            if r.outcome == "refused":  # never sent again unchanged; the run goes on
                self._withhold(it, r.message)  # saved before the mark clears: a crash between holds it
                self.led.clear_pending(it["key"])
                # aqtf: nor does a reply sent again count. A channel that refuses for good
                # would otherwise stop a run for each two of its threads, every three days.
                self.n["refused"] += not ja and not it.get("again")
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
        root, e = it.get("root") if it["kind"] == "ja" else None, None
        if it["kind"] == "reply":  # the root it replied to in ITS channel (a critical has one per channel)
            e = self.led.lookup(it["ids"], scope=it.get("scope"))
            root = (getattr(e, "channel_ids", {}).get(it["channel"]) if e is not None else None) or it.get("root")
        self._owed(it["sent"], it["text"], self._tag(it), root,
                   reply=it["kind"] == "reply" and getattr(e, "claim", None) is not None)

    def _owed(self, eid, text, tag, root, reply):
        """Record one acknowledged post as owed. ``reply``: it is a reply in a thread whose
        root carries a claim. One a reader counts as a renewal of that thread says so, with
        the times it counts (gtw9, ``signer.renewals_of``): the run's time twice for one
        whose block names a level (the event is dated no earlier), else its claim's. The
        signer never gives such a reply up for lost."""
        if self.config.checkpoint_key_file is None:
            return
        try:  # m729: the real sender wrote it down before the send; another sender, or a person's word, did not
            sent.note(self.config.sent_state, eid, self.now)
        except OSError as e:
            self.owe_failed = True
            raise LedgerError(f"sent record {self.config.sent_state}: {e.strerror or e}") from None
        try:
            size = len(text.encode("utf-8")) + (wire.tag_bytes(tag) if tag else 0)  # hh5s: a channel file holds the tag
            c = self._parsed(tag[1]) if tag and reply else None
            named = (pull._patch(text) or {}).get("level") if reply else None
            times = (self.now, self.now) if named in RANK else (c["confirmed_at"], c["checked_at"]) if c else None
            signer.record_sent(self.config.owed_state, eid, size, root, self.now, renewal=times)
        except OSError as e:  # a debt that cannot be written down must stop the run, not be forgotten
            self.owe_failed = True  # and this run signs no checkpoint: it would omit the post
            raise LedgerError(f"checkpoint state {self.config.owed_state}: {e.strerror or e}") from None

    def _withhold(self, it, message):  # a refused item, with a root's copies that need it, leaves the journal
        group = [it] + [o for o in self.state["outbox"] if it["kind"] == "root" and o["kind"] == "copy"
                        and o["root"] is None and o["scope"] == it["scope"] and _fold(o["ids"]) & _fold(it["ids"])]
        for o in group:
            self.state["outbox"].remove(o)
        if it["kind"] == "reply" and it.get("root"):
            self.refused.add(it["root"])
        keep = it["kind"] != "ja" and len(json.dumps(group + self._withheld_items())) <= MAX_JA_BYTES  # else dropped
        if it.get("retried"):  # jsje: refused twice, three days apart: nothing here can deliver it
            keep = False
            self.state["dropped"] += 1
            self.n["dropped"] += 1
        if keep:  # a Japanese reply never grows the list; neither does one past the backlog bound
            self.state["withheld"].append({"key": it["key"], "items": group, "message": message, "at": self.now})
        self.save()
        self.n["ja_failed" if it["kind"] == "ja" else "withheld"] += 1
        _say(f"{it['key']} refused by the relay, {'withheld' if keep else 'dropped'}: {message}")

    def _withheld_items(self):
        return [o for w in self.state["withheld"] for o in w["items"]]

    # ------------------------------------------------------------ settling without a person (jsje)

    def _unwithhold(self, w):
        """Remove one withheld group, with any pending mark a stopped run left on its
        items (never a journaled item's: that mark is its own). Saved by the caller."""
        live = {o["key"] for o in self.state["outbox"]}
        self.state["withheld"].remove(w)
        for it in w["items"]:  # the mark first: a withheld item never sends, so this order is safe
            if it["key"] not in live and self.led.has_pending(it["key"]):
                self.led.clear_pending(it["key"])

    def expire_withheld(self):
        """A refused item leaves ``withheld`` WITHHELD_SECONDS after the relay refused it.

        A root with its copies, a copy or a digest is dropped: nothing then holds its
        advisory, which is planned anew from its sources (a candidate was deferred while
        it waited; the digest plans its own). The next digest counts it.

        A reply is not dropped yet. Another channel may have taken the same change, and
        the ledger then records it, so nothing would plan it again and this channel would
        lack it for good. It goes back to the journal marked ``retried`` and is sent once
        more as it is; refused again, it is dropped and counted (``_withhold``). The mark
        is the item's own and on disk: a restart, or a failed send, does not forget it."""
        for w in [w for w in self.state["withheld"] if self.now - w["at"] >= WITHHELD_SECONDS]:
            it, days = w["items"][0], (self.now - w["at"]) // 86400
            self._unwithhold(w)
            if it["kind"] == "reply" and not it.get("retried") and self.led.thread(it["root"] or "") is not None \
                    and all(o["key"] != it["key"] for o in self.state["outbox"]):
                it["retried"] = True
                self.state["outbox"].append(it)
                self.save()
                _say(f"{w['key']} refused by the relay {days} days ago ({w['message']}); sent once more")
                continue
            self.state["dropped"] += 1
            self.save()
            self.n["dropped"] += 1
            _say(f"{w['key']} dropped: refused by the relay {days} days ago ({w['message']}); "
                 "its advisory is planned anew")

    def _mirror(self, root, fetch):
        """(the relay bot's events in the poster's verified copy of the mirror after a
        pull made now, without those this poster did not sign (``_own``, 9cch),
        {channel name: when its file was generated}), or None when there
        is no copy to read. The second is empty when the pull failed: stored events are
        still evidence of a delivery, and nothing is evidence of an absence."""
        get, seen = fetch or pull.default_fetch, {}

        def keep(url, *a):
            seen[url.rsplit("/", 1)[1]] = body = get(url, *a)
            return body
        try:
            st = State.load(self.config.mirror_dir)
        except (ValueError, OSError):  # an unreadable mirror state
            return None
        try:
            res = translate.bounded(lambda: pull.fetch(self.config.translate_mirror_url, st, fetch=keep,
                                                       root_pubkey=root, now=self.now, checkpoint=False), 120)
        except (translate.CallError, ValueError, OSError):
            # The pull did not finish. What an earlier pull stored is still evidence of a
            # delivery; read it again, since the abandoned pull may yet write to ``st``.
            res = None
            try:
                st = State.load(self.config.mirror_dir)
            except (ValueError, OSError):
                return None
        m = st.accepted(root)
        if m is None:
            return None
        made = {}
        if res is not None and res.error is None:
            for name in pull.FILES:
                try:
                    at = _dt.datetime.strptime(json.loads(seen[name])["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
                    made[name.rsplit(".", 1)[0]] = int(at.replace(tzinfo=_dt.timezone.utc).timestamp())
                except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
                    pass
        return [e for e in self._own(st.events_for(root), m).values()
                if manifest.role_of(m, e["pubkey"]) == "relay-bot"], made

    def _delivery(self, it, p, events) -> str | None:
        """The id of the mirror event that is this journal item's send, or None: the
        relay bot's, with the item's exact text, in its channel, replying to its thread
        root there (to nothing, for a root, a copy or a digest), dated from the item's
        first unknown attempt on (``tried``; ``p`` is the attempt in flight), with the
        item's claim tag and no other (hh5s; none for an item without one), and recorded
        nowhere yet. The oldest that would record."""
        try:
            target = it["root"] if it["kind"] == "ja" else \
                self._entry(it).channel_ids.get(it["channel"]) if it["kind"] == "reply" else None
        except LedgerError:
            return None
        if target is None and it["kind"] in ("reply", "ja"):
            return None
        channel = self.channels[it["channel"]]
        claim = [self._tag(it)] if self._tag(it) else []
        hits = [e for e in events if e["content"] == it["text"] and pull._thread_ref(e) == target
                and [t for t in e["tags"] if isinstance(t, list) and t and t[0] == wire.CLAIM_TAG] == claim
                and [t[1] for t in e["tags"] if len(t) >= 2 and t[0] == "h"] == [channel]
                and e["created_at"] >= min(p["at"], it.get("tried", p["at"])) - SETTLE_SKEW]
        if self.config.checkpoint_key_file is not None:
            # m729: text is no proof of who signed (a thief can copy it). Only an event whose
            # id this poster wrote down before sending is its send; a lost record settles nothing.
            mine = sent.holds(self.config.sent_state)
            hits = [e for e in hits if e["id"] in mine]
        return next((e["id"] for e in sorted(hits, key=lambda e: (e["created_at"], e["id"]))
                     if _unrecordable(self, it, e["id"]) is None), None)

    def settle(self, root=TRUST_ROOT_PUBKEY, fetch=None):
        """Settle every send whose outcome is unknown, as ``resolve`` would on a person's
        word, from the mirror: an event that is the send records it (``--delivered``); a
        send at least PENDING_EXPIRY old that a mirror generated within MIRROR_FRESH does
        not show is expired, so the drain sends it again (``--not-delivered``); one
        GIVE_UP old is expired whatever the mirror says, since the other choice is to
        wait for a person. The mirror is pulled only when something is unknown."""
        items = {it["key"]: it for it in self.state["outbox"]}
        withheld = {it["key"] for it in self._withheld_items()}
        unknown = [p for p in self.led.pending_entries() if (items.get(p["key"]) or {}).get("sent") is None]
        # An item sent again after an expiry, whose second send certainly failed: the first
        # one may still show (no pending entry; the floor is the first attempt).
        again = [{"key": it["key"], "at": it["tried"], "idle": True} for it in self.state["outbox"]
                 if it["sent"] is None and "tried" in it and not self.led.has_pending(it["key"])]
        # And one whose repeat the relay refused: the refusal says nothing of the first send.
        refused = [w for w in self.state["withheld"] if "tried" in w["items"][0] and w["key"] not in items]
        mirror = self._mirror(root, fetch) if again or refused or any(p["key"] in items for p in unknown) else None
        events, made = mirror if mirror is not None else ([], {})
        for w in refused:
            it = w["items"][0]
            eid = self._delivery(it, {"key": it["key"], "at": it["tried"]}, events)
            if eid is not None:
                self._unwithhold(w)
                self.state["outbox"] += w["items"]  # a root's copies follow it, as before the refusal
                it["sent"] = eid
                self.save()
                self.deliver(it)
                self.n["settled"] += 1
                _say(f"{it['key']} settled: the mirror shows it as {eid}; recorded")
        for p in unknown + again:
            it, age = items.get(p["key"]), self.now - p["at"]
            if it is None:
                if not self.led.has_pending(p["key"]):
                    pass  # cleared above, with a withheld repeat the mirror settled
                elif p["key"] in withheld:  # a run stopped between withholding it and clearing the mark
                    self.led.clear_pending(p["key"])
                elif age >= ledger.PENDING_EXPIRY:  # nothing to send again
                    self.led.expire_pending(p["key"], "no journal item 24 hours after the attempt", now=self.now)
                continue
            eid = self._delivery(it, p, events)
            if eid is not None:
                it["sent"] = eid
                self.save()  # the journal holds the id before the ledger records it, as after a send
                self.deliver(it)
                self.n["settled"] += 1
                _say(f"{p['key']} settled: the mirror shows it as {eid}; recorded")
            elif not p.get("idle") and age >= ledger.PENDING_EXPIRY and (
                    age >= GIVE_UP or it["channel"] in made
                    and -pull.MAX_AHEAD_S <= self.now - made[it["channel"]] <= MIRROR_FRESH):
                why = "not on the mirror 24 hours after the attempt" if age < GIVE_UP \
                    else "not seen on the mirror 72 hours after the attempt"
                # In the journal first: the item stays one a channel may have (drop_unsent_lowerings,
                # yields), and a later run still knows the first attempt's event as its delivery.
                it["tried"] = min(p["at"], it.get("tried", p["at"]))
                self.save()
                self.led.expire_pending(p["key"], why, now=self.now)
                self.n["resent"] += 1
                _say(f"{p['key']} {why}: sent again")

    def yields(self, e, level) -> bool:
        """True when a raise of thread ``e`` to ``level`` may be planned although work
        of the thread is journaled or withheld: all of it is work a raise may supersede.
        That is a reply of this thread which the relay has not acknowledged and whose
        block is a level below the raise's and nothing else (a lowering, whichever
        channels have it: the raise states the level in each), or ids, sources and a
        severity word and nothing else when no channel can have it (the thread records
        none of them and the item was never attempted; its candidate brings them again).
        Never while any send under the thread's ids has an unknown outcome, nor when
        anything else of the thread waits (a copy, a reply with a fix).

        Nothing is removed here. The work is noted in ``passed``: ``busy(passing=True)``
        and the drain pass over it, and ``enqueue`` removes it in the same save that
        journals the raise. A run that stops before then has lost nothing."""
        self.passed.pop(e.root_event_id, None)
        if self.led.pending_for(e.aliases):
            return False
        want, minor = _fold(e.aliases), {"aliases", "sources", "advisory_severity"}
        have = {s.get("url") for s in e.advisory.get("sources") or [] if isinstance(s, dict)}
        known = _fold([e.advisory.get("id"), *(e.advisory.get("aliases") or [])])

        def mine(it):
            return it["kind"] != "ja" and it["scope"] == e.scope and bool(
                _fold(it["ids"]) & want or it["root"] == e.root_event_id)

        def lesser(it):
            if it["kind"] != "reply" or it["sent"] is not None or it["root"] != e.root_event_id:
                return False
            try:  # what the reply says on the wire, not what the thread would be after it
                patch = json.loads(schema._last_block(it["text"]))
            except (TypeError, ValueError):
                return False
            if not isinstance(patch, dict) or not patch:
                return False
            if set(patch) == {"level"}:  # the raise is a level reply in every channel: it says the level last
                # kk2q: a withdrawal is below every level, and the raise ends it on every reader
                return wire.is_withdrawal(patch) or (patch["level"] in RANK and RANK[patch["level"]] < RANK[level])
            if not set(patch) <= minor or "tried" in it or it.get("retried"):
                return False
            # Ids and sources only. The thread's lists only grow, so one it already holds in
            # full was recorded from another channel, whatever was recorded after it.
            urls = {x.get("url") for x in patch.get("sources") or [] if isinstance(x, dict)}
            return not (urls <= have and _fold(patch.get("aliases") or []) <= known)

        out = [it for it in self.state["outbox"] if mine(it)]
        groups = [w for w in self.state["withheld"] if any(mine(it) for it in w["items"])]
        work = out + [it for w in groups for it in w["items"]]
        if not all(lesser(it) for it in work):
            return False
        if work:
            self.passed[e.root_event_id] = (out, groups, level)
        return True

    def _passing(self, it) -> bool:
        """This journal or withheld item is one a raise of its thread is about to replace."""
        return any(it is o or any(it is x for w in groups for x in w["items"])
                   for out, groups, _ in self.passed.values() for o in out or [None])

    def _clears(self, c, scope, entry) -> bool:
        """A candidate that raises its thread supersedes the lower-priority work in the
        thread's way (``yields``); one that would not raise supersedes nothing."""
        if entry is None or self.is_synthetic(c) or compose.is_synthetic(entry.advisory.get("id")):
            return False
        if entry.gone:  # kk2q: plan_known raises no withdrawn thread; the recompute does
            return False
        c, level, reason = self._rate(c, scope, entry)
        level = self._thread_level(level, reason, entry)[0]
        # 65xv: a raise plan_known will not plan must not pass over the thread's unsent work
        return RANK[level] > RANK[entry.level] and self._may_rise(c, scope, entry, level) and self.yields(entry, level)

    def make_way(self, merged):
        """Before the journal drains: a candidate that raises its thread passes over what
        is unsent there (``yields``), so the drain does not send a lowering only for the
        same run to raise it."""
        for c, scope in merged:
            scope, entry, _ = self._thread_for(c, scope)  # btqg: a joined member's too
            self._clears(c, scope, entry)

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
                    self.n["busy"] += 1  # unknown outcome: settled by a later run, as for English
                    continue
                if not self.deliver(it):
                    return
        except Exception as e:  # noqa: BLE001 - nothing here may reach the run's exit code
            self.n["ja_failed"] += 1
            _say(f"ja replies stopped: {e}")

    # ------------------------------------------------------------ curator translation

    def curator_events(self, fetch=None, root=TRUST_ROOT_PUBKEY, done=(), start=None):
        """(event, root id, of, channel) for each curator root or amendment in the mirror,
        oldest first, from after the backfill floor. None when the mirror cannot be read.
        Read from the copy without the relay-bot events this poster did not sign (``_own``,
        9cch): a forged translation marks nothing as translated, a curator's reply in a
        forged thread has no root here, and no forged block shapes an amended advisory.
        Raises sent.NotStarted when, with a checkpoint key, the copy could not be judged."""
        try:
            st = State.load(self.config.mirror_dir)
            if translate.bounded(lambda: pull.fetch(self.config.translate_mirror_url, st, fetch=fetch,
                                                    root_pubkey=root, now=self.now, checkpoint=False), 120).error is not None:
                return None
        except (translate.CallError, ValueError, OSError):  # a timeout, an unreadable mirror state
            return None
        m = st.manifest
        names = {self.channels[c]: c for c in ("feed", "critical")}  # the journal takes no other channel
        self.mirror_ids, out = set(st.events), []  # the whole copy: it only bounds the translate state
        # strict: the record may have been lost since ``translate_curator`` asked (the pull
        # above can take two minutes); the read that filters is the one that says so
        evs = self._own(st.events, m, strict=True)
        # What the bot has already translated, (thread root, of), so a lost translate file never reposts
        # (9cch: what this poster's record holds; a translation the record does not hold counts for nothing).
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
        if self.config.checkpoint_key_file is not None and not sent.started(self.config.sent_state):
            # 9cch: nothing is translated from a copy that cannot be judged yet. A translation
            # made from a forged block would be sent as the poster's own and never made again.
            # The signer starts the record at the end of this run; the next run translates.
            return "no-record"
        path = self.config.translate_state
        try:
            tr = _translate_state(path)
        except (OSError, ValueError, RecursionError):
            _say(f"translate state {path} unreadable; translating nothing")
            return "state-error"
        if tr["hold"] is not None or self.key_refused:  # c6ak: a wording 401/403 this run holds it too
            return "held"
        start = time.monotonic()  # the pass deadline covers the mirror and the replay too
        try:
            evs = self.curator_events(fetch, root, {k for k, v in tr["done"].items() if v in ("ok", "untranslated")}, start)
        except sent.NotStarted:  # lost between the question above and the read of the copy
            return "no-record"
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
            # A call starts only when the API's own deadline fits in what is left: never cut
            # short by a tighter one here, which could lose a 401 that answers late.
            if WORDING_SECONDS - self._wspent - (time.monotonic() - start) < translate.TIMEOUT:
                return None
            self._wasked += 1
            self.n["word_asked"] += 1
            try:
                w, outcome = wording.draft(c, scope, call=self._wcall)
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
            self._stand(eid, it, enrol=True)
            for o in self.state["outbox"]:  # its copies now name this thread, never a lookup
                if o["kind"] == "copy" and o["root"] is None and o["scope"] == it["scope"] \
                        and _fold(o["ids"]) & _fold(it["ids"]):
                    o["root"] = eid
        elif it["kind"] == "copy":
            e = self._entry(it)
            if ch not in e.channel_ids:  # aqtf: with the level its block states
                self.led.add_channel(e.root_event_id, ch, eid, (_block(it["text"]) or {}).get("level"))
            self._stand(e.root_event_id, it)
        elif it["kind"] == "reply":
            e = self._entry(it)
            if not any(r.get(ch) == eid for r in e.replies):
                adv = schema.validate(it["adv"])
                patch = self._patch(it)
                gone = wire.is_withdrawal(patch)  # kk2q: the state, not a level; the thread's advisory stays
                if gone:
                    adv = schema.validate(e.advisory)
                    self.withdrew.add(e.root_event_id)
                elif it.get("retried") or "tried" in it:
                    # jsje: sent, or settled, long after it was planned; the thread may have
                    # recorded other replies since. What it says on the wire is applied to
                    # the thread as it is now: its snapshot would undo them.
                    adv = compose.parse_reply(it["text"], schema.validate(e.advisory)) or adv
                m = candidates.BOT_ID.fullmatch(adv.id)
                low = [m.group(1) if m else adv.id, wire.WITHDRAWN if gone else adv.level]
                # ny5g: a lowering, recorded for its first channel (kk2q: so is entering the state)
                if (not e.gone) if gone else RANK[adv.level] < RANK[e.level]:
                    if low not in self.rc["lowered"]:  # for the digest; once, though a replay comes here again
                        self.rc["lowered"] = (self.rc["lowered"] + [low])[-recompute.MAX_LOWERED:]
                    recompute.note(self.rc, e.root_event_id, self.now)  # the breaker counts what was sent, once
                    self.save_rc()
                # gtw9: the level counts from the attempt's time, also when a later run records it
                at = [p["at"] for p in self.led.pending_entries() if p["key"] == it["key"]] + [it.get("tried", self.now)]
                self.led.record_reply(e.root_event_id, adv, {ch: eid}, now=self.now, exploited=it["exploited"],
                                      ids=it["ids"], changed_at=min(at),
                                      withdrawn=True if gone else False if "level" in patch else None,
                                      again=it.get("again") is True)
            self._stand(e.root_event_id, it)
        else:  # digest: acknowledge exactly the notices and ledger cutoff it was built from
            snap = set(it["adv"]["held"])
            keep = [h for h in self.state["held"] if not set(self._notice_keys(h["scope"], h["adv"])) <= snap]
            ids = self.state["digest_ids"]
            replayed = eid in ids
            if eid not in ids:  # a replay after a crash records it once
                ids = (ids + [eid])[-inputs.MAX_DIGEST_IDS:]
            if not replayed:  # jsje: this digest counted them
                self.state["dropped"] = max(0, self.state["dropped"] - it["adv"].get("dropped", 0))
                if it["adv"].get("foreign"):  # m729: and said the line for these
                    try:
                        sent.mark_said(self.config.sent_state, it["adv"]["foreign"])
                    except OSError as e:
                        _say(f"sent record not written ({e.strerror or type(e).__name__}): the next digest repeats its line")
            self.state.update(weekly=it["adv"].get("week", self.state["weekly"]),
                              digest_date=it["date"], digest_at=it["adv"]["cutoff"],
                              digest_roots=it["adv"]["roots"], digest_ids=ids,
                              held=keep, digested=(self.state["digested"] + sorted(snap))[-MAX_DIGESTED:])
            _say(f"digest {it['date']} sent: {eid}")

    @staticmethod
    def _parsed(text) -> dict | None:
        """The claim a tag's text holds when a reader takes it as a renewal (well formed,
        of a level), else None."""
        try:
            c = ruleset.parse_claim(wire.claim_of({"tags": [[wire.CLAIM_TAG, text]]}))
        except Exception:  # noqa: BLE001 - whatever the text holds, it is then no claim
            return None
        return c if c["level"] != ruleset.NONE else None

    def _stand(self, root, it, enrol=False):
        """gtw9: a sent item's claim of a level becomes its thread's standing claim, when
        it was checked no earlier than the one the ledger holds. ``enrol``: the item is the
        thread's first root, whose claim is what makes readers compute the thread's life.
        A reply's or a later copy's claim is kept only for a thread that has one already,
        so a thread whose first root carries none is never renewed or stepped down."""
        new = self._parsed(it.get("claim"))
        e = self.led.thread(root)
        if new is None or e is None or (e.claim is None and not enrol):
            return
        ids = e.root_ids if e.claim is not None else [it["adv"]["id"], *it["adv"]["aliases"]]
        if verify.norm_id(new["id"]) not in {verify.norm_id(i) for i in ids or ()}:
            return  # about an id a later reply brought: no renewal may rest on it (Entry.root_ids)
        old = self._parsed(e.claim)
        if old is None or new["checked_at"] >= old["checked_at"]:
            self.led.set_claim(root, it["claim"], None if e.claim is not None else ids)

    def busy(self, ids, scope, passing=False, learn=True) -> bool:
        """True when this advisory has journaled work or a send in flight. Its ids are
        learned by the overlapping items, so a later candidate under any of them waits too.
        ``passing``: asked for a raise, which passes over the work it will replace (yields).
        ``learn=False`` (btqg, a member joining by its fix): the items learn nothing, or
        their send would record it into the thread past the join's checks."""
        want, root = _fold(ids), getattr(self.led.lookup(ids, scope=scope), "root_event_id", None)
        hits = [it for it in self.state["outbox"] + self._withheld_items()  # withheld: until expire_withheld
                if it["kind"] != "ja" and it["scope"] == scope and (_fold(it["ids"]) & want or root and it["root"] == root)
                and not (passing and self._passing(it))]
        for it in hits if learn else ():
            it["ids"] = list(dict.fromkeys(it["ids"] + [i for i in ids if i.casefold() not in _fold(it["ids"])]))
        if hits and learn:
            self.save()
        return bool(hits) or bool(self.led.pending_for(ids))

    def enqueue(self, items, instead=None):
        """Journal ``items`` and send them. ``instead``: what ``yields`` noted for the
        thread these items raise; it leaves the journal and the withheld list in the same
        save that journals the raise, so no run can stop between the two."""
        if instead is not None:
            out, groups, level = instead
            for w in [w for w in groups if w in self.state["withheld"]]:
                self._unwithhold(w)
            work = out + [it for w in groups for it in w["items"]]
            self.state["outbox"] = [o for o in self.state["outbox"] if not any(o is it for it in out)]
            self.n["superseded"] += len(work)
            _say(f"{', '.join(it['key'] for it in work)} superseded by a raise to {level}")
        self.state["outbox"].extend(items)
        self.save()
        for it in items:
            if it in self.state["outbox"]:  # not withheld with a refused root
                self.deliver(it)

    # ------------------------------------------------------------ planning

    def page(self, url, allow):
        """One fetch per URL per run, MAX_RUN_PAGES in all (the ledger lock is held)."""
        if url not in self.pages:
            if len(self.pages) >= min(MAX_RUN_PAGES, self.page_cap):
                raise rules.PageBudget
            self.pages[url] = self.fetch_page(url, allow, rules.FETCH_TIMEOUT)
        return self.pages[url]

    def admit_all(self, pairs) -> list:
        """``admit`` for each (candidate, scope) of ``pairs``, in their order, with the
        lane's advisory reads given out in turn (ai-tools-alerts#vszx).

        ``admit`` asks for a candidate's advisory as it reaches it, and the collector
        keeps its order from hour to hour: asked that way, the first ``LANE_READS``
        candidates whose page confirms them took every read of every run, and the
        others were never read. So every candidate's evidence is read first (the pages,
        in the order ``admit`` would fetch them: ``rules.evidence`` knows the
        candidate, its scope and the page cache, nothing an admission changes), then
        the advisories those pages confirm are asked for, those never asked for first
        and the rest from where the last run's requests ended (``sources.in_turn``), and
        only then is each candidate admitted, from the evidence already read. ``admit``
        finds its read made, or not made this run. The turn is kept (``Config.admit_turn``) before
        anything is admitted; a file that cannot be written, or whose path is another
        file's (``Config.admit_turn_free``), is said and costs the next run its place,
        never this run its work."""
        evs = [rules.evidence(c, scope, self.page) for c, scope in pairs]
        asks = [i for ev in evs if ev.structured and ev.ghsa and (i := rules.ghsa_lookup(ev.ghsa)) is not None]
        self.asked = set(asks)  # for the line about unread ids: these came from pages, through ghsa_lookup
        path = self.config.admit_turn if self.config.admit_turn_free() else None
        after, seen = sources.load_turn(path) if path is not None else (None, frozenset())
        made, place = set(), after
        for i in sources.in_turn(asks, after, seen):
            before = self.api.requests
            self._admit_read(i)
            if self.api.requests > before:
                made.add(i)
                if i in seen:
                    place = i  # the ring's place; a first request is ahead of the ring and moves nothing
        if made:
            try:
                if path is None:
                    raise ValueError("its path is another file's")
                # Every id asked for stays remembered, in this run's record or not: a candidate
                # whose page fails for a run is not news when it answers again, or two groups
                # taking turns at failing would be first for good and the ring never move.
                sources.save_turn(path, place, sources.remembered(seen | made, self.asked))
            except (OSError, TypeError, ValueError) as e:
                _say(f"admission's place among the advisory reads not kept ({type(e).__name__}): "
                     "the next run asks for the same ids first")
        return [(a, scope) for (c, scope), ev in zip(pairs, evs) if (a := self.admit(c, scope, ev)) is not None]

    def admit(self, c, scope, ev=None):
        """c as an authoritative source states it, or None (h340). The candidate is a
        pointer (an id, a product, URLs); what goes on to the merge, a level, the held
        list and a post is what ``rules.evidence`` read from CISA's catalog or from the
        vendor's own page: the ids that source assigns, its fixed version, range, title
        and severity word, and as sources only the page that confirmed it, CISA's for a
        KEV entry and the global page of the vendor's own GHSA. A record's own severity
        text and model-read flags count only when a repository advisory page confirmed
        it and the record cites nothing else; a vendor site page alone makes a notice. Nothing confirmed and a fetch failed, a page did not parse or
        the page budget ran out: deferred to the next run, never dropped for that.
        ``ev``: the candidate's evidence when it was read already (``admit_all``)."""
        if not candidates.BOT_ID.fullmatch(c.id):
            self.skipped["id shape"] += 1
            return None
        if ev is None:
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
        readings = rules.readings_for(c, ev, self._admit_read)  # s6mt: what the level can rest on, as fields
        if ev.structured and ev.ghsa and not any(r[0] == "ghsa" for r in readings) and not self.is_synthetic(c):
            # 3qyq: the advisory API gave no reading (a failure, a 429, a spent share). The
            # candidate goes on as its other evidence rates it, and is admitted again each
            # run for RETRY_DAYS from first sight: a held notice whose fields support more
            # then posts, with no new input record.
            self.saw(scope.name, c.id)  # only a first sight on record bounds the retry: none, no retry
            if f"{scope.name}|{c.id.casefold()}" in self.state["waiting"] \
                    and self.now - self.first_seen(scope.name, [c.id]) < RETRY_DAYS * 86400:
                self.defer([(c, scope)])
        return replace(c, aliases=tuple(aliases), fixed=ev.fixed, affected=ev.affected, sources=tuple(kept),
                       source_title=title, source_text=text,
                       severity_word=ev.severity,  # dmmf: the page's word, alone
                       readings=readings,
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

    def _admit_read(self, i):
        """An advisory read for a candidate: the ``admit`` lane, which no thread's read spends."""
        return self.api.read(i, "admit")

    def _tied(self, c, entry=None):
        """c with only the ``ghsa`` readings the source ties to the first id of its
        post (``sources.tied``, from this run's reads): its thread's published id when
        it has one (``entry``), else its own. ``ledger.merge`` unions the readings of
        candidates that share an id or a fixed release, and a later sighting of one
        member alone arrives under that member's id; a member's check reads the
        thread's first id and ignores an advisory that id's source does not name. So
        does the level (3qyq)."""
        first = recompute.lookup_id(entry.advisory.get("id") if entry is not None else c.id)
        aliases = recompute.published_aliases(entry) if entry is not None else \
            [x for x in map(recompute.lookup_id, c.aliases) if x is not None]
        keep = tuple(r for r in c.readings if r[0] != "ghsa"
                     or sources.tied(first, json.loads(r[1]).get("ghsa_id"), self._admit_read, aliases))
        return c if keep == tuple(c.readings) else replace(c, readings=keep)

    def _rate(self, c, scope, entry):
        """(the candidate, its level, the reason) against its thread; ``entry`` is None
        for a new one."""
        c = self._tied(c, entry)  # 3qyq: only readings the source ties to the post's first id
        if entry is not None and entry.joined:
            # btqg: so too a KEV listing, on a thread an advisory joined by its fix: a member's
            # check reads the CVEs its first id names, so a joined advisory's own listing
            # neither raises the thread nor marks it exploited (``one`` lets a louder one out).
            first = recompute.lookup_id(entry.advisory.get("id"))
            kev = [r for r in c.readings if r[0] == "kev"]
            keep = [r for r in kev if sources.tied(first, json.loads(r[1]).get("cve_id"), self._admit_read,
                                                   recompute.published_aliases(entry))]
            if len(keep) < len(kev):
                c = replace(c, readings=tuple(r for r in c.readings if r[0] != "kev" or r in keep),
                            exploited=c.exploited if keep else False)
        if entry is not None and entry.lowered and c.exploited is True \
                and not any(r[0] == "kev" for r in c.readings):
            # ny5g: on a lowered thread the recompute holds the KEV level. A mark that no
            # KEV entry read this run stands behind (lent by the ledger when candidates were
            # merged, before the journal drained, or kept in the state file) raises nothing.
            c = replace(c, exploited=False)
        level, reason = self.level(c, scope)
        was = (entry.advisory.get("products") or [{}])[0].get("fixed") if entry is not None else None
        if entry is not None and reason in ("no-action", "stop-using") and compose.schema_fixed(c.fixed) is None:
            # 9kgk: the thread already states a fix, which plan_known keeps; the upgrade is complete.
            if compose.schema_fixed(was):
                level, reason = self.level(replace(c, fixed=was), scope)
        return c, level, reason

    @staticmethod
    def _thread_level(level, reason, entry):
        """(level, reason) as a known thread can take it."""
        if level == "critical" and entry.level != "critical" and (
                reason == "stop-using" or not compose.schema_fixed(entry.fix_at_root)):
            # 9kgk: a reply cannot add stop_using, and a fix a reply adds where the root had
            # none is held by every reader (tyje): the member would hold a critical with no
            # version. A thread is raised to critical only when its root stated the fix.
            return ruleset.load().action_cap, "no-action"
        return level, reason

    def _gone(self):
        """btqg: (retracted ids, withdrawn thread roots) as the mirror says now
        (``_withdrawn``), pulled once a run, the first time a candidate could join a
        thread by its fix; None when the pull failed, and no join this run."""
        if not hasattr(self, "_gone_now"):
            try:
                self._gone_now = self._withdrawn(*self.mirror)
            except (translate.CallError, OSError, ValueError) as err:  # StateError is a ValueError
                _say(f"join by fix held: {err}")
                self._gone_now = None
        return self._gone_now

    def _fix_thread(self, c, scope):
        """btqg: (scope, entry) of the open thread whose fixed version is c's, for a
        candidate with no thread of its own, or None. Under the product's name or a former
        one (wa6n), the oldest; never a synthetic thread, a withdrawn one (kk2q), one that
        has ended (65xv: it is no longer renewed and is running down, and a new advisory
        is news that gets a thread of its own), one the mirror shows retracted or expired, or any thread for a candidate whose own id is
        retracted (a reader retracts a whole thread for any one of its ids). A former name
        another scope entry also lists does not say which product its thread is about
        (``_scope_named``): none under it. Nor a thread whose ids and c's pass the one-block
        cap (``ledger.BLOCK_IDS``): a thread's ids stay what one block could name."""
        key = ledger.fix_key_of(c.fixed)
        if key is None or self.is_synthetic(c):
            return None
        index = rules._default_index().values()
        names = (scope.name, *(n for n in getattr(scope, "formerly", ())
                               if len({s.name for s in index if n in getattr(s, "formerly", ())}) == 1))
        mine = _fold([c.id, *c.aliases])
        found = [e for e in self.led.entries()
                 if e.scope in names and not e.gone and e.ended is None
                 and not (e.split or {}).get("released")  # yd1y: what left it does not come back by its fix
                 and not compose.is_synthetic(e.advisory.get("id"))
                 and ledger.fix_key_of((e.advisory.get("products") or [{}])[0].get("fixed")) == key
                 and len(_fold(e.aliases) | mine) <= ledger.BLOCK_IDS]
        if not found:
            return None
        gone = self._gone()
        if gone is None:
            return None  # the mirror cannot say: the candidate posts on its own, never waits for it
        ids, roots = gone
        if not ids.isdisjoint(mine):
            return None
        for e in found:  # every id the thread holds, published or learned
            if compose.withdrawn(schema.validate(e.advisory), ids, self.now) or not ids.isdisjoint(_fold(e.aliases)) \
                    or not roots.isdisjoint({e.root_event_id, *e.channel_ids.values()}):
                continue
            return (scope if e.scope == scope.name else replace(scope, name=e.scope, formerly=())), e
        return None

    def _thread_for(self, c, scope):
        """(scope, thread entry or None, joined): c's own thread, else (btqg) the open
        thread of its fix (``_fix_thread``). The thread's level and exploited mark rest on
        its first id (3qyq), which no source ties to c: a candidate that alone rates above
        the thread's level, or is exploited where the thread is not, joins nothing and
        posts its own root, so a join never changes either."""
        ids = [c.id, *c.aliases]
        scope = self._former(scope, ids)
        entry = self.led.lookup(ids, scope=scope.name)
        if entry is not None:
            return scope, entry, entry.member(ids) is not None  # a joined advisory sighted again
        got = self._fix_thread(c, scope)
        if got is None:
            return scope, None, False
        joined, e = got
        if not self._judged(c) or self._louder(c, scope, e):
            return scope, None, False
        return joined, e, True

    def _judged(self, c) -> bool:
        """btqg: c's own advisory reading is in hand this run, or c has no GHSA id to read.
        Without it (a read failed, a share spent) what c alone supports is unknown."""
        return not any(i.casefold().startswith("ghsa-") for i in (c.id, *c.aliases)) \
            or any(r[0] == "ghsa" for r in self._tied(c).readings)

    def _leaves(self, c, scope, e) -> bool:
        """btqg: a joined advisory sighted again leaves thread e when it is exploited where e
        is not (a KEV listing needs no advisory read), when its own fix is one e's does not
        cover (a later or an incomparable version), or, its reading in hand, when it alone
        rates above e."""
        if c.exploited is True and not e.exploited:
            return True
        mine = compose.schema_fixed(c.fixed)
        theirs = compose.schema_fixed((e.advisory.get("products") or [{}])[0].get("fixed"))
        if mine is not None and mine != theirs:
            a, b = versions.parse(mine), versions.parse(theirs)
            if a is None or b is None or a > b:
                return True
        return self._judged(c) and self._louder(c, scope, e)

    def _louder(self, c, scope, e) -> bool:
        """btqg: c alone rates above thread e, or is exploited where e is not. A thread's
        level and mark rest on its first id (3qyq), which no source ties to c."""
        return RANK[self._rate(c, scope, None)[1]] > RANK[e.level] or (c.exploited is True and not e.exploited)

    def _own_mark(self, c):
        """yd1y: c without an ``exploited`` mark that is not its own. A candidate for an id
        a thread released may carry the mark of the thread it left (``ledger.merge`` runs
        before the release and lends it): KEV's word comes with a KEV reading, or not at all."""
        if c.exploited is True and not any(r[0] == "kev" for r in c.readings) \
                and not self.released().isdisjoint(_base(i) for i in (c.id, *c.aliases)):
            return replace(c, exploited=False)
        return c

    def one(self, c, named):
        c = self._own_mark(c)
        ids = [c.id, *c.aliases]
        scope = own = self._former(named, ids)
        entry = self.led.lookup(ids, scope=scope.name)
        # btqg: a joined advisory's ids are never learned by the thread's work, whose send
        # would record them as the thread's own
        learn = entry is None or entry.member(ids) is None
        # jsje: a raise never waits behind lower-priority work on its own thread
        if self.busy(ids, scope.name, learn=learn) and not (
                self._clears(c, scope, entry) and not self.busy(ids, scope.name, passing=True, learn=learn)):
            self.n["busy"] += 1
            self.defer([(c, scope)])  # its update (a fix, a promotion) is planned once the send resolves
            return
        joined = False
        if entry is not None and entry.member(ids) is not None:
            joined = True  # btqg: a joined advisory sighted again keeps the join's rules
            if self._leaves(c, scope, entry):
                # it now says more than the thread can: it leaves and posts alone
                self.led.unjoin(entry.root_event_id, ids)
                scope = own = self._former(named, ids)
                entry, joined = None, False
        elif entry is None:
            scope, entry, joined = self._thread_for(c, scope)
        # btqg: joining now: the thread's work counts, found by its ids and root, not by c's
        if joined and self.led.lookup(ids, scope=scope.name) is None:
            both = [*entry.aliases, *ids]
            if self.busy(both, scope.name, learn=False) and not (
                    self._clears(c, scope, entry) and not self.busy(both, scope.name, passing=True, learn=False)):
                self.n["busy"] += 1
                self.defer([(c, own)])  # kept under its own id; it joins once the thread's send resolves
                return
        c, level, reason = self._rate(c, scope, entry)
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
                else self.plan_known(c, scope, level, reason, ids, entry, joined)
        except ValueError:  # compose refused something: the whole advisory is withheld
            self.n["withheld"] += 1
            return
        if items:
            self.enqueue(items, self.passed.pop(entry.root_event_id, None) if entry is not None else None)
            if any(it in self._withheld_items() for it in items):  # withheld: planned anew once it is dropped
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
        # 3qyq: a fix group's first member is its loudest, not its newest; the group is
        # news if any member is (faxq), so its age is its newest member's.
        dated = [d for m in self.groups.get((scope.name, c.id.casefold()), ()) if (d := _published(m.sources)) is not None]
        if dated:
            published = max([*dated, *([published] if published is not None else [])])
        w, key = self.state["waiting"], self._seen_key(scope.name, ids, f"{scope.name}|{c.id.casefold()}")
        # A KEV entry is exempt: the day CISA lists it is the news, whatever the advisory's age.
        if level != "notice" and not test and c.exploited is not True and published is not None \
                and seen - published > AGE_LIMIT and _base(c.id) not in self.released():
            # z360: not for a root led by an id a retired thread released: news when its group posted
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
        claim = self._claim(rules._readings(c), [adv.id, *adv.aliases], scope.name) if ROOT_CLAIMS else None
        ja = self._ja(compose.root_post_ja, adv, reason, compose.fix_unexpressed(c), title,
                      exploited=c.exploited is True, range_unexpressed=compose.range_unexpressed(c),
                      package=compose.package_of(scope), wording=w)
        return [self._item("root" if i == 0 else "copy", scope.name, ids, ch, text, key_id=c.id,
                           adv=asdict(adv), exploited=c.exploited, ja=ja,
                           source_title=title if i == 0 else None, floor=floor if i == 0 else None, claim=claim)
                for i, ch in enumerate(chans)]

    def _posted(self, h) -> bool:
        """A held notice has posted when every id it holds has a thread under its product's
        name, current or former (wa6n). Every id, not any: a held fix group (faxq) keeps
        its members as aliases, and one member's root leaves the others unposted."""
        names = {h["scope"]}
        for s in rules._default_index().values():
            if h["scope"] == s.name or h["scope"] in getattr(s, "formerly", ()):
                names.update({s.name, *getattr(s, "formerly", ())})
        return all(any(self.led.lookup([i], scope=n) is not None for n in names)
                   for i in [h["adv"]["id"], *h["adv"]["aliases"]])

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
                if self._struck(h):  # 9je7: it waits to be split (retire); what it took would go with it
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
                    # 9je7: with their sources, by which a member is judged if another is retracted
                    src = [asdict(s) for s in compose._sources([*h["adv"]["sources"], *adv.sources])]
                    h["adv"] = {**h["adv"], "aliases": ids, "products": [p], "sources": src}
                    self.save()
            # Members, not ids: an id new to a listed advisory (a CVE assigned later) is not news.
            fresh = [i for m in self.groups.get((scope, a["id"].casefold()), ())
                     if not any(f"{scope}|{k.casefold()}" in known for k in (m.id, *m.aliases))
                     for i in compose._ids([m.id, *m.aliases], None)]
            fresh = list(dict.fromkeys(fresh))
            if fresh and not any(h["scope"] == scope and not self._struck(h) and set(self._notice_keys(scope, h["adv"]))
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

    def _may_rise(self, c, scope, entry, level) -> bool:
        """Whether candidate ``c`` may raise its thread to ``level`` (65xv). A thread that
        has ended is raised only above the level it ended at: the sources still state
        that level, and that is no news. A thread no read has confirmed for 45 days less
        a day, which the poster has stepped down or is about to, and that this run's own
        reads do not confirm either, is raised only by a reading of fields: the claim the
        candidate's readings give for an id of the root must be of at least ``level``.
        Sent with the raise, it becomes the standing claim, confirmed now. A reading of
        prose would raise it for one TTL, to be stepped down again, for as long as
        candidates bring it."""
        if entry.ended is not None and RANK[level] <= RANK[entry.ended]:
            return False
        old = self._parsed(entry.claim)
        if old is None or self.now - old["confirmed_at"] < ruleset.UNCONFIRMED_DAYS * 86400 - STEP_EARLY \
                or self._confirming(entry, old)[0]:
            return True
        new = self._parsed(self._claim(rules._readings(c), entry.root_ids or [], scope.name))
        return new is not None and RANK[new["level"]] >= RANK[level]

    def plan_known(self, c, scope, level, reason, ids, entry, joined=False):
        """An update of ``entry``'s thread from candidate c. ``joined`` (btqg): c is an
        advisory that joins the thread by its fix, or one that did (``Entry.member``): the
        thread keeps its fix and headline, its range widens to cover c's, and c's ids are
        learned and never published (so it can leave, ``one``)."""
        prev = schema.validate(entry.advisory)
        level, reason = self._thread_level(level, reason, entry)
        # kk2q: nor does a candidate move a withdrawn thread: the recompute ends that state, by
        # a reply that names the level alone, from what this candidate taught (floor, KEV).
        if entry.gone or RANK[level] <= RANK[entry.level] or not self._may_rise(c, scope, entry, level):
            # a run never lowers a level; and 65xv: not every higher level is a raise
            level, reason = entry.level, None
        was = prev.products[0]
        stored = _fold(entry.aliases)
        fresh = [i for i in dict.fromkeys(ids) if i.casefold() not in stored and i != prev.id]
        if joined:  # btqg: one group for each advisory, a fix group's members apart, so each can leave
            members = self.groups.get((scope.name, c.id.casefold()), [c])
            for m in members:
                self.led.add_ids(entry.root_event_id, [m.id, *m.aliases], joined=True)
            have = _fold([i for m in members for i in (m.id, *m.aliases)])
            if rest := [i for i in ids if i.casefold() not in have]:  # with its first member's
                self.led.add_ids(entry.root_event_id, [members[0].id, *rest], joined=True)
        elif fresh:  # identity is learned whether or not a reply can say so (the 50-alias cap)
            self.led.add_ids(entry.root_event_id, fresh)
        hidden = set().union(*map(set, entry.joined or ())) | (_fold(ids) if joined else set())  # btqg
        title = (entry.source_title or compose.source_title(c)) if joined else compose.source_title(c)
        if title and not entry.source_title:  # learned late: the digest carries it; no reply says it
            self.led.learn_title(entry.root_event_id, title)
        own_fix = compose.schema_fixed(c.fixed) is not None and not joined  # btqg: one fix by the key
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
                       if i.casefold() not in prev_ids and compose.public_id(i) and i.casefold() not in hidden]
        k = replace(  # the thread's identity and everything already known, plus what is new
            c, id=prev.id, aliases=tuple(prev.aliases) + tuple(unpublished),
            fixed=c.fixed if own_fix else was.fixed,
            # a range the schema cannot say is kept raw when none is known: no "not stated" (0dvh)
            # faxq: one member's sighting never narrows a fix group's range, which covers them
            # all; a range that differs widens it to everything before the fix
            # btqg: so does a thread a member joined by its fix, before a reply names it;
            # the member joining widens it to cover the member's own
            affected=_join_range(was, c) if joined
            else _group_range(was, c, c.fixed if own_fix else was.fixed) if compose.covers(prev)[0] not in (0, 1)
            or entry.joined
            else c.affected if compose.schema_affected(c.affected) else (was.affected or c.affected),
            sources=tuple(prev.sources) + tuple(extra),
            source_title=title or entry.source_title)  # faxq: a copy's headline; btqg: the thread's when joined
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
        if changes and not joined and new.advisory_severity not in (None, prev.advisory_severity):
            changes["advisory_severity"] = new.advisory_severity  # 0dvh: never a reply on its own
        copies = [ch for ch in CHANNELS_FOR[level] if ch not in entry.channel_ids and not entry.gone]
        # hh5s: what this candidate's readings say of the thread, for a level change and
        # (ROOT_CLAIMS) for a copy, a root in its channel. Each is chosen among the ids its
        # own event leaves the thread with: a copy states them all, a level-only reply none new.
        def claim_for(ids):
            return self._claim(rules._readings(c), ids, scope.name)
        # gtw9: only for a thread whose first root carries one, so both roots are enrolled alike
        claim = (claim_for([new.id, *new.aliases]) or self._checked(entry)) \
            if copies and ROOT_CLAIMS and entry.claim is not None else None
        w = self.wording(k, scope, level, reason) if copies else None  # c6ak: a copy is a post
        if w is not None:
            text = compose.root_post(k, (level, reason), scope, posted_at=prev.posted_at, wording=w)[0]
        ja = self._ja(compose.root_post_ja, new, reason, compose.fix_unexpressed(k), title or entry.source_title,
                      exploited=k.exploited is True, range_unexpressed=compose.range_unexpressed(k),
                      package=compose.package_of(scope), wording=w) if copies else None
        items = [self._item("copy", scope.name, ids, ch, text, key_id=prev.id, exploited=c.exploited,
                            root=entry.root_event_id, ja=ja, claim=claim)
                 for ch in copies]
        if changes and entry.lowered and "level" in changes:
            # ny5g, spec/wire.md rule 2: on a thread that has had a lowering a level change
            # travels alone; whatever else this run learned follows in a reply without it.
            items += self._level_items(entry, changes.pop("level"), claim_for(self._stated(entry, prev)))
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
            # a reply with no level change carries none
            said = claim_for(self._stated(entry, merged, changes.get("aliases", ()))) if "level" in changes else None
            items += [self._item("reply", scope.name, ids, ch, reply, key_id=prev.id,
                                 adv=asdict(merged), exploited=c.exploited, root=entry.root_event_id, ja=ja,
                                 claim=said)
                      for ch in entry.channel_ids]
        return items

    def _withdrawal_items(self, entry, claim=None, channels=None):
        """The withdrawal (kk2q, ``compose.withdrawal_post``), one reply for each channel
        the thread has a root in, with the claim of the withdrawn reading. It is a level
        reply to the journal (the same key), so what holds for an unsent lowering holds
        for it; its ``adv`` is the thread's advisory, which it does not change.
        ``channels``: only these of the thread's channels (aqtf: the ones that lack it)."""
        prev = schema.validate(entry.advisory)
        text = compose.withdrawal_post()
        return [self._item("reply", entry.scope, entry.aliases, ch, text, key_id=f"{prev.id}#level",
                           adv=asdict(prev), exploited=entry.exploited, root=entry.root_event_id, claim=claim)
                for ch in entry.channel_ids if channels is None or ch in channels]

    def _level_items(self, entry, level, claim=None, reason=None, channels=None, again=False):
        """A level change and nothing else (``compose.level_post``), one reply for each
        channel the thread has a root in, each with the claim the change rests on
        (``_claim``; None: no reading states it). No Japanese copy: the digest reports it. A
        channel of the new level the thread has no root in gets its copy from ``copies``,
        which is a root there. ``reason``: a sentence for the reply's line (gtw9). On a
        withdrawn thread the level may be the one the thread kept (kk2q). ``channels``:
        only these of the thread's channels (aqtf: the ones that lack the reply).
        ``again``: the level may be the thread's own, for a reply that ends a withdrawal
        (kk2q) or one sent again to a channel that lacks it (aqtf). The line is worded
        for the thread's level; the block is what a reader applies, from whatever its
        channel stands at."""
        prev = schema.validate(entry.advisory)
        text = compose.level_post(prev, level, reason, again=again)
        return [self._item("reply", entry.scope, entry.aliases, ch, text, key_id=f"{prev.id}#level",
                           adv=asdict(replace(prev, level=level)), exploited=entry.exploited,
                           root=entry.root_event_id, claim=claim)
                for ch in entry.channel_ids if channels is None or ch in channels]

    def _claim_of(self, text) -> dict | None:
        """The claim a tag's text holds, of any level (``none`` too), else None."""
        try:
            return ruleset.parse_claim(wire.claim_of({"tags": [[wire.CLAIM_TAG, text]]}))
        except Exception:  # noqa: BLE001 - whatever the text holds, it is then no claim
            return None

    def reconcile(self, up: bool, skip=frozenset()):
        """Send each channel that lacks its thread's standing level reply that reply
        again (ai-tools-alerts#aqtf). The journal gives up a reply a channel refused
        twice (``_withhold``); the ledger still names the channel (``Entry.lacking``),
        so nothing is lost with the item: the reply is composed anew from the ledger,
        the withdrawal or the thread's level alone, and goes through the journal like
        any level reply.

        ``up``: the channels that show less than the thread holds (a lower level, or
        withdrawn under a standing level), which ``recompute`` sends before its
        lowerings; else the channels that show more. Never for a synthetic thread, a
        thread with work in flight (``busy``: a channel is tried again no sooner than
        the journal lets go of the last attempt), a thread a reply of which the relay
        refused in this run (the next run plans it; two refusals stop a run), nor a
        level for a thread whose withdrawal this run recorded (kk2q: the two could
        carry one second). Nor for a thread in ``skip``: one this run is about to lower,
        whose lowering goes to every channel and is the standing reply from then on. A
        refusal of such a reply does not count toward the two that stop a run
        (``deliver``), so every lacking thread is tried, whatever the others meet.

        The claim is the one that states the standing word: this run's reading of the
        thread, else for a level the standing claim checked now; none when neither does.
        The item is marked ``again``: recorded, the thread's channels no longer count as
        holding the same ids (``Entry.uneven``). Raises _Stop or LedgerError as any send."""
        for e in self.led.entries():
            word = e.standing
            rank = RANK.get(word, -1)
            lacking = [ch for ch, w in e.lacking.items() if (RANK.get(w, -1) < rank) == up]
            if not lacking or compose.is_synthetic(e.advisory.get("id")) or e.root_event_id in self.refused | set(skip) \
                    or (e.root_event_id in self.withdrew and not e.gone) or self.busy(e.aliases, e.scope):
                continue
            try:
                ids = [schema.validate(e.advisory).id]  # the channels differ: only the first id is in each
                want = ruleset.NONE if e.gone else word
                texts = [self._claim(getattr(self, "readings", {}).get(e.root_event_id, ()), ids, e.scope),
                         None if e.gone else self._checked(e)]
                claim = next((t for t in texts if t and (self._claim_of(t) or {}).get("level") == want), None)
                items = self._withdrawal_items(e, claim, lacking) if e.gone \
                    else self._level_items(e, word, claim, channels=lacking, again=True)
            except ValueError:  # compose refused it: tried again by the next run
                self.n["withheld"] += 1
                continue
            for it in items:
                it["again"] = True
            self.again.add(e.root_event_id)
            _say(f"{compose.public_form(e.advisory.get('id'))}: {', '.join(lacking)} lacks the reply "
                 f"that says {word}; sent again")
            self.enqueue(items)

    def drop_unsent_lowerings(self):
        """Before the journal drains: a lowering no channel has yet is not sent on the
        evidence of an earlier run. It leaves the journal, and this run sends it again
        only if a complete read still supports it (its wait is kept). One a channel
        already has stays, whatever this run reads: the thread's channels must agree. A
        channel has it when the relay acknowledged it (journaled as sent, though the
        ledger may not say so yet: a run that stopped between the two), when its outcome
        is unknown or was when the attempt expired (``tried``), or when the ledger already
        holds the lower level. A withdrawal (kk2q) is such a lowering until the ledger
        marks the thread withdrawn."""
        level_items = [it for it in self.state["outbox"] if it["kind"] == "reply" and "#level:" in it["key"]]
        had = {it["root"] for it in level_items if it["sent"] is not None or self.led.has_pending(it["key"])
               or "tried" in it}  # jsje: sent once with an unknown outcome, since expired
        gone = []
        for it in level_items:
            e = self.led.thread(it["root"])
            lowers = e is None or (not e.gone if wire.is_withdrawal(self._patch(it))
                                   else RANK[it["adv"]["level"]] < RANK[e.level])
            if it["root"] not in had and lowers:
                gone.append(it)
        if gone:
            self._drop(gone)

    def observe(self, kev_out: dict):
        """Judge every open thread that has a source to judge it by (the ledger marks it
        exploited, or it carries an advisory id: ``recompute.judged``) against this run's KEV
        copy and advisory reads, and save what that does to each wait, before anything is sent (ny5g). A
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
        st["exploited"] = {r: v for r, v in st["exploited"].items() if r in self.observed}
        self.verdicts, self.judged, self.known = {}, set(), set()
        self.readings: dict[str, list] = {}  # hh5s: root -> the readings its verdict rested on
        pages = len(self.pages)
        waits = sum(e.root_event_id in st["dwell"] for e in entries)
        for e in self._in_turn(entries):  # yd1y: each thread, then its members, in the thread's own turn
            # A thread is first in its lane once in as many hours as the lane has threads:
            # its members' turn moves on once in that time, not with the hour.
            lane = waits if e.root_event_id in st["dwell"] else len(entries) - waits
            self._judge([e], rs)
            self.part(e, rs, pages, self.now // 3600 // max(1, lane))
        if self.api.unread:
            # vszx: admission's are named, so two runs' lines show that they take turns. Only
            # those: ids a vendor's page stated, in the one shape ``rules.ghsa_lookup`` gives.
            # A thread lane can also be asked for an id a response named (``sources.chosen``),
            # and nothing a response says is printed.
            ids = sorted(self.api.unread & getattr(self, "asked", set()))
            more = f" and {len(ids) - UNREAD_NAMED} more" if len(ids) > UNREAD_NAMED else ""
            named = f"; of admission's: {', '.join(ids[:UNREAD_NAMED])}{more}" if ids else ""
            _say(f"advisory reads: {len(self.api.unread)} id(s) not read this run (the lane's share was spent); "
                 f"their threads are unknown and nothing of theirs moves{named}")
        st["open"] = None  # the observation is whole and saved: the next run may count from it
        self.save_rc()

    def _judge(self, entries, rs):
        """Judge each entry and keep its verdict by root: ("raise" | "due", level) or
        nothing. An entry with no source to judge it by (``recompute.judged``), out of
        scope now or with work in flight is not judged, and its wait takes no time for a
        run that did not look at it. In scope is by the thread's name
        (``rules.scope_named``, zmg2: a name is not always an identity), a former name
        too (aabw: ``recompute.support`` reads it as a member's check does, by
        ``Ruleset.stands_for``). Advisory reads are made here (3qyq), in the ``wait``
        lane for a thread whose wait is running and in ``rest`` for any other."""
        st = self.rc
        for e in entries:  # with no copy every read is unknown, and judge says so to each wait
            root = e.root_event_id
            self.verdicts.pop(root, None)
            self.readings.pop(root, None)
            self.known.discard(root)
            scope = rules.scope_named(e.scope, former=True) if recompute.judged(e) else None
            if scope is None or (
                    self.busy(e.aliases, e.scope) and not self._raise_clears(e, scope, rs)):
                self.judged.discard(root)
                recompute.pause(st, root)
                continue
            self.judged.add(root)
            lane = "wait" if root in st["dwell"] else "rest"

            def read(i, lane=lane):
                return self.api.read(i, lane)
            info: dict = {}
            verdict = recompute.judge(e, scope, self.copy, rs, st, self.now, read, info)
            if info.get("known"):
                self.known.add(root)
            self.readings[root] = info.get("readings") or []
            if verdict is not None:
                self.verdicts[root] = (e, *verdict)

    def part(self, e, rs, pages: int, turn: int = 0) -> None:
        """Release the members of thread ``e`` whose own source supports more than its
        first id does (ai-tools-alerts#yd1y; ``recompute.outlived``).

        A thread's level and claim rest on its first id (3qyq), and the other advisories
        of a fix group (faxq, btqg) are ids no source ties to it. When the first id's
        source is withdrawn or lowers while another member's own advisory still supports
        more, that member's alert falls with the thread on every member's machine, and
        the member keeps the thread unknown here, so not even the lowering completes.
        So, for a thread just judged: each member whose own response supports more than
        the first id's sources state leaves the thread's identity (``Ledger.release``, as
        z360's retired threads do), with the ids its response or its page assigns, and
        only with a pointer candidate, built from its own repository advisory page
        (``_judge_id``), which the next run plans like any deferred candidate: admitted
        from its page, grouped by fix with the others, posted as a root whose first id a
        member's check reads. One whose page assigns an id of the thread's own is no other
        advisory: it stays for good (``split``'s ``kept``). One whose page is not read this
        run, or is not a structured page naming it, stays and is tried again next run; at most RETIRE_PAGES new pages
        a run are fetched for this (``pages``: how many the run had read before), counted
        at each fetch.

        The members' responses are read in the thread's own lane right after its own
        (``observe``), so the thread that is first in its lane this hour has its members
        read too, and the members start one further on with each ``turn`` (once in as
        many hours as the lane has threads): reads spent on other threads, or on the
        members ahead, cannot keep one unread for good.

        The pointer is saved first, then the ledger: a run that stops between the two
        plans the pointer onto the old thread, as a sighting of the member is planned
        today, and releases again. The thread is then judged again, now by its first id
        alone, so a wait for a lower level starts in this run. A thread the manifest's
        retraction hides is ``retire``'s. A released id returns only if the first id's
        source comes to name it; if that source comes back there are two threads, and
        both are true. Never raises."""
        root = e.root_event_id
        bases = self.gone | {_base(i) for i in self.gone}
        if root not in self.judged or not bases.isdisjoint(_base(a) for a in e.aliases):
            return
        scope = rules.scope_named(e.scope, former=True)
        if scope is None:
            return
        lane = "wait" if root in self.rc["dwell"] else "rest"

        def read(i):
            return self.api.read(i, lane)
        out, cves = recompute.outlived(e, scope, self.copy, rs, self.rc, read, turn)
        theirs = {_base(i) for i, _ in out} | {_base(i) for i in cves}
        known = [e.advisory.get("id"), *(e.advisory.get("aliases") or ()), *e.aliases]
        # the first id and what its source ties: not this run's loose ids, nor ids released before
        # (the root still names those, and another member's page may assign one of them)
        own_ids = {_base(x) for x in known if isinstance(x, str)} - theirs \
            - {_base(x) for x in recompute.released(e)}
        released, kept, pointers = [], [], []
        for i, _ in out:
            own = next((x for x in known if recompute.lookup_id(x) == i), None)
            r = read(i)
            if own is None or r is None or own in released:
                continue
            self.page_cap = pages + RETIRE_PAGES  # at each fetch: one id's evidence can read several pages
            try:
                verdict = self._judge_id(e, own, bases)
            finally:
                self.page_cap = MAX_RUN_PAGES
            if verdict is not None and verdict[1] & own_ids:
                # Its own page assigns an id of the thread's (a vendor's GHSA whose API answer
                # does not name its CVE): no other advisory, and not asked again (``kept``).
                kept.append(own)
                continue
            if verdict is None or not verdict[0]:
                continue  # no page read, or none that proves the id: the next run tries again
            assigned = {_base(n) for n in r.names} | verdict[1]
            pointers.append(verdict[2])
            same = [a for a in e.aliases if _base(a) in assigned & theirs and a != own]
            released.extend(x for x in [own, *same] if x not in released)
        if not released and not kept:
            return
        for c in pointers:  # in place of a row for the same id, and kept past this run's end
            self.state["deferred"] = [d for d in self.state["deferred"] if not (
                d["product_text"] == c.product_text and d["id"].casefold() == c.id.casefold())] + [c.to_dict()]
            named = rules.scope_of(c.product_text)
            if named is not None:
                self.defer([(c, named)])
        self.save()  # the pointers first: a run that stops before the ledger write repeats it
        try:
            now = self.led.release(root, released, kept)
        except LedgerError as err:  # one thread's record never stops the run
            _say(f"{root[:12]}: members not released: {err}")
            return
        if not released:
            return
        self._released = None
        _say(f"{compose.public_form(e.advisory.get('id'))}: its first id supports less than a member's own source; "
             f"released {', '.join(released)}")
        self._judge([now], rs)  # by its first id alone from here on

    def _in_turn(self, entries):
        """The order threads are read in (3qyq): those with a wait running, then the
        rest, each group in a stable order that starts one thread further on every
        hour. So every thread is first in its lane once in as many hours as the lane
        has threads, and reads that keep failing ahead of it cannot keep it unread."""
        dwell = self.rc["dwell"]
        out = []
        for group in ([e for e in entries if e.root_event_id in dwell],
                      [e for e in entries if e.root_event_id not in dwell]):
            group.sort(key=lambda e: e.root_event_id)
            k = (self.now // 3600) % len(group) if group else 0
            out += group[k:] + group[:k]
        return out

    def _raise_clears(self, e, scope, rs) -> bool:
        """jsje: a busy thread this run's reads raise supersedes the lower-priority
        work in its way (``yields``), and is then judged like any other."""
        lane = "wait" if e.root_event_id in self.rc["dwell"] else "rest"  # 3qyq: as _judge reads it
        level = recompute.raised(e, scope, self.copy, rs, lambda i: self.api.read(i, lane))
        return level is not None and self.yields(e, level) and not self.busy(e.aliases, e.scope, passing=True)

    def recompute(self, trust_root=TRUST_ROOT_PUBKEY, fetch=None):
        """Send what the verdicts say (ny5g): a raise now; a lowering when the thread
        has had seven quiet days and the circuit breaker lets it through. The run has
        drained the journal and planned its candidates since ``observe``, so every
        thread that was not judged there (posted by this run, or busy then), and every
        thread whose ledger entry is no longer the one judged (a candidate added an id,
        a floor, a fix, another level), is judged again now, from the entry as it is:
        no verdict outlives the entry it was reached on, and the reply is composed from
        the current advisory. The breaker's share is of the threads judged, the only
        ones that can be lowered: a ledger full of other threads must not make a mass
        lowering look small. Last, ``copies`` posts the copy a thread's level lacks
        (3t4p); ``trust_root`` and ``fetch`` are its mirror pull's, as ``digest``'s."""
        st = self.rc
        now = [e for e in self.led.entries() if not compose.is_synthetic(e.advisory.get("id"))]
        self._judge([e for e in now if e.root_event_id not in self.judged
                     or (e.root_event_id in self.verdicts and self.verdicts[e.root_event_id][0] != e)],
                    ruleset.load())
        live = {e.root_event_id for e in now}
        # Not busy when judged, and not busy now: a candidate of this run can leave work in
        # flight under a thread's ids without touching its entry (a refused item of a thread
        # that shares an id), and nothing is sent on top of work in flight.
        found = [v for root, v in self.verdicts.items()
                 if root in live and not self.busy(v[0].aliases, v[0].scope, passing=v[1] == "raise")]
        # kk2q: a thread whose withdrawal this run recorded is not brought back by this run
        raises = [(e, level) for e, kind, level in found if kind == "raise" and e.root_event_id not in self.withdrew]
        due = recompute.select([(e, level) for e, kind, level in found
                                if kind == "due" and recompute.quiet(e, self.now)], len(self.known & live), st, self.now)
        self.save_rc()
        # 3qyq: KEV listed these threads; the ledger says so from now on. Here, after this
        # run's candidates were planned (plan_known reads the mark) and after the last
        # judging above, which is where a thread posted by this run is first seen listed.
        for root in st["exploited"]:
            if root in live:
                self.led.mark_exploited(root)
        for raising, verdicts in ((True, raises), (False, due)):
            for e, level in verdicts:
                try:
                    ids = self._stated(e, schema.validate(e.advisory))
                    claim = self._claim(self.readings.get(e.root_event_id, ()), ids, e.scope)
                    only = None
                    if e.gone and e.lacking and RANK[level] <= RANK[e.level]:
                        # kk2q: some channel never took the withdrawal and stands at a level
                        # of its own. The thread returns to the ledger's level in every
                        # channel (aqtf: that one too, for the reply's date); a fall from it
                        # is a lowering's.
                        level = e.level
                    if level == wire.WITHDRAWN:  # aqtf: not to a channel whose last word it already is
                        only = [ch for ch in e.channel_ids if e.word(ch) != wire.WITHDRAWN]
                    items = self._withdrawal_items(e, claim, only) if level == wire.WITHDRAWN \
                        else self._level_items(e, level, claim, again=e.gone)
                except ValueError:  # compose refused it: this thread's change is withheld
                    self.n["withheld"] += 1
                    continue
                # its wait stays until the ledger shows the level: see drop_unsent_lowerings
                self.enqueue(items, self.passed.pop(e.root_event_id, None) if raising else None)
            # aqtf: a channel that lacks a raise shows less than the poster holds, so it goes
            # before this run's lowerings; a channel that shows more goes after them. Not
            # for a thread about to be lowered: the two replies could carry one second.
            self.reconcile(up=raising, skip={e.root_event_id for e, _ in due} if raising else ())
        self.copies(trust_root, fetch)

    @staticmethod
    def _scope_named(name):
        """The scope entry a thread is filed under, by its stored name or a former one
        (``catalog._scope``; a display name is not always an identity, so not
        ``scope_of``). A former name several entries share (the MCP servers were one
        entry once) does not say which of them the thread is about: the scope then keeps
        the name and names no package, so a copy never states another product's."""
        scope = catalog._scope(name)
        entries = rules._default_index().values()
        if scope is not None and not any(s.name == name for s in entries) \
                and len({s.name for s in entries if name in getattr(s, "formerly", ())}) > 1:
            scope = replace(scope, package=None)
        return scope

    def copies(self, trust_root=TRUST_ROOT_PUBKEY, fetch=None):
        """Post the copy a thread's level lacks (ai-tools-alerts#3t4p): for every thread
        with a channel of its level (``CHANNELS_FOR``) it has no root in, a root there,
        composed from the ledger's advisory as it stands (``compose.copy_post``), with the
        Japanese reply a copy has. Last in ``recompute``, from the ledger as the run's
        sends left it: a feed-only thread the recompute has just raised to critical is
        critical there and gets its copy in this run; a raise the relay refused left it
        at high and it gets none. No candidate is needed, so this also plans again a
        copy the relay refused and ``expire_withheld`` dropped, and one compose refused
        in an earlier run.

        Not for a synthetic thread (it takes no update), a thread whose product the scope
        file no longer has under its name or a former one (``_scope_named``), or a thread with work in
        flight (``busy``): a journaled, withheld or unknown copy is never planned twice.
        Nor for a withdrawn advisory, which is never announced again: the mirror is
        pulled, only when some thread lacks a copy, and a retracted id, a retracted
        thread and an expired one get none (``_withdrawn``, as the digest). When the
        pull fails no copy is planned this run. A copy compose refuses is withheld for
        this run. Either is tried again by the next run."""
        want = []
        for e in self.led.entries():
            # kk2q: a withdrawn thread keeps its level in the ledger and is announced nowhere
            missing = [ch for ch in CHANNELS_FOR.get(e.level, ()) if ch not in e.channel_ids and not e.gone]
            scope = self._scope_named(e.scope) if missing and not compose.is_synthetic(e.advisory.get("id")) else None
            if scope is not None and not self.busy(e.aliases, e.scope):
                want.append((e, scope, missing))
        if not want:
            return
        try:
            gone, gone_roots = self._withdrawn(trust_root, fetch)
        except (translate.CallError, OSError, ValueError) as err:  # StateError is a ValueError
            _say(f"copies held: {err}")
            return
        for e, scope, missing in want:
            try:
                adv = schema.validate(e.advisory)
                if compose.withdrawn(adv, gone, self.now) or not gone_roots.isdisjoint(
                        {e.root_event_id, *e.channel_ids.values()}):
                    continue
                text = compose.copy_post(adv, scope, title=e.source_title, exploited=e.exploited)
                # gtw9: a root in its channel, enrolled as the thread's first root is: the claim
                # this run's reads state, else the standing one, checked now. None for a
                # thread whose first root carries none (a copy must not enrol it).
                claim = (self._claim(getattr(self, "readings", {}).get(e.root_event_id, ()), [adv.id, *adv.aliases], e.scope)
                         or self._checked(e)) if ROOT_CLAIMS and e.claim is not None else None
                ja = self._ja(compose.root_post_ja, adv, compose.title_reason(adv), False, e.source_title,
                              exploited=e.exploited is True, package=compose.package_of(scope))
                items = [self._item("copy", e.scope, e.aliases, ch, text, key_id=adv.id, exploited=e.exploited,
                                    root=e.root_event_id, ja=ja, claim=claim) for ch in missing]
            except ValueError:
                self.n["withheld"] += 1
                continue
            self.enqueue(items)

    # ------------------------------------------------------------ renewals (gtw9)

    def _checked(self, e) -> str | None:
        """The thread's standing claim with ``checked_at`` now: what a check that could
        not confirm says. None for a thread with none, or a clock behind its last check."""
        old = self._parsed(e.claim)
        if old is None or self.now < old["checked_at"]:
            return None
        try:
            return wire.claim_tag({**old, "checked_at": self.now})[1]
        except ValueError:
            return None

    def _confirming(self, e, old) -> tuple[bool, str | None]:
        """(whether this run's reads confirm the thread's level, the text of the renewal's
        claim when they do). Confirmed: the thread was judged (``_judge``) and, of the
        readings its verdict rested on, the one chosen for its ids gives no less than the
        level being kept, the lower of the standing claim ``old``'s and the ledger's. A
        read that failed, was not made or cannot lower, a thread not judged, and a source
        that now states less do not confirm. The text is the new claim, or, when that no
        longer fits a tag (the size of a reading is no failure to confirm), ``old`` with
        both times now: the fields of the last reading that fit."""
        root = e.root_event_id
        if root not in getattr(self, "judged", ()) or not e.root_ids:
            return False, None
        try:
            ids = e.root_ids  # what the first root stated: every reader of the thread holds them
            read = getattr(self, "readings", {}).get(root, ())
            whole = rules.claim_text(read, ids, e.scope, self.now, limit=False)
            new = ruleset.parse_claim(json.loads(whole)) if whole else None
        except (ValueError, RecursionError):  # a RulesetError is a ValueError
            return False, None
        kept = min(_CLAIM_RANK[old["level"]], RANK[e.level])
        if new is None or _CLAIM_RANK.get(new["level"], -1) < kept or new["level"] == ruleset.NONE:
            return False, None
        text = self._claim(read, ids, e.scope)
        if text is None:
            try:
                text = wire.claim_tag({**old, "confirmed_at": self.now, "checked_at": self.now})[1]
            except ValueError:
                return False, None
        return True, text

    @staticmethod
    def _life(e, rs, confirmed_at, checked_at) -> int:
        """The last second a reader keeps the thread at its ledger level, as the reader
        computes it (``Ruleset.stands_until``): by a claim with these times, or by the
        thread's last level change, which a reader counts as a renewal of its own date."""
        t = max(e.changed or [0])
        return max(rs.stands_until(e.level, confirmed_at, checked_at), rs.stands_until(e.level, t, t) if t else 0)

    def renew(self):
        """Keep every enrolled thread (one with a standing claim) standing on readers, and
        step down the level nothing confirms (module docstring; docs/superpowers/specs/
        2026-11-26-gtw9-renewals-and-step-down-design.md).

        For each: ``life`` is how long what was sent keeps its level standing, ``best``
        how long a renewal sent now would: the claim this run's reads confirm
        (``_confirming``), else the standing claim checked now. When ``best`` is under
        STEP_EARLY away (45 days since the last confirmation, or the level's TTL since
        the step that brought it there), a level above notice is lowered one step through
        the journal, as every lowering is, with the reason in its line. Otherwise a
        renewal is due when under half the level's TTL is left and it adds life, or when
        the checkpoint state was lost since the claim was checked (``signer.load_owed``:
        what was owed is forgotten, so every thread is renewed and owed anew).

        A thread whose level last changed RENEW_DAYS ago, with no work in flight, ends
        here (65xv, ``Ledger.end``). An ended thread is not renewed and no read confirms
        it, so ``best`` is ``life`` and each level is stepped down as that runs out, the
        line giving its age. One renewal it still gets: after a lost checkpoint state,
        while its life has not run out, a renewal that this run's reads confirm, which
        makes redundant whatever acknowledged renewal the ledger never recorded. Until
        a run can send that, its roots are left out of the checkpoint. One whose life by
        the ledger has run out is sent nothing and stays listed: unlisted, it would show
        again on every reader that still stores it.

        A renewal is a reply with no block in each of the thread's channels, at most
        MAX_RENEWALS sends a run, the due threads in an order that starts one further on
        each hour. It is not journaled: the ledger takes the new claim when every channel
        acknowledged it, a thread whose send was not is left for the next run, and three
        such sends end the pass. ``unrenewed`` then holds the roots of each thread whose
        due renewal or step is undelivered with under two hours of life left, of each
        whose renewal after a lost checkpoint state is undelivered, and of each channel
        that lacks a journaled level reply: the checkpoint leaves them out, since listed
        they would decay for want of an event the poster failed to send. A level reply
        sent before the loss is not replaced by such a renewal: see ``level_changes``.
        Raises _Stop or LedgerError as a step down's send does."""
        try:
            self._renew()
        finally:  # also when a step's send stopped the run: what is unsent must not be vouched for
            for it in self.state["outbox"] + self._withheld_items():
                e = self.led.thread(it["root"]) if it["kind"] == "reply" and it["sent"] is None \
                    and "#level:" in it["key"] else None
                if e is not None and e.claim is not None and it["channel"] in e.channel_ids:
                    # A level reply this channel lacks: the ledger's level, and so ``life``,
                    # may already count it (another channel took it). Not listed until sent.
                    self.unrenewed.add(e.channel_ids[it["channel"]])
            for e in self.led.entries():
                if e.claim is not None:
                    # aqtf: so is a level reply the journal gave up, until the channel takes it
                    self.unrenewed |= {e.channel_ids[ch] for ch in e.lacking}

    def _renew(self):
        rs, due, steps = ruleset.load(), [], []
        lost, soon = None, self.now + 2 * 3600
        if self.config.checkpoint_key_file is not None:
            # What was owed was forgotten when this hold began (it stays in the record after
            # it ends): every claim checked before then is renewed, due or not.
            hold = signer.load_owed(self.config.owed_state, self.now)["hold_until"]
            lost = hold - signer.OWED_S if hold > 0 else None

        def lapsing(life, e, anyway=False):
            if life < soon or anyway:
                self.unrenewed |= {e.root_event_id, *e.channel_ids.values()}
        for e in self.led.entries():
            old = self._parsed(e.claim)
            if old is None or compose.is_synthetic(e.advisory.get("id")) or self.now < old["checked_at"]:
                continue
            if e.gone:
                # kk2q: no renewal and no step. A step names a level, which ends the withdrawal
                # on every reader; the thread decays there as its claims say, and the
                # checkpoint keeps listing it (``signer.lapsed``).
                continue
            ended = e.ended is not None
            if not ended and self.now - max([e.posted_at, *(e.changed or ())]) >= RENEW_DAYS * 86400 \
                    and not self.busy(e.aliases, e.scope):
                e, ended = self.led.end(e.root_event_id, e.level), True
            life = self._life(e, rs, old["confirmed_at"], old["checked_at"])
            if ended:
                # A renewal the ledger never recorded may be newer than its claim: only a
                # confirmation made now covers it. Nothing is sent to a thread off readers.
                # Past the ledger's life nothing is sent and its roots stay listed: a thread
                # a checkpoint does not list is not judged, so a reader that still stores an
                # expired one would show it again, and a renewal would bring it back too.
                forced = lost is not None and old["confirmed_at"] < lost and life >= self.now
                fresh, text = self._confirming(e, old) if forced else (False, None)
                if forced and not fresh:
                    lapsing(life, e, anyway=True)
            else:
                forced = lost is not None and old["checked_at"] < lost
                fresh, text = self._confirming(e, old)
            best = self._life(e, rs, self.now if fresh else old["confirmed_at"], self.now) if fresh or not ended else life
            if not fresh and best - self.now <= STEP_EARLY:
                if RANK[e.level] > 0:
                    if self.busy(e.aliases, e.scope) or e.root_event_id in self.again:
                        # its step, or other work of the thread, is in flight; or (aqtf) a
                        # reply sent again in this run names a level in the same second
                        lapsing(best, e)
                    else:
                        steps.append((best, e, old))
                continue
            if ended:
                if fresh:
                    due.append((life, e, text, True))
                continue
            # A read that confirms a claim sent unconfirmed is sent at once: kept only in a
            # renewal, a confirmation between two renewals would be lost to the 45-day count.
            if forced or (fresh and old["checked_at"] > old["confirmed_at"]) or (life - self.now <= rs.ttl_days[e.level] * 86400 // 2 and best > life):
                due.append((life, e, text if fresh else self._checked(e), forced))
        due.sort(key=lambda x: x[1].root_event_id)
        k = (self.now // 3600) % len(due) if due else 0
        left, failed = MAX_RENEWALS, 0
        for life, e, text, forced in due[k:] + due[:k]:
            ok = None
            if text is not None and len(e.channel_ids) <= left and failed < 3:
                left -= len(e.channel_ids)
                ok = self._send_renewal(e, text)
                failed += ok is False
            if not ok:
                lapsing(life, e, anyway=forced)
        for best, e, old in steps:
            if not self._step_down(e, old):
                lapsing(best, e)

    def level_changes(self) -> list:
        """``(root, t, u)`` for each channel root of a thread with a standing claim whose
        level last changed before the checkpoint state was lost (p93w): ``t`` when the
        reply was first attempted, ``u`` when the run that recorded it began. The state
        file was the only memory that the relay acknowledged that reply, and a reader
        counts it as a renewal of its own date; the signer leaves the root out until its
        copy of the mirror holds the reply or a later confirmation (``signer.answered``).
        Empty when no loss is on record. A level change after the loss is owed in the
        new record. A thread in the state ``withdrawn`` (kk2q) is not passed: its last
        change is the withdrawal, which names no level and renews nothing on a reader, so
        a reader that lacks it loses no life; and the poster neither renews nor steps the
        thread there, so nothing would end the wait (``signer.lapsed`` lists it too)."""
        if self.config.checkpoint_key_file is None:
            return []
        hold = signer.load_owed(self.config.owed_state, self.now)["hold_until"]
        if hold <= 0:
            return []
        lost = hold - signer.OWED_S
        return [(root, max(e.changed), e.last_change) for e in self.led.entries()
                if e.claim is not None and not e.gone and e.changed and max(e.changed) <= lost
                for root in sorted({e.root_event_id, *e.channel_ids.values()})]

    def _step_down(self, e, old) -> bool:
        days = (self.now - (e.posted_at if e.ended is not None else old["confirmed_at"])) // 86400
        lower = next(lv for lv, r in RANK.items() if r == RANK[e.level] - 1)
        reason = compose.AGED if e.ended is not None else compose.UNCONFIRMED  # 65xv: it has ended
        try:
            items = self._level_items(e, lower, self._checked(e), reason.format(days=days))
        except ValueError:  # compose refused it: nothing is journaled, and the caller says so
            self.n["withheld"] += 1
            return False
        why = f"is {days} days old and no longer renewed" if e.ended is not None else f"no source confirmed {e.level} for {days} days"
        _say(f"{compose.public_form(e.advisory.get('id'))}: {why}; lowered to {lower}")
        self.enqueue(items)
        return True

    def _send_renewal(self, e, text) -> bool | None:
        """Send one thread's renewal to each of its channels. True when every channel
        acknowledged it (the ledger then holds the claim); None when the relay refused
        one or it is not sendable; False when a send failed or gave no answer."""
        body, tag = compose.renewal_post(), [wire.CLAIM_TAG, text]
        for ch, root in sorted(e.channel_ids.items()):
            try:
                transport.check_send(self.channels[ch], body, root, tag)
            except (ValueError, KeyError):
                self.n["renew_failed"] += 1
                return None
            r = self.send(self.channels[ch], body, root, tag)
            if r.outcome != "ok":
                self.n["renew_failed"] += 1
                _say(f"renewal of {compose.public_form(e.advisory.get('id'))} in {ch} {r.outcome}: the next run sends it")
                return None if r.outcome == "refused" else False
            self._owed(r.event_id, body, tag, root, reply=True)
            self.n["renewed"] += 1
        self.led.set_claim(e.root_event_id, text)
        return True

    def _withdrawn(self, root, fetch=None) -> tuple[set, set]:
        """(case-folded advisory ids, root event ids) withdrawn under ``root`` as of a
        mirror pull made now: the manifest's retracted ids (whoever posted them), and the
        root of every thread that is retracted or, as amended, expired (that thread only:
        another product's post of the same id stays). Raises when the pull fails.
        Read without the relay-bot events this poster did not sign (``_own``, 9cch)."""
        st = State.load(self.config.mirror_dir)
        res = translate.bounded(lambda: pull.fetch(self.config.translate_mirror_url, st, fetch=fetch,
                                                   root_pubkey=root, now=self.now, checkpoint=False), 120)
        if res.error is not None:
            raise ValueError(f"mirror pull: {res.error}")
        m = st.accepted(root)
        roots = set()
        for t in pull.threads_from(list(self._own(st.events_for(root), m).values()), m):
            t = pull.standing(t, self.now)  # c1g2: a curator's retraction of a bot thread lapses
            if t.retracted or (t.adv.expires_at is not None and t.adv.expires_at < self.now):
                roots.add(t.root_id)
        return {i.casefold() for i in m.retracted}, roots

    # ------------------------------------------------------------ partial retraction (z360)

    def retire(self, root=TRUST_ROOT_PUBKEY) -> None:
        """Release the still-valid ids of every thread the manifest's retraction hides.

        A fix group (faxq) is one root: retracting one member hides the others with it,
        and their sightings find the hidden thread. From the poster's own copy of the
        mirror as the last pull left it (no fetch here), a thread is retired when the
        reader hides it now because of the manifest: retracted under the stored manifest
        and not under the same one with no retracted ids, each as ``pull.standing`` has
        it now (the reader's own rule; a curator's retraction, while it holds, is not
        one). Only a thread whose ledger ids include a retracted one is judged: one
        hidden by a curator's alias is left as it is. Each other id the thread's
        advisory publishes is judged once, by its own repository advisory page: released
        when that page is structured, names the id and assigns no retracted id, kept
        when a page answers otherwise (the retracted advisory's own CVE) or no source
        confirms it, and left for the next run when a page could not be read (with the
        ids of advisories that joined the thread by fix, btqg, never published). On doubt
        the retraction wins. Ids are compared by their base (a thread key's slug
        dropped), so a retracted ``CVE-...:slug`` keeps its bare CVE and GHSA.

        A released id goes into the state's deferred list as a pointer candidate (saved,
        in place of any row for the same id), then leaves the thread's identity in the
        ledger with every learned id its page assigns (``Ledger.release``), so the run
        plans it like any deferred candidate: admitted from its own page, grouped by
        fix with the other survivors, and posted as a new root. The work starts at a
        different thread each hour, so ids whose pages keep failing never starve the
        rest of the RETIRE_PAGES budget. Sets ``gone`` for the run. Never raises."""
        try:
            st = State.load(self.config.mirror_dir)
            m = st.accepted(root)
        except (ValueError, OSError):
            return
        if m is None or not m.retracted:
            return
        self.gone = frozenset(i.casefold() for i in m.retracted)
        bases = self.gone | {_base(i) for i in self.gone}
        try:
            self._retire_held(bases)  # 9je7: whatever the threads below give
        except LedgerError:  # the state not written: as any save of the run
            raise
        except Exception as e:  # noqa: BLE001 - a notice never stops the run
            _say(f"held notices not split: {type(e).__name__}")
        try:
            events = list(self._own(st.events_for(root), m).values())  # 9cch: never a post it did not sign
            hidden = {t.root_id for t in pull.threads_from(events, m) if pull.standing(t, self.now).retracted}
            hidden -= {t.root_id for t in pull.threads_from(events, replace(m, retracted=()))
                       if pull.standing(t, self.now).retracted}
        except Exception as e:  # noqa: BLE001 - a damaged copy never stops the run
            _say(f"retired threads not read: {type(e).__name__}")
            return
        work = []  # per retired thread, its undecided ids, GHSA ids first (a CVE is often decided with its GHSA)
        for e in self.led.entries():
            if hidden.isdisjoint({e.root_event_id, *e.channel_ids.values()}):
                continue
            back = [i for i in (e.split or {}).get("released", ()) if _base(i) in bases]
            if bases.isdisjoint(_base(a) for a in [*e.aliases, *back]):
                continue  # hidden by an id the poster never held (a curator's alias): not judged
            done = {_base(x) for k in ("released", "kept") for x in (e.split or {}).get(k, ())}
            mine = {_base(a) for a in e.aliases}
            joined = [i.upper() if i.startswith("cve-") else "GHSA" + i[4:] for g in e.joined or () for i in g]
            ids = [i for i in [e.advisory.get("id"), *(e.advisory.get("aliases") or ()), *joined]  # btqg: joined too
                   if isinstance(i, str) and candidates.BOT_ID.fullmatch(i) and not compose.is_synthetic(i)
                   and _base(i) in mine and _base(i) not in bases | done]
            if ids:
                work.append([(e, i) for i in sorted(dict.fromkeys(ids), key=lambda i: not i.upper().startswith("GHSA"))])
        if not work:
            return
        k = (self.now // 3600) % len(work)  # threads, not ids, rotate: a GHSA stays ahead of its CVE
        work = [x for thread in work[k:] + work[:k] for x in thread]
        start, verdicts = len(self.pages), {}  # root -> (entry, released, kept, pointers)
        for e, i in work:
            _, released, kept, _ = verdicts.setdefault(e.root_event_id, (e, [], [], []))
            if _base(i) in {_base(x) for x in released + kept}:
                continue  # decided with another id of its advisory
            if len(self.pages) - start >= RETIRE_PAGES:
                continue  # the rest wait for the next run
            verdict = self._judge_id(e, i, bases)
            if verdict is None:
                continue  # no page read: the next run tries again
            ok, assigned, pointer = verdict
            same = [a for a in e.aliases if _base(a) in assigned | {_base(i)} and _base(a) not in bases]  # learned ids too
            (released if ok else kept).extend(x for x in [i, *same] if x not in released + kept)
            if ok:
                verdicts[e.root_event_id][3].append(pointer)
        judged = [v for v in verdicts.values() if v[1] or v[2]]
        if not judged:
            return
        for _, _, _, pointers in judged:
            for c in pointers:  # in place of a row for the same id: its sources are proven
                self.state["deferred"] = [d for d in self.state["deferred"] if not (
                    d["product_text"] == c.product_text and d["id"].casefold() == c.id.casefold())] + [c.to_dict()]
        self.save()  # the pointers first: a run that stops before the ledger write repeats it
        for e, released, kept, _ in judged:
            try:
                # yd1y: a retracted id the thread released while it stood (``part``) is still in
                # its root, so it hides the thread, and it is the thread's again: the hidden
                # thread keeps an id when its last other one is released.
                back = [i for i in (e.split or {}).get("released", ()) if _base(i) in bases]
                self.led.release(e.root_event_id, released, kept, back=back)
            except LedgerError as err:  # one thread's record never stops the run
                _say(f"{e.root_event_id[:12]} retired, not recorded: {err}")
                continue
            _say(f"{e.root_event_id[:12]} retired: released {', '.join(released) or '-'};"
                 f" kept {', '.join(kept) or '-'}")
        self._released = None

    def _struck(self, h) -> bool:
        """9je7: a held notice one of whose ids the stored manifest retracts (``gone``, set
        by ``retire``): the test ``compose.withdrawn`` applies, so a digest leaves it out."""
        return not _fold([h["adv"].get("id"), *h["adv"].get("aliases", ())]).isdisjoint(self.gone)

    def _part_retracted(self, h, gone) -> bool:
        """9je7: a held notice the digest would leave out only because ``gone`` (case-folded
        retracted ids) names one of its ids, and that has an id the retraction may leave
        true (``_survivors``). Not a synthetic or an expired one: nothing of those is listed."""
        try:
            a = schema.validate(h["adv"])
        except ValueError:
            return False
        return compose.withdrawn(a, gone, self.now) and not compose.withdrawn(a, (), self.now) \
            and bool(self._survivors(h["adv"], set(gone) | {_base(i) for i in gone}))

    @staticmethod
    def _survivors(adv: dict, bases) -> list[str]:
        """9je7: the ids of a held notice that a retraction of ``bases`` may leave true:
        bot ids, not synthetic, whose base is not retracted (a bare id under a scoped
        retraction is not one: on doubt the retraction wins). GHSA ids first, as z360."""
        ids = [i for i in dict.fromkeys([adv.get("id"), *adv.get("aliases", ())])
               if isinstance(i, str) and candidates.BOT_ID.fullmatch(i) and not compose.is_synthetic(i)
               and _base(i) not in bases]
        return sorted(ids, key=lambda i: not i.upper().startswith("GHSA"))

    @staticmethod
    def _pages_for(adv: dict, i, decided, bases) -> list[dict]:
        """9je7: the sources id ``i`` of a struck held notice is judged by (``_judge_id``).

        A GHSA id: the sources named for it and those named for a retracted id, no
        other (only its own page can release it). When the notice keeps no source named
        for it (one held before a joining member's source was kept, or past the
        20-source cap), its page in every repository whose advisory page the notice
        does keep: an advisory of the same product is most often there, and the page
        itself decides. A CVE: the sources not named for an id already decided this
        run (their pages did not assign it), those named for a retracted id first, at
        most ``rules.MAX_PAGES``. Either way never more than one candidate's page
        budget, so an id no page confirms is kept, not left undecided run after run."""
        srcs = [s for s in adv.get("sources") or () if isinstance(s, dict) and isinstance(s.get("url"), str)]

        def named(s):
            return _base(s["url"].rstrip("/").rsplit("/", 1)[-1])
        if not i.upper().startswith("GHSA"):
            rest = [s for s in srcs if named(s) not in decided]
            return sorted(rest, key=lambda s: named(s) not in bases)[:rules.MAX_PAGES]
        own = [s for s in srcs if named(s) == _base(i)]
        if not own:
            repos = dict.fromkeys(s["url"].rstrip("/").rsplit("/", 1)[0] for s in srcs
                                  if rules.host_of(s["url"]) == "github.com" and not (q := urlsplit(s["url"])).query
                                  and rules._REPO_ADVISORY.fullmatch(q.path))
            own = [{"url": f"{r}/{candidates.BOT_ID.fullmatch(i).group(1)}", "published_at": None} for r in repos]
        return (own + [s for s in srcs if named(s) in bases])[:rules.MAX_PAGES]

    def _retire_held(self, bases) -> None:
        """9je7: split every held notice the manifest's retraction strikes.

        A fix group that rates notice is one held notice whose ids are every member's
        (faxq). The digest leaves out a notice with a retracted id and acknowledges every
        id of it, so the other members were never counted. Here each surviving id
        (``_survivors``) is judged by its own repository advisory page, as a retired
        thread's (``_judge_id``, over ``_pages_for``): released as a pointer candidate
        in the state's deferred list, which this run plans and holds as a notice of its
        own; kept with the notice when a page answers otherwise or no source confirms
        it; left in the notice for the next run when a page could not be read. A notice
        with nothing left to decide is dropped, the ids it still has marked digested
        (what the digest did with all of them). New pages are capped at RETIRE_PAGES a
        run and the work starts at a different notice, and in it a different id, each
        hour. A notice a journaled digest already acknowledges is that digest's, and an
        expired one is dropped whole by the next digest. One notice's failure is said
        and the others go on. One save: the pointers, the held list and the digested
        keys are one file."""
        pending = [set(it["adv"]["held"]) for it in self.state["outbox"] + self._withheld_items()
                   if it["kind"] == "digest"]
        struck = [h for h in self.state["held"] if self._struck(h)
                  and not (type(t := h["adv"].get("expires_at")) is int and t < self.now)
                  and not any(set(self._notice_keys(h["scope"], h["adv"])) <= s for s in pending)]
        if not struck:
            return
        k = (self.now // 3600) % len(struck)
        start, changed = len(self.pages), False
        for h in struck[k:] + struck[:k]:
            try:
                changed = self._split(h, bases, start) or changed
            except LedgerError:
                raise
            except Exception as e:  # noqa: BLE001 - one notice never stops the others
                _say(f"held notice {h['adv'].get('id')} not split: {type(e).__name__}")
        if changed:
            self.save()

    def _split(self, h, bases, start) -> bool:
        """9je7: judge one struck held notice (``_retire_held``); True when the state changed.
        Nothing is changed before every verdict of this run is in."""
        a = h["adv"]
        survivors, released, kept, pointers, undecided = self._survivors(a, bases), [], [], [], False
        # A different id first each hour, GHSA ids still ahead of CVEs (a CVE is often
        # decided with its GHSA): pages that keep failing never starve the ids behind.
        n = sum(i.upper().startswith("GHSA") for i in survivors)
        turn = [x for part in (survivors[:n], survivors[n:]) if part
                for x in part[(self.now // 3600) % len(part):] + part[:(self.now // 3600) % len(part)]]
        for i in turn:
            if i in released + kept:
                continue  # decided with another id of its advisory
            verdict = None
            if len(self.pages) - start < RETIRE_PAGES:
                pages = self._pages_for(a, i, {_base(x) for x in released + kept}, bases)
                shim = SimpleNamespace(scope=h["scope"], advisory={"sources": pages}, learned_sources=None)
                verdict = self._judge_id(shim, i, bases)  # the shim: what _judge_id reads of an entry
            if verdict is None:
                undecided = True  # no page read: the next run tries again
                continue
            ok, assigned, pointer = verdict
            (released if ok else kept).extend(x for x in survivors if _base(x) in assigned | {_base(i)}
                                              and x not in released + kept)
            if ok:
                pointers.append(pointer)
        if undecided and not released:
            return False
        for c in pointers:  # in place of a row for the same id: its sources are proven
            self.state["deferred"] = [d for d in self.state["deferred"] if not (
                d["product_text"] == c.product_text and d["id"].casefold() == c.id.casefold())] + [c.to_dict()]
        out = _fold(released)
        rest = [i for i in dict.fromkeys([a["id"], *a["aliases"]]) if i.casefold() not in out]  # never empty: the retracted id
        if undecided:
            title = a["title"].replace(f"({compose.public_form(a['id'])})", f"({compose.public_form(rest[0])})")
            h["adv"] = {**a, "id": rest[0], "aliases": rest[1:], "title": title}
        else:
            self.state["held"] = [x for x in self.state["held"] if x is not h]
            keys = self._notice_keys(h["scope"], {"id": rest[0], "aliases": rest[1:]})
            self.state["digested"] = (self.state["digested"]
                                      + [x for x in keys if x not in self.state["digested"]])[-MAX_DIGESTED:]
        _say(f"held notice {a['id']} split: released {', '.join(released) or '-'}; kept {', '.join(kept) or '-'}"
             + ("; the rest wait" if undecided else "; dropped"))
        return True

    def released(self) -> set[str]:
        """The base ids retired threads released (z360), read once a run."""
        if getattr(self, "_released", None) is None:
            self._released = {_base(i) for i in self.led.released_ids()}
        return self._released

    def _judge_id(self, e, i, bases):
        """(released, the base ids the page assigns, the pointer) for id ``i`` of retired
        thread ``e``, or None when a page could not be read. The thread's product, under
        its name or a former one; a former name several entries share tries each. The
        sources that name ``i`` are read first, then those that name a retracted id
        (whose page assigns its CVE), then the rest. Any retry ``rules.evidence`` reports
        leaves the id undecided: a page that failed this run may answer the next."""
        names = rules._default_index().values()
        scopes = [s for s in names if s.name == e.scope] or [s for s in names if e.scope in getattr(s, "formerly", ())]

        def order(s):
            last = _base(urlsplit(s["url"]).path.rstrip("/").rsplit("/", 1)[-1])
            return 0 if last == _base(i) else 1 if last in bases else 2
        urls = sorted({s["url"]: s for s in [*(e.advisory.get("sources") or ()), *(e.learned_sources or ())]
                       if isinstance(s, dict) and isinstance(s.get("url"), str)}.values(), key=order)  # btqg: learned
        retry, answered = False, None
        for scope in scopes:
            text = next((x for x in scope.match if (r := rules.scope_of(x)) is not None and r.name == scope.name), None)
            if text is None:
                continue
            c = candidates.Candidate(
                id=i, aliases=(), product_text=text, advisory_severity=None, local_level_hint=None,
                exploited=False, trojanized=False, injection_exec=False, fixed=None, affected=None,
                sources=tuple(candidates.Source(s["url"], s.get("published_at")) for s in urls), observed_at=None)
            ev = rules.evidence(c, scope, self.page)
            assigned = frozenset(_base(x) for x in ev.ids)
            if ev.ok and ev.structured and _base(i) in assigned and assigned.isdisjoint(bases):
                return True, assigned, c
            if ev.ok:
                answered = answered or (False, assigned, None)
            retry = retry or ev.retry  # a fetch that may pass, a page not parsed, a budget spent
        return None if answered is None and retry else answered or (False, frozenset(), None)
    def _own(self, events: dict, m, strict: bool = False) -> dict:
        """9cch: the mirror copy's events without the relay-bot events this poster did
        not sign (``sent.own``), for every read of the copy outside the signer. The
        copy as it is without a checkpoint key (no record is kept), without a manifest,
        and, with one line on stderr, when the check itself fails: no read waits on it.
        ``strict`` (the curator-translation pass, whose result outlives the run): with a
        checkpoint key, sent.NotStarted is raised instead whenever the copy was not
        judged, by an unstarted or unreadable record or by a check that failed."""
        if self.config.checkpoint_key_file is None or m is None:
            return events
        try:
            return sent.own(self.config.sent_state, events, m, self.now, strict=strict)
        except sent.NotStarted:
            raise
        except Exception as e:  # noqa: BLE001
            _say(f"own-key check of the mirror copy stopped: {type(e).__name__}")
            if strict:
                raise sent.NotStarted from None
            return events

    def _foreign(self, root) -> list:
        """m729: the ids of the relay-bot events this poster did not sign that no digest has
        reported, after a check of the mirror copy the digest just pulled, so one that
        arrived since the last run is said today. Never raises: a digest is not held for it."""
        if self.config.checkpoint_key_file is None:
            return []
        try:
            st = State.load(self.config.mirror_dir)
            m = st.accepted(root)
            if m is not None:
                sent.check(self.config.sent_state, st.events_for(root).values(), m, self.now)
        except Exception as e:  # noqa: BLE001
            _say(f"own-key check before the digest stopped: {type(e).__name__}")
        try:
            return sent.unsaid(self.config.sent_state)
        except Exception:  # noqa: BLE001
            return []

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
        # The threads whose root was posted since the last digest, oldest first (so a
        # backlog larger than one post moves forward day by day): (advisory, (posted, root)).
        # A thread is listed once, by its root; a later change is a reply in it (qwpw).
        led_items, titles = [], {}
        at, done = self.state["digest_at"], set(self.state["digest_roots"])
        for e in self.led.roots_since(at - 1):
            if e.posted_at == at and e.root_event_id in done:
                continue  # listed by the last digest
            try:
                adv = schema.validate(e.advisory)
            except ValueError:
                self.n["withheld"] += 1
                continue
            # else its thread is withdrawn: by a curator or expiry, or (kk2q) by its source
            if gone_roots.isdisjoint({e.root_event_id, *e.channel_ids.values()}) and not e.gone:
                led_items.append((adv, (e.posted_at, e.root_event_id)))
                if adv.products:
                    titles[(adv.id, adv.products[0].name)] = e.source_title
        # The held notices: the week's catalog additions, which only the weekly summary lists.
        # A notice that has since posted is listed once, as posted, and one withdrawn since
        # (retracted, expired) never; both leave the held list with this digest (retire).
        notices, unlisted, retire = [], [], []
        for h in self.state["held"]:
            if self._part_retracted(h, gone):
                # 9je7: it stays held, unlisted, until retire has judged the rest. Before
                # ``_posted``: a group that posted since is acknowledged with every id too.
                continue
            if self._posted(h):
                retire.append(h)
                continue
            try:
                a = schema.validate(h["adv"])
            except ValueError:
                self.n["withheld"] += 1
                continue
            if compose.withdrawn(a, gone, self.now):
                retire.append(h)
                continue
            if not compose.listable(a) or not a.products:
                # 8ke5: a lead, or no primary source. It leaves the held list but is
                # never marked digested, so a sighting with a primary source is held
                # again and listed.
                unlisted.append(h)
                continue
            notices.append((a, h))
        if unlisted:
            self.state["held"] = [h for h in self.state["held"] if h not in unlisted]
            self.save()
        # qwpw: the first digest of an ISO week after the one the last summary was sent in
        # (a fresh state names its own week): Monday's, or the next one when Monday's was missed.
        week = inputs.iso_week(local.date())
        weekly = self.state["weekly"] < week
        link = _mirror_link(self.config)
        summaries, names = {}, [a.products[0].name for a, _ in notices]
        if weekly:
            try:
                summaries["en"] = compose.weekly(names, link)
            except ValueError:  # refused by the publication check: the notices wait, the daily posts
                self.n["withheld"] += 1
                weekly = False
        dropped = self.state["dropped"]  # jsje: refused items a run dropped since the last digest
        foreign = self._foreign(root)
        keep = len(led_items)
        while True:  # the largest prefix that fits one post; the rest waits for tomorrow
            try:
                text = compose.digest([x[0] for x in led_items[:keep]], local.date(), retracted=gone, now=self.now,
                                      titles=titles, held=len(notices), link=link, summary=summaries.get("en"),
                                      dropped=dropped, foreign=bool(foreign)) \
                    + compose.level_report(self.rc["lowered"], self.rc["tripped"])
            except ValueError:
                self.n["withheld"] += 1
                return
            if len(text) <= transport.MAX_CONTENT or keep == 0:
                break
            keep //= 2
        taken = led_items[:keep]
        led_taken = [x[1] for x in taken]
        if len(led_taken) == len(led_items):  # the roots at the cutoff are listed: never again (8ke5)
            cutoff = self.now
            roots = [r for t, r in led_taken if t == cutoff]
        elif led_taken:  # acknowledged: every root up to the last one listed, by root at that time
            cutoff = led_taken[-1][0]
            roots = [r for t, r in led_taken if t == cutoff] + (sorted(done) if cutoff == at else [])
        else:
            cutoff, roots = at, sorted(done)
        acked = retire + ([h for _, h in notices] if weekly else [])
        snap = {"held": sorted({k for h in acked for k in self._notice_keys(h["scope"], h["adv"])}),
                "cutoff": cutoff, "roots": roots, **({"week": week} if weekly else {}),
                **({"dropped": dropped} if dropped else {}), **({"foreign": foreign} if foreign else {})}
        ja = self._ja(lambda: compose.digest([x[0] for x in taken], local.date(), lang="ja", retracted=gone,
                                             now=self.now, titles=titles, held=len(notices), link=link,
                                             summary=compose.weekly(names, link, "ja") if weekly else None,
                                             dropped=dropped, foreign=bool(foreign))
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


def _mirror_link(config) -> str:
    """The mirror a digest links to: the poster's own when public, else the default
    (a file:// URL names a local path, and one naming a host the publication check refuses
    would refuse every digest: neither reaches a post)."""
    url = config.translate_mirror_url
    if isinstance(url, str) and url.startswith("https://"):
        try:
            return compose._guard(url)
        except ValueError:
            pass
    return _member_config.DEFAULT_MIRROR_URL


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


def _join_range(was, c) -> str | None:
    """btqg: a thread's range once advisory c joined it by its fix: one that covers both.
    The thread's when they agree, none stated when either states none (c's unknown range
    may be any), else everything before the thread's fix."""
    new = compose.schema_affected(c.affected)
    if new is None or was.affected is None:
        return None
    if new == was.affected:
        return was.affected
    fixed = compose.schema_fixed(was.fixed)
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
    extra = {}
    if config.checkpoint_key_file is not None:  # m729: every id is written down before its send
        def noted(event_id):
            sent.note(config.sent_state, event_id, int(time.time()))
        extra["on_signed"] = noted
    return transport.Relay(config.relay_url, key_source, expected_pubkey=bots[0], **extra).send


def run(now: int, config, *, send=None, ssh=None, kev_fetch=inputs.urllib_fetch,
        page=rules.http_page, channels: dict | None = None,
        digest_now: bool = False, kev_catalog: dict | None = None,
        mirror_fetch=None, translate_call=None, catalog_channel=None, wording_call=None,
        advisory_fetch=None, clock=None, **translate_kw) -> tuple[int, str]:
    """One poster run. Returns (exit code, one-line summary). ``digest_now`` sends
    today's digest whatever the hour (once per date); ``kev_catalog`` replaces the
    KEV fetch with a synthetic catalog (``inputs.read_kev_file``). ``catalog_channel``:
    None reads spec/catalog-channel.json, False turns the catalog lane off, a string is
    the channel id (q03f). ``clock``: the signer's clock, which must be the one the sender
    stamps posts with (``main`` passes ``time.time``); the checkpoint is dated by it
    when it is signed (p93w, ``signer.run_checkpoint``). None:
    the checkpoint is dated ``now``."""
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
                    wording_call=wording_call, reader=sources.Reader(advisory_fetch))
            n, w_run = r.n, r
            _gate(state, led)
            recompute.begin(r.rc, now)  # ny5g: before anything is read, so a run that stops is known to have
            r.save_rc()
            merged, english_ok = None, False  # merged: set once the old deferred list is folded in
            try:
                r.expire_withheld()  # jsje: first, so nothing below waits behind what a person used to settle
                r.retire(translate_kw.get("root", TRUST_ROOT_PUBKEY))  # z360: before deferred is read
                r.settle(root=translate_kw.get("root", TRUST_ROOT_PUBKEY), fetch=mirror_fetch)
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
                pairs = r.admit_all(pairs)  # vszx: the advisory reads in turn, the admissions in order
                if r.gone:  # z360: a root naming a retracted id is hidden by every reader
                    kept = [(a, scope) for a, scope in pairs if r.gone.isdisjoint(_fold([a.id, *a.aliases]))]
                    if len(kept) < len(pairs):
                        skipped["retracted, not planned"] += len(pairs) - len(kept)
                    pairs = kept
                if review:
                    led.add_review(review, now=now)
                # faxq: in flight, an id joins no fix group (that send would record the group's ids)
                settled = {f"{it['scope']}|{i.casefold()}" for it in state["outbox"] + r._withheld_items()
                           for i in it["ids"]}
                merged = ledger.merge(pairs, led, r.groups, settled=settled,  # BEFORE level_for
                                      loud=lambda c, scope: rules.evidence_rank(r._tied(c), scope))
                r.observe(kev_out)
                r.mirror = (translate_kw.get("root", TRUST_ROOT_PUBKEY), mirror_fetch)  # btqg: _gone
                r.make_way(merged)
                r.drain()
                for i, (c, scope) in enumerate(merged):
                    r.one(c, scope)
                    merged[i] = None  # planned (or deferred by one() itself)
                r.recompute(translate_kw.get("root", TRUST_ROOT_PUBKEY), mirror_fetch)
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
            if err is None:  # gtw9: also after a stopped send, so one thread's failure starves no renewal
                try:
                    r.renew()
                except _Stop:
                    code = 1
                except LedgerError as e:
                    code, err = 1, str(e)
                except Exception as e:  # noqa: BLE001 - the pass must not cost the run its state save below
                    code = 1
                    _say(f"renewal pass stopped: {type(e).__name__}: {e}")
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
                    known = led.event_ids() | set(state["digest_ids"]) | {
                        it["sent"] for it in state["outbox"] + r._withheld_items() if it.get("sent")}
                    cp_status = signer.run_checkpoint(config, now, ssh=ssh, fetch=mirror_fetch,
                                                      root=translate_kw.get("root", TRUST_ROOT_PUBKEY),
                                                      suppress=frozenset(r.unrenewed), known=frozenset(known),
                                                      clock=clock, changes=r.level_changes())
            except Exception as e:  # noqa: BLE001 - nothing here may reach the run's exit code
                cp_status = "error"
                _say(f"checkpoint stopped: {type(e).__name__}")
            if state["withheld"]:  # every run says so while any waits
                _say(f"withheld={len(state['withheld'])} refused by the relay; each is dropped, or a reply sent once "
                     f"more, {WITHHELD_SECONDS // 86400} days after its refusal (sooner: resolve --requeue|--drop)")
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
    done = ("settled", "resent", "dropped", "superseded")
    if any(n[k] for k in done):  # jsje: likewise, only in a run that settled something by itself
        summary += " settled=" + ",".join(f"{'delivered' if k == 'settled' else k}:{n[k]}" for k in done)
    if n["renewed"] or n["renew_failed"]:  # gtw9: likewise, only in a run that tried a renewal
        summary += f" renewed={n['renewed']}" + (f"/{n['renew_failed']}" if n["renew_failed"] else "")
    if err:
        print(f"aitools-alerts-poster: {err}", file=sys.stderr)
        summary += " error=" + ("internal" if err.startswith("internal error") else "ledger")
    return code, summary


def _iso(t: int) -> str:
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unrecordable(r: Run, it, eid) -> str | None:
    """Why ``eid`` cannot be recorded as the unsent journal item ``it``'s send, or None:
    the checks ``Run._record`` makes, before anything is written (``resolve --delivered``
    and ``Run.settle``)."""
    if r.led.has_event(eid) or eid in r.state["digest_ids"] \
            or any(o["sent"] == eid for o in r.state["outbox"]):  # journaled, unrecorded
        return "that event id is already recorded for another post"
    if it["kind"] == "root":
        e = r.led.lookup(it["ids"], scope=it["scope"])
        if e is not None:
            return f"thread {e.root_event_id} already holds these ids"
    elif it["kind"] in ("copy", "reply"):
        try:
            r._entry(it)
        except LedgerError:
            return "no thread recorded for it yet; resolve its root first"
    return None


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
                if it["sent"] is None and (why := _unrecordable(r, it, delivered)) is not None:
                    return refuse(why)
                it["sent"] = delivered
                r.save()  # the journal holds the id before the ledger records it, as after a send
                r.deliver(it)
                return 0, [f"aitools-alerts-poster: resolved {key}: delivered as {delivered}, recorded"]
            if it is not None and it["sent"]:
                return refuse(f"the journal says it was delivered as {it['sent']}; use --delivered")
            if now - p["at"] < ledger.PENDING_EXPIRY:
                return refuse(f"pending under 24 hours; --not-delivered is allowed from "
                              f"{_iso(p['at'] + ledger.PENDING_EXPIRY)}")
            if it is not None:  # jsje: as Run.settle: a channel may have it, and its event still settles it
                it["tried"] = min(p["at"], it.get("tried", p["at"]))
                inputs.save_state(config.state, state)
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
                        kev_catalog=kev_catalog, clock=time.time)
    print(summary)
    return code


if __name__ == "__main__":
    sys.exit(main())
