"""The poster's reads of GitHub's advisory database and of OSV (ai-tools-alerts#3qyq).

Two endpoints and no other URL, both fixed in ``aitools_alerts.verify``:
``api.github.com/advisories/<GHSA id>`` and ``api.osv.dev/v1/vulns/<id>``. The
request, the limits and the field builders are the member's own (``verify``), so the
poster and a member's check build the same reading from one response.

``Reader.read`` gives a ``Read`` or None. None is ``unknown``: the id is not one a
lookup uses, the lane's share is spent, or the request did not end in a 200 whose
body arrived whole, parsed strictly and is a reading the ruleset accepts. A timeout,
a 3xx (no redirect is followed), 403, 404, 429 and 5xx are all None, and a 404 is
never a withdrawal. Nothing is kept between runs and nothing a response says is printed.

A run makes at most ``LANE_READS`` requests, in at most ``LANE_SECONDS`` spent inside
them, in each of three
lanes, which cannot spend each other's share: ``admit`` (new candidates), ``wait``
(threads with a wait for a lowering running) and ``rest`` (every other thread).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from aitools_alerts import ruleset, verify

__all__ = ["LANES", "LANE_READS", "LANE_SECONDS", "TIMEOUT", "Read", "Reader", "advisory_id", "tied", "chosen"]

LANES = ("admit", "wait", "rest")
LANE_READS = 10  # GitHub allows one address 60 unauthenticated requests an hour; a run is hourly
LANE_SECONDS = 20.0  # spent inside the lane's requests; the ledger lock is held
TIMEOUT = 5.0  # one request, from the call to the last byte


@dataclass(frozen=True)
class Read:
    """One good read of one id. ``fields``: the reading. ``support``: per scope product
    ``[level, lowers, stop_using]`` (``verify._record``). ``lowers``: the reading's own
    authority, about a product it does not name and about which ids are one advisory.
    ``names``: the lookup ids the response names, in ``verify.norm_id``'s form."""
    source: str
    fields: dict
    support: dict
    lowers: bool
    names: tuple


def advisory_id(i) -> str | None:
    """``i`` when it is an id one of the two endpoints is asked for, exactly as a
    lookup writes it (``verify.norm_id``); None for a CVE and for anything else."""
    if not isinstance(i, str) or verify.norm_id(i) != i or ruleset.source_of(i) not in ("ghsa", "osv"):
        return None
    return i


class Reader:
    """A run's reads. ``fetch(url, etag, limit, timeout) -> (status, etag, body)`` or an
    exception; the default is ``verify.default_fetch``, looked up at each call."""

    def __init__(self, fetch=None, clock=time.monotonic, rs=None):
        self._fetch = fetch if fetch is not None else (lambda *a: verify.default_fetch(*a))
        self._clock, self._rs = clock, rs
        self._memo: dict = {}
        self._lanes: dict = {}  # lane -> [requests, seconds spent inside them]
        self.requests = 0
        self.unread: set = set()  # ids not asked for: their lane's share was spent

    def _spend(self, lane: str) -> float | None:
        """Count one request of ``lane`` and give its timeout, or None when the lane's
        requests or seconds are used up."""
        used = self._lanes.setdefault(lane, [0, 0.0])
        left = LANE_SECONDS - used[1]
        if used[0] >= LANE_READS or left <= 0:
            return None
        used[0] += 1
        self.requests += 1
        return min(TIMEOUT, left)

    def read(self, lookup_id, lane: str = "rest") -> Read | None:
        """The read of ``lookup_id``, asked for at most once a run (a failed read is not
        tried again in it). Never raises."""
        i = advisory_id(lookup_id)
        if i is None or lane not in LANES:
            return None
        if i in self._memo:
            return self._memo[i]
        timeout = self._spend(lane)
        if timeout is None:
            self.unread.add(i)
            return None  # not memoised: another lane may still ask
        self.unread.discard(i)
        start = self._clock()
        self._memo[i] = got = self._get(i, timeout)
        # Only the time inside its own requests: a candidate's page fetch between two
        # reads is not the lane's, or five slow vendor pages would end admission's reads.
        self._lanes[lane][1] += max(0.0, self._clock() - start)
        return got

    def _get(self, i: str, timeout: float) -> Read | None:
        source = ruleset.source_of(i)
        try:
            status, _etag, body = self._fetch(verify.url_of(i), None, verify.LIMITS[source], timeout)
            if type(status) is not int or status != 200 or type(body) is not bytes or len(body) > verify.LIMITS[source]:
                return None
            fields, named = (verify._ghsa_reading if source == "ghsa" else verify._osv_reading)(verify._strict(body), i)
            rec = verify._record(self._rs or ruleset.load(), source, [fields], named, None, 0)
            return Read(source=source, fields=fields, support=rec["support"], lowers=rec["lowers"],
                        names=tuple(rec["names"]))
        except Exception:  # noqa: BLE001 - nothing of the failure is kept or shown: its text may quote the response
            return None


def chosen(first, aliases, read) -> tuple[list, bool]:
    """(the ids a member's check reads beside the first id, in its order; whether that
    is all of them): ``verify._Run.thread``'s own selection, so the poster counts no
    id a member never reads. ``first`` a CVE: the advisory ids among ``aliases`` (the
    thread's published aliases, in lookup form, in order). ``first`` a GHSA or MAL id
    whose response may lower: the ids that response names, CVEs among them, sorted.
    Only the first ``verify.MAX_ALIASES`` are read; with more, the thread is not read
    whole, and beside a CVE first id none is chosen. ``read``: id -> Read or None."""
    if not isinstance(first, str):
        return [], True
    if ruleset.source_of(first) == "kev":
        ids = list(dict.fromkeys(a for a in aliases if advisory_id(a) is not None))
        if len(ids) > verify.MAX_ALIASES:
            # Which three a member reads then depends on what its own machine read
            # before (tavj): no three are every member's, so none is counted.
            return [], False
    elif advisory_id(first) is not None:
        r = read(first)
        ids = [n for n in r.names if n != first] if r is not None and r.lowers else []
    else:
        return [], True
    return ids[:verify.MAX_ALIASES], len(ids) <= verify.MAX_ALIASES


def tied(first, i, read, aliases=()) -> bool:
    """Whether a member's check would count id ``i`` for a thread whose first id is
    ``first`` (``verify._Run.thread``). ``i`` is the first id itself, an advisory id; or
    it is one of the ids that check reads (``chosen``) and the source ties it: for a
    CVE first id, ``i``'s own response may lower and names that CVE; for a GHSA or MAL
    first id, being named by the first id's response is the tie. The bot's word that
    two ids are one advisory counts for nothing."""
    if not isinstance(first, str) or not isinstance(i, str):
        return False
    if i == first:
        return advisory_id(first) is not None
    if i not in chosen(first, aliases, read)[0]:
        return False
    if ruleset.source_of(first) == "kev":
        r = read(i)
        return r is not None and r.lowers and first in r.names
    return True
