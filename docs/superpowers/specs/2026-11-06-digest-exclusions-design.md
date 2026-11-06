# Digest exclusions: retracted, expired and synthetic advisories (ai-tools-alerts#d3f6)

## Problem

The first public digest (2026-11-06) listed the E3 synthetic test advisory
CVE-2099-0010 under Critical, a thread the curator retracted on 2026-11-05
minutes after it posted. `compose.digest` is built from the ledger's changed
entries and the held notices; it never consults retractions or `expires_at`,
so a retracted or expired advisory is announced to members again in the
next digest, and a synthetic test reaches the public digest at all.

## Success criteria

1. `compose.digest(advs, date, lang, *, retracted=(), now=None)` leaves out:
   - every advisory whose primary id is synthetic (`compose.is_synthetic`);
   - every advisory whose id or any alias, case-folded, is in `retracted`;
   - every advisory with `expires_at` set and `expires_at < now` (the rule
     `pull.active` uses: an advisory expiring exactly at `now` is still
     active), when `now` is given.
   The first line's count is the count of the lines that remain; when every
   advisory is left out the digest is the "no advisories" line. The same
   holds for `lang="ja"`.
2. `main.Run.digest` passes `now=self.now` and the withdrawn set to both the
   English and the Japanese call. Once the digest is due (after the date,
   hour and journal checks), the poster pulls the mirror
   (`translate_mirror_url`) into its mirror state (`Config.mirror_dir`, the
   state the curator-translation pass uses) under the same 120 s bound,
   whether or not translation is on, and builds the set from the trust
   root's manifest and events:
   - the manifest's `retracted` ids (id-wide, as every reader treats them);
   - the root event id of every thread `pull.threads_from` reports
     retracted, or whose advisory as amended has `expires_at < now` (a
     curator's expiry reaches the ledger's posts only this way). A ledger
     entry whose `root_event_id` or any channel copy's event id is such a
     root is left out (the poster's own root retracted by a curator reply —
     the motivating case). By root, never by bare id: another product's
     post of the same id, in its own thread, stays (code review S1).
3. The pull fails (an error in the pull result, a timeout, an unreadable
   state): the digest is not built this run, a line on stderr says why, and
   the next run tries again (the digest date is not recorded); the summary
   line counts it as `digest_held=1`. A digest a run late is cheaper than a
   retracted advisory announced again.
4. An excluded item is still acknowledged by the digest snapshot (cutoff,
   roots, held keys) like any listed item, so it is never carried forward
   to the next day's digest.
5. Tests in `tests/poster`: a retracted root, an expired root and a
   synthetic root, each excluded in English and Japanese with the count
   reduced; main-level tests where a manifest-retracted ledger post, and a
   ledger post whose thread is withdrawn, are left out of the sent digest,
   where `_withdrawn` reads a curator retraction reply and a curator expiry
   from a signed mirror, and where a failed pull holds the digest until the
   next run. Existing tests that expected a synthetic line in the digest
   now expect it absent.
6. Under 150 changed lines (code and tests), standard library only.

## Approach

Filtering lives in `compose.digest`, after the latest-version-wins pass (an
amendment that clears `expires_at` keeps the advisory) and before grouping,
so counts and groups are computed from what remains. The synthetic marks
inside the digest path (`_single`'s legacy mark, `_group_key`'s synthetic
flag, `_group_line`'s mark) become unreachable and are removed.

`main.Run._withdrawn()` pulls and returns the case-folded id set and the
withdrawn root event ids, or raises; `digest` catches the raise, says so,
and returns before journaling anything. The pull reuses `pull.fetch`, the
reader the curator pass already runs, against the same URL: no new network
destination. It runs only on a run where the digest is due, so once a day
when the mirror is up.

## Alternatives considered

- Read the stored mirror state without a pull. Rejected after the spec
  review: a retraction published between the last pull and the digest run
  is missed, and the curator pass skips its pull when translation is off,
  held or its state is unreadable, so the state can be arbitrarily old.
- Record retractions in the ledger. Rejected: the poster never sends a
  retraction (only curators do), so the ledger would need a new reader of
  mirror events and a schema change; the mirror state already holds them.
- Proceed without retractions when the state is unreadable (fail open).
  Rejected: re-announcing a retracted advisory is the defect being fixed; a
  digest a run late is cheaper.

## Assumes

- A digest that was journaled and whose send definitely failed is resent
  by `drain()` with the text built when it was journaled. A retraction in
  the hour between is not applied to that resend; follow-up
  ai-tools-alerts#n1fc (the motivating case, a retracted advisory announced in every later
  digest, is fixed here).

## Blast radius / rollback

Digest text only; root posts, replies, ledger and journal formats are
unchanged. Rollback: revert the commit; the poster's state stays readable.

## Open questions

None.
