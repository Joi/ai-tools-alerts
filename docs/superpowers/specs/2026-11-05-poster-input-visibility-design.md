# Poster: visible inputs, kept digest ids, a forced digest and a KEV file (ai-tools-alerts#akq9)

## Problem

Found while installing the poster on the live host (jibot-code#zhja):

1. `main.run` passes `gather()` a throwaway `Counter()`. A KEV fetch failure, a
   collector record that is not validated or unreadable, and every whole-input
   rejection from `candidates.from_heartbeat` / `from_collector` are counted and
   dropped. Such a run exits 0 with a summary identical to a quiet hour, and
   the heartbeat and collector watermarks still advance past a rejected input.
2. A digest's event id is kept nowhere: the journal drops the outbox item once
   recorded and a digest has no ledger entry.
3. E3 (jibot-code#gs18) has no way to force a digest or to feed the poster a
   synthetic KEV entry without the network.

## Success criteria

- S1. The summary line ends its counters with
  `inputs=kev:<ok|304|file|unavailable>,collector:<off|none|ok|rejected>,heartbeat:<off|N/M>`.
  `M` is the number of heartbeat run dirs read this run, `N` how many were
  accepted (not rejected whole). `off` means the input is not configured;
  `collector:none` means no record newer than the watermark.
- S2. A KEV fetch failure prints `aitools-alerts-poster: kev unavailable` on
  stderr; a rejected collector record or heartbeat dir prints one stderr line
  naming the input's run-dir name (a timestamp) and the reason. Per-item skip
  counts (all inputs) print as one stderr line when any are non-zero. Reasons
  are fixed strings from the code, never input text.
- S3. A rejected input does not advance its watermark:
  - collector: a record that is not validated, unreadable, or rejected whole by
    `from_collector` sets no collector mark (today only the first two hold it).
  - heartbeat: the mark advances to the last dir before the first rejected one;
    when the first dir read is rejected, no mark is set.
  - KEV: an unavailable catalog sets no `kev_since` (as before). With no
    `kev_since` yet, the floor is the state's own `since` (fixed at the first
    run), not `now - backfill_days`, so a KEV outage from the first run on
    loses no entries.
  - Supersession is by design and is not a loss: only the newest collector
    record is ever read (each is a whole snapshot), and with no heartbeat
    watermark only the newest run dir is read (its run.json is cumulative).
    A newer accepted input replaces a refused one; the hold makes the refused
    input be read again only until then.
- S4. Exit code unchanged: 0 for a run whose sends all succeeded, whatever its
  inputs. The recommendation on an input-outage code is in the run manifest.
- S5. The state file gains `digest_ids`: the event ids of the last 10 digests
  sent, oldest first. A state file without the key (every live one today) loads
  as `digest_ids: []`; the key is validated (list of 64-hex, at most 10). When
  a digest is recorded, stderr gets `aitools-alerts-poster: digest <date> sent: <event id>`.
  A replayed record (crash between send and record) does not append the id twice.
- S6. `aitools-alerts-poster run --digest-now` sends the digest for the current
  Asia/Tokyo date whatever the hour, once per date: when `digest_date` is
  already today it sends nothing and prints
  `aitools-alerts-poster: digest for <date> already sent; --digest-now does nothing`;
  when a digest is already journaled it says that instead. The rest of the run
  is an ordinary run.
- S7. `aitools-alerts-poster run --kev-file <path>` reads KEV from that file:
  no fetch, no cache read or write. The file must be a CISA-shaped catalog
  (`vulnerabilities` list, no `items`), at most `MAX_KEV` bytes, strict JSON,
  with at least one entry, every entry's `vulnerabilityName` must contain
  `SYNTHETIC TEST`, and every `cveID` must be a reserved synthetic id
  (`CVE-2099-NNNN`, `compose.SYNTHETIC_ID`); otherwise the command prints a config error and exits 2
  before taking the ledger lock. The run reports `inputs=kev:file`.
- S8. A run with `--kev-file`:
  - does not advance `kev_since` (the real catalog was not read this run; an
    advance would skip real entries added during an outage);
  - reads every entry of the file regardless of `kev_since` and of the state's
    `since` floor (the operator chose the file);
  - the provenance is the id: a candidate from any input whose id or alias is
    a reserved synthetic id is synthetic in every run, and the ledger keeps
    the id, so nothing needs to remember which run read the file;
  - a synthetic root post's head line reads `CRITICAL (SYNTHETIC TEST): ...`
    and a synthetic advisory's digest line begins `- (SYNTHETIC TEST)`
    (compose renders both; main adds no text);
  - a synthetic candidate is never deferred, never held as a notice, and
    never replies to a known thread. A real candidate never carries a 2099
    id, so merging cannot fold a real update into a synthetic one.
- S9. `tests/fixtures/kev-synthetic.json`: one entry, `cveID` `CVE-2099-0010`
  (a reserved-looking id no real CVE will carry for decades),
  `vendorProject` `Anthropic`, `product` `Claude Code` (scope tier 1 under
  spec/scope.json version 2), `vulnerabilityName` beginning `SYNTHETIC TEST`,
  `dateAdded` `2026-11-05` (any valid date works, by S8).
- S10. Tests, one per item at least: summary shows `kev:unavailable` and
  `collector:rejected` (and stderr lines); collector and heartbeat watermarks
  hold on rejection; digest id recorded, capped at 10 and printed; old state
  without `digest_ids` loads; `--digest-now` once per date; `--kev-file`
  bypasses the fetch, composes the synthetic entry with the marker and leaves
  `kev_since`; a bad `--kev-file` exits 2. `scripts/test-gate.sh` passes.

## Approach

- `candidates.CandidateList` gains `rejected: str | None` (the whole-input
  reason), set at each early return of `from_heartbeat` / `from_collector` /
  `from_kev`. Main reads that instead of matching reason strings.
- `inputs.fetch_kev(cache, fetch, deadline) -> (catalog | None, status)` with
  status `ok`, `304` or `unavailable`; `load_kev` keeps its signature and
  returns `fetch_kev(...)[0]` (the zhja check script calls it).
- `inputs.collector_record` keeps its return value; gather tells `rejected`
  from `none` by the counts it already bumps.
- `inputs.read_kev_file(path) -> dict` raising `ConfigError` for S7.
- `gather(config, state, now, kev_fetch, counts, kev_catalog=None)` returns
  `(candidates, marks, status)`; status is the dict behind `inputs=`. The file
  candidates' ids are returned too (`status["synthetic"]`, a folded id set)
  for the Run.
- `Run` gains `digest_now: bool` and `synthetic: frozenset[str]`.
- `compose.root_post(..., test=False)`: `test=True` adds ` (SYNTHETIC TEST)`
  to the head line, beside the existing `(unverified ...)` form.
- `main()` gains `--digest-now` and `--kev-file PATH`; `run()` gains
  `digest_now=False, kev_catalog=None`.

## Alternatives considered

- Carry the KEV `vulnerabilityName` into the post body (what the brief
  assumed): no. The poster never copies feed free text into a post (the
  publication guard and the design both rest on that), and nothing in
  `from_kev` or `compose` reads that field today. Requiring the marker in every
  file entry's `vulnerabilityName` plus a compose-rendered head marker gives
  the same visible result without a free-text path.
- A `synthetic` field on `Candidate`, or a run-local set of the file's ids: no.
  Deferred candidates are stored with an exact field set (a new field needs a
  state migration), and a run-local set is lost before the next digest lists
  the ledger entry. The reserved id carries the provenance everywhere.
- An exit code for input outages: not changed (S4); see the manifest.
- A separate `digest` subcommand: `--digest-now` on `run` keeps one lock and
  one code path; the brief named the flag.

## Blast radius and rollback

The live poster reads the state file: `digest_ids` is added on the first save
and an older poster would then refuse the file (`malformed`). Rollback to the
previous version: (1) stop the hourly job (`launchctl bootout` of its
LaunchAgent) and start no manual run; (2) wait until no
`aitools-alerts-poster` process runs; (3) under the ledger lock
(`with Ledger(path):`), read the state with `inputs.read_json`, delete
`digest_ids`, and write it back with `inputs.write_json` (atomic: temp file,
fsync, rename); (4) install the older version and check it loads the state
with its own `load_state`; (5) bootstrap the job again. Nothing else changes
shape. Watermark holds can make a run re-read up to `MAX_RUN_DIRS` heartbeat
dirs while one stays rejected; re-reading is idempotent (ledger lookup,
held-notice dedup). The synthetic root is recorded in the ledger like any
root; the digest lists it marked (S8). E3 retracts the posts.

## Open questions

None blocking. Assumes the live heartbeat run dir that is rejected is a
partial write that a later read accepts; a permanently bad dir leaves the
window after `MAX_RUN_DIRS` newer dirs and the mark then moves on.
