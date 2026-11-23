# Reader: only checkpointed events apply; an incomplete mirror is refused

Kata: ai-tools-alerts#6whv, piece 3 of ai-tools-alerts#ek5q. Sources: the adversarial review of 2026-11-23, finding H2 (`docs/security/2026-11-23-adversarial-review.md` on branch `mythos-adversarial-review`); rule 7 of the design review (comments on ai-tools-alerts#h29n); the format of piece 2 (`docs/superpowers/specs/2026-11-23-zb8b-checkpoint-format-design.md`, `aitools_alerts/checkpoint.py`).

## Problem

The reader verifies each event and never the set. Run against an in-memory mirror with throwaway keys (the issue's four attacks):

1. The mirror omits one critical and serves the digest: no error, no advisory, `stale_since` empty.
2. The mirror omits a curator's `retract` reply: a new client lists the retracted upgrade under `auto-apply (opted in)`.
3. The mirror keeps serving the manifest from before a revocation: a new client accepts the revoked key with no warning.
4. One bot event dated ten years ahead: `stale_since` stays empty however long the mirror is frozen. (Piece 1 refuses the event; this piece replaces the heuristic it defeated.)

## What changes, in one paragraph

Every pull also fetches the checkpoint key certificate and the checkpoint, and fetches the manifest and the certificate from a second origin as well. The reader admits a new event only when an accepted checkpoint lists it, refuses a pull whose mirror lacks a listed event, never goes back to an older checkpoint or certificate, and never un-applies an event it applied before. Freshness is the checkpoint's: once the accepted checkpoint is past its validity the feed reads stale. Unless the last pull succeeded and the reader holds a usable certificate and a fresh, complete checkpoint, every alert is marked unverified and `plan` lists nothing under auto-apply.

## The pull, step by step

`pull.fetch(base_url, state, fetch=None, root_pubkey=..., now=None, second_origin=None, checkpoint=True)`.

`checkpoint=False` is the pull as it is today, for the two parties that write to the feed. The poster signs the checkpoints, so it cannot wait for one (`aitools_alerts/poster/main.py`, its two `pull.fetch` calls). The curator command must see a thread it posted a minute ago, to amend or retract it before the next checkpoint lists it (`aitools_alerts/curator.py`: its pull, and its reads through `advisories(state, checkpointed=False)`). Both read every verified event, as today, and neither touches the stored certificate or checkpoint. A writer-mode pull never counts as a checked pull: it records `checkpoint_ok: false` and `writer: true` in `last_pull` (see "Stale and unverified"), so on a machine where the curator command and the member commands share a state directory, the member side reads unverified after any curator pull until its own next pull succeeds. Otherwise a curator pull of an incomplete mirror would wipe out the member side's record of a refused pull. What a writer's pull stored is treated like what the released reader stored: shown until the next member pull, which keeps it applied (step 0). The curator's own retraction therefore holds on the curator's machine before any checkpoint lists it. A machine that never pulls as a writer is not affected. The member commands (`pull`, `check`, `notify`, `plan`, `run`) never pass it. The rest of this section is `checkpoint=True`.

0. **Mark the pull as begun.** Before anything is fetched, in every mode (a writer's pull too), `last_pull` is written with `checkpoint_ok: false` and the error `interrupted`. Just before that, if the previous `last_pull` was written by a reader that knows no checkpoint (it has no `checkpoint_ok`: the released reader was run on this state directory) or by a writer's pull (`writer: true`), every event that pull stored joins the applied set and the set is saved, for every trust root that holds a checkpoint (`last_pull` is one record for all roots): a retraction it fetched is not un-applied on the way back. Whatever happens next, including a crash or a failed write of the final record, the reader is unverified until a pull finishes and records success.
1. **Manifest.** Fetch `manifest.json` from `second_origin + "manifest.json"` first, when `second_origin` is set, then from the mirror. Each candidate that beats what is held is written to disk as soon as it is verified, so a mirror that stalls until the pull is killed cannot keep a revocation published at the second origin from being recorded. A candidate counts when it loads against the floor (not older than the accepted or bundled manifest) and verifies under the root. The higher version wins; at equal versions the second origin's (the repository is the source of truth). No candidate: the pull fails as today (`bad manifest`, `manifest not signed by the trust root`, or the fetch error), and a second origin that cannot be reached is never by itself an error: it is recorded in `last_pull["second_origin"]`. The chosen manifest is accepted and written to disk at once, with the stored events it still trusts, before anything else is fetched, so its revocations hold even if the pull is cut off at the next step.
2. **Certificate.** Candidates: the mirror's `checkpoint-key.json`, the second origin's, the one bundled in the package (`trust/checkpoint-key.json`, when present), and the stored one. A candidate counts when it loads, verifies under the root, is for this manifest and is not dated ahead of the clock; **expiry is not a filter**. The latest `issued_at` wins and is saved as the floor even when it has expired, and the pull then ends `no checkpoint key certificate`: an expired replacement must leave the reader unverified, never hand authority back to the certificate it replaced. `cert_order` against the stored certificate decides between "the same or newer" and a refusal; a stored certificate that is newer than every fetched one and still fits the manifest stays. None: the pull ends with `no checkpoint key certificate`. **The chosen certificate is saved at once, before the checkpoint is looked at**, like the manifest: it is the root's word on which key counts, and it must not depend on the mirror then serving a good checkpoint. If a mirror answers a new certificate with a checkpoint signed by the retired key, the pull fails, the new certificate stays, and the stored checkpoint (signed by a key the stored certificate no longer names) makes the reader unverified from that moment (see "Stale and unverified"). A later pull that cannot reach the second origin still has the newer certificate as its floor.
3. **Checkpoint.** The mirror's `checkpoint.json` must load, verify under the certificate, pass `checkpoint_problem(cp, manifest, now)` and `checkpoint_order(cp, stored)`. Failures end the pull with `no checkpoint` (missing or unreadable), `bad checkpoint` (shape, signature, another manifest), `checkpoint dated ahead of this clock` (more than 10 minutes: the member's clock is behind, or the signer's ahead), `older checkpoint` or `conflicting checkpoint`. A checkpoint past its validity is still accepted when it is newer than the stored one: it is the newest statement there is, and the feed then reads stale.
4. **Events.** Both event files are fetched and filtered as today (signature, manifest key, channel binding, the date bound for new events), together with the stored events. Then **completeness**: every id the checkpoint lists must be among the kept events. If one is missing the pull ends with `mirror incomplete` and neither the events nor the stored checkpoint change. A listed event the reader itself refused counts as missing. With a clock that is behind by more than 10 minutes the checkpoint itself is normally refused first (`checkpoint dated ahead of this clock`); when only an event is ahead (a signer that listed an event dated after its own checkpoint), the pull ends `mirror incomplete` and the dated-ahead warning of piece 1 is printed. Retention (`_retain`) runs after the completeness check and is not overridden by listing: a whole thread whose newest event is older than 400 days is dropped whether a checkpoint lists it or not. One change: a thread that has applied events takes its age from those alone. Otherwise a recent reply that no checkpoint lists (so it is stored but not applied) would keep an old root in the store after its retraction had aged out and been forgotten, and a checkpoint listing only that root would show it active. A thread with no applied event yet takes its age from all its events, so a new thread waits in the store for its checkpoint. An honest signer lists no aged-out thread (piece 4 applies the same retention); if one does, the listed events are dropped again by retention and the reader reads unverified (reason 6).

What no rule here can stop: a holder of the checkpoint key who also controls the mirror can list a root with a genuine recent reply and withhold an old retraction from a reader that never had it or has aged it out, exactly as it can for a new reader. The design review names that key as the remaining single point; the README's trust section says so.
5. **Save.** In this order: the checkpoint file (certificate, checkpoint and the applied set, see below), then `events.json`, then `last_pull.json` with `checkpoint_ok: true`. **Only applied events are stored.** An event no checkpoint lists yet is not kept; the pull that follows its checkpoint fetches it again. Stored, it would be shown by the released reader if that were run on this state (it reads every event in `events.json` and knows no checkpoint), and it would let anyone who can post crowd the store. If the applied events do not fit the store's limits, the pull ends `state limit reached` and nothing changes. (The first version of this design staged unlisted events in the store; the code review showed both problems.)

Any failure after step 2 leaves the previous events, checkpoint and applied set in place: the reader keeps showing what it showed, marked unverified, because the last pull failed.

New `PULL_ERRORS`: `no checkpoint key certificate`, `no checkpoint`, `bad checkpoint`, `checkpoint dated ahead of this clock`, `older checkpoint`, `conflicting checkpoint`, `mirror incomplete`.

## What is applied: the applied set

The reader keeps, beside the checkpoint, the set of event ids it applies. `advisories(state)` builds threads from the stored, channel-bound events in that set.

- **An event enters the set only by being listed in an accepted checkpoint** whose listed events were all present (step 4).
- **An event never leaves the set while it is stored.** When a checkpoint is accepted, the new set is the old set plus the checkpoint's list. Nothing is removed from the set in the save that removes events from the store: ids are dropped from the set only at the start of a later pull, and only those that are no longer in the store on disk. So if the save is interrupted between the two files, an event that is still stored is still applied. So a checkpoint that stops listing a retraction, an amendment or a whole thread un-applies nothing: not a stale one served to a member who already holds the retraction, and not one signed with a stolen checkpoint key. A checkpoint can add; it cannot take away. What leaves the store, and so what is shown, is what the manifest revokes (the signer's key) and what retention ages out as a whole thread.
- **The first checkpoint.** A reader upgraded from v0.1.4 holds events and no set. When its first checkpoint is accepted, the set starts as every channel-bound event then stored, plus the checkpoint's list: a retraction v0.1.4 stored survives a first checkpoint that predates it.
- **After the released reader ran on this state.** `last_pull` then has no `checkpoint_ok`. Until the next pull, `advisories` shows every stored event, as that reader did; the next pull merges them into the applied set (step 0).
- **Before any checkpoint was ever accepted** (upgraded, or the mirror not yet serving one): the stored events are applied as before, marked unverified, and no member pull admits a new one. Showing nothing would hide alerts the member already had on the day they upgrade; admitting new events without a checkpoint is the hole this piece closes. A fresh install with nothing stored shows nothing and says why. On a curator's machine, events its curator-mode pulls stored count as stored here; they are shown unverified like the rest and are never auto-applied.

A thread that has left the checkpoint's window stays applied on a reader that had it, until retention drops it. A fresh reader never sees it, which is what a new reader of the capped mirror sees today.

## Stale and unverified

`pull.unverified(state, now) -> str | None` is the one question "may this reader trust the completeness of what it shows, right now". The first reason that applies:

1. `the last pull failed (<error>)`, `the last pull was interrupted`, `the last pull checked no checkpoint` or `no pull yet`: `last_pull.checkpoint_ok` is not true. Only a pull with `checkpoint=True` that reached the end of step 5 writes true; step 0 writes false first; a writer-mode pull writes false; state last written by v0.1.4 has no such key. This is what turns a refused pull into a refusal to auto-apply: with a fresh checkpoint C1 stored and a mirror that withholds an event of C2 (`mirror incomplete`), C1 is still fresh, and without this rule the withdrawn upgrade would still be offered for auto-apply. A network failure reads unverified too, until a pull succeeds.
2. `no checkpoint key certificate` / `no checkpoint`: none stored.
3. `checkpoint key certificate expired`, `... is for another manifest`, `... dated ahead of this clock`: `cert_problem` of the stored certificate against the effective manifest (the bundled manifest when newer, as `advisories` uses).
4. `checkpoint is not signed by the certified key`: `verify_checkpoint(stored checkpoint, stored certificate)` fails: the certificate was replaced (step 2) and the stored checkpoint is the retired key's.
5. `checkpoint is for another manifest` / `checkpoint dated ahead of this clock`: `checkpoint_problem` now. A clock set back behind the checkpoint lands here, not in "fresh".
6. `stored events do not match the checkpoint`: an id the checkpoint lists is not stored (an interrupted save, see "State").
7. `checkpoint out of date`: past `fresh_until`.

`stale_since(state, now)`:
- None while `unverified` is None;
- else, with an accepted checkpoint, its `created_at`;
- else the newest stored trusted event's time, else the manifest's issue time, else (no manifest at all: a fresh install whose first pull failed) the time of the last pull attempt, else `now`.

The 3-day and 90-day rules are gone, not kept beside this: a reader without a checkpoint is always unverified, so they could only ever choose which time to print. (The first draft of this section kept them for that case.)

The CLI's `_stale_since` no longer returns nothing when the stored state belongs to another trust root or there is none: that is itself an unverified state (`no pull yet under this trust root`) and reports as above.

So `stale_since` is non-null exactly when the reader is unverified (stale is one of its reasons). That is deliberate: the session-start hook installed on member machines discards stderr and looks only for exit status 2 and a non-null `stale_since` in `run --json`; a hook that members copied from an earlier release therefore warns in every unverified state without being replaced.

CLI:
- `check` prints one line, `warning: alerts are unverified (<reason>); nothing is auto-applied`, in place of the stale line when both apply;
- `plan` prints the same line and puts every action under `prepare (ask first)`: nothing is listed under `auto-apply (opted in)`;
- `run --json` gains `"unverified": <reason or null>`; `check --json` is a list and does not change;
- `pull` prints the checkpoint's number and how many events it lists;
- `hooks/claude-code/session-start.sh`: its second line becomes "alerts may be stale or unverified (no fresh signed checkpoint, or the last pull failed); run aitools-alerts check". The match (`"stale_since": "`) does not change, so the tests that feed it old and new CLI output both hold. The skills' and the AGENTS snippet's description of `stale_since` is updated to match, and they name `unverified`.

"Nothing is auto-applied" is enforced where the plan is made (`cmd_plan`), which is the only place an auto-apply instruction comes from; the skill tells an agent to run without asking only what `plan` lists there.

## State

Stored documents are rebuilt from their decoded events without the network byte limit (`cert_from_event`, `checkpoint_from_event`): re-encoded, a checkpoint that fit on the wire can be longer, and a reader that then refused its own state could never pull again.

A new file `checkpoint.json` in the state directory: per trust root, `{"cert": event, "checkpoint": event or null, "applied": [ids]}`. The released v0.1.4 reader refuses an `events.json` record with an unknown key (`state.py`), so nothing is added there; it ignores a file it does not know, so a downgrade works. A file that does not parse raises `StateError`, as the others do: starting from empty would forget the rollback floor and the applied set.

Two files cannot be replaced in one step, so the order is chosen so that every interruption reads as unverified and never as more than was verified:

- **Step 2 (certificate):** the checkpoint file alone is rewritten with the new certificate; events untouched. If the stored checkpoint is the old key's, reason 4 applies.
- **Before anything:** step 0's record is on disk, so every later interruption, and a failed write of the final record, reads `the last pull was interrupted`.
- **Step 5, crash after the checkpoint file, before `events.json`:** the new checkpoint and the grown applied set are on disk with the old events. The applied set only names ids, so events not yet stored are simply absent, and events the interrupted save meant to drop are still stored and still applied. A listed id that is not stored is reason 6. The next pull completes it.
- **Step 5, crash after `events.json`, before `last_pull.json`:** state is complete and reads `the last pull was interrupted` until the next pull.
- **The manifest's early save** (step 1) rewrites `events.json` once before the certificate is fetched; the final save rewrites it again.
- Applied ids are pruned only one pull after their events left the store on disk (see the applied set).

Tests interrupt the save at each boundary (the write function is made to raise), for a successful pull and for a refused one starting from a verified state, and assert the reason reported, that no unlisted event is applied, and that a stored retraction is still applied after reload and after the following pull, including a following pull whose checkpoint lists only the root.

## Second origin

`config.toml` key `second_origin`, default `https://raw.githubusercontent.com/Joi/ai-tools-alerts/main/trust/` (the repository's `trust/` directory, served by another operator than the mirror); `""` turns it off; anything else must be an `https://` URL ending in `/`. It is fetched with a 5-second timeout, so a session-start hook is not held up by it. It is used only for the pinned root: under a test root override it is skipped unless the config sets it.

What it buys: after a revocation, a mirror that keeps serving the old manifest is overruled by the repository's newer one on every reader that can reach it. Where it cannot be reached, the old manifest lives until the certificate bound to it expires, and the reader then reads unverified.

## The four attacks, as tests

Each uses the in-memory mirror with throwaway keys and fails the attacker:

1. Omitted critical: the checkpoint lists it; the pull ends `mirror incomplete`. A fresh reader shows nothing and is unverified. A reader that holds an earlier fresh checkpoint keeps its events and is unverified too (reason 1).
2. Omitted `retract`, in the three forms the review found: (a) a fresh reader: `mirror incomplete`, nothing admitted; (b) a reader holding fresh checkpoint C1 with the upgrade, served C2 without the retract reply: `mirror incomplete`, and `plan` lists the upgrade under `prepare`, not auto-apply; (c) a reader that already holds the retraction (stored by v0.1.4, or applied under an earlier checkpoint), served a checkpoint that lists only the upgrade, whether a stale genuine one or one signed with the checkpoint key at a higher number: the thread stays retracted.
3. Old manifest after a revocation: with the second origin, the newer manifest wins and the revoked key's events are dropped; without it, the pull works until the old certificate expires, after which `unverified` reports it and `plan` auto-applies nothing. And the rotation case: the second origin serves a newer certificate naming a new key while the mirror serves a checkpoint by the old key: the pull fails, the reader is unverified at once, and a later pull without the second origin still refuses the old key's checkpoints.
4. Ten-years-ahead event: refused (piece 1); with the mirror frozen, `stale_since` reports the checkpoint's time once its validity has passed, at 30 and at 80 days.

Also tested: a writer's pull under one root, a pull under another root, then the first root again with its checkpoint replayed (the retraction the writer's pull stored stays); a member pull refused, then a curator pull of the same mirror, then `plan` (still nothing auto-applied); a fresh install whose first pull fails before any manifest (`stale_since` non-null, the installed hook warns); state written by this reader, at each save boundary and with a certificate only, read by the released v0.1.4 reader; the pull refusing a certificate and a checkpoint whose signature is corrupted, whose id is altered, or whose content is altered with the id recomputed, each claiming the right key, from the mirror and from the second origin; the state file's malformed forms, isolation between roots, and a stale `State` object not overwriting a newer certificate; the clock set back behind the stored checkpoint (unverified, reason 5) and behind a served one (`checkpoint dated ahead of this clock`); the save interrupted at each boundary; the hook's line on real unverified `run --json` output and on v0.1.4-shaped output; the curator command amending a thread no checkpoint lists yet; a flood of unlisted events that fills the store while every listed event is still stored; a reader whose clock is behind (`mirror incomplete` with the dated-ahead warning); a replayed older checkpoint after a newer one (`older checkpoint`); two checkpoints with one number (`conflicting checkpoint`); a checkpoint signed by a key the certificate does not name; a certificate for another manifest; an event on the mirror that the checkpoint does not list (not stored, not applied; both after the next checkpoint lists it); the upgrade path from stored v0.1.4 state; the state file's round trip and its refusal when malformed; the poster's pulls unchanged with `checkpoint=False`; the released v0.1.4 reader pulling a mirror that also serves the two new files (it ignores them).

## Existing tests that change

- `tests/test_checkpoint.py::test_nothing_in_the_package_uses_the_module_yet` is removed: this piece is the use it waited for.
- `tests/mirror_helpers.Mirror` serves a certificate and, at each fetch, a checkpoint signed by its own checkpoint key over what an honest signer would list: the events that verify, are signed by a poster of the current manifest, are channel-bound and are not dated after the checkpoint. A test that needs another list sets it. So the existing tests that serve a forged, revoked, unbound or future-dated event beside good ones keep proving what they prove. So the existing member-path tests (`tests/test_pull.py`, `tests/test_cli.py`) keep running through `checkpoint=True`; none is switched to `checkpoint=False` except the poster's and curator's own.
- The freshness tests of the 3-day and 90-day rule move to the state they still govern: events stored by v0.1.4 and no checkpoint. `test_live_feed_fixture_is_read_whole` reads the real events with `checkpoint=False` (their keys cannot sign a test checkpoint), which is the path the poster uses.
- The released-reader tests fail, not skip, when the `v0.1.4` tag is missing from the clone: the compatibility check is mandatory.
- Which new tests must fail on the parent branch: every test of the new enforcement (attacks 1, 2a, 2b, 3 and the rotation). Attack 4's event refusal and attack 2c's kept retraction are behaviour the parent already has for a reader that holds the events; those tests are regression tests through the new code path and are named as such.
- `tests/fixtures/mirror/` is re-signed once more (its secret keys are discarded each time) with `checkpoint-key.json` and `checkpoint.json` beside the three files.

## Alternatives considered

- **Apply exactly what the newest checkpoint lists.** Rejected: a checkpoint that omits a retraction the reader already holds would resurrect the alert. See the applied set.
- **Keep the certificate with the checkpoint, saved only on a good pull.** Rejected: a mirror could keep a key rotation from ever being recorded.

- **Show nothing until the first checkpoint.** Rejected: see "Before any checkpoint was ever accepted".
- **Apply unlisted events as unverified.** Rejected: an attacker with the bot key and the mirror would then still deliver alerts the signer never saw; "applies an event only when a head lists it" is rule 7.
- **Fail the pull when the second origin is unreachable.** Rejected: GitHub being down would stop every reader.
- **Keep the 3-day rule beside the checkpoint.** Rejected for readers that have a checkpoint: two freshness rules disagree; kept only for the no-checkpoint case.
- **Hold the new manifest back until a checkpoint names it.** Rejected: a revocation must apply at once. Cost: for up to one poster interval after a new manifest, pulls end `bad checkpoint` and the reader reads unverified.

## Compatibility with v0.1.4 readers

They fetch `manifest.json`, `feed.json`, `critical.json` only; none of the three changes. A test runs the released reader against a mirror that also serves the new files.

## Blast radius and rollback

Until the rollout (the certificate signed, the poster signing checkpoints, the exporter publishing both), a reader built from this piece ends every pull with `no checkpoint key certificate` and reads unverified. It must not be released before the rollout; the rollout issue under ek5q carries that order. Members install from a signed release tag, so merging to main releases nothing.

Rollback: revert the merge commit. The extra state file is ignored by the previous reader.

## Out of scope

- Expiry measured against the checkpoint's time and the 72-hour lowering rule: ai-tools-alerts#r0ra, #fv4g.
- The poster's signing, the exporter's publishing and the guard: ai-tools-alerts#nfm3.
