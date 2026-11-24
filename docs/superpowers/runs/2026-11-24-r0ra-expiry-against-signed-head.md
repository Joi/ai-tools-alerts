# Run: r0ra-expiry-against-signed-head
Instruction: ai-tools-alerts#r0ra (starting rung floored at medium): expiry is computed and applies only against a fresh signed head; bound future-dated events (finding D5 of the design review on ai-tools-alerts#h29n)
Stage: committing
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5, hard trigger none; the dispatch brief floors it at medium too)
Lens: "Released readers (v0.1.4 to v0.1.7) must keep working"; "Nothing you build may wait for a person to act; a curator is an optional override only"; "No rollout"
Follow-up filed: ai-tools-alerts#gtw9 (the poster half: claims, renewals, the 45-day step down; blocked by ny5g)
Last reviewed: spec fc1097db9b8a66ad609ecec1ae4144e1c56a2d72
Last reviewed: plan 24a5e9cad1b4208c46864ffea52696efad01d057
Last reviewed: code a4133f77eb70484b357556c4ea7a9d91b342d726 (the whole branch), then the delta `--since a4133f77eb70484b357556c4ea7a9d91b342d726` at ea88676ca4397d05c5e3d84c0137e33fd627c5c4
Unreviewed after the delta: the fix of what the delta raised (the commit after ea88676)
Review tier: gpt-6-astra at high (h29n calls the work security-shaped)
Spec: docs/superpowers/specs/2026-11-24-r0ra-expiry-against-signed-head-design.md   Plan: docs/superpowers/plans/2026-11-24-r0ra-expiry-against-signed-head.md
Agency project: —
Kata: ai-tools-alerts#r0ra
Limits: wall clock 5 hours from the 2026-11-24 dispatch; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.

## Scorecards
Pass 1 [spec]: 5B/4S/0C/0R · fixed -/- · velocity = (—→9, escalation no)
spec passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-153447-18ea3b) · six fixed in the spec, three rebutted

Spec findings and what was done:
1. BLOCKER, a holder of the bot key can renew its alert for ever with fresh claims. Rebutted: a renewal proves no source read, as a new false alert proves none; the member's source check (fv4g) and the poster's foreign-event check (D14) answer a false claim. The spec now says what a renewal does not prove.
2. BLOCKER, a first claim confirmed in 1970, replied to a thread with no claim, ends it. Fixed: only a thread whose root carries a claim decays ("enrolled"); later claims can only lengthen.
3. BLOCKER, `_retain` ages threads out by the member's clock, so a clock a year ahead deletes stored alerts. Fixed: a checked pull takes the retention clock from the head.
4. BLOCKER, the signer gives up a missing renewal after 72 hours and signs a head with the root and without it. Rebutted for this change, carried to gtw9: no renewal exists until the poster sends one, and the signer rule must land with the first.
5. BLOCKER, a decayed thread shows at its first level again when a later head omits its root. Rebutted: kept on purpose and now stated; decaying an unlisted thread would let a mirror that hides a root for 72 hours lower it; too high is the safe side.
6. SUBSTANTIVE, the head is saved before the events, so an interrupted save leaves a later head over an earlier store. Fixed: `head_clock` gives no clock unless every listed event is stored.
7. SUBSTANTIVE, the honest signer lists posts dated after its checkpoint (the owed ones). Fixed: the pull-level refusal is gone; a claim counts only when its event is dated at or before the head. Deviation from the issue's wording, stated in the spec and the kata comment.
8. SUBSTANTIVE, the wire-compat test that must change was not named. Fixed.
9. SUBSTANTIVE, the ten-years-ahead test passed without the new check. Fixed: it is a regression test of ek5q's rule; the new rule has its own case.

Pass 1 [plan]: 0B/3S/0C/0R · fixed -/- · velocity = (—→3, escalation no)
plan passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-154126-15baa8) · all three fixed

Plan findings and what was done:
1. SUBSTANTIVE, the size-limit fallback of the final settle would age the old store by a head that is then not accepted. Fixed in the plan and the code: the fallback uses the clock already held; a test fails without it.
2. SUBSTANTIVE, `mirror.checkpoint(now=at)` lists no event dated after `at`, so case 4 could not be built as written. Fixed: explicit ids, as the tests already did.
3. SUBSTANTIVE, case 5 gave confirmation dates, and retention reads event dates. Fixed: the roots are dated then too; the test fails when the retention clock is the local one (checked by putting the old line back).

Pass 1 [code:reader]: 3B/5S/3C/0R · fixed -/- · velocity = (—→11, escalation no)
code passes: 1 so far · Stage 2 gpt-6-astra on the whole branch at a4133f77eb70484b357556c4ea7a9d91b342d726 (fresheyes run 20261124-154853-11eed3) · Stage 1 a same-model reviewer on the same diff

Code findings, pass 1, and what was done (the commit after a4133f7):
1. BLOCKER (Stage 2; Stage 1 found the same from the honest side), a raise was judged by the older confirmation of the lower level, so a permitted raise could show lower than before it. Fixed: `level_at` steps down through each lower level and never answers lower for a higher level; a relay-bot raise is a renewal of its own date.
2. BLOCKER (Stage 2), a patch that dropped an alias took away the renewals made under it. Fixed: the ids a claim may name are every id and alias the thread has held.
3. BLOCKER (Stage 2), with the root's claim held back (root dated after the head) an ancient claim in an earlier-dated reply was the only one counted. Fixed: a thread with any renewal dated after the head is not judged under that head.
4. SUBSTANTIVE (Stage 1), a raise posted in the run whose head is dated before it showed at the old level until the next head. Fixed by 1 and 3.
5. SUBSTANTIVE (Stage 2), the wire-compat fixture's claims were malformed, so no released-reader comparison met an enrolled thread. Fixed: the claims are ones the reader takes, the test asserts three threads are enrolled and that a month on they show notice here and critical on every released reader.
6. SUBSTANTIVE (Stage 1), the changelog said the release changes nothing a member sees; a curator's `expires_at` is now judged by the checkpoint. Fixed in CHANGELOG.md and spec/wire.md.
7. SUBSTANTIVE (Stage 1), the web index marks a curator's expiry by the exporter's clock and the CLI by the checkpoint. Rebutted: the exporter is the operator's page and has no member checkpoint; the comment there now says so.
8. SUBSTANTIVE (Stage 1), no test for `head_clock` with no state or after a writer's pull. Fixed. Its note that the compat helper passes a time and not `head_clock` is rebutted: the test must look a month ahead, which only a time can do; it now asserts a head is held.
9. COSMETIC, fixed: the `advisories` docstring on which threads carry renewals. Left: a damaged ruleset is loaded once per enrolled thread; the "shown" half of the clock test cannot fail by itself (its stored-events assertion is the one that fails on the old code).

Pass 2 [code:reader]: 1B/0S/0C/0R · fixed 7/8 prior · velocity ↓ (11→1, escalation no)
code passes: 2 (the whole branch, then the one delta `--since a4133f77eb70484b357556c4ea7a9d91b342d726` at ea88676ca4397d05c5e3d84c0137e33fd627c5c4, fresheyes run 20261124-155816-7c95ca, with the standing rebuttals) · no rebuttal overturned

Code findings, pass 2 (the delta), and what was done (the commit after ea88676, no further pass):
1. BLOCKER, the raise's renewal depended on the order of replay: a second raise dated before the first made the first no raise, its renewal vanished and the alert could end. Fixed: any relay-bot reply whose block names a level gives a renewal of its own date, judged by the event alone; a regression test adds the backdated raise.

## Chunks
- [x] reader: computed expiry, the head as the clock, retention by the head, tests, spec/wire.md, changelog: committed a4133f7, review fixes in the commit after it

## Notes
- Prior work searched: `kata search "renew unknown step down 45 days poster claim"` (hit: h29n only); the run records of ek5q's slices (zb8b, 6whv, nfm3: the checkpoint is the signed head), s6mt (the claim, `ttl_days`) and t8jr (the claim tag; rule 3 of spec/wire.md: no expiry in a relay-bot block).
- A mistake of mine: `fresheyes.sh --help` is not a help flag; it started a review of the text "--help" (run 20261124-153424-9cb1ba, default model). I stopped its processes by pid within a minute. It is not one of this run's passes.
- Notes left on ai-tools-alerts#ny5g, #fv4g and #gtw9.
- Agency: its tools are not connected in this session, so no project was made and the chunk was built directly. s6mt's record notes the step composes a prompt and executes nothing.
- The spec and plan fixes after the spec review, and the code, were applied with a script that asserts each replaced text occurs exactly once (it stops on a miss); the plan was rewritten whole with the write tool.
- The plan was drafted and the tests written while the spec review ran; the code was written while the plan review ran. Both were revised to the reviewed text before the commit.
- One existing test outside the plan's list changed: `tests/mirror/test_export.py::test_index_marks_expired` used a relay-bot block's `expires_at`, which is no longer read; it now uses a curator's and asserts the relay-bot one is not marked expired. `tests/test_pull.py::test_future_dated_event_is_refused` did not need to change once the pull-level rule was dropped.
- Gate: `scripts/test-gate.sh` exit 0 at a4133f7 in a clone of this branch alone (1966 passed); in the shared clone the public scan stops on other sessions' refs, none of whose objects this branch reaches (`--hit-ids` against `git rev-list --objects HEAD`: none in common).
- The rung did not climb: no hard trigger, and no BLOCKER or SUBSTANTIVE finding survived its pass unfixed or unrebutted. The delta is the Review Cycle rule's, not heavy's.
- Size: 245 lines of code and text, 370 of tests, outside docs/superpowers. Over the 600-line mark by the regression tests the reviews asked for; the poster half was split off before the build.
- Split decided before the spec: the poster half of the issue (renew on `unknown`, step down after 45 days) goes to a follow-up issue. The poster sends no claim tag today and has no three-result source read (ai-tools-alerts#ny5g); every acceptance case of r0ra is a reader case.
