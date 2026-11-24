# Run: r0ra-expiry-against-signed-head
Instruction: ai-tools-alerts#r0ra (starting rung floored at medium): expiry is computed and applies only against a fresh signed head; bound future-dated events (finding D5 of the design review on ai-tools-alerts#h29n)
Stage: code-review:reader
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5, hard trigger none; the dispatch brief floors it at medium too)
Lens: "Released readers (v0.1.4 to v0.1.7) must keep working"; "Nothing you build may wait for a person to act; a curator is an optional override only"; "No rollout"
Follow-up filed: ai-tools-alerts#gtw9 (the poster half: claims, renewals, the 45-day step down; blocked by ny5g)
Last reviewed: spec fc1097db9b8a66ad609ecec1ae4144e1c56a2d72
Last reviewed: plan 24a5e9cad1b4208c46864ffea52696efad01d057
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

## Chunks
- [ ] reader: computed expiry, the head as the clock, the listed-event date bound, tests, spec/wire.md, changelog

## Notes
- Prior work searched: `kata search "renew unknown step down 45 days poster claim"` (hit: h29n only); the run records of ek5q's slices (zb8b, 6whv, nfm3: the checkpoint is the signed head), s6mt (the claim, `ttl_days`) and t8jr (the claim tag; rule 3 of spec/wire.md: no expiry in a relay-bot block).
- A mistake of mine: `fresheyes.sh --help` is not a help flag; it started a review of the text "--help" (run 20261124-153424-9cb1ba, default model). I stopped its processes by pid within a minute. It is not one of this run's passes.
- Notes left on ai-tools-alerts#ny5g, #fv4g and #gtw9.
- Agency: its tools are not connected in this session, so no project was made and the chunk was built directly. s6mt's record notes the step composes a prompt and executes nothing.
- The spec and plan fixes after the spec review, and the code, were applied with a script that asserts each replaced text occurs exactly once (it stops on a miss); the plan was rewritten whole with the write tool.
- The plan was drafted and the tests written while the spec review ran; the code was written while the plan review ran. Both were revised to the reviewed text before the commit.
- One existing test outside the plan's list changed: `tests/mirror/test_export.py::test_index_marks_expired` used a relay-bot block's `expires_at`, which is no longer read; it now uses a curator's and asserts the relay-bot one is not marked expired. `tests/test_pull.py::test_future_dated_event_is_refused` did not need to change once the pull-level rule was dropped.
- Split decided before the spec: the poster half of the issue (renew on `unknown`, step down after 45 days) goes to a follow-up issue. The poster sends no claim tag today and has no three-result source read (ai-tools-alerts#ny5g); every acceptance case of r0ra is a reader case.
