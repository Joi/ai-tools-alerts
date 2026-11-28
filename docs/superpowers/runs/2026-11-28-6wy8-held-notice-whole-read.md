# Run: 6wy8-held-notice-whole-read
Instruction: Read TASK-ai-tools-alerts#6wy8.md in this worktree root, then run `kata show ai-tools-alerts#6wy8` and follow the brief and the dispatch rules (do-it, start rung floored at medium; landing per the brief: scripts/test-gate.sh, one independent review, a PR merged with the no-reply author, the issue closed on the merge commit).
Stage: code-review:hold
Rung: medium (start-floor medium: dispatch floor; evaluator constraint-lens, BR1 REV1 NOV1 INT0 FC1 = 4, no hard trigger)
Lens: "Nothing you build may wait for a person to act." / "No rollout, no install, no release in this task." / "it must replace the held notice's fixed and affected together" (the evaluator's; carried in every review prompt)
Spec: docs/superpowers/specs/2026-11-28-6wy8-held-notice-whole-read-design.md   Plan: docs/superpowers/plans/2026-11-28-6wy8-held-notice-whole-read.md
Agency project: — (no mcp__agency__* tools in this session; built directly)
Kata: ai-tools-alerts#6wy8
Limits: wall clock 5 hours; one independent pass per artifact, one delta when a BLOCKER fix changed behaviour; completion check: a held notice with one range and no fix, read again from a page in the shape of GHSA-v2gx-m79c-pvxj, holds fixed 2.17.0 and no range.
Last reviewed: spec 1769055 (snapshot); plan and code whole branch origin/main...6107110; delta 6107110..HEAD of the fix commit (see the scorecard)

## Scorecards
Pass 1 [spec]: 3B/3S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6.1-sol high, snapshot 1769055, REASON=-)
  - B the read signal (a stated fix or range) misses a box that states neither: `admit` records the read (`Run.boxed`), test (fixed)
  - B "covers every id" froze a held group whose member's fix or range changed: a read of some ids now widens the notice (`Run._cover`), tests (fixed)
  - B a group sharing one member joined under the held notice's earlier fix: the widening runs before the faxq join, test (fixed)
  - S "a reader takes the newest root" is the lane's contract in `catalog.py`, and this repository has no catalog reader: the spec says so and scopes criterion 1 to the block and criterion 5 to the posted root (fixed)
  - S `test_an_old_source_posts_no_root_and_reaches_the_digest_notices` asserted the old rule: changed, and named in the spec (fixed)
  - S the snapshot's commit message: rebutted, a dangling review snapshot, never on the branch
  passes: 1 · the three BLOCKER fixes changed the spec; at medium there is no second spec pass, and the whole-branch code review reads the spec and the code built from it
Pass 1 [code:hold]: 1B/4S/2C/0R · fixed -/- · velocity = (—→7, escalation no)   (Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6.1-sol high, whole branch origin/main...6107110, plan included, REASON=-)
  - B (S1, S2) a member's read gave back a fix another member had lost, and the result depended on read order: a partial read gives a fix only when both sides state one (fixed, tests in both orders and on the next run)
  - S (S2; S1 as cosmetic) a notice held under a former product name is never reached by a later read: rebutted for this issue. `Run.one` drops the sighting before `plan_new` (wa6n), before this change and after; filed as ai-tools-alerts#2emq and stated in the spec and the changelog
  - S (S1) tests asserted too little: both members of a diverged group are now read, in both orders; the catalog test's third run is a real re-sighting (fixed)
  - S (S1) a whole read whose patched text the schema cannot express clears a held fix: rebutted. One read gives both fields, and a first read of that box holds the same block; the changelog says so
  - S (S1) `boxed` held every id the page assigns, so another record those ids name could count as a read: `boxed` holds the candidate's own id only (fixed; no test isolates it: the two records merge by id in any run that plans both)
  - C (S1) the changelog read as if the live notice is corrected unconditionally: it now names the condition (fixed)
  - C (S1) a diverged group stays at no fix and no range until the digest lists it: accepted, the wide direction, no person needed
  passes: 1 · a BLOCKER fix changed behaviour: one delta (fresheyes --since 6107110 --rebuttals) follows

## Chunks
- [x] hold — a read replaces or widens a held notice's fix and range; tests

## Notes
- The repo has no `.repoman-managed` marker: the ending is the brief's (gate, one independent review, a pull request this session merges), not a repoman handoff.
- Prior work searched (`kata search "held notice merge several ranges fixed affected"`): xkbf (the parser fix that made several-range reads possible), z3fs (found this on the first v0.5.0 run), n2yj (re-read of notices a digest already listed; open, not this issue), h29n (design review: narrowing rules).
- On main's code the four tests first written failed (several-range, range-and-no-patch, member sighting, catalog root): the fault reproduced before the change.
- Mutation checks at the fix commit, ten, each caught by a test: read always true; whole always true; whole always false; the old per-field merge; `boxed` filled from stated fields only; `_cover` giving a fix when the held notice has none; `_cover` keeping the held fix when the read states none; `_cover` taking the lower fix; `_cover` keeping the held range when they differ; `_cover` giving "before the fix" though one side states no range.
- Skip-temptation, recorded: the plan was written while the spec's review ran and is reviewed beside the code. No artifact was skipped.
- The issue text predates nothing that landed since; main at d2dd492 (v0.5.0 pin) is the code read.
- The whole suite takes over an hour on this host while other sessions run theirs; it is run once, as the gate, on the final head.
- Follow-up filed: ai-tools-alerts#2emq (a notice held under a former name).
