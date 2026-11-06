# Run: digest-exclusions
Instruction: start at medium. Task: ai-tools-alerts#d3f6 — digest excludes retracted, expired and synthetic advisories (brief TASK-ai-tools-alerts#d3f6.md). Non-repoman ending (ff-merge main per brief).
Stage: verifying
Rung: medium (start-floor medium: dispatch floor; evaluator BR1 REV1 NOV1 INT1 FC1 = 5, medium on the prod-shaped test)
Lens: "Under 150 changed lines"
Spec: docs/superpowers/specs/2026-11-06-digest-exclusions-design.md   Plan: docs/superpowers/plans/2026-11-06-digest-exclusions.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#d3f6
Last reviewed: spec+plan d5a97d9c88fbaa5808bccc366d9d0322cf95348b (pass 1, gpt-6-astra, run 20261106-073345-264a84)
Last reviewed: code e806b4587a12b3d2f9fe7d85e8bfb1ae4f4080b7 (whole branch, gpt-6-astra, run 20261106-074049-8467c0)

## Scorecards
Pass 1 [spec+plan]: 0B/7S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
- Reviewer graded all seven "major" and called them blocking; triaged as SUBSTANTIVE (none makes the change unsafe to ship; each is a gap or a test/plan defect). Fixed: S1 a curator expiry reaches ledger posts only through the mirror thread → expired threads are withdrawn too, test. S2 the stored mirror state can be arbitrarily old (the curator pass skips its pull when translation is off or held) → the digest pulls the mirror itself, under the 120 s bound, and a failed pull holds the digest, test. S4 the plan's host-name grep line carried the host names → removed from the tracked plan. S5 the manifest-only test did not exercise the thread path → `_withdrawn` tested over a signed retraction reply and a curator expiry, and the ledger-root mapping tested end to end. S6 the `_plain` default change would fold the synthetic fixture into the real group → the synthetic fixture keeps its reserved prefix, the guard subcase uses a separate real group.
- Rebutted: S3 a journaled digest whose send definitely failed is resent with its old text by `drain()`; a retraction in the hour between is not applied. Narrow race on a failed send; the motivating defect (re-announced in every digest) is fixed; follow-up filed. S7 the snapshot commit's message: a dangling review snapshot, never on the branch.
- No BLOCKER: no delta pass on the docs; the whole-branch code pass carries the docs and these findings.

Pass 1 [code:whole branch e806b45]: Stage 1 0B/5S/3C · fresheyes (gpt-6-astra, run 20261106-074049-8467c0) 0B/0S/0C PASSED · fixed 5/7 prior (S3, S7 rebutted, not re-raised) · velocity ↑ (7→8, escalation no)
- Fixed: Stage 1 S1 a thread withdrawal excluded every advisory sharing the id, whatever the product → thread withdrawals leave out only the ledger entry whose root or channel copy is the thread's root; the manifest's list stays id-wide; test with a second product of the same id that stays. S3 a held digest was visible only on stderr → `digest_held` in the summary line, test. C8 the spec cites ai-tools-alerts#n1fc.
- Rebutted: S2 a persistent "state limit reached" pull error holds the digest for as long as it lasts: that error also stops new events for every member reader and the curator pass, so it is an incident on its own, now visible as digest_held=1 each run; holding is the safe side of the defect being fixed. S4 a pull timeout leaves the bounded thread holding the mirror lock, so the curator pass's pull also waits up to 120 s (240 s total, ledger locked): only on a run where the digest is due and the mirror stalls, once a day; the same hazard exists in the curator pass alone; poster runs are serial. S5 no end-to-end test of a curator reply on the poster's own root: the ledger root ids are FakeSSH's, which cannot be a signed mirror event's id; the two halves are each tested (`_withdrawn` over a signed retraction reply → its root; a withdrawn root → the ledger entry left out); the Japanese body is covered at compose level in both languages. C6 two pulls on a digest run, C7 thread name: cosmetic, not changed.
- SUBSTANTIVE fixes only, no BLOCKER: no delta pass (ruling jibot-code#41e2).

## Chunks
- [x] compose + main — digest exclusions and tests (e806b45; review fixes in the next commit)

## Notes
- Prior work: kata search "digest retracted" finds h2gf (B3, compose.digest interface), hgs0, yxd6 (a retracted root reads 撤回: in the Japanese feed); no earlier exclusion attempt. pull.active is the existing not-retracted/not-expired rule; reused for the expiry comparison.
- The poster never sends a retraction; "a retraction it sent or saw" is the mirror state it pulls.
- Built while the spec+plan pass ran (the reviewer read a snapshot sha); order deviation as on bq8v, not a skipped step.
- Size: 122 added / 37 removed in aitools_alerts and tests (159; the issue says under 150). The spec review's fixes (the pull, expired threads, their tests) added it; decided comment on the issue.
