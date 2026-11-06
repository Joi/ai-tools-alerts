# Run: digest-exclusions
Instruction: start at medium. Task: ai-tools-alerts#d3f6 — digest excludes retracted, expired and synthetic advisories (brief TASK-ai-tools-alerts#d3f6.md). Non-repoman ending (ff-merge main per brief).
Stage: code-review:whole-branch
Rung: medium (start-floor medium: dispatch floor; evaluator BR1 REV1 NOV1 INT1 FC1 = 5, medium on the prod-shaped test)
Lens: "Under 150 changed lines"
Spec: docs/superpowers/specs/2026-11-06-digest-exclusions-design.md   Plan: docs/superpowers/plans/2026-11-06-digest-exclusions.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#d3f6
Last reviewed: spec+plan d5a97d9c88fbaa5808bccc366d9d0322cf95348b (pass 1, gpt-6-astra, run 20261106-073345-264a84)

## Scorecards
Pass 1 [spec+plan]: 0B/7S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
- Reviewer graded all seven "major" and called them blocking; triaged as SUBSTANTIVE (none makes the change unsafe to ship; each is a gap or a test/plan defect). Fixed: S1 a curator expiry reaches ledger posts only through the mirror thread → expired threads are withdrawn too, test. S2 the stored mirror state can be arbitrarily old (the curator pass skips its pull when translation is off or held) → the digest pulls the mirror itself, under the 120 s bound, and a failed pull holds the digest, test. S4 the plan's host-name grep line carried the host names → removed from the tracked plan. S5 the manifest-only test did not exercise the thread path → `_withdrawn` tested over a signed retraction reply and a curator expiry, and the ledger-root mapping tested end to end. S6 the `_plain` default change would fold the synthetic fixture into the real group → the synthetic fixture keeps its reserved prefix, the guard subcase uses a separate real group.
- Rebutted: S3 a journaled digest whose send definitely failed is resent with its old text by `drain()`; a retraction in the hour between is not applied. Narrow race on a failed send; the motivating defect (re-announced in every digest) is fixed; follow-up filed. S7 the snapshot commit's message: a dangling review snapshot, never on the branch.
- No BLOCKER: no delta pass on the docs; the whole-branch code pass carries the docs and these findings.

## Chunks
- [ ] compose + main — digest exclusions and tests

## Notes
- Prior work: kata search "digest retracted" finds h2gf (B3, compose.digest interface), hgs0, yxd6 (a retracted root reads 撤回: in the Japanese feed); no earlier exclusion attempt. pull.active is the existing not-retracted/not-expired rule; reused for the expiry comparison.
- The poster never sends a retraction; "a retraction it sent or saw" is the mirror state it pulls.
- Built while the spec+plan pass ran (the reviewer read a snapshot sha); order deviation as on bq8v, not a skipped step.
- Size: 121 added / 36 removed in aitools_alerts and tests (157; the issue says under 150). The spec review's fixes (the pull, expired threads, their tests) added it; decided comment on the issue.
