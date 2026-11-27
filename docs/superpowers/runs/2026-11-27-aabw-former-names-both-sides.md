# Run: aabw-former-names-both-sides
Instruction: ai-tools-alerts#aabw (starting rung floored at medium, never light): a thread under a product's former name is never recomputed by the poster nor confirmed by a member's check; decide how a former name is read, on both sides at once
Stage: done
Rung: medium (start-floor medium: constraint-lens, BR2 REV2 NOV1 INT1 FC1 = 7; the dispatch brief floors it at medium too)
Lens: "the service runs with no human in the loop; nothing you build may wait for a person to act"; "no rollout, no install, no signing step, no release in this work"
Last reviewed: spec f44bc56ea7a5d444875acf6e407e7b075eee9745
Last reviewed: plan 2af413ec18310519cb199be33d26838a97a8d3e8
Last reviewed: code af685e7dab543a9dff135e909fc0cb690d7cb787 (the whole branch, `git diff origin/main...HEAD`, main then at dd4d195); delta f78ec70a1906bd3c0547a449253b68e6c4a77e87 (`--since af685e7`)
Unreviewed after the last reviewed head: fc5a5485d9bd6cee03ac966d073a9e0e0921d007 (the fix of the delta's two findings: the matcher change removed, `cli._installed_as`); 4d0860d625443ba3bdb6f9fb7f2593e3f6dc2d23 (merge of main at cfdbfc7, nx25: cache version 7); da1a2e1498cd2fbe5d28c7a5c90f8c96200d8eca (merge of main at d40fef5, kk2q: the first acceptance test holds a withdrawal); the merge of main at 21aca74 (p93w, no conflict, no file of this change); and the commit that records this.
Gate: `scripts/test-gate.sh` exit 0, each run in a clone holding this branch alone: at af685e7 (3386 passed, 1 skipped), fc5a548 (3392 passed), 4d0860d (3450 passed), da1a2e1 (3507 passed). The run at the final head is reported on the kata issue, since this file is part of that head.
Pull request: https://github.com/Joi/ai-tools-alerts/pull/58
Spec: docs/superpowers/specs/2026-11-27-aabw-former-names-both-sides-design.md   Plan: docs/superpowers/plans/2026-11-27-aabw-former-names-both-sides.md
Agency project: — (no Agency tools on this seat's session; the chunk was built inline)
Kata: ai-tools-alerts#aabw
Limits: wall clock 5 hours from the 2026-11-26T20:27Z dispatch; review shape one independent pass per artifact (fleet default reviewer) and one delta only after a behaviour-changing BLOCKER fix, three review rounds at most; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.

## Scorecards
Pass 1 [spec]: 1B/2S/1C/0R · fixed -/- · velocity = (—→4, escalation no)
spec passes: 1 · reviewer gpt-6.1-sol at high (fresheyes run 20261127-053215-bad03b, REASON=-) · the BLOCKER fixed (criterion 7 names the cache-version test as a third test that changes, and that test now carries a stored `no-source`), one SUBSTANTIVE fixed (a renewal test for an enrolled former-name thread), one rebutted (the throwaway snapshot's message: a dangling commit made for the reviewer, on no branch, never lands), the COSMETIC fixed (10 requests, not 20); nothing survives, so the rung stays medium
Pass 1 [plan]: 1B/3S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
plan passes: 1 · reviewer gpt-6.1-sol at high (fresheyes run 20261127-053852-24ce69, REASON=-) · all four fixed: the BLOCKER in the plan's text (the fixture as built already carried `root_ids`), two SUBSTANTIVE by a new test each (mutations 11 and 12 now fail one), one in the landing steps (fetch before the author check); nothing survives, so the rung stays medium
Pass 1 [code:former-names]: 0B/3S/4C/0R · fixed -/- · velocity = (—→7, escalation no)
code passes: 1 · whole branch at af685e7dab543a9dff135e909fc0cb690d7cb787 · Stage 2 reviewer gpt-6.1-sol at high (fresheyes run 20261127-211328-c75b84, REASON=-): one SUBSTANTIVE (another package under a former name's key takes its confirmation) · Stage 1 (same-model subagent): two SUBSTANTIVE (the same one; silence about a former name read as absence, which this run regrades BLOCKER) and four COSMETIC · all seven fixed (spec, "Review dispositions (code)"); nothing survives, so the rung stays medium; the two behaviour-changing fixes get the one delta pass
Pass 2 [code:former-names]: 0B/2S/0C/0R · fixed 3/3 prior · velocity ↓ (7→2, escalation no)
code delta: fresheyes `--since af685e7dab543a9dff135e909fc0cb690d7cb787` at f78ec70a1906bd3c0547a449253b68e6c4a77e87, no rebuttals file (nothing was left unfixed), run 20261127-213007-fcce09, REASON=- · two findings, both on the `check._identity` fix, both fixed in the commit after it (the matcher change removed; a match on a former name is not judged for interrupts); no further pass (Review Cycle: repoman has no part here, so the gate and the merge are the next looks)

## Chunks
- [x] former-names: the ruleset says what a name stands for; the member's check and the recompute read a former name by it; tests, changelog

## Notes
- The 5-hour wall clock passed while the seat's usage limit held the session (stopped about 2026-11-26T20:50Z, resumed 2026-11-27T12:00Z on a written instruction to continue through the merge and the close). Main had not moved: `origin/main` is still `dd4d195`.
- Agency: `mcp__agency__*` is not among this session's tools, so the one chunk was built inline, first in a copy of the tree outside the worktree while the spec and plan reviews read the worktree.
- A stray review: `fresheyes.sh --help` is not a help flag; it started a review of the text "--help" (run 20261127-053151-3e1392). Stopped within a minute by ending its own process group; no finding was read from it.
- Found after the spec review, while writing the changelog: `cli._source_lines` printed nothing for a former name, and `_shown` would show such an alert at notice with no line. Fixed with a test (spec "Member: cli.py").
- Mutations, each failing the test the plan names: 1, 2, 4 to 13. Mutation 3 (the KEV line by `scope.name`) survives: no entry that lists a former name has a KEV identity.
- Mutations for the code review's fixes, each failing a named test: 14 (the member's silence rule), 15 and 18 (the poster's), 16 (`_identity`, a fix since removed), 21 and 22 (a former-name match judged for interrupts; its `--json` result taken from the thread), 17 (the schema rule), 19 and 20 (a current name keeps silence-is-absence, member and poster).
- `tests/test_never_supported_cli.py::test_for_48_hours_after_a_rebuilt_record_nothing_shows_at_notice` failed once in a run made while two other suites ran on the machine, and passed in three runs alone and in the full suite. It is about a Claude Code thread and reads the real clock; this branch does not touch it.
- Main moved three times during the run (nx25, kk2q, p93w); each was merged before the pull request was merged. What each changed here is in the spec's two "After the merge of main" sections; p93w touched the signer and the checkpoint and none of this change's files.
- Split: the branch is about 890 added lines against main, of which the three run documents are about 290 and tests about 460; the source change is about 130 lines in seven files. It was not split: one rule read on two sides is one deliverable, and half of it would publish levels the other side cannot confirm.
- The repository has no repoman marker: the run ends with a pull request this session merges, as the brief says, not a repoman handoff.
