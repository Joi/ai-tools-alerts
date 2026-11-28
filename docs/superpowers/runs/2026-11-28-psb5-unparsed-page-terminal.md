# Run: psb5-unparsed-page-terminal
Instruction: Read TASK-ai-tools-alerts#psb5.md in this worktree root, then run `kata show ai-tools-alerts#psb5` and follow the brief and the dispatch rules (do-it, start rung floored at medium; landing per the brief: scripts/test-gate.sh, one independent review, a PR merged with the no-reply author, the issue closed on the merge commit).
Stage: executing
Rung: medium (start-floor medium: dispatch floor; evaluator constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5, no hard trigger)
Lens: "the service runs with no human in the loop. Nothing you build may wait for a person to act." (carried in every review prompt)
Spec: docs/superpowers/specs/2026-11-28-psb5-unparsed-page-terminal-design.md   Plan: docs/superpowers/plans/2026-11-28-psb5-unparsed-page-terminal.md
Agency project: — (no mcp__agency__* tools in this session; built directly)
Kata: ai-tools-alerts#psb5
Limits: wall clock 5 hours; one independent pass per artifact, one delta when a BLOCKER fix changed behaviour; completion check: a test over repeated runs where a repository advisory page never parses and the candidate leaves the deferred list at RETRY_DAYS from first sight, as a held notice when the page names the id and the product, else dropped and counted.
Last reviewed: spec 822271e

## Scorecards
Pass 1 [spec]: 2B/2S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   (fresheyes gpt-6.1-sol high, at 822271e, REASON=-)
  - B the fallback took a page that names the id and product in its text, also one that parses as another advisory, a CVE only its text names, or a repository shared by several products: the notice now needs a page `read_advisory` cannot read at all, the candidate's id in the page's own URL, a repository that is one product's alone, and the name test (fixed; tests for each)
  - B the end was forgotten, so the collector's next record started a new seven days: the `waiting` entry is kept while an input names the ended candidate (`Run.ended`, one condition in the prune), written `RETRY_DAYS` old when none existed (fixed; test re-feeds the finding across thirteen days)
  - S a missing first sight did not tell a refused record from a candidate deferred for another reason: first sight is recorded at the first unparsed read, and only a record `saw` refuses in that same run ends at once (fixed; test)
  - S the `ceil(n / MAX_RUN_PAGES)` bound did not follow from the rotation: the spec states the real one (head of the deferred list within n hours; fresh candidates first, the starvation ai-tools-alerts#vszx is about) (fixed in the spec)
  passes: 1 · no further spec pass at medium; the revised spec is read with the code by the whole-branch review

## Chunks
- [ ] terminal — an unparsed page past RETRY_DAYS is read by the vendor-site rule or dropped; tests

## Notes
- Skip-temptation, recorded: the code and the plan were written while the spec's review ran; the review's two blockers changed both before anything was committed. No artifact was skipped.
- Follow-up filed: ai-tools-alerts#ewh2 (a fetch that fails for ever defers with no end).
- No `.repoman-managed` marker and no `AGENTS.md` in this repo: the landing is the brief's (gate, one independent review, a pull request merged by this session).
