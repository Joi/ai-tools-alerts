# Run: psb5-unparsed-page-terminal
Instruction: Read TASK-ai-tools-alerts#psb5.md in this worktree root, then run `kata show ai-tools-alerts#psb5` and follow the brief and the dispatch rules (do-it, start rung floored at medium; landing per the brief: scripts/test-gate.sh, one independent review, a PR merged with the no-reply author, the issue closed on the merge commit).
Stage: verifying (pull request; merged by this session)
Rung: medium (start-floor medium: dispatch floor; evaluator constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5, no hard trigger)
Lens: "the service runs with no human in the loop. Nothing you build may wait for a person to act." (carried in every review prompt)
Spec: docs/superpowers/specs/2026-11-28-psb5-unparsed-page-terminal-design.md   Plan: docs/superpowers/plans/2026-11-28-psb5-unparsed-page-terminal.md
Agency project: — (no mcp__agency__* tools in this session; built directly)
Kata: ai-tools-alerts#psb5
Limits: wall clock 5 hours; one independent pass per artifact, one delta when a BLOCKER fix changed behaviour; completion check: a test over repeated runs where a repository advisory page never parses and the candidate leaves the deferred list at RETRY_DAYS from first sight, as a held notice when the page names the id and the product, else dropped and counted.
Last reviewed: spec 822271e; plan 45e9db9; code whole branch origin/main...45e9db9, delta 45e9db9..bd73722. Not reviewed after: the fix of the delta's finding, this record and any merge of main

## Scorecards
Pass 1 [spec]: 2B/2S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   (fresheyes gpt-6.1-sol high, at 822271e, REASON=-)
  - B the fallback took a page that names the id and product in its text, also one that parses as another advisory, a CVE only its text names, or a repository shared by several products: the notice now needs a page `read_advisory` cannot read at all, the candidate's id in the page's own URL, a repository that is one product's alone, and the name test (fixed; tests for each)
  - B the end was forgotten, so the collector's next record started a new seven days: the `waiting` entry is kept while an input names the ended candidate (`Run.ended`, one condition in the prune), written `RETRY_DAYS` old when none existed (fixed; test re-feeds the finding across thirteen days)
  - S a missing first sight did not tell a refused record from a candidate deferred for another reason: first sight is recorded at the first unparsed read, and only a record `saw` refuses in that same run ends at once (fixed; test)
  - S the `ceil(n / MAX_RUN_PAGES)` bound did not follow from the rotation: the spec states the real one (head of the deferred list within n hours; fresh candidates first, the starvation ai-tools-alerts#vszx is about) (fixed in the spec)
  passes: 1 · no further spec pass at medium; the revised spec is read with the code by the whole-branch review

Pass 1 [plan]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (fresheyes gpt-6.1-sol high, at 45e9db9, REASON=-; run beside the code review)
  - B a run that reads no new collector record forgot the end (`Run.ended` lasted one run): the end is now an entry of `waiting` under the candidate's key with `|end`, dated each run that ends it and pruned a week after the last (fixed; test with runs between records)
  - B a map at its cap could not hold the end: `_end` writes it whatever the map holds, the oldest entry making way (fixed; test)
Pass 1 [code:terminal]: 4B/3S/3C/0R · fixed -/- · velocity = (—→10, escalation no)   (Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6.1-sol high, whole branch origin/main...45e9db9, REASON=-)
  - B (S1 as S, S2) one idle run forgets the end: the plan's first B (fixed)
  - B (S2) a full map makes the end temporary: the plan's second B (fixed)
  - B (S1 as S, S2) the made-up first sight, seven days old, weakened the age limit and the six-hour hold when the page parsed later: no first sight is written any more; the end has its own entry (fixed; test: a source ten days old still ages)
  - B (S2) a repository that is one product's alone does not prove each advisory in it is that product's: REBUTTED, see Notes
  - S (S2) a first sight under the product's former name was not counted: `_lapsed` reads the former names' keys (fixed; test)
  - S (S2) the many-candidates test read the deferred list once, after all runs: it reads it after each run (fixed)
  - C (S1) no test of a map at the hard cap (added); a run that stops early is sound by reading (no change); the half-map test emptied the map by hand (it now checks the end entries)
  passes: 1 · BLOCKER fixes changed behaviour: one delta (fresheyes --since 45e9db9 --rebuttals) follows
Pass 2 [code:terminal]: 1B/0S/0C/0R · fixed 9/9 prior · velocity ↓ (10→1, escalation no)   (delta: fresheyes --since 45e9db9 --rebuttals, at bd73722, gpt-6.1-sol high, REASON=-; the standing rebuttal not reopened)
  - B the end let the candidate's real first sight be pruned, so a page that parsed soon after was judged old by the age limit and posted no root: the first sight stays while the end entry does, and a full map never evicts it for its own end (fixed in the commit after bd73722; tests). No further pass (ruling jibot-code#41e2): the gate and the patrol are the next looks.

## Chunks
- [x] terminal — an unparsed page past RETRY_DAYS is read by the vendor-site rule or dropped; tests

## Notes
- Rebuttal, wrong product in a one-product repository (code pass, S2 BLOCKER). The case: the vendor publishes, in the repository that is this product's alone, an advisory for another package; the page does not parse for seven days; its text names this product. The notice then names this product. Not fixed, because nothing on a page that cannot be parsed binds a product more strongly than its repository and its text, so the only stricter rule is to drop every such page, which is option (b) of the issue. The issue chooses (a), "a notice from the page's id and product name alone ... (a) keeps members informed and is the safe direction". What is built is already stricter than that text: the id must be the one in the page's URL, the repository one product's alone, a page that parses as another advisory never counts. The cost of the residue is a notice (no channel post, no level above notice, no fix or range claimed, the source linked) for a product of the same vendor in the same repository; the cost of dropping is that, during a markup change, members hear of no repository advisory at all. A vendor site page has confirmed by id and product name alone since h340. Stated in the spec ("Residual risk, stated").
- Mutation checks at the final head, eighteen; seventeen caught. The one not caught writes a made-up first sight beside the end entry: `run` prunes it before the state is saved (it is seven days old and no deferred candidate names it), so no later run sees it. The regression test for the age limit covers the stored state.
- Skip-temptation, recorded: the code and the plan were written while the spec's review ran; the review's two blockers changed both before anything was committed. No artifact was skipped.
- Follow-up filed: ai-tools-alerts#ewh2 (a fetch that fails for ever defers with no end).
- No `.repoman-managed` marker and no `AGENTS.md` in this repo: the landing is the brief's (gate, one independent review, a pull request merged by this session).
