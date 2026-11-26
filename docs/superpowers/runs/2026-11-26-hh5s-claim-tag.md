# Run: hh5s-claim-tag
Instruction: Read TASK-ai-tools-alerts#hh5s.md in this worktree root, then run `kata show ai-tools-alerts#hh5s` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: committing
Rung: medium (start-floor medium: FC=2 and constraint-lens; hard trigger none; BR2 REV2 NOV1 INT2 FC2 = 9; the dispatch floors it at medium too)
Lens (carried in every review prompt): "Nothing you build may wait for a person to act"; "Stay inside this issue"; "No rollout"; "No host, tailnet, VM or home-path names and no personal email in any commit, PR text or run record"; "A state file written before this change loads; an item without the key sends as before"; "the poster must not run this code for 14 days without gtw9".
Last reviewed: spec f89c75aa4f6305b0af8ab7e420b23273404b37ea
Last reviewed: plan 50fca8529924d9317c60a0d1b189f12064ddba49
Last reviewed: code 72ac8ba5ba46080b6028c8c994b39aea89d2dc95 (whole branch) +fix 01f511486b01898ba7d66f33eea4383136b9708d, then merges of origin/main 353de3461c5b69a03832c7655626fdce2073ba49 and 35d732b3fb41182ec76b0ca762b6a32496f92999 (a changelog conflict in each, both entries kept; no other conflict)
Spec: docs/superpowers/specs/2026-11-26-hh5s-claim-tag-design.md   Plan: docs/superpowers/plans/2026-11-26-hh5s-claim-tag.md
Agency project: — (no agency tools in this session; the plan is executed directly)
Kata: ai-tools-alerts#hh5s
Limits: wall clock 5 hours from the 2026-11-26T01:48Z dispatch; review shape one independent pass per artifact (gpt-6-astra, security-shaped) and one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Ending: the repository has no repoman marker, so the brief's landing applies: a pull request this session merges.

## Scorecards
Pass 1 [spec]: 3B/4S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
passes: 1 (spec). Reviewer gpt-6-astra through fresheyes, run 20261126-105227-82891d, REASON=-. Six fixed, one rebutted; the rung stays medium.
- BLOCKER, claims start expiry before the poster can renew: fixed. Root claims are built and tested and ship off (`main.ROOT_CLAIMS = False`); gtw9 turns them on with renewals. This narrows the issue's acceptance for roots (notice on the issue).
- BLOCKER, the signer gives up a renewal-bearing reply after 72 hours: fixed by the same switch. With no enrolled root no reply's claim can end or shorten an alert; the signer's part stays gtw9's.
- BLOCKER, the test fixtures cannot carry a claim (FakeRelay, test_settle's mirror): fixed, success criterion 7.
- SUBSTANTIVE, the rollback text was wrong (`load_state` raises, nothing is replaced): fixed.
- SUBSTANTIVE, a copy `plan_known` adds without a level change is a root too: fixed, every new copy follows the root switch.
- SUBSTANTIVE, `verify.claimed` is not in any release and the compat matrix stops at v0.1.7: fixed, criterion 6 names all seven tags.
- SUBSTANTIVE, the snapshot commit's message: rebutted. The snapshot is a dangling commit made for the reviewer and never lands.
Pass 1 [plan]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)
passes: 1 (plan). Reviewer gpt-6-astra through fresheyes, run 20261126-110016-9fb5fa, REASON=-. Both fixed; the rung stays medium.
- BLOCKER, one claim chosen for `plan_known` could name an alias the level-only reply never publishes: fixed. Each event's claim is chosen among the ids that event leaves the thread with; a regression test covers the lowered thread.
- BLOCKER, an existing assertion compares the recompute's `info` whole: fixed, the plan names the assertion and its new value.
Pass 1 [code:all]: 0B/4S/5C/0R · fixed -/- · velocity = (—→9, escalation no)
passes: 1 (code). Whole branch `git diff origin/main...HEAD` at 72ac8ba5ba46080b6028c8c994b39aea89d2dc95. Stage 2: gpt-6-astra through fresheyes, run 20261126-112603-fce9ec, REASON=- (1 SUBSTANTIVE). Stage 1: a same-model reviewer with no shared context (4 SUBSTANTIVE, one of them the same; 5 COSMETIC). Three fixed, one rebutted; no BLOCKER, so no delta pass. The rung stays medium.
- SUBSTANTIVE (both reviewers), a claim could name an alias one channel of the thread never received (a reply one channel took and the other refused for good): fixed. `Run._stated` gives the ids every channel was sent; when the channels were not sent the same number of replies only the first id counts.
- SUBSTANTIVE, the id filter was tested on one of three paths: fixed for the recompute (a ledger id no reply published) and by the unit test of `_stated`. For the shared reply, `new` and `merged` hold the same ids except at the 50-alias cap; not tested apart.
- SUBSTANTIVE, settle was tested only for a claimed root: fixed, a claimed level reply is settled only by an event with its claim.
- SUBSTANTIVE, nothing in the repository shows the relay takes a kind 9 event with this tag: rebutted. ai-tools-alerts#yw7r posted a 2048-byte claim tag to the live relay and read it back byte for byte from the relay and from the mirror (its note on ai-tools-alerts#3qyq); this seat may not reach the relay. A relay that refused the tag would withhold a level change for three days, send it once more and drop it, each said on stderr; resending without the claim is not built.
- COSMETIC: `claim_text` now catches every exception, as its docstring says; the reader rule in spec/wire.md is its own paragraph again. Not done: a test that `deliver` checks the tag before marking pending (the fake relay's own check covers it); the size in the too-large line; the plan's test of a copy added with no level change (the copy switch is covered by the raise test, on and off); the plan's clock test became an assertion that the event is dated by the sender's clock.

## Chunks
- [x] carrier: transport, journal item, byte count, settle
- [x] claims: which reading each root and level change carries; the recompute's readings
- [x] wire compat test, spec/wire.md, changelog

## Notes
- Size: the branch is about 1,050 added lines, past the brief's 600. The code under `aitools_alerts/` is about 150 of them; the spec, plan and this record are about 330, and tests the rest. It is one deliverable and was not split.
- The session moved seats at a usage limit after the first merge of main; the model changed from Mythos 5.2 to Fable 5.2. Main had moved again (24 commits, ai-tools-alerts#zmg2 in `poster/recompute.py` and `main.py` among them); the second merge and its gate were run after.
- Gate: `scripts/test-gate.sh` in a clone holding this branch alone, exit 0 at 353de34 (2951 passed, 1 skipped) and again at 35d732b (3064 passed, 1 skipped).
- The spec review was launched before the evaluator's lens arrived and did not carry it; every later pass does.
- A `--help` probe of the review script started a review of the text "--help" (run 20261126-105207-e31b41); it was stopped within a minute and is not a pass.
- The spec and plan were revised once each with a script that asserts every needle occurs exactly once, not with the Edit tool; every later artifact edit uses Edit.
- Code for tasks 1 and 3 was started while the plan review ran. Its two findings were applied to the code after.
- Agency tools are not present in this session; the plan's tasks were executed directly, tests first where the plan names them.
- The plan put the `claim_text` unit tests in `tests/poster/test_rules.py` and the item tests in `test_inputs.py`; they are in `tests/poster/test_claims.py`, which has the fixtures.
- Prior work: `kata search "claim tag message_event ENVELOPE MAX_CLAIM_BYTES"` gives ny5g (notes t8jr 4, s6mt 6), 3qyq (the split, yw7r's relay note) and this issue. ai-tools-alerts#gtw9 lists "attach the claim tag to each root and level change" as its first build item: this issue builds it; gtw9 keeps renewals and the step down.
