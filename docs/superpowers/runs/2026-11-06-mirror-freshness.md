# Run: mirror-freshness
Instruction: ai-tools-alerts#544a per TASK-ai-tools-alerts#544a.md — pull records the newest trusted event's created_at and the manifest's issued time; check and the hook warn with one fixed line (never fail) when the newest trusted event is older than 3 days or the manifest older than 90 days; --json carries stale_since. Tests in tests/test_pull.py and test_cli.py. Under 200 changed lines. Dispatched as /do-it, starting rung floored at medium. Not repoman-managed; non-repoman ending (ff-merge to main, close issue). Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: committing
Rung: medium (start-floor medium: constraint-lens; BR1 REV1 NOV1 INT1 FC1 = 5; Lens: "warn with one fixed line (never fail)"; dispatch floor medium)
Spec: docs/superpowers/specs/2026-11-06-mirror-freshness-design.md   Plan: docs/superpowers/plans/2026-11-06-mirror-freshness.md
Agency project: — (executed inline, as the earlier tasks did)
Kata: ai-tools-alerts#544a
Last reviewed: spec+plan a5640bcbf85b73d51a9c129b4909c09de9d6c9ab; code (whole branch) 8176b3ed964c1da15c601a17fef8e057c0ab7c04
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/5S/1C/1R · fixed -/- · velocity = (—→7, escalation no)   # fresheyes gpt-6-astra on snapshot a5640bc (REASON=-), 6 major + 1 minor. SUBSTANTIVE fixed: (1) plan's max(...) unparenthesized generator → plan corrected (code already parenthesized); (2) plan's `rc=$?` would hide the exit-2 status → plan says the existing `$?` test follows the assignment directly (code did so; the exit-2 hook test passes); (3) plan wrote the fleet host names and its grep would match itself → plan uses scripts/public-scan.sh (external terms file); (4) both warning lines claimed "no new signed data" for the manifest-only condition, which is false → one template true for either condition, in cli.STALE_LINE, the hook, README, both SKILL.md and the snippet; (5) the revocation test passed even without freshness's role filter (pull's _filter already drops the events) → the test now puts an event from a key outside the manifest into the in-memory state and asserts freshness and stale_since ignore it. COSMETIC (minor) already met: check's text path uses the same root guard as run --json (cli._stale_since); a test for the mismatch added. R (rebutted): snapshot commit message (a dangling review snapshot, never on a branch; same rebuttal as earlier tasks). Summary notes: selective withholding with fresh heartbeats is not detected → spec "Limit" note, follow-up ai-tools-alerts#y779; a future-dated event from a trusted signer defeats the 3-day signal → the threat is the mirror operator, who cannot sign (spec Assumes), not changed.
passes: spec+plan 1 · no BLOCKER, so no delta.
Pass 1 [code:whole-branch]: 0B/2S/3C/0R · fixed -/- · velocity = (—→5, escalation no)   # whole branch origin/main...8176b3e. Stage 2 fresheyes gpt-6-astra (REASON=-): PASSED, 1 nit (trailing space in the plan → fixed). Stage 1 subagent: 0B/2S/2C. SUBSTANTIVE fixed: (1) run --json collected the inventory twice (_unseen_critical and the JSON branch each called _matches), doubling the hook's version probes against its 90 s timeout → cmd_run computes the matches once and passes them to _unseen_critical; (2) no test tied the real run --json text to the hook's substring → test_cli asserts '"stale_since": "' in the raw stale output, absent in the fresh output, and absent from json.dumps of a hostile title. COSMETIC fixed: last_pull's freshness fields on a pull that fails before accepting under a different root described the other root → null unless the stored root is the one pulled; README "Otherwise it prints nothing" → "(neither line)".
No BLOCKER → no delta pass (Review Cycle); SUBSTANTIVE fixes take no further pass.

## Chunks
- [x] chunk 1 — pull freshness (pull.py, tests/test_pull.py)
- [x] chunk 2 — check line, run --json stale_since, hook line (cli.py, hooks/claude-code/session-start.sh, tests/test_cli.py, tests/test_templates.py)
- [x] chunk 3 — README, SKILL.md, snippets/AGENTS.md

## Notes
- kata search "mirror freshness stale": only 544a itself. capability-search "mirror stale freshness": 4 hits, none overlapping (morning-brief, cap-experiment-watch, lane-tools-sync x2 are fleet tooling, not this reader).
- Spec and plan reviewed in one fresheyes pass (as the earlier tasks did); code written while it ran against the frozen snapshot.
- decided (kata comment): stale_since in run --json; check --json stays a list; no new exit status.
- Gate (scripts/test-gate.sh: public scan + suite) after the review fixes: 1039 passed. 190 changed lines excluding run artifacts.
