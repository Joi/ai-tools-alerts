# Run: ed7n-ruleset-pin
Instruction: Read TASK-ai-tools-alerts#ed7n.md in this worktree root, then run `kata show ai-tools-alerts#ed7n` and follow the brief and the dispatch rules. (Issue: self-correct: the root-signed manifest carries the ruleset pin; the CLI says when its ruleset is out of date, finding D10, second half of s6mt. Its first comment moves the pin from the manifest to the checkpoint key certificate.)
Stage: spec
Rung: heavy (start-floor heavy: hard-trigger, BR2 REV1 NOV1 INT2 FC2 = 8). Evaluator: "secrets, auth or credential handling — the diff changes `scripts/sign-checkpoint-key.py` (the script that signs with the trust root key) and changes what `checkpoint._parse_cert` / `verify_cert` check on the checkpoint key certificate". The dispatch floor was medium.
Lens (every review pass carries it): "a certificate without the key behaves as today"; "No rollout" (no signing step is run; it is filed as an issue); nothing built may wait for a person to act; released readers v0.1.6 and v0.1.7 "show what they showed before".
Last reviewed: spec 473b94f45de878e706b81d503c423ab5c15d6eb5 (the delta; first pass 8d460f1246dba3e2b9e57bc2ae54c7e0e1ec8d40)
Last reviewed: plan e015d6dfde1a7834653c1eadc29cf1c8b2204535 (the delta; first pass 473b94f45de878e706b81d503c423ab5c15d6eb5)
Spec: docs/superpowers/specs/2026-11-24-ed7n-ruleset-pin-design.md   Plan: docs/superpowers/plans/2026-11-24-ed7n-ruleset-pin.md
Agency project: —
Kata: ai-tools-alerts#ed7n
Limits: wall clock 5 hours from dispatch (2026-11-24T13:01Z); one independent review per artifact, one delta only after a behaviour-changing BLOCKER fix, three review rounds at most; completion check: `scripts/test-gate.sh` passes and the pull request is merged with the no-reply author address.

## Scorecards
Pass 1 [spec]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (fresheyes gpt-6.1-sol, reviewed 8d460f1246dba3e2b9e57bc2ae54c7e0e1ec8d40)
  B1 fixed: a None cache does not give `source_check: null` (`verify.result_for(adv, None)` answers "unknown, off"); `_check_json` gets its own out-of-date branch and the `verify = "off"` form is kept.
  B2 fixed: `test_unknown_content_keys_are_ignored` used `ruleset` as its unknown key; the spec and plan now change that example.
Pass 2 [spec]: 0B/0S/0C/0R · fixed 2/2 prior · velocity ↓ (2→0, escalation no)   (the delta, reviewed 473b94f45de878e706b81d503c423ab5c15d6eb5; passed)
Pass 1 [plan]: 1B/1S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (fresheyes gpt-6.1-sol, reviewed 473b94f45de878e706b81d503c423ab5c15d6eb5)
  B fixed: chunk 1's verification command named `tests/test_state.py`, which does not exist; it now names `tests/test_checkpoint_pull.py` and `tests/test_pull.py`, and chunk 2 names `tests/test_expiry.py` for the decay tests.
  S rebutted: the message of the reviewed commit is vague. It is the review snapshot, a dangling commit made to give the reviewer a fixed tree; it is on no branch and is never pushed.
Pass 2 [plan]: 0B/0S/0C/0R · fixed 1/1 prior · velocity ↓ (2→0, escalation no)   (the delta, reviewed e015d6dfde1a7834653c1eadc29cf1c8b2204535; passed, the rebuttal stands)

## Chunks
- [ ] pin in the certificate: `ruleset.outdated`, `checkpoint` parse, build and verify, the signing option
- [ ] the CLI's out-of-date line, `run --json` key, no judgment while out of date
- [ ] compatibility case with the released readers; changelog, `spec/wire.md`, README

## Notes
- Prior work searched: kata `ruleset pin certificate min_version` (two hits: this issue and ai-tools-alerts#s6mt, whose close-out and t8jr's note name the certificate as the place); auto-memory (three entries, all about this repository's test and merge rules). No earlier attempt at the pin.
- The repository has no `.repoman-managed` marker: the ending is a pull request this session merges (brief, "Landing"), not a repoman handoff. The gate is `scripts/test-gate.sh`.
