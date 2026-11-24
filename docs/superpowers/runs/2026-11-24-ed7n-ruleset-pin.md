# Run: ed7n-ruleset-pin
Instruction: Read TASK-ai-tools-alerts#ed7n.md in this worktree root, then run `kata show ai-tools-alerts#ed7n` and follow the brief and the dispatch rules. (Issue: self-correct: the root-signed manifest carries the ruleset pin; the CLI says when its ruleset is out of date, finding D10, second half of s6mt. Its first comment moves the pin from the manifest to the checkpoint key certificate.)
Stage: verifying
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
Pass 1 [code:whole-branch]: 1B/2S/5C/0R · fixed -/- · velocity = (—→8, escalation no)   (reviewed aeca706920adee5a76d72f986e35c01d3ade3692; Stage 2 fresheyes gpt-6.1-sol: failed, 1B; Stage 1 same-model subagent: 0B/2S/5C)
  B fixed (Stage 2): a certificate with a pin the reader cannot parse was refused, and `pull._choose_cert` then went on with the older stored certificate and no pin. An unreadable pin now loads as `ruleset_unreadable` and makes the reader out of date; a pull test covers a later certificate replacing a good one. This changes behaviour, so it gets the one delta.
  S fixed (Stage 1): main had released 0.1.8 under the branch. Merged; the changelog entry is under a new Unreleased heading; the documents say "0.1.8 and earlier"; the compatibility case runs v0.1.8 too.
  S fixed (Stage 1): the out-of-date clause of `_cache` had no test (a mutant survived). A test now caches a contradiction on a current CLI, then pins past it.
  C fixed: the wire.md sentence about a malformed pin (rewritten with the B fix); `verify`'s line no longer starts with `source check:`; the README names the three forms of the line; the exit-status sentence says a kept level can give exit 2; `cmd_run` computes the state once, `cmd_verify` returns before the inventory, `build_cert` parses the pin before signing.
Pass 2 [code:whole-branch]: 0B/0S/4C/0R · fixed 3/3 prior · velocity ↓ (8→4, escalation no)   (the delta, reviewed 83151d54999c9a677927d3d816f7c9429fa011e5; Stage 2 fresheyes `--since aeca706`: passed, no finding; Stage 1 same-model subagent: 0B/0S/4C, nine mutants of the fix all killed by the intended test)
  C fixed, with no further pass: `spec/wire.md` says "any other value that is standard JSON" (a certificate whose content is not standard JSON is refused as before); the nesting test asserts the flag outright and the dead `RecursionError` clause is gone; the no-expiry and cached-result tests run for the unreadable form too; the line says "ruleset unknown" when the reader's own ruleset cannot be loaded.

## Chunks
- [x] pin in the certificate: `ruleset.outdated`, `checkpoint` parse, build and verify, the signing option
- [x] the CLI's out-of-date line, `run --json` key, no judgment while out of date
- [x] compatibility case with the released readers; changelog, `spec/wire.md`, README

## Notes
- Prior work searched: kata `ruleset pin certificate min_version` (two hits: this issue and ai-tools-alerts#s6mt, whose close-out and t8jr's note name the certificate as the place); auto-memory (three entries, all about this repository's test and merge rules). No earlier attempt at the pin.
- The repository has no `.repoman-managed` marker: the ending is a pull request this session merges (brief, "Landing"), not a repoman handoff. The gate is `scripts/test-gate.sh`.
- Agency execution: the agency tools are not available in this session (no `mcp__agency__*` tool is listed). The chunks were built in this session; the reviews and the gate are unchanged.
- The three chunks were built while the spec and plan reviews ran and were reviewed as one unit, the whole branch, in one Stage 1 and Stage 2 round.
- Departure from the issue's acceptance, with a `notice:` comment on the issue: a malformed pin is refused when built, and when read it makes the reader out of date and does not refuse the certificate (the BLOCKER of the code review).
- Follow-up filed: ai-tools-alerts#46yr (rollout: sign a certificate that carries the pin). Notes posted on ai-tools-alerts#tavj, #0xq6, #c1g2, #faxq.
- `RELEASED` in `tests/test_wire_compat.py` does not list v0.1.8 yet; that list is the release's to extend (`spec/wire.md`, "Adding to the format"). The pin's own case runs v0.1.8.
