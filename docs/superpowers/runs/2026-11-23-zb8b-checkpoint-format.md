# Run: zb8b-checkpoint-format
Instruction: Piece 2 of ai-tools-alerts#ek5q (brief TASK-ai-tools-alerts#ek5q.md, /do-it, starting rung floored at medium): the root-signed checkpoint key certificate and the signed checkpoint, their parsers, verifiers and builders, and the script that signs the certificate. No reader behaviour change.
Stage: code-review:branch delta
Rung: heavy (dispatch floor medium; hard trigger in the diff: scripts/sign-checkpoint-key.py reads the trust root key and signs with it. Heavy is the medium pass plus one delta when a BLOCKER fix changes behaviour. Start-floor evaluator not run: its rubric file is outside the paths the seat rules let this session read.)
Lens: "Readers at v0.1.4 are on member machines. A change they cannot parse must fail safe (they ignore it), never crash them."
Spec: docs/superpowers/specs/2026-11-23-zb8b-checkpoint-format-design.md   Plan: docs/superpowers/plans/2026-11-23-zb8b-checkpoint-format.md
Agency project: — (no agency tools in this session; built directly)
Kata: ai-tools-alerts#zb8b (parent ai-tools-alerts#ek5q)
Review shape: one independent pass per artifact (fresheyes, gpt-6-astra: security-shaped per the brief), one delta only when a BLOCKER fix changes behaviour. Completion check: scripts/test-gate.sh passes and the pull request merges.

## Scorecards
Pass 1 [spec]: 0B/3S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6-astra high, snapshot b3cd1b81, REASON=-)
  spec passes: 1 · fixed 3: the order rules (seq scoped to the key, rollback and conflict refused, certificate order) are part of this piece as cert_order and checkpoint_order; a format version v: 1 so a later restriction fails closed instead of being ignored; the checkpoint certifies a bounded window agreed by signer, exporter and reader, with the ceiling lowered to 2,000 ids.
Pass 1 [plan]: 0B/2S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (fresheyes gpt-6-astra high, snapshot 628b1384, REASON=-)
  plan passes: 1 · fixed 2: forgery tests for both documents that only a signature check can refuse (signature corrupted; content changed with the id recomputed; content changed under the old id); the checkpoint's kind, tag and event-key boundary tested with checkpoint-shaped signed events.
Pass 1 [code:branch]: 2B/5S/5C/0R · fixed -/- · velocity = (—→12, escalation no)   (Stage 2 fresheyes gpt-6-astra high on origin/main...a3d4e8a, REASON=-: 1 critical, 2 major; Stage 1 same-model subagent with mutation runs: 1B/4S/5C, its B the same as one major, one S the same as the critical)
  B fixed: the script took a 64-hex key, and a hex secret is a valid public key half the time, so a pasted secret could be signed into the public certificate; it now takes an npub only and refuses the root and every manifest poster. B fixed: both loaders copied the event before checking its shape, so about 1 KB of nested JSON escaped as RecursionError; the shape is checked first.
  S fixed: the script refuses a certificate that readers holding the existing one would refuse (cert_order), and --out equal to the manifest; the tests now fail under each mutation the same-model pass ran (every dataclass field, duplicate keys and constants inside a valid event, non-canonical dates, the copy, manifest_version from a version 2 manifest, the 48-hour boundary, the script's check of what it signed). C fixed: dates must match the canonical ASCII form; checkpoint created_at bounded; seq up to 2^53 - 1.
  S rebutted (1): "the branch exceeds the plan's 600-line gate; split it". The code is about 430 lines; the rest is the refusal matrix of two signed formats. Module and script are one deliverable (the script is the module's only caller), and a split would buy a second review cycle of the same design. The plan's acceptance line is corrected.
  C not changed: verify_* on hand-built objects with hostile __eq__ (as manifest.verify); the temp file name and error prefix inherited from sign-manifest; an unwritable --out directory found after the key is read (no secret in the traceback).
  Heavy: the BLOCKER fixes changed behaviour, so one delta pass follows (fresheyes --since a3d4e8a --rebuttals).

## Chunks
- [x] chunk 1 — aitools_alerts/checkpoint.py and its tests
- [x] chunk 2 — scripts/sign-checkpoint-key.py and its tests (tests/test_checkpoint.py: 103 passed)

## Notes
- Prior work: piece 1 (ai-tools-alerts#gefy, merged eb45e6e) supplies pull.MAX_AHEAD_S. Design sources: the notice comment on ek5q of 2026-11-23, rule 7 of the design review (comments on ai-tools-alerts#h29n). kata search for checkpoint and lease found nothing else. capability-search not run: it is in a private repository the brief puts out of scope.
- Gate at this stage: the test suite passes; scripts/test-gate.sh stops at the public scan's history pass on main's merge commit eb45e6e (GitHub's merge of pull request 5, which carries the account's personal address as author; notice comment on ai-tools-alerts#ek5q). The hit is on main, not in this branch, and the known-hits baseline is outside what this session may edit.
- No merge from this session until ai-tools-alerts#xrx2 closes: the pull request stays open and the issue is labelled pr-open.
- CHANGELOG: the rebase onto main had left piece 1's entry under the 0.1.5 heading, a release that does not contain it. This branch moves it to a new Unreleased section.
