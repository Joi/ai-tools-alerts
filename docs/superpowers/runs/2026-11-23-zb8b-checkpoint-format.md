# Run: zb8b-checkpoint-format
Instruction: Piece 2 of ai-tools-alerts#ek5q (brief TASK-ai-tools-alerts#ek5q.md, /do-it, starting rung floored at medium): the root-signed checkpoint key certificate and the signed checkpoint, their parsers, verifiers and builders, and the script that signs the certificate. No reader behaviour change.
Stage: code-review:branch
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

## Chunks
- [x] chunk 1 — aitools_alerts/checkpoint.py and its tests
- [x] chunk 2 — scripts/sign-checkpoint-key.py and its tests (tests/test_checkpoint.py: 103 passed)

## Notes
- Prior work: piece 1 (ai-tools-alerts#gefy, merged eb45e6e) supplies pull.MAX_AHEAD_S. Design sources: the notice comment on ek5q of 2026-11-23, rule 7 of the design review (comments on ai-tools-alerts#h29n). kata search for checkpoint and lease found nothing else. capability-search not run: it is in a private repository the brief puts out of scope.
- Gate at this stage: the test suite passes; scripts/test-gate.sh stops at the public scan's history pass on main's merge commit eb45e6e (GitHub's merge of pull request 5, which carries the account's personal address as author; notice comment on ai-tools-alerts#ek5q). The hit is on main, not in this branch, and the known-hits baseline is outside what this session may edit.
- No merge from this session until ai-tools-alerts#xrx2 closes: the pull request stays open and the issue is labelled pr-open.
- CHANGELOG: the rebase onto main had left piece 1's entry under the 0.1.5 heading, a release that does not contain it. This branch moves it to a new Unreleased section.
