# Run: 6whv-reader-checkpoint
Instruction: Piece 3 of ai-tools-alerts#ek5q (brief TASK-ai-tools-alerts#ek5q.md, /do-it, starting rung floored at medium): the reader fetches the certificate and checkpoint, takes the higher manifest of the mirror and a second origin, applies only checkpointed events, refuses an incomplete mirror, reports stale from the checkpoint, and marks alerts unverified (no auto-apply) without a usable certificate and fresh checkpoint. The four attacks of the ek5q body become tests.
Stage: code-review:branch
Rung: heavy (escalated from medium at the plan review: its pass found three blockers in the design that the single medium pass left open; the pass taken counts as heavy's first, and the fix gets the one delta. Started medium: dispatch floor medium; no hard trigger: the reader handles public keys and signatures only, no secret, no credential, no deploy path. Start-floor evaluator not run: its rubric file is outside the paths the seat rules let this session read.)
Lens: "Readers at v0.1.4 are on member machines. A change they cannot parse must fail safe (they ignore it), never crash them."
Spec: docs/superpowers/specs/2026-11-23-6whv-reader-checkpoint-design.md   Plan: docs/superpowers/plans/2026-11-23-6whv-reader-checkpoint.md
Agency project: — (no agency tools in this session; built directly)
Kata: ai-tools-alerts#6whv (parent ai-tools-alerts#ek5q)
Review shape: one independent pass per artifact (fresheyes, gpt-6-astra: security-shaped per the brief), one delta only when a BLOCKER fix changes behaviour. Completion check: the test suite passes and the pull request is open (merges wait on ai-tools-alerts#xrx2).

## Scorecards
Pass 1 [spec]: 3B/4S/0C/0R · fixed -/- · velocity = (—→7, escalation no)   (fresheyes gpt-6-astra high, snapshot 298822f5, REASON=-)
  spec passes: 1 · fixed 7: unverified whenever the last pull failed (an incomplete pull kept auto-apply alive under the earlier fresh checkpoint); an applied set that only grows, seeded with the legacy events at the first checkpoint (a checkpoint omitting a retraction resurrected the alert); the certificate saved before the checkpoint is judged, and a stored checkpoint by a retired key reads unverified (a mirror could keep a key rotation from being recorded); save order and a completeness check at read so every interruption reads unverified; the stored checkpoint re-checked against the clock, and a distinct pull error for a checkpoint dated ahead; stale_since non-null whenever unverified, so hooks members already installed warn, plus the hook's wording; the test migration (the no-use test removed, the helper mirror serving certificate and checkpoint).
Pass 1 [plan]: 3B/7S/0C/0R · fixed -/- · velocity = (—→10, escalation yes)   (fresheyes gpt-6-astra high, snapshot a5ac6910, REASON=-)
  plan passes: 1 · fixed 10. B: applied ids are no longer pruned in the save that drops their events, and retention is no longer overridden by listing (an interrupted save could forget a stored retraction; a checkpoint could bring an aged-out thread back as its root). B: step 0 writes a durable "interrupted, not checked" record before anything is fetched (a failed write of the failure record left the reader verified). B: only a checked pull that finishes sets checkpoint_ok; a curator pull never does (it cleared the member side's refused pull). S: the automatic test checkpoint lists what an honest signer lists; the legacy freshness tests and the live fixture test are migrated explicitly; pull-level signature forgery tests; v0.1.4 reads state this reader wrote, and the tag is mandatory; a stale_since fallback with no manifest; state-file tests; the curator regression test; which tests must be red on the parent.
  Escalation medium to heavy: cause above. Delta pass follows over the spec and plan (git diff of the two snapshots).
Pass 2 [spec+plan delta]: 1B/3S/0C/0R · fixed 10/10 prior · velocity ↓ (10→4, escalation no)   (fresheyes gpt-6-astra high, git diff a5ac6910 55860df5, REASON=-)
  B fixed: an unlisted recent reply kept an aged-out root in the store without its forgotten retraction; a thread with applied events now takes its age from those alone (test: test_revoked_key_events_leave_and_old_threads_age_out_whatever_is_listed, test_interrupted_pruning_never_forgets_a_stored_retraction). The residual the fix cannot reach (the checkpoint key plus the mirror, against a reader that never held the retraction) is stated in the spec and the README.
  S fixed: the plan's two contradictory retention lines; the helper's signing clock made independent of event dates; the migrated expectations of the clock-set-back and freshness tests written down. No further pass on the design (ruling jibot-code#41e2); the code gets its own pass next.

## Chunks
- [x] chunk 1 — state file and the pull (pull.py, state.py, the poster's two calls, the curator's pull and reads)
- [x] chunk 2 — applied set, stale and unverified; CLI, config, hook, skills
- [x] chunk 3 — the four attacks and the compatibility tests (tests/test_attacks.py, tests/test_checkpoint_pull.py)

## Notes
- Stacked on zb8b-checkpoint-format (pull request 9, open, unmerged): reviews of this branch diff against that branch's head, not origin/main.
- Prior work: pieces 1 and 2 (ai-tools-alerts#gefy merged eb45e6e; ai-tools-alerts#zb8b). r0ra and fv4g build on this piece and are out of its scope.
- decided (execution): stale_since has no separate legacy rule. A reader without a checkpoint is always unverified, so the 3-day and 90-day rules could only choose which time to print; the spec section says so.
- decided (execution): the exporter's own reader tests pull with checkpoint=False until ai-tools-alerts#nfm3 makes the exporter publish a checkpoint.
- Gate: the suite passes; scripts/test-gate.sh stops at the public scan on main's merge commit eb45e6e (see ai-tools-alerts#ek5q). Pull request stays open; merges wait on ai-tools-alerts#xrx2.
