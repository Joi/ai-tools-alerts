# Run: t8jr-wire-format
Instruction: Read TASK-ai-tools-alerts#t8jr.md in this worktree root, then run `kata show ai-tools-alerts#t8jr` and follow the brief and the dispatch rules. (Issue: self-correct wire format: released readers refuse unknown fields; carry the claim outside the alert block, finding D12.)
Stage: committing
Rung: heavy (start-floor heavy: hard-trigger, BR2 REV1 NOV1 INT2 FC2 = 8). Evaluator: "secrets, auth or credential handling — the diff changes the code that mints and checks the root-signed checkpoint key certificate (`build_cert`, `_parse_cert`, and the content `scripts/sign-checkpoint-key.py` signs with the trust root key)". The dispatch floor was medium.
Lens (every review pass carries it): "The block schema does not change in the h29n slices"; "every alert still appears, at the same or a higher level"; "A lowering is its own event and carries no other change"; "the block schema is byte-identical to v0.1.4's".
Last reviewed: spec 9f7404cad0bac7c351fb1eee301cdf1f8cd0d4f4 (the delta; first pass a70b020345b0bf9ba2aee1c89407a5d1b604f362)
Last reviewed: plan 9f7404cad0bac7c351fb1eee301cdf1f8cd0d4f4
Spec: docs/superpowers/specs/2026-11-24-t8jr-wire-format-design.md   Plan: docs/superpowers/plans/2026-11-24-t8jr-wire-format.md
Agency project: —
Kata: ai-tools-alerts#t8jr
Limits: wall clock 5 hours; one independent review per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: `scripts/test-gate.sh` passes and the pull request is merged with the no-reply author address.

## Scorecards
Pass 1 [spec]: 2B/3S/1C/0R · fixed -/- · velocity = (—→6, escalation no)
  B1 fixed: a raise after a lowering is a lowering to a released reader; rule 2 (level changes travel alone on a lowered thread), `level_post`, two control tests.
  B2 fixed: the test compares active alerts and installation matches, now and thirty days on; rule 3 (no `expires_at` in a relay-bot block) with a control on all four tags; narrowing stated as out of the format.
  S1 fixed: the test contract for `min_cli` on the current reader is in criterion 4 and built.
  S2 fixed: the four composer tests are migrated; the spec names them.
  S3 rebutted: the commit reviewed was the review snapshot, a dangling commit made only to give the reviewer a fixed tree; it is never pushed. The branch's commits carry their own messages.
  C1 fixed: the reply-key row says what v0.1.7 does.
Pass 2 [spec]: 1B/0S/0C/0R · fixed 5/5 prior · velocity ↓ (6→1, escalation no)   (the delta, reviewed 9f7404cad0bac7c351fb1eee301cdf1f8cd0d4f4; the last pass on the spec)
  B fixed: rule 3 said a relay-bot block "carries no `expires_at`", but the schema requires the key in a root. It now says null in a root, absent from a reply, and `reply_post` refuses the key. Named in the kata comment; no further pass (one review, one delta).
Pass 1 [plan]: 2B/0S/0C/0R · fixed -/- · velocity = (—→2, escalation no)   (reviewed 9f7404cad0bac7c351fb1eee301cdf1f8cd0d4f4)
  B1 fixed: the same `expires_at` wording as the spec's delta finding: null in a bot root, absent from a bot reply.
  B2 fixed: the plan now says the current reader's compatibility pull passes the real timestamp and asserts the pull succeeded.
Pass 2 [plan]: 0B/0S/0C/0R · fixed 2/2 prior · velocity ↓ (2→0, escalation no)   (the delta, reviewed f66daaf1f3874dd7d2bd5936d4c21250cdb13bdb; passed)
Pass 1 [code:whole-branch]: 0B/2S/8C/0R · fixed -/- · velocity = (—→10, escalation no)   (reviewed caa12dbe; Stage 2 fresheyes gpt-6.1-sol: passed, 0B/0S/1C; Stage 1 same-model subagent: 0B/2S/7C)
  S fixed (Stage 1): `wire.claim_of` returned `1e999` as infinity and an escaped lone surrogate, which `claim_tag` cannot write; it now returns None for both.
  S fixed (Stage 1): rule 2 had no hook in code; `reply_post(..., lowered=True)` refuses any level change.
  C fixed (both stages): the 0.1.7 join exception in the changelog, `wire.py` and the composer comment; "every command that reads the feed"; "the 0.1.7 release and earlier"; the tag comparison by number; the mixed-reply control on v0.1.4 and v0.1.6; a deep-nesting case inside the size limit; the upgrade line cannot replace a command's status when stderr is gone; the signing script warns when a new certificate drops the floor.
  C not done: no test for the "new key in a reply's block" row on a released tag, and none for an expired certificate still reporting `min_cli`. Both are behaviours of code this branch does not change or of a deliberate choice stated in `cli._min_cli`; left for the slice that first sends a reply with a new key.
  No BLOCKER, so no delta pass on the code.

## Chunks
- [x] wire: the claim tag and the level-only reply (`aitools_alerts/wire.py`, `poster/compose.py`)
- [x] min_cli: certificate key, signing option, the CLI's upgrade line
- [x] compatibility test with the released readers; changelog and `spec/wire.md`

## Notes
- Prior work searched: kata `min_cli`, `claim tag wire format released reader`, the slices of ai-tools-alerts#9mx8; auto-memory (two entries, both about this repository's test and merge rules). No earlier attempt at this format.
- Agency execution: the agency tools are not available in this session (no `mcp__agency__*` tool is listed). The chunks are built in this session; the reviews and the gate are unchanged.
- The repository has no `.repoman-managed` marker: the ending is a pull request this session merges (brief, "Landing"), not a repoman handoff.
- The three chunks were built while the spec review ran and were reviewed as one unit, the whole branch, in one Stage 1 and Stage 2 round. That round is also the one independent whole-branch review the merge needs.
- Skip-temptation, resolved by doing it: writing the plan after most of the code existed felt redundant; it was written, reviewed twice, and its review found the clock setup the compatibility pull depends on.
- Changed lines: about 190 outside tests and documents, about 560 in tests. Over the 600-line guide counting tests; one deliverable, so not split.
- Gate: the public scan run in the shared working clone fails on objects that only other sessions' local branches reach (no object in common with this branch or with origin/main, checked with `--hit-ids`). The gate was run again in a clone holding only this branch and the tags, at 24d5d79433ccc0fbe6804b5e6cc42022b734bd57 (after merging origin/main): the scan found nothing new, 1778 passed, 1 skipped, exit 0.
- Follow-ups filed: ai-tools-alerts#yw7r (confirm the relay keeps an unknown tag), ai-tools-alerts#pwv0 (sign a certificate with `min_cli`).
- Notes posted on: ai-tools-alerts#9mx8 (the design's sentence, corrected), #wa6n, #q03f, #0xq6, #9kgk, #r0ra, #ny5g, #fv4g, #s6mt.
