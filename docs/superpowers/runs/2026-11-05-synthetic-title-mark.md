# Run: synthetic-title-mark
Instruction: Task ai-tools-alerts#hhe3 per TASK-ai-tools-alerts#hhe3.md — when the primary id is reserved (is_synthetic), the aitools-alert block's title starts with `SYNTHETIC TEST: ` and the head line keeps its mark; check, plan, run notifications and the skill then show it. Tests in test_compose and test_cli; the session-start hook line unchanged. Under 150 changed lines. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: code-review:compose-title
Rung: medium (start-floor medium: constraint-lens, evaluator BR1 REV1 NOV0 INT1 FC1 = 4, no hard trigger)
Lens: "the session-start hook line is unchanged"; "a synthetic test is never labelled real"; for any id that is not reserved, "the title never carries the mark"
Last reviewed: spec+plan ee1c94c0f30c3e6f238b6eeb51df5acdd12d13d7 (pass 1, gpt-6-astra)
Spec: docs/superpowers/specs/2026-11-05-synthetic-title-mark-design.md   Plan: docs/superpowers/plans/2026-11-05-synthetic-title-mark.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#hhe3

## Scorecards
Pass 1 [spec+plan]: 5B/0S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
- fresheyes gpt-6-astra, run 20261105-153244-8141aa; reviewer graded all five "major", read as BLOCKER.
- Fixed 1 (legacy synthetic roots, replayed journal entries and the Atom exporter stay unmarked) and 3 (a reader accepts a patch that removes the mark): `schema.validate` marks the title of any reserved primary id, so every reader path (pull roots and patches, parse_post, the exporter, the ledger) marks it whatever the post says.
- Fixed 2 (`test=True` could mark a real id): `root_post` drops `test`; only the id marks.
- Fixed 4 (the acceptance grep matched the plan itself): scoped to `aitools_alerts tests`.
- Rebutted 5 (snapshot commit message): ee1c94c is a dangling review snapshot built by commit-tree; it never lands on a branch.
- Medium rung: no delta on the documents; the BLOCKER fixes are code-reviewed in the code pass.

Pass 1 [code:compose-title, whole branch ef5b6a7]: Stage 1 0B/3S/2C · fresheyes (gpt-6-astra, run 20261105-153959-df6789) 3B/0S/0C · fixed -/- · velocity = (—→8, escalation no)
- fresheyes B2 + Stage 1 S1 (one cause: a synthetic title over 300 after the prefix was refused, so the root vanished from check/notify and the Atom exporter fell back to the unmarked first line): fixed, `validate` cuts the marked title to 300, never refuses; schema and Atom tests (a 300-char legacy title).
- fresheyes B3 (the writer sent an unmarked title patch because `_publishable` checked the re-marked merge): fixed, the template check reads the title as sent; test.
- Stage 1 S2 (no Atom test): fixed, `test_atom_marks_a_synthetic_root`.
- Stage 1 C4 (digest checked `SYNTHETIC`, validate `SYNTHETIC: `): fixed.
- Rebutted fresheyes B1 (a non-reserved id whose title a poster wrote as "SYNTHETIC TEST: ..." keeps it): compose never marks a non-reserved id (tested). A title a trusted poster wrote is that poster's label, and curator test threads use non-reserved ids (E3's SYNTHETIC-E3-CURATOR-1): stripping the words would present a curator's test as real, which breaks the stronger rule, a synthetic test is never labelled real.
- Rebutted Stage 1 S3 (no curator-path test): the curator's root and amend reach readers through the same `schema.validate` as the relay bot's, which test_schema and test_cli cover; the curator module builds no Advisory of its own.
- Rebutted Stage 1 C5 (`curator amend --title X` on a synthetic thread posts a no-op amend): a curator amending a synthetic thread is a by-hand test step; the reply still reads marked. Not worth code here.
- BLOCKER fixes changed behaviour: one delta pass `--since ef5b6a7`.

## Chunks
- [ ] compose-title — title mark, _titles, digest, tests

## Notes
- Skill rule slip: the spec/plan amendments after pass 1 were applied with a python str.replace script, not Edit; each replacement asserted or was checked by the harness diff shown afterwards, and the files read as intended. Later artifact edits use Edit.
- decided: no skill or hook edit. The skill quotes `title`, so the marked title reaches the agent; ai-tools-alerts#h260 edits the skills in parallel.
- decided: the head line keeps `(SYNTHETIC TEST)` per the brief, so it reads `CRITICAL (SYNTHETIC TEST): SYNTHETIC TEST: ...`.
