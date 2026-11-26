# Run: pypi-placeholders
Instruction: Read TASK-ai-tools-alerts#26f0.md in this worktree root, then run `kata show ai-tools-alerts#26f0` and follow the brief (publish aitools-alerts 0.0.2 as an empty placeholder whose text says no release is on PyPI and points at the README's verified signed release, with no install command; yank 0.0.1 with the same reason; reserve ai-tools-alerts with the same placeholder; keep the source out of the package tree; verify with one unauthenticated GET per name; close with evidence).
Stage: spec
Rung: heavy (start-floor heavy: hard-trigger, BR2 REV2 NOV1 INT2 FC2 = 9; the run reads PYPI_TOKEN from the helper and publishes to PyPI's live index, though neither enters the repository diff)
Lens: the token never enters the repository diff; empty package, no code/entry point/deps; no install command; keep placeholder source out of the package tree; no host/tailnet/VM/home-path names, no personal email
Spec: docs/superpowers/specs/2026-11-26-pypi-placeholders-design.md   Plan: docs/superpowers/plans/2026-11-26-pypi-placeholders.md
Agency project: — (no mcp__agency__* tools in this session; executed directly)
Kata: ai-tools-alerts#26f0
Last reviewed: spec 0b75c2ac5cd64c3d1d1d3594d47bff5bb77c52c7

## Scorecards
Pass 1 [spec]: 2B/5S/2C/0R · fixed -/- · velocity = (—→9, escalation no)   (fresheyes gpt-6.1-sol, run 20261126-112902-dca666, snapshot 0b75c2a)
  B: sdist runs install-time code → wheel only; install guard NAME misses ai-tools-alerts → extended. S: artifact selection, artifact/metadata inspection, only the similarity refusal counts, PEP 541 caveat → fixed; "vague snapshot commit message" → rebutted (dangling review object, never pushed). C: filename-reuse wording, 403 diagnosis → fixed.
Pass 2 [spec]: 0B/0S/0C/0R · fixed 7/7 prior · velocity ↓ (9→0, escalation no)   (delta 0b75c2a..7fc9804, run 20261126-113600-a1c79b, rebuttal stood)
Pass 1 [plan]: 1B/4S/1C/1R · fixed -/- · velocity = (—→7, escalation no)   (run 20261126-113700-d9d9a1, snapshot 04b8b41)
  B: whole-branch review came after the irreversible upload → blocking review before upload, checker committed, upload script quoted in the prompt. S: files must be committed before the scan; only the similarity 400 triggers the README form; NAME separator runs; verification compares description, HTTP status, post-yank evidence → fixed. C: top_level.txt newline → strip(). R: snapshot commit message → rebutted again.
Pass 2 [plan]: 1B/0S/0C/0R · fixed 6/6 prior · velocity ↓ (7→1, escalation no)   (delta 04b8b41..a510809, run 20261126-114212-f3d38b)
  B: the revised Chunk 3 lost "open the PR" → restored in Chunk 1's review step; no further pass (one delta).
spec passes: 2 · plan passes: 2 · plan pass 1 first launch (first launch FRESHEYES_STALLED REASON=CHILD_EXIT: "Selected model is at capacity", an environment failure; relaunched once).

## Chunks
- [ ] placeholder source + test + README/CHANGELOG
- [ ] publish (aitools-alerts 0.0.2; ai-tools-alerts 0.0.1 attempt), verify, yank hand action

## Notes
- Prior work: ai-tools-alerts#4fkh (README says nothing ships to PyPI; install guard test), ai-tools-alerts#fzr2 (PyPI reservation named as Joi's hand action). Session search: the 0.0.1 upload (2026-11-06T00:09Z) is not in any transcript on this host; its metadata gives author "Joichi Ito", no email.
- Credential: the vault holds PYPI_TOKEN, read through get_secret. Its macaroon carries one caveat, [3, <user id>] (RequestUser), so it is account-scoped and can create a project. Value never printed.
- PyPI has no API for yanking (web UI only), so yanking 0.0.1 is a hand action for Joi.
