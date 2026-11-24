# Run: c6ak-model-wording
Instruction: Read TASK-ai-tools-alerts#c6ak.md in this worktree root, then run `kata show ai-tools-alerts#c6ak` and follow the brief and the dispatch rules (do-it, starting rung floored at medium; the issue names the independent review on gpt-6-astra).
Stage: code-review:whole-branch
Rung: heavy (start-floor heavy: hard-trigger, credential handling: the poster reads the provider key for wording calls and writes the auth hold; BR2 REV1 NOV1 INT1 FC1 = 6)
Lens: "The text never enters the block and the CLI never reads it as an action"; "on rejection or any model error the post uses the source title and no Who line"; "nothing may wait for a person"; with model_wording off, "no call, no read of the key" and the summary line byte for byte as today.
Review model: gpt-6-astra (the issue calls the work security-shaped)
Spec: docs/superpowers/specs/2026-11-24-c6ak-model-wording-design.md   Plan: docs/superpowers/plans/2026-11-24-c6ak-model-wording.md
Agency project: —
Kata: ai-tools-alerts#c6ak
Last reviewed: —

## Scorecards
Pass 1 [spec]: 6B/0S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6-astra, snapshot 3e3130d4; 5 fixed in the spec, 1 rebutted: "do-it review snapshot" is the snapshot's own message, never landed)
spec passes: 1 · plan + code: one whole-branch pass below (see Notes)

## Chunks
- [ ] wording module and source text
- [ ] poster wiring, config, summary

## Notes
- Prior work: bq8v (curator translation, the call path and hold this reuses), faxq (headline(), root_post shape), k5tr (mention tokens), 9mx8 section 6, h29n D2 (a model's reading may word a post, never set a level). capability-search "model headline wording check": 0 hits.
- Agency MCP tools are not loaded in this session: chunks are executed directly, each checked by its plan's tests (recorded, not skipped).
- An accidental fresheyes launch (`fresheyes.sh --help`, detached) was stopped by its process group before it produced a verdict; it is not counted as a pass.
- Plan written while the spec review ran; spec findings are folded into the plan before its review.
- Was tempted to skip a separate plan pass: the code was built while the spec review ran, so a plan-only pass would review a plan already executed. Wrote the plan anyway and reviewed plan and code together in the one whole-branch independent pass; the issue allows three review rounds (spec, whole branch, one delta).
- Gate: scripts/test-gate.sh exits 1 in its public scan on 66 history objects reachable only from local refs/heads/rescue/2026-11-23/* (none on this branch or on origin/main; checked with merge-base --is-ancestor). Tracked as ai-tools-alerts#a373. The test half is run as `python3 -m pytest -q` for evidence.
- Provider-facing call: Joi's decision is design decision 4 on ai-tools-alerts#9mx8 (approved 2026-11-23); this reuses translate.py's call and key reader, adds no new reader.
- No repoman marker: the landing is a pull request merged by this session (xrx2 closed, so --author-email works).
