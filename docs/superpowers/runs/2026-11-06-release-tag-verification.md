# Run: release-tag-verification
Instruction: Dispatch of ai-tools-alerts#b9mz in mode do-it, starting rung floored at medium; brief TASK-ai-tools-alerts#b9mz.md: add trust/allowed_signers with exactly the public-key line from the decided comment (principal 19930+Joi@users.noreply.github.com); README install section gets a short "Verify the release" block (clone, `git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.1.1`; v0.1.0 is unsigned, v0.1.1 the first signed tag; GitHub shows the tag as Verified); the mirror index subscribe block gets one line pointing at the verification section; CHANGELOG.md. No tag is cut. Under 80 changed lines.
Stage: done
Rung: heavy (start-floor heavy: hard-trigger credential handling — the diff adds the key file members' `git tag -v` trusts; BR1 REV0 NOV1 INT2 FC1 = 5; dispatch floor was medium)
Lens: "containing exactly the public-key line from the decided comment (principal 19930+Joi@users.noreply.github.com)"; "No tag is cut by this task"; "Under 80 changed lines"
Spec: docs/superpowers/specs/2026-11-06-release-tag-verification-design.md   Plan: docs/superpowers/plans/2026-11-06-release-tag-verification.md
Agency project: —
Kata: ai-tools-alerts#b9mz
Last reviewed: spec+plan 1eb44e7d00d6b893a814e1f023a0b1707269fcbe (pass 1); delta 1f37af88e12c3e88ac06eb0261f7bcaac0e5150a (pass 2)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan, snapshot 1eb44e7, fresheyes gpt-6-astra high, REASON=-]: 4B/2S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
- B1 verification did not bind what is installed (install by URL refetches; hooks copied from default branch): fixed (verify section before init; `git checkout v0.1.1 && pipx install .`; later commands run from that checkout).
- B2 Joi.keys and the Verified badge are the same GitHub account, not a second origin; abbreviated key: fixed (trust assumption stated; full fingerprint published on the mirror page, served from the relay VM; GitHub checks named as account-only).
- B3 signer-file test passes a different ed25519 key: fixed (exact bytes; fingerprint computed from the file must equal the mirror constant).
- B4 manual proof accepts `Good "git" signature` without principal/exit: fixed (exit 0 + principal; unknown-key and unsigned cases fail; explicit key path) — already run that way, Notes.
- S1 line budget excludes docs/superpowers, untracked files missed: count moved to the committed diff (fixed); the exclusion rebutted (build precedent, fzr2 FS1).
- S2 snapshot commit message vague: rebutted (dangling review snapshot, never lands).
Pass 2 [spec+plan delta, git diff 1eb44e7 1f37af8, fresheyes gpt-6-astra high, --rebuttals, REASON=-]: 3B/0S/0C/0R · fixed 4/4 prior · velocity ↓ (6→3, escalation no) — both rebuttals accepted by the reviewer
- DB1 one block ran checkout+install after a failed verify (newline ends the && chain): fixed (verify block alone; install block after the checks, "only after both checks pass").
- DB2 verify placed after the v0.1.0 install; `pipx install .` skips an existing install: fixed (Verify section first; `pipx install --force .`; init marked first-install; v0.1.0 block labelled unsigned, below).
- DB3 `git checkout v0.1.1` picks a same-named branch: fixed (`git checkout --detach 'refs/tags/v0.1.1^{commit}'`; proven in scratchpad, plain checkout landed on the branch).
- No third spec/plan pass (heavy = one pass + one delta); the fixes are covered by the code round, whose diff contains the README.
Pass 1 [code:branch, origin/main...0f61956; Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6-astra high, REASON=-]: 1B/4S/3C/0R · fixed -/- · velocity = (—→8, escalation no)
- FB1 (fresheyes) spec criterion 7's command counted docs/superpowers too: fixed (pathspec added). Doc-only: no delta.
- S1 README "Run it every hour" told a verified member to clone again (default branch, nested dir): fixed (run from the verified checkout; v0.1.0 clone line pins the tag's commit).
- S2 "Without pipx" had no verified form: fixed (`pip install .` from the verified checkout; v0.1.0 URL as the alternative).
- S3 mirror lists the URL install line before the verify line: fixed (verify line first, both languages). Order only, no new behaviour; no delta.
- S4 the mirror shows the fingerprint only after a deploy of a commit with this change: not code; named in the close-out and on jibot-code#gr5b for the v0.1.1 cut (deploy v0.1.1 to the mirror; also bump PIPX_LINE and the install lines to the verified form).
- C5 paragraph split: fixed. C6 `gpg.minTrustLevel=fully`: not taken; measured on git 2.55.0 an unlisted key already exits 1 (`No principal matched`), and the README requires exit 0 and the principal line. C7 CHANGELOG blank line: matches the file's existing style; left.

## Build
- Agency: not used, as on the earlier runs of this build; one 37-line chunk built directly while the plan delta ran (files disjoint from the reviewed artifacts).
- `pip install .` from the worktree into a scratch venv installs `aitools-alerts` and `aitools-alerts-poster` (the README's `pipx install .` path); venv deleted.
- tests/mirror/test_export.py: 68 passed.

## Chunks
- [x] trust file + README + mirror line + CHANGELOG + test — d54ac61, review fixes a5c666a (rebased on d5d9ff6); landed on main a5c666af5521f3e709a94c10f059a712c921f533

## Landing
- Gate (scripts/test-gate.sh: public scan + pytest): 1050 passed on 0f61956 and on 05a1970; 1068 passed on the rebased head a5c666a. ai-tools-alerts#rvw5 is closed; no known failure.
- 53 changed lines outside docs/superpowers. No tag cut. roborev: repo not enrolled, no post-push patrol; the review fixes after the whole-branch pass are doc/order only (no behaviour-changing BLOCKER fix), so no delta.
- For the v0.1.1 cut (coordinator): sign the tag; bump `__version__`, PIPX_LINE and the README install lines to v0.1.1 in the verified form; deploy v0.1.1 to the mirror so the fingerprint is served.

## Notes
- An accidental `fresheyes.sh --help` (no help flag; it took `--help` as scope) launched a detached review 20261106-080924-835d75; its process group was killed within a minute, no verdict used. Not counted as a pass.
- Proof (git 2.55.0, throwaway ed25519 key in the scratchpad, deleted): a tag signed by a key in allowed_signers -> `Good "git" signature for <principal> with ED25519 key SHA256:…`, exit 0; signed by a key not in the file -> `Good "git" signature with ED25519 key …` + `No principal matched.`, exit 1; unsigned annotated tag -> `error: no signature found`, exit 1. README must say: success is the line naming 19930+Joi@users.noreply.github.com and exit 0.
- kata search "signed tag allowed_signers": only b9mz itself.
- Prior run: docs/superpowers/runs/2026-11-06-release-v0-1-0.md (fzr2) tagged v0.1.0 unsigned and filed b9mz.
