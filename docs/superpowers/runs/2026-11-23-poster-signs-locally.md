# Run: poster-signs-locally
Instruction: ai-tools-alerts#vzc3 — start at medium (dispatched; never light). Brief: TASK-ai-tools-alerts#vzc3.md in the worktree root. Unmanaged repo: PR + self-merge ending, FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: committing (live steps done; merging)
Rung: heavy (start-floor heavy: hard-trigger, credential handling + live deploy path; BR2 REV2 NOV1 INT2 FC2 = 9)
Lens: secrets come from the secrets helper and are never printed; keep a backup of anything replaced and name it; a failed send must not wedge the hourly run; remove the key only after one real hourly run proves the new path; README.md:21 states only what is true
Spec: docs/superpowers/specs/2026-11-23-poster-signs-locally-design.md   Plan: docs/superpowers/plans/2026-11-23-poster-signs-locally.md
Agency project: 01a20524-cc46-7546-82de-98a6ed645033 (tasks A, B evaluated)
Kata: ai-tools-alerts#vzc3
Last reviewed: spec 115efa8b30d9332f03a319414edeec355398ac38
Last reviewed: plan 7ff12addae9b7ee75c845cfacd06da3de0d622f0
Last reviewed: code origin/main...63587deacea908be38777446185c13e9f0871e2a (whole branch); delta 192aeef..119098a (the scan's post-review change)
Pre-handoff review: —

## Scorecards
Pass 1 [spec]: 1B/5S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6-astra, run 20261123-060806-c98a97)
- B1 rollback kept key on VM: fixed (backup is the secrets store; no VM copy; tarballs repacked).
- S1 400 not permanent: fixed (refused only 413 or 400 `invalid:` JSON; else failed).
- S2 no bounded execution: fixed (20 s connect, 90 s wall deadline, 64 KiB cap).
- S3 manual send as proof: fixed (scheduled run only).
- S4 verifier by filename: fixed (scan derives pubkeys, recurses archives).
- S5 snapshot commit message: rebutted (a dangling review snapshot, never on the branch; branch commits get real messages).
Pass 2 [spec delta 115efa8]: 0B/3S/0C/0R · fixed 6/6 prior · velocity ↓ (6→3, escalation no)   (run 20261123-061544-cbe4d7; last pass)
- S1 repack breaks MANIFEST.txt; S2 rewrite overwrites the off-VM backup host's original via the pull: fixed together (delete VM tarballs after the off-VM backup host checksum match; pull has no --delete).
- S3 proof id not retained for non-digest sends: fixed (ledger channel id at that run's time, or the digest record).
Pass 1 [plan]: 0B/9S/0C/0R · fixed -/- · velocity = (—→9, escalation no)   (run 20261123-061933-fc7762; no BLOCKER, so no delta)
- late send after failed: fixed (lock-guarded cancel gate before first write); TIMEOUT name: fixed (IO_TIMEOUT); duplicate: fixed; FakeSSH consumers in test_translate/test_live_replay: fixed; grep allowlist: fixed; proof evidence: fixed; rollback mechanism (uv tool): fixed; post-removal rollback: fixed (named route backups, full recovery, README revert).
- commit message of the snapshot: rebutted (dangling review snapshot, never on the branch).
Pass 1 [code:whole-branch]: 0B/6S/4C/0R · fixed -/- · velocity = (—→10, escalation no)   (Stage 2 fresheyes gpt-6-astra run 20261123-063534-e77970: 0B/4S; Stage 1 subagent: 0B/2S/4C)
- fixed in 35e5a0e: scan fails closed on size/depth/unknown format; uppercase nsec; plan allowlist; rollback order; README ssh wording; duplicate id check.
- rebutted: a permanent non-invalid rejection retries hourly (deliberate; visible as failed=1; no duplicate post).
- no BLOCKER, so no delta (ruling jibot-code#41e2). Evidence line posted on vzc3 at oid 35e5a0ea738df20389e7ef879fe3a72a5da0bcc4.

## Chunks
- [x] A: transport signs and posts over HTTPS; config; key reader (82e5fc1)
- [x] B: docs and retired VM route (9c5e571, 63587de; review fixes 35e5a0e)

## Notes
- Live step 1 (poster Mac) done 2026-11-23 06:55 JST; PR https://github.com/Joi/ai-tools-alerts/pull/6 open, merges after the VM step.
- First draft of the spec/plan/manifest named two fleet hosts; the public scan caught it before any push and the unpushed commits were rewritten.
- Split before start (review-cycle rule: one deliverable per issue). This branch carries the poster change and README.md:21. Filed separately: the VM's relay-admin key swap (cell-fleet), the exporter's read-only database role, the third-origin fingerprint.
- The first scheduled run on the new path sent the 2026-11-23 digest; the event is in the mirror's feed.json under the relay-bot key. The relay VM's route and key files were removed after that run (details in kata).
- The first scan of the relay VM crashed on a damaged gzip (zlib.error not caught); fixed with a test. The second found no poster key but 23 upstream toolchain test fixtures it cannot open; `--allow-unread` takes their exact labels. The delta review (fresheyes gpt-6-astra, run 20261123-095730-2f55e2, 2 major) found that a waiver could cover a file whose bytes were never searched, and matched printed rather than raw names; both fixed in the next commit. No further pass, per the review cycle.
