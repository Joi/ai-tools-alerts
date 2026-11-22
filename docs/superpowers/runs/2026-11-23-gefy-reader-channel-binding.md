# Run: gefy-reader-channel-binding
Instruction: Piece 1 of ai-tools-alerts#ek5q (brief TASK-ai-tools-alerts#ek5q.md, /do-it, starting rung floored at medium): the reader accepts only kind 9 events with an h tag naming a channel in spec/channels.json (report M3), refuses an event dated more than a few minutes ahead of the local clock, and each manifest lists every retraction.
Stage: code-review:branch delta
Rung: medium (dispatch floor medium; start-floor evaluator not run: its rubric file is outside the paths the seat rules let this session read; no hard trigger in this piece: no key or credential handling changes)
Lens: "Readers at v0.1.4 are on member machines. A change they cannot parse must fail safe (they ignore it), never crash them."
Last reviewed: spec 5dcb8f3b0fffa8c0e0e148abe3d1ce893706e528
Last reviewed: plan 60fa6387f8fcb336c2b340f4e07fe72fd94070d9
Spec: docs/superpowers/specs/2026-11-23-gefy-reader-channel-binding-design.md   Plan: docs/superpowers/plans/2026-11-23-gefy-reader-channel-binding.md
Agency project: — (no agency tools in this session; built directly)
Kata: ai-tools-alerts#gefy (parent ai-tools-alerts#ek5q)
Review shape: one independent pass per artifact (fresheyes, gpt-6-astra: security-shaped per the brief), one delta only when a BLOCKER fix changes behaviour. Completion check: scripts/test-gate.sh passes and the pull request merges.

## Scorecards
Pass 1 [spec]: 2B/4S/0C/1R · fixed -/- · velocity = (—→7, escalation no)   (fresheyes gpt-6-astra high, REASON=-)
  spec passes: 1 · fixed 6: the --retract-from sweep is dropped (B: it widened a thread retraction into a global one; S: incomplete input; S: --unretract undone by the next sweep), see the notice on gefy; the date bound is an admission check, stored events are never re-judged (B: clock rollback undid a stored retraction); ChannelSpecError handled in pull and cli (S); test migration named: helper tags, fixture dates, clock, the far-future exporter test (S) · rebutted 1 (snapshot commit message: a dangling review snapshot, never landed).
Pass 1 [plan]: 0B/5S/0C/0R · fixed -/- · velocity = (—→5, escalation no)   (fresheyes gpt-6-astra high, snapshot 60fa6387, REASON=-)
  plan passes: 1 · fixed 5: one fatal path for a broken channel spec in cli.main (run printed twice); record passes the pull's clock to freshness; the four existing tests whose dates contradict the bound are named and re-clocked; the live signed fixture goes through the reader; a release-pinned v0.1.4 reader test over the regenerated fixture.
Pass 1 [code:branch]: 1B/5S/4C/0R · fixed -/- · velocity = (—→10, escalation no)   (Stage 2 fresheyes gpt-6-astra high on origin/main...61519d8, REASON=-: 1 critical, 3 major; Stage 1 same-model subagent: 0B/2S/4C, one S the same as the critical)
  B1 fixed: curator._after dated a correction after a stored future-dated reply, so the correction itself was refused everywhere; it now ignores stored events dated ahead and caps its result (regression test).
  S fixed: the exporter's date bound is an admission check too (a clock set back withdrew a published retraction); channel_ids requires exactly feed and critical, distinct, no duplicate key; the freshness tests now tell a broken filter from a working one (unbound event dated newer, revoked-key event channel-bound); a pull that refuses future-dated events warns on stderr (a slow clock lost news silently); last_pull's newest_event_at asserted for a stored future event.
  C fixed: stale exporter comment. C not changed: _bound on a hand-edited state file (the same input already breaks _thread_ref; State.load is the place, not this piece); no real-clock test of the fixture README's claim.
  Medium does not loop: the BLOCKER fix changed behaviour, so it gets the one delta pass of the Review Cycle (fresheyes --since 61519d8), no rebuttals file (nothing left unfixed that was B or S).

## Chunks
- [x] chunk 1 — reader: channel binding and the future-date bound (pull.py, cli.py, tests, fixtures)
- [x] chunk 2 — exporter publishes no future-dated or unbound event

## Notes
- Prior work: kata search (checkpoint, lease, manifest expiry, future-dated, h tag) found ek5q, r0ra (expiry against the checkpoint; its future-date bound is built here) and r98k (names M3; built here). capability-search not run: it is in a private repository the brief puts out of scope.
- Split of ek5q recorded in its notice comment of 2026-11-23: gefy, zb8b, 6whv, nfm3.
- Spec and plan edits after the spec review were made with checked Python replacements (each asserted one match), noted against the Edit/Write-only rule.
- decided (execution): the fixture mirror keeps its 2099 dates and the test suite runs the reader on a fixed clock (tests/conftest.py reader_clock), instead of moving the fixture to the past as the spec said. A fixture in the past ages out of the reader's 400-day retention and turns every CLI test stale after 3 days.
- decided (execution): the exporter binds an event to any alert channel in its --channels file, the reader's own rule, not to the one channel whose rows it came from; its summary line appends unbound= and future= after capped= so existing log matches hold.
- The released-reader test first ran v0.1.4 with HOME set; v0.1.4 takes the home from the password database, so one run wrote a last_pull.json into the real state directory of this machine, which did not exist before. Removed (trash); the test now points config.home at its temp home in-process.
- Both chunks are one commit and one review: the piece is one pull request.
