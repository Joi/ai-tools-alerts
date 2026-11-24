# Run: fv4g-member-source-check
Instruction: Read TASK-ai-tools-alerts#fv4g.md in this worktree root, then run `kata show ai-tools-alerts#fv4g` and follow the brief and the dispatch rules (ai-tools-alerts#fv4g, /do-it with the starting rung floored at medium): the member source check from three fixed endpoints, three results, and what cannot-verify means (findings D7 and D8 of the design review on ai-tools-alerts#h29n)
Stage: verifying
Rung: medium (start-floor medium: constraint-lens, BR1 REV0 NOV1 INT1 FC1 = 4; the dispatch brief floors it at medium too)
Lens: "No URL taken from an event is ever fetched"; "https only, no redirects"; "At most 10 fetches and 30 s per run"; "Runs in the hourly job, never in the session-start hook"; "no string from a source is printed or stored"; "a 404, a 429 and a truncated body are each `unknown` and change nothing"
Last reviewed: spec 6c065d9d7c14b70e4715cf4fc4684a960685caba
Last reviewed: plan 5106781b36e16a2b29fb4f6b4da1882ebb315983
Last reviewed: code 785da1da9f467e1b495435e6d909e8f8775c4d5f (the whole branch), then the delta `--since` it at 702d0560f6aac22b1ed3a3af2b277630606f3159
Unreviewed after the delta: the commit that fixes what the delta raised, and this record
Review tier: gpt-6-astra at high (ai-tools-alerts#h29n calls the work security-shaped)
Spec: docs/superpowers/specs/2026-11-24-fv4g-member-source-check-design.md   Plan: docs/superpowers/plans/2026-11-24-fv4g-member-source-check.md
Agency project: — (the Agency tools are not offered in this session; both chunks were built in the session itself)
Kata: ai-tools-alerts#fv4g
Limits: wall clock 5 hours from the 2026-11-24 06:27Z dispatch; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Split: decided before the spec. This run builds the source check and reports its results; applying them (the D8 table) is ai-tools-alerts#tavj.

## Scorecards
Pass 1 [spec]: 8B/3S/0C/0R · fixed -/- · velocity = (—→11, escalation no)
spec passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-153440-fe9758) · all eight BLOCKERs fixed in the spec; of the three SUBSTANTIVE findings two fixed, one answered by a stated rule

Spec findings and what was done:
1. BLOCKER, one supported product confirmed every product of the thread. Fixed: a result per product; the thread's summary is the worst.
2. BLOCKER, a bot-written alias could borrow an unrelated advisory's level. Fixed: an alias counts only when a source response ties it to the first id.
3. BLOCKER, the cache dropped `lowers`, so an attacker-written source's withdrawal read as a contradiction. Fixed: `lowers` is kept per product and per reading; a downward `contradicted` needs it true, else `unknown` for `unauthoritative`.
4. BLOCKER, with one read failed, "equal" was `confirmed` and never retried. Fixed: a failed read comes first; every product of the thread is `unknown`.
5. BLOCKER, a socket timeout does not bound name lookup or the whole request. Fixed: the request runs in a worker thread with a bounded wait of `min(10, what is left of 30)` seconds.
6. BLOCKER, a body shorter than its declared length could parse. Fixed: the declared length must arrive, or the chunked body must end; neither is a failed read.
7. BLOCKER, cached results outlived the ruleset. Fixed: the cache carries the ruleset digest; another digest is an empty cache.
8. BLOCKER, a flagged line could print an id `source_of` refuses. Fixed: only an id `norm_id` returned is printed; a thread without one is never flagged; a product name is printed only when it is the scope file's.
9. SUBSTANTIVE, a 304 gave a new decisive result against "200 only". Answered in the spec, not removed: the issue asks for conditional requests with stored ETags; a 304 is used only when the support parsed from that ETag's 200 body is held under the current ruleset, and criterion 4 now says so.
10. SUBSTANTIVE, `off` stored results that were never read again. Fixed: `off` is never stored.
11. SUBSTANTIVE, the snapshot commit's message. Fixed for later snapshots (a descriptive message); the commit is dangling and never lands.

Pass 1 [plan]: 5B/1S/0C/0R · fixed -/- · velocity = (—→6, escalation no)
plan passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-154134-8694b1) · all six fixed in the plan

Plan findings and what was done:
1. BLOCKER, "no string of a response in the file" cannot hold (the id is a key, a level is a word). Fixed: sentinel text in every field that must not persist, and a structural check of the file.
2. BLOCKER, `verify` was missing from the dispatch dictionary of `main`. Fixed, and the test calls `cli.main(["verify"])`.
3. BLOCKER, per-phase timeout tests pass with a deadline that restarts. Fixed: a three-phase cumulative test and an engine test where the last request gets only what is left.
4. BLOCKER, an exception's text could carry response text to stderr. Fixed: one fixed line; sentinel tests on stdout and stderr of `run` and `verify`.
5. BLOCKER, no test for a failed re-read after a cached success. Fixed: 404, 429 and a truncated body after a state change, with support cached.
6. SUBSTANTIVE, invalidation tested for level only. Fixed: an added product and an added alias over persisted state.

Pass 1 [code:verify+cli]: 4B/9S/3C/0R · fixed -/- · velocity = (—→16, escalation no)
code passes: 1 so far · Stage 2 gpt-6-astra on the whole branch at 785da1da9f467e1b495435e6d909e8f8775c4d5f (fresheyes run 20261124-155808-063ed0: 3 BLOCKER, 4 SUBSTANTIVE) · Stage 1 a same-model reviewer on the same commit (1 BLOCKER, 6 SUBSTANTIVE, 3 COSMETIC; its BLOCKER and one SUBSTANTIVE are Stage 2's too)

Code findings, pass 1, and what was done (the fix commit after 785da1d):
1. BLOCKER (Stage 2), an attacker-written first id could name a real exploited CVE and borrow its level. Fixed: which ids are the same advisory is taken only from a response that is an authority (`lowers`); an unreviewed advisory ties nothing.
2. BLOCKER (both), dropping an alias turned a true alert into `unsupported`. Fixed: KEV not listing a CVE is no authority (`unknown` for `unauthoritative`); for a GHSA or MAL first id the related ids are the ones its own response names, read whether or not the thread lists them. Residue stated in the spec: a CVE that KEV lists for another product, supported only through an alias the bot then drops.
3. BLOCKER (Stage 2), a fabricated notice was `confirmed` by an unreviewed advisory. Fixed: support from a class with `lowers` false is not a level; it confirms nothing.
4. SUBSTANTIVE (Stage 2), the timeout bounded the caller's wait, not the request. Fixed: one deadline inside the request, checked between phases and reads, the socket timeout set to what is left; on expiry the thread is told to stop, its connection shut, and nothing is sent after a late name lookup.
5. SUBSTANTIVE (Stage 2), the 30 seconds began late and were checked only before a request. Fixed: from the start of `run`, and before each thread.
6. SUBSTANTIVE (both), a list where a word belongs in `verify.json` crashed `run --json`. Fixed: any exception in the shape check is an empty cache; tested through `run --json`, `check`, `plan` and `run`.
7. SUBSTANTIVE (Stage 2), `LEAD-...:docker` passed `norm_id` and would be sent to OSV. Fixed: of OSV's ids only `MAL-` is looked up; found with it: the poster's thread ids are ledger keys (`CVE-...:slug`), which `norm_id` refused, so no real thread would have been read. They are now read by their public id.
8. SUBSTANTIVE (Stage 1), three failing critical threads took the whole budget every run. Fixed: longest untried first, then level.
9. SUBSTANTIVE (Stage 1), `confirmed` does not cover the range or the fixed version. Rebutted for this slice: it reports and applies nothing; the limit is stated in the spec, the README and the changelog, and carried to ai-tools-alerts#tavj, which applies narrowings.
10. SUBSTANTIVE (Stage 1), every result but `unread` was permanent. Fixed: anything but `confirmed` is read again after 24 hours.
11. SUBSTANTIVE (Stage 1), an older scope file contradicted true alerts. Fixed: a product outside this reader's scope is `unknown`; a CLI the root calls too old prints no source-check line.
12. SUBSTANTIVE (Stage 1), `run` read the sources before notifying. Fixed: the notification first.
13. COSMETIC, fixed: an empty KEV vendor no longer makes a name the ruleset refuses; more than 50 named ids is a failed read; the timing test's window is wider.
Also changed with these: `below-source` stands when a related id's read failed (it rests on bodies that were read; a junk alias must not hide it). The spec review had asked for every failure to be `unknown`; the first id's failure still is.

Pass 2 [code:verify+cli]: 0B/4S/0C/0R · fixed 13/13 prior (12 fixed, 1 rebutted) · velocity ↓ (16→4, escalation no)
code passes: 2 (the whole branch, then the one delta `--since 785da1da9f467e1b495435e6d909e8f8775c4d5f` at 702d0560f6aac22b1ed3a3af2b277630606f3159, fresheyes run 20261124-161340-4f910e, gpt-6-astra). No standing rebuttal was overturned.

Code findings, pass 2 (the delta), and what was done (the commit after 702d056; no further pass):
1. SUBSTANTIVE ("major"), `http.client` clears `conn.sock` once a closing response owns the socket, so the deadline and the cancellation lost it. Fixed: the socket is kept from the connect.
2. SUBSTANTIVE, a cache written before the KEV rule changed kept `lowers: true` for an unlisted CVE. Fixed: the cache version is 2; version 1 is an empty cache. (No release carried version 1.)
3. SUBSTANTIVE, `"names": [null]` passed the shape check and then raised in every run. Fixed: every name is text.
4. SUBSTANTIVE, a thread cut off by the budget stayed "never tried" and came first again each run. Fixed: it is marked as tried when it spent requests.

## Chunks
- [x] verify: aitools_alerts/verify.py, the `verify` config key, tests/test_verify.py
- [x] cli: the check in `run` and `verify`, results in `check`, README and changelog

## Notes
- Prior work searched: `kata search "member source check verify endpoints"` and `"result table unverified lowering 72"` (hits: fv4g and h29n only); the specs and run records of s6mt, t8jr, tyje and ek5q in docs/superpowers; the notes s6mt and t8jr left on fv4g. Reused: `ruleset.source_of`, `Ruleset.read`, the strict JSON readers of `schema`, `state.write_json`.
- `capability-search` was not run: the seat rules of this run forbid reading outside the worktree, and the script lives outside it.
- The response shapes of `api.github.com/advisories/<id>` and `api.osv.dev/v1/vulns/<id>` were confirmed with one unauthenticated request each for a 2021 advisory: `repository_advisory_url`, `cvss_severities`, `first_patched_version` as text, a weak ETag from GitHub, none from OSV, a strong one from CISA.
- The plan says tests first. The code of both chunks was written before its tests; every test was then run against it, and the six that failed were wrong tests (a helper that turned a wrong-typed value into a valid one, two cases that shared one state key, a mirror rebuilt under a new root, an output compared with another command's), not wrong code.
- Tempted to skip the Agency step when its tools were missing; there was nothing to run it with, so the build was done directly and is recorded as such.
- Size: `aitools_alerts/verify.py` about 540 lines, 120 more in `cli.py`, `config.py` and `ruleset.py`, about 960 of tests. Larger than the 600 the split aimed for; the half kept is one deliverable and was not split again.
- The rung did not climb: no hard trigger in the diff (no secret, credential or deploy path), and no BLOCKER or SUBSTANTIVE finding was left unfixed or unanswered after its pass. The delta is the Review Cycle rule's for a behaviour-changing BLOCKER fix, not heavy's.
- Found in review and worth knowing elsewhere: the poster's thread ids are ledger keys (`CVE-...:slug`); `ruleset.source_of` reads those as nothing and reads internal keys (`LEAD-...`, `AITA-...`) as OSV ids. `verify.norm_id` handles both; ai-tools-alerts#ny5g and ai-tools-alerts#tavj are told.
