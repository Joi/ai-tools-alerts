# Run: s6mt-ruleset-level-function
Instruction: ai-tools-alerts#s6mt (starting rung floored at medium): a level function over structured fields, the authoritative-source table, a root-pinned ruleset (findings D2, D3, D10, D11 of the design review on ai-tools-alerts#h29n)
Stage: done
Rung: medium, with the one delta the Review Cycle rule gives a behaviour-changing BLOCKER fix (start-floor medium: constraint-lens, BR2 REV1 NOV1 INT2 FC1 = 7; the dispatch brief floors it at medium too)
Lens: "poster and CLI produce byte-identical canonical tuples for the shared vectors"; "A model's reading may add wording and may raise to high with `basis: reading`; it never makes a critical and never justifies a lowering"; "A source the subject's attacker can write never sets a level above notice and never lowers one"
Review tier: gpt-6-astra at high (h29n calls the work security-shaped)
Spec: docs/superpowers/specs/2026-11-24-s6mt-ruleset-level-function-design.md   Plan: docs/superpowers/plans/2026-11-24-s6mt-ruleset-level-function.md
Agency project: 01a20a63-76bf-7743-8ace-d2efaf98a0c8
Kata: ai-tools-alerts#s6mt
Limits: wall clock 5 hours from 2026-11-24 dispatch; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Last reviewed: spec 8ab1ebdbeb51069a127313b6d8c23b7092ccc9cd
Last reviewed: plan b917fce49a9425a15658b5ac0bb5e83d875d2361
Last reviewed: code 288c038ccd0d9dff97c47b08e90fb9368b20191d (the tree of commit 29849773634f65506936366e13b6e92d1f0e99e2), then the delta `--since 29849773634f65506936366e13b6e92d1f0e99e2` at 77cf7b903077c4dfe8619e6da70e039b00b94af0
Unreviewed after the delta: 675fecc62f3ab9b0566f0f8c17959331fd9e4bef the fix of what the delta raised, and the merge of origin/main (c75433e7fab04accf63264771b25cb84cf87e241)
Follow-up filed: ai-tools-alerts#ed7n (the manifest carries the ruleset pin)

## Scorecards
Pass 1 [spec]: 6B/1S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
spec passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-064340-dbe351) · all six BLOCKERs fixed in the spec, the SUBSTANTIVE one rebutted

Spec findings and what was done:
1. BLOCKER, corroboration by "any second reading for the same product" lets an attacker's `MAL-` entry borrow an unrelated advisory. Fixed: no rule adds readings up; the level is the highest one reading gives; the `second` and `with_second` columns are gone.
2. BLOCKER, "flag candidates are high" would raise tier-2 and no-fix cases. Fixed: only the two critical returns change; every predicate stays.
3. BLOCKER, package order was not total. Fixed: total order over four fields, repeats refused, builder sorts.
4. BLOCKER, `cwes` was `null` in one place and `[]` in another. Fixed: `[]`.
5. BLOCKER, a KEV claim built from the `exploited` flag is not a fresh catalog reading after a merge and a deferral. Fixed: the reading is made in `from_kev` from the entry's own fields and is never written to the state file.
6. BLOCKER, more tests than two depend on a flag-made critical. Fixed: criterion 8 and the plan name them and what each keeps.
7. SUBSTANTIVE, the snapshot commit's message. Rebutted: it is a dangling commit made for the reviewer by `git commit-tree`; it is on no branch and never lands.

Pass 1 [plan]: 3B/2S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
plan passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-065019-6e8d1b) · all five fixed in the plan

Plan findings and what was done:
1. BLOCKER, the downgrade test raised a cap and not the level rule. Fixed: both, and the test asserts the version-2 ruleset computes critical first.
2. BLOCKER, the source-isolation test's finding would be held six hours once it is a high. Fixed: it carries a range; the hold keeps its own tests.
3. BLOCKER, the Japanese-action test cannot keep "same level, title kept, two replies". Fixed: rewritten as the raise it now is (one copy, one reply, the title "known exploited vulnerability", the urgent action asserted); title retention stays covered in `tests/poster/test_compose.py`.
4. SUBSTANTIVE, nothing tested that `admit` attaches the readings. Fixed: two tests through `main.run`, and the property test asserts claim counts.
5. SUBSTANTIVE, lowering authority and "a reading never lowers" were thinly tested. Fixed: withdrawn and live cases for every class, and a two-run test that a dropped flag lowers nothing.

Agency: both tasks evaluated (chunk1 85, chunk2 84, approve with changes; the changes are in the Notes).

Pass 1 [code:ruleset+poster]: 3B/3S/9C/0R · fixed -/- · velocity = (—→15, escalation no)
Pass 2 [code:ruleset+poster]: 2B/0S/0C/0R · fixed 6/6 prior · velocity ↓ (15→2, escalation no)
code passes: 2 (the whole change, then the one delta) · Stage 2 gpt-6-astra (fresheyes runs 20261124-070258-fabb7c and 20261124-071941-0bdfed) · Stage 1 a same-model reviewer on the whole change

Code findings, pass 1, and what was done (commit 77cf7b9):
1. BLOCKER (both reviewers), a list or object in a GHSA `type` or `severity` raised TypeError. Fixed: a string check before every lookup; `check_claim` answers `refused`.
2. BLOCKER, the CVSS check took a vector cut short and one stating a metric twice. Fixed: `cvss_metrics` requires the version's base metrics, each once, with defined values.
3. BLOCKER, any text in `withdrawn_at` or `withdrawn` counted as a withdrawal. Fixed: a UTC time or the reading is refused.
4. SUBSTANTIVE (Stage 1), the ecosystem pattern and the 50-package limit could not carry real OSV records. Fixed: registries as sources name them, 1000 packages.
5. SUBSTANTIVE (Stage 1), unassigned code points were refused, which depends on the Unicode version. Changed in 77cf7b9, and replaced in pass 2's fix by the ASCII rule.
6. SUBSTANTIVE (Stage 1), the property test compared the claim count with its own input. Fixed: counted from what went in.
7. COSMETIC, fixed: the catch-all row must come last; rule conditions take only known values; stale docstring and docs; unused import; the page's fields are built inside the guarded call; the dash range is written with escapes.
8. COSMETIC, rebutted (standing, given to the delta, none overturned): the poster's own looser CVE pattern (predates this change; the effect here is no reading); the four lines `from_kev` repeats (candidates cannot import rules); `basis`, `claims_for`, `Support.lowers` and `ttl_days` have no caller yet (the spec says so; t8jr, ny5g and fv4g are the callers).

Code findings, pass 2 (the delta), and what was done (commit 675fecc, no further pass):
1. BLOCKER, a valid CVSS 3.1 vector with its metrics in another order was refused. Fixed: order is fixed for 4.0 only.
2. BLOCKER, with unassigned characters let through, a KEV name with U+1CCD8 bound to Claude Code on a reader with Unicode 16 and to nothing on one with Unicode 14. Fixed: every string of a reading, a claim and the digest's input is printable ASCII; the non-ASCII vector became one that shows the two escapes.

## Chunks
- [x] ruleset: spec/ruleset.json, spec/claim-vectors.json, aitools_alerts/ruleset.py, tests/test_ruleset.py
- [x] poster: rules.level_for and claims_for on the ruleset; Evidence and Candidate carry the readings — committed 2984977, review fixes 77cf7b9 and the commit after it

## Notes
- Prior work searched: `kata search "ruleset level function claim canonical"` (hits: s6mt, h29n only); docs/superpowers specs for h340, tyje, zb8b (reused: scope identities and `authority`, the strict JSON readers, the canonical-JSON convention of the manifest and checkpoint).
- The spec and plan fixes after each review were applied with a script that asserts each replaced text occurs exactly once (it stops on a miss); later edits use the edit tool.
- Before the test edits the full suite failed in five tests: the four that expected a flag-made critical (`test_trojanized_without_primary_is_high_unverified`, `test_injection_exec_needs_fix`, `test_kev_learned_at_the_same_level_makes_the_japanese_action_urgent`, `test_a_model_read_flag_counts_only_from_a_record_that_cites_the_vendors_advisory_alone`) and `tests/test_schema.py::test_spec_files_agree_with_constants`, which lists the spec files. No other test changed.
- Size: 640 lines of code, 650 of tests, and the vectors file. The split named below was taken before the build; the half kept is one deliverable.
- Tempted to skip the Agency step, which composes a prompt and executes nothing; did it anyway.
- Gate: `scripts/test-gate.sh` exit 0 three times: 1805 passed on the first build, 1845 after the pass-1 fixes, 1946 on the tree merged with origin/main (which brought t8jr's tests).
- Main moved during the run: t8jr (the wire format) landed. Its note moved the ruleset pin from the manifest to the checkpoint key certificate; ed7n carries that. `wire.claim_tag` writes the claim's canonical bytes, asserted by a test added in the merge commit.
- Notes left on ai-tools-alerts#9kgk, #fv4g, #ny5g, #t8jr and #ed7n.
- The rung did not climb: no hard trigger, and no BLOCKER or SUBSTANTIVE finding survived its pass unfixed. The delta is the Review Cycle rule's, not heavy's.
- Split decided before the spec: the manifest's `ruleset` pin and the CLI's out-of-date line go to a follow-up issue (a manifest key a released reader refuses needs a release first); `min_cli` is ai-tools-alerts#t8jr's.
