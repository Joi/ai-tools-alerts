# Run: s6mt-ruleset-level-function
Instruction: ai-tools-alerts#s6mt (starting rung floored at medium): a level function over structured fields, the authoritative-source table, a root-pinned ruleset (findings D2, D3, D10, D11 of the design review on ai-tools-alerts#h29n)
Stage: code-review:ruleset+poster
Rung: medium (start-floor medium: constraint-lens, BR2 REV1 NOV1 INT2 FC1 = 7; the dispatch brief floors it at medium too)
Lens: "poster and CLI produce byte-identical canonical tuples for the shared vectors"; "A model's reading may add wording and may raise to high with `basis: reading`; it never makes a critical and never justifies a lowering"; "A source the subject's attacker can write never sets a level above notice and never lowers one"
Review tier: gpt-6-astra at high (h29n calls the work security-shaped)
Spec: docs/superpowers/specs/2026-11-24-s6mt-ruleset-level-function-design.md   Plan: docs/superpowers/plans/2026-11-24-s6mt-ruleset-level-function.md
Agency project: 01a20a63-76bf-7743-8ace-d2efaf98a0c8
Kata: ai-tools-alerts#s6mt
Limits: wall clock 5 hours from 2026-11-24 dispatch; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Last reviewed: spec 8ab1ebdbeb51069a127313b6d8c23b7092ccc9cd
Last reviewed: plan b917fce49a9425a15658b5ac0bb5e83d875d2361
Last reviewed: code 288c038ccd0d9dff97c47b08e90fb9368b20191d
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

## Chunks
- [ ] ruleset: spec/ruleset.json, spec/claim-vectors.json, aitools_alerts/ruleset.py, tests/test_ruleset.py
- [ ] poster: rules.level_for and claims_for on the ruleset; Evidence and Candidate carry the readings

## Notes
- Prior work searched: `kata search "ruleset level function claim canonical"` (hits: s6mt, h29n only); docs/superpowers specs for h340, tyje, zb8b (reused: scope identities and `authority`, the strict JSON readers, the canonical-JSON convention of the manifest and checkpoint).
- The spec and plan fixes after each review were applied with a script that asserts each replaced text occurs exactly once (it stops on a miss); later edits use the edit tool.
- Before the test edits the full suite failed in five tests: the four that expected a flag-made critical (`test_trojanized_without_primary_is_high_unverified`, `test_injection_exec_needs_fix`, `test_kev_learned_at_the_same_level_makes_the_japanese_action_urgent`, `test_a_model_read_flag_counts_only_from_a_record_that_cites_the_vendors_advisory_alone`) and `tests/test_schema.py::test_spec_files_agree_with_constants`, which lists the spec files. No other test changed.
- Size: 640 lines of code, 650 of tests, and the vectors file. The split named below was taken before the build; the half kept is one deliverable.
- Tempted to skip the Agency step, which composes a prompt and executes nothing; did it anyway.
- Split decided before the spec: the manifest's `ruleset` pin and the CLI's out-of-date line go to a follow-up issue (a manifest key a released reader refuses needs a release first); `min_cli` is ai-tools-alerts#t8jr's.
