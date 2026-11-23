# Plan: a relay-bot patch never shrinks what a member sees (ai-tools-alerts#tyje)

Spec: `docs/superpowers/specs/2026-11-24-tyje-bot-patch-never-narrows-design.md`. One chunk, one pull request. About 150 lines of code and 250 of tests.

## Chunk 1: the range comparison, the reader rule, tests, docs

### Task 1: `versions.covers` (`aitools_alerts/versions.py`, before `affected()` at the end of the file)

- [ ] `_bounds(affected, fixed)`: the range as `check` reads it. Returns `(lower, upper)`, each `None` or `(sort key, inclusive)`; `None` for a range `check` cannot read (a non-string, more than four comparators, a comparator or `fixed` that `parse` cannot order). `>`/`>=`/`=` give a lower bound, `<`/`<=`/`=` an upper one, `fixed` an exclusive upper one. The tightest of each is kept: the highest lower bound and the lowest upper bound, an exclusive bound beating an inclusive one at the same version.
- [ ] `_empty(bounds)`: the bounds cross, or meet at one version without both being inclusive.
- [ ] `covers(affected, fixed, by_affected, by_fixed) -> bool`, the eight cases of the spec in the spec's order. It uses only `parse` and `_COMPARATOR`, the same readers `check` uses, so the two cannot read a range differently.

### Task 2: the rule (`aitools_alerts/pull.py`, at `_apply_patch`)

- [ ] Import `versions`.
- [ ] `_fixed_holds(old, new)`: `new` is null, or equals `old`, or both parse and `new` is higher. Judged apart from the range, because `check.plan` reads an upgrade's version from `fixed` (spec review, blocker 1).
- [ ] `_covered(p, by)`: one entry of `by` has `p`'s ecosystem, `p`'s name in lower case, a `fixed` that holds, and a range that `versions.covers` `p`'s.
- [ ] `_kept(a, by)`: one action of `by` has `a`'s verb and target and either `a`'s value or, for `upgrade`, a value that `_fixed_holds` (higher, or none).
- [ ] `_listed(s, by)`: one source of `by` has `s`'s URL.
- [ ] `_join(cur, new, stands)`: `cur`, then each entry of `new` that `cur` does not stand for, each replacing the entries it stands for. (Amended after the code review's blocker: the first plan held a narrowed field whole, which a patch dated earlier could turn against a later widening. See the spec, "Why a join".)
- [ ] `_apply_patch(adv, patch, role, dropped=None)`: unchanged up to validation, except that a field the patch omits is validated cut to the schema's limit and then kept whole. For a role other than `curator`, each of the three fields the patch names becomes the join of the thread's and the patch's, and `dropped["narrowing"]` is incremented once when a named list does not itself stand for the thread's. The level and expiry refusals stay.
- [ ] `threads_from` passes its `dropped` counter. When a non-curator patch is refused, it is counted `bad-patch` as today and then read again with only its `products`, `actions` and `sources`; if that changes the thread, it applies as a change.
- [ ] Docstrings of `_apply_patch` and `advisories` state the rule.

### Task 3: tests (`tests/test_bot_patch.py`, new)

End to end through `Mirror`, `pull.fetch`, `pull.advisories`, `check.match` and `check.plan`, with a member inventory holding Claude Code 2.1.3:

- [ ] The four patches of finding D1, one test each (parametrized): the advisory is unchanged, the member still matches and is shown `upgrade Claude Code 99.0.0`, the source URL is still there, `dropped == {"narrowing": 1}`.
- [ ] All four in one patch with a title change: counted once, the title applies.
- [ ] Narrower products held: a narrower range, a new lower bound, another spelling of the name, another ecosystem, an unreadable `fixed`, `fixed` cleared under a narrower `affected`.
- [ ] `fixed` set where there was none: held.
- [ ] `fixed` lowered, and `fixed` set, inside a range `affected` already bounds (`<50.0.0` with `fixed` 99.0.0 or null, patched to 50.0.0): held, and the plan still shows the original upgrade.
- [ ] A curator's title-only amendment after a held bot replacement of `products`: the title applies, `products` stay wide, the member still matches.
- [ ] Actions held: version lowered, version removed, other target, other verb, a changed value on another verb.
- [ ] A raise of `fixed` with its upgrade action applies (the acceptance test for a real correction).
- [ ] Add a product, widen `affected`, clear both range parts, the same name in another case, add an action, add a source and change `published_at`: each applies, nothing counted.
- [ ] A narrowing beside a level raise: the raise applies.
- [ ] Widen then narrow back: the widened state stays.
- [ ] A curator's narrowing patch on a bot thread applies whole; a bot narrowing on a curator thread is discussion (not counted).
- [ ] An upgrade action with no version, patched to carry one (products unchanged): the actions field is held; asserted on the stored action, since `check.plan` overwrites an upgrade's value with `fixed` (plan review).
- [ ] Each of the three lists starting with two entries: one kept and one removed is held; one removed or narrowed and one added is held, and the field equals the original exactly, so nothing a refused field adds survives (plan review).
- [ ] `versions.covers`: a table over the eight cases, and a grid test through `check.match` (plan review: `versions.check` alone cannot tell a match by name, which has actions, from an unparsable-version match, which has none): for every pair of ranges where `covers` says yes, no installation, with a readable, unreadable or missing version, is matched by the inner range and missed, or stripped of actions, by the outer. The null/null to star/null pair is asserted by name.
- [ ] Before the rule is wired (or with `_narrowed` stubbed to return nothing) the D1 tests fail: checked once by hand, recorded in the run manifest.

### Task 4: documents

- [ ] `CHANGELOG.md`, Unreleased: what changed, the cost (a true narrowing is held), what released readers do.
- [ ] `docs/design.md`, after the block description: what a reply may change, by signer.

### Verification

```
python3 -m pytest -q tests/test_bot_patch.py
scripts/test-gate.sh
```

Acceptance: both pass; `git diff origin/main --stat` shows no change under `spec/`, `aitools_alerts/schema.py`, `aitools_alerts/check.py`, `aitools_alerts/poster/` or `aitools_alerts/curator.py`, and no existing test file changed.

### Amendment after the code review (tests added)

- [ ] Two pulls per field: a widening applies, then a patch dated before it arrives; the widening's entry is still there and the member at 99.0.5 still matches.
- [ ] A backdated level raise turns a later patch (level raise plus widening) into a lowering: the patch is `bad-patch`, its title does not apply, its widening does.
- [ ] `_apply_patch` folded over every order of five product patches: every signed entry is stood for, and the list is the same four entries.
- [ ] A thread joined to 101 products still takes a bot level raise and a curator's title.
- [ ] `versions.covers` is transitive over a grid.
- [ ] Earlier tests that asserted a field unchanged after a narrowing now assert the join: nothing removed, additions appended.

### After the merge

- [ ] `rollout:` issue for the release that carries the rule to members (label `discovered-from:tyje`); no release is cut here.
- [ ] Notes on ai-tools-alerts#h29n (what the member check must lift: held true narrowings; `title`, `aliases`, `advisory_severity` and the position of an added source are still the bot's to change) and ai-tools-alerts#ny5g (the poster's ledger differs from readers after a held narrowing).

### Rollback

Revert the merge commit. No stored state depends on the rule: the reader replays stored events on every read.
