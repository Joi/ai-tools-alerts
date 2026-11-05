# Plan: retractions that survive revocation (ai-tools-alerts#jpzy)

Spec: docs/superpowers/specs/2026-11-05-manifest-retractions-design.md.
Standard library only; tests with pytest; gate `scripts/test-gate.sh`.
Budget: under 400 changed lines of code and tests.

## Chunk 1: manifest `retracted` (aitools_alerts/manifest.py, tests/test_manifest.py)

- [ ] Tests first (tests/test_manifest.py):
  - `test_retracted_absent_is_empty`: `content()` without the key loads
    with `m.retracted == ()` and verifies.
  - `test_retracted_loads_and_verifies`: `retracted=["CVE-2099-0001",
    "GHSA-aaaa-bbbb-cccc"]` loads into a tuple in the given order and
    verifies; `replace(m, retracted=())` does not verify.
  - parametrized `test_retracted_rejects`: not a list (`"CVE-1"`, `{}`),
    a non-string member (`1`, `None`), a bad id (`""`, `" CVE"`,
    `"-x"`, 129 chars), a duplicate, `MAX_RETRACTED + 1` entries.
  - `test_retracted_empty_list_loads` (an explicit `[]` is allowed).
- [ ] Code: `_CONTENT_KEYS` stays required; `_OPTIONAL_KEYS =
  frozenset({"retracted"})`; `_keys` gains an `optional` argument (the
  object's keys must include `keys` and be a subset of `keys | optional`).
  `MAX_RETRACTED = 1024`; `Manifest.retracted: tuple[str, ...] = ()`.
  `parse_content` returns `(version, issued_at, posters, retracted)`,
  checking each member with `schema._IDENT.fullmatch` (import `_IDENT` from
  `.schema`, which `manifest` already imports `ROLES` from) and rejecting
  duplicates. `_parse_event` passes the 4-tuple through; `load` builds the
  `Manifest` with it; `verify` compares the 4-tuple. Module docstring and
  `__all__` (`MAX_RETRACTED`) updated.
- Verify: `python3 -m pytest -q tests/test_manifest.py`.

## Chunk 2: readers (aitools_alerts/pull.py, tests/test_pull.py)

- [ ] Mirror helper: `Mirror.publish_manifest(..., retracted=None)` adds
  `"retracted": retracted` to the content when not None
  (tests/mirror_helpers.py).
- [ ] Tests (tests/test_pull.py):
  - `test_revoked_curator_retraction_needs_the_manifest_list` (the pinned
    case): second curator C in the manifest; bot root `advisory(id=X)`; C
    replies `retract`; pull: retracted. Manifest without C: pull: active,
    `dropped["revoked"] == 1`. Manifest without C and `retracted=[X]`:
    retracted, and `pull.active` is empty.
  - `test_manifest_retracted_matches_an_alias`: root with
    `aliases=["CVE-2099-0011"]`, list `["CVE-2099-0011"]`: retracted; an
    unrelated id in the list leaves it active.
  - `test_manifest_retracted_alias_dropped_by_patch_still_matches`: bot
    root with an alias, bot patch `{"aliases": []}`, list naming the alias:
    retracted.
  - `test_manifest_retracted_needs_a_signed_manifest`: a manifest with the
    list signed by another key: `res.error == "manifest not signed by the
    trust root"` and the thread stays as before.
  - `test_unlisting_reactivates`: v2 lists X, v3 drops it: active again.
- [ ] Code: in `advisories`, keep per root a set of ids (`{adv.id,
  *adv.aliases}` at the root, then `|= set(new.aliases)` after each applied
  patch). After the reply loop, `listed = set(m.retracted)`; a root whose
  set meets `listed` gets `retracted = True`. Ids compare case-folded
  (spec review fix); `manifest` refuses ids equal under casefold;
  sign-manifest merges case-folded. `advisories` skips kinds 5 and 9005
  (`_DELETION_KINDS`), tested with a curator- and bot-signed deletion. Docstring line for the rule.
  Module docstring paragraph: kind 9005 deletions are not read; a thread is
  withdrawn only by a trusted curator's retraction or the manifest list.
- Verify: `python3 -m pytest -q tests/test_pull.py`.

## Chunk 3: sign-manifest (scripts/sign-manifest.py, tests/test_manifest.py)

- [ ] Tests (each with a monkeypatched `TRUST_ROOT_PUBKEY` and the fake
  runner, as the existing sign tests do):
  - `test_sign_script_retract_round_trip`: v1 with `--retract A --retract
    B` → `m.retracted == ("A", "B")`; v2 with no flags keeps both; v3
    `--unretract A` → `("B",)`; v4 `--unretract B` → `()` and the content
    JSON has no `retracted` key.
  - `test_sign_script_merges_content_retracted`: content `retracted: [C]`
    plus previous `[A]` → `(A, C)`.
  - `test_sign_script_refuses_bad_unretract_before_reading_key`:
    `--unretract` of an absent id, and the same id on both flags → exit,
    runner never called, `--out` unchanged.
  - `test_sign_script_refuses_bad_retract_id_before_reading_key`.
  - `test_sign_script_refuses_unverified_previous`: `--out` holds a
    manifest signed by another key → refused before the key is read.
- [ ] Code: `--retract` / `--unretract` (`action="append", default=[]`).
  Read `previous` as today, then require `manifest.verify(previous,
  TRUST_ROOT_PUBKEY)` (die: "existing … is not signed by the trust root;
  move it aside to replace it"). `ids = set(previous.retracted if previous
  else ()) | set(raw.get("retracted", [])) | set(args.retract)`; refuse
  overlap between `--retract` and `--unretract`, and any `--unretract` not
  in `ids`; `ids -= set(args.unretract)`. `content["retracted"] =
  sorted(ids)` only when non-empty; re-run `manifest.parse_content(content)`
  so a bad `--retract` id dies before the key read. Docstring updated.
- Verify: `python3 -m pytest -q tests/test_manifest.py -k sign_script`.

## Chunk 4: curator retract (aitools_alerts/curator.py, tests/test_curator.py)

- [ ] Tests:
  - change `test_retract_is_reply_with_convention_text`: after the
    retraction is published, `find_threads(..., retracted_ok=True)`
    returns the thread; the default still raises "retracted".
  - `test_cli_retract_already_retracted_posts_anyway`: retracted thread,
    `cli.main(["curator", "retract", id, "--no-pull", "--dry-run"]) == 0`,
    stdout holds a `"retract"` event, stderr says `already retracted
    locally`.
  - amend on a retracted thread still fails (existing coverage; keep).
- [ ] Code: `find_threads(st, root, ref, retracted_ok=False)` returns all
  hits when `retracted_ok`; `cmd_curator` passes
  `retracted_ok=a.curator_cmd == "retract"` and prints the stderr note for
  each retracted thread before signing. Module docstring line.
- Verify: `python3 -m pytest -q tests/test_curator.py`.

## Whole result

- `scripts/test-gate.sh` (whole suite) passes.
- `git diff --stat origin/main` under 400 lines of code and tests.
- The fleet host-name grep from the brief's Gotchas, run on
  `git diff origin/main`, prints nothing; no nsec in the diff.
- Follow-up filed (ai-tools-alerts#0drq): the Atom rendering of manifest-listed retractions
  (mirror/export_mirror.py), priority 3, repo:ai-tools-alerts,
  discovered-from:jpzy.

## Rollback

Revert the branch's commits. Manifests without `retracted` behave as
before; none with it is published by this task.
