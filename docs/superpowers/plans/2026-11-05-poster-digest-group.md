# Plan: poster digest groups by vendor release and lead scope

Spec: docs/superpowers/specs/2026-11-05-poster-digest-group-design.md. Kata ai-tools-alerts#qg7p.

## Chunk 1: from_collector carries the release's fix version

- [ ] `aitools_alerts/poster/candidates.py` `from_collector.one` (line ~474): when `_fixed(f.get("fixed"))` is None and `f["product"]` is `macos` (case-insensitive), take the finding's source dicts whose `_url(url)` is among the retained candidate sources and whose host is `support.apple.com`. Each title must match from its start (`re.match`, not `fullmatch`: the impact text follows) `_APPLE_TITLE = APPLE-SA-[\w.-]{1,40} [^():]{1,120} \(macOS (\d{1,3}) fixed in (\d{1,3}(?:\.\d{1,4}){0,3})\): ` with the version's first component equal to the major; all must agree; else None. At least one such source.
- [ ] Tests in `tests/poster/test_candidates.py`: title version used; explicit `fixed` wins; two Apple titles disagreeing give None; an Apple source with a missing or unmatched title gives None; a version only in the impact text (`... 27.2: impact (component fixed in 1.2)`) gives None for a non-matching prefix; a non-macOS product gives None; a rejected (private-path) Apple URL gives None; a KEV source alongside is ignored.

Acceptance: `python3 -m pytest tests/poster/test_candidates.py -q` passes.

## Chunk 2: digest groups

- [ ] `aitools_alerts/poster/compose.py` `digest` (line ~278): after the dedupe, per level, build `(sort key, line)` items: critical one per advisory; `CVE-` ids with the plain `security advisory` title grouped on (primary URL, product name, synthetic); `LEAD-` ids with the plain title at notice grouped on (product name, synthetic); others single. Groups of one render the single line. Helpers `_single(a)` (today's line) and `_release(name, url, members, mark)`.
- [ ] Header N and section counts are the number of items.
- [ ] Group fix text: `fixed in <v>` when every member's `products[0].fixed` is the same non-empty value, else `update available` when `schema.is_primary(url)`, else `see the release`.
- [ ] Tests in `tests/poster/test_compose.py`: 44 notices on `https://vendor.example.com/en-us/149521` → one line `macOS: release 149521, 44 CVEs; see the release.` (not an allowlisted host), and `update available.` with `schema.is_primary` patched to accept that URL; 9 on `https://distro.example.com/security/notices/USN-8928-1` → one line; 12 `LEAD-` notices in Browsers → `Browsers: 12 unrated leads.`; header says 3 advisories for those (plus a critical on the same URL stays its own line, so 4); same fixed version → `fixed in`; a synthetic group carries the mark and does not merge with a real one; two KEV-kind highs on the catalog URL and two unverified highs stay separate lines; a group line the guard refuses is withheld as one item while a neighbouring group prints; the existing digest tests still pass (their advisories are not the plain kind).

Acceptance: `python3 -m pytest tests -q` passes (the repo's whole suite; no repoman row).

## Verification

- `python3 -m pytest tests -q` on the committed head and again after the rebase.
- `git diff origin/main...HEAD -- aitools_alerts tests | grep -Ei '<fleet-names>'` prints nothing.
- Diff stays under 300 changed lines (code + tests; run artifacts excluded).

## Rollback

`git revert` the commits; the coordinator reinstalls the poster.
