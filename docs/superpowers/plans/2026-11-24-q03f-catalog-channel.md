# Plan: q03f catalog channel (producer side)

Spec: docs/superpowers/specs/2026-11-24-q03f-catalog-channel-design.md.
Verification while working: `python3 -m pytest -q tests/poster tests/mirror`;
`scripts/test-gate.sh` once on the committed result.

## Chunk 1 — the poster's catalog lane

- [ ] `aitools_alerts/poster/inputs.py`
  - `Config.catalog_known` (`<ledger>.catalog-known.json`),
    `Config.catalog_state` (`<ledger>.catalog.json`),
    `Config.catalog_lock` (`<ledger>.catalog.lock`) properties beside
    `recompute_state`; all three added to `check_paths()` (and its message).
  - `load_catalog_channel(channels) -> str | None`: reads
    `schema.SPEC_DIR / "catalog-channel.json"`; missing -> None; anything
    but `{"catalog": <lowercase uuid>}` distinct from the two alert ids ->
    `ConfigError`.
- [ ] new `aitools_alerts/poster/catalog.py`
  - `MAX_PER_RUN = 20`, `DEADLINE = 120`, `MAX_KEYS = 20000`,
    `MAX_FILE = 32 MiB`.
  - `key(product, adv_id)`: `f"{product}|{adv_id.casefold()}"`.
  - `snapshot(led, held) -> dict[key, adv dict]`: ledger entries kept when
    `rules.scope_of(e.scope)` resolves to that name and
    `rules.starts(scope, e.level)`; held notices; synthetic ids skipped; adv
    validated (`schema.validate`), an invalid one skipped; a ledger entry
    wins over a held notice for the same key.
  - `remember(path, snap)`: read the inventory (missing or malformed ->
    empty, one stderr line), merge (`snap` replaces per key), drop keys whose
    product `rules.scope_of` no longer resolves, cap by oldest `posted_at`,
    write with `inputs.write_json`. Shape `{"v": 1, "known": {key: adv}}`.
  - `fingerprint(adv) -> str`: sha256 of canonical JSON
    (`sort_keys=True, separators=(",", ":"), ensure_ascii=False`).
  - `send_pass(config, channel_id, send, now=time.monotonic) -> str`:
    non-blocking `flock` on `catalog_lock` (busy -> `"busy"`); read known and
    sent (malformed -> empty); for each differing key by (`posted_at`, key):
    stop at MAX_PER_RUN sends or DEADLINE; `compose.catalog_post(adv)`
    (ValueError -> record null event); send; ok/refused/failed/unknown as in
    the spec; save after each recorded result; prune sent keys not in known;
    return `f"{sent}/{waiting}"`.
- [ ] `aitools_alerts/poster/compose.py`: `catalog_post(adv: dict) -> str`.
- [ ] `aitools_alerts/poster/main.py`
  - `run(..., catalog_channel=None)`: `None` -> `inputs.load_catalog_channel`;
    `False` -> off (tests); `ConfigError` -> lane off, status
    `off-bad-spec`, one stderr line.
  - inside the ledger block, after `r.recompute()` and before `r.digest(...)`:
    when the lane is on, `catalog.remember(config.catalog_known,
    catalog.snapshot(led, state["held"]))` in a `try/except Exception`
    (stderr line, status `error`), so a failure never reaches alert work.
    Note: digest runs after; a notice it removes is already remembered.
  - after the `with Ledger(...)` block (lock released, checkpoint done),
    when `english_ok` and the lane is on: `catalog.send_pass(...)` in
    `try/except Exception`.
  - summary: append ` catalog=<status>` only when the spec file exists
    (lane on or bad spec).
  - module docstring: one paragraph.
- [ ] `tests/poster/test_main.py` env.run: `kw.setdefault("catalog_channel",
  False)`, so existing tests stay off once q3fd adds the spec file.
- Tests in new `tests/poster/test_catalog.py` (reusing `test_main` helpers;
  the catalog id added to `test_main.NAME` with `monkeypatch.setitem`):
  - lane off: no `catalog=` in the summary; sends unchanged.
  - high: feed root, then one catalog root (catalog send after feed);
    catalog text parses back to the same id and product.
  - held notice: one catalog root, no feed post; a notice first seen in the
    digest run still posts to the catalog (digest at 09:00 run).
  - nothing new next run: no catalog send; a fix learned: one new root.
  - same CVE in two products: two catalog roots.
  - synthetic (`kev_catalog=`) never reaches the catalog.
  - catalog `fail`: exit 0, the feed root sent, catalog retried next run.
  - catalog `refuse`: not resent while the block is unchanged.
  - the ledger lock is free during the catalog pass (a send stub that opens
    `Ledger(config.ledger)` succeeds).
  - catalog lock busy: status `busy`, no send.
  - MAX_PER_RUN: 25 held notices -> 20 sends, `catalog=20/5`.
  - with the checkpoint configured (reuse test_main's checkpoint setup), the
    owed state never holds a catalog event id.
  - `load_catalog_channel`: missing, malformed, same id as feed.
  - feed rule: an out-class product with channel_if at high posts to feed
    and to the catalog; a catalog-class high reading posts no feed root but a
    catalog root.

## Chunk 2 — the exporter writes catalog.json

- [ ] `mirror/export_mirror.py`
  - `CATALOG_SPEC = REPO / "spec" / "catalog-channel.json"`;
    `load_catalog(path, channels) -> str | None` raising `ExportError` on a
    bad file.
  - psql reader: `read(name, cid, limit=None)`; with a limit the query is
    `... ORDER BY created_at DESC LIMIT n` and the rows are reversed; file
    reader: last n rows.
  - `export(..., catalog=None)`: everything for the alert files unchanged and
    written first; then `_export_catalog(...)` in `try/except (ExportError,
    OSError, ValueError, subprocess errors)` -> `result["catalog"]`
    (`"<kept> events"` or `"skipped:<reason>"` or `"off"`).
  - `--catalog PATH`; summary line names the catalog when not `off`.
  - docstring.
- Tests in `tests/mirror/test_export.py` (fixture monkeypatches
  `em.CATALOG_SPEC` to a missing path so existing tests stay off):
  - catalog written; alert-tagged event in catalog rows dropped; catalog
    event in feed rows dropped from feed.json.
  - bad spec, same id as feed, reader raising for catalog: alert files and
    checkpoint written, `catalog=skipped:...`, no catalog.json.
  - newest kept under the cap.

## Chunk 3 — docs

- [ ] `docs/design.md`: "Catalog channel" section (file, inventory, send pass,
  identity and the alert-thread-wins rule, no checkpoint, Buzz mute answer,
  8nb4, q3fd, v46a).
- [ ] `spec/wire.md`: catalog.json paragraph.
- [ ] `CHANGELOG.md`: Unreleased entry with the operator note (three files
  beside the ledger; rollback).

## Rollback

Revert the merge commit; after q3fd, delete spec/catalog-channel.json.

## Amendments after the plan review (fresheyes, snapshot af07bb2)

- B1: no catalog file is read or written under the ledger lock. `snapshot`
  stays in memory under the lock (before the digest); `send_pass(config, id,
  send, snap)` merges it into the inventory under the catalog lock, waited for
  at most `LOCK_WAIT = 60` s, after the ledger is released and the checkpoint
  signed. A pass that cannot get the lock reports `busy`; the next run's
  snapshot carries every thread and held notice (a notice digested in that same
  run is the one loss, stated in the design section). Test: `remember` runs
  with the ledger lock free.
- B2: the catalog paths leave `check_paths`; `Config.check_catalog_paths()`
  runs only with the lane on and a clash turns the lane off
  (`catalog=off-bad-paths`), never the run.
- S3: the exporter starts the catalog only while the export is younger than
  `CATALOG_START_BUDGET = 150` s, and the catalog query times out at 45 s, so
  with the unit's 5-minute timeout and 5-minute timer the catalog never holds
  the alert export into the next run.
- S4: the exporter's catalog boundary is `Exception`; tests raise
  `RuntimeError` and `RecursionError`, and `main()` exits 0 when only the
  catalog fails.
- S5: the inventory is written within `KEEP_BYTES = 48 MiB` and `MAX_KEYS =
  5000`, newest first sight kept, below the 64 MiB read limit; a round-trip
  test.
- S6: the checkpoint test uses the signer tests' `signing` fixture and
  `PutRelay`, asserts the signed checkpoint lists the feed root and not the
  catalog root, and that catalog sends come after the checkpoint; a
  `pull._bound` test shows the window cannot admit a catalog-tagged event; the
  exporter test serves catalog-tagged rows in both alert channels.
