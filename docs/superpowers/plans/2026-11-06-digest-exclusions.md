# Plan: digest exclusions (ai-tools-alerts#d3f6)

Spec: docs/superpowers/specs/2026-11-06-digest-exclusions-design.md

## Chunk 1 — compose and main (one commit)

- [x] `aitools_alerts/poster/compose.py`
  - `digest(advs_today, date, lang="en", *, retracted=(), now=None)`: after
    the `latest` pass, drop `a` when `is_synthetic(a.id)`, or
    `{a.id, *a.aliases}` case-folded meets `retracted`, or
    `now is not None and a.expires_at is not None and a.expires_at < now`.
    Docstring names the three exclusions.
  - Remove the now-unreachable synthetic marks in `_single`, `_group_key`
    (key tuple loses `syn`; `_group_line` indexes shift) and `_group_line`.
- [x] `aitools_alerts/poster/main.py`
  - `Run._withdrawn(root, fetch)`: `State.load(self.config.mirror_dir)`;
    `translate.bounded(pull.fetch(translate_mirror_url, ...), 120)`; an
    error in the result raises `ValueError`. Then `m = st.accepted(root)`,
    events `st.events_for(root)`. Ids: `m.retracted`; for `t` in
    `pull.threads_from(...)` with `t.retracted` or `t.adv.expires_at <
    now`: `t.adv.id`, `t.adv.aliases`; roots: `t.root_id`. Case-folded.
  - `Run.digest(root=TRUST_ROOT_PUBKEY, fetch=None)`: after the
    journaled-digest check, `try: gone, gone_roots = self._withdrawn(...)
    except (translate.CallError, OSError, ValueError)`: say "digest held"
    and return. A ledger entry whose `root_event_id` or channel copy id is
    in `gone_roots` adds its ids and aliases to `gone`. Pass
    `retracted=gone, now=self.now` to both `compose.digest` calls.
  - `run()`: `r.digest(root=translate_kw.get("root", TRUST_ROOT_PUBKEY),
    fetch=mirror_fetch)`.
- [x] `tests/poster/test_compose.py`
  - New `test_digest_leaves_out_retracted_expired_and_synthetic`: real
    critical + retracted (by alias, other case) + expired + still-active
    (expires_at == now) + synthetic; English and Japanese; count line and
    absence asserted; an expiry-clearing later version keeps it; all
    excluded → "no advisories" in both languages.
  - `_plain` default prefix `CVE-2098-` (not reserved); the synthetic
    fixture in the grouping test keeps `prefix="CVE-2099-"` explicitly and
    is asserted left out; the publication-guard subcase uses a separate
    real group; the Japanese test's expected lines lose the mark.
- [x] `tests/poster/test_main.py`
  - The `env` fixture serves a `mirror_helpers.Mirror` to every run
    (`mirror_fetch`, `root`), so no test reaches the network.
  - `test_synthetic_advisory_is_left_out_of_the_digest`.
  - `test_digest_leaves_out_withdrawn_ledger_posts`: a manifest-retracted
    ledger post → "no advisories"; `_withdrawn` over a signed curator
    retraction reply and a curator root with an expiry in the past; a
    ledger post whose feed copy is a withdrawn root → "no advisories".
  - `test_failed_mirror_pull_holds_the_digest`: no send, no digest date,
    stderr line; the next run with the mirror up sends it.

## Verification

- `python3 -m pytest tests/poster -q` while building; then the repo gate
  `scripts/test-gate.sh` once on the committed head.
- `git diff --shortstat origin/main -- aitools_alerts tests` near 150
  changed lines.
- The brief's fleet-host-name grep over `git diff origin/main`, written in
  a scratchpad script (never in a tracked file), prints nothing.

## Acceptance

Spec success criteria 1–6.

## Rollback

`git revert` the commit.
