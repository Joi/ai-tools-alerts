# Plan: poster level rules and scope matching (B2)

Spec: docs/superpowers/specs/2026-11-05-poster-level-rules-design.md. Kata ai-tools-alerts#31x7.
One chunk; one commit `feat: level rules` (plus review-fix commits). Standard library only.

## Chunk 1

### Files

- Create `aitools_alerts/poster/rules.py`
- Create `tests/poster/test_rules.py`
- Create `tests/poster/conftest.py` (no-network guard)
- Modify `aitools_alerts/poster/candidates.py` lines 60-63: delete the `Source`
  dataclass; add `from aitools_alerts.schema import Source  # re-exported` beside
  the other imports. Keep `asdict` (Candidate still uses it).

### Steps

- [ ] 1. Write `tests/poster/conftest.py`: autouse fixture monkeypatching
  `socket.socket.connect`, `socket.create_connection` and `socket.getaddrinfo` to
  raise `RuntimeError("network in tests")`.
- [ ] 2. Write the failing tests in `tests/poster/test_rules.py`, building
  Candidates with a helper `cand(**kw)` (defaults: id `CVE-2026-0001`, product
  `Anthropic Claude Code`, no flags, `fixed=None`, one source
  `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`):
  - the plan's six: `test_kev_tier1_is_critical` (critical, `kev-tier1`, even with
    source_ok False), `test_kev_tier2_is_high` (Ubuntu, exploited → high
    `kev-tier2`; all flags + source_ok on tier 2 → never critical),
    `test_trojanized_without_primary_is_high_unverified` (and with source_ok →
    critical `trojanized-primary`), `test_injection_exec_needs_fix` (no fix →
    notice; fix + source_ok → critical `injection-exec-fixed`; fix, no source →
    high `unverified`), `test_scope_match_is_pattern_based` ("ANTHROPIC CLAUDE
    CODE", "anthropic" alone → None and logged, "Anthropic Claude Desktop" → None
    and logged, "acme widget" → None and not logged, "Docker on Ubuntu" → tier 1,
    full-width "Ｄｏｃｋｅｒ" → tier 1 via NFKC, "google chrome" not logged for "go"),
    `test_out_of_scope_is_none` (None for "acme widget", "", None, 42; level_for
    with None raises ValueError).
  - `test_fix_rce_tier1_is_high` (fixed + "remote code execution" → high
    `fix-rce-tier1`; fixed + "CRITICAL" alone → notice; no fix + RCE → notice).
  - `test_hint_never_raises_level` (local_level_hint "critical" on a plain tier-1
    candidate → notice).
  - `test_source_ok_requires_true_bool` (`source_ok=1` → treated as not ok).
  - `test_source_ok_needs_primary_and_200` (non-primary 200 → False without
    calling fetch for it; primary 404 → False; primary 200 → True; fetch raising
    → False, next source still tried; timeout passed is 10).
  - the `http_status` tests of step 8a, through a fake opener — no network.
  - `test_unmatched_log_is_caller_owned` (no `log` → nothing kept anywhere).
  - `test_source_is_schema_source` (`candidates.Source is schema.Source`).
- [ ] 3. Run `python3 -m pytest tests/poster/test_rules.py -q` → FAIL (module missing).
- [ ] 4. Implement `rules.py` per the spec: `_entries()` cached `load_scope()`;
  `_norm(text)` NFKC + lower; `vendor_words(entries)`; `scope_of`; `level_for`
  with the table's order; `_SEVERE` regex over `_norm(advisory_severity)`;
  `source_ok` (skips non-primary URLs and root pages); `_NoRedirect(
  urllib.request.HTTPRedirectHandler)` whose `redirect_request` returns None, so
  urllib never follows a redirect; `_request(opener, method, url, deadline)`, the
  explicit redirect loop (primary-only targets, at most `MAX_REDIRECTS = 5` hops,
  every response closed unread, an answer after the deadline counts as 0);
  `http_status(url, timeout=10, opener=None)` HEAD then GET through `_request`,
  run in a daemon thread joined for the time left, 0 if it is still running.
- [ ] 5. Apply the candidates.py Source change.
- [ ] 6. Run `scripts/test-gate.sh` → PASS (B1's tests included).
- [ ] 7. Acceptance one-liner prints `1 2 None`.
- [ ] 8. Leak check over added lines only, plan and run files excluded (they name
  the pattern): `git diff -U0 origin/main...HEAD -- . ':!docs/superpowers' | grep '^+' | grep -v '^+++' | grep -Eic 'host-a|host-b|host-d|host-e|host-f|host-c'`
  prints `0` (grep exits 1).
- [ ] 8a. Review fixes (spec+plan pass 1): tier-2 test per critical clause with
  source_ok True and False; `http_status` tests through a fake opener: HEAD 200,
  HEAD 405 then GET 200, redirect to a primary URL followed, redirect to
  loopback/http/non-primary path refused before any request, 6 hops refused
  (also alternating between two URLs), deadline expired → 0 without a request,
  every response closed and never read; the real opener does not follow
  redirects. Unmatched log covers "Google" and "Nous Research".
- [ ] 8b. Review fixes (code pass 1): a 200 after the deadline is 0 (HEAD and
  GET); a hung transport returns 0 at the deadline (thread); every fake response,
  successful ones included, is closed and a body read fails the test; 3xx without
  Location; HEAD network error then GET 200; `source_ok` skips root pages;
  severity regex takes "code-execution", "arbitrary commands" and full-width
  text; `_` splits vendor tokens; conftest also blocks `gethostbyname(_ex)`.
- [ ] 9. Commit `feat: level rules`.

### Verification

- `scripts/test-gate.sh` green.
- `python3 -c "from aitools_alerts.poster import rules; print(rules.scope_of('Anthropic Claude Code').tier, rules.scope_of('Ubuntu 24.04').tier, rules.scope_of('acme widget'))"` → `1 2 None`.
- Lines changed under 600.

### Acceptance

Spec success criteria 1-5.

### Rollback

`git revert` the chunk commit; nothing depends on `rules` until B3.
