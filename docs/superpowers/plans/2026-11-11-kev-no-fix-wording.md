# Plan: KEV alert no-fix wording (ai-tools-alerts#4yr1)

Spec: docs/superpowers/specs/2026-11-11-kev-no-fix-wording-design.md. One chunk, test first.

## Chunk 1 — wording

### Files

- `aitools_alerts/poster/compose.py`
  - near `_kind` (line ~192): add `_exploited(adv) -> bool`: `adv.title.endswith(f"{_KINDS[0]} ({adv.id})")`.
  - `root_post` (lines ~250-259): the not-fixed, not-unexpressed strings become the spec's English Affected suffix and the two Action lines, chosen by `_exploited(adv)`.
  - `root_post_ja` (lines ~279-294): same for the Japanese 影響 suffix and the two 対応 lines.
  - `root_post` uses `c.exploited is True or _exploited(adv)`; `root_post_ja` gains keyword `exploited: bool = False`, effective value `exploited or _exploited(adv)`.
  - `_DIGEST` (lines ~437, ~445): `nofix` becomes `fixed version not stated, check the vendor` / `修正版の記載なし、ベンダーを確認してください`.
- `aitools_alerts/poster/main.py`
  - line ~520 (new root): `root_post_ja` via `self._ja(...)` gets `exploited=c.exploited is True` (wrap in a lambda or pass through `_ja` as it accepts args; read `_ja` first).
  - lines ~581 and ~592 (plan_known copy and reply): `exploited=k.exploited is True`.
  - `_advisory_text` (~729): ` No fixed version yet.` → ` No fixed version stated.`
- `aitools_alerts/curator.py` `_body` (~126): same replacement, so `_advisory_text` still mirrors the curator root body.
- `tests/poster/test_compose.py`
  - `test_root_post_without_fix_and_unverified` (line ~65): expect the new English Affected suffix and the non-exploited Action line (a trojanized candidate).
  - new `test_root_post_no_version_exploited_en_ja`: a KEV-shaped candidate (`exploited=True`, `fixed=None`, `affected=None`), plain and `unverified`: English and Japanese Affected/Action lines read exactly as the spec; no line contains "no fix", "No fixed version is known", "修正版はまだ" or "修正はまだ".
  - new assertion: unexpressed (`fixed="see vendor"`-shaped, as the existing unexpressed test uses) and fixed candidates produce exactly today's strings (byte-identical lens).
  - `tests/poster/test_main.py`: a thread first posted as a non-exploited advisory without a fix, then a KEV candidate for it at the same level: the reply's Japanese twin (the full advisory after the changed lines) carries the exploited 対応 line. Read how existing plan_known tests build the poster first.
  - curator and `_advisory_text`: any test asserting "No fixed version yet." changes (grep found none; add one assertion in `tests/test_curator.py` for the new phrase).
  - `test_root_post_ja...` (line ~361): expect the new Japanese 影響 suffix.
  - `test_digest_ja_scaffold_and_groups` (line ~389): expect `修正版の記載なし、ベンダーを確認してください。`; add the English digest single line with `fixed version not stated, check the vendor.`
- `README.md` line 23 ("What the bot posts"): append the sentence: "CISA's catalogue carries no version data, so an alert built from one of its entries may not name the fixed release even when the vendor has shipped one; check the vendor's advisory."
- `CHANGELOG.md`: an "Unreleased" entry naming the wording change and the reason.

### Steps

- [ ] Update and add the tests above; run `python3 -m pytest tests/poster/test_compose.py -q` and see the new expectations fail.
- [ ] Change compose.py (`_exploited`, root_post, root_post_ja `exploited=`, `_DIGEST`); rerun `tests/poster/test_compose.py`: pass.
- [ ] Add the main.py wiring test (red), then change main.py's three `root_post_ja` calls (`exploited=`) and `_advisory_text`, and curator.py `_body`; run `python3 -m pytest tests/poster/test_main.py tests/poster/test_translate.py tests/test_curator.py -q`: pass.
- [ ] `grep -rn -e "No fixed version is known" -e "No fixed version yet" -e "no fix is published" -e "no fix yet" -e "修正版はまだ" -e "修正はまだ" aitools_alerts/` prints nothing.
- [ ] README and CHANGELOG.
- [ ] No deployment detail (host names, home paths) in the landed docs: `scripts/public-scan.sh`, the first half of the gate, is the check.
- [ ] Commit; then `scripts/test-gate.sh` (public scan + whole suite) on the commit.
- [ ] Review: Stage 1 subagent ∥ fresheyes on `git diff origin/main...HEAD`.

### Acceptance

Spec success criteria 1-7. The unexpressed and fixed branches' strings are byte-identical (asserted).

### Landing (k5tr lane, not repoman)

Review evidence comment on 4yr1; `git fetch`; fast-forward `main` to the branch (`git push origin HEAD:main`, refused if not a fast-forward); push the branch; reinstall the poster on the poster Mac: its uv tool receipt installs from a local checkout of this repository, so `git pull --ff-only` in that checkout (on main, clean tree), then `uv tool install --force --reinstall <that checkout>`, then check the installed compose.py carries `_exploited`; `notice:` comment naming the install time, commit and revert; close 4yr1 with `--commit`.

### Rollback

`git revert <sha>` on main, push, reinstall the poster the same way. No state, schema or ledger change to undo.
