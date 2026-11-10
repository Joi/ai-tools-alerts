# A KEV alert must not say no fix is published when the source states no version (ai-tools-alerts#4yr1)

## Problem

A root post for a candidate with no fixed version says "No fixed version is known yet." and "Action: no fix is published yet; watch this thread." (Japanese: 修正版はまだ知られていません。 / 修正はまだ公開されていません。このスレッドで続報を確認してください。). The daily digest line says "no fix yet" (修正版はまだありません).

CISA's Known Exploited Vulnerabilities catalogue carries no version data, so every KEV-derived candidate reaches this branch. On 2026-11-10 the roots for CVE-2026-125350 (Chromium) and CVE-2026-123158 (OpenSSH) both told members no fix was published, while Google had shipped Chrome 157.0.8103.50/.51 on 2026-11-09 and OpenSSH had a fixed release. The poster turns "the source states no fixed version" into "no fix exists", and a member who believes it waits instead of updating — on a vulnerability known to be exploited.

## Success criteria

1. `compose.root_post`, when the candidate has no fixed version and the fix is not unexpressed (`fix_unexpressed(c)` false), writes:
   - Affected line suffix: ` The source does not state a fixed version; check the vendor's advisory.`
   - Action, not known-exploited: `Action: check the vendor for an update and apply it.`
   - Action, known-exploited: `Action: check the vendor for an update; this is exploited in the wild, so update now if a release is out.`
2. `compose.root_post_ja`, same branch:
   - 影響 suffix: ` 出典には修正版の記載がありません。ベンダーのアドバイザリを確認してください。`
   - 対応, not known-exploited: `対応: ベンダーの更新情報を確認し、リリースがあれば適用してください。`
   - 対応, known-exploited: `対応: ベンダーの更新情報を確認してください。悪用が確認されているため、リリースがあれば直ちに更新してください。`
3. "Fixed in X" / 修正版: X and the unexpressed branch are byte-identical to today.
4. Digest single line without a fixed version: `fixed version not stated, check the vendor` (en) and `修正版の記載なし、ベンダーの情報を確認してください` (ja), followed by the existing end mark. With a fixed version, unchanged.
5. No template the poster or the curator CLI fills in says or implies that no fix exists. `curator._body` and `main._advisory_text` (the English the poster sends for a curator translation, which mirrors `_body`) both say ` No fixed version stated.` instead of ` No fixed version yet.`. Verified on rendered output, not only by grep: tests render a KEV-shaped root (plain, unverified, synthetic), its Japanese twin and both digests, and assert none contains "no fix", "No fixed version is known", "watch this thread", "修正版はまだ" or "修正はまだ"; a grep of `aitools_alerts/` for the old literals returns nothing. A source's own title, quoted on its own line (`原題:` in Japanese), is the source's words and is not rewritten.
6. README, in the "What the bot posts" bullet: one sentence that KEV entries carry no version data, so such an alert may not name the fix even when one exists.
7. Tests: the existing assertions of the old wording (`tests/poster/test_compose.py` English root ~65-66, Japanese root ~361, Japanese digest ~389) change to the new strings; new tests cover the exploited and non-exploited actions, plain, unverified and synthetic titles, an exploited candidate merged into a thread whose title is not "known exploited vulnerability" (main.plan_known keeps the title when the level does not rise), and exact line equality of the fixed and unexpressed branches in both languages. Fixtures only; no live post.
8. `scripts/test-gate.sh` (public scan, then `python3 -m pytest -q`) passes.

## Approach

- Known-exploited: `root_post` uses `c.exploited is True` or the title. `root_post_ja` gains a keyword `exploited: bool = False`; it is exploited when that is true or when `_exploited(adv)` holds (`adv.title` ends with `known exploited vulnerability (<id>)`, true for the plain, `unverified` and `SYNTHETIC TEST:` variants `_kind` builds). The title alone is not enough: `main.plan_known` keeps a thread's title unless the level rises, so a thread that was a trojanized release and later appears in KEV keeps its old title in the merged Advisory. `main.py` therefore passes `exploited=k.exploited is True` (or `c.exploited is True` for a new root) at its three `root_post_ja` calls.
- `root_post` and `root_post_ja` change only the no-fixed, not-unexpressed strings.
- The digest's `nofix` strings change in `_DIGEST`. The digest has no access to the candidate, so the same wording covers both "no version" and "unexpressed" advisories; "not stated" is true of both.

## Alternatives considered

- Look up the vendor's fixed version (NVD, vendor feeds) for KEV entries. Right long-term, but a new provider-facing reader needs Joi's decision (global rule) and is a separate deliverable. Not this issue.
- Pass `c.exploited` into `root_post_ja` as a parameter. Changes the `main.py` call and the signature for something the title already carries.
- Drop the Affected suffix entirely. Leaves the reader not knowing whether a fix was checked; the brief asks for "the source does not state a fixed version".

## Out of scope (decided)

- Already-posted roots are not rewritten; a curator amendment for CVE-2026-125350 and CVE-2026-123158 is Joi's to send.

## Blast radius and rollback

Only text of new root posts and new digest lines changes; no schema field, ledger record or block content changes (the JSON block carries no wording). A post longer by about 40 characters stays well inside the relay's limits; `_guard` still runs on every body. Rollback: `git revert <commit>` on main and push; on the poster Mac, whose uv tool receipt installs from a local checkout of this repository, `git pull --ff-only` in that checkout, then `uv tool install --force --reinstall <that checkout>`. The `notice:` comment states it.

## Open questions

None.
