# faxq: group alerts by fix, the version 2 wording, a one-line block

Issue: ai-tools-alerts#faxq, slice 6 of ai-tools-alerts#9mx8 (design sections 5 "Group by fix" and "Reply only when the instruction changes", and 6 "Wording"). Main at e2ac9b6 carries h340, ek5q, 0dvh, tyje, s6mt, t8jr, r0ra, wa6n, fv4g, ny5g and 9kgk; this spec is written against that code.

## Problem

On 2026-11-18 five advisories for `mcp-server-git`, all fixed by release 2026.11.18, became five root posts. A member's action was one upgrade. Each post's headline was "security advisory" plus an id, the product line restated the scope name, the action line could say "check the vendor", and the block took 73% of the post's characters.

## Success criteria

1. Advisories that one run sees in one scope entry, with no thread yet, whose stated fixed version is the same are one thread: one root whose block lists every id (`id` plus `aliases`), at the level of its loudest member, with a range that covers every member's (theirs when they agree; none stated when one states none; else everything before the fix). A candidate that already has a thread joins no fix group (two threads never become one). Joining a new advisory to an existing thread across runs is not in this slice (review finding, see Notes): ai-tools-alerts#btqg.
1a. A fix group deferred for any reason (busy, a stopped run) is kept as its members, each re-admitted alone by the next run. A held notice that a fix group meets keeps the group's new ids. A run never lowers a thread's stated fix (a group member sighted again with its own older fix leaves the thread's later one).
2. The 11-18 replay (`tests/poster/test_live_replay.py`, fixture `live-feed-2026-11-07-and-18.json`) posts one root, not five, and its English text equals a golden file, `tests/fixtures/poster/golden/11-18-root.txt`, line for line except the block line. The golden file's lines match the design's example except the headline (this slice: the source title, slice 7 writes the model text) and the Who line (omitted in this slice).
3. Root body, in order:
   - `LEVEL[ (SYNTHETIC TEST)][ (unverified: ...)]: <headline>`. The headline is the source's own title (`compose.source_title`), with the product name and a colon in front when the title does not already name it; with no usable title, `<product>: <kind>`. No id. The line is at most 90 characters; the title part is cut at a word boundary with an ellipsis to fit, and the markers are never cut.
   - `Affected: <package> <range> (<registry>).`, package and registry from the scope entry's `package` (`pypi:mcp-server-git` gives `mcp-server-git` and `PyPI`); an entry without a `package` names the product and gives no registry. Range words: `before`, `up to`, `after`, `from`, `exactly`; "versions not stated" only when the source gives no range (0dvh's wording for an unexpressible range stays).
   - `Do: <one verb as a sentence>.` With a fix: `Do: upgrade X to V or later.` A fix the schema cannot express: `Do: upgrade X to the fixed release the source names.` The stop_using critical (9kgk): `Do: no fix yet. Stop using X until one ships.` No fix otherwise: `Do: apply the source's workaround, if it gives one, until a fixed release ships.`, with `This is exploited in the wild.` in front when it is. Never "check the vendor" or "watch this thread".
   - `Covers N advisor{y|ies}: <ids>`: the thread's public ids (the id's public form, then its public aliases), N the count of GHSA ids among them, or of all of them when there is none.
   - `Source: <url>`.
4. The `aitools-alert` block of every relay-bot root and reply is one line of JSON (`separators=(",", ":")`, `ensure_ascii=False`) between the fences. Its keys and values are unchanged (t8jr): the block's `title` keeps its template form with the id, so `_titles`, `_exploited`, `_ja_title`, the digest grouping and every released reader read it as before.
5. Replies: the same contract (8ke5 and 0dvh kept); their lines use the new words (`Do:` for an action, the new range words), and the `title` change that rides with a raise prints no line of its own (the level line says it). Japanese replies match.
6. Japanese root (`root_post_ja`) has the same five lines: `<level>: <headline>`, `影響: <package><range>（<registry>）。`, `対応: ...`, `対象: アドバイザリ N 件: <ids>`, `出典: <url>`. The headline is the same English source title (names stay as they are; the 原題 line goes, since the headline is the title).
7. `scripts/test-gate.sh` passes; `tests/test_wire_compat.py` (released readers v0.1.4 to v0.1.7 against today's posts) passes unchanged.

## Approach

- `ledger.merge`: a second union key per candidate in a scope, `fix:<schema_fixed(c.fixed)>`, when the fix is expressible and the candidate is not synthetic. Members of a component are merged as today (`_merged`: ids, sources, readings, exploited unioned; fix and range from the first member with a publishable fix). The level is then computed once on the merged candidate, so the group stands at its loudest member.
- `ledger.merge(pairs, ledger, groups)`: id components first (as before), then fix components over those, skipping a component that has a thread; `groups` receives each fix group's id-merged members. `Run.defer` writes those members instead of the group. `Run.hold` unions a matching held notice's aliases with the new ids. `plan_known` keeps the thread's fix when a candidate's own fix is older (`versions.parse`).
- `compose.root_post` and `root_post_ja` build the new body; `schema.render_post` writes the minified block (its parse-back check stays); `reply_post` and `level_post` write a minified patch. New helpers in `compose`: `headline`, `covers`, `package_of(scope)`, `do_line` and their Japanese twins.
- `main.py` passes the scope's package to `root_post_ja` (it has no scope today).

## Alternatives considered

- Group in the digest or only in presentation: rejected; the member gets five interrupts.
- A new block key listing the covered ids: rejected by t8jr (a new key drops the root on every released reader). `aliases` already carries ids and is matched by every reader.
- Change the block's `title` to the headline: rejected; the reply check, the exploited test, the Japanese title and the digest all read the template title, and slice 7 changes the headline again.
- Join a later advisory to an open thread with the same fix (the first draft of this spec): taken out after the spec review. It needs the busy check on the thread's ids, a retraction check (the ledger has no retraction state; `_withdrawn` reads the mirror only for the digest), and a range rule for the joined member. Filed as a follow-up.
- Suppress a range-only reply as "not an instruction change": rejected; a corrected range changes whether a member's installed version matches, which is the member's instruction.

## Blast radius and rollback

Post text and grouping on the relay bot's posts only. Released readers parse the minified block like the indented one (JSON); the wire-compat test proves it. A grouped thread is one ledger entry with many ids; lookups by any id find it, as with aliases today. Rollback: revert the merge commit; existing threads are unaffected (their entries carry their ids).

## Assumes

- An advisory's fix is per thread; a joined member whose own range differs is still fixed by the thread's version.
- `posted_at` of a ledger entry is the root's send time.

## Open questions

None blocking. The Who line and the model headline are slice 7 (ai-tools-alerts#c6ak); the catalog (q03f) will need to know a thread covers several ids: note on that issue.
