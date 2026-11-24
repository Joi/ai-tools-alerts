# Run: ny5g-lower-on-held-evidence
Instruction: ai-tools-alerts#ny5g (starting rung floored at medium): the poster lowers only on positive evidence held 24 h; outage, 404 and flapping lower nothing (findings D4, D13 and D15 of the design review on ai-tools-alerts#h29n)
Stage: verifying
Rung: heavy from the spec pass on (one BLOCKER of the spec pass is not fixed in this slice: see finding 4); started medium (start-floor medium: constraint-lens and FC=2, BR1 REV2 NOV1 INT1 FC2 = 7; the dispatch brief floors it at medium too)
Lens: "Nothing you build may wait for a person to act."; "`unknown` (timeout, 3xx, 403, 404, 429, 5xx, parse error, truncated or oversized body) changes no level and does not count toward expiry"; "A 404 is never a withdrawal."; "The bot does not get `retract`"; "`fetch_kev` already separates `unavailable`; keep that through the recompute."
Last reviewed: spec 7882422261538c32c5b289a756319316061c0e68, then the delta at b05a51660891e93b426e112a343e9959af692861
Last reviewed: plan b0d8fdb37e08fc1017fe1ad4ac45fc8dfe5d3b12, then the delta at 1a2cddb0a5f16aacd355df089da1e99bf6281319
Last reviewed: code d389897214eb710a576249ebbfc9e71a5920a85a (the whole branch), then the delta `--since d389897214eb710a576249ebbfc9e71a5920a85a` at b973e755b84b6b479afa794b2224525faeea7a8c
Unreviewed after the delta: the commit that fixes what the delta raised (named in the close-out comment on the issue)
Review tier: gpt-6-astra at high (h29n calls the work security-shaped)
Spec: docs/superpowers/specs/2026-11-24-ny5g-lower-on-held-evidence-design.md   Plan: docs/superpowers/plans/2026-11-24-ny5g-lower-on-held-evidence.md
Agency project: — (this session has no Agency tools; see Notes)
Kata: ai-tools-alerts#ny5g
Limits: wall clock 5 hours from the 2026-11-24 dispatch; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.
Follow-up filed: ai-tools-alerts#3qyq (GHSA and OSV readers, the `withdrawn` state, the claim tag); ai-tools-alerts#jsje (an unknown or refused send settled without a person)

## Scorecards
Pass 1 [spec]: 7B/3S/0C/0R · fixed -/- · velocity = (—→10, escalation no)
spec passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-153340-acac13) · six BLOCKERs fixed in the spec, one moved to its own issue with the reason below; two SUBSTANTIVE fixed, one rebutted

Spec findings and what was done:
1. BLOCKER, the catalog checks do not show completeness and the seven-day rule made a small copy the measure. Fixed: the measure is the largest complete copy ever read and never falls; no time makes a small copy complete; a CVE's absence counts only after a complete copy listed it (criterion 4). The 2% tolerance itself is the issue's rule and stays.
2. BLOCKER, an outage supplied the 24 hours. Fixed: the wait counts time only between complete reads, two hours a gap at most.
3. BLOCKER, a journaled lowering was replayed without looking at the evidence again. Fixed: an unsent lowering no channel has is removed before the journal drains and judged again; one a channel already has goes to the other channel.
4. BLOCKER, `Run.busy` holds a raise while a send is unknown or refused. Not fixed here: it is how the send journal treats every thread since the first release, a raise from a candidate included, and settling a send without a person is its own deliverable. Filed as ai-tools-alerts#jsje; the spec says so under "Not in this slice".
5. BLOCKER, the whole-catalog test threw away what a cut catalog lists. Fixed: a copy that parses is used for raises; only its absences need completeness.
6. SUBSTANTIVE, the ledger's exploited mark raised a lowered thread again through a candidate. Fixed: `ledger.merge` does not lend it from a thread marked lowered.
7. SUBSTANTIVE, the floor rebuilt from published fields loses the flags. Fixed: the ledger keeps the floor; an old entry is lowered to `reading_cap` at the lowest.
8. BLOCKER, neither rollback was safe. Fixed: rollback after a lowering is stated as one-way, with the steps that keep wire rule 2.
9. BLOCKER, the stateful cases were not tested. Fixed: tests for the outage inside a wait, the failed send followed by an unreadable catalog, one channel delivered, a lost state file, a candidate raise with a fix on a lowered thread.
10. SUBSTANTIVE, the snapshot commit's message. Rebutted: a dangling commit made for the reviewer by `git commit-tree`; it is on no branch and never lands.

Pass 2 [spec]: 3B/1S/0C/0R · fixed 8/9 prior · velocity ↓ (10→4, escalation no)
spec passes: 2 (the whole spec, then the one delta, fresheyes run 20261124-154904-6229f0, gpt-6-astra; neither standing rebuttal overturned) · all four fixed, no further pass

Spec findings, pass 2 (the delta), and what was done:
1. BLOCKER, a capped gap still credited an outage. Fixed: time is added only from one complete read to the next when no unknown read lies between and they are at most two hours apart; an unknown read clears the wait's last-read mark and keeps what was held.
2. BLOCKER, "seen listed" was kept per thread, so one CVE's sighting covered another's absence. Fixed: kept per thread and CVE; a gone CVE never seen is unknown.
3. BLOCKER, the rollback left reply items in the journal whose advisory holds the lowered level. Fixed: the steps now set the level in every journal and withheld item of such a thread.
4. SUBSTANTIVE, three fixes had no acceptance case. Fixed: named in criterion 14 and tested.

Pass 1 [plan]: 4B/3S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
plan passes: 1 · reviewer gpt-6-astra (fresheyes run 20261124-155614-7dbd71; neither standing rebuttal overturned) · all seven fixed

Plan findings and what was done:
1. BLOCKER, the cleanup removed the second channel's item of a lowering the first channel had acknowledged but the ledger had not recorded. Fixed: the cleanup judges the whole change; any item sent or pending keeps all of them.
2. BLOCKER, an unknown read in a run that stopped before the recompute was not recorded, so the next read took the time. Fixed: `Run.observe` judges the copy and pauses every wait before anything is sent.
3. BLOCKER, `ledger.merge` runs before the journal drains and lent the exploited mark from a ledger not yet reconciled. Fixed: `Run.one` drops the mark on a lowered thread unless a KEV entry read this run stands behind it.
4. BLOCKER, the real KEV fetch follows redirects, so a 3xx was read as an answer. Fixed: the fetch marks an answer that came through a redirect; it still makes candidates and is never a complete copy.
5. SUBSTANTIVE, a stop between journaling the digest and clearing the list repeated the line. Fixed: the digest's date is written first and the next run settles it.
6. SUBSTANTIVE, the plan's outage timeline was one read early. Fixed in the plan; the test already asserted hour 62.
7. SUBSTANTIVE, the rollback before a lowering left `changed`. Fixed: the steps remove all three keys; a test freezes the 0.1.7 key lists.

Pass 2 [plan]: 2B/0S/0C/0R · fixed 7/7 prior · velocity ↓ (7→2, escalation no)
plan passes: 2 (the whole plan, then the one delta, fresheyes run 20261124-160854-a3a606, gpt-6-astra) · both fixed, no further pass

Plan findings, pass 2 (the delta), and what was done:
1. BLOCKER, the early step recorded an unknown read only when the whole catalog was unusable, not when one thread's entry was (listed under another name). Fixed: every thread is judged before anything is sent, and the send step only acts on the verdicts.
2. BLOCKER, the "came direct" mark was kept apart from the cached body, so a redirected body cached by a run that stopped early passed on the next 304. Fixed: the state keeps the digest of the last body that came direct, and a cached body counts only when it is that body.

Found while building, not by a reviewer: the breaker counted one run's lowerings, so entries shed two an hour passed it. It now counts the last 24 hours (spec criterion 7).

Pass 1 [code:recompute]: 5B/5S/4C/0R · fixed -/- · velocity = (—→14, escalation no)
code passes: 1 · the whole branch at d389897214eb710a576249ebbfc9e71a5920a85a, after merging origin/main · Stage 2 gpt-6-astra (fresheyes run 20261124-162531-99d039; neither standing rebuttal overturned) · Stage 1 a same-model reviewer, which ran its findings against an export of that commit · all fixed

Code findings, pass 1, and what was done:
1. BLOCKER (both reviewers), a verdict reached before the journal drained was sent after a candidate had changed the thread: it lowered below a new floor, past an unread GHSA id, and wrote the old advisory over a recorded fix. Fixed: at send time every thread whose ledger entry is no longer the one judged is judged again, and the reply is composed from the current entry.
2. BLOCKER (Stage 2; Stage 1 SUBSTANTIVE), a redirect that ends in 304 counted as a direct read. Fixed: the fetch marks it, `fetch_kev` reports it, `kev_copy` needs this run's answer direct.
3. BLOCKER (Stage 2; Stage 1 SUBSTANTIVE for the window before `observe`), a run that stopped before saving what it read left the wait's last-read mark, so the next read took the time. Fixed: a run writes that it has begun before it reads; the next run finding that mark pauses every wait.
4. BLOCKER, an older catalog served again passed as "another version". Fixed: a version is numbers that order; one older than the latest complete copy's is not complete; a wait is due only at a later version.
5. BLOCKER, a cut catalog that lists the entry only paused a wait for a lower level. Fixed: evidence that holds the level ends the wait, complete or not.
6. SUBSTANTIVE (Stage 2), a thread busy at the start whose work the drain finished was not judged in that run, so a catalog listing it again did not raise it until the next. Fixed: judged at send time.
7. SUBSTANTIVE (Stage 1), the breaker counted lowerings that never sent. Fixed: counted when recorded.
8. SUBSTANTIVE (Stage 1), on a lowered thread a raise whose only other change was an unchanged title was withheld whole. Fixed: the unchanged title is dropped and the level goes alone.
9. SUBSTANTIVE (Stage 1), tests passed with the freshness check removed, and five paths had none. Fixed: a candidate on the due run, a failed lowering whose evidence still holds, an unknown outcome, a KEV candidate on a lowered thread, a redirect ending in 304, the digest still in the journal.
10. COSMETIC (Stage 1), fixed: `kev_copy` defaults to "not known direct"; `floor` is accepted on a root item only; the breaker's digest line no longer says "1 threads"; the unused `fresh` helper is gone; the docstring says threads judged.

Pass 2 [code:recompute]: 2B/1S/2C/0R · fixed 10/10 prior · velocity ↓ (14→5, escalation no)
code passes: 2 (the whole branch, then the one delta) · Stage 2 gpt-6-astra (fresheyes run 20261124-165008-2554e2, `--since d389897`; no standing rebuttal overturned) · Stage 1 a same-model reviewer on an export of b973e75, which reverted each of the eight fixes in turn and ran the tests · all five fixed, no further pass

Code findings, pass 2 (the delta), and what was done:
1. BLOCKER (Stage 2; Stage 1 COSMETIC), a journal replay after a failed ledger write counted one lowering twice in the breaker. Fixed: the breaker's list holds the thread, and a thread counts once in the window.
2. BLOCKER (Stage 2; Stage 1 SUBSTANTIVE, with a run that showed the ledger and the wire part ways after a requeue), the send step no longer checked for work in flight on a thread whose own entry was unchanged. Fixed: every verdict is checked against `busy` again before it is sent.
3. SUBSTANTIVE (Stage 1), the test for "a thread whose pending work the run finished is judged in that run" passed with the fix reverted, because its catalog entry was also a candidate. Fixed: the entry predates the watermark.
4. COSMETIC (Stage 1), fixed: the stderr line names the older-version cause; on a lowered thread, once the level has gone alone, ids, sources and a severity word make no reply of their own.

## Chunks
- [x] recompute: the evidence rules, the KEV reader, the ledger marks, the digest line (59bdcf9, merge d389897, review fixes in the commit after)

## Notes
- Split before building (decided comment on ny5g, 2026-11-24): this run is the evidence rules and the KEV reader; 3qyq is the rest.
- Agency: the skill's Step 3 names Agency for execution. Its tools are not offered to this session, and the seat rules forbid looking at the host to find out why. The chunk is built in this session and reviewed as the rung requires.
