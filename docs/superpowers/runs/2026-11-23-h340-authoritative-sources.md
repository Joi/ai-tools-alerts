# Run: h340-authoritative-sources
Instruction: ai-tools-alerts#h340 (starting rung floored at medium; repoman lane). Brief: `TASK-ai-tools-alerts#h340.md` — the poster signs only what an authoritative source says; do every item of the issue's fix list.
Stage: done (pull request open; merge waits on gate ai-tools-alerts#xrx2)
Rung: medium (start-floor medium: constraint-lens, BR2 REV1 NOV1 INT2 FC2 = 8; the dispatch brief floors it there too; security-shaped, so the review model is gpt-6-astra)
Lens: "A change they cannot parse must fail safe (they ignore it), never crash them." · "Nothing you build may wait for a person." · "a third-party package can never resolve to a tier-1 product name or produce an upgrade action for it" · "Any new text field that reaches the relay passes compose._inline (the mention guard)." · "no host, tailnet, VM or home-path name and no personal email in any commit, message, file or PR text."
Last reviewed: spec 8c3b2b64b26afaba0992a8b5ac770832b225639c
Last reviewed: plan f99e9eacbb8497a3692c8dcb7ae8442f24464a1e
Spec: docs/superpowers/specs/2026-11-23-h340-authoritative-sources-design.md   Plan: docs/superpowers/plans/2026-11-23-h340-authoritative-sources.md
Agency project: — (no agency tools in this session; the plan is executed directly)
Kata: ai-tools-alerts#h340
Wall-clock limit: 6 h. Review shape: one independent pass per artifact, one delta only when a BLOCKER fix changed behaviour. Completion check: `scripts/test-gate.sh` green and the claude-code-router regression test passing.

## Scorecards
Pass 1 [spec]: 5B/5S/0C/0R · fixed -/- · velocity = (—→10, escalation no)
spec: passes: 1 · elapsed: 14 min · reviewer fresheyes gpt-6-astra · all 10 fixed in the spec, none rebutted, so no escalation
Pass 1 [plan]: 0B/7S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
plan: passes: 1 · elapsed: 12 min · reviewer fresheyes gpt-6-astra · all 7 fixed in the plan, none rebutted, so no escalation
Pass 1 [code:whole-branch]: 3B/4S/1C/0R · fixed -/- · velocity = (—→8, escalation no)
Pass 1 [code:whole-branch, stage 1 same-model]: 3B/5S/7C/0R (two of the blockers and five others new; the rest restate stage 2)
Pass 2 [code:whole-branch, delta]: 0B/5S/0C/0R · fixed 8/8 prior · velocity ↓ (8→5, escalation no)
code: passes: 2 · elapsed: 35 min · reviewer fresheyes gpt-6-astra (whole branch at 139e877568e93f65fdbb4b82e4514ea65e0a7155, then --since that head with a rebuttals file) · no third pass (ruling 41e2)

Code findings, whole-branch pass (all fixed in "the code reviews' findings" commit):
- B: `github.com.` skipped the repository-advisory check → one host reading everywhere (`rules.host_of`).
- B: a description could supply the CVE ID of a page cut short → only a whole page is read; an oversize body is a failed fetch.
- B: the migration kept a thread's unpublished record title → forgotten with the ids and sources.
- S: an unexpressible vendor fix lost its "fix listed, no action" wording in a real run → carried through admit.
- S: the page budget could starve a candidate; S: budget exhaustion discarded a KEV confirmation; S: the per-candidate cap dropped a candidate with unread sources → rotation, budget handled inside `evidence`, every kept source read.
- C: duplicate identities could differ by a Unicode dash → refused by the loader.
Stage 1 (same model), fixed in the same commit: only the confirming page is listed as a source (a vendor-host URL nobody read carried record text); a URL with a query is never fetched and a site page alone makes a notice (a query-echo page confirmed an invented CVE and a pure record made it critical); `package: null` is absent; no version from an Apple page title; the migration resets the input watermarks; more package keys and a separate skip counter for "vendor page names another package". Rebutted (cosmetic): the id slug, quadratic tag regexes on a vendor page, a credited user named "Severity".
Delta pass (all five fixed in "the delta review's findings" commit, unreviewed after it per the one-delta rule): no fixed version when one of the product's packages has no patch; the CVE ID is read from GitHub's sidebar heading only; a redirect to a URL with a query is refused; deferred candidates rotate over a stable order; the filesystem-server package key removed.

Plan findings and what the plan now says:
- purity lost when the adapter filters or truncates sources → `from_collector` clears the three level inputs itself when any source entry was not kept.
- step 1 not green before step 2 → merged into one step with one verify line.
- three integration tests contradict the gate → named, with what each now asserts.
- `test_live_digests_leads_recomposed` composes leads directly → rewritten, named.
- loader does not refuse owner-level or off-list authority → loader validation and negative tests.
- compose fixtures rely on word matching → moved to exact identities in step 2.
- the grep acceptance line matched `level_for`'s parameter → narrowed.

Spec findings and what the spec now says:
- B1 version tokens prove no role → the poster reads the labelled Patched and Affected fields of the vendor page; the record's `fixed` and `affected` are never used.
- B2 one confirmed alias vouches for other ids → the primary id must be the page's own GHSA or CVE ID; aliases are cut to confirmed ids before the merge.
- B3 owner-wide authority → GitHub prefixes name one repository, and the page's Package block must resolve to the candidate's product.
- B4 `title_url` does not authenticate the text → the title is read from the page (or is CISA's); collector titles are deleted; no new Candidate field.
- B5 old state bypasses the gate → a `gate` key; a state without it loses its deferred, held, withheld and unsent composed items once; `learned_sources` filtered.
- S6 KEV identities unspecified → listed in the spec and pinned by a test.
- S7 GHSA-in-path rule rejects CVE-only candidates → the CVE ID field of the page confirms them.
- S8 transient failure could drop → always deferred, no age rule of its own.
- S9 rollback broken by a new Candidate field → the field is gone; rollback removes the `gate` key.
- S10 no verification matrix → section 7 of the spec.

## Chunks
- [x] exact scope identity, authority and evidence, signed wording, tests, docs (one chunk: the whole branch)

## Notes
- Not repoman-managed (no `.repoman-managed`): the ending is the brief's — `scripts/test-gate.sh`, one independent review, pull request, merge, close on the merge commit.
- Prior work searched in kata: ai-tools-alerts#s6mt (the authoritative-source table and a ruleset file, later; this run's `authority` lists are what it will move), ai-tools-alerts#h29n comments D2 and D3 (KEV matched on CISA's vendor and product fields only; a source the subject's attacker can write never sets a level above notice). `capability-search` lives outside this worktree and the seat rules forbid reading there; not run.
- Seat rules: only this worktree and the scratchpad are read. The do-it skill's own files and the fresheyes script are run because the brief orders both.
- A stray fresheyes run (handle 20261123-060548-c089af) was started when `fresheyes.sh --help` was read as scope text; both of its processes were stopped within a minute. It reviewed nothing of this branch and counts as no pass.
- Measured 2026-11-23: unauthenticated api.github.com answered 403 with 0 of 60 calls left from this network; the public advisory page answered 200 with labelled fields. The design reads the page.
- The plan-review fixes were applied to the plan and this manifest with a script that asserts each needle occurs once (it fails loudly on a stale needle); later edits use the Edit tool.
- Found while building, beyond the reviews: `read_advisory` misread a block whose "Affected versions" field is empty (the next label was taken as its value); the migration did not reach ids and sources the ledger's threads had learned before the gate (`Ledger.forget_unpublished`); a reserved synthetic id on a vendor page would have become an alias.
- Landing (h29n comments xbbcca, wjxmh9, wka9zv, 2026-11-23): main takes pull requests and signed commits only, and no PR on this repo is merged until gate ai-tools-alerts#xrx2 closes. This run ends at: PR open, gate and review passed, issue labelled `pr-open` and blocked by xrx2.
- Gate at the handoff head: `python3 -m pytest -q` 1238 passed, 1 skipped. `scripts/test-gate.sh` exits 1 on the public scan alone, for one object: the merge commit of pull request #5 on origin/main, which is not one of this branch's commits. This branch's six commits are signed and carry the no-reply author.
- No Agency tools in this session: the plan was executed directly, one chunk.
- Split rule: the diff will pass 600 lines. Kept as one issue: see the `decided:` comment on h340.
