# Run: h340-authoritative-sources
Instruction: ai-tools-alerts#h340 (starting rung floored at medium; repoman lane). Brief: `TASK-ai-tools-alerts#h340.md` — the poster signs only what an authoritative source says; do every item of the issue's fix list.
Stage: plan-review
Rung: medium (start-floor medium: constraint-lens, BR2 REV1 NOV1 INT2 FC2 = 8; the dispatch brief floors it there too; security-shaped, so the review model is gpt-6-astra)
Lens: "A change they cannot parse must fail safe (they ignore it), never crash them." · "Nothing you build may wait for a person." · "a third-party package can never resolve to a tier-1 product name or produce an upgrade action for it" · "Any new text field that reaches the relay passes compose._inline (the mention guard)." · "no host, tailnet, VM or home-path name and no personal email in any commit, message, file or PR text."
Last reviewed: spec 8c3b2b64b26afaba0992a8b5ac770832b225639c
Spec: docs/superpowers/specs/2026-11-23-h340-authoritative-sources-design.md   Plan: docs/superpowers/plans/2026-11-23-h340-authoritative-sources.md
Agency project: — (no agency tools in this session; the plan is executed directly)
Kata: ai-tools-alerts#h340
Wall-clock limit: 6 h. Review shape: one independent pass per artifact, one delta only when a BLOCKER fix changed behaviour. Completion check: `scripts/test-gate.sh` green and the claude-code-router regression test passing.

## Scorecards
Pass 1 [spec]: 5B/5S/0C/0R · fixed -/- · velocity = (—→10, escalation no)
spec: passes: 1 · elapsed: 14 min · reviewer fresheyes gpt-6-astra · all 10 fixed in the spec, none rebutted, so no escalation

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
- [ ] exact scope identity, authority and evidence, signed wording, tests, docs (one chunk: the whole branch)

## Notes
- Not repoman-managed (no `.repoman-managed`): the ending is the brief's — `scripts/test-gate.sh`, one independent review, pull request, merge, close on the merge commit.
- Prior work searched in kata: ai-tools-alerts#s6mt (the authoritative-source table and a ruleset file, later; this run's `authority` lists are what it will move), ai-tools-alerts#h29n comments D2 and D3 (KEV matched on CISA's vendor and product fields only; a source the subject's attacker can write never sets a level above notice). `capability-search` lives outside this worktree and the seat rules forbid reading there; not run.
- Seat rules: only this worktree and the scratchpad are read. The do-it skill's own files and the fresheyes script are run because the brief orders both.
- A stray fresheyes run (handle 20261123-060548-c089af) was started when `fresheyes.sh --help` was read as scope text; both of its processes were stopped within a minute. It reviewed nothing of this branch and counts as no pass.
- Measured 2026-11-23: unauthenticated api.github.com answered 403 with 0 of 60 calls left from this network; the public advisory page answered 200 with labelled fields. The design reads the page.
- Split rule: the diff will pass 600 lines. Kept as one issue: see the `decided:` comment on h340.
