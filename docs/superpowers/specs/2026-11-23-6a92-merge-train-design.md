# Merge train for the reviewed pull requests (6a92)

## Problem

Seven pull requests on this repository were built and independently reviewed
by the sessions that opened them, then left open: every merge on `main` is a
commit GitHub writes, and until the account kept its email private
(ai-tools-alerts#xrx2) that commit carried the owner's personal address. The
gate is closed; PR 4 proved it (merge commit 8efd213c, no-reply author). The
open pull requests touch the same files (poster, reader, exporter), so one
session merges them in a fixed order and owns the conflicts.

## Success criteria

1. PRs 11, 7, 8, 9, 10, 12 and 6 are merged into `main`, in that order, each
   with `gh pr merge <n> --merge --author-email 19930+Joi@users.noreply.github.com`.
2. After every merge, `git log -1 --format=%ae origin/main` prints the
   no-reply address. A merge that prints anything else stops the train.
3. No force-push to `main`; no change to GitHub settings or rulesets.
4. PR 8's run record (line 34) names no fleet machine before it merges; the
   branch is rewritten and force-pushed (a feature branch, not `main`) and
   the gate re-run.
5. PR 6's conflict with `main` is resolved by merging `main` into the branch
   (a signed merge commit; no rewrite of reviewed history), the gate passes,
   then it merges.
6. Stacked PRs 10 and 12 are retargeted to `main` after their base merges.
7. Each issue closes on its merge commit with `--pr`, `--commit` and the
   `review:` line already on the issue; `pr-open` and `joi-decision` labels
   are removed. mx38 closes on 8efd213c. ek5q closes after nfm3 when its own
   comments name nothing else left.
8. Nothing reaching GitHub (commits, PR text, comments) names a host,
   tailnet, VM, home path or personal email.

## Approach

- Gate: `scripts/test-gate.sh` (public scan, then pytest). Main's merge
  commit eb45e6eb carries the personal address and cannot be rewritten
  (detail on tppb); it is added to the private known-hits list on this
  machine, as b4b93807 was, so the scan fails only on a new hit.
- A pull request whose branch is behind `main` is updated by merging `main`
  into it (signed merge commit). When the update changed code, the gate runs
  on the updated head before the merge.
- The review evidence for each PR is the issue's own `review:` line; this
  run reviews only what it changes itself: the conflict resolution in PR 6,
  the line-34 rewrite in PR 8, and any merge-forward that needed a hand
  resolution. Those get one independent pass (fresheyes) before the merge.

## Alternatives considered

- Squash merges: rejected; the reviewed commits and their signatures would
  be replaced by one GitHub-written commit and the issues' oid evidence would
  name commits not on `main`.
- Rebasing PR 6 onto `main`: rejected; it rewrites a reviewed, published
  branch, and the merge-forward keeps the reviewed commits intact.
- Rewriting `main` to remove eb45e6eb: out of scope (ruleset blocks it; tppb
  owns the purge).

## Blast radius and rollback

Each merge is one merge commit on `main`. Rollback is a revert pull request
for that merge commit (`git revert -m 1 <sha>`), never a force-push. Live
deployments are not part of this run (rollout issues are separate), so a
merge changes no running system.

## Open questions

None blocking. vzc3's remaining step after merge (reinstall the poster from
`main` and confirm a run) is rollout work and goes to the rollout issues.
