# An advisory page that never parses reaches an end with no person (ai-tools-alerts#psb5)

## Problem

`Run.admit` defers a candidate whose repository advisory page answers 200 and
does not parse (`Evidence.unparsed`, counted as "advisory page not parsed,
deferred"). It does so every run, with no end:
`test_a_failed_fetch_or_an_unparsed_page_defers_and_never_drops` pins nine days
of it. Nobody watches this service (ruling 2026-11-23). If GitHub changes the
markup of the package box, every new repository advisory waits for good:
nothing posts, each deferred candidate costs one page of the run's 40 every
run, and the only sign is a count on stderr.

ai-tools-alerts#xkbf made the parser refuse any package box whose shape it does
not know, which is right for one page and makes this path more likely.

Prior work read: the design review and revised design on ai-tools-alerts#h29n
(D4: absence of evidence must not lower or drop a true alert; D2: only fields
bind a level), ai-tools-alerts#3qyq (`RETRY_DAYS`, "only a first sight on record
bounds the retry: none, no retry"), ai-tools-alerts#jsje (a run settles what a
person used to settle and says so), ai-tools-alerts#xkbf (the stricter parser;
its reviews raised this issue three times). `kata search "unparsed page
deferred"` finds no other attempt and no rejected experiment.

## Success criteria

- A candidate whose repository advisory page answers 200 and never parses
  leaves the deferred list at the first run `RETRY_DAYS` (7 days) or more after
  its first sight. No later run fetches its page again for that sighting.
- At that run, when the page's visible text names the candidate's id and the
  product's name, the candidate is held as a notice: id and product only, no
  fix, no range, no action, the page as its one source. This is what a vendor
  site page gives today.
- At that run, when the page names neither, the candidate is dropped and counted
  in the run's `skipped:` line as "advisory page not parsed, dropped".
- Before `RETRY_DAYS`, behaviour is unchanged: deferred, counted, nothing
  signed. A page that parses on any run before the end is read as now.
- A candidate with no first sight on record (the `waiting` map was half full
  when it was first deferred) is at its end at once: with no record there is no
  bound, and 3qyq already rules "none, no retry".
- A failed fetch (0, 403, 408, 429, 5xx) and a spent page budget defer as now,
  also past `RETRY_DAYS`. They are not this issue (see Out of scope).
- `scripts/test-gate.sh` passes.

## Approach

Two changes, both small.

**`rules.evidence(c, scope, page, entries=None, lapsed=False)`.** `lapsed` says
the candidate's retry time is over. Unchanged when it is False. When it is
True, a repository advisory page that answers 200 and does not parse as the
advisory its URL names is read by the rule every other authoritative page
already gets: it confirms the candidate when its visible text (`_lines`: no
tag, attribute or script) names the candidate's base id and the scope's name,
each as a whole token (`_names`). It then gives rank 1: the base id alone, no
fix, range, title or severity, `structured` False. A repository page that
parses, on another source of the same candidate, still wins (rank 2). The
existing name test moves into one helper that both branches call.

`Evidence` gains `failed`: a fetch failed in a way that can pass, and nothing
confirmed the candidate. `retry` stays the union it is now.

**`Run.admit`.** Before reading, it computes `lapsed`: the candidate has no
first sight on record after `saw` would have refused one (the map is half
full), or `now - first sight >= RETRY_DAYS * 86400`. It calls
`evidence(..., lapsed=lapsed)` only for a candidate that came from the deferred
list or has a first sight on record, so a fresh candidate's first read is never
the lapsed one. When the evidence is not ok:

- `unparsed`, `lapsed`, and neither `failed` nor `budget`: counted as "advisory
  page not parsed, dropped", not deferred. The end.
- anything else that asks for a retry: deferred and counted as now.

When the evidence is ok through the lapsed rule, the candidate goes on as a
vendor site page's does: `trusted` is False, the level rule makes it a notice,
`plan_new` holds it for the digest and the catalog. It is not deferred again.

First sight is `state["waiting"]`, written by `saw` on the first deferral and
kept while the candidate is on the deferred list (`run` prunes a key only when
it is neither live nor younger than `AGE_LIMIT`). No new state field, no change
to the state file's shape, no change to any post's wording.

## Why (a), and why not the others

The issue offers three ends. This builds (a) with a residue of (b).

- **(a) a notice from the page's id and product name, after `RETRY_DAYS`.**
  Chosen. Members hear of the advisory and are sent to the source. The notice
  rests on the test a vendor site page already passes, so no new trust is
  introduced: the page is on the vendor's own repository (`authoritative`), and
  its text must name the id and the product.
- **Why not the notice at first sight, with retries after.** A notice that the
  catalog lane has sent is not re-read today (ai-tools-alerts#n2yj). A page that
  fails to parse for one run would then leave a notice with no range and no fix
  in the catalog for good, where an hour's wait gives the real one.
- **(b) drop and say so in the digest.** Only for the residue: a page that
  after seven days still names neither the id nor the product is not a
  statement about this advisory (a sign-in wall, an error page served with 200).
  A candidate whose page says nothing is dropped silently today ("no
  authoritative source"); this one is counted under its own name. No digest
  line: the digest's wording is approved text in two languages, and a count of
  pages that said nothing tells a member nothing they can act on.
- **(c) a digest line when more than N are deferred in one run.** Not built. It
  is a sign for a person, and the ruling is that none is watching. With (a) the
  members are told of each advisory itself.

## What the reader of a post sees

Nothing new in form. The held notice is the one
`test_a_vendor_site_page_alone_makes_a_notice_whatever_the_record_says` pins:
title "<product>: security advisory (<id>)", level notice, no fix, no range, no
action, one source.

## Alternatives considered

- **Bind the product by the URL's repository alone, without the name test.**
  Rejected: `github.com/modelcontextprotocol/servers/` is the authority of seven
  products. The name test is what keeps an advisory for one out of another's
  notice.
- **Accept the package name as well as the product name.** Rejected for this
  issue: it widens the vendor-site rule, which is not asked for. The cost is a
  drop where a page names only `@anthropic-ai/claude-code` and never "Claude
  Code"; it is counted.
- **A back-off (read a deferred page less often).** Not needed: the page spend
  per candidate is now bounded by `RETRY_DAYS` of runs.

## Bounds

- Deferred list: a candidate deferred only for an unparsed page leaves it within
  `RETRY_DAYS` of first sight, at the first run that reads its page after that.
  When more deferred candidates wait than the run has pages, `run` already
  starts the deferred list one further each hour, so each is read within
  `ceil(n / MAX_RUN_PAGES)` hours of its end.
- Page budget: at most one page per run per such candidate, for `RETRY_DAYS`.

## Tests

In `tests/poster/test_rules.py`:

- `evidence(..., lapsed=True)` on an unparsed repository page that names the id
  and the product: ok, rank 1 values (url, ids = base only, no fix, range,
  title or severity, `structured` False, `unparsed` False).
- the same page with `lapsed=False`: not ok, `unparsed`, `retry` (as today).
- lapsed, page names the id and not the product; names the product and not the
  id; names the id only inside a tag attribute or a script: not ok, `unparsed`.
- lapsed, one source unparsed and one source that parses: rank 2 wins, whatever
  the order.
- lapsed, a page that parses for another advisory's GHSA and names this id and
  product in its text: confirmed as rank 1 (the vendor-site rule), never with
  that advisory's fields.
- `failed` is set for 503 and not for an unparsed page.

In `tests/poster/test_main.py`:

- the pinned test keeps its failed-fetch cases for nine days and loses the 200
  case, which moves to the new tests.
- repeated runs, hourly marks over eight days, a page that never parses and
  names the id and product: deferred and counted each run before day 7 with
  nothing held; at the first run at or past day 7 one held notice with the
  vendor-site shape, the deferred list empty; a run after fetches nothing for
  it. The pages fetched for it are counted: one a run before the end, none
  after.
- the same with a page that names nothing: at day 7 "advisory page not parsed,
  dropped=1", nothing held, nothing signed, the deferred list empty, no fetch
  after.
- a page that starts parsing on day 3: posts as the page states, as now.
- an unparsed page beside a source that answers 503, past day 7: still
  deferred ("source fetch failed" is not this issue).
- no first sight on record (a `waiting` map at half its cap): the end at the
  second run, not never.

## Blast radius and rollback

One code path: a candidate whose only evidence is a repository page that
answered 200 and did not parse. Before day 7 nothing changes. After it, a held
notice or a counted drop replaces a deferral. Nothing is posted to a channel by
this path (a notice has no channel; it goes to the weekly summary and the
catalog lane). Rollback is a revert of the commit; the state file's shape does
not change, so an older poster reads a newer state.

No install, signing step or release is part of this issue. The change reaches
the poster with the next release; a comment on ai-tools-alerts#g9bv says so.

## Out of scope

- A fetch that fails for ever (403 from a block, 5xx). It defers with no end
  too. Whether an outage may end a candidate is the question D4 of the design
  review answers "no" for lowering; it needs its own decision. Filed as a
  follow-up.
- Re-reading a notice the catalog lane has sent (ai-tools-alerts#n2yj).
- The order of the admit lane's reads (ai-tools-alerts#vszx, in flight; it
  touches `run` near the same lines).

## Assumes

- GitHub serves a repository advisory's id and the product's name as visible
  text whatever its markup becomes. Where it does not, the end is the counted
  drop.
