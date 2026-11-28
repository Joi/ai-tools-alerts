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
  leaves the deferred list at the first run that reads its page `RETRY_DAYS`
  (7 days) or more after its first sight, and never goes back on it for that
  page, also when the collector's later records list the same finding.
- At that run the candidate is held as a notice (id and product only, no fix,
  no range, no action, the page as its one source: what a vendor site page gives
  today) when all of these hold:
  - `read_advisory` cannot read the page at all. A page that parses as another
    advisory than its URL names is a known mismatch and confirms nothing.
  - the candidate's base id is the GHSA id in the page's own URL. The vendor's
    repository then ties the id to the page; a CVE named in the page's text is a
    sentence, not the advisory's CVE ID field.
  - the page's repository is the advisory location (`authority`) of this
    product and of no other product in the scope file.
  - the page's visible text names that id and the product's name.
- Otherwise the candidate is dropped at that run and counted in the run's
  `skipped:` line as "advisory page not parsed, dropped".
- Before `RETRY_DAYS`, behaviour is unchanged: deferred, counted, nothing
  signed. A page that parses on any run, before the end or after it, is read by
  its fields as now.
- First sight is recorded at the first run that finds the page unparsed, if no
  earlier one is on record. A candidate for which none can be recorded (`saw`
  keeps none in a `waiting` map half full) is at its end in that same run: with
  no record there is no bound, and 3qyq already rules "none, no retry".
- A failed fetch (0, 403, 408, 429, 5xx) and a spent page budget defer as now,
  also past `RETRY_DAYS`. They are not this issue (see Out of scope).
- `scripts/test-gate.sh` passes.

## Approach

**`rules.evidence(c, scope, page, entries=None, lapsed=False)`.** `lapsed` says
the candidate's retry time is over. Unchanged when it is False. When it is
True, a repository advisory page that answers 200 and that `read_advisory`
returns `None` for gives rank 1 (the base id alone; no fix, range, title or
severity; `structured` False) under the four conditions above. The name test
is the existing one (`_lines`: no tag, attribute or script; `_names`: whole
tokens), moved into one helper both branches call. `_sole(url, scope)` is the
new test that no other scope entry's authority covers the URL. Nothing that
confirmed the candidate before it is replaced (rank 0 only).

`Evidence` gains `failed`: a fetch failed in a way that can pass, and nothing
confirmed the candidate. `retry` stays the union it is now.

**`Run.admit`.** It reads the evidence as now. When that is not ok and the one
reason is `unparsed` (neither `failed` nor `budget`), it asks `_lapsed`: this
records first sight through `saw` if none is on record, and answers True when
there is still none or it is `RETRY_DAYS` old. Then:

- lapsed: `evidence` is read again with `lapsed=True`. No page is fetched for
  this: every source was read a moment before and a run fetches a URL once.
  Confirmed, the candidate goes on as a vendor site page's does (`trusted`
  False, a notice, held for the weekly summary and the catalog). Not confirmed,
  it is counted as dropped. Either way it is not deferred.
- not lapsed: deferred and counted as now.

**Remembering the end.** The collector's record is replaced about each hour
and lists largely the same findings, so an ended candidate comes back as a
fresh one, sometimes after runs that read no new record. The memory is an
entry of the `waiting` map under the candidate's key with the suffix `|end`,
dated the run that ended it (`Run._end`). `_lapsed` answers True at once for a
candidate that has one. `run` prunes the map as it always has (an entry no
deferred candidate names goes `AGE_LIMIT`, seven days, after its date), and
each run that ends the candidate again dates the entry anew. So the end holds
for as long as an input names the candidate and for a week after the last run
that met it; then it is forgotten, and a later sighting is a new one. While it
holds, each run that meets the candidate ends it by the same two reads of pages
already fetched: the notice is held once (`hold` knows its ids) and the drop is
counted each run, as "no authoritative source" is. If the page parses on a
later run it is read by its fields and the candidate posts as the page states.

The entry is written whatever the map holds. In a map at its cap
(`inputs.MAX_WAITING`, which `load_state` enforces) the oldest entry makes way:
it is the one nearest its own pruning, and the candidate it stood for is at
worst seen as new once more.

No new state field and no change to the state file's shape (`waiting` keys are
strings holding a `|`, values integers, as before), so an older poster reads a
newer state and prunes the entries it does not know. No change to any post's
wording. `run` does not change.

## Why (a), and why not the others

The issue offers three ends. This builds (a) with a residue of (b).

- **(a) a notice from the page's id and product name, after `RETRY_DAYS`.**
  Chosen. Members hear of the advisory and are sent to the source. The notice
  needs more than a vendor site page's does: the id comes from the page's own
  URL on the vendor's repository, the repository must be one product's alone,
  and the text must name both.
- **Why not the notice at first sight, with retries after.** A notice that the
  catalog lane has sent is not re-read today (ai-tools-alerts#n2yj). A page that
  fails to parse for one run would then leave a notice with no range and no fix
  in the catalog for good, where an hour's wait gives the real one.
- **(b) drop and say so in the digest.** Only for the residue: a page that
  after seven days does not meet the four conditions is not a statement this
  service can sign about this advisory for this product (a sign-in wall, an
  error page served with 200, a page under a CVE its text alone names, a
  repository shared by several products). A candidate whose page says nothing
  is dropped silently today ("no authoritative source"); this one is counted
  under its own name. No digest line: the digest's wording is approved text in
  two languages, and a count of pages that could not be read tells a member
  nothing they can act on.
- **(c) a digest line when more than N are deferred in one run.** Not built. It
  is a sign for a person, and the ruling is that none is watching. With (a) the
  members are told of each advisory itself.

## What the reader of a post sees

Nothing new in form. The held notice is the one
`test_a_vendor_site_page_alone_makes_a_notice_whatever_the_record_says` pins:
title "<product>: security advisory (<id>)", level notice, no fix, no range, no
action, one source.

## Alternatives considered

- **The vendor-site rule as it is (text names the id and the product).** The
  first draft. Rejected after review: a description can name another advisory's
  id or another product for comparison, and for a parsed page `evidence` already
  refuses a CVE that is only in the description. Hence the id from the URL and
  the one-product repository.
- **Accept the package name as well as the product name.** Rejected for this
  issue: it widens the name test, which is not asked for. The cost is a drop
  where a page names only `@anthropic-ai/claude-code` and never "Claude Code";
  it is counted.
- **A new state field for ended candidates.** Not needed, and it would make an
  older poster refuse the state (`load_state` knows its keys). The `waiting` map
  already holds dated entries per candidate and prunes them.
- **Keeping the first-sight entry while this run's inputs name the candidate.**
  The first build. Rejected after the plan's review: a run that reads no new
  record names nothing and forgot the end, and a full map could not hold it.
- **A back-off (read a deferred page less often).** Not needed: the deferred
  list no longer grows with such candidates.

## Residual risk, stated

A notice under this rule can still name the wrong product in one case: the
vendor's single-product repository publishes an advisory for another package
(the suite has one: Claude Desktop in the Claude Code repository), the page
does not parse for seven days, and its text names the product. The notice then
says "<product>: security advisory (<id>)", no range, no fix, with the page as
its source. It never becomes a root, never carries a level above notice, and a
member's check matches nothing on it. A vendor site page has had the same
residue since h340.

## Bounds

- Deferred list: a candidate deferred only for an unparsed page leaves it at
  the first run that reads its page at or after `RETRY_DAYS` from first sight.
  Which run reads it is decided by the run's page budget, as for every
  candidate: fresh candidates are read first, then the deferred list, which
  starts one further each hour. With n candidates on the deferred list a given
  one is at its head within n hours, and is read then unless the fresh
  candidates alone spend the run's `MAX_RUN_PAGES`. That starvation is the
  existing order of reads (ai-tools-alerts#vszx) and not changed here. In
  production the collector's record lists the candidate again each hour, so it
  is usually read as a fresh one.
- Page budget: such a candidate costs what any candidate an input names costs,
  one fetch of its page a run. What ends is the cost of candidates no input
  names any more, which the deferred list used to keep for good.

## Tests

In `tests/poster/test_rules.py`:

- `failed` is set for 503, not for an unparsed page, and for both together.
- lapsed, an unparsed page that meets the four conditions: ok, rank 1 values.
  The same page not lapsed: not ok, `unparsed`, `retry`.
- lapsed, the text names the id and not the product; the product and not the
  id; the id inside a longer token; both in attributes only; both in a script
  only; another product's name that holds this one's words; an empty page: not
  ok, `unparsed`.
- lapsed, a page that parses as another advisory and names this id and product
  in its description: not ok (the known mismatch stays one).
- lapsed, a candidate under a CVE, or under another GHSA, that the unparsed
  page's text names: not ok. The same CVE candidate with a page that parses: by
  its fields, equal to the not-lapsed result.
- lapsed, an unparsed page in `modelcontextprotocol/servers` naming two
  products: not ok for either.
- lapsed, a vendor site page that confirmed first is not replaced.
- lapsed changes nothing for a page that parses, a 503 and a 404.

In `tests/poster/test_main.py`:

- the pinned test keeps its failed-fetch cases for nine days; the 200 case
  moves to the tests below.
- 168 hourly runs with a page that never parses and meets the conditions: each
  deferred and counted, one page a run, nothing held; at hour 168 one held
  notice of the vendor-site shape, the deferred list empty; later runs with no
  input naming it fetch nothing. Pages fetched in all: 169.
- a page that names nothing: at day 7 "advisory page not parsed, dropped=1",
  nothing held or signed, the deferred list empty, the `waiting` map holding
  the end entry alone; a week with no input naming it later, the map empty.
- the collector lists the finding again after the end, three times over eight
  days, with two runs that read no new record before each: the end entry is
  still there, the candidate is dropped each time and never deferred; then the
  page meets the conditions: held once over two runs; then it parses: one root,
  as the page states.
- a `waiting` map at its cap: the end in the first run, the end entry written,
  the oldest entry gone, the map still at the cap; with the map emptied of the
  rest, the next record naming the candidate is ended at once.
- a page that starts parsing on day 3: posts as the page states.
- an unparsed page beside a source that answers 503, past day 7: deferred; when
  that source answers 404, the end.
- no first sight on record (the `waiting` map at half its cap): the end in the
  first run, one held and one dropped, none deferred, both end entries written;
  with room in the map again, no new wait.
- five such candidates with two pages a run: the deferred list only shrinks
  after day 7 and empties within eight runs; five notices held in all.

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
  review answers "no" for lowering; it needs its own decision:
  ai-tools-alerts#ewh2.
- Re-reading a notice the catalog lane has sent (ai-tools-alerts#n2yj).
- The order of the admit lane's reads (ai-tools-alerts#vszx, in flight; it
  touches `run` near the same lines).

## Assumes

- GitHub serves a repository advisory's id and the product's name as visible
  text whatever its markup becomes. Where it does not, the end is the counted
  drop.
