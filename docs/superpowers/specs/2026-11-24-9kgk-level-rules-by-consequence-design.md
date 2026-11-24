# 9kgk: levels by consequence; a critical needs a complete action

Issue: ai-tools-alerts#9kgk (slice 5 of the v2 design, ai-tools-alerts#9mx8 section 4).
Builds on s6mt (the level function, `spec/ruleset.json`), wa6n (ruleset version 2, scope
classes), r0ra (expiry computed from claims) and t8jr (`spec/wire.md`).

## Problem

The level table still lets the upstream severity word set a level alone (the
`severity_in` row and the poster's `severity-tier1` clause), and nothing stops a
critical from posting without an action a member can take. The one live critical, the
OpenSSH KEV thread, posted with no fix, no range and no action. The design says:

| Level | Rule |
|---|---|
| Critical | A malicious or trojanized release of an in-scope item confirmed by a primary source, or exploitation in the wild of an in-scope tool; in both cases the post carries a complete action (a verb with a target; `upgrade` needs a fixed version) |
| High | Code execution, credential or token theft, or sandbox or approval bypass in an in-scope tool, with a fix |
| Notice | Everything else, denial of service included |

An exploited flaw with no fix is high and is raised when the fix exists. The upstream
severity is printed and never sets the level alone. Every advisory carries `expires_at`;
a critical expires after 14 days unless renewed.

## What is already done elsewhere, and is not rebuilt here

- **Expiry.** t8jr's wire rule 3: a relay-bot block carries no expiry (`"expires_at":
  null` in a root, absent in a reply), because every released reader would drop a true
  critical at that time and refuse the renewal. r0ra computes expiry from the claim:
  `confirmed_at` plus `ttl_days` of the ruleset (critical 14, high 30, notice 90). The
  "every advisory carries `expires_at`" requirement is that computed value; this slice
  keeps `ttl_days.critical` at 14 and adds a test that pins it. It is not yet live end
  to end: the poster does not attach claims to its events (ai-tools-alerts#gtw9, open),
  and `pull.active` decays only a thread whose root carries a claim. Until gtw9 lands, a
  relay-bot critical does not expire; that dependency is gtw9's, not this slice's.
- **Re-evaluating open threads**, and lowering the OpenSSH critical: ai-tools-alerts#h29n
  and ny5g (kata comment c:kz1rj2, ruling 2026-11-23). wa6n made OpenSSH an `out`
  product, so a new sighting of CVE-2026-123158 computes notice and starts nothing; no
  update path raises it. This slice adds no lowering path.
- **Scope classes:** an SDK or containerd is `catalog` or `out` and is notice at most
  (wa6n). The acceptance replay checks this still holds.

## Approach

### 1. Ruleset version 3 (`spec/ruleset.json`, `aitools_alerts/ruleset.py`)

- `version` 3 (`ruleset.VERSION = 3`). No trust-root pin exists yet (ed7n is open), so no
  root file changes.
- New top-level key `action_cap`: the highest level an alert whose post carries no
  complete action may have. Value `"high"`. The reader refuses `critical` there.
- New optional rule-row key `stop_using: true`: the row's level is complete with the
  action `stop_using <product>` when the reading states no fixed version for that
  product. Set on the `ghsa-malware` row and the `ghsa-vendor` CWE-506 (trojanized) row:
  a malicious release has nothing to upgrade to, and "stop using it" is the action.
- The `severity_in` row is removed: the upstream severity never sets a level. The
  reader evaluates only version 3, so the condition word leaves `_RULE_WHEN` with the
  row, and a file naming it is refused.
- The channel high rows (`ghsa-vendor`, `ghsa-reviewed`, scope channel) gain the
  sandbox and approval bypass CWEs: CWE-22 (path traversal), CWE-59 (link following),
  CWE-693 (protection mechanism failure), CWE-862 (missing authorization), CWE-863
  (incorrect authorization). The code-execution and credential CWEs stay (77, 78, 94,
  95, 96, 502, 522, 798). `patched` stays ("with a fix"). `cvss_av` is dropped from the
  channel rows (review S1): an agent meets a local flaw through the repository content it
  reads in normal use, and GHSA-8wv7-r664-7594 (command execution through ordinary
  mcp-server-git calls) is `AV:L`. The `channel_if` rows (wa6n) keep network or adjacent.
- The KEV row stays critical for the channel class: exploitation in the wild is the
  consequence. The action cap makes it high until a fix is known.
- `Support` gains `stop_using: bool` (the row that gave the level carries `stop_using`
  and no package of this product in the reading has `first_patched`).
- New `Ruleset.action_level(level, actions, product, fixed, readings=()) -> str`:
  `level` when its rank is at most `action_cap`'s, or when `actions` (an iterable of
  `(verb, target, value)`) holds a complete action for `product`: an upgrade of it while
  `fixed`, the version the post states for the product (`products[].fixed`), is stated
  (review B1: the member's planner upgrades to `products[].fixed`, not to the action's
  value); or `("stop_using", product, _)` when a live reading of `readings` gives this
  level for `product` with `stop_using`. Otherwise `action_cap`. Pure, offline, shared by
  the poster and (later) the member check, so a member can recompute it from the signed
  block plus the claim's reading.
- The claim keeps meaning what the fields support (`check_claim` unchanged). The post's
  level is that, held to `action_cap` without a complete action. Recorded in the file's
  description.

### 2. Poster (`aitools_alerts/poster/rules.py`, `compose.py`)

- `_prose_level` loses the `severity-tier1` clause and `_HIGH_WORDS`: the severity word
  alone never raises.
- `_SEVERE` (the prose reading of a channel candidate's advisory text, capped at
  `reading_cap`, needing a fix) gains the design's other high consequences: sandbox or
  approval bypass ("sandbox escape/bypass", "bypass(es) the sandbox/approval/permission",
  "skip(s) approval", "outside the workspace/sandbox"), and the plain wordings of command
  execution the live mcp-server-git advisories use ("runs a command/program",
  "attacker-controlled code"). `_REMOTE_CODE` (channel_if) is unchanged.
- `level_for` applies `action_level` last, with the action the root post would carry:
  `upgrade <scope.name> <fixed>` when `compose.schema_fixed(c.fixed)` is a version, else
  `stop_using <scope.name>`. A critical without a complete action returns
  `("high", "no-action")`; a critical that stands through `stop_using` returns reason
  `stop-using`. The KEV prose clause (`kev-tier1`, used when this run made no KEV
  reading) is capped the same way.
- `compose.root_post`: a critical with no expressible fixed version is written only with
  reason `stop-using`; it then carries `Action("stop_using", scope.name, None)` and the
  line "Action: stop using <name> until a fixed release ships." Any other critical
  without a fixed version raises `ValueError` (the run already treats a compose error as
  "does not post" for that candidate; no critical without an action can leave the
  poster). `root_post_ja` writes the same action in Japanese.

### 3. Acceptance replay

`tests/poster/test_level_replay.py`: the 29 alert roots on the public feed (28 at the
design's count plus Hermes of 11-24), each as the poster sees it today (product text,
final fixed version after the fix replies, KEV flag and KEV reading for the two KEV
entries, the source's title as the advisory text, severity word "high"), as an inline
table. For each: `level_for`, then `root_post` when not notice. Asserts:

- no critical whose block lacks a complete action (`action_level` of the block's own
  actions equals its level), across all 29;
- the containerd crash and the four SDK request-size/memory items are notice;
- the full resulting level of each row, so a later change to the table shows up.

Expected: high for Claude Code GHSA-5xjx (writes outside the workspace) and GHSA-pq7j
(attacker-controlled code), the two Inspector RCE items, git RCE, and the five
mcp-server-git command items with a fix (h2g3 "runs gc.recentObjectsHook" included,
review S2); notice for the rest, OpenSSH and Chromium included. No row is critical, so
the "no critical without an action" assertion is checked by the unit cases below and by
the poster tests of KEV with and without a fix (review B4). Plus unit cases: a channel KEV with no fix is high (`no-action`) and becomes
critical with `upgrade` when a fix is known; a GHSA malware reading for a channel
package with no fix is critical with `stop_using`.

## Success criteria

1. `spec/ruleset.json` version 3 loads; version 2 is refused; `action_cap` and
   `stop_using` are validated (unknown values refused).
2. No `severity_in` row and no `severity-tier1` reason remain; a severity word alone
   gives notice.
3. Replay: 0 critical without a complete action across the 29; containerd and SDK items
   notice.
4. `ttl_days.critical == 14` pinned by a test.
5. Claim vectors (`spec/claim-vectors.json`) regenerated for version 3 and the vector
   test passes; `scripts/test-gate.sh` passes.
6. Under about 600 changed lines excluding regenerated vectors.

## Alternatives considered

- **Give the KEV reading a `fixed` field, or a rule over two readings (KEV plus the
  vendor's advisory).** A KEV entry states no version, and s6mt refused levels that add
  readings up (a borrowed advisory). The ghsa reading has no CVE field to tie it to the
  KEV entry; adding one changes every reading's key set and refuses every published
  ghsa claim. Rejected: the action is a property of the post, which the member holds
  signed, so the cap is evaluated over the block.
- **Put the action cap in the poster only.** Then a member's recompute (fv4g) would see
  KEV say critical and the post say high, and flag "published below source". Rejected:
  the cap lives in the shared ruleset so both sides compute the same thing.
- **Lower the claim's level to the capped one.** `check_claim` would then disagree with
  the fields. Rejected.
- **Write `stop_using` for every critical without a fix.** It would tell members to stop
  using OpenSSH on an exploited-but-unfixed CVE, which the design makes high with the
  mitigation. Rejected.

### 4. Poster paths beyond the root (review B2, B3, and one found in the build)

- `Run.plan_known`: a `stop-using` critical on a known thread is held at `action_cap`
  (`no-action`). A relay-bot reply's only action is `upgrade` (`compose._publishable`),
  so a thread is raised to critical only by a fix.
- `Run.deliver`: an unsent journaled item whose block is critical with no complete
  action (no upgrade while `products[0].fixed` is stated, no `stop_using`) is dropped
  with its copies and counted `withheld`; the candidate is planned again. This covers an
  outbox written by a poster from before this rule.
- `Run.one`: when the candidate states no fix but its known thread does, the level is
  computed with the thread's fix, which `plan_known` keeps. Without this a KEV listing of
  a thread that already states its fix would be held at high.
- `compose.root_post` refuses a critical without a fix only when a reason is given; a
  bare level is a thread's standing level, which `plan_known` never lowers (the OpenSSH
  thread keeps taking updates; lowering it is h29n's).

Added after the whole-branch review (independent model, and the stage-1 pass):

- **A raise needs the root's fix.** Every reader holds a fix that a reply adds where the
  root had none (tyje: it cannot tell a real fix from a thief's `0.0.1`). A thread raised
  to critical in that reply would show members a critical whose upgrade has no version,
  and `verify.judge` would call it above the source. So `plan_known` raises a known
  thread to critical only when its root stated a fixed version: the ledger entry keeps
  `root_fixed` (for an entry written before it, the thread's fix when no reply changed
  it). A thread whose root had no fix stays high with its fix until a member's source
  check can confirm the held fix (h29n, tavj). The common order (the vendor's advisory
  with its fix first, KEV later) still raises.
- The outbox check covers new roots and their copies (a copy's block is read from its
  text when it keeps no `adv`); replies keep a thread's standing level.
- A reply that is not a fix keeps a root's `stop_using`, and `_publishable` allows it
  while no fix is stated. `Run.one` counts the thread's fix for a `stop-using` critical
  too. A fix the schema cannot express never yields `stop_using`.
- **Curator.** `curator post` and `curator amend` refuse a critical with no complete
  action (any verb with a target; an upgrade needs the product's fixed version). A curator
  critical already without one may still take a note. Readers are unchanged: nothing
  already published is hidden.

### Consequences for other behaviour

- A non-exploited flaw with no fix known is a notice, held for the digest, and posts a
  root at high when the fix is read (raised when the fix exists). 0dvh's six-hour hold of
  a bare high therefore applies only to a verified trojanized reading now; its tests use
  that case.
- The synthetic check (`run --kev-file`, docs/plan.md E3) posts at high in the feed: a
  KEV entry states no version. A synthetic check of the critical channel needs a
  synthetic fix; follow-up.

## Known limits (follow-ups)

- The poster's ghsa reading comes from the HTML page: no `type`, CVSS vector or CWE
  list. The malware and CWE rows fire for the poster only after ny5g reads
  `api.github.com/advisories/<id>`. Until then the poster's highs come from prose.
- The member CLI does not yet apply `action_level` to what it shows; fv4g's recompute
  must apply it (note left on fv4g).
- CWE-15 (external control of a configuration setting), which GHSA-8wv7 names, is not
  added: in most products it is not code execution. The prose reading covers that item.

## Blast radius and rollback

Poster levels change: fewer highs (the severity word no longer raises), KEV criticals
without a fix post at high. Readers: the ruleset version moves to 3; the CLI and poster
ship together, and a claim naming version 2 is still checked with this reader's rules
(`check_claim` computes with its own). Rollback: revert the merge commit; ruleset version
2 returns with it.

Assumes: no curator or member flow relies on `severity-tier1` as a reason string (grep
shows tests only).
