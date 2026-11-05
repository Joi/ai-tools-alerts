# Poster digest: one line per vendor release and per lead scope

Kata: ai-tools-alerts#qg7p (parent epic jibot-code#gr5b). Plan tasks B3 (compose, digest) and B1 (collector adapter) in docs/plan.md; compose contract in docs/superpowers/specs/2026-11-05-poster-compose-ledger-design.md.

## Problem

Since the collector gained Apple security releases and Ubuntu security notices (amplifier-bundle-joi#x484), one hourly run holds 107 notices for the 2026-11-06 digest: 44 CVEs from one Apple release page, 39 from another, 9 from one Ubuntu notice, a few more, and 12 browser leads (`LEAD-...` ids). `compose.digest` keys on (id, product) and prints one line per key, so the digest is 107 lines of `macOS: security advisory (CVE-...); no fix yet. <the same URL>`.

Two faults:

1. Grain. A vendor release that fixes N CVEs is one item for a member, not N.
2. "no fix yet" is wrong for a vendor release: the release is the fix. The collector record carries no `fixed` field for these findings. For Apple the fix version is in the primary source's title, which the collector writes as `APPLE-SA-<id> <release name> (macOS <major> fixed in <version>): <impact>`; for Ubuntu the record has no version at all.

## Success criteria

- S1. A digest with 44 CVE notices sharing one primary source URL prints one line for them: `- macOS: release 149521, 44 CVEs; <fix>. <url>`. Same for 9 CVEs sharing an Ubuntu notice URL.
- S2. 12 leads (`LEAD-` ids) in one scope at one level print one line: `- Browsers: 12 unrated leads.`
- S3. A critical advisory is always its own line, whatever its source.
- S4. The header reads `Daily digest for <date>: N advisories.` with N the number of item lines (a group counts once). Section headers count lines too.
- S5. `--json`, the ledger and the held queue still hold every advisory; `main` is unchanged. The grouping is presentation only.
- S6. `candidates.from_collector` sets `fixed` from the finding's `fixed` field (as now) or, when that is absent or unusable, from the finding's Apple release titles: only for a finding whose `product` is `macos`, only from sources whose URL is retained (passes B1's URL checks) and whose host is `support.apple.com`, and only from a title that matches the collector's whole prefix `APPLE-SA-<id> <release name> (macOS <major> fixed in <version>):`, with the version inside the major. Every such Apple source must carry a parseable title and all must name one version; any other outcome gives no version. Sources from other publishers (KEV, GHSA) state no version and are ignored.
- S7. A grouped release line says `fixed in <v>` when every member has the same fixed version, else `update available` when the shared URL is an allowlisted primary source (`schema.is_primary`), else `see the release`. A single advisory line is unchanged (`fixed in <v>` or `no fix yet`).
- S8. A group line passes the publication guard like any line; a failing one is withheld and counted as one item.
- S9. Tests pin the three real shapes (44, 9, 12) with CVE-2099 ids and example.com-style URLs. No fleet host names. Under 300 changed lines; stdlib only.

## Approach

### compose.digest

After the existing dedupe (latest per (id, product)), per level section, build line items:

- critical: one line per advisory, as now.
- high and notice: an advisory whose id starts with `CVE-` and whose title is the plain kind (`<name>: security advisory (<id>)`, exactly) groups under the key (level, primary URL, product name, synthetic). The primary URL is `_primary(adv.sources)` (first allowlisted primary source, else the first source). A key with two or more members prints one group line; a key with one member prints the ordinary line. Titles of any other kind — known exploited (every KEV candidate shares the catalog URL), trojanized, injection to code execution, anything unverified — keep one line each, so a shared catalog URL never reads as a release and the `unverified` mark is never dropped.
- notice only: an advisory whose id starts with `LEAD-` and whose title is the plain kind groups under (level, product name, synthetic). Two or more members print `- <name>: <n> unrated leads.`; one member prints the ordinary line. A lead rated high, or with any other title kind (unverified, trojanized), keeps its own line.
- Anything else (GHSA ids, other prefixes) keeps one line per advisory.

Synthetic (CVE-2099) and real advisories never share a group, because `synthetic` is in the key; a synthetic group line carries the `(SYNTHETIC TEST)` mark like a single synthetic line.

Group line for a release: `- [mark]<product>: release <label>, <n> CVEs; <fix>. <url>`. `<label>` is the URL's last non-empty path segment when it matches `[A-Za-z0-9][A-Za-z0-9._-]{0,39}` (Apple `149521`, Ubuntu `USN-8928-1`); otherwise the line reads `<product>: one release, <n> CVEs; ...`. The label comes from the URL that already passed B1's URL checks and goes through the guard with the line.

Order in a section: by the earliest member's (posted_at, id), the existing single-line sort key, so the digest stays deterministic.

The header N and each section count are the number of line items before the guard, as N is today (withheld lines are reported on their own line).

### candidates.from_collector

When `_fixed(f.get("fixed"))` is None (the field is absent or unusable) and the finding's `product` is `macos`, `_apple_fixed` reads the finding's source dicts whose URL survives B1's checks (`_url`, and is among the candidate's retained sources) and whose host is `support.apple.com`. Each such title must match, from its start, `APPLE-SA-[\w.-]{1,40} [^():]{1,120} \(macOS (\d{1,3}) fixed in (\d{1,3}(?:\.\d{1,4}){0,3})\): ` (the prefix up to the impact text), with the version's first component equal to the major. Every such source must match and all must name one version, which must pass `_fixed`; otherwise there is no version. The release-name part excludes `(`, `)` and `:`, so the impact text after the colon cannot supply a version. Sources from other publishers are ignored, and a version is never read from `product`, the finding's rationale or host evidence (B1: those can carry a locally observed version).

## Alternatives considered

- Group by primary URL alone, listing several products on one line. Rejected: one line per (release, product) keeps the line short and the product scope readable; a USN that touches two scoped products is two lines, which is still a large cut.
- Group every advisory sharing a URL, including GHSA ids. Rejected: a GHSA page is one advisory; grouping only CVE ids (vendor releases list many CVEs) matches the finding and avoids surprising merges.
- Name the vendor (`Apple security release 149521`) from the host. Rejected: it hardcodes vendor host names in compose; the path segment gives the same release id for the two real shapes and works with fixture URLs.
- Derive a fix version from the Apple range in the collector (`macos 27: < 27.1`). Rejected: ranges are not in the run record's findings; the title is.
- Say `update available` for every collector advisory with a vendor-release source. Rejected for single lines: a single line keeps today's text, and only a group, which is by construction a release fixing many CVEs, asserts an update.

## Blast radius and rollback

Two functions: `compose.digest` (text only) and `candidates.from_collector` (one more source for `fixed`). The second change reaches root posts: an Apple finding with a title version now posts `Fixed in <v>` and an `upgrade` action. That is the point of (c), and the version comes from Apple's own release name. Rollback: revert the commit; the coordinator reinstalls the poster. No state format changes, so a revert needs no migration.

## Assumes

- The collector's Apple source title shape is the one in amplifier-bundle-joi's `collect_apple` at e947e11a; a changed shape yields no version, never a wrong one.
- The coordinator reinstalls the live poster; this task runs no install and no live send.
