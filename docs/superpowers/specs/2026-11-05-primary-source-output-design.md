# check --json, run --json and plan print the advisory's primary source

Kata: ai-tools-alerts#h260 (discovered in ai-tools-alerts#83xn, epic jibot-code#gr5b).
Parent: docs/plan.md Task A6 Interfaces; A6 spec
docs/superpowers/specs/2026-11-05-skills-hooks-templates-design.md, Open questions.

## Problem

The A6 skills tell the person, for each critical match, "the primary source
link if the CLI printed one". The CLI prints none: `cli._match_json` (used
by `check --json` and `run --json`) and `cli.cmd_plan` omit `adv.sources`.
A6 shipped a fallback sentence pointing at `#security-feed` because
`aitools_alerts/` was out of its scope.

## Success criteria

1. Every object in `check --json`, and in `run --json`'s `matches`, carries
   `sources`: the advisory's sources as a list of `{"url", "published_at"}`
   in post order, and `source`: one URL string (rule below).
2. `plan <id>` prints `  source: <url>` on the line after each matched
   advisory's header line, same rule.
3. The rule: the first source for which `schema.is_primary(url)` is true,
   else the first source (the schema requires at least one). This is the
   rule `poster/compose._primary` already uses.
4. The printed `source` is the URL with every character outside the URL
   reserved and unreserved ASCII set percent-encoded (`%` kept), so it holds
   no whitespace and no non-ASCII. The schema already refuses control and
   line-separator characters in a source URL; it allows spaces and other
   `Zs` characters, and a URL with a space could otherwise put text such as
   `command: ...` on the `source:` line that an agent reads.
   `sources[].url` is the stored value, unencoded (JSON escapes it).
5. `skills/claude-code/aitools-alerts/SKILL.md`,
   `skills/hermes/aitools-alerts/SKILL.md` and `snippets/AGENTS.md` name
   `sources` and `source` in the `matches` description, tell the agent to
   give the person `source` for each critical match, say `plan` prints
   `source: <url>`, and drop the `#security-feed` fallback. The three keep
   one procedure (the existing word-for-word tests).
6. The session-start hook's one fixed line is unchanged; `notify` text is
   unchanged (out of scope).
7. Tests: `tests/test_cli.py` asserts both JSON fields for the fixture and
   for a two-source advisory whose primary is second, the plan line, and the
   encoding of a URL with a space; `tests/test_templates.py` asserts the
   quoted CLI strings exist in cli.py and the fallback is gone.
8. Under 200 changed lines outside docs/superpowers. Full test suite passes.

## Approach

One helper in cli.py, `_source(adv) -> str`: pick per rule 3, encode per
rule 4 with `urllib.parse.quote(url, safe=":/?#[]@!$&'()*+,;=%~")`.
`_match_json` adds `"source": _source(t.adv)` and
`"sources": [asdict(x) for x in t.adv.sources]`. `cmd_plan` prints
`  source: {_source(t.adv)}` after the header. The JSON stays one object per
(thread, match), so ai-tools-alerts#54p7 (one line per advisory id) can
later group thread ids per advisory without a shape change here.

## Alternatives considered

- **Only `sources`, no `source` field** (the issue's literal list). Rejected:
  step 2 tells the person before `plan` runs, and the agent cannot evaluate
  `is_primary`; it would guess. `source` is additive.
- **A `primary: bool` per source entry.** Rejected: changes the documented
  `{url, published_at}` entry shape; one `source` field is simpler to quote.
- **Print the raw URL.** Rejected per rule 4 (a space-bearing URL from a
  relay-bot post could forge text on the `source:` line).
- **Reuse `poster/compose._primary`.** Rejected: the poster package is the
  relay-bot side and is being edited in parallel (qg7p, hhe3); the member
  CLI keeps its own two-line helper.

## Blast radius / rollback

Additive JSON keys and one added plan line; consumers that ignore unknown
keys are unaffected. Skills and snippet text change. Rollback: revert the
commit.

## Open questions

None blocking. Assumes: `is_primary` with the default domain list (spec/
primary-domains.json) is the right notion of primary for the member side,
as it is for the curator and the poster.
