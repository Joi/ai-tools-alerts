# Spec: the SYNTHETIC TEST mark reaches the advisory title (ai-tools-alerts#hhe3)

## Problem

Found live on jibot-code#gs18 (E3). A `run --kev-file` post (fixture
CVE-2099-0010) marks only its head line: `CRITICAL (SYNTHETIC TEST): Claude
Code: known exploited vulnerability (CVE-2099-0010)`. The `aitools-alert`
block's `title` is `Claude Code: known exploited vulnerability
(CVE-2099-0010)`, and every reader uses the block: `aitools-alerts check`,
`plan`, `run`'s desktop notification (level and title), the mirror's
`feed.atom` entry title, and the Claude Code skill, which quotes `title`. The
E3 session told the user "this machine matches a known exploited
vulnerability in Claude Code" and never said it was a test. Fleet rule: a
synthetic test is never labelled real (docs/design.md; akq9 spec
docs/superpowers/specs/2026-11-05-poster-input-visibility-design.md).

## Success criteria

1. `compose.root_post` for a candidate whose primary id is reserved
   (`is_synthetic`, `CVE-2099-NNNN`) yields an advisory whose `title` starts
   `SYNTHETIC TEST: `; `schema.parse_post` of the post text returns that
   title. For any other id the title never carries the mark.
1a. A reader marks a synthetic advisory whatever its post says: a legacy
   root with an unmarked title and a reply patch that sets an unmarked title
   both read `SYNTHETIC TEST: ...` from `schema.parse_post` / `pull`.
2. The head line keeps its existing mark:
   `CRITICAL (SYNTHETIC TEST): SYNTHETIC TEST: Claude Code: ...`.
3. The digest line carries the mark exactly once, for a marked title and for
   a synthetic advisory already in a ledger with an unmarked title.
4. A relay-bot reply to a synthetic thread can never drop the mark: the
   template-title check accepts only marked titles for a reserved id.
   (A synthetic thread takes no reply today, main.py ~l.231; this keeps the
   compose contract consistent if that ever changes.)
5. `aitools-alerts check` (text and `--json`) and `plan` on a pulled
   synthetic relay-bot root show the marked title (tests/test_cli.py).
6. The session-start hook line is unchanged: the hook prints one fixed line;
   a synthetic critical still interrupts (that is the test's purpose), and
   the skill reads the title. No change to hooks/ or skills/.
7. Under 150 changed lines of code and tests; stdlib only.

## Approach

The id is the provenance, so the reader contract enforces the mark, not only
the writer (review pass 1, findings 1 and 3):

- `aitools_alerts/schema.py`: `SYNTHETIC`, `SYNTHETIC_ID` and `is_synthetic`
  move here from compose (compose re-exports them). `validate` prefixes
  `SYNTHETIC TEST: ` to the title of any advisory whose primary id is
  reserved and whose title lacks it, then checks the 300-character limit.
  Every reader builds its advisories through `validate` (`parse_post` for a
  root in `pull` and the mirror's Atom exporter, `pull._apply_patch` for a
  reply, `compose.apply_patch`, the poster's ledger), so a root posted before
  this change, a replayed journal entry, a curator post and a patch that sets
  an unmarked title all read marked.
- `compose.root_post`: the head mark follows `is_synthetic(c.id)` only; the
  `test` argument is removed (main passes it from the same predicate), so a
  caller cannot mark a real advisory (review finding 2). The title comes back
  marked from `validate`.
- `compose._titles(name, adv_id)`: for a reserved id the marked forms only.
- `compose.digest`: prefix `(SYNTHETIC TEST) ` only when the id is reserved and
  the title lacks the mark (an Advisory built without `validate`).

The title stays within 1..300 characters: a marked title over 300 is invalid.

## Alternatives considered

- Mark only through a new block field (`synthetic: true`): a schema change,
  every reader must learn it, and the skill would still quote an unmarked
  title. Rejected.
- Drop the head-line mark now that the title carries it: the brief says the
  head line keeps its mark; the doubled text is explicit and harmless.
- Edit the skills to tell the agent about synthetic titles: the skill
  already quotes the title verbatim, and ai-tools-alerts#h260 edits the
  skills in parallel. Not needed for the fix.

## Blast radius and rollback

Two modules (schema.py, compose.py), one line in poster/main.py, tests.
Existing posts and ledger entries for synthetic ids read marked through
`validate`; nothing is rewritten on disk. The live poster is reinstalled by the coordinator after landing; no
live send from this task. Rollback: revert the commit; posts already made
stay as posted (a synthetic thread is retracted by hand per E3).

## Open questions

None. A curator post with a reserved primary id reads marked too (the reader
marks by id); a curator's free-text title is otherwise its own.
