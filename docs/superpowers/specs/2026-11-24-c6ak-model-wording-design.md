# c6ak: model-written headline and Who line, with a deterministic check and fallback

Slice 7 of ai-tools-alerts#9mx8 (design section "6. Wording", Joi decision 4).

## Problem

After faxq a root post's headline is the source's own title, the product name put
in front when the title lacks it. A vendor title often says little ("Fix path
handling", "Security update"), and nothing in the post says who is exposed. The
design calls for two lines a model writes from the primary source: the headline
(level, the package as a member types it, what goes wrong, at most 90 characters,
no id) and one sentence naming the precondition ("Who:"). These are the only free
text in a post; everything else stays a template.

## What the code holds today (main at cc40b02)

- `compose.root_post(c, level, scope)` builds the body: `headline(head, name,
  source_title(c), fallback)`, Affected, Do, Covers, Source; then the block, whose
  title stays the template form `"<scope>: <kind> (<public id>)"`.
- `compose.root_post_ja` takes the same headline text, in English.
- `rules.read_advisory` parses a repository advisory page and keeps its title; the
  description below the "Description" heading is read for nothing. A KEV entry
  gives `vulnerabilityName` (the title) and `shortDescription`, which
  `candidates.from_kev` does not keep.
- `translate.py` holds the one provider-facing call (`api_call`), the secrets
  helper read (`read_key`) and the error types (`AuthError` for 401/403,
  `CallError` for the rest). The curator translation pass counts its calls (20 a
  UTC day) and, on `AuthError`, writes a hold into the translate state file that
  `translate-clear-hold` removes.

The issue text predates faxq; its note (comment ebfjm4) matches the code above.

## Approach

### 1. The primary source text

- `rules.AdvisoryPage` gains `description`: the page's text nodes after the
  "Description" heading and before the sidebar's last "Severity" label, joined
  with spaces, cut to `MAX_SOURCE_TEXT` = 4000 characters. `Evidence` gains `text`
  from it.
- `candidates.from_kev` keeps `shortDescription` (through the same `_title`
  cleaning as the title, which strips fleet host names and refuses a private
  path) as `Candidate.source_text`.
- `Candidate.source_text` is set by `Run.admit` as the title is: the vendor page's
  description when a page confirmed the candidate, else the KEV entry's text for a
  KEV candidate, else None. Like `severity_word` and `readings` it is never kept in
  the state file: a deferred candidate is admitted again, which reads it again.

### 2. `aitools_alerts/poster/wording.py` (new)

- `draft(c, scope, *, call) -> Wording | None`: one `call(SYSTEM, text)`. The user
  text gives the product name, the package, the source title and the source text,
  each on a labelled line. The model answers exactly two lines, `Headline: …` and
  `Who: …`. Any other shape is None.
- `check(wording, advisory_text, names) -> reason | None`, deterministic, applied to
  both lines. The contract is narrower than "no command anywhere in English": it is
  that every word the model writes is either a word of the advisory, the product or
  package name, or a word of a closed vocabulary shipped in the module, and that no
  character or shape a reader or the relay could act on survives. A draft is refused
  when either line:
  - is empty, has a line break, or exceeds 90 characters (headline) or 200 (Who);
  - holds a character outside `A-Z a-z 0-9`, space and `. , ; : ' ( ) / _ @ -`: no
    backtick or tilde (code span, fence), no `*`, `[`, `]`, `{`, `}`, `|`, `$`, `\`,
    `#`, `!`, `&`, `?`, `%`, `+`, `=`, `<`, `>`, `"`, and nothing non-ASCII. Shell
    metacharacters, redirects and Markdown cannot be written at all;
  - holds a URL or scheme: `://`, `www.`, a `:` inside a token (`javascript:x`), or a
    domain-shaped token (dot-joined labels, the last of letters) other than the
    product or package name;
  - holds a command shape: an option token (`-x`, `--name`) or a known tool
    invocation (`npm install`, `npx <x>`, `pip install`, `uvx <x>`, `curl`, `wget`,
    `sudo`, `brew install`, `apt install`, `docker run`, `git clone`, `rm`, `bash`,
    and the rest of `wording._COMMAND`). This list is a second line, not the
    guarantee: the vocabulary rule below is;
  - holds an advisory id (`CVE-…`, `GHSA-…`, `MAL-…`, any `ABC-123` shape, as
    `translate._ID` reads them), in either line: the design says "no id";
  - holds a mention token: an `@`-token that is not exactly the product or package
    name, or an `@` inside a token;
  - holds a word that is not grounded: each token (edge punctuation and a
    possessive `'s` removed) must be, case-insensitively, a whole token of the
    advisory text (source title and source text), the product or package name, or
    a word of `wording.VOCABULARY` (about 300 common English and security words:
    articles, pronouns, auxiliaries, "anyone", "agent", "repository", "untrusted",
    "attacker", "execute", …). A product the advisory does not name ("firefox",
    "Firefox users") or a program ("printf") is refused, capitalised or not;
  - names a fleet host or holds a local path or kata ref (`compose._guard`), which
    would otherwise withhold the whole post.
  - (code review pass 1) holds a domain anywhere in the line, inside a token or
    after a comma, once the product's and package's names are taken out as
    whole tokens only (a name inside `openclaw.example` is not taken out), or `//`;
    an advisory id in any case; a capitalised word the advisory does not write
    with that capital (the vocabulary never vouches for a name: "Pages users");
  - does not start with a fixed subject: the Who line with a word of
    `wording.SUBJECTS` (Anyone, Users, Developers, …) followed by a word of
    `wording.CONNECTORS` (who, whose, of, with, running, using, …), so
    "Users, disable the sandbox" is refused (delta review); the headline with the
    product or package name. Neither line can then be an instruction to the
    reader. Negations and modal verbs (not, no, need, should, must, can, could,
    may, might, will, would) are not in the vocabulary, so a Who line cannot say "users need not upgrade" unless the
    advisory itself says it.

  What this does not claim: that no sequence of advisory or vocabulary words can
  name a program ("Claude Code runs install"). It claims there is no shell
  character, option, known tool invocation, URL, id, mention, or ungrounded name,
  and no imperative sentence; the text is never executed, and readers act on the
  block alone.
- On a refusal, `CallError`, any other exception, or an empty answer, `draft`
  returns None. `AuthError` propagates so the run can stop calling.

### 3. Composing

- `compose.root_post(..., wording=None)`: with a `Wording`, the headline's text is
  the model headline (`headline()` adds the product name in front when it is
  missing, as for a title) and a `Who: <sentence>` line follows the headline. When
  the model headline does not fit `HEADLINE_MAX` with the level head without a
  cut, the wording is dropped whole and the source title is used: a model line is
  never cut.
- `compose.root_post_ja(..., wording=None)` uses the same model headline, in
  English, as faxq made it do for the source title. The Who line is not put in the
  Japanese post: it would be the only English sentence in it, and the post's
  remaining lines are the template's (decided; see "Alternatives").
- Nothing in the block changes: the title keeps its template form with the id,
  so the reply check, `_exploited`, `_ja_title` and the digest read what they read
  today. The CLI reads only the block (`schema.parse_post` → `_last_block`); the
  checked text cannot open a fence (no backtick, no tilde).
- The digest and the ledger keep the source title; the model text appears only in
  root post bodies.

### 4. The poster

- Config gains `model_wording` (bool, default false). Off: no call, no new state,
  the summary line byte for byte as today.
- On: `Run.wording(c, scope, level, reason)` is called by `plan_new` for a candidate
  that will post a root (level high or critical after the age and hold rules; never
  a synthetic one) and by `plan_known` when it posts copies. It reads the key once
  per run (`translate.read_key(config.secrets_helper)`), only when there is a root
  with source prose to word, and makes at most `WORDING_CALLS` = 4 calls a run, none
  after 60 seconds of calls in that run. The same key, the same call path, the same
  model. A drafted headline that would be cut beside the level head is refused.
  The key read and the calls share one budget of 60 seconds a run; a call starts
  only when the API's own 30-second deadline fits in what is left, and is never
  cut shorter (a late 401 must still set the hold), so wording delays a run's posts
  by at most 60 seconds plus a key read that took longer than its share.
- **One exception boundary.** Everything `Run.wording` does (reading the translate
  state, reading the key, the call, the check, writing the hold) is inside one
  `try`; any exception other than the ones it handles by name turns wording off for
  the rest of the run, is said on stderr, and returns None. Planning, composing and
  sending never see a wording exception, so the post goes out with the source
  title whatever happens.
- The hold is the translate hold: when the translate state file holds a hold, no
  wording call is made; an unreadable or malformed translate state also means no
  call (and is not rewritten); the check is translation's own (`_translate_state`). An `AuthError` from a wording call first turns
  wording off in memory, then writes that hold (the same shape, `why` naming
  wording; a state file that does not exist is created in the default shape); a
  failed write is said on stderr; the in-memory latch (`Run.key_refused`) still
  stops the curator translation pass in the same run. A run whose state directory
  cannot be written stops anyway (the journal and ledger live there), so the next
  run that calls is one whose disk works again, and its own 401 writes the hold. Posts go on with the
  source title while the hold stands: nothing waits for a person. Retrying the
  refused key every run is what the hold prevents (fleet rule: no credential retry
  after an auth failure). `translate-clear-hold`, which exists, clears it.
- A key that cannot be read, a model error, or a refused draft: the post uses
  the source title and no Who line. A refused draft counts `word_refused`, a call
  error `word_failed`; neither reaches the exit code.
- The summary line, only with `model_wording` on, gains ` wording=<worded>/<asked>`
  or ` wording=held` / ` wording=key-error`.
- The post text is journaled before it is sent, so a run that stops after planning
  and resumes never calls again for that post (one call per post).

## Success criteria

1. A root post (and its critical/feed copy) with an accepted draft shows the model
   headline and a `Who:` line; the block is identical to the one composed without
   wording.
2. Each refusal class above (including `javascript:x`, `printf x > y`, "Firefox
   users", "firefox", a CVE id the source states), a `CallError`, an `AuthError`,
   an unreadable key, a malformed answer, an unreadable translate state and a
   failed hold write produce the post composed today (source title, no Who line);
   tested one by one.
2a. A saved state holding a deferred candidate (no `source_text` key) still loads,
   and a candidate round-trips through `to_dict`/`candidate_from` without it.
3. `model_wording` off: no call, no read of the key, summary unchanged.
4. An `AuthError` writes the hold; the next run calls nothing; `translate-clear-hold`
   clears it.
5. At most 4 calls a run.
6. `scripts/test-gate.sh` passes.

## Alternatives considered

- **A new state file and daily budget for wording.** Roots are rare (high and
  critical only, about one a day), so a per-run cap bounds cost without a second
  ledger; the translate state's hold is reused because the key is the same.
- **Hold posts until the model answers.** Refused: the standing ruling (no human
  in the loop) and the design's fallback both say post with the title.
- **The Who line in Japanese by a second call.** Doubles the calls and the
  checks for one line; the Japanese reader gets the same headline. Can follow.
- **Model text in the digest.** The design names the root post only.
- **A name check by token shape only** (capitals, digits, inner punctuation).
  Reviewed and refused: "firefox" and "Firefox users" pass it. The closed
  vocabulary shipped in the module is deterministic on every machine and refuses
  them; the cost is more fallbacks, which post the source title.

## Blast radius and rollback

Off by default; with it off the only changes are the parsed description and KEV
text carried in memory. Rollback: set `model_wording` false, or revert the merge.
Turning it on is a live config change on the poster host: a follow-up issue
"rollout: model_wording on the poster" (discovered-from:c6ak) carries it.

## Assumes

- The vendor page's description and KEV's `shortDescription` are the "primary
  source text" the issue names.
- `secrets_helper` is set on the poster (config already requires it for the relay key).
