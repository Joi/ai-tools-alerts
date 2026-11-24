# Plan: c6ak model-written headline and Who line

Spec: docs/superpowers/specs/2026-11-24-c6ak-model-wording-design.md

Verification for every chunk: `python3 -m pytest -q tests/poster` while working;
`scripts/test-gate.sh` (public scan, then the whole suite) on the committed head.

## Chunk 1: source text and the wording module

- [ ] `aitools_alerts/poster/rules.py`
  - `AdvisoryPage` gains `description: str | None = None`. `read_advisory` sets it
    to the text nodes after the "Description" heading and before the last
    "Severity" node (the sidebar), joined with one space, cut to
    `MAX_SOURCE_TEXT = 4000`; None when empty.
  - `Evidence` gains `text: str | None = None`; `evidence()` carries
    `text=p.description` in the repository-page branch.
- [ ] `aitools_alerts/poster/candidates.py`
  - `Candidate` gains `source_text: str | None = None`, never kept by `to_dict`
    (deleted there as `severity_word` is). `inputs.py`'s candidate-shape check
    lists the never-kept fields; add `source_text` to its exclusion set.
  - `from_kev` passes `text=_title(it.get("shortDescription"), hosts)` cut to
    `MAX_SOURCE_TEXT`; `_build` takes `text=None` and sets `source_text`.
    (`_title` already strips fleet hosts and refuses a private path; check its
    length limit and use a separate cut when it is shorter than 4000.)
- [ ] `aitools_alerts/poster/main.py` `admit`: `source_text=ev.text if ev.url and ev.text
      else c.source_text if ev.kev else None`, beside `source_title`.
- [ ] `aitools_alerts/poster/wording.py` (new): `Wording(headline, who)`, `SYSTEM`,
      `VOCABULARY`, `prompt(c, scope)`, `parse(answer)`, `check(w, advisory, names)`
      (returns the refusal reason or None), `usable(c)`, `draft(c, scope, *, call)`
      returning `(wording, "ok" | "refused" | "failed")`; spec section 2 is the
      contract, including the closed vocabulary and the id rule (spec review pass 1).
- [ ] `aitools_alerts/poster/compose.py`
  - `head_of(level, id, reason)` and `worded(head, name, wording)` (the headline
    fits whole). `root_post(..., wording=None)`: headline text from the wording when
    it fits; `Who: <who>` after the headline.
  - `root_post_ja(..., wording=None)`: the model headline as `title`; no Who.
- [ ] Tests, `tests/poster/test_wording.py` (new):
  - accepted draft: headline and Who in the post, block (`schema.parse_post`)
    equal to the one composed without wording, the title in the template form;
  - one refusal test per class: over 90 / over 200, a line break, a backtick, a
    tilde, a URL (`https://`, `www.`, `example.com`), a command (`npm install x`,
    `--flag`, `curl x`), a mention (`@someone`), a name absent from the advisory
    (`Kubernetes`, `CVE-2026-9999`, `evil-pkg`), a fleet host name, non-ASCII;
  - allowed: the scoped package name `@scope/pkg`, a version that the source text
    states, a capitalised first word;
  - `parse`: extra lines, missing labels, empty answers give None;
  - `draft`: `CallError` and any exception give None; `AuthError` propagates;
  - headline that would need a cut drops the wording (source title instead);
  - `read_advisory` reads the description; a KEV item keeps `shortDescription`.

Acceptance: `python3 -m pytest -q tests/poster` passes.

## Chunk 2: poster wiring, config, summary

- [ ] `aitools_alerts/poster/inputs.py` `Config.model_wording: bool = False`, parsed
      like `translate_curator` (`type(...) is bool`).
- [ ] `aitools_alerts/poster/main.py`
  - `run(..., wording_call=None)` passes it to `Run`; `Run.__init__` takes
    `wording_call=None` and sets `self._wcall`, `self._wasked = 0`,
    `self._wspent = 0.0`, `self.w_status` (`off` | `ok` | `held` | `key-error`).
  - `Run.wording(c, scope, level, reason)`: None when off, a notice, synthetic, no
    source prose, held, over 4 calls or 60 s. One `try` around all of it: reads the
    translate state's `hold` (unreadable state: status `error`, no call); reads the
    key lazily (a `CallError` sets `key-error`); calls `wording.draft`; on
    `AuthError` sets `held` in memory first, then writes the hold (default shape
    when the file is absent); a failed write is said and changes nothing else; a
    drafted headline that would be cut is refused. Counts `word_asked`, `worded`,
    `word_refused`, `word_failed`.
  - `plan_new`: after the notice branch decision, compute the wording only when
    `level != "notice"`, then `compose.root_post(..., wording=w)` and
    `root_post_ja(..., wording=w)`. Restructure so the notice path composes
    exactly as today (no call).
  - `plan_known`: when `copies` is non-empty, compose the copy text with
    `wording=self.wording(k, scope)`; the reply path unchanged.
  - summary: ` wording=<worded>/<asked>` (or `held` / `key-error`) only when
    `model_wording` is on.
- [ ] Tests in `tests/poster/test_wording.py` (run-level, with the existing
      `env.run` harness from `tests/poster/test_translate.py`):
  - off: a fake `wording_call` that fails the test is never called; summary has no
    `wording=`;
  - on: a high posts with the model headline and Who line, in every channel's copy;
    the Japanese reply carries the headline and no Who line;
  - refused draft, `CallError`, any other exception, unreadable key: the source title;
  - unreadable translate state and a failed hold write: the post still goes out;
  - a saved deferred candidate without `source_text` loads;
  - a raise to critical: the copy in the critical channel is worded;
  - `AuthError`: the hold is written, the next run makes no call, summary
    `wording=held`; `translate-clear-hold` clears it;
  - a notice makes no call; more than 4 roots in a run: 4 calls.

Acceptance: `scripts/test-gate.sh` exits 0 on the committed head.

## Rollback

Revert the merge commit; or leave the code and keep `model_wording` false.

## After landing

File "rollout: model_wording on the poster" (labels discovered-from:c6ak,
repo:ai-tools-alerts, priority 2): turning it on is a live config change.
