# 4fkh: no install line or promise that points at PyPI

Issue: ai-tools-alerts#4fkh (finding H5 of the adversarial review z5wb).

## Problem

The finding: the README named the PyPI package `aitools-alerts` as coming, and a
member's agent told to "install the required tools" can reach for
`pipx install aitools-alerts`. If the name were free, anyone could register it
with a package that runs code at install.

State on main at 8f91677:

- The "coming" sentence is gone. `README.md:97` now ends "There is no package on
  PyPI; install only as above." That is no longer true: the name holds a
  placeholder.
- PyPI, one unauthenticated GET of `https://pypi.org/pypi/<name>/json` each
  (2026-11-26): `aitools-alerts` (and `aitools_alerts`, the same normalized
  project) returns version 0.0.1 only, author "Joichi Ito", homepage this
  repository, files uploaded 2026-11-06, summary "Name reserved for ai-tools
  security alerts (install from https://github.com/Joi/ai-tools-alerts until 0.1
  is published here)". The JSON API does not name the account that owns it; the
  author, the homepage and the date match the coordinator's note on the issue
  that the name was reserved from the fleet on 2026-11-06. `ai-tools-alerts`,
  `aitoolsalerts` and `ai-tool-alerts` return 404: unregistered.
- `aitools_alerts/relay.py:30`, printed when `curator post` runs without the
  websockets extra: `install the curator extra: pip install 'aitools-alerts[curator]'`.
  That is an install by name, which pip resolves on PyPI. In a fresh environment
  it installs the 0.0.1 placeholder; if the placeholder ever changed hands, it
  would install whatever that owner published.

## Success criteria

1. No shipped text (README, SECURITY.md, CHANGELOG.md, the package, skills,
   snippets, hooks, templates, mirror page) tells a reader the package is, or
   will be, on PyPI, or gives an install line by the bare package name.
2. The README says the only supported install is the verified release commit and
   that the PyPI name holds an empty placeholder that is not a release.
3. The curator hint installs the extra from the verified checkout.
4. A test fails if a shipped file gains `pip install aitools-alerts...` or
   `pipx install aitools-alerts...` again, or a sentence saying PyPI is coming.
5. `scripts/test-gate.sh` passes.

## Approach

- `README.md:97`: replace the last sentence with: "No release of this project is
  published to PyPI, and none is planned. The name `aitools-alerts` there holds an
  empty placeholder, version 0.0.1, that installs nothing: do not install from
  PyPI."
- `relay.py` `INSTALL_HINT`: "install the curator extra from the verified
  checkout: pipx install --force '.[curator]', or pip install '.[curator]' in
  its venv". `tests/test_curator.py:265` follows.
- New test in `tests/test_install_path.py` over the shipped files of criterion 1.

The placeholder exists, so no "someone else holds it" warning is needed.

## Alternatives rejected

- Reserve the name: already done on 2026-11-06. Publishing a new placeholder
  (to change its summary, which still says "until 0.1 is published here" and
  gives an unpinned install line) is a publish step, class a: a follow-up for
  Joi, not this branch.
- Rewrite the historical specs and plans under `docs/superpowers/` that record
  the 2026-11-06 plan to name PyPI as coming: they are dated records of a past
  decision, not instructions to a reader installing the tool; the README is
  what a reader follows. Their text stays; after the independent review each
  instruction that prescribes the PyPI sentence or the by-name hint carries a
  "Superseded by ai-tools-alerts#4fkh" line.
- Say nothing about the placeholder: a reader who searches PyPI finds 0.0.1 and
  cannot tell whether it is ours. One sentence settles it.

## Blast radius and rollback

Text only, plus one hint string and its test. Rollback: revert the commit.

## Follow-ups

- Joi (class a, publishing): a 0.0.2 placeholder whose summary and description
  say "not published here; install only from a verified release commit, see the
  README", replacing "until 0.1 is published here" and the unpinned install line.
- Joi (class a): reserve `ai-tools-alerts`, the repository's own name, which is
  unregistered.
