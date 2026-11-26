# Plan: PyPI placeholders (ai-tools-alerts#26f0)

Spec: docs/superpowers/specs/2026-11-26-pypi-placeholders-design.md

## Chunk 1: placeholder source, test, README and CHANGELOG

Files:

- [ ] `pypi-placeholder/aitools-alerts/pyproject.toml` (new). `[build-system]` requires `setuptools==80.9.0` exactly, the root's pin. `[project]`: name `aitools-alerts`, version `0.0.2`, `description` = SUMMARY, `readme = "README.md"`, `dependencies = []`, `[project.urls] Homepage = "https://github.com/Joi/ai-tools-alerts"`. No `authors`, `maintainers`, `scripts`, `entry-points`, `optional-dependencies`, `license` or `requires-python`. `[tool.setuptools] packages = []`, `py-modules = []`.
- [ ] `pypi-placeholder/aitools-alerts/README.md` (new): the long description, below.
- [ ] `pypi-placeholder/ai-tools-alerts/pyproject.toml` and `README.md` (new): the same, with name `ai-tools-alerts` and version `0.0.1`.
- [ ] `pypi-placeholder/README.md` (new, not uploaded): two sentences saying what the directory is, and that it is not part of the package. No build or upload command naming a token.
- [ ] `tests/test_install_path.py:57`: `NAME` also matches `ai-tools-alerts` (`ai[-_.]*tools[-_.]+alerts`: separator runs, as PyPI normalization collapses them), with cases `pipx install ai-tools-alerts`, `pip install ai_tools.alerts`, `pip install ai--tools-alerts` and `pip install aitools__alerts` added to the caught list. The negative cases, including the `git+https://github.com/Joi/ai-tools-alerts@<sha>` line, still pass.
- [ ] `tests/test_pypi_placeholder.py` (new). For each of the two projects, with `tomllib`: the `[project]` keys are exactly `{name, version, description, readme, dependencies, urls}`; `dependencies == []`; `packages == []` and `py-modules == []`; the build requirement equals the root pyproject's. The description equals the SUMMARY constant in the test. The README contains "No release of ai-tools-alerts is published on PyPI", "verified signed release" and the README URL. No line matches `test_install_path.INSTALL`, and no word "pip", "pipx" or "uv" appears as a command. The two READMEs are equal after swapping the names.
- [ ] `pypi-placeholder/check-wheel.py` (new, committed so the review sees it): the pre-upload check of Chunk 2. It holds no paths and no credential.
- [ ] `README.md:97`. Replace "The name `aitools-alerts` there holds an empty placeholder, version 0.0.1, that installs nothing: do not install from PyPI." with the form for the expected outcome. That form names no version and says `aitools-alerts` holds an empty placeholder and that PyPI refuses `ai-tools-alerts` as too similar to it. The words "do not install from PyPI" stay, since test_install_path asserts them. If Chunk 2's outcome differs, Chunk 2 changes this sentence in its own commit.
- [ ] `CHANGELOG.md` "Unreleased": one paragraph.

SUMMARY (one line):
`Empty placeholder. No release of ai-tools-alerts is published on PyPI; the only supported install is the verified signed release described in the README at https://github.com/Joi/ai-tools-alerts`

Long description:

```
# aitools-alerts

This is an empty placeholder. It contains no code, no command and no dependencies.

No release of ai-tools-alerts is published on PyPI, and none is planned. The only supported install is the verified signed release described in the README at https://github.com/Joi/ai-tools-alerts: verify the signed release tag and its commit as the README says, and install from that verified checkout.

The name is held here so that nobody else can publish a package under it.
```

Verification, in this order: commit every Chunk 1 file first, because the public scan and the install guard read `git ls-files`; then run

```
scripts/test-gate.sh            # public scan + the whole suite (the repo's own gate; no repoman row)
```

Acceptance: the gate passes on the committed HEAD. The new test fails if a dependency, a script or an author is added, or if an install command is added to either README (checked by temporarily adding one).

Review, blocking, before any upload: push the branch, open the PR (`gh pr create`, record its number `<n>`), and run the whole-branch review (`git diff origin/main...HEAD`, Stage 1 ∥ fresheyes). The review covers the placeholder source, `check-wheel.py` and the scratchpad upload script, whose full text goes into the review prompt (it names home paths, so it is not committed). Fix every BLOCKER, and fix or rebut every SUBSTANTIVE finding. A behaviour-changing BLOCKER fix gets its one delta pass before Chunk 2 starts.

## Chunk 2: publish and verify (only after the Chunk 1 review)

- [ ] For each name, copy `pypi-placeholder/<name>/` into a fresh scratchpad directory and build a wheel only: `uv build --wheel --out-dir <scratch>/dist-<name> <scratch>/src-<name>`. Never build from the repository root, and never build an sdist: installing one would run the setuptools backend.
- [ ] `python3 -I pypi-placeholder/check-wheel.py <wheel> <name> <version> <repo root>` (committed; the scratchpad build script runs it on each wheel) asserts, for the one wheel that will be uploaded: the members are exactly `<dist>.dist-info/{METADATA,WHEEL,top_level.txt,RECORD}`; `top_level.txt` is empty after `strip()` (setuptools writes a single newline); `METADATA` has Name and Version as expected, Summary equal to SUMMARY, exactly the headers Metadata-Version, Name, Version, Summary, Project-URL and Description-Content-Type (so no author, maintainer or dependency); a body equal to the committed README; no `@` anywhere. tests/test_pypi_placeholder.py runs it on synthetic wheels, one good and seven bad. The upload script refuses a dirty tree or an unexpected HEAD, turns shell tracing off before it reads the token, and reads the token with `KURA_NO_CACHE_KEYS=PYPI_TOKEN` so no plaintext cache entry is written.
- [ ] Upload with a scratchpad script: `source ~/dotfiles-private/scripts/lib/secrets.sh; UV_PUBLISH_TOKEN="$(get_secret PYPI_TOKEN)" uv publish <the exact checked wheel path>`. The token travels only in the environment. aitools-alerts first. On a 403, read the body, stop, comment, label `joi-action`. Then ai-tools-alerts. A 400 whose body says "too similar to an existing project" is the expected outcome: record it and go on. Any other refusal is reported as unmet.
- [ ] Verify with one unauthenticated GET per name, `curl -s -w '%{http_code}'`:
  - aitools-alerts: HTTP 200; `info.version` 0.0.2; `info.summary` equals SUMMARY; `info.description` equals the approved long description; `info.author` and `info.author_email` empty; 0.0.2's only file is the checked wheel (sha256 equal to the local one), not yanked.
  - ai-tools-alerts, on the expected similarity refusal: HTTP 404, the name still unregistered and unregistrable while aitools-alerts exists. On a successful upload: HTTP 200 with the same assertions at 0.0.1.
  - Quote version, summary, the description's first line and each file's `yanked`/`yanked_reason` in the close-out.
- [ ] Yank 0.0.1: hand action. Kata comment with the exact step (pypi.org → Your projects → aitools-alerts → Manage → Releases → 0.0.1 → Options → Yank, with the reason text below) and the label `joi-action`. The yank evidence is a GET of `https://pypi.org/pypi/aitools-alerts/0.0.1/json` after Joi acts, showing `yanked: true` and that reason on both files.

Yank reason:
`Superseded by 0.0.2: no release of ai-tools-alerts is published on PyPI; the only supported install is the verified signed release described in the README at https://github.com/Joi/ai-tools-alerts`

- [ ] Only if the ai-tools-alerts upload got the similarity refusal (a 400 whose body says "too similar to an existing project"): delete `pypi-placeholder/ai-tools-alerts/` and its test entry, since nothing was published from it, keep README.md:97 as written, commit, and re-run the gate. If it succeeded: keep the directory and change README.md:97 and the CHANGELOG sentence to say both names hold empty placeholders, in one commit. On any other refusal: keep everything, record the criterion as unmet on the issue, and do not close.

## Chunk 3: land

- [ ] Push Chunk 2's commits. They were made after the reviewed sha; the PR description and the close-out name each one, with `git diff <reviewed sha>..HEAD`.
- [ ] Merge: `gh pr merge <n> --merge --author-email '19930+Joi@users.noreply.github.com'`.
- [ ] Close-out comment (commits, test results, review line, PyPI JSON quotes). Close only when the yank evidence is in and every criterion is met. Until then the issue stays open with `joi-action`, the comment says what remains, and a watcher polls the 0.0.1 JSON for the yank.

## Rollback

Repository: revert the merge commit. PyPI: uploads are permanent per version. A wrong text means uploading 0.0.3 and yanking the bad version.
