# PyPI placeholders say nothing is published there (ai-tools-alerts#26f0)

## Problem

The PyPI name `aitools-alerts` holds a placeholder, 0.0.1 (uploaded 2026-11-06). Its summary says "install from https://github.com/Joi/ai-tools-alerts until 0.1 is published here", and its description gives `pipx install git+https://github.com/Joi/ai-tools-alerts`, an unpinned branch install. Both contradict the README since ai-tools-alerts#4fkh: no release goes to PyPI, and the only supported install is a verified release commit. The repository's own name, `ai-tools-alerts`, returns 404 on PyPI. Joi ruled on 2026-11-26 to publish new placeholder text and reserve the second name (option 1 of the park on this issue).

## Success criteria

1. `https://pypi.org/pypi/aitools-alerts/json` reports version 0.0.2. Its summary and description say that no release of ai-tools-alerts is published on PyPI, and that the only supported install is the verified signed release described in the README at https://github.com/Joi/ai-tools-alerts. Neither contains an install command.
2. Each upload is a wheel only, never an sdist. Installing an sdist runs the setuptools build backend on the installer's machine, and a wheel runs nothing. Each wheel contains only its `.dist-info` files (`METADATA`, `WHEEL`, `top_level.txt`, `RECORD`): no module, no `entry_points.txt`. Its `METADATA` has no `Requires-Dist`, `Author`, `Author-email`, `Maintainer` or `Maintainer-email` field, so no personal email is published. A check script in the scratchpad asserts all of this on the exact files before any upload.
3. 0.0.1 is yanked with a reason saying the same as (1). PyPI offers no API for yanking, so this is a hand step for Joi in the web UI. The issue carries the label `joi-action` and the exact step.
4. `ai-tools-alerts` is reserved with the same empty placeholder at version 0.0.1, or the close-out quotes PyPI's name-similarity refusal ("too similar to an existing project"). Warehouse refuses a new name whose "ultranormalized" form (lowercased, `-`/`_`/`.` removed, confusable letters folded) matches an existing project. `ai-tools-alerts` and `aitools-alerts` both fold to the same string, so this refusal is expected, and as long as `aitools-alerts` exists nobody else can register the name either. Only that refusal counts. Any other refusal (invalid metadata, a 403, registration disabled) leaves the criterion unmet, and the close-out says so.
   PyPI's name-retention policy (PEP 541) counts empty projects held only to reserve a name as invalid and open to removal on request. Neither placeholder is a durable guarantee, so the close-out says so. That is a risk of Joi's ruling, not a reason to skip it: both names belong to an existing, active project, and the placeholder exists to stop impersonation.
5. The placeholder source lives in `pypi-placeholder/<name>/`, outside the package tree. It holds no host, tailnet, VM or home-path names and no personal email (the public scan passes). A test keeps it empty and free of install lines.
6. The install guard in tests/test_install_path.py (`NAME`) also matches `ai-tools-alerts` and its separator variants, so no shipped file can install by either name.
7. The README says nothing that contradicts the placeholders. The sentence at README.md:97 stops naming the version "0.0.1" and states what PyPI now holds under both names.

## Approach

- `pypi-placeholder/aitools-alerts/` and `pypi-placeholder/ai-tools-alerts/`. Each holds a `pyproject.toml` (setuptools pinned exactly as in the root, `packages = []`, `py-modules = []`, no dependencies, no scripts, no author, Homepage URL only) and a `README.md`, the long description, with the same text in both apart from the name.
- `tests/test_pypi_placeholder.py` parses both pyproject files. It asserts no dependencies, no optional dependencies, no scripts or entry points, empty `packages` and `py-modules`, no author or maintainer, the summary text, and a README with no install command (the `INSTALL` regex from tests/test_install_path.py) that names the README's verified release. The existing install guard already walks every tracked file outside `tests/` and `docs/superpowers/`, so it covers the new files too.
- Copy each `pypi-placeholder/<name>/` to a fresh scratchpad directory so build leftovers never land in the source tree. Build it there with `uv build --wheel --out-dir <scratch>/dist-<name> <copy>`, never from the repository root, whose bare `uv build` would build the real CLI. Run the check script on the one resulting wheel. Upload with `uv publish <that exact wheel path>`, the token passed through the environment from `get_secret PYPI_TOKEN` in a script file, never on a command line.
- Verify with one unauthenticated GET per name of the JSON API.
- README.md:97 and a CHANGELOG "Unreleased" paragraph describe what PyPI now holds.

## Alternatives considered

- **Keep the source out of the repository entirely (scratchpad only).** The brief allows that. It is rejected because a later re-upload or audit would have no record of what was published, and a committed test keeps the text honest.
- **Author "Joichi Ito" as in 0.0.1.** Rejected: the brief allows the no-reply address or nothing. Nothing is simplest and publishes no address.
- **A `hatchling` build.** Rejected: the root project already pins setuptools, and one backend is enough.

## Blast radius and rollback

A PyPI upload cannot be undone: a distribution filename can never be uploaded again, even after deletion, so a published wheel's text is permanent. A wrong text is fixed by uploading 0.0.3 and yanking 0.0.2. Installing either placeholder installs an empty wheel and runs nothing. The repository change is new files plus two prose edits, reverted by reverting the merge.

## Open questions

None. Assumes: the vault's `PYPI_TOKEN` belongs to the account that owns `aitools-alerts`. A 403 on the aitools-alerts upload means the token cannot publish there. The response body says why: another owner, or registration disabled. Ownership is not inferred from the status code. Then the brief's rule applies: say so, label `joi-action`, stop.
