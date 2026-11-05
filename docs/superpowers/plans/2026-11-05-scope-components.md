# Plan: scope components (ai-tools-alerts#qme5)

Spec: docs/superpowers/specs/2026-11-05-scope-components-design.md. One chunk; one commit plus run artifacts.

## Chunk 1 — schema v4 components through both matchers

### Tests first (red on the base tree)

- [ ] `tests/poster/test_rules.py`
  - `test_scope_file_versions`: rewrite. Version 4 reads (word default, substring allowed); no version, 1, 2, 3, 5, `True`, `"4"`, `4.0`, a bad `match_mode`, an unknown top-level key and a non-string description are refused.
  - `test_scope_file_not_match_needs_version_3`: rename to `..._version_4`; the load helper writes version 4; the "version 2 refuses not_match" rows become "version 3 refused".
  - new `test_scope_file_components`: a version-4 file with components loads them (`ScopeComponent` name, match tuple, not_match tuple); refused: component missing name, empty match, unknown key, uppercase pattern, a component name equal to another entry's or component's name, an entry with neither match nor components, components given as `[]`; allowed: a component named as its own entry.
  - new `test_scope_of_resolves_components` (shipped file): "containerd" → name `containerd`, ecosystem docker, tier 1; "Opencontainers runc" → `runc`; "Docker Desktop" → `Docker`; "containerd shim in Docker Engine" → `containerd`; "@modelcontextprotocol/inspector" → `MCP Inspector`; "mcp-remote" → `mcp-remote`; "Example MCP server" → `MCP servers and clients`; "ClawHub" → `ClawHub`; "skills.sh registry" → `skills.sh`; "Claude skill" → `ClawHub and skills.sh`; "Ubuntu" → `Ubuntu`; "Google Chrome" → `Chrome`; "rustup" → `rustup`; "Rust toolchain" → `Rust`; a resolved scope has `components == ()`.
  - new `test_component_not_match_and_entry_not_match` (constructed entries): a component vetoed by its own not_match falls to the next component, then the entry fallback; an entry not_match vetoes a picked component; both log for review.
  - `test_short_pattern_does_not_match_inside_another_word`: `skills.sh` assertions now expect `skills.sh`.
  - `test_vendor_words_from_tier1_names`: add `containerd`, `runc`, `rustup` ⊆ words.
  - Any other assertion on `.name == "ClawHub and skills.sh"` / `"MCP servers and clients"` / `"Linux distributions"` / `"Browsers"` / `"Docker"` for component text: update to the component name (grep).
- [ ] `tests/test_schema.py::test_scope_patterns_avoid_common_words`: `scoped()` tests entry and component patterns. `test_load_scope_rejects_bad_entries`: fixtures carry version 4 and a valid control, so each case refuses for its own defect, not the missing version.
- [ ] `tests/poster/test_compose.py::test_entry_fallback_composes_under_the_entry_name`: "Example MCP server" composes under "MCP servers and clients" (the fallback is resolved, so compose's guard passes it). Digest test: "Ubuntu linux kernel" now names `Linux kernel`.
- [ ] `tests/poster/test_compose.py`
  - new `test_containerd_kev_composes_containerd`: a KEV candidate with product text "containerd", fixed "1.7.29", resolved by `rules.scope_of`, composes title `containerd: known exploited vulnerability (CVE-…)`, products[0] `containerd`/docker/fixed `1.7.29`, action upgrade `containerd` `1.7.29`, body "Action: upgrade containerd to 1.7.29 or later."
  - new `test_root_post_refuses_unresolved_entry`: passing the raw Docker entry (components present) raises ValueError.
- [ ] `tests/test_check.py`
  - new `test_component_advisory_matches_component_installation`: the composed containerd advisory, via `schema.parse_post` of the post text, matched against `Inventory({"docker": [Installed("containerd", "1.7.20", "containerd")]})` → one Match, reason affected; against `[Installed("Docker", "27.3.1", "docker")]` → none.
  - new `test_docker_advisory_does_not_match_containerd`: a Docker advisory (fixed 27.4.0) against the containerd installation → none (the alias fix).
  - new `test_component_installation_never_auto_applies`: curator containerd post, `Config(auto_apply={"upgrade"})` → `auto_apply == []`, the upgrade is in `prepare`.
  - new `test_aggregate_components_match_by_name`: an mcp advisory with product `mcp-remote` matches an installed mcp server named `mcp-remote`; a skill advisory `ClawHub` does not match an unrelated skill.
- [ ] `tests/test_inventory.py`: new `test_docker_component_probes`: runner answering `containerd --version` ("containerd github.com/containerd/containerd v1.7.20 8fc6bcff5") and `runc --version` ("runc version 1.1.12") yields `containerd 1.7.20` and `runc 1.1.12` under docker; no answers → nothing extra.

Run `python3 -m pytest -q tests/poster/test_rules.py tests/poster/test_compose.py tests/test_check.py tests/test_inventory.py tests/test_schema.py` and record the red count.

### Code

- [ ] `aitools_alerts/schema.py` (≈ lines 98-110, 354-425)
  - add `@dataclass(frozen=True) class ScopeComponent: name: str; match: tuple[str, ...]; not_match: tuple[str, ...] = ()`.
  - `ScopeEntry`: add `components: tuple[ScopeComponent, ...] = ()`.
  - `SCOPE_VERSION = 4`, `SCOPE_VERSIONS = (4,)`; `_scope_mode`: a non-object → `_fail("scope", "not an object")`; missing or other version → `_fail("scope.version", "not 4")`; rest unchanged. Docstring updated.
  - `load_scope`: entry keys = required {name, ecosystem, tier} + optional {match, not_match, components}, at least one of match/components; `_scope_component(v, at)` validates a component (keys name, match, optional not_match); collect all names into one set, a component may repeat only its own entry's name.
- [ ] `aitools_alerts/poster/rules.py`
  - `scope_of`: the order in the spec (components, entry fallback, entry not_match veto, excluded flag on any veto); a picked component returns `dataclasses.replace(e, name=c.name, match=list(c.match), not_match=c.not_match, components=())`. Docstring updated.
  - `vendor_words`: also the first word of each tier-1 component name.
- [ ] `aitools_alerts/poster/compose.py::root_post`: `if getattr(scope, "components", ()): raise ValueError("an unresolved scope entry would publish a group name")`.
- [ ] `aitools_alerts/check.py::_aliases`: add IDENTITY and the ecosystem name only when `installed.name.lower()` is in `IDENTITY.get(ecosystem, set()) | {ecosystem}`; update the IDENTITY comment (components are named installations now).
- [ ] `aitools_alerts/inventory.py`: `COMPONENT_TOOLS = {"containerd": ("docker", ("containerd", "--version"), rx), "runc": ("docker", ("runc", "--version"), rx)}`; `collect_tool` takes argv/rx through a small helper so both tables share it; `collect` adds each component probe under its ecosystem, named by the component.
- [ ] `spec/scope.json`: version 4, description rewritten for components, entries as in the spec (Docker, MCP, ClawHub and skills.sh, Linux, Browsers, Rust).

### Verification

- `python3 -m pytest -q` (the repo gate, scripts/test-gate.sh): all pass.
- `git diff --stat origin/main -- aitools_alerts spec tests` ≤ 400 changed lines; `git diff origin/main -- trust/` empty.
- Leak grep over added lines: `git diff origin/main | grep '^+' | grep -Ei 'host-a|host-b|host-d|host-e|host-f|host-c'` → none.
- Smoke: `python3 -c` resolving the KEV containerd text through `rules.scope_of` and `compose.root_post` prints the containerd title.

### Acceptance

The spec's six success criteria, each pinned by a test named above (1: compose test; 2: four check tests; 3: resolve test; 4: version tests; 5: full suite; 6: the stat and trust diff).

### Rollback

`git revert <sha>`: the version 3 file and readers return together; no state migration to undo (the ledger keeps whatever threads were posted).
