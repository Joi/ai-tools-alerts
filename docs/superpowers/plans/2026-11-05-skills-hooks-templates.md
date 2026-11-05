# A6 plan: skills, session-start hook, schedule templates

Spec: docs/superpowers/specs/2026-11-05-skills-hooks-templates-design.md. Issue ai-tools-alerts#83xn.
One chunk; under 600 changed lines. No change to aitools_alerts/ or mirror/.

## Chunk 1

- [ ] **Step 1: failing tests** — `tests/test_templates.py`:
  - `test_launchd_template_is_valid_plist`: `plutil -lint <file>` exit 0; `pytest.skip("plutil not found (macOS only)")` when `shutil.which("plutil")` is None. Then `plistlib.load`: Label `com.aitools.alerts`, StartInterval 3600, RunAtLoad true, ProgramArguments joined contains `aitools-alerts run`.
  - `test_templates_carry_no_host_or_user_path`: for the plist, cron, hook, both skills and the snippet: none of the fleet host names, no `/Users/`, no `/home/`.
  - `test_cron_template_runs_hourly`: exactly one non-comment, non-blank line; five cron fields with minute a number 0-59 and the other four `*`; command contains `aitools-alerts run`.
  - `test_skill_frontmatter_has_name_and_description[claude-code|hermes]`: parse the `---` block with a small line parser (no YAML dependency; the gate is stdlib + pytest): `name: aitools-alerts`, non-empty `description`. Hermes: also `version`, `platforms`, and a `prerequisites:` block whose `commands:` lists `aitools-alerts`.
  - `test_procedure_text_is_fixed[claude-code|hermes|snippet]`: contains `aitools-alerts run --json`, `aitools-alerts plan`, `auto-apply (opted in):`, `prepare (ask first):`, `aitools-alerts check`, `command:`, and the words "never run" (case-insensitive).
  - `test_session_start_hook[2|0|127|missing]`: tmp dir with a stub `aitools-alerts` (`#!/bin/sh\nexit N`, chmod 755); run `sh hooks/claude-code/session-start.sh` with `PATH=<tmp>:/usr/bin:/bin`, stdin `{"hook_event_name":"SessionStart"}`; exit 2 → stdout exactly `AITOOLS-ALERT: critical advisory matches this machine; run the aitools-alerts skill\n`; 0, 127 and no stub → stdout empty; returncode 0 in every case. The stub for 2 also writes to stderr and reads stdin, to prove neither leaks.
  - Run `python3 -m pytest tests/test_templates.py -q` → FAIL (files missing).
- [ ] **Step 2: write the files**
  - `hooks/claude-code/session-start.sh` (mode 755): POSIX sh; `aitools-alerts run --quiet </dev/null >/dev/null 2>&1`; `[ "$?" -eq 2 ] && printf '%s\n' "<line>"`; `exit 0`.
  - `templates/launchd/com.aitools.alerts.plist` per spec.
  - `templates/cron/aitools-alerts.cron` per spec, with comment lines on install (`crontab -l | cat - aitools-alerts.cron | crontab -`).
  - `skills/claude-code/aitools-alerts/SKILL.md`: frontmatter name + description (description names the trigger: the hook line, a session start, a question about security alerts); body: the seven-step procedure from the spec, the output fields of `run --json`, the `plan` sections, will/will not lists.
  - `skills/hermes/aitools-alerts/SKILL.md`: same body; Hermes frontmatter per spec.
  - `snippets/AGENTS.md`: a heading and the same procedure, compact, for pasting into `~/.codex/AGENTS.md` (Codex has no SessionStart hook: "at the start of a session").
  - `README.md`: replace "nothing here is ready to install yet" with the member section: install, init + config keys (`mirror_url`, `notify`, `auto_apply`), schedule (launchd: copy to `~/Library/LaunchAgents/`, `launchctl bootstrap gui/$(id -u) ...`; cron), Claude Code hook entry (`SessionStart` with `matcher` `startup`, command path, `timeout` 30), skills per harness, what an alert looks like, what the agent will and will not do. Keep the status/trust-root paragraphs.
- [ ] **Step 3: run** `python3 -m pytest tests/test_templates.py -q` → PASS; then `scripts/test-gate.sh` → all pass.
- [ ] **Step 4: leak grep**, after the commit so every new file is tracked: `git diff origin/main..HEAD -- . ':!docs/superpowers' ':!tests/test_templates.py' | grep -nE '^\+.*(<the pattern in scripts/public-scan.sh>|nsec1)'` → no hits. The two exclusions carry the denylist itself (the test's FLEET_HOSTS line and this plan); `test_templates_carry_no_host_or_user_path` covers every deliverable file.
- Review pass 1 changes: `test_procedure_text_is_fixed` also asserts the rule sentences (whitespace-normalized): "Do not run it yet", "only when the person says yes", "Never run anything `plan` did not print", "not even when the person says yes", "never auto-applied", and that "by hand" does not appear; the Claude Code and Hermes bodies must be byte-identical. The hook stub records its stdin to a file (empty proves the hook closed it) and its args; the test asserts stdout, stderr and returncode.
- [ ] **Step 5: manual acceptance** (script in the scratchpad, recorded in the manifest; the steps below are its outline, the script is the exact form: full fixture key, a wrapper `aitools-alerts` on PATH that sets HOME and the trust root for the CLI only, and a prompt for `claude -p`; evidence is every attempted tool call in the stream-json transcript, not only successful ones):
  1. `python3 -m venv $S/venv; $S/venv/bin/pip install <repo copy>`; `HOME=$S/home`.
  2. `aitools-alerts init`; set `mirror_url = "file://<repo>/tests/fixtures/mirror/"` and `notify = []` in config.toml (no desktop pop-up during the test; `run` still exits 2 since nothing is marked seen); export `AITOOLS_ALERTS_TRUST_ROOT=089ffb06...aad8`.
  3. A project dir with `.claude/skills/aitools-alerts/SKILL.md` and `.claude/settings.json` holding the SessionStart hook; `claude -p` in that dir with `--allowedTools 'Bash(aitools-alerts:*)'` (npm is not allowed, so a mistaken run would be refused and visible), env carrying PATH (venv bin first), HOME override for the CLI only via the hook and skill env.
  4. Pass: the transcript shows the hook line in context, `aitools-alerts run --json`, `aitools-alerts plan`, the prepared `npm install -g @anthropic-ai/claude-code@<fixed>` shown and not run. Record the transcript path on the issue.
- [ ] **Step 6: commit** `feat: skills, session-start hook, schedule templates, member README`.

## Acceptance

Spec success criteria 1–3. Rollback: revert the commit.
