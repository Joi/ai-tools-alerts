# Run: skills-hooks-templates
Instruction: Start at medium. Task: ai-tools-alerts#83xn (A6) per TASK-ai-tools-alerts#83xn.md — skills, hooks, schedule templates, tests, README member section. Not repoman-managed: ff-merge ending.
Stage: code-review:whole-branch
Rung: medium (start-floor medium: constraint-lens, BR1 REV0 NOV1 INT1 FC1 = 4; Lens: "The SKILL.md procedure is fixed by the plan's Interfaces block; copy it, do not loosen it.")
Spec: docs/superpowers/specs/2026-11-05-skills-hooks-templates-design.md   Plan: docs/superpowers/plans/2026-11-05-skills-hooks-templates.md
Agency project: — (executed inline, as A1 to A5 did)
Kata: ai-tools-alerts#83xn
Last reviewed: spec+plan 09034833999c912cb34a39f661b4b6e5dd4b59e4
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 1B/7S/0C/2R · fixed -/- · velocity = (—→10, escalation no)   # fresheyes gpt-6-astra on snapshot 0903483 (REASON=-), 10 reported "major". BLOCKER fixed: the skill let an agent do a notify-only action "by hand" after a yes, which loosens the fixed procedure → removed from both skills, the snippet, the README and the spec; a yes never widens what may run. SUBSTANTIVE fixed: cron redirect into a state dir that a fresh install lacks → mkdir first; a venv install was not on the schedules' PATH → README links the command into ~/.local/bin; keyword-only procedure test → asserts the rule sentences, forbids loosening phrases, bodies identical; hook test isolation → stub records stdin and args, test asserts stdout, stderr, exit; acceptance not executable → exact script (see Notes); leak grep missed untracked files → runs after the commit over origin/main..HEAD with narrow exclusions. SUBSTANTIVE rebutted: primary-source link → decided in the spec: follow-up issue (aitools_alerts/ out of scope; A7 edits cli.py in parallel); `--allowedTools` does not forbid npm → the acceptance evidence is every attempted tool call in the stream-json transcript (only `aitools-alerts run --json` and `plan` were attempted). R: snapshot commit message (dangling review snapshot, never on a branch; same rebuttal as A2, A4, A5).
passes: spec+plan 1. Medium rung: no spec/plan delta; the whole-branch code pass reviews the fixed spec and plan with the code.

## Chunks
- [ ] chunk 1 — skills, snippet, hook, templates, tests, README

## Notes
- kata search "session-start hook skill aitools": 0 hits. capability-search session-start hook launchd template: 0 hits in 1300 files.
- Tests and files were written while the spec/plan pass ran (it reads a frozen snapshot), as A5 did; the plan's failing-test step therefore ran together with the files.
- Acceptance (pre-review text): /private/tmp/claude-501/-Users-joi-repos--worktrees-83xn-a6-skills-hooks-and-schedule-templates/6bf5f55d-6546-44dc-9302-2e09a682020a/scratchpad/accept/setup.sh then session.sh. Result: hook_response stdout was the one AITOOLS-ALERT line; the model invoked the skill, ran `aitools-alerts run --json` (exit 2, relay-bot critical AITA-FIXTURE-0001), `aitools-alerts plan be9546b2…`, showed `npm install -g @anthropic-ai/claude-code@99.0.0` under prepare (ask first) and asked; no other tool call was attempted. Session 75f2a737-021e-48de-a01a-43844447d295. Re-run on the final head below.
- Hermes frontmatter: `grep -rl prerequisites --include=SKILL.md` over /path/to/repos/cell-fleet and /path/to/repos/amplifier-bundle-joi: 0 hits; over /path/to/repos: three nanoclaw skills (name/description only, not the Hermes shape); no local Hermes `optional-skills` tree. Shape taken from the Hermes Agent optional-skill convention (name, description, version, author, license, platforms, prerequisites.commands, metadata.hermes.tags) as the brief and plan list it; no file copied.
