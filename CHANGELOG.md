# Changelog

## 0.1.0 — 2026-11-06

First release, tagged `v0.1.0`. Install it with
`pipx install git+https://github.com/Joi/ai-tools-alerts@v0.1.0`.

- `aitools-alerts`: verifies each alert's signature against the trust
  manifest, matches it against what is installed, and prepares the fix
  (`init`, `run`, `keygen`, the curator subcommand); English and Japanese.
- `aitools-alerts-poster`: composes and posts advisories to the relay.
- `mirror/export_mirror.py`: the signed static mirror at
  `https://buzz.ai-tools.md/alerts/` (JSON, Atom in two languages, an index
  page, the manifest, and `root.pub`).
- Trust root `afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4`,
  also in `trust/root.pub` and at `https://buzz.ai-tools.md/alerts/root.pub`.
