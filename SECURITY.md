# Security policy

Report a vulnerability privately through GitHub's private vulnerability reporting: https://github.com/Joi/ai-tools-alerts/security/advisories/new. Do not open a public issue or pull request for it, and do not post it in the Buzz channels.

In scope: the `aitools-alerts` CLI and its signature checks, the trust root and the trust manifest (`trust/`), the schema (`spec/`), the poster (`aitools_alerts/poster/`), the relay VM pieces (`ops/vm/`), the session-start hook, the skills and the snippets, the mirror exporter, and the install instructions in `README.md`. The instructions count as code: an agent runs them.

Out of scope: the Buzz relay itself, and advisories about third-party tools that this service relays. Report those to their vendors.

A report gets a reply on the advisory. Fixes ship as a new signed release tag; the README then pins that tag and its commit.
