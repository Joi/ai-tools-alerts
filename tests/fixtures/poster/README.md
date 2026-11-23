# Poster fixtures

`live-feed-2026-11-07-to-11.json`: ten signed relay-bot events copied verbatim
from the public feed (https://buzz.ai-tools.md/alerts/feed.json, generated
2026-11-22T19:55:27Z), English posts only:

- the CVE-2026-88968 (Claude Code) thread: the root on 11-07, the fix reply two
  hours later, and the source-only reply of 11-10;
- the CVE-2026-123158 (OpenSSH) thread in `feed`: the root on 11-09 and its four
  replies, which added only sources and, once, a ledger key as an alias;
- the 11-10 and 11-11 daily digests, whose lead lines give the replay its lead
  candidates.

`tests/poster/test_live_replay.py` replays them through the poster (ai-tools-alerts#8ke5).
Leads that a digest only counted ("N unrated leads") get invented ids
(`LEAD-replayNN:<scope>`) and invented Mastodon URLs; every other value is the
live one.

`advisory-page.html`: the labelled part of a public repository security advisory
page, https://github.com/anthropics/claude-code/security/advisories/GHSA-5j29-h97v-84ch
as GitHub served it on 2026-11-23: the title, the header, the package block, the
description, the severity and the CVE ID, with scripts, images and the author link
removed. `rules.read_advisory` reads these labels; the fixture pins the markup it
depends on (ai-tools-alerts#h340).
