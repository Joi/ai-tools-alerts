# Wire format: where new signed data may go

Readers already installed cannot be changed. This file says what each released reader (v0.1.4 to v0.1.7) does with a field it does not know, and where the self-correcting design (ai-tools-alerts#h29n) therefore puts what it adds. `tests/test_wire_compat.py` unpacks each release from its tag and runs it against a feed built to these rules. The promise it checks: every alert is still shown on a released reader, at the level the current reader shows or a higher one, to the member whose machine it matches. One exception, which no wire format causes and the same test states: a relay-bot thread a curator lowered, narrowed or retracted (see "A curator's reply to a relay-bot thread").

## What released readers do

| Where a new field goes | v0.1.4 to v0.1.7 |
|---|---|
| A new key in the `aitools-alert` block of a root | The root is never an advisory. No error is shown |
| A new key in a reply's block | The reply is skipped. v0.1.7 still joins its `products`, `actions` and `sources` |
| A relay-bot reply that lowers `level` or sets `expires_at` | The reply is skipped, with the same v0.1.7 exception. "Lowers" is judged against the level that reader holds |
| A finite `expires_at` in a root's block | The alert is no longer shown after that time. No relay-bot reply can move it |
| A new key in the manifest's content, or a second tag on its event | The manifest is refused and the pull fails |
| A new key in the checkpoint key certificate's content | Ignored by v0.1.6 and v0.1.7. v0.1.4 and v0.1.5 do not read the certificate |
| A new tag on an alert event (not `h`, not `e`) | Ignored. Tags are signed and stored |

So the block (`spec/advisory.schema.json`) and the manifest are frozen: a test holds the schema to the v0.1.4 file. New signed data goes in an event tag, or in the certificate when the trust root must say it.

## The claim

The signed statement of what an alert's state rests on travels in one tag on the event whose state it describes (a root, a level change, a renewal):

    ["claim", "<JSON object text>"]

- At most one `claim` tag on an event, of exactly two elements.
- The value is a JSON object, at most 2048 bytes of UTF-8, with no duplicate key and no `NaN` or `Infinity`.
- `aitools_alerts.wire.claim_tag(obj)` writes it (sorted keys, no spaces); `wire.claim_of(event)` reads it and returns None for anything else.

What the object holds, its canonical form and its test vectors are defined with the level function (ai-tools-alerts#s6mt). A reader never refuses an event because of its claim tag: an event with a claim the reader cannot use is read as an event with none.

## Level changes and expiry

1. **Every lowering by the relay bot is a level-only reply:** its block is exactly `{"level": "<level>"}` (`poster.compose.level_post`). Released readers skip it and keep the higher level. Nothing else is in it to lose.
2. **On a thread that has had a lowering, every later level change is a level-only reply too.** A released reader still holds the higher level, so a raise from notice to high is a lowering to it, and it would skip a fix sent in the same reply. On a thread never lowered, a raise may share a reply. The poster knows which threads it lowered; it passes `lowered=True` to `compose.reply_post`, which then refuses any level change.
3. **A relay-bot block sets no expiry.** A root's block has `"expires_at": null` (the schema requires the key); a reply's block leaves the key out. Expiry is computed from the claim by readers that know it.

## How this reader computes expiry

From the release after 0.1.7 (ai-tools-alerts#r0ra). Released readers do none of this: to them a relay-bot alert never expires.

- A relay-bot root's `expires_at` is not read. A curator's is: it ends the thread.
- A **renewal** is a relay-bot event of the thread, the root or any reply, whose claim is well formed (`ruleset.parse_claim`), names a level (not `none`) and one of the thread's ids, and has `checked_at` no later than the event's `created_at`. Its text does not matter: an event whose only news is its claim tag is a renewal.
- A thread can decay only when its **root** carries a renewal. A relay-bot thread whose root has no claim never expires, whatever its replies carry: a reply must not be able to end an alert. An id or alias the thread has held keeps counting after a patch drops it.
- One renewal keeps the thread's level standing until `max(confirmed_at + TTL, min(checked_at + TTL, confirmed_at + 45 days))`, with the TTL of `spec/ruleset.json` for the level the reader shows. A check that could not confirm leaves `confirmed_at` as it was and moves `checked_at`. The longest renewal counts; a shorter one changes nothing. When the level no longer stands, the thread shows at the highest lower level that still stands by the same formula (critical 14 days, then high to day 30, then notice to day 90), and then it is gone. A relay-bot reply whose block names a level counts as a renewal of its own date, with or without a claim, so raising a thread never shortens what it shows.
- The clock is the `created_at` of the newest checkpoint the reader has accepted, never the machine's clock. A thread decays only under a checkpoint that lists its root. With a frozen mirror the checkpoint stops, so nothing expires and the reader says the feed is stale.
- While any renewal of a thread is on an event dated after the checkpoint, the thread is not judged and keeps its level; the next checkpoint judges it with every renewal counted. The poster's checkpoint is dated at the start of its run and lists the posts of that run, so such an event is not refused, and a raise posted in that run shows at once.
- A thread a curator posted does not decay. A relay-bot thread a curator amended does not decay while the curator's hold is in force (next section).

## A curator's reply to a relay-bot thread

From 0.2.0 (ai-tools-alerts#c1g2). No event differs; only what a reader does with it.

- Released readers take a curator's `retract`, `level:` line or block as final, and read every later relay-bot reply to that thread as discussion.
- This reader holds it for 14 days from the reply's `created_at`, judged by the checkpoint's time under a checkpoint that lists the root. A curator's later action renews the hold; `curator renew` signs the held action again. After the hold the thread is its widest state: every reply, the curator's too, applied under the relay bot's rules.
- During a hold a relay-bot reply that names a level above the held one raises it at once. Its other changes show after the hold.
- The member's source check can refuse a curator's lowering or retraction (the source supports more) and can keep a lowering past the hold (the source gives exactly that level, and the level is not below the ruleset's `reading_cap`).
- So on such a thread, after the hold, a released reader can show a lower level than this reader, or nothing where this reader shows the alert. That is the exception to the promise above. The curator role is unused on the feed; the next manifest names no curator.

A relay-bot level-only lowering (rule 1 above) is no longer only skipped by this reader: it is kept as the thread's published level and applied when the member's own source check gives exactly that level, read no more than two days ago. Without that the reader keeps the higher level, as a released reader does.

A released reader that has refused a lowering shows the alert at its earlier, higher level for as long as the thread lasts. That is intended: the reader cannot check the lowering, and too high is the safe side.

A narrowing of `products` is not covered here. v0.1.4 to v0.1.6 apply any relay-bot `products` list whole; v0.1.7 and later join it to what the thread held. That is true of the replies the poster sends today.

## `min_cli`

The trust root can name the oldest release that reads the feed in full. It is an optional key in the content of the checkpoint key certificate (`trust/checkpoint-key.json`): `"min_cli": "0.2.0"`, three dotted numbers. A CLI older than it prints one `upgrade:` line after every command that reads the feed (`pull`, `check`, `notify`, `plan`, `run`), once it holds the certificate, and goes on working; nothing is refused or hidden because of it. The 0.1.7 release and earlier ignore the key.

It is not in the manifest because a released reader refuses a manifest with a key it does not know. The same holds for anything else the root must pin: the certificate, not the manifest.

## The ruleset pin

The trust root can pin the ruleset a reader judges with (ai-tools-alerts#ed7n). It is an optional key in the content of the checkpoint key certificate, beside `min_cli`:

    "ruleset": {"version": 3, "sha256": "<64 lowercase hex>", "min_version": 3}

`version` and `sha256` are the version and the digest of the pinned ruleset (`spec/ruleset.json` over `spec/scope.json`, `ruleset.load().digest`). `min_version` is the oldest ruleset version a reader may judge with, and the oldest a claim may name; `1 <= min_version <= version`. The object has exactly these three keys. `"ruleset": null` and no key both mean no pin. Any other value that is standard JSON is a pin this reader cannot read (a certificate whose content is not standard JSON, with `NaN`, a duplicate key or an integer past the reader's digit limit, is no certificate at all): the certificate is still accepted, and the reader counts as out of date, because the root pinned something and it cannot tell what. It is not a reason to refuse the certificate: a reader that holds an older certificate would go on with that one and no pin. So a later form of the pin may add keys; a reader that does not know them stops judging until it is upgraded. The signing script signs only the three-key form.

A reader is **out of date** when its own ruleset version is below `min_version`, or equals `version` with another digest (`ruleset.outdated`), or when it cannot read the pin. A reader between `min_version` and `version`, or above `version`, is not. An out-of-date CLI prints one `out of date:` line on stderr after every command that reads the feed and judges no level: it reads no primary source and prints no source check result, gives `source_check: null`, and applies no computed expiry, so a relay-bot thread shows at the level its events give. It hides nothing, refuses nothing, and notifies as before; a level kept higher is the only way an exit status differs from a current CLI's. `run --json` carries `ruleset_outdated`: null, or `{"have", "pinned", "min_version"}`, the last two null for a pin it cannot read (`have` is null only when the reader's own ruleset files are damaged).

The 0.1.8 release and earlier ignore the key (v0.1.4 and v0.1.5 never read the certificate). Like `min_cli`, the pin lasts only as long as the certificate that carries it: the next certificate must name it again.

## `catalog.json`

A new file on the mirror, which no released reader fetches. Its events are relay posts in the catalog channel named by `spec/catalog-channel.json`, bound to that id alone; no catalog event is ever served in `feed.json` or `critical.json` (v0.1.4 and v0.1.5 would show it as an alert) or listed in a checkpoint (v0.1.6 and v0.1.7 would refuse the pull). Each is a root carrying one advisory's whole block for one product; the newest root per advisory id and product is current, and an alert thread for the same advisory and product governs over it. Since old readers never see it, the catalog entry's own format may change with the CLI that reads it (ai-tools-alerts#8nb4).

## Adding to the format

Put a new signed thing where the table says released readers ignore it. Add it to the feed in `tests/test_wire_compat.py` first, and add the newly released tag to `RELEASED` there at each release.
