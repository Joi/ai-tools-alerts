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

What the object holds, its canonical form and its test vectors are defined with the level function (ai-tools-alerts#s6mt).

What the poster sends (ai-tools-alerts#hh5s):

- **A level change carries a claim**: a raise that shares a reply, and every level-only reply. It is built from the readings the change rested on in that run (`poster.rules.claim_text`): of those whose id is one the thread has stated in every one of its channels (its first id always; an alias when no reply reached one channel and not another), the one the ruleset gives the highest level for the product, the first id's on a tie. `confirmed_at` and `checked_at` are the time of the run that read the source; the event is dated when it is sent, at or after that.
- A level change that no reading states carries none: a lowering that rests only on a CVE's absence from KEV, a level that rests on a reading of prose. A claim whose level is `none` (the source withdrew the advisory) is sent; it is no renewal.
- A claim larger than 2048 bytes is not sent, and nothing is left out of it to make it fit: the event goes out with no claim tag. Readers 0.1.8 to 0.2.1 read a longer tag as no claim, so a larger limit would reach none of them.
- **A root carries its claim** (ai-tools-alerts#gtw9, `poster.main.ROOT_CLAIMS`), built the same way from the readings of the run that posts it, among the ids the root states. A thread whose root carries one decays on readers 0.1.8 and later unless it is renewed (next section), so the poster renews it. A root with no reading, or whose claim would pass 2048 bytes, carries none: that thread never expires, and neither does any thread posted before this change. A copy of a root in another channel carries a claim only when the thread's first root does.
- **A renewal** is a reply whose only news is its claim tag: the line `Sources checked. No change to this alert.`, no block. The poster sends one in each channel of a thread whose first root carries a claim when the thread's remaining life on a reader (next section) is down to half its level's TTL: a critical every 7 days, a high every 15, a notice every 45. When that run's read of the source states the level again, `confirmed_at` and `checked_at` are the run's time. When the read failed or was not made, `confirmed_at` is that of the last confirming read and `checked_at` is the run's time; such a renewal is sent only while it adds life, which it stops doing 45 days after the confirmation. A renewal names an id the first root stated, never an alias a later reply brought, so a reader that holds the root and the renewal counts it.
- **The step down.** A level that no read has confirmed for 45 days, less one day so that the reply is on the feed before readers reach the ceiling, is lowered one step by a level-only reply (rule 1 below) whose line gives the reason: `Level is now high. No source has confirmed the higher level for 44 days.` Its claim keeps the old `confirmed_at`. The reply's own date is what renews the new level on a reader (next section), so the next step comes when that level's TTL from the step runs out; at notice nothing more is sent, and the thread leaves readers 90 days later unless a source confirms it again.
- A reply with no level change that is not a renewal, a Japanese reply, a digest and a catalog root carry none.

The poster's checkpoint never lists a thread's root without the renewals that keep it standing (`poster.signer`): before signing it reads its own verified copy of the mirror as a reader would (`signer.lapsed`), and a claimed root whose renewals no longer hold the level the bot last named above notice is left out of the checkpoint, as is the thread of a renewal the mirror stopped serving, and a reader keeps a thread its checkpoint does not list at the level its events give.

A reader never refuses an event because of its claim tag: an event with a claim the reader cannot use is read as an event with none.

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

A relay-bot level-only lowering (rule 1 above) is no longer only skipped by this reader: it is kept as the thread's published level and applied when the member's own source check, read no more than two days ago, gives no more than that level. Below the ruleset's `reading_cap` that also needs every higher level the thread stated (the root, and each reply that names a level) to carry a claim whose id is the thread's first id and whose fields this reader's ruleset computes that level from (ai-tools-alerts#tavj, `verify.claimed`). A lowering the check cannot settle applies once checkpoints 72 hours apart have listed its reply; the reply's own date is not read. A lowering the check refuses does not apply. Until one of these the reader keeps the higher level, as a released reader does, so a released reader never shows less than this one.

A released reader that has refused a lowering shows the alert at its earlier, higher level for as long as the thread lasts. That is intended: the reader cannot check the lowering, and too high is the safe side.

A narrowing of `products` travels in the block, as the poster has always sent it: a relay-bot reply whose `products` list does not stand for every entry the thread holds (a shorter range, a lower or a first `fixed`, a product left out). Nothing is added to the wire for it.

- v0.1.4 to v0.1.6 apply any relay-bot `products` list whole, at once and unchecked. Nothing on the feed reaches those readers to say so: they do not read `min_cli`.
- v0.1.7 to v0.2.1 join the list to what the thread held and keep the wider entry for the life of the thread.
- This reader joins it too, and keeps the list as the thread's published narrowing (ai-tools-alerts#swfe). The member's own source check compares it with the version ranges and first patched versions the GitHub advisory states for the product. Confirmed (every range the advisory states is stated by an entry in each ecosystem the thread holds for the product, every new entry states one of them, and `fixed` is absent or exactly the advisory's first patched version): the thread shows the published list. Contradicted: it does not, and the list is remembered as refused by the entries it holds, so sending it again, reordered or respelled, changes nothing: after one refusal no other list of that thread applies unchecked until whole reads of the sources do not contradict it. Not settled (the source cannot be read, states no versions, or `verify = "off"`): it applies once checkpoints 72 hours apart have listed its reply. Until one of these the reader shows the wider entry, as a released reader does.

So after a narrowing applies here, a released reader shows more than this one: the wider entry. It never shows less. Only `products` are narrowed; actions and sources stay joined.

## `min_cli`

The trust root can name the oldest release that reads the feed in full. It is an optional key in the content of the checkpoint key certificate (`trust/checkpoint-key.json`): `"min_cli": "0.2.0"`, three dotted numbers. A CLI older than it prints one `upgrade:` line after every command that reads the feed (`pull`, `check`, `notify`, `plan`, `run`), once it holds the certificate, and goes on working; nothing is refused or hidden because of it. The 0.1.7 release and earlier ignore the key.

It is not in the manifest because a released reader refuses a manifest with a key it does not know. The same holds for anything else the root must pin: the certificate, not the manifest.

## The ruleset pin

The trust root can pin the ruleset a reader judges with (ai-tools-alerts#ed7n). It is an optional key in the content of the checkpoint key certificate, beside `min_cli`:

    "ruleset": {"version": 3, "sha256": "<64 lowercase hex>", "min_version": 3}

`version` and `sha256` are the version and the digest of the pinned ruleset (`spec/ruleset.json` over `spec/scope.json`, `ruleset.load().digest`). `min_version` is the oldest ruleset version a reader may judge with, and the oldest a claim may name; `1 <= min_version <= version`. The object has exactly these three keys. `"ruleset": null` and no key both mean no pin. Any other value that is standard JSON is a pin this reader cannot read (a certificate whose content is not standard JSON, with `NaN`, a duplicate key or an integer past the reader's digit limit, is no certificate at all): the certificate is still accepted, and the reader counts as out of date, because the root pinned something and it cannot tell what. It is not a reason to refuse the certificate: a reader that holds an older certificate would go on with that one and no pin. So a later form of the pin may add keys; a reader that does not know them stops judging until it is upgraded. The signing script signs only the three-key form.

A reader is **out of date** when its own ruleset version is below `min_version`, or equals `version` with another digest (`ruleset.outdated`), or when it cannot read the pin. A reader between `min_version` and `version`, or above `version`, is not. An out-of-date CLI prints one `out of date:` line on stderr after every command that reads the feed and judges no level: it reads no primary source and prints no source check result, gives `source_check: null`, and applies no computed expiry, so a relay-bot thread shows at the level its events give. It hides nothing and refuses nothing. It applies no relay-bot lowering unchecked. Every relay-bot critical is unverified to it, so at most two from one poster key interrupt in 24 hours and the rest are held and listed (ai-tools-alerts#tavj); beyond that, a level kept higher is the only way an exit status differs from a current CLI's. `run --json` carries `ruleset_outdated`: null, or `{"have", "pinned", "min_version"}`, the last two null for a pin it cannot read (`have` is null only when the reader's own ruleset files are damaged).

The 0.1.8 release and earlier ignore the key (v0.1.4 and v0.1.5 never read the certificate). Like `min_cli`, the pin lasts only as long as the certificate that carries it: the next certificate must name it again.

## `catalog.json`

A new file on the mirror, which no released reader fetches. Its events are relay posts in the catalog channel named by `spec/catalog-channel.json`, bound to that id alone; no catalog event is ever served in `feed.json` or `critical.json` (v0.1.4 and v0.1.5 would show it as an alert) or listed in a checkpoint (v0.1.6 and v0.1.7 would refuse the pull). Each is a root carrying one advisory's whole block for one product; the newest root per advisory id and product is current, and an alert thread for the same advisory and product governs over it. Since old readers never see it, the catalog entry's own format may change with the CLI that reads it (ai-tools-alerts#8nb4).

## Adding to the format

Put a new signed thing where the table says released readers ignore it. Add it to the feed in `tests/test_wire_compat.py` first, and add the newly released tag to `RELEASED` there at each release.
