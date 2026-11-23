# The self-correcting wire format: what released readers accept (ai-tools-alerts#t8jr)

Finding D12 of the design review on ai-tools-alerts#h29n; rule 9 of its revised design.

## Problem

The self-correcting design (ai-tools-alerts#h29n) adds three things to the feed: a signed claim beside each alert state (`{id, source, fields, ruleset, level, confirmed_at, checked_at}`), lowerings posted by the relay bot, and a minimum CLI version pinned by the trust root. The v2 design on ai-tools-alerts#9mx8 says "Version 0.1.x readers ignore unknown fields". They do not. Read and run against tags v0.1.4 to v0.1.7:

| Where a new field goes | What every released reader does |
|---|---|
| A new key in the `aitools-alert` block of a root | `schema.validate` refuses the block; the root is counted `no-block` and is never an advisory. No error, fresh heartbeat |
| A new key in a reply's block | The patch is `bad-patch` and skipped. v0.1.7 still joins its `products`, `actions` and `sources`; v0.1.4 to v0.1.6 lose every field of it |
| A relay-bot reply that lowers `level` or sets `expires_at` | The whole patch is skipped, with the same v0.1.7 exception. "Lowers" is judged against the level that reader holds, which after a refused lowering is higher than the poster's |
| A finite `expires_at` in a root's block | The alert leaves `active()` at that time on all four, and on this reader. No relay-bot reply can move it: a bot `expires_at` is refused |
| A relay-bot reply that replaces `products` with a narrower list | v0.1.4 to v0.1.6 apply it whole (finding D1); v0.1.7 joins. Not new: the poster sends product updates today, and the 0.1.7 changelog states the gap |
| A new key in the manifest's content, or a second tag on the manifest event | `manifest.load` refuses the manifest: "bad manifest", the pull fails |
| A new key in the checkpoint key certificate's content | v0.1.6 and v0.1.7 ignore it; v0.1.4 and v0.1.5 never read the certificate |
| A new tag on an alert event, other than `h` and `e` | Ignored by all four. Tags are signed and kept in state |

The manifest row is not in the review. The issue asks that "the manifest gains `min_cli`"; built as written, it would stop every installed CLI from pulling.

## Success criteria

1. The claim has one defined carrier outside the block, with a reader function, and a test proves the block schema is byte-identical to v0.1.4's.
2. A level change by the relay bot has one defined form that carries no other change. The poster's composer cannot emit a lowering mixed with another change. The format states when a raise must travel alone too, and that a relay-bot block sets no expiry (`expires_at` null in a root, absent from a reply).
3. One test runs each released reader (v0.1.4, v0.1.5, v0.1.6, v0.1.7, unpacked from its tag) against a feed in the new format and compares what a member is shown: the active alerts, now and thirty days on, each at the level the current reader shows or a higher one, each matching an installed copy of the product where the current reader matches it. A fix posted beside a lowering, and beside a raise that follows a lowering, still arrives. Controls show the three things the format avoids losing an alert or a fix on a released reader.
4. The root can pin `min_cli`; a CLI older than it prints one line on every command that reads state, and `run --json` carries the value. Released readers are not disturbed by the key. Tests on the current reader cover: the value is bound by the root's signature (an object that says another value does not verify); a certificate signed by another key, or issued before the one held, cannot set it; it survives a state reload and a failed pull; versions compare as numbers (0.10.0 is above 0.9.0); malformed values are refused when signed and when read; the line and the JSON key appear, once, and no exit status changes.
5. The changelog says old readers keep the higher level after a bot lowering. The v2 design's sentence and its slices 4, 8 and 10 are corrected on their issues.
6. `scripts/test-gate.sh` passes.

## Approach

### 1. The claim travels in one event tag

`["claim", "<JSON object text>"]` on the event whose state it describes: a root, a raise, a lowering, a renewal. New module `aitools_alerts/wire.py`:

- `CLAIM_TAG = "claim"`, `MAX_CLAIM_BYTES = 2048`.
- `claim_tag(obj) -> list`: the tag for a dict, serialized with sorted keys and compact separators, UTF-8; refuses a non-object, a value JSON cannot hold, and text over the limit.
- `claim_of(event) -> dict | None`: the decoded object when the event carries exactly one `claim` tag of exactly two elements whose value is an object within the limit, parsed with the strict parser (no duplicate keys, no `NaN`). Anything else is None. Never raises.

This slice fixes the carrier only. What is inside the object, its canonical form and its test vectors belong to ai-tools-alerts#s6mt; `wire` checks none of it. A claim never decides today whether an event is read: the reader ignores the tag until the member check (ai-tools-alerts#fv4g) uses it. The poster does not send a claim yet; ai-tools-alerts#ny5g wires `claim_tag` into `transport.message_event` (and must count the tag's bytes, which `signer.ENVELOPE` does not cover).

Why a tag and not a second reply event: the tag is signed with the state it describes, so there is no pair to keep together, no order between the two, and no case where the checkpoint lists one and not the other. Tags are already stored (`state.EVENT_KEYS`) and exported (`mirror/export_mirror.py` reads `tags` whole).

Assumes: the relay stores and returns a tag it does not know. The repository shows the exporter copying `tags` from the relay's database; whether the relay refuses an unknown tag at send time cannot be checked from here (no live host on this seat). A rollout issue asks for one test send before the first claim is posted.

### 2. A level change that can be refused travels alone

A level-only reply is a reply whose block is exactly `{"level": "<level>"}`: one key. The claim that justifies it rides in the tag. Three rules, in `spec/wire.md`:

1. **Every lowering is a level-only reply.** A released reader skips the reply and keeps the higher level; nothing else was in it.
2. **On a thread that has had a lowering, every later level change is a level-only reply too.** After the refused lowering a released reader holds a higher level than the poster does, so the poster's raise from notice to high is a lowering from critical to that reader, and v0.1.4 to v0.1.6 would drop a fix sent with it. Before any lowering, readers and poster agree on the level, a raise is a raise everywhere, and it may share a reply as the poster sends it today.
3. **A relay-bot block sets no expiry.** A root's block has `"expires_at": null` (the schema requires the key; a root without it is no advisory on any reader); a reply's block leaves the key out. A finite one in a root ends the alert on every released reader at that time, and no reply from the bot can renew it. The expiry of the self-correcting design is computed from the claim (`confirmed_at` plus the ruleset's time to live), by readers that know the claim (ai-tools-alerts#r0ra).

Functions:

- `wire.is_lowering(patch, level) -> bool`: the patch names a level below `level`.
- `compose.level_post(prev, level) -> str`: the level-only reply, "Level is now X." and the one-key block, for a change in either direction. Refuses an unknown level and no change.
- `compose.reply_post` refuses a patch that lowers the level (rule 1).

What code enforces and what it does not: rule 1 is enforced in the composer now. Rule 2 needs the thread's history, which the ledger does not record until the poster can lower. The composer has the hook: `reply_post(..., lowered=True)` refuses any level change. ai-tools-alerts#ny5g, which adds the lowering, records "this thread was lowered", passes the flag, and sends level changes on such a thread through `level_post`. Rule 3 is enforced in the composer: `root_post` always writes null, and `reply_post` now refuses a patch that names `expires_at` (one existing test, `test_reply_only_carries_changed_fields`, sent one; `main` never does). ai-tools-alerts#9kgk and ai-tools-alerts#r0ra, which planned a finite value, get a note. The compatibility test carries a feed that follows the three rules and a control for each rule broken, so a slice that breaks one has a failing shape to compare with. The backdated-reply case (a key holder dates a critical reply before an honest raise, so the raise reads as a lowering) needs the bot's key; readers at 0.1.6 and earlier are open to that key in simpler ways (finding D1), and 0.1.7 keeps the lists of a refused reply.

The reader does not change. Every released reader, and this one, refuses a relay-bot lowering and keeps the higher level; that is the safe direction until the member check lands (ai-tools-alerts#fv4g). A future `withdrawn` state is a level change and follows rules 1 and 2.

Narrowing is not part of this format. A relay-bot reply that narrows `products` (a fix appears for an alert that had none) is applied whole by v0.1.4 to v0.1.6 and joined by v0.1.7 and this reader; that difference exists today and no carrier can remove it from readers already installed. How a checked narrowing is carried is the member check's question; the constraint is on its issue.

### 3. `min_cli` in the certificate, not the manifest

`min_cli` is an optional key of the checkpoint key certificate's content: `"min_cli": "0.2.0"`, three dotted numbers. The certificate is signed by the root, readers already store the newest one and refuse an older one (`cert_order`), and released readers tolerate the key (the certificate row above).

- `checkpoint.Cert` gains `min_cli: str | None`; `_parse_cert` reads it and refuses a malformed value (the root signed it; a certificate this reader cannot read exactly is not used); `build_cert(..., min_cli=None)`.
- `scripts/sign-checkpoint-key.py --min-cli X.Y.Z`. Checked before the root key is read.
- `cli`: after `pull`, `check`, `notify`, `plan` and `run`, when the stored certificate of the current root names a `min_cli` above `__version__`, one stderr line: `upgrade: this aitools-alerts is 0.1.7; the feed needs 0.2.0 or later. Newer alerts may be missing or shown at an older level here. See the README to upgrade.` `run --json` gains `"min_cli"` (the value, or null). Nothing is blocked: an old CLI keeps showing what it can read.

No certificate carrying `min_cli` is signed in this change. Signing needs the root key and a person; the value is only needed when a release must be required. Readers at 0.1.7 and earlier can never print the line: they do not have the code. The line helps from the next release on.

### 4. The compatibility test

`tests/test_wire_compat.py`, using `mirror_helpers.released_reader` (already mandatory: a clone without the tag fails). One feed, dated at the real clock (v0.1.6 refuses events dated ahead), with: a root carrying a claim; a raise with a claim and a fix on a thread never lowered; a bot critical with a level-only lowering, then a level-only raise, then a fix in a reply of its own; a curator root; a certificate carrying `min_cli`; `expires_at` null in every bot root and absent from every bot reply.

What is compared is what a member is shown, computed by a short script run inside the released tree: `pull.active(pull.advisories(state), at)` at the clock and thirty days on, and for each active thread its level, its fixed versions and whether `check.match` matches it against an installed Claude Code 2.0.0. For each of the four tags: the pull succeeds (a checked pull on v0.1.6 and v0.1.7, so the certificate with `min_cli` was accepted); the same alerts are active at both times; each level is the current reader's or higher; each matches the installation; the fix arrived.

Controls, each the feed breaking one rule: a root with a new block key is absent on a released reader; a reply that lowers and fixes loses the fix on v0.1.4; so does a raise-with-fix after a lowering; a bot root with a finite `expires_at` and a renewal reply is gone thirty days on, on all four and on this reader; a manifest with `min_cli` in its content fails the pull.

`released_reader` gains a way to run a short script in the released tree; `Mirror` gains a `min_cli` argument on `publish_cert` and a method writing its files to a directory; `mirror_now` builds a mirror dated at the real clock.

Four existing tests in `tests/poster/test_compose.py` build a reply text with `reply_post(adv, c, {"level": "high"})` on a critical (`_all_text`, `test_rule_inputs_never_reach_post_text`, `test_reply_is_held_to_root_publication_rules`, `test_synthetic_digest_and_reply_keep_one_mark`). Each wants any reply text, or the unverified line on a level change: they move to a raise (a high thread raised to critical), keep their assertions, and where the text of a lowering mattered also check `level_post`. One adds the refusal itself.

## Alternatives considered

- **`min_cli` in the manifest, as the issue says.** Breaks every released reader (the manifest row). Rejected.
- **`min_cli` in the checkpoint.** Tolerated by v0.1.6 and v0.1.7 too, but the checkpoint key is online on the poster machine; a stolen checkpoint key could then tell every member to upgrade. The root should say it.
- **A new root-signed file.** A second document to fetch, order and store, for one string. The certificate already has all three.
- **The claim as a separate reply event.** Two events per state, with ordering and completeness cases, for no gain over a tag.
- **Every level change alone, from now, raises included.** The simplest rule to state. It means splitting the poster's raise-with-fix reply into two journal items per channel, with their ledger keys and Japanese replies, in `poster/main.py`; the split is needed only once a thread has been lowered, which no thread can be until ai-tools-alerts#ny5g. That slice touches the same code and owns the thread's lowered state.
- **A lowering as a first line `level: notice` with no block,** the curator's convention. Old readers ignore it without counting it, which is also safe; but the block is where every other machine-read change is, and a one-key block parses with the code that exists.
- **Vendoring the v0.1.4 tree as a fixture.** About 5,000 lines in the repository and the public scan; the tag is already required by an existing test.
- **Changing the reader to apply a bot lowering.** Out of scope: that is the member check, ai-tools-alerts#fv4g.

## Blast radius and rollback

Added: one module, one composer function, one optional certificate key, one CLI line, one JSON key in `run --json`. No event, block, manifest or state format changes; the poster sends nothing new. `reply_post` newly refuses a lowering, which the poster never composes today (`main` adds `level` to a reply only when it rises). Reverting the commit removes all of it; a certificate signed with `min_cli` meanwhile stays valid for a reverted reader, which ignores the key as v0.1.7 does.

The session-start hook reads `run --json`; a new key there is additive for the hook the repository ships (it reads named keys).

## Open questions

None blocking. For the siblings, posted as notes on their issues: the size limit of the claim (s6mt), the envelope bytes and rule 2 (ny5g), no expiry in a bot block (9kgk, r0ra), `ruleset` in the certificate (s6mt), a checkpoint that lists catalog-channel events fails every v0.1.6 pull as "mirror incomplete" (ai-tools-alerts#q03f), a `package` key on a product drops the root on released readers (ai-tools-alerts#wa6n, ai-tools-alerts#0xq6).
