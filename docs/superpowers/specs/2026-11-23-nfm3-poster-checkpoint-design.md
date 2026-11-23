# The poster signs the checkpoint; the relay VM receives and publishes it

Kata: ai-tools-alerts#nfm3, piece 4 of ai-tools-alerts#ek5q. Builds on the format (`aitools_alerts/checkpoint.py`, piece 2) and the reader (piece 3). Sources: the adversarial review of 2026-11-23, finding H2; rule 7 of the design review (comments on ai-tools-alerts#h29n); "What the checkpoint certifies, and the mirror's caps" in `docs/superpowers/specs/2026-11-23-zb8b-checkpoint-format-design.md`.

## Problem

The reader of piece 3 refuses every pull until the mirror serves a certificate and a checkpoint. Nothing produces a checkpoint yet. It must be signed on the poster machine, by a key the relay VM never holds, because the VM is the machine a checkpoint exists to distrust; and it must reach the mirror directory on that VM through the poster's one narrow ssh route.

## The three parts

### 1. Poster: sign each run (`aitools_alerts/poster/`)

Config (the poster's TOML), all optional; without `checkpoint_key_file` the poster signs nothing and says `checkpoint=off` in its summary line:

- `checkpoint_key_file`: absolute path of a file holding the checkpoint secret key (an nsec or 64 hex), on the poster machine. The poster refuses it unless it is a regular file owned by the running user with mode 600 (no group or other bits). It is opened without following a symlink and without blocking (a FIFO with no writer must not hang the run under the ledger lock), and checked on the open descriptor.
- `relay_put_wrapper`: absolute path on the relay VM of the delivery command (part 2).

`aitools-alerts-poster checkpoint-keygen --config <toml>` creates the key file at `checkpoint_key_file` (mode 600, never overwriting one) and prints only the npub, which is what `scripts/sign-checkpoint-key.py` takes.

The poster keeps one small file beside its mirror state, `<ledger>.checkpoint.json`, written whole like its other files: `{"last_seq": N, "owed": [{"id", "bytes", "since", "root"}], "hold_until": T}`. `checkpoint-keygen` creates it empty with no hold. **If it is ever missing or unreadable afterwards, the memory of what the relay acknowledged is gone**, so the poster signs nothing for 72 hours (`hold_until`, written at the next save; summary `checkpoint=held`): the time after which any debt would have been given up anyway. Starting clean instead would let whoever can delete one file on the poster machine, or a disk error, cancel a withheld post's debt. The key file and this file are part of the config's path collision check (`Config.check_paths`), so neither can be the KEV cache, the ledger or each other.

**Owed events.** Every event this poster sent and the relay acknowledged is owed until the poster has seen it in the mirror. The entry is written to the owed file **at the moment of the acknowledgement**, inside the send path, before the send journal drops the item: a run that then fails its mirror pull, or dies, has still recorded the debt. It holds the id, the size of the text sent (plus a fixed allowance for the envelope), the time, and the thread root the post replied to (none for a root). An entry leaves only when its id is in the poster's mirror state, or after 72 hours, counted in the summary as `owed_dropped=N`: a relay that truly lost a post must not stop the service for good, and by then every reader has been stale for two days. Nothing is ever dropped for lack of room: if the owed events do not fit a checkpoint, no checkpoint is signed (below). If the entry cannot be written (a full disk), the run fails as a ledger error and signs no checkpoint (`checkpoint=owed-unrecorded`); the item is still in the send journal, and the next run's replay records the debt before it signs.

At the end of every `run`, after the posts, the digest and the translations, whatever their outcome (a run whose posts failed still vouches for what exists):

1. **Pull** the mirror into the poster's own mirror state with `checkpoint=False` (the writers' pull) and fetch the mirror's `checkpoint-key.json` and `checkpoint.json`, all three inside one 120-second wall-clock bound: a mirror that drips bytes must not hold the run, and with it the ledger lock, past that. If the pull fails, no checkpoint this run (`checkpoint=no-mirror`); the owed file is already up to date.
2. **Certificate.** Among the bundled `trust/checkpoint-key.json` and the mirror's, take the newest that the root signed for the manifest the pull accepted (`pull._choose_cert`: the reader's ordering, so a renewed or re-bound certificate on the mirror is picked up without reinstalling the poster). Sign only if it is usable now (`cert_problem` is None) and names this key. Summary: `checkpoint=no-certificate`.
3. **Settle** the owed list: drop ids the poster now holds from the mirror and could list (an event the relay stamped after this run began is not listed yet, so it stays owed until the next run), and entries older than 72 hours. **Events that left the mirror:** the poster's copy of the mirror never forgets by itself, so an event the mirror stopped serving stays listed, readers refuse the mirror, and within a day they read stale: that is the detection. After 72 hours of absence the poster gives the event up (removes it from its copy; summary `gone_dropped=N`), or a post that was truly deleted on the relay would keep every reader stale for as long as the poster remembered it. If it comes back it is an event on the mirror again.
4. **Window** (`signer.window`), from the stored, verified, channel-bound events not dated after the signing time. A thread is eligible when its newest event is not older than 398 days (the reader's retention is 400 days, `pull.RETENTION_S`; the two-day margin keeps a thread from ageing out on a reader between the signing and a pull). The budget is 990 events and 2 MiB of serialized events: two consecutive checkpoints can list entirely different events and the exporter must serve both during the move from one to the next (part 3); twice the budget is inside one channel's caps (2,000 events, 4 MiB). It is spent in this order:
   - **first, what must be listed:** the owed ids; and, for every eligible thread that has a curator reply or an owed reply, its root with every curator reply. A plain root with no correction is not in the must-list (a year of daily digests alone would otherwise fill it and stop all signing); it is listed by the newest-first rule below. A thread an owed reply belongs to is eligible whatever its age (the reply, once members have it, keeps the thread inside their retention, so its root must come with every correction the poster knows). Where a thread's root and corrections are all older than the 398-day line and only other replies keep it alive, its newest event is part of the must-list too, so the reader's retention, which sees only listed events, does not drop them. A curator reply is how an alert is retracted, lowered or corrected, so no amount of other traffic, in that thread or in newer ones, can push one out. **If these do not fit, no checkpoint is signed** (`checkpoint=too-large`): readers read stale within a day, which is the truth, instead of being handed a checkpoint that silently omits a correction or an acknowledged post;
   - **then whole threads, newest first.** A thread that does not fit whole is skipped and the next is tried; its root and curator replies are already listed.
   The reader stores only what a checkpoint lists, and the released reader shows whatever is stored, so the window is also everything a new member sees.
5. **Number.** `seq` is the highest of: the signing time in seconds; one more than the last number this poster used (`last_seq`, saved before the checkpoint is sent); one more than the number of the mirror's published checkpoint when that one is signed by this key. So a number is never used twice, also for two runs in one second, and after a lost state file the published checkpoint supplies the floor even when earlier numbers had run ahead of the clock. Only a lost file together with a mirror that hides the published checkpoint can produce a repeated number, and then readers answer `conflicting checkpoint` until the clock has passed it. A clock set back makes readers answer `older checkpoint` until it has caught up, which is the correct outcome for a signer whose clock is wrong. One checkpoint key belongs to one poster with one ledger; the config comment says so.
6. **Deliver**: `ssh <relay_ssh_host> <relay_put_wrapper> checkpoint` with the event JSON on stdin (the options of `transport.send`). Outcome in the summary line: `checkpoint=sent`, `checkpoint=failed` (the next run signs a newer one; nothing is retried or queued), `checkpoint=off`.

The key is read once per run, held in memory for the signature, never logged, never passed on a command line, never sent anywhere. Nothing about it reaches the VM.

A checkpoint is valid for 24 hours and the poster runs hourly, so a poster that is down for a day makes every reader read stale. That is the intent (nobody is watching; silence must show).

**What the checkpoint does and does not vouch for.** It vouches that the listed events exist and that nothing the poster sent or has seen on the mirror is missing. It cannot vouch for a curator's post that the relay withheld from the mirror before the poster ever saw it: the poster learns of curator posts only through the mirror. Closing that needs the curator command to report its own sends to the signer, which is outside this piece and noted on ai-tools-alerts#r98k (the dedicated curator key). It also does not say the legitimate poster wrote an event signed by the bot key (ai-tools-alerts#m729).

### 2. Relay VM: one more guarded command (`ops/vm/`)

`ops/vm/mirror-put` (bash, installed as `~/bin/mirror-put` of the relay user, mode 700): `mirror-put checkpoint` reads stdin, refuses more than 256 KiB, anything that is not one JSON object with exactly the seven NIP-01 keys, and writes it atomically (temp file, rename) to `~/alerts-inbox/checkpoint.json`, mode 600, creating the directory mode 700. It verifies no signature: the exporter does, with the repository's code and the root-signed certificate. It prints one JSON line (`{"stored":true,"bytes":N}`) or one error line, like `buzz-send`.

`ops/vm/aitools-poster-shell` gains a second allowed command shape, exactly two words: `/home/<relay user>/bin/mirror-put checkpoint`. Everything else is refused as today. `ops/vm/sudoers-aitools-poster` gains that exact command. The poster's key on the VM therefore gains one ability: replacing the inbox file with other bytes, which the exporter will not publish unless the checkpoint key signed them.

### 3. Exporter: verify, then publish (`mirror/export_mirror.py`)

New options: `--checkpoint-key trust/checkpoint-key.json` (from the checkout, like the manifest) and `--inbox <dir>`; the systemd unit passes both. Without `--checkpoint-key`, or when the file is absent, the exporter behaves as before and publishes neither file.

Each run:

- **Certificate.** Loaded from the checkout; published as `checkpoint-key.json` only if it verifies under the pinned root, `cert_problem(cert, manifest, now)` is None, and it may replace the one being served (`cert_order`: a restored older deployment must not put an older certificate back). A certificate that is unusable (expired, for another manifest) is not published and the run says so in its summary; the rest of the export goes on (readers then read unverified, which is the truth).
- **Candidate checkpoint.** `<inbox>/checkpoint.json`, if it loads, verifies under the certificate, has no `checkpoint_problem`, and is not older than the one already published: `checkpoint_order` against `<out>/checkpoint.json`, which is taken as the floor whenever it is a well-formed checkpoint with a valid signature, whichever key signed it. After a key rotation the published checkpoint is the old key's and no longer verifies under the new certificate; readers still hold it and refuse a new-key checkpoint dated before it, so the exporter must too.
- **Caps honour the checkpoints.** The exact events the published checkpoint lists are kept first, whatever their thread has grown to; `cap()` then applies its thread rule to everything else within what is left. The candidate's events are kept the same way when published and candidate together fit each channel's caps (one checkpoint is at most 990 events and 2 MiB, so they normally do); when they do not, the candidate waits and the summary line says so. The signer's next checkpoint is built from the mirror as it then is.
- **Publish together.** The candidate replaces the published checkpoint only if every event it lists is in this export. Otherwise the published one stays, with its events, until a later run can serve the new one (the relay had not stored a just-sent event yet). `checkpoint.json` is written after the two event files: a reader that fetched the older checkpoint and newer events is fine; one that fetched a newer checkpoint would otherwise find its events missing.
- Summary line: `checkpoint=published seq N`, `kept seq N (candidate lists K events not exported)`, `none`, or `refused (<reason>)`.

The VM stays untrusted for integrity: it can only publish a checkpoint the poster's key signed, or hold one back, and holding back shows on every reader within the checkpoint's 24 hours.

## Success criteria

- A poster run with throwaway keys against the in-memory mirror delivers (through a fake ssh) a checkpoint that `load_checkpoint`, `verify_checkpoint` and `checkpoint_problem` accept, listing every stored event and the ids sent in the run, with `seq` equal to the run's time.
- End to end: poster run → guard → `mirror-put` → exporter → a `checkpoint=True` member pull of the exporter's output succeeds and reads verified. (The exporter's reader tests of piece 3 that used the writers' pull go back to the member pull.)
- The window: 1,200 events in 40 threads lists whole threads, newest first, within 990 events; a thread older than 398 days is never listed; an event dated after the signing time is not listed; a thread of 1,100 events is skipped, the older ones are listed, and its root and its curator retraction are listed all the same; a newer thread of 990 small bot events does not push out an older thread's curator retraction; an old root and old curator reply kept alive by recent bot replies in an oversized thread are listed with the thread's newest event, and a fresh reader of that checkpoint stays verified; owed ids and the roots they reply to are listed first; when the must-list events exceed the budget no checkpoint is signed.
- The suppression attack over several runs: the relay acknowledges a post, never exports it, and drops that run's checkpoint; the next three runs' checkpoints all list the owed id; a reader served the latest reads `mirror incomplete`; after 72 hours the id is dropped and counted. The same with the mirror pull failing in the run that sent the post, and with the run dying right after the acknowledgement: the next run's checkpoint still lists the id. A run that acknowledges 200 posts lists all 200 or signs nothing; none is forgotten.
- A renewed certificate, and a certificate for a new manifest, served by the mirror are picked up by the poster with an older bundled one in place; two runs in the same second sign different numbers; after the counter has run ahead of the clock and the state file is lost, the published checkpoint supplies the floor.
- The exporter after a key rotation refuses a new-key candidate dated before the published old-key checkpoint; a published checkpoint's root stays served when its thread grows past the exporter's cap.
- A key file that is a FIFO with no writer is refused at once; a config whose key file or owed file collides with another of the poster's files is refused before anything is written.
- Two consecutive checkpoints listing disjoint sets of 990 events: the exporter serves both sets while the second waits, then publishes it.
- A reader that applied a thread, then is served a checkpoint for which that thread grew past the budget and gained a curator retraction: the retraction is listed and applied.
- An export that crosses the event cap between two checkpoints still serves every event the published checkpoint lists, and the member pull stays complete.
- The exporter refuses: a checkpoint by another key; one for another manifest; one dated ahead; one older than the published; a certificate that does not verify, is expired, or is for another manifest. It holds a candidate back while a listed event is not exported, and publishes it on the run where it is.
- The poster refuses a key file that is group- or world-readable, not a regular file, or not a valid key; signs nothing without a usable certificate; never prints the key (asserted on captured output and on every argv the fake ssh saw).
- Guard: the new shape is accepted and reaches `mirror-put`; `mirror-put manifest`, `mirror-put checkpoint extra`, a different path, and every refusal the existing tests cover stay refused. `mirror-put` refuses oversized input, non-JSON, an array, an object with other keys; writes atomically; leaves the previous file on refusal.
- `tests/test_templates.py`-style check that the unit's ExecStart, run from a fresh export of the tree with a rows file, still writes a mirror (with and without the new files present).
- The released v0.1.4 reader pulls the exporter's output that includes both new files.

## Alternatives considered

- **Post the checkpoint as a channel message.** Rejected: an hourly machine message in a channel people read, and the relay bot's key (on the VM) would sign the carrier.
- **A stored counter alone, or the clock alone, for `seq`.** Rejected: a counter is lost with its file; the clock repeats within a second. Step 5 uses both.
- **Forget an acknowledged post after the run that sent it.** Rejected: see step 3; the relay could then drop one post and one checkpoint and be served a clean checkpoint an hour later.
- **A window as large as the exporter's cap.** Rejected: the exporter must hold two windows during a transition.
- **Let the exporter sign.** Rejected: that is the VM.
- **Retry or queue a failed delivery.** Rejected: the next hourly run supersedes it, and a queue of old checkpoints has no use.
- **Verify the signature in `mirror-put`.** Rejected: it would need the package and the certificate in a second place on the VM; the exporter verifies before anything is published, and the inbox is not served.

## Compatibility with v0.1.4 readers

They fetch three files, unchanged in shape. The exporter keeping checkpoint-listed events ahead of its caps changes only which old threads fall off first.

## Blast radius and rollback

- Poster: without the two config keys nothing changes. With them, one more ssh command per run.
- VM: a new script, one more guard shape and sudoers line; the exporter unit's command line. All installed by the rollout issue, from a verified release export as `ops/vm/README.md` requires. Rollback: reinstall the previous guard, sudoers file and unit; remove `mirror-put`.
- Exporter without `--checkpoint-key`: exactly today's behaviour.

## Rollout (for the rollout issue under ek5q; nothing here is done by this piece)

`ops/vm/README.md` installs the VM's files only from a verified release export, and members install the release the README pins. The repository's release scheme already separates the two: a signed release tag, then a later pin commit that makes members install it. That removes the circle:

1. Land the four pieces. Tag a signed release from main (the candidate). The README still pins the previous release, so no member installs it.
2. On the poster machine: install the poster from that tag's verified export, set `checkpoint_key_file` and `relay_put_wrapper` in its config, and run `aitools-alerts-poster checkpoint-keygen --config <toml>`. Until the next steps are done its runs say `checkpoint=no-certificate` and nothing else changes.
3. Sign the certificate with the root (`scripts/sign-checkpoint-key.py <npub>`) and land `trust/checkpoint-key.json` by pull request; tag again so that the VM's export contains it (the exporter reads it from the checkout).
4. From that tag's verified export: install `mirror-put`, the guard, the sudoers file and the exporter unit on the VM.
5. Confirm: the poster's summary says `checkpoint=sent`; the exporter's says `checkpoint=published`; the mirror serves `checkpoint-key.json` and `checkpoint.json`; a pull with the candidate reader reads verified; the released v0.1.4 reader still pulls.
6. Only then the pin commit that makes members install the release.

## Out of scope

- Leaving events under the bot key that the poster's ledger did not send out of the checkpoint (ai-tools-alerts#m729).
- The bot key leaving the relay VM (ai-tools-alerts#vzc3).
