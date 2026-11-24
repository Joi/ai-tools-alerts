# The trust root pins the ruleset; the CLI says when its own is out of date (ai-tools-alerts#ed7n)

Finding D10 of the design review on ai-tools-alerts#h29n, rule 8 of its revised design; the second half of ai-tools-alerts#s6mt.

## Problem

A member's CLI computes levels with the ruleset it was installed with (`spec/ruleset.json` over `spec/scope.json`, one SHA-256 digest, `ruleset.load().digest`). Three things in the CLI rest on it today: the source check (`verify`), which says whether a primary source supports a posted level; the computed expiry (`pull.active`, which lowers and ends a relay-bot thread by the ruleset's TTL table); and, once ai-tools-alerts#tavj lands, accepting a relay-bot lowering. A CLI with an old ruleset judges by rules the service has replaced, and nothing tells the member or the CLI.

ai-tools-alerts#s6mt built the check for it: `ruleset.parse_pin` reads `{version, sha256, min_version}` and `ruleset.check_claim(claim, product, pin=...)` returns `outdated` when the reader's ruleset is below the pin's `min_version`, or is the pinned version with another digest. The pin is still a value a caller passes in. Nothing signed carries one and no caller passes one.

The issue's body puts the pin in the manifest. Its first comment (a `notice:`) moves it to the checkpoint key certificate, because ai-tools-alerts#t8jr showed that every released reader refuses a manifest with a content key it does not know, while v0.1.6 and v0.1.7 ignore unknown content keys of the certificate and v0.1.4 and v0.1.5 never read it. The comment wins: this spec builds the certificate form. The body's "order of release" paragraph and its rollout issue for a manifest no longer apply; what remains of the rollout is signing a certificate that carries the pin.

## Success criteria

1. A certificate whose content has a valid `ruleset: {version, sha256, min_version}` loads, verifies under the root, and `Cert.ruleset` is that pin. A certificate without the key, or with `"ruleset": null`, has no pin and behaves as today. A certificate with a malformed pin is refused when read and when built.
2. The pin is bound by the root's signature: a `Cert` object that states another pin, or none, than its event does not verify.
3. `scripts/sign-checkpoint-key.py --ruleset-min-version N` writes the pin with `version` and `sha256` taken from the checkout's own ruleset. It refuses `N` below 1 or above that version before the root key is read. Without the option no pin is written, and the script warns when the certificate it replaces had one.
4. On every command that reads the feed, the CLI prints one `out of date:` line on stderr when its own ruleset is below the pin's `min_version`, or is the pinned version with another digest, and not otherwise. `run --json` carries the same fact in the key `ruleset_outdated` (null when not out of date).
5. While out of date the CLI judges no level: it reads no source, prints no `source check:` line, gives `source_check: null` in JSON, and applies no computed expiry (a relay-bot thread keeps the level its events give). Matches, notifications and exit statuses are as before.
6. The released readers v0.1.6 and v0.1.7 pull a mirror whose certificate carries a pin, and show what they showed before (one more case in `tests/test_wire_compat.py`; the shared feed there carries a pin too).
7. The changelog states what the released readers do with the key, and that no certificate carries it yet.
8. `scripts/test-gate.sh` passes. The change is under about 600 lines.

## Approach

### One definition of "out of date"

`ruleset.outdated(pin, rs=None) -> bool`: `rs.version < pin.min_version or (rs.version == pin.version and rs.digest != pin.sha256)`. `check_claim` calls it in place of its inline condition, so the CLI's line and the claim check cannot disagree.

A reader above the pinned version is not out of date: a release may ship a ruleset before the root pins it. A reader between `min_version` and the pinned version is not out of date either; that is what `min_version` is for.

### The certificate

`checkpoint._parse_cert` reads the optional content key `ruleset`. Absent or null: no pin. Otherwise `ruleset.parse_pin`, whose `RulesetError` becomes `CheckpointError("certificate: ruleset: ...")`. `Cert` gains `ruleset: Pin | None = None`; the tuple `verify_cert` compares gains it. `build_cert` takes `ruleset_pin: Pin | None = None` and writes the key only when given, as an object with exactly the three keys. `checkpoint` imports `ruleset`; `ruleset` imports only `schema`, so there is no cycle.

`parse_pin` accepts exactly three keys. A later pin with a fourth key is therefore a malformed pin to this release: the certificate is refused and the pull is unverified. That is the fail-closed reading the certificate's `v` already has, and the acceptance asks for it ("one with a malformed pin is refused"). A later format that needs more than three keys adds a new content key beside `ruleset`, not a key inside it. `spec/wire.md` says so.

### The signing script

`--ruleset-min-version N` (an integer). The pin is `Pin(rs.version, rs.digest, N)` with `rs = ruleset.load()` of the checkout the script runs from. `N < 1` or `N > rs.version` is refused by argparse or `_die` before `read_root_secret`. Without the option no pin is signed: signing a pin is a decision about every member's CLI (a CLI at the pinned version whose scope file differs prints the line), so it is never a default. As with `min_cli`, the script warns on stderr when the certificate being replaced named a pin and this run names none, and also when the new pin's `version` or `min_version` is lower than the old one's. Neither is refused: the root may need to take a ruleset back.

### The CLI

`cli._ruleset_outdated(a, st) -> dict | None` reads the pin from the stored certificate of the current root (`st.cert_for(a.root)`, the same source as `_min_cli`; its signature was checked by `State.load`; expired or not, it is the root's newest word). It returns `{"have": rs.version, "pinned": pin.version, "min_version": pin.min_version}` when `ruleset.outdated(pin)`, else None. No certificate, no pin, or a ruleset that cannot be loaded: None (a damaged package is reported by the command itself).

`OUTDATED_LINE`, printed to stderr in the same `finally` of `main` as the upgrade line, on every command that reads the feed:

    aitools-alerts: out of date: this aitools-alerts has ruleset {have}; the trust root pins ruleset {pinned} (oldest accepted: {min_version}). It judges no level until it is upgraded: no source check, no computed expiry. See the README to upgrade.

`run --json` gains `"ruleset_outdated"`: that object, or null. `check --json` prints a list of matches and stays a list; the line on stderr is how `check` carries it. (The issue says "`check` and `run --json` carry it"; a new top-level key cannot be added to a list without breaking every consumer.)

While out of date:

- `_cache` returns None, so no results file is read, and `_source_lines` prints nothing (it returns on a None cache). `_source_check` returns before any request. `cmd_verify` prints `source check: not run (this aitools-alerts is out of date)`.
- `_check_json` has its own out-of-date branch and returns None, so `source_check` is null in `check --json` and `run --json`. A None cache alone would not do that: `verify.result_for(adv, None)` answers `{"result": "unknown", "why": "off"}` for a relay-bot product, which is what `verify = "off"` prints today and goes on printing when the CLI is not out of date.
- `_matches` calls `pull.active(..., decay=False)`. `active` gains the keyword `decay: bool = True`; with False the claim-computed expiry is skipped and a curator's `expires_at` still ends its thread. An out-of-date reader thus shows a relay-bot thread at the level its events give for as long as the thread is listed. That is the side every released reader is on (they compute no expiry), and the TTL table is part of the ruleset the pin says is wrong.

Nothing is refused or hidden because of the pin: matches, the notification of an unseen critical and the exit statuses do not change.

### Tests

- `tests/test_ruleset.py`: `outdated` over the four cases (below `min_version`; same version, other digest; same version and digest; reader above the pin), and `check_claim` still returns `outdated` through it.
- `tests/test_checkpoint.py`: the existing `test_unknown_content_keys_are_ignored` signs `"ruleset": {"n": 1}` as its example of an unknown key; `ruleset` is now a known key, so the example becomes `"later": {"n": 1}` and the assertion (unknown keys are ignored) stays. New tests: the key is optional; a pin is read and bound by the signature; malformed pins (a list, a missing key, an extra key, `min_version` above `version`, a short digest, a bool) are refused when built and when read; null reads as absent; the script signs the pin from the checkout's ruleset, refuses a bad `N` before reading the root key, and warns on a dropped or lowered pin.
- `tests/test_cli.py`: the line on every command and the JSON key when `min_version` is above the CLI's ruleset; the line when the version is the same and the digest differs; no line with no pin, a matching pin, a pin whose `min_version` the CLI meets, and under another trust root; no decay while out of date (a thread a month past its TTL keeps its level) and decay as before otherwise.
- `tests/test_verify_cli.py`: an out-of-date CLI makes no request and prints no `source check:` judgment; JSON `source_check` is null. With `verify = "off"` and no pin, or a pin the CLI meets, `source_check` is still `{"result": "unknown", "why": "off", ...}` (the existing assertion, unchanged).
- `tests/test_wire_compat.py`: the shared `feed()` certificate carries a pin this reader meets (so its month-on decay assertions still hold); one more test signs a pin far ahead (`version` 99, `min_version` 99) and shows v0.1.6 and v0.1.7 pull it checked and show the alert, while this reader reports out of date.
- `tests/mirror_helpers.py`: `publish_cert` and `mirror_now` take `ruleset_pin`.

### Documents

`spec/wire.md` gains a section on the pin beside `min_cli`. `README.md` gains the `out of date:` line beside the `upgrade:` paragraph. `CHANGELOG.md` gains an Unreleased entry and its "does not yet pin the ruleset" sentence under s6mt is brought up to date. The script's docstring describes the option.

## Alternatives considered

- **The pin in the manifest, as the issue body says.** Every released reader refuses the manifest and the pull fails for every member who has not upgraded (`tests/test_wire_compat.py`, the manifest control). Rejected by the issue's own `notice:` comment.
- **Always sign a pin, `min_version` defaulting to 1.** Every certificate renewal would then pin the digest of whatever checkout the root signed from, and a member whose scope file differs at the same version would be told to upgrade as a side effect of a renewal. Rejected: the pin is opt-in per signing.
- **Refuse to show alerts while out of date.** The design's rule is that too high is the safe side and an old CLI never goes quiet (t8jr). Rejected: the CLI keeps showing and notifying; it only stops judging.
- **Keep the computed expiry while out of date.** An old TTL table could end a true alert early, which is the unsafe direction. Rejected.
- **A looser `parse_pin` that ignores unknown keys.** s6mt landed the strict form and its tests; a key that restricts (a later "this scope version or newer") must fail closed. Kept strict.

## Blast radius and rollback

No certificate carries the key and this change signs none, so no installed CLI behaves differently until the root signs one: that step is filed as its own "rollout:" issue. With no pin, every path added here returns before doing anything (`Cert.ruleset is None`).

`State.load` parses the stored certificate with the same parser. A certificate with a malformed pin that an older release stored (it ignores the key) would make this release refuse its state file, as a malformed `min_cli` already does. `build_cert` and the signing script both refuse to produce one, so this needs a root signature made with other tooling.

Rollback is reverting the pull request. A certificate that carries a pin is ignored by v0.1.6 and v0.1.7, so the root does not have to re-sign to go back.

## Assumes

- The pin is advisory to the CLI in this slice: it turns judgment off and prints a line. Enforcing it on claims (`check_claim(..., pin=...)` at the point a lowering is accepted) is ai-tools-alerts#tavj's, which gets `cli._ruleset_outdated` and `Cert.ruleset` to pass on.
- The service runs with no human in the loop (ruling of 2026-11-23): nothing here waits for a person. The line asks the member to upgrade; the CLI keeps working if they never do.

## Open questions

None that block. Whether the hourly job should upgrade the CLI by itself when it is out of date belongs to the install path (ai-tools-alerts#mx38), not here.
