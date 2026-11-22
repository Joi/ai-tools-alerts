"""Helpers for the pull and CLI tests: an in-memory signed mirror."""

import json
from dataclasses import asdict
from pathlib import Path

from aitools_alerts import checkpoint, manifest, nostr, schema
from aitools_alerts.schema import Action, Advisory, Product, Source

FIXTURE_MIRROR = Path(__file__).parent / "fixtures" / "mirror"
FIXTURE_ROOT = json.loads((FIXTURE_MIRROR / "manifest.json").read_text())["pubkey"]
T0 = 4070908800  # 2099-01-01T00:00:00Z
SECOND = "https://second.example.invalid/trust/"  # the second origin of the tests
CHANNELS = json.loads((Path(__file__).parents[1] / "spec" / "channels.json").read_text())


def iso(ts: int) -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def advisory(**over) -> Advisory:
    base = dict(
        id="AITA-TEST-0001", aliases=[], level="critical", advisory_severity=None,
        title="Invented critical for tests",
        products=[Product("Claude Code", "claude-code", "<99.0.0", "99.0.0")],
        actions=[Action("upgrade", "Claude Code", "99.0.0")],
        sources=[Source("https://example.invalid/advisory", None)],
        posted_by="curator", posted_at=T0, expires_at=None)
    base.update(over)
    return Advisory(**base)


class Mirror:
    """Keys, a manifest, a checkpoint key certificate, two channel files and a
    checkpoint, served by ``fetch``.

    ``raw[name]`` replaces a file's bytes; ``raw[name] = None`` makes it
    missing. Unless a test stored a checkpoint (``checkpoint()``) or set
    ``raw["checkpoint.json"]``, every fetch of checkpoint.json signs a fresh
    one over everything the mirror holds: an honest mirror whose signer has
    just run. ``second`` holds the files of the second origin (``SECOND``),
    which serves nothing by default."""

    def __init__(self):
        self.root_sec, self.root = nostr.keygen()
        self.cur_sec, self.cur = nostr.keygen()
        self.bot_sec, self.bot = nostr.keygen()
        self.ck_sec, self.ck = nostr.keygen()
        self.version = 0
        self.seq = 0
        self.events = {"feed.json": [], "critical.json": []}
        self.raw: dict[str, bytes] = {}
        self.second: dict[str, bytes] = {}
        self.stored_checkpoint = None
        self.clock = T0 + 1000  # the signer's clock for automatic checkpoints: the tests' reader clock
        self.publish_manifest()

    @property
    def man(self):
        return manifest.load(json.dumps(self.manifest).encode())

    def publish_cert(self, key=None, issued=None, days=120, signer=None, man=None):
        """Sign and serve a certificate for the current manifest (or ``man``)."""
        man = man or self.man
        issued = issued if issued is not None else man.event["created_at"]
        self.cert = checkpoint.build_cert(signer or self.root_sec, man, key or self.ck, issued, issued + days * 86400)
        self.raw.pop("checkpoint-key.json", None)
        return self.cert

    def honest_ids(self, at):
        """What an honest signer lists at time ``at``: events that verify, are
        signed by a poster of the current manifest, are bound to an alert
        channel, and are not dated after the checkpoint."""
        from aitools_alerts import pull
        man, chans = self.man, frozenset(CHANNELS.values())
        return [e["id"] for evs in self.events.values() for e in evs
                if isinstance(e, dict) and nostr.verify_event(e) and manifest.role_of(man, e["pubkey"]) is not None
                and pull._bound(e, chans) and e["created_at"] <= at]

    def checkpoint(self, ids=None, seq=None, now=None, sec=None, valid_s=86400, man=None, store=True):
        """Sign a checkpoint; by default over what an honest signer lists,
        numbered one higher than the last, dated at the newest event not after
        ``self.clock`` (never before the certificate). ``store`` makes
        it the one served until the next call."""
        if now is None:  # the newest event the signer's clock has reached: never a hostile event's date
            near = [e["created_at"] for evs in self.events.values() for e in evs
                    if isinstance(e, dict) and isinstance(e.get("created_at"), int) and e["created_at"] <= self.clock]
            now = max(near + [self.cert["created_at"]])
        if ids is None:
            ids = self.honest_ids(now)
        self.seq = seq if seq is not None else self.seq + 1
        ev = checkpoint.build_checkpoint(sec or self.ck_sec, man or self.man, self.seq, ids, now, valid_s)
        if store:
            self.stored_checkpoint = ev
            self.raw.pop("checkpoint.json", None)
        return ev

    def publish_manifest(self, posters=None, version=None, issued=None, signer=None, retracted=None, cert=True):
        self.version = version if version is not None else self.version + 1
        issued = issued if issued is not None else T0 + self.version
        posters = posters if posters is not None else [
            {"pubkey": self.cur, "role": "curator", "name": "cur"},
            {"pubkey": self.bot, "role": "relay-bot", "name": "bot"}]
        content = {"version": self.version, "issued_at": iso(issued), "posters": posters}
        if retracted is not None:
            content["retracted"] = retracted
        self.manifest = nostr.sign_event(signer or self.root_sec, {
            "created_at": issued, "kind": 30078, "tags": [["d", "aitools-alerts-manifest"]],
            "content": json.dumps(content)})
        self.raw.pop("manifest.json", None)
        if cert:  # a new manifest needs a new certificate: it is bound by the manifest's event id
            try:
                self.publish_cert()
            except Exception:  # a manifest the tests made unusable on purpose
                self.cert = None
        return self.manifest

    def post(self, sec, content, created_at=T0 + 100, tags=(), files=("feed.json",), kind=9, h="auto"):
        """``h``: the channel tag. "auto" names the first file's channel unless
        ``tags`` already carries an h tag; None sends no h tag."""
        tags = [list(t) for t in tags]
        if h == "auto" and not any(t[0] == "h" for t in tags):
            h = CHANNELS[files[0].split(".")[0] if files else "feed"]
        if h not in (None, "auto"):
            tags.insert(0, ["h", h])
        ev = nostr.sign_event(sec, {"created_at": created_at, "kind": kind,
                                    "tags": tags, "content": content})
        for f in files:
            self.events[f].append(ev)
        return ev

    def root_post(self, sec, adv=None, files=("feed.json", "critical.json"), **kw):
        return self.post(sec, schema.render_post(adv or advisory(), "Body line."), files=files, **kw)

    def reply(self, sec, root_ev, text, created_at=T0 + 200):
        return self.post(sec, text, created_at=created_at, tags=[["e", root_ev["id"], "", "root"]])

    def patch_text(self, **fields) -> str:
        return f"Update.\n\n```{schema.INFO_STRING}\n{json.dumps(fields)}\n```\n"

    def body(self, name: str) -> bytes:
        if name in self.raw:
            if self.raw[name] is None:
                raise OSError(f"no such file {name}")
            return self.raw[name]
        if name == "manifest.json":
            return json.dumps(self.manifest).encode()
        if name == "checkpoint-key.json":
            if self.cert is None:
                raise OSError("no certificate")
            return json.dumps(self.cert).encode()
        if name == "checkpoint.json":
            ev = self.stored_checkpoint or self.checkpoint(store=False)
            return json.dumps(ev).encode()
        return json.dumps({"generated_at": "2099-01-01T00:00:00Z",
                           "channel": name.split(".")[0], "events": self.events[name]}).encode()

    def fetch(self, url: str) -> bytes:
        name = url.rsplit("/", 1)[1]
        if url.startswith(SECOND):
            if self.second.get(name) is None:
                raise OSError(f"second origin: no such file {name}")
            return self.second[name]
        if name not in ("manifest.json", "feed.json", "critical.json", "checkpoint-key.json", "checkpoint.json"):
            raise OSError(f"no such file {name}")
        return self.body(name)


__all__ = ["CHANNELS", "FIXTURE_MIRROR", "FIXTURE_ROOT", "SECOND", "T0", "Mirror", "advisory", "asdict"]
