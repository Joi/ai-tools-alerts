"""Helpers for the pull and CLI tests: an in-memory signed mirror."""

import json
from dataclasses import asdict
from pathlib import Path

from aitools_alerts import nostr, schema
from aitools_alerts.schema import Action, Advisory, Product, Source

FIXTURE_MIRROR = Path(__file__).parent / "fixtures" / "mirror"
FIXTURE_ROOT = json.loads((FIXTURE_MIRROR / "manifest.json").read_text())["pubkey"]
T0 = 4070908800  # 2099-01-01T00:00:00Z


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
    """Keys, a manifest and two channel files, served by ``fetch``."""

    def __init__(self):
        self.root_sec, self.root = nostr.keygen()
        self.cur_sec, self.cur = nostr.keygen()
        self.bot_sec, self.bot = nostr.keygen()
        self.version = 0
        self.events = {"feed.json": [], "critical.json": []}
        self.raw: dict[str, bytes] = {}
        self.publish_manifest()

    def publish_manifest(self, posters=None, version=None, issued=None, signer=None):
        self.version = version if version is not None else self.version + 1
        issued = issued if issued is not None else T0 + self.version
        posters = posters if posters is not None else [
            {"pubkey": self.cur, "role": "curator", "name": "cur"},
            {"pubkey": self.bot, "role": "relay-bot", "name": "bot"}]
        content = {"version": self.version, "issued_at": iso(issued), "posters": posters}
        self.manifest = nostr.sign_event(signer or self.root_sec, {
            "created_at": issued, "kind": 30078, "tags": [["d", "aitools-alerts-manifest"]],
            "content": json.dumps(content)})
        self.raw.pop("manifest.json", None)
        return self.manifest

    def post(self, sec, content, created_at=T0 + 100, tags=(), files=("feed.json",)):
        ev = nostr.sign_event(sec, {"created_at": created_at, "kind": 9,
                                    "tags": [list(t) for t in tags], "content": content})
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
            return self.raw[name]
        if name == "manifest.json":
            return json.dumps(self.manifest).encode()
        return json.dumps({"generated_at": "2099-01-01T00:00:00Z",
                           "channel": name.split(".")[0], "events": self.events[name]}).encode()

    def fetch(self, url: str) -> bytes:
        name = url.rsplit("/", 1)[1]
        if name not in ("manifest.json", "feed.json", "critical.json"):
            raise OSError(f"no such file {name}")
        return self.body(name)


__all__ = ["FIXTURE_MIRROR", "FIXTURE_ROOT", "T0", "Mirror", "advisory", "asdict"]
