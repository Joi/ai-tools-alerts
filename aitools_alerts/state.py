"""Local state: ~/.local/state/aitools-alerts/.

Four files, each written whole to a temp file and moved into place:
``events.json`` (per trust root a pull used: the last accepted manifest and
the verified events filtered under it, plus which root is current),
``checkpoint.json`` (per trust root: the accepted checkpoint key certificate,
the accepted checkpoint, and the ids of the events the reader applies; see
``pull``), ``seen.json`` (thread ids already notified) and ``last_pull.json``
(the last pull attempt's outcome). The certificate and checkpoint are not in
``events.json`` because the released v0.1.4 reader refuses a record there
with a key it does not know; it ignores a file it does not know. A manifest and the events it authorises are one
file, so no reader and no crash ever pairs events with another manifest; and
one record per root means a test pull under another root never touches the
pinned root's floor or events.
A missing file is empty; a file that does not parse raises StateError,
because starting from empty would lower the floor and re-notify. ``locked``
serialises pulls and notifies so neither rolls the other back.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import checkpoint, config, manifest, nostr
from .manifest import Manifest

__all__ = ["StateError", "State", "write_json"]

MAX_STATE_BYTES = 64 << 20


class StateError(ValueError):
    """A state file is unreadable or has the wrong shape."""


def write_json(path: Path, obj) -> None:
    """Atomically replace ``path`` with ``obj`` as JSON (mode 0600)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read(path: Path, default):
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return default
    except OSError as e:
        raise StateError(f"{path}: {e.strerror}") from None
    if len(data) > MAX_STATE_BYTES:
        raise StateError(f"{path}: larger than {MAX_STATE_BYTES} bytes")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise StateError(f"{path}: not JSON ({e})") from None


EVENT_KEYS = ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")


def _load_trust(where: Path) -> dict:
    """checkpoint.json as {root: {"cert", "checkpoint", "applied"}}, each
    document parsed and its signature checked: the certificate under its
    root, the checkpoint as a well-formed signed event (which certificate
    vouches for it is decided at use, since certificates are replaced). A
    file that is present and wrong raises StateError: starting from empty
    would forget what may never be rolled back."""
    rec = _read(where, {})
    if not isinstance(rec, dict):
        raise StateError(f"{where}: not a checkpoint record")
    out = {}
    for root, r in rec.items():
        if (not nostr._is_hex(root, 32) or not isinstance(r, dict) or set(r) != {"cert", "checkpoint", "applied"}
                or not isinstance(r["applied"], list) or not all(nostr._is_hex(i, 32) for i in r["applied"])):
            raise StateError(f"{where}: bad record for root {root!r}")
        try:
            cert = checkpoint.load_cert(json.dumps(r["cert"]).encode("utf-8"))
            cp = (None if r["checkpoint"] is None
                  else checkpoint.load_checkpoint(json.dumps(r["checkpoint"]).encode("utf-8")))
        except checkpoint.CheckpointError as e:
            raise StateError(f"{where}: {e}") from None
        if not checkpoint.verify_cert(cert, root):
            raise StateError(f"{where}: certificate not signed by its recorded root")
        if cp is not None and not nostr.verify_event(cp.event):
            raise StateError(f"{where}: checkpoint signature does not verify")
        out[root] = {"cert": cert, "checkpoint": cp, "applied": set(r["applied"])}
    return out


@dataclass
class State:
    dir: Path
    roots: dict = field(default_factory=dict)  # root -> [Manifest, {id: event}]
    manifest_root: str | None = None
    seen: set = field(default_factory=set)
    last_pull: dict = field(default_factory=dict)
    trust: dict = field(default_factory=dict)  # root -> {"cert": Cert, "checkpoint": Checkpoint | None, "applied": set}

    @classmethod
    def load(cls, dir: Path | None = None) -> "State":
        d = Path(dir) if dir is not None else config.state_dir()
        where = d / "events.json"
        rec = _read(where, None)
        roots: dict = {}
        current = None
        if rec is not None:
            if (not isinstance(rec, dict) or set(rec) != {"current", "roots"}
                    or not isinstance(rec["roots"], dict) or rec["current"] not in rec["roots"]):
                raise StateError(f"{where}: not a state record")
            for root, r in rec["roots"].items():
                if (not nostr._is_hex(root, 32) or not isinstance(r, dict)
                        or set(r) != {"manifest", "events"} or not isinstance(r["events"], dict)):
                    raise StateError(f"{where}: bad record for root {root!r}")
                try:
                    m = manifest.load(json.dumps(r["manifest"]).encode("utf-8"))
                except manifest.ManifestError as e:
                    raise StateError(f"{where}: {e}") from None
                if not manifest.verify(m, root):
                    raise StateError(f"{where}: manifest not signed by its recorded root")
                evs = r["events"]
                if not all(isinstance(k, str) and isinstance(v, dict) and v.get("id") == k
                           and tuple(sorted(v)) == tuple(sorted(EVENT_KEYS))
                           for k, v in evs.items()):
                    raise StateError(f"{where}: not events by id")
                roots[root] = [m, evs]
            current = rec["current"]
        seen = _read(d / "seen.json", [])
        if not isinstance(seen, list) or not all(isinstance(s, str) for s in seen):
            raise StateError(f"{d / 'seen.json'}: not a list of ids")
        last = _read(d / "last_pull.json", {})
        if not isinstance(last, dict):
            raise StateError(f"{d / 'last_pull.json'}: not an object")
        return cls(dir=d, roots=roots, manifest_root=current, seen=set(seen), last_pull=last,
                   trust=_load_trust(d / "checkpoint.json"))

    @property
    def manifest(self) -> Manifest | None:
        """The accepted manifest of the current root (the last pull's)."""
        r = self.roots.get(self.manifest_root)
        return r[0] if r else None

    @property
    def events(self) -> dict:
        """The verified events of the current root."""
        r = self.roots.get(self.manifest_root)
        return r[1] if r else {}

    def accepted(self, root: str) -> Manifest | None:
        r = self.roots.get(root)
        return r[0] if r else None

    def events_for(self, root: str) -> dict:
        r = self.roots.get(root)
        return r[1] if r else {}

    def accept(self, root: str, m: Manifest, events: dict) -> None:
        self.roots[root] = [m, events]
        self.manifest_root = root

    @contextlib.contextmanager
    def locked(self):
        """Hold an exclusive lock on the state directory and re-read it, so
        the caller decides on the latest saved state."""
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.dir / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            fresh = State.load(self.dir)
            self.roots, self.manifest_root = fresh.roots, fresh.manifest_root
            self.seen, self.last_pull, self.trust = fresh.seen, fresh.last_pull, fresh.trust
            yield self
        finally:
            os.close(fd)

    def _record(self, roots: dict | None = None) -> dict:
        roots = self.roots if roots is None else roots
        return {"current": self.manifest_root,
                "roots": {r: {"manifest": m.event, "events": evs} for r, (m, evs) in roots.items()}}

    def size_with(self, root: str, m: Manifest, events: dict) -> int:
        """Bytes events.json would take with ``root`` holding ``events``."""
        rec = self._record({**self.roots, root: [m, events]})
        return len(json.dumps(rec, ensure_ascii=False, sort_keys=True).encode("utf-8"))

    def save_pull(self) -> None:
        """Write manifests and events (one file, one replace), then last_pull."""
        self.save_events()
        self.save_last_pull()

    def save_events(self) -> None:
        if self.manifest_root is not None:
            write_json(self.dir / "events.json", self._record())

    def cert_for(self, root: str):
        """The accepted checkpoint key certificate of ``root``, or None."""
        t = self.trust.get(root)
        return t["cert"] if t else None

    def checkpoint_for(self, root: str):
        """The accepted checkpoint of ``root``, or None."""
        t = self.trust.get(root)
        return t["checkpoint"] if t else None

    def applied_for(self, root: str):
        """The ids of the events the reader applies under ``root``; None until
        a first checkpoint was accepted (the stored events then all apply)."""
        t = self.trust.get(root)
        return t["applied"] if t and t["checkpoint"] is not None else None

    def set_trust(self, root: str, cert, cp, applied) -> None:
        self.trust[root] = {"cert": cert, "checkpoint": cp, "applied": set(applied)}

    def save_trust(self) -> None:
        """Write checkpoint.json: certificates, checkpoints and applied ids."""
        write_json(self.dir / "checkpoint.json", {
            root: {"cert": t["cert"].event, "checkpoint": t["checkpoint"].event if t["checkpoint"] else None,
                   "applied": sorted(t["applied"])} for root, t in self.trust.items()})

    def save_last_pull(self) -> None:
        write_json(self.dir / "last_pull.json", self.last_pull)

    def save_seen(self) -> None:
        write_json(self.dir / "seen.json", sorted(self.seen))
