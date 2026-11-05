"""Local state: ~/.local/state/aitools-alerts/.

Four files, each written whole to a temp file and moved into place:
``events.json`` (verified events by id), ``seen.json`` (thread ids already
notified), ``last_pull.json`` (the last pull attempt's outcome) and
``manifest.json`` (the last accepted manifest for every trust root a pull
used, and which root is current). Keeping one record per root means a test
pull under another root never erases the pinned root's freshness floor.
A missing file is empty; a file that does not parse raises StateError,
because starting from empty would lower the floor and re-notify. ``locked``
serialises pulls so two of them cannot roll the manifest back.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import config, manifest, nostr
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


@dataclass
class State:
    dir: Path
    events: dict = field(default_factory=dict)
    seen: set = field(default_factory=set)
    accepted: dict = field(default_factory=dict)
    manifest_root: str | None = None
    last_pull: dict = field(default_factory=dict)

    @classmethod
    def load(cls, dir: Path | None = None) -> "State":
        d = Path(dir) if dir is not None else config.state_dir()
        events = _read(d / "events.json", {})
        if not isinstance(events, dict) or not all(
                isinstance(k, str) and isinstance(v, dict) and v.get("id") == k
                for k, v in events.items()):
            raise StateError(f"{d / 'events.json'}: not an object of events by id")
        seen = _read(d / "seen.json", [])
        if not isinstance(seen, list) or not all(isinstance(s, str) for s in seen):
            raise StateError(f"{d / 'seen.json'}: not a list of ids")
        last = _read(d / "last_pull.json", {})
        if not isinstance(last, dict):
            raise StateError(f"{d / 'last_pull.json'}: not an object")
        rec = _read(d / "manifest.json", None)
        accepted: dict[str, Manifest] = {}
        current = None
        where = d / "manifest.json"
        if rec is not None:
            if (not isinstance(rec, dict) or set(rec) != {"current", "accepted"}
                    or not isinstance(rec["accepted"], dict)
                    or rec["current"] not in rec["accepted"]):
                raise StateError(f"{where}: not a manifest record")
            for root, ev in rec["accepted"].items():
                if not nostr._is_hex(root, 32):
                    raise StateError(f"{where}: bad root {root!r}")
                try:
                    m = manifest.load(json.dumps(ev).encode("utf-8"))
                except manifest.ManifestError as e:
                    raise StateError(f"{where}: {e}") from None
                if not manifest.verify(m, root):
                    raise StateError(f"{where}: manifest not signed by its recorded root")
                accepted[root] = m
            current = rec["current"]
        return cls(dir=d, events=events, seen=set(seen), accepted=accepted,
                   manifest_root=current, last_pull=last)

    @property
    def manifest(self) -> Manifest | None:
        """The manifest of the current root (the last pull's)."""
        return self.accepted.get(self.manifest_root) if self.manifest_root else None

    def accept(self, root: str, m: Manifest) -> None:
        self.accepted[root] = m
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
            self.events, self.seen, self.accepted = fresh.events, fresh.seen, fresh.accepted
            self.manifest_root, self.last_pull = fresh.manifest_root, fresh.last_pull
            yield self
        finally:
            os.close(fd)

    def save_pull(self) -> None:
        """Write events, then the manifest record, then last_pull. Events go
        first: a reader between the two writes sees the new events under the
        old manifest, and a key the new manifest removed has no events left."""
        write_json(self.dir / "events.json", self.events)
        if self.manifest_root is not None:
            write_json(self.dir / "manifest.json",
                       {"current": self.manifest_root,
                        "accepted": {r: m.event for r, m in self.accepted.items()}})
        write_json(self.dir / "last_pull.json", self.last_pull)

    def save_last_pull(self) -> None:
        write_json(self.dir / "last_pull.json", self.last_pull)

    def save_seen(self) -> None:
        write_json(self.dir / "seen.json", sorted(self.seen))
