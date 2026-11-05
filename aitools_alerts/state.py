"""Local state: ~/.local/state/aitools-alerts/.

Four files, each written whole to a temp file and moved into place:
``events.json`` (verified events by id), ``seen.json`` (thread ids already
notified), ``last_pull.json`` (the last pull's outcome) and ``manifest.json``
(the last accepted manifest and the root it was accepted under). A missing
file is empty; a file that does not parse raises StateError, because starting
from empty would lower the manifest freshness floor and re-notify.
"""

from __future__ import annotations

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
    manifest: Manifest | None = None
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
        m = root = None
        if rec is not None:
            if (not isinstance(rec, dict) or set(rec) != {"root", "event"}
                    or not nostr._is_hex(rec["root"], 32)):
                raise StateError(f"{d / 'manifest.json'}: not a manifest record")
            try:
                m = manifest.load(json.dumps(rec["event"]).encode("utf-8"))
            except manifest.ManifestError as e:
                raise StateError(f"{d / 'manifest.json'}: {e}") from None
            if not manifest.verify(m, rec["root"]):
                raise StateError(f"{d / 'manifest.json'}: not signed by its recorded root")
            root = rec["root"]
        return cls(dir=d, events=events, seen=set(seen), manifest=m,
                   manifest_root=root, last_pull=last)

    def save_pull(self) -> None:
        """Write events and the manifest record, then last_pull."""
        write_json(self.dir / "events.json", self.events)
        if self.manifest is not None:
            write_json(self.dir / "manifest.json",
                       {"root": self.manifest_root, "event": self.manifest.event})
        write_json(self.dir / "last_pull.json", self.last_pull)

    def save_last_pull(self) -> None:
        write_json(self.dir / "last_pull.json", self.last_pull)

    def save_seen(self) -> None:
        write_json(self.dir / "seen.json", sorted(self.seen))
