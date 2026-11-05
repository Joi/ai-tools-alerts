"""The poster's inputs and run state: config, the state file, the KEV fetch, run dirs.

Nothing here sends. The state file is the run's journal (``outbox``) plus its
watermarks; it is written atomically and only while the caller holds the
ledger's lock, and a malformed one is refused (LedgerError), because a run that
cannot read its journal could send a message twice.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from aitools_alerts import schema
from aitools_alerts.poster import rules
from aitools_alerts.poster.ledger import LedgerError

DEFAULT_CONFIG = Path.home() / ".config" / "aitools-alerts-poster" / "config.toml"
STATE_DIR = Path.home() / ".local" / "state" / "aitools-alerts-poster"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_DEADLINE = 90.0
MAX_KEV = 32 * 1024 * 1024
MAX_RECORD = 16 * 1024 * 1024
MAX_RUN_DIRS = 48
RUN_DIR = re.compile(r"\d{4}-\d{2}-\d{2}T\d{6}Z")

_STATE_KEYS = {"schema_version", "since", "heartbeat", "collector", "kev_since",
               "digest_date", "digest_at", "held", "digested", "outbox"}
_ITEM_KEYS = {"key", "kind", "scope", "ids", "channel", "text", "adv", "exploited", "date", "sent"}
_KINDS = {"root", "copy", "reply", "digest"}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    heartbeat_runs: Path | None = None
    collector_runs: Path | None = None
    ledger: Path = STATE_DIR / "ledger.json"
    kev_cache: Path = STATE_DIR / "kev.json"
    digest_hour: int = 9
    backfill_days: int = 2

    @property
    def state(self) -> Path:
        return self.ledger.parent / "poster-state.json"


def load_config(path) -> Config:
    """The TOML config; unknown keys and wrong types are a ConfigError."""
    try:
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from None
    bad = set(raw) - set(Config.__dataclass_fields__)
    if bad:
        raise ConfigError(f"unknown keys {sorted(bad)}")
    out = {}
    for k in ("heartbeat_runs", "collector_runs", "ledger", "kev_cache"):
        if k in raw:
            if not isinstance(raw[k], str) or not raw[k]:
                raise ConfigError(f"{k} must be a path string")
            out[k] = Path(raw[k]).expanduser()
    for k, lo, hi in (("digest_hour", 0, 23), ("backfill_days", 0, 30)):
        if k in raw:
            if type(raw[k]) is not int or not lo <= raw[k] <= hi:
                raise ConfigError(f"{k} must be an integer {lo}-{hi}")
            out[k] = raw[k]
    return Config(**out)


def load_channels() -> dict:
    ch = json.loads((schema.SPEC_DIR / "channels.json").read_text(encoding="utf-8"))
    if not (isinstance(ch, dict) and all(isinstance(ch.get(k), str) for k in ("feed", "critical"))):
        raise ConfigError("spec/channels.json needs feed and critical")
    return ch


# ---------------------------------------------------------------- files


def write_json(path: Path, data) -> None:
    """Atomic: a temp file in the same directory, fsync, rename, directory fsync."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def read_json(path: Path, limit: int):
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file too large")
    return json.loads(data)


# ---------------------------------------------------------------- run state


def new_state(now: int, backfill_days: int) -> dict:
    since = now - backfill_days * 86400
    return {"schema_version": 1, "since": since, "heartbeat": None, "collector": None,
            "kev_since": None, "digest_date": None, "digest_at": since,
            "held": [], "digested": [], "outbox": []}


def _strs(v) -> bool:
    return isinstance(v, list) and all(isinstance(i, str) and i for i in v)


def _item_ok(it) -> bool:
    return (isinstance(it, dict) and set(it) == _ITEM_KEYS and it["kind"] in _KINDS
            and isinstance(it["key"], str) and it["channel"] in ("feed", "critical")
            and isinstance(it["text"], str) and it["text"] and _strs(it["ids"]) and it["ids"]
            and type(it["exploited"]) is bool
            and all(it[k] is None or isinstance(it[k], str) for k in ("scope", "date", "sent"))
            and (it["adv"] is None or isinstance(it["adv"], dict)))


def load_state(path: Path, now: int, backfill_days: int) -> dict:
    """The run state, or a fresh one; a malformed file is a LedgerError (send nothing)."""
    try:
        st = read_json(path, MAX_RECORD)
    except FileNotFoundError:
        return new_state(now, backfill_days)
    except (OSError, ValueError, RecursionError) as e:
        raise LedgerError(f"state {path} unreadable: {e}") from None
    ok = (isinstance(st, dict) and set(st) == _STATE_KEYS and st["schema_version"] == 1
          and type(st["since"]) is int and type(st["digest_at"]) is int
          and all(st[k] is None or isinstance(st[k], str)
                  for k in ("heartbeat", "collector", "kev_since", "digest_date"))
          and isinstance(st["held"], list)
          and all(isinstance(h, dict) and isinstance(h.get("scope"), str) and isinstance(h.get("adv"), dict)
                  for h in st["held"])
          and isinstance(st["digested"], list) and all(isinstance(i, str) for i in st["digested"])
          and isinstance(st["outbox"], list) and all(_item_ok(it) for it in st["outbox"]))
    if not ok:
        raise LedgerError(f"state {path} malformed; refusing to send")
    return st


def save_state(path: Path, st: dict) -> None:
    try:
        write_json(path, st)
    except OSError as e:
        raise LedgerError(f"cannot write state {path}: {e}") from None


# ---------------------------------------------------------------- KEV


def urllib_fetch(url: str, headers: dict, timeout: float = KEV_DEADLINE):
    """(status, headers, body) for one GET; a 304 or other HTTP error has an empty body."""
    req = urllib.request.Request(url, headers={**headers, "User-Agent": rules.USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(MAX_KEV + 1)
    except urllib.error.HTTPError as e:
        hdrs = dict(e.headers.items()) if e.headers else {}
        e.close()
        return e.code, hdrs, b""


def _header(headers: dict, name: str):
    return next((v for k, v in headers.items() if isinstance(k, str) and k.lower() == name.lower()), None)


def _bounded(fetch, url, headers, deadline):
    """fetch(url, headers) under one wall-clock deadline, in a daemon thread; None on a miss."""
    result = [None]

    def go():
        try:
            result[0] = fetch(url, headers)
        except Exception:  # network, TLS, protocol: a failed fetch
            result[0] = None

    worker = threading.Thread(target=go, name="aitools-alerts-kev", daemon=True)
    start = time.monotonic()
    worker.start()
    worker.join(deadline)
    if worker.is_alive() or time.monotonic() - start > deadline:
        return None
    return result[0]


def load_kev(cache: Path, fetch=urllib_fetch, deadline: float | None = None) -> dict | None:
    """The KEV catalog this run fetched (or the cache on 304); None when unavailable."""
    cached = None
    try:
        c = read_json(cache, MAX_KEV * 2)
        if isinstance(c, dict) and isinstance(c.get("catalog"), dict):
            cached = c
    except (OSError, ValueError, RecursionError):
        pass
    lm = cached.get("last_modified") if cached else None
    headers = {"If-Modified-Since": lm} if isinstance(lm, str) and lm else {}
    got = _bounded(fetch, KEV_URL, headers, KEV_DEADLINE if deadline is None else deadline)
    if not (isinstance(got, tuple) and len(got) == 3):
        return None
    status, hdrs, body = got
    if status == 304:
        return cached["catalog"] if cached else None
    if status != 200 or not isinstance(body, bytes) or len(body) > MAX_KEV:
        return None
    try:
        catalog = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        return None
    lm = _header(hdrs, "Last-Modified") if isinstance(hdrs, dict) else None
    try:
        write_json(cache, {"last_modified": lm if isinstance(lm, str) else None, "catalog": catalog})
    except OSError:
        pass  # a cache failure only costs a full fetch next hour
    return catalog


# ---------------------------------------------------------------- run dirs


def heartbeat_dirs(root: Path, after: str | None) -> list[Path]:
    """Run dirs newer than ``after`` that hold a run.json, oldest first (at most 48);
    with no watermark only the newest, since its run.json is cumulative."""
    try:
        names = sorted(p.name for p in root.iterdir() if RUN_DIR.fullmatch(p.name))
    except OSError:
        return []
    dirs = [root / n for n in names if (after is None or n > after) and (root / n / "run.json").is_file()]
    return dirs[-1:] if after is None else dirs[-MAX_RUN_DIRS:]


def collector_record(root: Path, after: str | None, counts: Counter):
    """(dir name, record) for the newest collector record, if newer than ``after``
    and validated (job.json steps.validate.out == "ok"); else None."""
    try:
        names = sorted(p.name for p in root.iterdir()
                       if RUN_DIR.fullmatch(p.name) and (p / "run-record.json").is_file())
    except OSError:
        return None
    if not names or (after is not None and names[-1] <= after):
        return None
    d = root / names[-1]
    try:
        ok = read_json(d / "job.json", MAX_RECORD)["steps"]["validate"]["out"] == "ok"
    except (OSError, ValueError, RecursionError, KeyError, TypeError):
        ok = False
    if not ok:
        counts["collector not validated"] += 1
        return None
    try:
        return names[-1], read_json(d / "run-record.json", MAX_RECORD)
    except (OSError, ValueError, RecursionError):
        counts["collector unreadable"] += 1
        return None
