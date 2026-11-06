"""The poster's inputs and run state: config, the state file, the KEV fetch, run dirs.

Nothing here sends. The state file is the run's journal (``outbox``) plus its
watermarks; it is written atomically and only while the caller holds the
ledger's lock, and a malformed one is refused (LedgerError), because a run that
cannot read its journal could send a message twice.
"""

from __future__ import annotations

import datetime as _dt
import fcntl
import json
import os
import re
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from aitools_alerts import config as _member_config, schema
from aitools_alerts.poster import rules
from aitools_alerts.poster.compose import SYNTHETIC, SYNTHETIC_ID
from aitools_alerts.poster.candidates import Candidate
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
               "digest_date", "digest_at", "digest_roots", "digest_ids", "held", "digested",
               "outbox", "deferred"}
MAX_DIGEST_IDS = 10  # the event ids of the last digests sent, oldest first
_ITEM_KEYS = {"key", "kind", "scope", "ids", "channel", "text", "adv", "exploited", "date", "sent", "root"}
_CANDIDATE_FIELDS = frozenset(Candidate.__dataclass_fields__)
_KINDS = {"root", "copy", "reply", "digest", "ja"}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,252}")  # three or more: compose skips shorter names
_SUFFIX = re.compile(r"\.[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
_SSH_HOST = re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
_WRAPPER = re.compile(r"/[A-Za-z0-9._/-]{1,255}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


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
    # Deployment detail lives here, never in the public code: host names that drop a
    # field or item (candidates.FLEET_HOSTS), extra internal source-host suffixes, and
    # the relay route (ssh destination, absolute wrapper path on the relay VM).
    strip_hosts: tuple[str, ...] = ()
    internal_host_suffixes: tuple[str, ...] = ()
    relay_ssh_host: str | None = None
    relay_send_wrapper: str | None = None
    # Curator translation (ai-tools-alerts#bq8v): off by default; the helper is get_secret's.
    translate_curator: bool = False
    translate_mirror_url: str = _member_config.DEFAULT_MIRROR_URL
    secrets_helper: Path | None = None

    def check_relay(self) -> None:
        """A run sends, so it needs the relay route; pending and resolve do not."""
        if not self.relay_ssh_host or not self.relay_send_wrapper:
            raise ConfigError("relay_ssh_host and relay_send_wrapper must be set")
        # Checked here too, so a Config built in code meets the load_config rules
        # before anything is marked pending.
        if not isinstance(self.relay_ssh_host, str) or not _SSH_HOST.fullmatch(self.relay_ssh_host):
            raise ConfigError("relay_ssh_host must be an ssh host ([user@]host)")
        if not isinstance(self.relay_send_wrapper, str) or not _WRAPPER.fullmatch(self.relay_send_wrapper):
            raise ConfigError("relay_send_wrapper must be an absolute path")

    @property
    def state(self) -> Path:
        """The run journal, named after the ledger whose lock guards it, so two ledgers
        in one directory never share a journal."""
        return self.ledger.with_name(self.ledger.name + ".poster-state.json")

    @property
    def translate_state(self) -> Path:
        """Hold, daily call count and translated event ids (never the journal: rollback-safe)."""
        return self.ledger.with_name(self.ledger.name + ".translate.json")

    @property
    def mirror_dir(self) -> Path:
        """The verified mirror events the curator pass reads (a member-style state dir)."""
        return self.ledger.with_name(self.ledger.name + ".mirror")

    def check_paths(self) -> None:
        """The ledger, its lock, the journal and the KEV cache are four distinct files."""
        files = [self.ledger, self.ledger.with_name(self.ledger.name + ".lock"), self.state, self.kev_cache,
                 self.translate_state, self.mirror_dir]
        # Case-folded: APFS is case-insensitive, so ledger.json and LEDGER.json are one file.
        real = [os.path.realpath(p).casefold() for p in files]
        if len(set(real)) != len(real):
            raise ConfigError("ledger, ledger lock, state, kev_cache and the translation files must differ")


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
            if not out[k].is_absolute():  # launchd runs from /: a relative path would move
                raise ConfigError(f"{k} must be an absolute path")
    for k, lo, hi in (("digest_hour", 0, 23), ("backfill_days", 0, 30)):
        if k in raw:
            if type(raw[k]) is not int or not lo <= raw[k] <= hi:
                raise ConfigError(f"{k} must be an integer {lo}-{hi}")
            out[k] = raw[k]
    for k in ("strip_hosts", "internal_host_suffixes"):
        if k in raw:
            v = raw[k]
            ok = _SUFFIX if k == "internal_host_suffixes" else _NAME  # ".io" is a suffix; "io" is no host
            dot = ok is _SUFFIX
            if not isinstance(v, list) or not all(isinstance(h, str) and ok.fullmatch(h) for h in v):
                raise ConfigError(f"{k} must be a list of host names" + (" each starting with '.'" if dot else ""))
            out[k] = tuple(h.lower() for h in v)
    for k, pattern, what in (("relay_ssh_host", _SSH_HOST, "an ssh host ([user@]host)"),
                             ("relay_send_wrapper", _WRAPPER, "an absolute path")):
        if k in raw:
            if not isinstance(raw[k], str) or not pattern.fullmatch(raw[k]):
                raise ConfigError(f"{k} must be {what}")
            out[k] = raw[k]
    if "translate_curator" in raw:
        if type(raw["translate_curator"]) is not bool:
            raise ConfigError("translate_curator must be true or false")
        out["translate_curator"] = raw["translate_curator"]
    if "translate_mirror_url" in raw:
        try:
            out["translate_mirror_url"] = _member_config.check_mirror_url(raw["translate_mirror_url"])
        except _member_config.ConfigError:
            raise ConfigError("translate_mirror_url must be an https:// or file:// URL") from None
    if "secrets_helper" in raw:
        if not isinstance(raw["secrets_helper"], str) or not os.path.isabs(raw["secrets_helper"]):
            raise ConfigError("secrets_helper must be an absolute path")
        out["secrets_helper"] = Path(raw["secrets_helper"])
    if out.get("translate_curator") and "secrets_helper" not in out:
        raise ConfigError("translate_curator needs secrets_helper")
    cfg = Config(**out)
    cfg.check_paths()
    return cfg


def load_channels() -> dict:
    try:
        ch = json.loads((schema.SPEC_DIR / "channels.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigError(f"spec/channels.json unreadable: {e}") from None
    uuid = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    if not (isinstance(ch, dict) and all(isinstance(ch.get(k), str) and uuid.fullmatch(ch[k])
                                         for k in ("feed", "critical"))):
        raise ConfigError("spec/channels.json needs feed and critical as lowercase UUIDs")
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
            _sync(fh.fileno())
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


def _sync(fd: int) -> None:
    """fsync; on macOS F_FULLFSYNC, since fsync there does not flush the drive cache."""
    if sys.platform == "darwin":
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(fd)


def read_json(path: Path, limit: int):
    """Strict: duplicate keys and NaN/Infinity are refused (as schema.decode_block)."""
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file too large")
    return json.loads(data, object_pairs_hook=schema._no_duplicates,
                      parse_constant=schema._reject_constant)


# ---------------------------------------------------------------- run state


def new_state(now: int, backfill_days: int) -> dict:
    since = now - backfill_days * 86400
    return {"schema_version": 1, "since": since, "heartbeat": None, "collector": None,
            "kev_since": None, "digest_date": None, "digest_at": since, "digest_roots": [], "digest_ids": [],
            "held": [], "digested": [], "outbox": [], "deferred": []}


def _strs(v) -> bool:
    return isinstance(v, list) and all(isinstance(i, str) and i for i in v)


def _date_ok(v) -> bool:
    if not (isinstance(v, str) and _DATE.fullmatch(v)):
        return False
    try:
        _dt.date.fromisoformat(v)
    except ValueError:
        return False
    return True


def _adv_ok(v) -> bool:
    try:
        schema.validate(v)
    except (ValueError, TypeError):
        return False
    return True


def _item_ok(it) -> bool:
    """A journal item that a later run can finish: every field its kind needs is there
    and well formed, so nothing fails after the post is public."""
    if not (isinstance(it, dict) and set(it) in (_ITEM_KEYS, _ITEM_KEYS | {"ja"})  # "ja": rd8t; older items lack it
            and (it.get("ja") is None or isinstance(it["ja"], str) and it["ja"]) and isinstance(it["kind"], str)
            and it["kind"] in _KINDS and isinstance(it["key"], str) and it["key"]
            and it["channel"] in ("feed", "critical") and isinstance(it["text"], str) and it["text"]
            and _strs(it["ids"]) and it["ids"] and type(it["exploited"]) is bool
            and all(it[k] is None or (isinstance(it[k], str) and _HEX64.fullmatch(it[k]))
                    for k in ("sent", "root"))):
        return False
    kind, adv = it["kind"], it["adv"]
    if kind == "ja":  # a Japanese reply: names its target, no advisory, no text of its own to come
        return (adv is None and it["root"] is not None and it["date"] is None and it.get("ja") is None
                and (it["scope"] is None or isinstance(it["scope"], str) and it["scope"] != ""))
    if (kind == "reply") != (it["root"] is not None) and kind != "copy":
        return False  # a reply names its thread's root; a root or digest names none
    if kind == "digest":
        return (it["scope"] is None and _date_ok(it["date"]) and isinstance(adv, dict)
                and set(adv) == {"held", "cutoff", "roots"} and type(adv["cutoff"]) is int
                and isinstance(adv["held"], list) and all(isinstance(k, str) for k in adv["held"])
                and isinstance(adv["roots"], list) and all(isinstance(k, str) for k in adv["roots"]))
    if not (isinstance(it["scope"], str) and it["scope"] and it["date"] is None):
        return False
    return (adv is None and kind == "copy") or _adv_ok(adv)


def candidate_from(d) -> Candidate:
    """A Candidate rebuilt from Candidate.to_dict(); ValueError when it is not one."""
    if not (isinstance(d, dict) and set(d) == _CANDIDATE_FIELDS):
        raise ValueError("not a candidate")
    strs = ("id", "product_text")
    opt = ("advisory_severity", "local_level_hint", "fixed", "affected", "observed_at")
    flags = ("exploited", "trojanized", "injection_exec")
    if not (all(isinstance(d[k], str) and d[k] for k in strs)
            and all(d[k] is None or isinstance(d[k], str) for k in opt)
            and all(type(d[k]) is bool for k in flags) and _strs(d["aliases"])
            and isinstance(d["sources"], list) and d["sources"]
            and all(isinstance(s, dict) and set(s) == {"url", "published_at"} and isinstance(s["url"], str)
                    and (s["published_at"] is None or isinstance(s["published_at"], str))
                    for s in d["sources"])):
        raise ValueError("not a candidate")
    return Candidate(**{**d, "aliases": tuple(d["aliases"]),
                        "sources": tuple(schema.Source(s["url"], s["published_at"]) for s in d["sources"])})


def _deferred_ok(d) -> bool:
    try:
        candidate_from(d)
    except ValueError:
        return False
    return True


def _held_ok(h) -> bool:
    return isinstance(h, dict) and set(h) == {"scope", "adv"} and isinstance(h["scope"], str) \
        and _adv_ok(h["adv"])


def load_state(path: Path, now: int, backfill_days: int) -> dict:
    """The run state, or a fresh one; a malformed file is a LedgerError (send nothing)."""
    try:
        st = read_json(path, MAX_RECORD)
    except FileNotFoundError:
        return new_state(now, backfill_days)
    except (OSError, ValueError, RecursionError) as e:
        raise LedgerError(f"state {path} unreadable: {e}") from None
    if isinstance(st, dict) and set(st) == _STATE_KEYS - {"digest_ids"}:
        st["digest_ids"] = []  # a state file written before digest_ids existed
    try:
        ok = (isinstance(st, dict) and set(st) == _STATE_KEYS
              and type(st["schema_version"]) is int and st["schema_version"] == 1
              and type(st["since"]) is int and type(st["digest_at"]) is int
              and isinstance(st["digest_roots"], list) and all(isinstance(i, str) for i in st["digest_roots"])
              and isinstance(st["digest_ids"], list) and len(st["digest_ids"]) <= MAX_DIGEST_IDS
              and all(isinstance(i, str) and _HEX64.fullmatch(i) for i in st["digest_ids"])
              and all(st[k] is None or (isinstance(st[k], str) and RUN_DIR.fullmatch(st[k]))
                      for k in ("heartbeat", "collector"))
              and all(st[k] is None or _date_ok(st[k]) for k in ("kev_since", "digest_date"))
              and isinstance(st["held"], list) and all(_held_ok(h) for h in st["held"])
              and isinstance(st["digested"], list) and all(isinstance(i, str) for i in st["digested"])
              and isinstance(st["outbox"], list) and all(_item_ok(it) for it in st["outbox"])
              and len({it["key"] for it in st["outbox"]}) == len(st["outbox"])  # one item per key
              and isinstance(st["deferred"], list) and all(_deferred_ok(d) for d in st["deferred"]))
    except (TypeError, KeyError, AttributeError):
        ok = False
    if not ok:
        raise LedgerError(f"state {path} malformed; refusing to send")
    return st


def save_state(path: Path, st: dict) -> None:
    try:
        write_json(path, st)
    except (OSError, TypeError, ValueError) as e:
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


def _catalog_ok(c) -> bool:
    """The CISA catalog shape only: never the heartbeat feeds.json ``items`` shape,
    which from_kev also parses (B1 c:6mnrdz)."""
    return isinstance(c, dict) and isinstance(c.get("vulnerabilities"), list) and "items" not in c


def load_kev(cache: Path, fetch=urllib_fetch, deadline: float | None = None) -> dict | None:
    """The KEV catalog this run fetched (or the cache on 304); None when unavailable."""
    return fetch_kev(cache, fetch, deadline)[0]


def fetch_kev(cache: Path, fetch=urllib_fetch, deadline: float | None = None) -> tuple[dict | None, str]:
    """(catalog, status): status ``ok`` (fetched), ``304`` (the cache, not modified)
    or ``unavailable`` (catalog None)."""
    cached = None
    try:
        c = read_json(cache, MAX_KEV * 2)
        if isinstance(c, dict) and _catalog_ok(c.get("catalog")):  # else: an unconditional fetch
            cached = c
    except (OSError, ValueError, RecursionError):
        pass
    lm = cached.get("last_modified") if cached else None
    headers = {"If-Modified-Since": lm} if isinstance(lm, str) and lm else {}
    got = _bounded(fetch, KEV_URL, headers, KEV_DEADLINE if deadline is None else deadline)
    if not (isinstance(got, tuple) and len(got) == 3):
        return None, "unavailable"
    status, hdrs, body = got
    if status == 304:
        return (cached["catalog"], "304") if cached else (None, "unavailable")
    if status != 200 or not isinstance(body, bytes) or len(body) > MAX_KEV:
        return None, "unavailable"
    try:
        catalog = json.loads(body)
    except (ValueError, RecursionError):
        return None, "unavailable"
    if not _catalog_ok(catalog):
        return None, "unavailable"
    lm = _header(hdrs, "Last-Modified") if isinstance(hdrs, dict) else None
    try:
        write_json(cache, {"last_modified": lm if isinstance(lm, str) else None, "catalog": catalog})
    except OSError:
        pass  # a cache failure only costs a full fetch next hour
    return catalog, "ok"


def read_kev_file(path: Path) -> dict:
    """A local KEV catalog for a synthetic check (``run --kev-file``): strict JSON in the
    CISA shape, at least one entry, and every entry's vulnerabilityName saying
    SYNTHETIC TEST, so a real catalog cannot be posted through this path by mistake.
    ConfigError otherwise. Nothing is fetched or cached."""
    try:
        c = read_json(Path(path), MAX_KEV)
    except (OSError, ValueError, RecursionError) as e:
        raise ConfigError(f"kev file {path} unreadable: {e}") from None
    if not _catalog_ok(c) or not c["vulnerabilities"]:
        raise ConfigError(f"kev file {path}: not a KEV catalog with entries")
    if not all(isinstance(v, dict) and isinstance(v.get("vulnerabilityName"), str)
               and SYNTHETIC in v["vulnerabilityName"] for v in c["vulnerabilities"]):
        raise ConfigError(f"kev file {path}: every entry's vulnerabilityName must say {SYNTHETIC}")
    if not all(isinstance(v.get("cveID"), str) and SYNTHETIC_ID.fullmatch(v["cveID"])
               for v in c["vulnerabilities"]):
        raise ConfigError(f"kev file {path}: every cveID must be a reserved synthetic id (CVE-2099-NNNN)")
    return c


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


def collector_record(root: Path, after: str | None, counts: Counter, rejected: list | None = None):
    """(dir name, record) for the newest collector record, if newer than ``after``
    and validated (job.json steps.validate.out == "ok"); else None. A refused record
    appends (dir name, reason) to ``rejected``. Only the newest record is ever read:
    each one is a whole snapshot, so a newer record supersedes a refused one."""
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
        if rejected is not None:
            rejected.append((names[-1], "not validated"))
        return None
    try:
        return names[-1], read_json(d / "run-record.json", MAX_RECORD)
    except (OSError, ValueError, RecursionError):
        counts["collector unreadable"] += 1
        if rejected is not None:
            rejected.append((names[-1], "unreadable"))
        return None
