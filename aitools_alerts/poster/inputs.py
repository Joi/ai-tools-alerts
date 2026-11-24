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
import stat
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
               "outbox", "deferred", "withheld", "waiting", "gate", "weekly"}
MAX_WAITING = 2000  # 0dvh: first sight of a held high, per scope and id
GATE = 1  # h340: everything unpublished in the state was admitted by an authoritative source
MAX_DIGEST_IDS = 10  # the event ids of the last digests sent, oldest first
WEEK = re.compile(r"\d{4}-W\d{2}")  # qwpw: the ISO week of the last weekly summary sent
_TOKYO = _dt.timezone(_dt.timedelta(hours=9))


def iso_week(day) -> str:
    """The ISO week of a date, or of an epoch second in Tokyo: ``2026-W48``. Such strings
    sort by week."""
    if isinstance(day, int):
        day = _dt.datetime.fromtimestamp(day, _TOKYO).date()
    y, w, _ = day.isocalendar()
    return f"{y:04d}-W{w:02d}"
_ITEM_KEYS = {"key", "kind", "scope", "ids", "channel", "text", "adv", "exploited", "date", "sent", "root"}
_CANDIDATE_FIELDS = frozenset(Candidate.__dataclass_fields__)
_KINDS = {"root", "copy", "reply", "digest", "ja"}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,252}")  # three or more: compose skips shorter names
_SUFFIX = re.compile(r"\.[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
_SECRET_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_SSH_HOST = re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
_WRAPPER = re.compile(r"/[A-Za-z0-9._/-]{1,255}")
DEFAULT_RELAY_URL = "https://buzz.ai-tools.md"
# Posting through the relay VM's ssh wrapper (ai-tools-alerts#w75s) retired with vzc3: the
# poster signs here and posts over HTTPS. A config that still names the wrapper is refused
# by name. relay_ssh_host stays, for the checkpoint's put-only route (nfm3) and nothing else.
RETIRED_KEYS = ("relay_send_wrapper",)
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
    # the name of the relay key in the secrets helper.
    strip_hosts: tuple[str, ...] = ()
    internal_host_suffixes: tuple[str, ...] = ()
    relay_url: str = DEFAULT_RELAY_URL
    relay_key_secret: str | None = None  # the secrets helper's name for jibot's key
    # Curator translation (ai-tools-alerts#bq8v): off by default; the helper is get_secret's.
    translate_curator: bool = False
    translate_mirror_url: str = _member_config.DEFAULT_MIRROR_URL
    secrets_helper: Path | None = None
    # The feed checkpoint (ai-tools-alerts#nfm3): the file holding the checkpoint secret
    # key on THIS machine (mode 600; one key, one poster, one ledger), the ssh destination
    # of the put-only route on the relay VM, and the absolute path there of the command
    # that stores a checkpoint. All three or none.
    checkpoint_key_file: Path | None = None
    relay_ssh_host: str | None = None
    relay_put_wrapper: str | None = None

    def check_relay(self) -> None:
        """A run sends, so it needs the relay and its key; pending and resolve do not."""
        if not self.relay_key_secret or not self.secrets_helper:
            raise ConfigError("relay_key_secret and secrets_helper must be set")
        # Checked here too, so a Config built in code meets the load_config rules
        # before anything is marked pending.
        _check_relay_url(self.relay_url)
        if not isinstance(self.relay_key_secret, str) or not _SECRET_NAME.fullmatch(self.relay_key_secret):
            raise ConfigError("relay_key_secret must be a secret name (A-Z, 0-9, _)")
        if not os.path.isabs(str(self.secrets_helper)):
            raise ConfigError("secrets_helper must be an absolute path")
        self.check_checkpoint()

    def check_checkpoint(self) -> None:
        """The checkpoint's three keys: all or none, each well formed. load_config and
        check_relay both call this, so a Config built in code meets the same rule."""
        keys = (self.checkpoint_key_file, self.relay_ssh_host, self.relay_put_wrapper)
        if any(k is None for k in keys) and any(k is not None for k in keys):
            raise ConfigError("checkpoint_key_file, relay_ssh_host and relay_put_wrapper go together")
        if self.checkpoint_key_file is None:
            return
        if not os.path.isabs(str(self.checkpoint_key_file)):
            raise ConfigError("checkpoint_key_file must be an absolute path")
        if not isinstance(self.relay_ssh_host, str) or not _SSH_HOST.fullmatch(self.relay_ssh_host):
            raise ConfigError("relay_ssh_host must be an ssh host ([user@]host)")
        if not isinstance(self.relay_put_wrapper, str) or not _WRAPPER.fullmatch(self.relay_put_wrapper):
            raise ConfigError("relay_put_wrapper must be an absolute path")

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
    def owed_state(self) -> Path:
        """The checkpoint number last used and the acknowledged posts not yet seen on the mirror."""
        return self.ledger.with_name(self.ledger.name + ".checkpoint.json")

    @property
    def recompute_state(self) -> Path:
        """The last good KEV copy and each thread's wait before a lowering (ny5g; never the journal)."""
        return self.ledger.with_name(self.ledger.name + ".recompute.json")

    @property
    def catalog_known(self) -> Path:
        """The catalog lane's inventory (q03f): written only under catalog_lock."""
        return self.ledger.with_name(self.ledger.name + ".catalog-known.json")

    @property
    def catalog_state(self) -> Path:
        """What the catalog lane last sent per key (q03f): written only under catalog_lock."""
        return self.ledger.with_name(self.ledger.name + ".catalog.json")

    @property
    def catalog_lock(self) -> Path:
        return self.ledger.with_name(self.ledger.name + ".catalog.lock")

    @property
    def mirror_dir(self) -> Path:
        """The verified mirror events the curator pass reads (a member-style state dir)."""
        return self.ledger.with_name(self.ledger.name + ".mirror")

    def check_paths(self) -> None:
        """The ledger, its lock, the journal and the KEV cache are four distinct files."""
        files = [self.ledger, self.ledger.with_name(self.ledger.name + ".lock"), self.state, self.kev_cache,
                 self.translate_state, self.owed_state, self.recompute_state]
        if self.checkpoint_key_file is not None:  # a cache write must never land on the key
            files.append(self.checkpoint_key_file)
        files.append(self.mirror_dir)
        # Case-folded: APFS is case-insensitive, so ledger.json and LEDGER.json are one file.
        real = [os.path.realpath(p).casefold() for p in files]
        mirror = real[-1] + os.sep  # the mirror directory holds its own state files and lock
        if len(set(real)) != len(real) or any(r.startswith(mirror) for r in real[:-1]):
            raise ConfigError("ledger, ledger lock, state, kev_cache, the translation, checkpoint and recompute files "
                              "and the checkpoint key file must differ")


    def check_catalog_paths(self) -> None:
        """The catalog lane's three files differ from each other and from every file
        check_paths guards. Checked only when the lane is on, and a clash turns off the
        lane alone (q03f): a catalog path never stops alert work."""
        own = [self.catalog_known, self.catalog_state, self.catalog_lock]
        others = [self.ledger, self.ledger.with_name(self.ledger.name + ".lock"), self.state, self.kev_cache,
                  self.translate_state, self.owed_state, self.recompute_state, self.mirror_dir]
        if self.checkpoint_key_file is not None:
            others.append(self.checkpoint_key_file)
        real = [os.path.realpath(p).casefold() for p in own + others]
        mirror = os.path.realpath(self.mirror_dir).casefold() + os.sep
        if len(set(real)) != len(real) or any(r.startswith(mirror) for r in real[:3]):
            raise ConfigError("the catalog files must differ from each other and from the poster's other files")


def _check_relay_url(url) -> str:
    from aitools_alerts.poster import transport  # here: transport imports nothing of inputs
    try:
        transport.check_url(url)
    except ValueError:
        raise ConfigError("relay_url must be https://<host>") from None
    return url


def load_config(path) -> Config:
    """The TOML config; unknown keys and wrong types are a ConfigError."""
    try:
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from None
    retired = sorted(set(raw) & set(RETIRED_KEYS))
    if retired:
        raise ConfigError(f"{retired} retired: the poster signs locally and posts over HTTPS; "
                          "set relay_key_secret and secrets_helper instead")
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
    if "relay_url" in raw:
        out["relay_url"] = _check_relay_url(raw["relay_url"])
    if "relay_key_secret" in raw:
        if not isinstance(raw["relay_key_secret"], str) or not _SECRET_NAME.fullmatch(raw["relay_key_secret"]):
            raise ConfigError("relay_key_secret must be a secret name (A-Z, 0-9, _)")
        out["relay_key_secret"] = raw["relay_key_secret"]
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
    if "checkpoint_key_file" in raw:
        if not isinstance(raw["checkpoint_key_file"], str) or not os.path.isabs(raw["checkpoint_key_file"]):
            raise ConfigError("checkpoint_key_file must be an absolute path")
        out["checkpoint_key_file"] = Path(raw["checkpoint_key_file"])
    if "relay_put_wrapper" in raw:
        if not isinstance(raw["relay_put_wrapper"], str) or not _WRAPPER.fullmatch(raw["relay_put_wrapper"]):
            raise ConfigError("relay_put_wrapper must be an absolute path")
        out["relay_put_wrapper"] = raw["relay_put_wrapper"]
    if "relay_ssh_host" in raw:
        if not isinstance(raw["relay_ssh_host"], str) or not _SSH_HOST.fullmatch(raw["relay_ssh_host"]):
            raise ConfigError("relay_ssh_host must be an ssh host ([user@]host)")
        out["relay_ssh_host"] = raw["relay_ssh_host"]
    if out.get("translate_curator") and "secrets_helper" not in out:
        raise ConfigError("translate_curator needs secrets_helper")
    cfg = Config(**out)
    cfg.check_checkpoint()
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


CATALOG_SPEC = "catalog-channel.json"


def load_catalog_channel(channels: dict, path: Path | None = None) -> str | None:
    """The catalog channel id (q03f) from spec/catalog-channel.json, or None when the
    file does not exist (the catalog is off). ConfigError when it is not exactly
    ``{"catalog": <lowercase uuid>}`` naming neither alert channel."""
    path = path if path is not None else schema.SPEC_DIR / CATALOG_SPEC
    try:
        ch = read_regular_json(path, 4096)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, RecursionError) as e:
        raise ConfigError(f"spec/{CATALOG_SPEC} unreadable: {type(e).__name__}") from None
    uuid = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    if not (isinstance(ch, dict) and set(ch) == {"catalog"} and isinstance(ch["catalog"], str)
            and uuid.fullmatch(ch["catalog"])):
        raise ConfigError(f"spec/{CATALOG_SPEC} needs exactly catalog as a lowercase UUID")
    if ch["catalog"] in (channels.get("feed"), channels.get("critical")):
        raise ConfigError(f"spec/{CATALOG_SPEC} names an alert channel")
    return ch["catalog"]


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


def read_regular_json(path: Path, limit: int):
    """read_json for a file that must be a regular file: opened without blocking (a FIFO
    or a device at the path never holds the run), refused with ValueError when it is not
    a regular file. FileNotFoundError when it does not exist."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("not a regular file")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(limit + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > limit:
        raise ValueError("file too large")
    return json.loads(data, object_pairs_hook=schema._no_duplicates,
                      parse_constant=schema._reject_constant)


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
            "held": [], "digested": [], "outbox": [], "deferred": [], "withheld": [], "waiting": {},
            "gate": GATE, "weekly": iso_week(now)}  # qwpw: the first summary is next Monday


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
    if not (isinstance(it, dict) and _ITEM_KEYS <= set(it) <= _ITEM_KEYS | {"ja", "source_title", "floor"}  # rd8t, r7hr, ny5g
            and ("floor" not in it or (it["kind"] == "root" and it["floor"] in schema.LEVELS))
            and all(it.get(k) is None or isinstance(it[k], str) and it[k] for k in ("ja", "source_title"))
            and isinstance(it["kind"], str)
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
                and set(adv) - {"week"} == {"held", "cutoff", "roots"} and type(adv["cutoff"]) is int
                and ("week" not in adv or isinstance(adv["week"], str) and WEEK.fullmatch(adv["week"]))
                and isinstance(adv["held"], list) and all(isinstance(k, str) for k in adv["held"])
                and isinstance(adv["roots"], list) and all(isinstance(k, str) for k in adv["roots"]))
    if not (isinstance(it["scope"], str) and it["scope"] and it["date"] is None):
        return False
    return (adv is None and kind == "copy") or _adv_ok(adv)


def candidate_from(d) -> Candidate:
    """A Candidate rebuilt from Candidate.to_dict(); ValueError when it is not one."""
    if not (isinstance(d, dict) and set(d) | {"source_title"} == _CANDIDATE_FIELDS - {"severity_word", "readings"}  # r7hr
            and (d.get("source_title") is None or isinstance(d["source_title"], str))):
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
    return isinstance(h, dict) and set(h) in ({"scope", "adv"}, {"scope", "adv", "source_title"}) \
        and isinstance(h["scope"], str) and _adv_ok(h["adv"]) \
        and (h.get("source_title") is None or isinstance(h["source_title"], str))


def _withheld_ok(w) -> bool:  # 8acj: the refused item, then a root's copies; the relay's message; when
    return isinstance(w, dict) and set(w) == {"key", "items", "message", "at"} \
        and isinstance(w["items"], list) and w["items"] and all(_item_ok(it) for it in w["items"]) \
        and w["items"][0]["key"] == w["key"] and isinstance(w["message"], str) and type(w["at"]) is int


def load_state(path: Path, now: int, backfill_days: int) -> dict:
    """The run state, or a fresh one; a malformed file is a LedgerError (send nothing)."""
    try:
        st = read_json(path, MAX_RECORD)
    except FileNotFoundError:
        return new_state(now, backfill_days)
    except (OSError, ValueError, RecursionError) as e:
        raise LedgerError(f"state {path} unreadable: {e}") from None
    if isinstance(st, dict) and "withheld" not in st:
        st["withheld"] = []  # a state file written before withheld existed (8acj)
    if isinstance(st, dict) and "waiting" not in st:
        st["waiting"] = {}  # a state file written before waiting existed (0dvh)
    if isinstance(st, dict) and "weekly" not in st:
        st["weekly"] = iso_week(now)  # written before the weekly summary (qwpw): the first is next Monday
    if isinstance(st, dict) and "gate" not in st:
        st["gate"] = 0  # written before the h340 gate: main.run migrates it once
    if isinstance(st, dict) and set(st) == _STATE_KEYS - {"digest_ids"}:
        st["digest_ids"] = []  # a state file written before digest_ids existed
    try:
        ok = (isinstance(st, dict) and set(st) == _STATE_KEYS
              and type(st["schema_version"]) is int and st["schema_version"] == 1
              and type(st["since"]) is int and type(st["digest_at"]) is int
              and type(st["gate"]) is int and st["gate"] in (0, GATE)
              and isinstance(st["weekly"], str) and WEEK.fullmatch(st["weekly"])
              and isinstance(st["digest_roots"], list) and all(isinstance(i, str) for i in st["digest_roots"])
              and isinstance(st["digest_ids"], list) and len(st["digest_ids"]) <= MAX_DIGEST_IDS
              and all(isinstance(i, str) and _HEX64.fullmatch(i) for i in st["digest_ids"])
              and all(st[k] is None or (isinstance(st[k], str) and RUN_DIR.fullmatch(st[k]))
                      for k in ("heartbeat", "collector"))
              and all(st[k] is None or _date_ok(st[k]) for k in ("kev_since", "digest_date"))
              and isinstance(st["held"], list) and all(_held_ok(h) for h in st["held"])
              and isinstance(st["digested"], list) and all(isinstance(i, str) for i in st["digested"])
              and isinstance(st["outbox"], list) and all(_item_ok(it) for it in st["outbox"])
              and isinstance(st["withheld"], list) and all(_withheld_ok(w) for w in st["withheld"])
              and isinstance(st["waiting"], dict) and len(st["waiting"]) <= MAX_WAITING
              and all(isinstance(k, str) and "|" in k and type(t) is int for k, t in st["waiting"].items())
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


REDIRECTED = "x-aitools-alerts-redirected"  # urllib_fetch's mark on an answer that came through a redirect


class _SeenRedirect(urllib.request.HTTPRedirectHandler):
    """Follows a redirect as urllib does, and remembers that it did."""
    seen = False

    def redirect_request(self, *args, **kwargs):
        self.seen = True
        return super().redirect_request(*args, **kwargs)


def urllib_fetch(url: str, headers: dict, timeout: float = KEV_DEADLINE, handlers=()):
    """(status, headers, body) for one GET; a 304 or other HTTP error has an empty body.
    An answer reached through a redirect carries the header ``REDIRECTED`` (ny5g): its
    entries still make candidates, and it is never a read whose absences count."""
    req = urllib.request.Request(url, headers={**headers, "User-Agent": rules.USER_AGENT})
    seen = _SeenRedirect()
    try:
        with urllib.request.build_opener(seen, *handlers).open(req, timeout=timeout) as resp:
            hdrs = dict(resp.headers.items())
            return resp.status, {**hdrs, REDIRECTED: "1"} if seen.seen else hdrs, resp.read(MAX_KEV + 1)
    except urllib.error.HTTPError as e:
        hdrs = dict(e.headers.items()) if e.headers else {}
        e.close()
        return e.code, {**hdrs, REDIRECTED: "1"} if seen.seen else hdrs, b""  # a 304 at the end of a redirect too


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


def fetch_kev(cache: Path, fetch=urllib_fetch, deadline: float | None = None,
              info: dict | None = None) -> tuple[dict | None, str]:
    """(catalog, status): status ``ok`` (fetched), ``304`` (the cache, not modified)
    or ``unavailable`` (catalog None). ``info``, when given, gets ``redirected``: whether
    this request's answer, a 200 or a 304, came through a redirect. A 304 says only
    that the cache is current; which fetch filled the cache is the caller's to know."""
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
    if info is not None:
        info["redirected"] = not isinstance(hdrs, dict) or _header(hdrs, REDIRECTED) is not None
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
