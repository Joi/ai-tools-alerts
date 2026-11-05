"""The member's settings: ~/.config/aitools-alerts/config.toml.

Every path is computed when called, from ``Path.home()``, so a test that sets
HOME never touches the real one. Unknown keys are ignored; a known key with
the wrong type is an error naming the key. ``auto_apply`` keeps only verbs in
the fixed vocabulary, ``notify`` only known channels. Secrets are not kept
here: the Telegram bot token lives in its own mode-600 file.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import schema
from .check import Config

__all__ = ["DEFAULT_MIRROR_URL", "CHANNELS", "ConfigError", "Settings", "config_dir",
           "config_path", "key_path", "state_dir", "load", "write_default"]

DEFAULT_MIRROR_URL = "https://buzz.ai-tools.md/alerts/"
CHANNELS = ("desktop", "imessage", "signal", "telegram", "webhook")
_RECIPIENT = re.compile(r"[A-Za-z0-9+@._:][A-Za-z0-9+@._:-]{0,127}")
_RECIPIENT_KEYS = ("imessage_to", "signal_to", "signal_account", "telegram_chat_id")
MAX_CONFIG_BYTES = 1 << 20


class ConfigError(ValueError):
    """The config file does not parse, or a key has the wrong type or form."""


def config_dir() -> Path:
    return Path.home() / ".config" / "aitools-alerts"


def config_path() -> Path:
    return config_dir() / "config.toml"


def key_path() -> Path:
    return config_dir() / "key.nsec"


def state_dir() -> Path:
    return Path.home() / ".local" / "state" / "aitools-alerts"


def _token_default() -> str:
    return str(config_dir() / "telegram.token")


@dataclass(frozen=True)
class Settings:
    mirror_url: str = DEFAULT_MIRROR_URL
    notify: tuple[str, ...] = ("desktop",)
    auto_apply: frozenset[str] = field(default_factory=frozenset)
    imessage_to: str | None = None
    signal_to: str | None = None
    signal_account: str | None = None
    telegram_chat_id: str | None = None
    webhook_url: str | None = None
    telegram_token_file: str | None = None

    def check_config(self) -> Config:
        return Config(auto_apply=self.auto_apply)


def check_mirror_url(url) -> str:
    if not isinstance(url, str) or not url.startswith(("https://", "file://")) or len(url) > 2048:
        raise ConfigError("mirror_url must be an https:// or file:// URL")
    return url


def _strings(v, key: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(s, str) for s in v):
        raise ConfigError(f"{key} must be a list of strings")
    return v


def load(path: Path | None = None) -> Settings:
    path = Path(path) if path is not None else config_path()
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return Settings(telegram_token_file=_token_default())
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror}") from None
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path} is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        raw = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{path} does not parse: {e}") from None
    out: dict = {}
    if "mirror_url" in raw:
        out["mirror_url"] = check_mirror_url(raw["mirror_url"])
    if "notify" in raw:
        out["notify"] = tuple(dict.fromkeys(c for c in _strings(raw["notify"], "notify")
                                            if c in CHANNELS))
    if "auto_apply" in raw:
        out["auto_apply"] = frozenset(_strings(raw["auto_apply"], "auto_apply")) & schema.VERBS
    for key in _RECIPIENT_KEYS:
        if key in raw:
            v = raw[key]
            if isinstance(v, int) and not isinstance(v, bool) and key == "telegram_chat_id":
                v = str(v)
            if not isinstance(v, str) or not _RECIPIENT.fullmatch(v):
                raise ConfigError(f"{key} must be 1..128 characters of A-Z a-z 0-9 + @ . _ : - "
                                  "and not start with -")
            out[key] = v
    if "webhook_url" in raw:
        v = raw["webhook_url"]
        if not isinstance(v, str) or not v.startswith("https://") or len(v) > 2048:
            raise ConfigError("webhook_url must be an https:// URL")
        out["webhook_url"] = v
    token = raw.get("telegram_token_file", _token_default())
    if not isinstance(token, str):
        raise ConfigError("telegram_token_file must be a path string")
    out["telegram_token_file"] = os.path.expanduser(token)
    return Settings(**out)


TEMPLATE = f"""\
# ai-tools security alerts: member settings.
# Reading alerts needs no account. Nothing here is sent anywhere.

# Where the signed mirror lives.
mirror_url = "{DEFAULT_MIRROR_URL}"

# Where critical alerts go: any of "desktop", "imessage", "signal",
# "telegram", "webhook".
notify = ["desktop"]

# Verbs your agent may apply by itself, and only from a curator post.
# "upgrade" is the only verb expected here. Empty: everything asks first.
auto_apply = []

# imessage_to = "+15555550100"        # needs the imsg CLI
# signal_to = "+15555550100"          # needs signal-cli
# signal_account = "+15555550101"
# telegram_chat_id = "123456789"      # bot token in telegram.token (mode 600)
# webhook_url = "https://example.invalid/hook"
"""


def write_default(path: Path | None = None, force: bool = False) -> Path:
    """Write the commented default config (mode 0600, directory 0700).
    Refuses an existing file unless ``force``."""
    path = Path(path) if path is not None else config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise ConfigError(f"{path} exists; use --force to overwrite it") from None
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(TEMPLATE)
    os.chmod(path, 0o600)
    return path
