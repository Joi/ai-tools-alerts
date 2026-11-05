"""Tell the member: desktop, iMessage, Signal, Telegram or a webhook.

Every transport is a subprocess with a fixed argv list (no shell; the alert
text is one argument, never part of a script) or a urllib POST of JSON.
``send`` never raises; a send counts only when ``accepted`` is True.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import check
from .check import Match
from .config import Settings

__all__ = ["SendResult", "send", "format_text", "TITLE", "OSASCRIPT"]

TITLE = "ai-tools alert"
TIMEOUT = 30
MAX_TEXT = 3500  # under Telegram's 4096 and most webhook limits
# The text is item 1 of argv; it never becomes AppleScript source.
OSASCRIPT = ("on run argv\n"
             f'display notification (item 1 of argv) with title "{TITLE}"\n'
             "end run")


@dataclass(frozen=True)
class SendResult:
    accepted: bool
    detail: str


def format_text(adv, m: Match | None = None) -> str:
    """Level and title, what is affected, the action, the primary source."""
    lines = [f"{adv.level.upper()}: {adv.title}"]
    p = m.product if m is not None and m.product is not None else (adv.products[0] if adv.products else None)
    if p is not None:
        have = f" {m.installed.version}" if m is not None and m.installed.version else ""
        fixed = f" (fixed in {p.fixed})" if p.fixed else ""
        lines.append(f"Affected: {p.name}{have}{fixed}")
    actions = check.plan(m, check.Config()).prepare if m is not None else adv.actions
    lines += [f"Action: {check.describe(a)}" for a in actions] or ["Action: see the advisory"]
    if adv.sources:
        lines.append(f"Source: {adv.sources[0].url}")
    text = "\n".join(lines)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 1] + "…"


def _run(argv: list[str], run) -> SendResult:
    if shutil.which(argv[0]) is None:
        return SendResult(False, f"{argv[0]} not installed")
    try:
        r = run(argv, shell=False, timeout=TIMEOUT, stdin=subprocess.DEVNULL,
                capture_output=True, text=True, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return SendResult(False, f"{argv[0]} failed: {type(e).__name__}")
    if r.returncode != 0:
        return SendResult(False, f"{argv[0]} exited {r.returncode}")
    return SendResult(True, f"sent with {argv[0]}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect turns a POST into a GET without the body, so a 200 after
    one proves nothing was delivered: refuse it."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect)


def _default_post(url: str, payload: dict) -> tuple[int, bytes]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "aitools-alerts"})
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as r:
            return r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, b""


def _token(path: str | None) -> str | None:
    """The bot token, only from a file nobody else can read."""
    if not path:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO) or st.st_uid != os.getuid():
            return None
        tok = f.read(256).decode("utf-8", "replace").strip()
    ok = tok and all(c.isalnum() or c in ":_-" for c in tok)
    return tok if ok else None


def send(channel: str, text: str, settings: Settings, run=subprocess.run, post=None,
         platform: str | None = None) -> SendResult:
    """Send ``text`` on one channel. Never raises."""
    try:
        return _send(channel, text, settings, run, post or _default_post, platform or sys.platform)
    except Exception as e:  # a transport bug must not stop the other channels
        return SendResult(False, f"{channel} failed: {type(e).__name__}")


def _send(channel, text, s: Settings, run, post, platform) -> SendResult:
    if not isinstance(text, str) or not text:
        return SendResult(False, "empty text")
    if channel == "desktop":
        if platform == "darwin":
            return _run(["osascript", "-e", OSASCRIPT, text], run)
        if platform.startswith("linux"):
            return _run(["notify-send", "--", TITLE, text], run)
        return SendResult(False, f"no desktop notifier for {platform}")
    if channel == "imessage":
        if not s.imessage_to:
            return SendResult(False, "imessage_to not set")
        return _run(["imsg", "send", "--to", s.imessage_to, "--text", text], run)
    if channel == "signal":
        if not s.signal_to:
            return SendResult(False, "signal_to not set")
        acct = ["-a", s.signal_account] if s.signal_account else []
        return _run(["signal-cli", *acct, "send", "-m", text, s.signal_to], run)
    if channel == "telegram":
        if not s.telegram_chat_id:
            return SendResult(False, "telegram_chat_id not set")
        tok = _token(s.telegram_token_file)
        if tok is None:
            return SendResult(False, "telegram token file missing, malformed, or readable by others")
        try:
            code, body = post(f"https://api.telegram.org/bot{tok}/sendMessage",
                              {"chat_id": s.telegram_chat_id, "text": text})
        except (OSError, ValueError):
            return SendResult(False, "telegram request failed")  # never echo the URL
        try:
            ok = code == 200 and json.loads(body).get("ok") is True
        except (ValueError, AttributeError):
            ok = False
        return SendResult(ok, "sent with telegram" if ok else f"telegram refused (HTTP {code})")
    if channel == "webhook":
        if not s.webhook_url:
            return SendResult(False, "webhook_url not set")
        try:
            code, _ = post(s.webhook_url, {"text": text})
        except (OSError, ValueError) as e:
            return SendResult(False, f"webhook failed: {type(e).__name__}")
        ok = 200 <= code < 300
        return SendResult(ok, "sent with webhook" if ok else f"webhook refused (HTTP {code})")
    return SendResult(False, f"unknown channel {channel!r}")
