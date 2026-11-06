"""Japanese translation of curator free text: one Claude API call per curator event.

``translate(text, call=...)`` does no I/O of its own: ``call(system, text)``
returns the model's text or raises ``AuthError`` (HTTP 401/403) or
``CallError`` (anything else). The output is used only when every URL,
version string and id in the source appears unchanged in it (``tokens``).

``read_key`` reads the API key with ``get_secret`` from the deployment's
secrets helper, in a bash subprocess whose SECRETS_CACHE_DIR is a fresh
directory with no write permission (the pattern of scripts/sign-manifest.py):
the key comes back over the subprocess's stdout pipe only, never in argv, a
file or a log, and no error message carries it. ``api_call(key)`` is the one
provider-facing call: JSON over HTTPS to the Messages API, standard library only.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request

MODEL = "claude-sonnet-5-5"
API_URL = "https://api.anthropic.com/v1/messages"
TIMEOUT = 30
DAILY_CALLS = 20
KEY_NAME = "ANTHROPIC_API_KEY"
MARK = "（機械翻訳）"  # the last line of every machine translation the poster posts
MAX_RESPONSE = 1 << 20
MAX_SOURCE = 6000  # characters sent; longer is untranslated without a call (readers cut at 8000)

SYSTEM = """You translate security alerts from English into Japanese for a security alert feed read by software developers.

Rules:
- Output only the Japanese translation of the user's text. No preface, no notes, no quotation marks around it.
- Keep the line structure: one output line for each input line, in the same order.
- Copy exactly, character for character: product names, package names, every number, version strings, version ranges, dates, CVE, GHSA and other advisory ids, event ids, URLs, file names, commands and code.
- Never add, drop, explain, summarize or soften anything. Never add advice that is not in the text.
- Translate the level words: CRITICAL as 重大, HIGH as 高, NOTICE as 注意."""

_URL = re.compile(r"https?://[^\s<>\"'`]+")
_ID = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|[0-9a-f]{64}|[A-Z][A-Z0-9]+-\d[\w.-]*)\b")
# Whole versions as schema accepts them (2.1.0, 9.9p1, 1.0rc1, 22, v2.0.1-rc1), never a prefix.
_VERSION = re.compile(r"(?<![\w.-])v?\d+(?:\.\d+)*(?:[a-z]+\d*)*(?:[-+][0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?(?![\w]|\.\d)")

# Removed from the helper's environment: a stale copy of the key (get_secret falls back
# to it) and bash startup/trace hooks that would run code or trace inside the process.
_DROP_ENV = frozenset({"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "BASH_XTRACEFD", "PS4", KEY_NAME})
_HELPER = 'source "$AITOOLS_ALERTS_SECRETS_HELPER" && get_secret "$AITOOLS_ALERTS_SECRET_NAME"'


class AuthError(Exception):
    """The API refused the key (HTTP 401 or 403): hold until a human clears it."""


class CallError(Exception):
    """Any other failure of a call or of reading the key; the message never carries the key."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # never re-send the key elsewhere: a 3xx is an HTTPError
        return None


_OPENER = urllib.request.build_opener(_NoRedirect).open


def bounded(fn, deadline: float):
    """fn() under one wall-clock deadline (a slow drip of bytes never outlives it), in a
    daemon thread. CallError("timeout") when it does not finish; fn's exception otherwise."""
    box: list = []

    def go():
        try:
            box.append((True, fn()))
        except BaseException as e:  # noqa: BLE001 - handed to the caller
            box.append((False, e))
    t = threading.Thread(target=go, name="aitools-alerts-translate", daemon=True)
    t.start()
    t.join(deadline)
    if not box:
        raise CallError("timeout")
    ok, v = box[0]
    if not ok:
        raise v
    return v


def tokens(text: str) -> set[str]:
    """Every URL, id and version string in text: what a translation must keep unchanged."""
    out = {u.rstrip(".,;:!?)]}") for u in _URL.findall(text)}
    rest = _URL.sub(" ", text)
    return out | set(_ID.findall(rest)) | set(_VERSION.findall(rest))


def translate(text: str, *, call) -> str | None:
    """The Japanese translation of text, or None when it is empty or loses a token.
    AuthError and CallError from call propagate."""
    if len(text) > MAX_SOURCE:
        return None
    out = call(SYSTEM, text)
    out = out.strip() if isinstance(out, str) else ""
    if not out or not tokens(text) <= tokens(out):  # whole tokens: "2.1" never passes as "2.10"
        return None
    return out


def _refuses_writes(directory: str) -> bool:
    probe = os.path.join(directory, ".write-probe")
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return True
    os.close(fd)
    os.unlink(probe)
    return False


def read_key(helper, runner=subprocess.run) -> str:
    """The API key from the secrets helper at ``helper`` (an absolute path)."""
    if os.geteuid() == 0:
        raise CallError("api key unavailable: refusing to read it as root")
    if not os.path.isabs(str(helper)) or not os.path.isfile(helper):
        raise CallError("api key unavailable: secrets_helper is not a file")
    cache = tempfile.mkdtemp(prefix="aitools-translate-")
    try:
        os.chmod(cache, 0o500)
        if not _refuses_writes(cache):
            raise CallError("api key unavailable: the throwaway cache directory accepts writes")
        env = {k: v for k, v in os.environ.items() if k not in _DROP_ENV}
        env.update(SECRETS_CACHE_DIR=cache, AITOOLS_ALERTS_SECRETS_HELPER=str(helper),
                   AITOOLS_ALERTS_SECRET_NAME=KEY_NAME)
        try:
            res = runner(["bash", "-c", _HELPER], env=env, stdin=subprocess.DEVNULL,
                         capture_output=True, timeout=60)
        except (subprocess.TimeoutExpired, OSError):
            raise CallError("api key unavailable: the secrets helper did not run") from None
        if os.listdir(cache):
            raise CallError("api key unavailable: the secrets helper wrote into its cache")
        lines = res.stdout.decode("ascii", "replace").splitlines() if res.returncode == 0 else []
        if len(lines) != 1 or not lines[0].strip() or "�" in lines[0]:
            raise CallError(f"api key unavailable (get_secret exit {res.returncode})")
        return lines[0].strip()
    finally:
        os.chmod(cache, 0o700)
        shutil.rmtree(cache, ignore_errors=True)


def api_call(key: str, opener=None):
    """``call(system, text) -> str`` for one Messages API request per call, TIMEOUT seconds
    in all. A refusal or a cut-off answer returns "" (never translated, never retried)."""
    def call(system: str, text: str) -> str:
        return bounded(lambda: _post(system, text), TIMEOUT)

    def _post(system: str, text: str) -> str:
        body = json.dumps({"model": MODEL, "max_tokens": 4096, "system": system,
                           "output_config": {"effort": "low"},
                           "messages": [{"role": "user", "content": text}]}).encode()
        req = urllib.request.Request(API_URL, data=body, method="POST", headers={
            "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        try:
            with (opener or _OPENER)(req, timeout=TIMEOUT) as r:
                data = r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            e.close()
            if e.code in (401, 403):
                raise AuthError(f"http {e.code}") from None
            raise CallError(f"http {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):  # a timeout is an OSError
            raise CallError("unreachable") from None
        try:
            msg = json.loads(data) if len(data) <= MAX_RESPONSE else None
            if not isinstance(msg, dict) or not isinstance(msg.get("stop_reason"), str):
                raise ValueError
            if msg["stop_reason"] != "end_turn":
                return ""
            return "".join(b["text"] for b in msg["content"] if b.get("type") == "text")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise CallError("bad response") from None
    return call
