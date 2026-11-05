#!/usr/bin/env python3
"""Export the ai-tools alert channels to the static mirror (Task C1).

Runs on the relay VM from a checkout of ai-tools-alerts (the systemd user
timer in this directory, every 5 minutes):

    python3 -I mirror/export_mirror.py --channels spec/channels.json \\
        --manifest trust/manifest.json --out /home/relay/alerts-mirror

For each channel in spec/channels.json it reads the channel's events from the
relay's PostgreSQL with one psql query, re-verifies every event's id and
BIP-340 signature and drops (and counts) the failures, then writes
feed.json, critical.json, feed.atom and manifest.json into --out, each to a
temp file in that directory and then os.replace. Nothing is written unless
every channel read and the manifest check succeed, so a failed run leaves the
previous files served.

Exit codes: 0 written, 1 refused or a read failed (nothing written), 2 usage.
Standard library plus this repo's aitools_alerts package only.
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from aitools_alerts import TRUST_ROOT_PUBKEY, nostr, schema  # noqa: E402
from aitools_alerts import manifest as mf  # noqa: E402

QUERY = (
    "SELECT json_build_object('id',encode(id,'hex'),'pubkey',encode(pubkey,'hex'),"
    "'created_at',extract(epoch from created_at)::bigint,'kind',kind,'tags',tags,"
    "'content',content,'sig',encode(sig,'hex')) FROM events "
    "WHERE channel_id = '{channel_id}' AND deleted_at IS NULL ORDER BY created_at"
)
DEFAULT_PSQL = ["docker", "exec", "buzz-prod-postgres-1", "psql", "-U", "buzz", "-d", "buzz", "-At", "-c"]
PSQL_TIMEOUT = 120
DEFAULT_MIRROR_URL = "https://buzz.ai-tools.md/alerts/"
NIP01_KEYS = ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")
CHANNELS = ("feed", "critical")  # exactly these: the file names A5 reads
_XML_ILLEGAL = re.compile(r"[^\t\n\r\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")
ATOM_NS = "http://www.w3.org/2005/Atom"
MALFORMED = None  # a psql line that is not JSON


class ExportError(Exception):
    """A refusal or read failure: nothing is written."""


# ---------------------------------------------------------------- inputs

def load_channels(path) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError) as e:
        raise ExportError(f"channels file unreadable: {e.__class__.__name__}") from None
    if not isinstance(obj, dict):
        raise ExportError("channels file must be a JSON object")
    if sorted(obj) != sorted(CHANNELS):
        raise ExportError(f"channels file must name exactly {', '.join(CHANNELS)}")
    for name, cid in obj.items():
        try:
            ok = isinstance(cid, str) and str(uuid.UUID(cid)) == cid
        except ValueError:
            ok = False
        if not ok:
            raise ExportError(f"channel {name}: id is not a canonical lowercase UUID")
    return obj


def psql_reader(prefix: list[str]):
    """A reader that runs prefix + [query] per channel (argv, no shell)."""
    def read(name: str, channel_id: str) -> list:
        argv = list(prefix) + [QUERY.format(channel_id=channel_id)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=PSQL_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise ExportError(f"channel {name}: psql timed out after {PSQL_TIMEOUT}s") from None
        except OSError as e:
            raise ExportError(f"channel {name}: psql could not run ({e.__class__.__name__})") from None
        if proc.returncode != 0:
            raise ExportError(f"channel {name}: psql exited {proc.returncode}")
        rows = []
        # psql -At ends each row with "\n"; JSON escapes "\n" inside strings
        # but not U+0085/U+2028/U+2029, which str.splitlines() would split on.
        for line in proc.stdout.split("\n"):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except (ValueError, RecursionError):
                rows.append(MALFORMED)
        return rows
    return read


def file_reader(path):
    """A reader over a JSON object {channel name: [row, ...]} (tests, acceptance)."""
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        raise ExportError(f"rows file unreadable: {e.__class__.__name__}") from None
    if not isinstance(obj, dict):
        raise ExportError("rows file must be a JSON object")

    def read(name: str, channel_id: str) -> list:
        rows = obj.get(name)
        if not isinstance(rows, list):
            raise ExportError(f"channel {name}: no rows list in the rows file")
        return rows
    return read


def clean(rows) -> tuple[list[dict], Counter]:
    """Keep rows that are NIP-01 events whose id and signature verify."""
    kept, counts = [], Counter()
    for row in rows:
        if not isinstance(row, dict):
            counts["malformed"] += 1
            continue
        ev = {k: row[k] for k in NIP01_KEYS if k in row}
        if len(ev) != len(NIP01_KEYS) or not nostr.verify_event(ev):
            counts["bad_sig"] += 1
            continue
        kept.append(ev)
    counts["kept"] = len(kept)
    return kept, counts


def check_manifest(path):
    """The manifest file's bytes and parsed Manifest, if it is signed by the root."""
    try:
        raw = Path(path).read_bytes()
        m = mf.load(raw)
    except (OSError, mf.ManifestError) as e:
        raise ExportError(f"manifest unusable: {e}") from None
    if not mf.verify(m, TRUST_ROOT_PUBKEY):
        raise ExportError("manifest is not signed by the trust root")
    return raw, m


# ---------------------------------------------------------------- rendering

def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def channel_doc(name: str, events: list[dict], generated_at: str) -> bytes:
    doc = {"generated_at": generated_at, "channel": name, "events": events}
    return (json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _xml_safe(s: str) -> str:
    return _XML_ILLEGAL.sub("", s)


def _lines(content: str) -> list[str]:
    return schema._LINES.split(content)  # CommonMark line endings, as parse_post


def _first_line(content: str) -> str:
    for line in _lines(content):
        if line.strip():
            return line.strip()[:200]
    return "(untitled)"


def _body_before_block(content: str) -> str:
    """The text before the opener of the last CLOSED aitools-alert fence,
    tracking fences the way schema._last_block does, so a block quoted
    inside another fence is not taken for the real one."""
    lines = _lines(content)
    opener, fence = None, None  # fence: (char, length, ours, opener index)
    for i, line in enumerate(lines):
        if fence is None:
            m = schema._FENCE_OPEN.match(line)
            if m:
                ch, n, info = m.group(2)[0], len(m.group(2)), m.group(3)
                if ch == "`" and "`" in info:
                    continue
                ours = ch == "`" and m.group(1) == "" and info.strip() == schema.INFO_STRING
                fence = (ch, n, ours, i)
            continue
        body = line.lstrip(" ")
        closer = body.rstrip(" \t")
        if len(line) - len(body) <= 3 and len(closer) >= fence[1] and set(closer) == {fence[0]}:
            if fence[2]:
                opener = fence[3]
            fence = None
    if opener is None:
        return content.strip()
    return "\n".join(lines[:opener]).strip()


def _reply_target(ev: dict) -> str | None:
    """The root an event replies to (NIP-10 marked tags): its e tag marked
    root, else its e tag marked reply. Unmarked e tags (mentions) are not
    replies and never retract anything."""
    marked = {t[3]: t[1] for t in ev["tags"] if len(t) >= 4 and t[0] == "e"}
    return marked.get("root") or marked.get("reply")


def _is_root(ev: dict) -> bool:
    return not any(t and t[0] == "e" for t in ev["tags"])


def atom_doc(events: list[dict], m, generated_at: str, mirror_url: str) -> bytes:
    """Atom entries for the feed channel's root posts by manifest posters.
    Feed readers cannot verify signatures, so the Atom carries only what the
    CLI would trust. A root a curator retracted keeps its entry id but is
    rewritten as a withdrawal ("Retracted: ...", the retraction's text, the
    retraction's time as updated), because readers keep entries they have
    already fetched and an entry that just disappears is never withdrawn."""
    names = {p.pubkey: p.name for p in m.posters}
    # created_at beyond 9999-12-31 has no Atom date: such an event stays in
    # the JSON (it is signed and raw) but takes no part in the Atom.
    dated = [ev for ev in events if ev["created_at"] <= schema.MAX_TIMESTAMP]
    retraction = {}
    for ev in dated:  # query order is created_at order: the latest wins
        if (mf.role_of(m, ev["pubkey"]) == "curator"
                and _lines(ev["content"])[0].strip() == "retract"):
            target = _reply_target(ev)
            if target:
                retraction[target] = ev
    roots = [ev for ev in dated
             if _is_root(ev) and mf.role_of(m, ev["pubkey"]) is not None]

    def updated(ev):
        return max(ev["created_at"], retraction[ev["id"]]["created_at"]) if ev["id"] in retraction else ev["created_at"]
    roots.sort(key=lambda ev: (updated(ev), ev["id"]), reverse=True)

    ET.register_namespace("", ATOM_NS)
    q = lambda tag: f"{{{ATOM_NS}}}{tag}"  # noqa: E731

    def sub(parent, tag, text=None, **attrs):
        el = ET.SubElement(parent, q(tag), attrs)
        if text is not None:
            el.text = _xml_safe(text)
        return el

    feed = ET.Element(q("feed"))
    sub(feed, "id", mirror_url + "feed.atom")
    sub(feed, "title", "ai-tools security alerts")
    sub(feed, "updated", _iso(updated(roots[0])) if roots else generated_at)
    sub(feed, "link", rel="self", href=mirror_url + "feed.atom")
    sub(feed, "link", rel="alternate", href=mirror_url + "feed.json")
    sub(sub(feed, "author"), "name", "ai-tools alerts")
    for ev in roots:
        adv = schema.parse_post(ev["content"])
        title = adv.title if adv is not None else _first_line(ev["content"])
        body = _body_before_block(ev["content"]) if adv is not None else ev["content"]
        if ev["id"] in retraction:
            title = "Retracted: " + title
            body = retraction[ev["id"]]["content"].strip()
        entry = sub(feed, "entry")
        sub(entry, "id", f"urn:nostr:event:{ev['id']}")
        sub(entry, "title", title)
        sub(entry, "updated", _iso(updated(ev)))
        sub(entry, "published", _iso(ev["created_at"]))
        sub(entry, "link", rel="alternate", href=mirror_url + "feed.json")
        sub(sub(entry, "author"), "name", names.get(ev["pubkey"], "unknown"))
        sub(entry, "content", body, type="text")
    xml = ET.tostring(feed, encoding="unicode")
    return ('<?xml version="1.0" encoding="utf-8"?>\n' + xml + "\n").encode("utf-8"), len(roots)


# ---------------------------------------------------------------- writing

def write_atomic(out: Path, name: str, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=out, prefix=f".{name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), 0o644)
        os.replace(tmp, out / name)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def export(channels_path, manifest_path, out, reader, mirror_url=DEFAULT_MIRROR_URL, now=None) -> dict:
    out = Path(out)
    if not out.is_dir():
        raise ExportError(f"output directory {out} does not exist")
    channels = load_channels(channels_path)
    raw_manifest, m = check_manifest(manifest_path)
    if not mirror_url.endswith("/"):
        mirror_url += "/"
    generated_at = _iso(int(now if now is not None else datetime.now(timezone.utc).timestamp()))

    events, counts = {}, {}
    for name, cid in channels.items():
        events[name], counts[name] = clean(reader(name, cid))
    atom, entries = atom_doc(events["feed"], m, generated_at, mirror_url)

    # Manifest first: a reader never sees a new poster's event before the
    # manifest naming them. The feed's Atom goes last.
    files = [("manifest.json", raw_manifest)]
    for name in sorted(channels, key=lambda n: n == "feed"):
        files.append((f"{name}.json", channel_doc(name, events[name], generated_at)))
    files.append(("feed.atom", atom))
    for fname, data in files:
        write_atomic(out, fname, data)
    return {"channels": counts, "atom_entries": entries}


def summary_line(result: dict) -> str:
    parts = [f"{name} kept={c['kept']} malformed={c['malformed']} bad_sig={c['bad_sig']}"
             for name, c in result["channels"].items()]
    return "export_mirror: " + "; ".join(parts) + f"; atom entries={result['atom_entries']}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export the ai-tools alert channels to the static mirror.")
    ap.add_argument("--channels", required=True, help="spec/channels.json")
    ap.add_argument("--manifest", required=True, help="trust/manifest.json")
    ap.add_argument("--out", required=True, help="output directory (must exist)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--psql-cmd", help="command prefix the query is appended to "
                     f"(default: {shlex.join(DEFAULT_PSQL)})")
    src.add_argument("--rows-from", help="JSON file {channel name: [row, ...]} instead of psql")
    ap.add_argument("--mirror-url", default=DEFAULT_MIRROR_URL, help="public URL of --out, for the Atom links")
    args = ap.parse_args(argv)

    try:
        if args.rows_from:
            reader = file_reader(args.rows_from)
        else:
            prefix = shlex.split(args.psql_cmd) if args.psql_cmd else DEFAULT_PSQL
            if not prefix:
                raise ExportError("--psql-cmd is empty")
            reader = psql_reader(prefix)
        result = export(args.channels, args.manifest, args.out, reader, args.mirror_url)
    except ExportError as e:
        print(f"export_mirror: {e}; nothing written", file=sys.stderr)
        return 1
    print(summary_line(result), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
