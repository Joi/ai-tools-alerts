#!/usr/bin/env python3
"""Export the ai-tools alert channels to the static mirror (Task C1).

Runs on the relay VM from a checkout of ai-tools-alerts (the systemd user
timer in this directory, every 5 minutes):

    python3 -I mirror/export_mirror.py --channels spec/channels.json \\
        --manifest trust/manifest.json --out /home/relay/alerts-mirror

For each channel in spec/channels.json it reads the channel's events from the
relay's PostgreSQL with one psql query, re-verifies every event's id and
BIP-340 signature and drops (and counts) the failures, keeps only kind 9
(NIP-29 group chat message) events signed by a poster in the current
manifest, then writes feed.json, critical.json,
feed.atom, index.html and manifest.json into --out, each to a
temp file in that directory and then os.replace. Nothing is written unless
every channel read and the manifest check succeed, so a failed run leaves the
previous files served.

Exit codes: 0 written, 1 refused or a read failed (nothing written), 2 usage.
Standard library plus this repo's aitools_alerts package only.
"""

import argparse
import html
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
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from aitools_alerts import TRUST_ROOT_PUBKEY, nostr, pull, schema  # noqa: E402
from aitools_alerts import manifest as mf  # noqa: E402
from aitools_alerts.state import State  # noqa: E402

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
CHAT_KIND = 9  # NIP-29 group chat message: the only kind posters and curators send
PIPX_LINE = "pipx install git+https://github.com/Joi/ai-tools-alerts"  # README's, verbatim
REPO_URL = "https://github.com/Joi/ai-tools-alerts"
RELAY_HOST = "buzz.ai-tools.md"
INDEX_LIMIT = 20
# The CLI refuses a channel file over 8 MiB or 10,000 events (pull.MAX_FETCH_BYTES,
# pull.MAX_EVENTS). Each file keeps its newest events within half of both, so no
# poster, however many or large its posts, can make the mirror unreadable.
MAX_CHANNEL_EVENTS = 2000
MAX_CHANNEL_BYTES = 4 << 20
URL_REFUSED = frozenset("\"'<>\\ \t\r\n")  # browsers read a backslash as a slash
ATOM_SUBTITLE = ("Security alerts for people who run AI agents on their own machines. This feed is "
                 "for humans and feed readers; agents use the aitools-alerts CLI, which verifies "
                 "each alert's signature (" + REPO_URL + ").")


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


def clean(rows, m) -> tuple[list[dict], Counter]:
    """Keep rows that are NIP-01 events whose id and signature verify, whose
    kind is 9 and whose pubkey is a poster in manifest m.

    The relay also stores NIP-29 admin events in a channel (kinds 9000-9020,
    39000-39003, 40099...), signed by the relay-bot key with no e tag: they
    are not posts, and every reader would otherwise take them for roots
    (counted other_kind). The relay is members-only and the mirror is its
    only public surface, so a member's discussion reply, and every post by a
    key the manifest no longer lists (a revoked poster), stays off the mirror
    (counted not_poster)."""
    kept, counts = [], Counter()
    for row in rows:
        if not isinstance(row, dict):
            counts["malformed"] += 1
            continue
        ev = {k: row[k] for k in NIP01_KEYS if k in row}
        if len(ev) != len(NIP01_KEYS) or not nostr.verify_event(ev):
            counts["bad_sig"] += 1
            continue
        if ev["kind"] != CHAT_KIND:
            counts["other_kind"] += 1
            continue
        if mf.role_of(m, ev["pubkey"]) is None:
            counts["not_poster"] += 1
            continue
        kept.append(ev)
    counts["kept"] = len(kept)
    return kept, counts


def _event_size(ev: dict) -> int:
    return len(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1


def cap(events: dict[str, list[dict]], m, generated_at: str) -> tuple[dict[str, list[dict]], dict[str, int]]:
    """Each channel's events within MAX_CHANNEL_EVENTS and, as the written
    file, MAX_CHANNEL_BYTES, in their original (query) order, with the count
    dropped per channel.

    Threads (a root and every reply marked to it, in either channel) are kept
    or dropped whole, newest thread first, across both channels together, so a
    kept root never loses the retraction, level change or patch that amends it,
    wherever that was posted. A thread that does not fit is skipped and the
    next older one is tried, so one oversized event costs only its thread.

    A skipped thread still sends its curator replies (retractions, level
    changes, patches), newest first, each as far as it fits: a CLI that cached
    the root in an earlier pull keeps every event it stored, so a correction
    must still reach it when its thread has outgrown the cap. Without the root
    the page does not show the thread."""
    def key(ev):
        return _reply_target(ev) or ev["id"]

    newest: dict[str, tuple] = {}
    for evs in events.values():
        for ev in evs:
            k = key(ev)
            newest[k] = max(newest.get(k, (0, "")), (ev["created_at"], ev["id"]))
    count = {name: 0 for name in events}
    budget = {name: MAX_CHANNEL_BYTES - len(channel_doc(name, [], generated_at)) for name in events}
    members: dict[str, dict[str, list[int]]] = {}
    for name, evs in events.items():
        for i, ev in enumerate(evs):
            members.setdefault(key(ev), {}).setdefault(name, []).append(i)
    keep = {name: set() for name in events}
    for k in sorted(newest, key=newest.get, reverse=True):
        parts = members[k]
        need = {name: (len(ix), sum(_event_size(events[name][i]) for i in ix)) for name, ix in parts.items()}
        if any(count[n] + c > MAX_CHANNEL_EVENTS or b > budget[n] for n, (c, b) in need.items()):
            salvage = [(events[n][i]["created_at"], events[n][i]["id"], n, i)
                       for n, ix in parts.items() for i in ix
                       if events[n][i]["id"] != k and _reply_target(events[n][i]) == k
                       and mf.role_of(m, events[n][i]["pubkey"]) == "curator"]
            for _, _, n, i in sorted(salvage, reverse=True):
                size = _event_size(events[n][i])
                if count[n] + 1 <= MAX_CHANNEL_EVENTS and size <= budget[n]:
                    count[n] += 1
                    budget[n] -= size
                    keep[n].add(i)
            continue
        for n, (c, b) in need.items():
            count[n] += c
            budget[n] -= b
            keep[n].update(parts[n])
    out = {name: [ev for i, ev in enumerate(evs) if i in keep[name]] for name, evs in events.items()}
    return out, {name: len(events[name]) - len(out[name]) for name in events}


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


def _first_line(content: str) -> str | None:
    """The first non-blank line, or None when there is none."""
    for line in _lines(content):
        if line.strip():
            return line.strip()[:200]
    return None


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
    # A root with no text has no title: never an "(untitled)" entry.
    roots = [ev for ev in dated
             if _is_root(ev) and mf.role_of(m, ev["pubkey"]) is not None
             and _first_line(ev["content"]) is not None]

    def updated(ev):
        # A withdrawal must move updated strictly past the published root's,
        # even when the retraction's own clock says earlier.
        if ev["id"] in retraction:
            return max(ev["created_at"] + 1, retraction[ev["id"]]["created_at"])
        return ev["created_at"]
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
    sub(feed, "subtitle", ATOM_SUBTITLE)
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


def _esc(s: str) -> str:
    return html.escape(_xml_safe(s), quote=True)


def _threads(events: dict[str, dict], m, now: int) -> list:
    """The threads the CLI would build from these events under manifest m:
    the reader's whole-thread retention, then pull.advisories, over an
    in-memory state (never loaded or saved)."""
    # pull.advisories reads pull.effective_manifest, which prefers the
    # checkout's bundled trust/manifest.json when it is newer than m; the unit
    # passes that same file as --manifest, so both are one manifest.
    kept = pull._retain(events, now, pull.PullResult())
    st = State(dir=Path("/nonexistent"), roots={TRUST_ROOT_PUBKEY: [m, kept]},
               manifest_root=TRUST_ROOT_PUBKEY)
    return pull.advisories(st)


def _source(adv) -> tuple[str, bool]:
    """The first primary source, else the first source (as the CLI picks)."""
    url = next((s.url for s in adv.sources if schema.is_primary(s.url)), None)
    return (url, True) if url is not None else (adv.sources[0].url, False)


INDEX_STYLE = (
    "body{font:16px/1.5 system-ui,-apple-system,sans-serif;max-width:46rem;margin:2rem auto;"
    "padding:0 1rem;color:#1a1a1a;background:#fff}"
    "h1{font-size:1.6rem}h2{font-size:1.2rem;margin-top:2rem}"
    "ol{padding-left:1.2rem}li{margin:.6rem 0}"
    ".level{font-weight:700;text-transform:uppercase;font-size:.85rem}"
    ".level-critical{color:#b00020}.level-high{color:#8a4b00}.level-notice{color:#444}"
    "time,.meta{color:#555;font-size:.9rem}code{background:#f3f3f3;padding:.1rem .3rem}"
)


def index_doc(events: dict[str, list[dict]], m, channels: dict, now: int,
              mirror_url: str) -> tuple[bytes, int]:
    """The static page at the mirror's root: what this is, the latest
    advisories as the CLI reads them (synthetic tests left off), and how to
    subscribe. No scripts; every posted string is escaped. One <section> per
    block, so another language lands as one more section.

    Threads are built from both channels together, as the CLI pulls them: a
    curator reply in one channel amends or retracts a root in the other.
    Every accepted event takes part in the threads, as in the CLI; only a
    root dated past 9999-12-31, which has no date to print, is left off."""
    generated_at = _iso(now)
    union = {e["id"]: e for name in sorted(events) for e in events[name]}
    created = {eid: e["created_at"] for eid, e in union.items()}
    threads = [t for t in _threads(union, m, now) if not schema.is_synthetic(t.adv.id)
               and created[t.root_id] <= schema.MAX_TIMESTAMP]
    threads.sort(key=lambda t: (created[t.root_id], t.root_id), reverse=True)
    threads = threads[:INDEX_LIMIT]

    rows = []
    for t in threads:
        adv = t.adv
        expired = adv.expires_at is not None and adv.expires_at < now  # pull.active's rule
        title = ("Retracted: " if t.retracted else "Expired: " if expired else "") + adv.title
        url, primary = _source(adv)
        date = _iso(created[t.root_id])[:10]
        note = "" if primary else " (not a primary source)"
        rows.append(
            f'<li><span class="level level-{_esc(adv.level)}">{_esc(adv.level)}</span> '
            f"{_esc(title)}<br>"
            f'<span class="meta"><time datetime="{date}">{date}</time> · '
            f'<a href="{_esc(url)}">{_esc(url)}</a>{note}</span></li>')
    listing = "<ol>\n" + "\n".join(rows) + "\n</ol>" if rows else "<p>No advisories yet.</p>"
    atom = mirror_url + "feed.atom"
    feed_json = mirror_url + "feed.json"
    names = " and ".join(f"<code>#security-{_esc(n)}</code>" for n in sorted(channels, key=lambda n: n != "feed"))
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ai-tools security alerts</title>
<link rel="alternate" type="application/atom+xml" title="ai-tools security alerts" href="{_esc(atom)}">
<style>{INDEX_STYLE}</style>
</head>
<body>
<main>
<h1>ai-tools security alerts</h1>
<section id="about">
<h2>What this is</h2>
<p>Security alerts for people who run AI agents on their own machines: Claude Code, Codex, Cursor, Hermes, MCP servers and agent skills. Every alert is signed by a key in a trust manifest, and a small command-line tool checks the signature, compares the alert with what is installed and prepares the fix.</p>
</section>
<section id="advisories">
<h2>Latest advisories</h2>
{listing}
<p class="meta">Updated <time datetime="{generated_at}">{generated_at}</time>.</p>
</section>
<section id="subscribe">
<h2>Subscribe</h2>
<p>No account is needed for any of these:</p>
<ul>
<li>Atom feed, for you and your feed reader: <a href="{_esc(atom)}">{_esc(atom)}</a></li>
<li>The same alerts as signed JSON: <a href="{_esc(feed_json)}">{_esc(feed_json)}</a></li>
<li>Command-line tool for your agent, which verifies every alert's signature: <code>{_esc(PIPX_LINE)}</code>, then <code>aitools-alerts init</code></li>
<li>Source and instructions: <a href="{_esc(REPO_URL)}">{_esc(REPO_URL)}</a></li>
</ul>
<p>The channels {names} on {_esc(RELAY_HOST)} are for ai-tools community members; reading the relay needs a member's auth token.</p>
</section>
</main>
</body>
</html>
"""
    return doc.encode("utf-8"), len(threads)


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
    parts = urlsplit(mirror_url)
    if parts.scheme != "https" or not parts.hostname or any(c in URL_REFUSED for c in mirror_url):
        raise ExportError("--mirror-url must be an https URL with a host")
    if not mirror_url.endswith("/"):
        mirror_url += "/"
    now = int(now if now is not None else datetime.now(timezone.utc).timestamp())
    generated_at = _iso(now)

    events, counts = {}, {}
    for name, cid in channels.items():
        events[name], counts[name] = clean(reader(name, cid), m)
    events, capped = cap(events, m, generated_at)
    for name in channels:
        counts[name]["capped"] = capped[name]
    atom, entries = atom_doc(events["feed"], m, generated_at, mirror_url)
    index, listed = index_doc(events, m, channels, now, mirror_url)

    # Manifest first: a reader never sees a new poster's event before the
    # manifest naming them. The page, then the feed's Atom, go last.
    files = [("manifest.json", raw_manifest)]
    for name in sorted(channels, key=lambda n: n == "feed"):
        files.append((f"{name}.json", channel_doc(name, events[name], generated_at)))
    files.append(("index.html", index))
    files.append(("feed.atom", atom))
    for fname, data in files:
        write_atomic(out, fname, data)
    return {"channels": counts, "atom_entries": entries, "index_advisories": listed}


def summary_line(result: dict) -> str:
    parts = [f"{name} kept={c['kept']} malformed={c['malformed']} bad_sig={c['bad_sig']}"
             f" other_kind={c['other_kind']} not_poster={c['not_poster']} capped={c['capped']}"
             for name, c in result["channels"].items()]
    return ("export_mirror: " + "; ".join(parts) + f"; atom entries={result['atom_entries']}"
            f"; index advisories={result['index_advisories']}")


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
