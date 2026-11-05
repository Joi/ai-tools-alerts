"""The curator subcommand: sign and send a post, an amendment or a retraction.

    aitools-alerts curator post --level L --title T --product NAME --ecosystem E
        [--affected A] [--fixed V] [--action verb:target[:value]]... --source URL...
        [--id ID] [--alias X]... [--severity S] [--expires-at TS] [--channel feed|critical]
    aitools-alerts curator amend <event-id|advisory-id> [--level L] [--fixed [NAME=]V]
        [--title T] [--source URL]... [--action ...]... [--expires-at TS | --no-expiry]
        [--note TEXT] [--no-pull]
    aitools-alerts curator retract <event-id|advisory-id> [--reason TEXT] [--no-pull]

Every command takes --dry-run (print the signed events, send nothing) and
--relay-url. A critical post goes to the critical channel and the feed.
amend and retract pull the mirror first, and reply to every open thread of
an advisory id. A retraction is idempotent: retract also replies to a thread
the stored state already holds as retracted, and says so on stderr. The key
is read from config.key_path() (mode 600, never argv).
Events follow the reader rules in pull.advisories: a root has no e tag; a
reply carries the root-marked e tag; ``retract`` or ``level: high|notice``
as the first line; any other change is a block holding the changed fields.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

from . import TRUST_ROOT_PUBKEY, check, config, manifest, nostr, pull, relay, schema
from .poster import compose
from .state import State

KIND = 9
_RANK = {"notice": 1, "high": 2, "critical": 3}
_SEC = re.compile(r"[0-9a-f]{64}")


class CuratorError(Exception):
    pass


# ------------------------------------------------------------------ key, channels, manifest

def read_key(path: Path | None = None) -> str:
    """The curator's secret key (hex) from a private file. Errors never carry
    the file's content."""
    path = Path(path) if path is not None else config.key_path()
    why = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # a FIFO never blocks
    except FileNotFoundError:
        why = "missing (run: aitools-alerts keygen)"
    except OSError:
        why = "unreadable or a symlink"
    if why is None:
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                why = "not a regular file"
            elif st.st_mode & 0o077 or st.st_uid != os.getuid():
                why = "not private to you (chmod 600)"
            else:
                raw = f.read(1025)
        if why is None:
            text = raw.decode("ascii", "replace").strip() if len(raw) <= 1024 else ""
            sec = None
            if text.startswith("nsec1"):
                try:
                    sec = nostr.nsec_to_hex(text)
                except ValueError:
                    sec = None
            elif _SEC.fullmatch(text) and 1 <= int(text, 16) < nostr.N:
                sec = text
            if sec is not None:
                return sec
            why = "not a valid nsec"
    raise CuratorError(f"cannot use the curator key at {path}: {why}")


def channels() -> dict[str, str]:
    data = json.loads((schema.SPEC_DIR / "channels.json").read_text(encoding="utf-8"))
    return {"feed": data["feed"], "critical": data["critical"]}


def role_manifest(st: State, root: str):
    """The newest manifest known for this root: the one accepted under it in
    the state, or the bundled one under the pinned root, whichever is newer.
    Never another root's: a test-root pull cannot roll back a revocation."""
    have = [x for x in (st.accepted(root), pull.bundled_manifest() if root == TRUST_ROOT_PUBKEY else None)
            if x is not None]
    return max(have, key=lambda x: x.version) if have else None


def _curator_pub(sec: str, m, root: str) -> str:
    if m is None or not manifest.verify(m, root):
        raise CuratorError("no manifest that verifies under the trust root; run: aitools-alerts pull")
    pub = nostr.pubkey_gen(bytes.fromhex(sec)).hex()
    if manifest.role_of(m, pub) != "curator":
        raise CuratorError(f"key {nostr.npub(pub)} has no curator role in manifest v{m.version}")
    return pub


def _sign(sec: str, tags: list, content: str, now: int) -> dict:
    return nostr.sign_event(sec, {"created_at": now, "kind": KIND, "tags": tags, "content": content})


# ------------------------------------------------------------------ post

def parse_action(text: str) -> schema.Action:
    parts = text.split(":", 2)
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise argparse.ArgumentTypeError(f"{text!r}: expected verb:target[:value]")
    return schema.Action(parts[0], parts[1], parts[2] if len(parts) > 2 and parts[2] else None)


def _body(adv: schema.Advisory) -> str:
    p = adv.products[0]
    lines = [f"{adv.level.upper()}: {adv.title}",
             f"Affected: {p.name} {p.affected or '(all versions)'}."
             + (f" Fixed in {p.fixed}." if p.fixed else " No fixed version yet.")]
    lines += [f"Action: {check.describe(a)}." for a in adv.actions]
    lines.append(f"Source: {next(s.url for s in adv.sources if schema.is_primary(s.url))}")
    return "\n".join(lines)


def post_events(sec: str, m, root: str, *, level, title, product, ecosystem, sources,
                affected=None, fixed=None, actions=(), adv_id=None, aliases=(), severity=None,
                expires_at=None, channel=None, now: int | None = None) -> list[dict]:
    """Signed root posts: kind 9, a channel's h tag, no e tag, body plus block.
    A critical goes to the critical channel and the feed (the feed is
    complete) unless --channel names one."""
    _curator_pub(sec, m, root)
    now = int(time.time() if now is None else now)
    ids = channels()
    chans = [channel] if channel else (["critical", "feed"] if level == "critical" else ["feed"])
    if any(c not in ids for c in chans):
        raise CuratorError(f"--channel must be one of {sorted(ids)}")
    if not any(schema.is_primary(u) for u in sources):
        raise CuratorError("no --source is on the primary-source list (spec/primary-domains.json)")
    aliases = list(aliases)
    adv_id = adv_id or (aliases[0] if aliases else
                        time.strftime("AITA-%Y%m%d-", time.gmtime(now)) + secrets.token_hex(3))
    raw = {"id": adv_id, "aliases": aliases, "level": level, "advisory_severity": severity,
           "title": title, "products": [{"name": product, "ecosystem": ecosystem,
                                          "affected": affected, "fixed": fixed}],
           "actions": [asdict(a) for a in actions],
           "sources": [{"url": u, "published_at": None} for u in sources],
           "posted_by": "curator", "posted_at": now, "expires_at": expires_at}
    try:
        adv = schema.validate(raw)
        content = schema.render_post(adv, _body(adv))
    except ValueError as e:
        raise CuratorError(f"not a valid advisory: {e}") from None
    return [_sign(sec, [["h", ids[c]]], content, now) for c in chans]


# ------------------------------------------------------------------ replies

def find_threads(st: State, root: str, ref: str, retracted_ok: bool = False) -> list:
    """[(Thread, root event)] for a root event id, or every open thread of an
    advisory id (a critical has a root in each channel); with ``retracted_ok``,
    the retracted threads too. Only state pulled under ``root`` is used."""
    if st.manifest_root != root or st.manifest is None:
        raise CuratorError("the stored state was not pulled under this trust root; run: aitools-alerts pull")
    hits = [t for t in pull.advisories(st) if ref in (t.root_id, t.adv.id)]
    if not hits:
        raise CuratorError(f"no thread {ref!r} in the pulled state; run: aitools-alerts pull")
    open_ = hits if retracted_ok else [t for t in hits if not t.retracted]
    if not open_:
        raise CuratorError(f"{ref!r} is retracted")
    return [(t, st.events[t.root_id]) for t in open_]


def _reply_tags(root_ev: dict) -> list:
    h = [t[1] for t in root_ev["tags"] if len(t) >= 2 and t[0] == "h"]
    if not h:
        raise CuratorError(f"root {root_ev['id']} has no channel tag")
    return [["h", h[0]], ["e", root_ev["id"], "", "root"]]


def _after(st: State, root_id: str, now: int) -> int:
    """A created_at that sorts after every stored event of the thread, so the
    readers apply this reply last."""
    last = max([ev["created_at"] for ev in st.events.values()
                if ev["id"] == root_id or pull._thread_ref(ev) == root_id] or [0])
    return max(now, last + 1)


def _replayed(st: State, ev: dict, root_id: str):
    """The thread as pull.advisories builds it with ``ev`` added."""
    m, evs = st.roots[st.manifest_root]
    view = State(dir=st.dir, roots={**st.roots, st.manifest_root: [m, {**evs, ev["id"]: ev}]},
                 manifest_root=st.manifest_root)
    return next(t for t in pull.advisories(view) if t.root_id == root_id)


def _one_line(text: str | None, what: str) -> str:
    if text is None:
        return ""
    if schema._LINES.search(text) or "```" in text or "~~~" in text or len(text) > 500:
        raise CuratorError(f"{what}: one line of at most 500 characters, no code fences")
    return text.strip()


def amend_event(sec: str, m, root: str, st: State, thread, root_ev: dict, *, level=None,
                fixed=None, title=None, sources=(), actions=None, expires_at=None,
                no_expiry=False, note=None, now: int | None = None) -> dict:
    """A signed reply that changes the thread; refused unless the readers,
    replaying the stored thread with it, reach exactly the merged advisory."""
    _curator_pub(sec, m, root)
    prev = thread.adv
    old = asdict(prev)
    new = json.loads(json.dumps(old))
    lower = None
    if level is not None and level != prev.level:
        if level not in _RANK:
            raise CuratorError("--level must be critical, high or notice")
        if _RANK[level] < _RANK[prev.level]:
            lower = level  # the convention line: readers apply it as lower-only
        else:
            new["level"] = level
    if fixed is not None:
        name, _, ver = fixed.rpartition("=")
        hits = [p for p in new["products"] if not name or p["name"] == name]
        if len(hits) != 1:
            raise CuratorError("--fixed: give NAME=VERSION naming one product")
        hits[0]["fixed"] = ver
        for a in new["actions"]:
            if a["verb"] == "upgrade" and a["target"] == hits[0]["name"]:
                a["value"] = ver
    if title is not None:
        new["title"] = title
    for u in sources:
        if u not in {s["url"] for s in new["sources"]}:
            new["sources"].append({"url": u, "published_at": None})
    if actions is not None:
        new["actions"] = [asdict(a) for a in actions]
    if no_expiry:
        new["expires_at"] = None
    elif expires_at is not None:
        new["expires_at"] = expires_at
    patch = {k: v for k, v in new.items() if v != old[k]}
    if not patch and lower is None:
        raise CuratorError("nothing to change")
    try:
        merged = compose.apply_patch(replace(prev, level=lower or prev.level), patch)
    except ValueError as e:
        raise CuratorError(f"the amended advisory is not valid: {e}") from None
    # The first line is always ours: a note can never read as retract or level.
    lines = [f"level: {lower}" if lower else f"Amended: {merged.title}"]
    note = _one_line(note, "--note")
    if note:
        lines.append(note)
    content = "\n".join(lines)
    if patch:
        content += f"\n\n```{schema.INFO_STRING}\n{json.dumps(patch, indent=2, ensure_ascii=False)}\n```\n"
    now = _after(st, thread.root_id, int(time.time() if now is None else now))
    ev = _sign(sec, _reply_tags(root_ev), content, now)
    t = _replayed(st, ev, thread.root_id)
    if t.retracted or t.adv != merged:
        raise CuratorError("the readers would not apply this amendment as written")
    return ev


def retract_event(sec: str, m, root: str, st: State, thread, root_ev: dict, *, reason=None,
                  now: int | None = None) -> dict:
    """A signed reply whose first line is ``retract``."""
    _curator_pub(sec, m, root)
    reason = _one_line(reason, "--reason")
    now = _after(st, thread.root_id, int(time.time() if now is None else now))
    ev = _sign(sec, _reply_tags(root_ev), "retract" + (f"\n{reason}" if reason else ""), now)
    if not _replayed(st, ev, thread.root_id).retracted:
        raise CuratorError("the readers would not apply this retraction")
    return ev


# ------------------------------------------------------------------ CLI

def add_parser(sub) -> None:
    cur = sub.add_parser("curator", help="sign and send a curator post, amendment or retraction")
    csub = cur.add_subparsers(dest="curator_cmd", required=True)

    def common(p):
        p.add_argument("--dry-run", action="store_true", help="print the signed events; send nothing")
        p.add_argument("--relay-url", default=relay.RELAY_URL)

    def reply(p):
        common(p)
        p.add_argument("ref", help="root event id, or advisory id (every open thread of it)")
        p.add_argument("--no-pull", action="store_true",
                       help="use the stored state; do not pull the mirror first")

    p = csub.add_parser("post", help="a new advisory")
    common(p)
    p.add_argument("--channel", choices=("feed", "critical"),
                   help="one channel only (default: critical posts to critical and feed)")
    p.add_argument("--level", required=True, choices=sorted(_RANK))
    p.add_argument("--title", required=True)
    p.add_argument("--product", required=True)
    p.add_argument("--ecosystem", required=True)
    p.add_argument("--affected")
    p.add_argument("--fixed")
    p.add_argument("--action", action="append", default=[], type=parse_action)
    p.add_argument("--source", action="append", required=True)
    p.add_argument("--id", dest="adv_id")
    p.add_argument("--alias", action="append", default=[])
    p.add_argument("--severity")
    p.add_argument("--expires-at", type=int)
    p = csub.add_parser("amend", help="change a thread (lower level, fixed, sources, ...)")
    reply(p)
    p.add_argument("--level", choices=sorted(_RANK))
    p.add_argument("--fixed", help="VERSION, or NAME=VERSION")
    p.add_argument("--title")
    p.add_argument("--source", action="append", default=[])
    p.add_argument("--action", action="append", type=parse_action)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--expires-at", type=int)
    g.add_argument("--no-expiry", action="store_true")
    p.add_argument("--note")
    p = csub.add_parser("retract", help="retract a thread")
    reply(p)
    p.add_argument("--reason")


def cmd_curator(a, st: State) -> int:
    sec = read_key()
    if a.curator_cmd == "post":
        evs = post_events(sec, role_manifest(st, a.root), a.root, level=a.level, title=a.title,
                          product=a.product, ecosystem=a.ecosystem, affected=a.affected,
                          fixed=a.fixed, actions=a.action, sources=a.source, adv_id=a.adv_id,
                          aliases=a.alias, severity=a.severity, expires_at=a.expires_at,
                          channel=a.channel)
    else:
        if not a.no_pull:  # amend against the newest thread the mirror has
            res = pull.fetch(config.load().mirror_url, st, root_pubkey=a.root)
            if res.error:
                raise CuratorError(f"pull failed ({res.error}); retry, or pass --no-pull")
        m = role_manifest(st, a.root)
        _curator_pub(sec, m, a.root)  # a revocation the pull just fetched refuses here
        evs = []
        pairs = find_threads(st, a.root, a.ref, retracted_ok=a.curator_cmd == "retract")
        for t, root_ev in pairs:
            if a.curator_cmd == "retract":
                if t.retracted:
                    print(f"{t.root_id}: already retracted locally; posting the retraction anyway",
                          file=sys.stderr)
                evs.append(retract_event(sec, m, a.root, st, t, root_ev, reason=a.reason))
                continue
            try:
                evs.append(amend_event(sec, m, a.root, st, t, root_ev, level=a.level,
                                       fixed=a.fixed, title=a.title, sources=a.source,
                                       actions=a.action, expires_at=a.expires_at,
                                       no_expiry=a.no_expiry, note=a.note))
            except CuratorError as e:
                if str(e) != "nothing to change" or len(pairs) == 1:
                    raise
                print(f"{t.root_id}: already up to date, skipped")  # e.g. a retry after a partial send
        if not evs:
            raise CuratorError("nothing to change")
    if a.dry_run:
        print(json.dumps(evs, indent=2, ensure_ascii=False))
        return 0
    if a.curator_cmd == "post":
        print(f"advisory {schema.parse_post(evs[0]['content']).id}")
    m = role_manifest(st, a.root)
    for i, ev in enumerate(evs):
        try:
            eid, ok, msg = relay.send(ev, a.relay_url, sec, manifest=m, root_pubkey=a.root)
        except relay.RelayError as e:
            raise CuratorError(f"{e}{_recovery(a, evs, i)}") from None
        print(f"{eid}: {'accepted' if ok else 'rejected'}" + (f" ({msg})" if msg else ""))
        if not ok:
            print(_recovery(a, evs, i).strip())
            return 1
    return 0


def _recovery(a, evs: list, i: int) -> str:
    """What to run after a send failed at event i of several."""
    if i == 0:
        return ""
    if a.curator_cmd == "post":
        adv = schema.parse_post(evs[i]["content"])
        chan = next(k for k, v in channels().items() if v == evs[i]["tags"][0][1])
        return (f"; {i} of {len(evs)} sent. To finish, post again with --id {adv.id} "
                f"--channel {chan} (same advisory id)")
    return f"; {i} of {len(evs)} sent. Rerun the same command: threads already changed are skipped"
