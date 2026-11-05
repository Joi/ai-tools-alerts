"""aitools-alerts: the member CLI.

    aitools-alerts init [--make-key] [--force]
    aitools-alerts keygen
    aitools-alerts pull [--mirror-url URL]
    aitools-alerts check [--json]
    aitools-alerts notify
    aitools-alerts plan <advisory-id>
    aitools-alerts run
    aitools-alerts curator post|amend|retract ...   (needs the curator extra)

Nothing here executes a string from a post. ``plan`` prints commands built
from fixed templates keyed by the product's ecosystem; it runs none of them.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shlex
import sys
from dataclasses import asdict, dataclass
from urllib.parse import quote

from . import TRUST_ROOT_PUBKEY, __version__, check, config, curator, inventory, nostr, notify, pull, relay, schema
from .state import State, StateError

TRUST_ROOT_ENV = "AITOOLS_ALERTS_TRUST_ROOT"
EXIT_UNSEEN_CRITICAL = 2

# ecosystem -> argv template for an upgrade; "{fixed}" is products[].fixed,
# which the schema restricts to digits, dots and a lowercase suffix.
UPGRADE_TEMPLATES = {
    "claude-code": ("npm", "install", "-g", "@anthropic-ai/claude-code@{fixed}"),
    "codex": ("npm", "install", "-g", "@openai/codex@{fixed}"),
    "gemini-cli": ("npm", "install", "-g", "@google/gemini-cli@{fixed}"),
}

PAIRING_STEPS = """\
To post or discuss on the ai-tools Buzz relay (reading alerts needs no account):
  1. Send the npub above to the ai-tools relay admin and ask to be added.
  2. In the Buzz app, sign in with the key in {path} (keep that file private;
     it is your secret key and is never printed).
  3. Open #security-feed and #security-critical once you are added."""


def _err(msg: str) -> None:
    print(f"aitools-alerts: {msg}", file=sys.stderr)


def _root(s: config.Settings) -> tuple[str, list[str]]:
    """(root, ignored env vars). The variable counts only with trust_root_override:
    a project's environment reaches the hook and must not silence alerts."""
    env = os.environ.get(TRUST_ROOT_ENV)
    if env is None:
        return TRUST_ROOT_PUBKEY, []
    if not s.trust_root_override:
        _err(f"ignoring {TRUST_ROOT_ENV}: trust_root_override is not set in config.toml")
        return TRUST_ROOT_PUBKEY, [TRUST_ROOT_ENV]
    if not nostr._is_hex(env, 32):
        raise SystemExit(f"aitools-alerts: {TRUST_ROOT_ENV} must be 64 lowercase hex characters")
    _err(f"warning: trust root overridden by {TRUST_ROOT_ENV} (for tests only)")
    return env, []


def upgrade_command(ecosystem: str, fixed: str | None) -> list[str] | None:
    t = UPGRADE_TEMPLATES.get(ecosystem)
    if t is None or not fixed:
        return None
    return [a.format(fixed=fixed) for a in t]


# ------------------------------------------------------------------ commands

def _make_key() -> int:
    path = config.key_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    sec, pub = nostr.keygen()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _err(f"{path} exists; not replacing a key")
        return 1
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(nostr.nsec(sec) + "\n")
    print(f"wrote {path} (mode 600)")
    print(f"npub: {nostr.npub(pub)}")
    print(PAIRING_STEPS.format(path=path))
    return 0


def cmd_init(a) -> int:
    path = config.config_path()
    if a.make_key and config.key_path().exists():
        _err(f"{config.key_path()} exists; not replacing a key")
        return 1
    if path.exists() and not a.force:
        if not a.make_key:
            _err(f"{path} exists; use --force to overwrite it")
            return 1
        print(f"kept {path}")
    else:
        config.write_default(force=a.force)
        print(f"wrote {path}")
    return _make_key() if a.make_key else 0


def cmd_keygen(a) -> int:
    a.force = False
    a.make_key = True
    return cmd_init(a)


def _pull(a, st: State, url: str) -> pull.PullResult:
    return pull.fetch(url, st, root_pubkey=a.root)


def cmd_pull(a, st: State, s: config.Settings) -> int:
    url = config.check_mirror_url(a.mirror_url) if a.mirror_url else s.mirror_url
    res = _pull(a, st, url)
    if res.error:
        _err(res.error)
        return 1
    dropped = ", ".join(f"{k} {v}" for k, v in sorted(res.dropped.items())) or "none"
    print(f"pulled manifest v{res.manifest.version}: {len(res.new_events)} new events, "
          f"{len(st.events)} stored, dropped: {dropped}")
    return 0


@dataclass(frozen=True)
class Entry:
    """One advisory as check, plan and notify show it: every current root
    (thread) a poster role posted under one advisory id with equal content.
    A critical has one root per channel. ``root_id`` is the first root."""
    root_id: str
    root_ids: tuple[str, ...]
    adv: schema.Advisory
    translations: dict  # lang -> text, of the first root


def _entries(threads: list, warned: set) -> list[Entry]:
    """Group threads by (advisory id, poster role), in reader order; the first
    root is shown. Only copies whose advisories are equal merge: copies that
    differ (an update one root has not had yet) stay apart, so no copy's match
    or notification is dropped, and stderr says so once per advisory."""
    groups: dict[tuple[str, str], list[list]] = {}
    for t in threads:
        copies = groups.setdefault((t.adv.id.casefold(), t.adv.posted_by), [])
        same = next((c for c in copies if c[0].adv == t.adv), None)
        if same is None:
            copies.append([t])
        else:
            same.append(t)
    out = []
    for key, copies in groups.items():
        if len(copies) > 1 and key not in warned:
            warned.add(key)
            _err(f"copies of {copies[0][0].adv.id} differ; listing each")
        out += [Entry(c[0].root_id, tuple(t.root_id for t in c), c[0].adv, c[0].translations)
                for c in copies]
    return out


def _seen(t: Entry, st: State) -> bool:
    return not st.seen.isdisjoint(t.root_ids)


def _tr(t: Entry, s: config.Settings) -> str | None:
    """The translation to show for ``t``, or None: English."""
    return t.translations.get(s.lang) if s.lang != "en" else None


def _title(t: Entry, s: config.Settings) -> str:
    tr = _tr(t, s)
    return pull.translation_title(tr, t.adv.id) if tr else t.adv.title


def _thread_ref(t: Entry) -> str:
    if len(t.root_ids) == 1:
        return f"thread {t.root_id[:12]}"
    return "threads " + ", ".join(r[:12] for r in t.root_ids)


def _matches(a, st: State) -> tuple[list, list]:
    """Current advisories (one Entry per advisory id and poster role), and
    (entry, Match) pairs for this machine. State pulled under another trust
    root is not used."""
    if st.manifest is not None and st.manifest_root != a.root:
        _err("the stored state was pulled under another trust root; run: aitools-alerts pull")
        return [], []
    threads = _entries(pull.active(pull.advisories(st)), a.__dict__.setdefault("warned", set()))
    ms = check.match([t.adv for t in threads], inventory.collect())
    by_adv = {id(t.adv): t for t in threads}
    return threads, [(by_adv[id(m.adv)], m) for m in ms]


def _source(adv) -> tuple[str, bool]:
    """The link to give the person, and whether it is a primary source: the
    first primary source, else the first. Percent-encoded to URL ASCII, so a
    space in a posted URL cannot put more text on the line that carries it."""
    domains = schema.load_primary_domains()
    url = next((s.url for s in adv.sources if schema.is_primary(s.url, domains)), None)
    primary = url is not None
    return quote(url if primary else adv.sources[0].url, safe=":/?#[]@!$&'()*+,;=%~"), primary


def _source_line(adv) -> str:
    url, primary = _source(adv)
    return f"  source: {url}" if primary else f"  source: {url} (not a primary source)"


def _match_json(t, m) -> dict:
    source, primary = _source(t.adv)
    return {"thread": t.root_id, "threads": list(t.root_ids), "id": t.adv.id, "level": t.adv.level, "title": t.adv.title,
            "posted_by": t.adv.posted_by, "reason": m.reason, "source": source,
            "source_primary": primary, "sources": [asdict(x) for x in t.adv.sources],
            "installed": asdict(m.installed), "product": asdict(m.product) if m.product else None,
            "actions": [asdict(x) for x in m.actions_allowed],
            "translations": dict(t.translations)}


def cmd_check(a, st: State, s: config.Settings) -> int:
    threads, pairs = _matches(a, st)
    if a.json:
        print(json.dumps([_match_json(t, m) for t, m in pairs], indent=2))
        return 0
    if not st.last_pull.get("last_ok_at"):
        print("no successful pull yet; run: aitools-alerts pull")
    for t, m in pairs:
        ver = m.installed.version or "unknown version"
        print(f"{t.adv.level.upper()}: {_title(t, s)} [{m.installed.name} {ver}: {m.reason}] "
              f"(id {t.adv.id}, {_thread_ref(t)})")
    matched = {t.root_id for t, _ in pairs}
    other = [t for t in threads if t.adv.level == "critical" and t.root_id not in matched]
    if other:
        print("Critical advisories not installed here:")
        for t in other:
            print(f"  CRITICAL: {_title(t, s)} (id {t.adv.id}, {_thread_ref(t)})")
    print(f"{len(threads)} advisories, {len(pairs)} matches on this machine")
    return 0


def _unseen_critical(a, st: State) -> list:
    _, pairs = _matches(a, st)
    return [(t, m) for t, m in pairs if t.adv.level == "critical" and not _seen(t, st)]


def _notify(st: State, s: config.Settings, pending) -> int:
    """Send each pending advisory once, under the state lock: a concurrent
    run waits, then re-reads seen and skips what this one already sent. Every
    root of an advisory is marked seen; one seen root makes it seen."""
    if not pending:
        return 0
    if not s.notify:
        _err("no notify channel configured")
        return 1
    status = 0
    with st.locked():
        for t, m in pending:
            if _seen(t, st):
                continue  # sent already (by this run, or a concurrent one)
            text = notify.format_text(t.adv, m, _tr(t, s))
            accepted = False
            for ch in s.notify:
                r = notify.send(ch, text, s)
                print(f"{ch}: {r.detail}")
                accepted = accepted or r.accepted
            if accepted:
                st.seen.update(t.root_ids)
                st.save_seen()
            else:
                status = 1
    return status


def cmd_notify(a, st: State, s: config.Settings) -> int:
    return _notify(st, s, _unseen_critical(a, st))


def cmd_plan(a, st: State, s: config.Settings) -> int:
    threads, pairs = _matches(a, st)
    wanted = [t for t in threads if a.advisory_id in (*t.root_ids, t.adv.id)]
    if not wanted:
        _err(f"no current advisory {a.advisory_id!r}")
        return 1
    hits = [(t, m) for t, m in pairs if t in wanted]
    if not hits:
        print(f"{_title(wanted[0], s)}: nothing installed here is affected")
        return 0
    cfg = s.check_config()
    for t, m in hits:
        p = check.plan(m, cfg)
        print(f"{t.adv.level.upper()}: {_title(t, s)} [{m.installed.name} "
              f"{m.installed.version or 'unknown version'}] posted by {t.adv.posted_by}")
        tr = _tr(t, s)  # quoted with "> ": translated text, never a section or a command
        for line in (tr.split("\n")[1:] if tr else []):
            print(f"    > {line}".rstrip())
        print(_source_line(t.adv))
        for title, actions in (("auto-apply (opted in)", p.auto_apply),
                               ("prepare (ask first)", p.prepare)):
            if not actions:
                continue
            print(f"  {title}:")
            for x in actions:
                print(f"    {check.describe(x)}")
                if x.verb == "upgrade" and m.product is not None:
                    argv = upgrade_command(m.product.ecosystem, x.value)
                    if argv:
                        print(f"      command: {shlex.join(argv)}")
                    elif not x.value:
                        print("      no fixed version given: notify only, no command")
                    else:
                        print("      no command template; upgrade with your package manager")
    print("nothing was executed")
    return 0


def cmd_run(a, st: State, s: config.Settings) -> int:
    """pull, check, notify. --json prints one object; --quiet prints nothing
    on stdout. Exit 2 when a critical match was unseen at the start."""
    res = _pull(a, st, s.mirror_url)
    if res.error:
        _err(f"{res.error} (using the last good state)")
    pending = _unseen_critical(a, st)
    if a.json:
        _, pairs = _matches(a, st)
        out = {"pull_error": res.error, "ignored_env": a.ignored_env, "matches": [_match_json(t, m) for t, m in pairs],
               "unseen_critical": sorted({r for t, _ in pending for r in t.root_ids})}
    elif not a.quiet:
        a.json = False
        cmd_check(a, st, s)
    if a.quiet or a.json:
        with contextlib.redirect_stdout(io.StringIO()):
            status = _notify(st, s, pending)
    else:
        status = _notify(st, s, pending)
    if a.json:
        print(json.dumps(out, indent=2))
    return EXIT_UNSEEN_CRITICAL if pending else status


# ---------------------------------------------------------------------- main

def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="aitools-alerts", description="ai-tools security alerts")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="write the config; --make-key also makes a Buzz key")
    p.add_argument("--make-key", action="store_true")
    p.add_argument("--force", action="store_true", help="overwrite an existing config")
    sub.add_parser("keygen", help="same as init --make-key")
    p = sub.add_parser("pull", help="fetch and verify the signed mirror")
    p.add_argument("--mirror-url")
    p = sub.add_parser("check", help="match advisories against this machine")
    p.add_argument("--json", action="store_true")
    sub.add_parser("notify", help="send unseen critical matches")
    p = sub.add_parser("plan", help="print the actions and commands for one advisory")
    p.add_argument("advisory_id")
    p = sub.add_parser("run", help="pull, check and notify; exit 2 on an unseen critical")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true", help="print one JSON object")
    g.add_argument("--quiet", action="store_true", help="print nothing on stdout")
    curator.add_parser(sub)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
        if a.cmd == "init":
            return cmd_init(a)
        if a.cmd == "keygen":
            return cmd_keygen(a)
        s = config.load()
        a.root, a.ignored_env = _root(s)
        if a.cmd == "curator":
            return curator.cmd_curator(a, State.load())
        st = State.load()
        return {"pull": cmd_pull, "check": cmd_check, "notify": cmd_notify,
                "plan": cmd_plan, "run": cmd_run}[a.cmd](a, st, s)
    except (config.ConfigError, StateError, curator.CuratorError, relay.RelayError) as e:
        _err(str(e))
        return 1
    except OSError as e:  # e.g. the state directory is not writable
        _err(f"{type(e).__name__}: {e.strerror or e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
