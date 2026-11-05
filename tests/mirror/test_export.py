"""Mirror exporter (Task C1). Throwaway keys only; no relay data."""
import importlib.util
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from aitools_alerts import TRUST_ROOT_PUBKEY, nostr, schema

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "mirror" / "export_mirror.py"
REAL_MANIFEST = ROOT / "trust" / "manifest.json"
ATOM = "{http://www.w3.org/2005/Atom}"
FEED_ID = "11111111-2222-4333-8444-555555555555"
CRIT_ID = "66666666-7777-4888-9999-aaaaaaaaaaaa"
NAMES = {"manifest.json", "feed.json", "critical.json", "index.html", "feed.atom", "feed.ja.atom"}

spec = importlib.util.spec_from_file_location("export_mirror", SCRIPT)
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)

ROOT_SEC, ROOT_PUB = nostr.keygen()
CUR_SEC, CUR_PUB = nostr.keygen()
BOT_SEC, BOT_PUB = nostr.keygen()
STRANGER_SEC, _ = nostr.keygen()


def advisory_post(title: str, body: str) -> str:
    adv = schema.validate({
        "id": "AITA-TEST-0101", "aliases": [], "level": "high",
        "advisory_severity": None, "title": title,
        "products": [{"name": "Example Tool", "ecosystem": "npm", "affected": "<1.2.0", "fixed": "1.2.0"}],
        "actions": [{"verb": "upgrade", "target": "Example Tool", "value": "1.2.0"}],
        "sources": [{"url": "https://example.com/advisory", "published_at": None}],
        "posted_by": "curator", "posted_at": 1793865600, "expires_at": None,
    })
    return schema.render_post(adv, body)


def ev(sec, content, created_at=1793865600, tags=(), kind=9):
    return nostr.sign_event(sec, {"created_at": created_at, "kind": kind,
                                  "tags": [list(t) for t in tags], "content": content})


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Channels file, a manifest signed by a throwaway root, an output dir."""
    monkeypatch.setattr(em, "TRUST_ROOT_PUBKEY", ROOT_PUB)
    channels = tmp_path / "channels.json"
    channels.write_text(json.dumps({"feed": FEED_ID, "critical": CRIT_ID}))
    man = nostr.sign_event(ROOT_SEC, {
        "created_at": 1793865600, "kind": 30078, "tags": [["d", "aitools-alerts-manifest"]],
        "content": json.dumps({"version": 1, "issued_at": "2026-11-05T08:00:00Z", "posters": [
            {"pubkey": CUR_PUB, "role": "curator", "name": "Curator"},
            {"pubkey": BOT_PUB, "role": "relay-bot", "name": "bot"}]}),
    })
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(man, indent=2))
    out = tmp_path / "out"
    out.mkdir()
    return channels, manifest, out


def rows_reader(feed, critical=()):
    data = {"feed": list(feed), "critical": list(critical)}
    calls = []

    def read(name, cid):
        calls.append((name, cid))
        return data[name]
    read.calls = calls
    return read


def run_export(env, reader, **kw):
    channels, manifest, out = env
    return em.export(channels, manifest, out, reader, now=1793865900, **kw)


def leftovers(out):
    return [p.name for p in out.iterdir() if p.name.startswith(".")]


# ---------------------------------------------------------------- plan tests

def test_export_writes_atomically(env, monkeypatch):
    out = env[2]
    real_replace = os.replace
    seen = []

    def spy(src, dst):
        seen.append((Path(src), Path(dst)))
        assert Path(src).exists()
        real_replace(src, dst)
    monkeypatch.setattr(em.os, "replace", spy)
    run_export(env, rows_reader([ev(CUR_SEC, "hello")]))
    assert {d.name for _, d in seen} == NAMES
    assert [d.name for _, d in seen] == ["manifest.json", "critical.json", "feed.json", "index.html", "feed.atom",
                                       "feed.ja.atom"]
    for src, dst in seen:
        assert src.parent == dst.parent == out
        assert src.name.startswith(".") and not src.exists()
    for name in NAMES:
        assert (out / name).stat().st_mode & 0o777 == 0o644
    assert leftovers(out) == []

    # A failure mid-write removes its temp file and leaves earlier files alone.
    (out / "feed.json").write_text("previous")
    n = {"calls": 0}

    def flaky(src, dst):
        n["calls"] += 1
        if n["calls"] == 3:
            raise OSError("disk full")
        real_replace(src, dst)
    monkeypatch.setattr(em.os, "replace", flaky)
    with pytest.raises(OSError):
        run_export(env, rows_reader([ev(CUR_SEC, "hello again")]))
    assert (out / "feed.json").read_text() == "previous"
    assert leftovers(out) == []


def test_exported_events_verify(env, capsys):
    good1 = ev(CUR_SEC, "one", 1793865600)
    good2 = ev(BOT_SEC, "two\nlines", 1793865660)
    extra = dict(ev(STRANGER_SEC, "three", 1793865720), channel_id="x")
    skewed = dict(ev(CUR_SEC, "skewed", 1793865780))
    skewed["created_at"] += 1  # what a rounding mismatch looks like
    flipped = ev(CUR_SEC, "flipped", 1793865840)
    flipped["sig"] = ("0" if flipped["sig"][0] != "0" else "1") + flipped["sig"][1:]
    missing = {k: v for k, v in ev(CUR_SEC, "nosig").items() if k != "sig"}
    rows = [good1, skewed, good2, flipped, "not an object", extra, missing]
    channels, manifest, out = env
    assert em.main(["--channels", str(channels), "--manifest", str(manifest), "--out", str(out),
                    "--rows-from", _write(out.parent / "rows.json", {"feed": rows, "critical": []})]) == 0
    doc = json.loads((out / "feed.json").read_text())
    assert set(doc) == {"generated_at", "channel", "events"}
    assert doc["channel"] == "feed"
    assert len(doc["generated_at"]) == 20 and doc["generated_at"].endswith("Z")
    assert [e["content"] for e in doc["events"]] == ["one", "two\nlines"]  # "three": not a poster
    for e in doc["events"]:
        assert set(e) == set(em.NIP01_KEYS)
        assert nostr.verify_event(e)
    assert json.loads((out / "critical.json").read_text())["events"] == []
    err = capsys.readouterr().err
    assert "feed kept=2 malformed=1 bad_sig=3 other_kind=0 not_poster=1 capped=0" in err
    assert "skewed" not in err and "flipped" not in err


def test_atom_has_one_entry_per_root(env):
    a = ev(CUR_SEC, advisory_post("Alpha", "Upgrade Example Tool now.\nSecond line."), 1793865600)
    reply = ev(CUR_SEC, "level: high", 1793865610, tags=[("e", a["id"], "", "reply")])
    b = ev(BOT_SEC, "First line\nmore", 1793865620)
    c = ev(STRANGER_SEC, "spoofed alert", 1793865630)
    d = ev(BOT_SEC, "to be retracted", 1793865640)
    d_retract = ev(CUR_SEC, "retract\nwrong product", 1793865650, tags=[("e", d["id"], "", "reply")])
    e = ev(BOT_SEC, "stays", 1793865660)
    e_fake = ev(STRANGER_SEC, "retract", 1793865670, tags=[("e", e["id"], "", "reply")])
    b_bot = ev(BOT_SEC, "retract", 1793865680, tags=[("e", b["id"], "", "reply")])  # relay-bot cannot retract
    run_export(env, rows_reader([a, reply, b, c, d, d_retract, e, e_fake, b_bot]))
    tree = ET.parse(env[2] / "feed.atom")
    entries = tree.getroot().findall(f"{ATOM}entry")
    assert [x.findtext(f"{ATOM}id") for x in entries] == [
        f"urn:nostr:event:{e['id']}", f"urn:nostr:event:{d['id']}",
        f"urn:nostr:event:{b['id']}", f"urn:nostr:event:{a['id']}"]
    withdrawn = entries[1]
    assert withdrawn.findtext(f"{ATOM}title") == "Retracted: to be retracted"
    assert withdrawn.findtext(f"{ATOM}content") == "retract\nwrong product"
    assert withdrawn.findtext(f"{ATOM}updated") == "2026-11-05T08:00:50Z"
    assert withdrawn.findtext(f"{ATOM}published") == "2026-11-05T08:00:40Z"
    assert entries[0].findtext(f"{ATOM}title") == "stays"
    assert entries[2].findtext(f"{ATOM}title") == "First line"
    alpha = entries[3]
    assert alpha.findtext(f"{ATOM}title") == "Alpha"
    assert alpha.findtext(f"{ATOM}content") == "Upgrade Example Tool now.\nSecond line."
    assert alpha.find(f"{ATOM}author/{ATOM}name").text == "Curator"
    assert alpha.find(f"{ATOM}link").get("href") == "https://buzz.ai-tools.md/alerts/feed.json"
    assert entries[2].findtext(f"{ATOM}content") == "First line\nmore"
    assert tree.getroot().findtext(f"{ATOM}updated") == "2026-11-05T08:01:00Z"


# ---------------------------------------------------------------- edges

def _write(path, obj):
    Path(path).write_text(json.dumps(obj))
    return str(path)


def test_psql_path_parses_lines(env, monkeypatch):
    good = ev(CUR_SEC, "multi\nline")
    argvs = []

    class Done:
        returncode = 0
        stdout = json.dumps(good) + "\n\n{not json\n"

    def fake_run(argv, **kw):
        argvs.append((argv, kw))
        return Done()
    monkeypatch.setattr(em.subprocess, "run", fake_run)
    result = run_export(env, em.psql_reader(["fake-psql", "-At", "-c"]))
    assert result["channels"]["feed"]["kept"] == 1 and result["channels"]["feed"]["malformed"] == 1
    assert [a[0][-1] for a in argvs] == [em.QUERY.format(channel_id=FEED_ID),
                                         em.QUERY.format(channel_id=CRIT_ID)]
    assert em.QUERY.format(channel_id=FEED_ID) == (
        "SELECT json_build_object('id',encode(id,'hex'),'pubkey',encode(pubkey,'hex'),"
        "'created_at',extract(epoch from created_at)::bigint,'kind',kind,'tags',tags,"
        "'content',content,'sig',encode(sig,'hex')) FROM events WHERE channel_id = "
        f"'{FEED_ID}' AND deleted_at IS NULL ORDER BY created_at")
    for argv, kw in argvs:
        assert argv[:3] == ["fake-psql", "-At", "-c"] and len(argv) == 4
        assert kw["timeout"] == em.PSQL_TIMEOUT and not kw.get("shell")
    assert em.DEFAULT_PSQL == ["docker", "exec", "buzz-prod-postgres-1", "psql",
                               "-U", "buzz", "-d", "buzz", "-At", "-c"]


@pytest.mark.parametrize("failure", ["exit", "timeout", "missing"])
def test_read_failure_writes_nothing(env, monkeypatch, failure):
    out = env[2]
    (out / "feed.json").write_text("previous")

    def fake_run(argv, **kw):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, kw["timeout"])
        if failure == "missing":
            raise FileNotFoundError(argv[0])

        class Failed:
            returncode = 2
            stdout = "secret row content"
        return Failed()
    monkeypatch.setattr(em.subprocess, "run", fake_run)
    with pytest.raises(em.ExportError) as exc:
        run_export(env, em.psql_reader(["fake-psql"]))
    assert "secret row content" not in str(exc.value)
    assert sorted(p.name for p in out.iterdir()) == ["feed.json"]
    assert (out / "feed.json").read_text() == "previous"


@pytest.mark.parametrize("channels", [
    {"feed": "x' OR 1=1 --", "critical": CRIT_ID},
    {"feed": FEED_ID, "critical": CRIT_ID.upper()},
    {"feed": FEED_ID, "critical": CRIT_ID, "../x": FEED_ID},
    {"feed": FEED_ID},
    ["not", "an", "object"],
])
def test_bad_channels_refused(env, channels):
    path, _, out = env
    path.write_text(json.dumps(channels))
    reader = rows_reader([])
    with pytest.raises(em.ExportError):
        run_export(env, reader)
    assert reader.calls == [] and list(out.iterdir()) == []


def test_bad_manifest_refused(env, monkeypatch, capsys):
    channels, manifest, out = env
    other, _ = nostr.keygen()
    forged = json.loads(manifest.read_text())
    forged = nostr.sign_event(other, forged)
    manifest.write_text(json.dumps(forged))
    assert em.main(["--channels", str(channels), "--manifest", str(manifest), "--out", str(out),
                    "--rows-from", _write(out.parent / "rows.json", {"feed": [], "critical": []})]) == 1
    assert list(out.iterdir()) == []
    assert "nothing written" in capsys.readouterr().err


def test_manifest_copied_verbatim(env, monkeypatch):
    monkeypatch.setattr(em, "TRUST_ROOT_PUBKEY", TRUST_ROOT_PUBKEY)  # the real root
    channels, _, out = env
    em.export(channels, REAL_MANIFEST, out, rows_reader([]))
    assert (out / "manifest.json").read_bytes() == REAL_MANIFEST.read_bytes()


def test_cli_rows_from_end_to_end(tmp_path):
    """The script runs from the checkout with python3 -I (as the unit does):
    the sys.path insertion finds aitools_alerts. Real manifest and channels."""
    out = tmp_path / "out"
    out.mkdir()
    rows = _write(tmp_path / "rows.json",
                  {"feed": [ev(STRANGER_SEC, "not a poster")], "critical": []})
    proc = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--channels", str(ROOT / "spec" / "channels.json"),
         "--manifest", str(REAL_MANIFEST), "--out", str(out), "--rows-from", rows],
        cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert {p.name for p in out.iterdir()} == NAMES
    assert json.load(open(out / "feed.json"))["events"] == []  # a non-poster never reaches the mirror
    root = ET.parse(out / "feed.atom").getroot()
    assert root.findall(f"{ATOM}entry") == []
    assert "feed kept=0 malformed=0 bad_sig=0 other_kind=0 not_poster=1 capped=0" in proc.stderr


def test_missing_out_dir_refused(env):
    channels, manifest, out = env
    with pytest.raises(em.ExportError):
        em.export(channels, manifest, out / "absent", rows_reader([]))


def test_atom_strips_xml_illegal_chars(env):
    run_export(env, rows_reader([ev(CUR_SEC, "bell\x07 and esc\x1b[31m red￾")]))
    entry = ET.parse(env[2] / "feed.atom").getroot().find(f"{ATOM}entry")
    assert entry.findtext(f"{ATOM}title") == "bell and esc[31m red"


def test_reserved_channel_name_refused(env):
    path, _, out = env
    path.write_text(json.dumps({"feed": FEED_ID, "critical": CRIT_ID,
                                "manifest": "0aaaaaaa-1111-4222-8333-444444444444"}))
    with pytest.raises(em.ExportError):
        run_export(env, rows_reader([]))
    assert list(out.iterdir()) == []


def test_retract_needs_marked_reply(env):
    a = ev(BOT_SEC, "alpha", 1793865600)
    b = ev(BOT_SEC, "beta", 1793865610)
    c = ev(BOT_SEC, "gamma", 1793865620)
    mention = ev(CUR_SEC, "retract", 1793865630, tags=[("e", a["id"])])  # unmarked: a mention
    marked = ev(CUR_SEC, "retract", 1793865640,
                tags=[("e", c["id"], "", "mention"), ("e", b["id"], "", "root")])
    run_export(env, rows_reader([a, b, c, mention, marked]))
    titles = {x.findtext(f"{ATOM}id"): x.findtext(f"{ATOM}title") for x in
              ET.parse(env[2] / "feed.atom").getroot().findall(f"{ATOM}entry")}
    assert titles == {f"urn:nostr:event:{a['id']}": "alpha",
                      f"urn:nostr:event:{b['id']}": "Retracted: beta",
                      f"urn:nostr:event:{c['id']}": "gamma"}


def test_atom_body_ignores_quoted_block(env):
    real = advisory_post("Real", "Human body.")
    quoted = "Example:\n````\n```aitools-alert\n{}\n```\n````\n"
    run_export(env, rows_reader([ev(CUR_SEC, real + "\n" + quoted)]))
    entry = ET.parse(env[2] / "feed.atom").getroot().find(f"{ATOM}entry")
    assert entry.findtext(f"{ATOM}title") == "Real"
    assert entry.findtext(f"{ATOM}content") == "Human body."


def test_far_future_timestamp_kept_in_json_not_atom(env):
    far = ev(CUR_SEC, "year ten thousand", schema.MAX_TIMESTAMP + 1)
    ok = ev(CUR_SEC, "normal")
    result = run_export(env, rows_reader([far, ok]))
    assert result["channels"]["feed"]["kept"] == 2
    assert len(json.loads((env[2] / "feed.json").read_text())["events"]) == 2
    entries = ET.parse(env[2] / "feed.atom").getroot().findall(f"{ATOM}entry")
    assert [x.findtext(f"{ATOM}title") for x in entries] == ["normal"]


def test_unit_execstart_runs_from_fresh_checkout(tmp_path):
    """The install layout the service assumes: a checkout at ~/ai-tools-alerts
    holding aitools_alerts/, mirror/, spec/, trust/, and ~/alerts-mirror.
    Runs the unit's own ExecStart (with %h = a fixture home) plus --rows-from."""
    import shlex
    import shutil
    home = tmp_path / "home"
    co = home / "ai-tools-alerts"
    for d in ("aitools_alerts", "mirror", "spec", "trust"):
        shutil.copytree(ROOT / d, co / d, ignore=shutil.ignore_patterns("__pycache__"))
    (home / "alerts-mirror").mkdir()
    unit = (ROOT / "mirror" / "aitools-alerts-mirror.service").read_text()
    line = next(x for x in unit.splitlines() if x.startswith("ExecStart="))
    argv = shlex.split(line[len("ExecStart="):].replace("%h", str(home)))
    assert argv[:2] == ["/usr/bin/python3", "-I"]
    rows = _write(tmp_path / "rows.json", {"feed": [], "critical": []})
    proc = subprocess.run([sys.executable] + argv[1:] + ["--rows-from", rows],
                          cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert {p.name for p in (home / "alerts-mirror").iterdir()} == NAMES


def test_psql_rows_keep_unicode_line_separators(env, monkeypatch):
    """psql prints JSON with U+0085/U+2028/U+2029 unescaped (only "\\n" is a
    row boundary); a signed event containing them must survive."""
    odd = ev(CUR_SEC, "paste\u2028from a web page\u0085and\u2029more")
    plain = ev(CUR_SEC, "plain")

    class Done:
        returncode = 0
        stdout = "\n".join(json.dumps(e, ensure_ascii=False) for e in (odd, plain)) + "\n"
    monkeypatch.setattr(em.subprocess, "run", lambda argv, **kw: Done())
    result = run_export(env, em.psql_reader(["fake-psql"]))
    assert result["channels"]["feed"] == {"kept": 2, "capped": 0}
    assert [e["id"] for e in json.loads((env[2] / "feed.json").read_text())["events"]] == [odd["id"], plain["id"]]


def test_deeply_nested_row_is_malformed_not_a_crash(env, monkeypatch):
    class Done:
        returncode = 0
        stdout = "[" * 200000 + "]" * 200000 + "\n" + json.dumps(ev(CUR_SEC, "ok")) + "\n"
    monkeypatch.setattr(em.subprocess, "run", lambda argv, **kw: Done())
    result = run_export(env, em.psql_reader(["fake-psql"]))
    assert result["channels"]["feed"]["kept"] == 1 and result["channels"]["feed"]["malformed"] == 1


def test_retraction_is_published_as_a_withdrawal(env):
    """Two generations: readers keep entries they already fetched, so the
    retracted root must reappear as a withdrawal under the same id, and the
    feed's updated time must move forward."""
    root = ev(BOT_SEC, "Upgrade now", 1793865600)
    later = ev(BOT_SEC, "Unrelated", 1793865700)
    run_export(env, rows_reader([root, later]))
    first = ET.parse(env[2] / "feed.atom").getroot()
    retract = ev(CUR_SEC, "retract\nwrong advice", 1793865800, tags=[("e", root["id"], "", "root")])
    run_export(env, rows_reader([root, later, retract]))
    second = ET.parse(env[2] / "feed.atom").getroot()
    assert second.findtext(f"{ATOM}updated") > first.findtext(f"{ATOM}updated")
    top = second.find(f"{ATOM}entry")
    assert top.findtext(f"{ATOM}id") == f"urn:nostr:event:{root['id']}"
    assert top.findtext(f"{ATOM}title") == "Retracted: Upgrade now"
    assert "Upgrade now" not in top.findtext(f"{ATOM}content")


@pytest.mark.parametrize("delta", [0, -300])
def test_withdrawal_updated_advances_past_root(env, delta):
    """A retraction stamped at or before its root (a fast poster clock) still
    moves the entry's updated past the time readers already have."""
    root = ev(BOT_SEC, "Upgrade now", 1793865600)
    run_export(env, rows_reader([root]))
    before = ET.parse(env[2] / "feed.atom").getroot().find(f"{ATOM}entry").findtext(f"{ATOM}updated")
    retract = ev(CUR_SEC, "retract", 1793865600 + delta, tags=[("e", root["id"], "", "root")])
    run_export(env, rows_reader([root, retract]))
    entry = ET.parse(env[2] / "feed.atom").getroot().find(f"{ATOM}entry")
    assert entry.findtext(f"{ATOM}title") == "Retracted: Upgrade now"
    assert entry.findtext(f"{ATOM}updated") > before


@pytest.mark.parametrize("title", ["Example Tool: looks real", "y" * 300])
def test_atom_marks_a_synthetic_root(env, title):
    adv = schema.asdict(schema.parse_post(advisory_post("t", "CRITICAL: Example Tool: looks real")))
    adv.update(id="CVE-2099-0010", title=title)  # a root posted before readers marked it
    content = f"CRITICAL: Example Tool: looks real\n\n```{schema.INFO_STRING}\n{json.dumps(adv)}\n```\n"
    run_export(env, rows_reader([ev(CUR_SEC, content)]))
    entry = ET.parse(env[2] / "feed.atom").getroot().find(f"{ATOM}entry")
    assert entry.findtext(f"{ATOM}title").startswith("SYNTHETIC TEST: ")


# ---------------------------------------------------------------- launch readiness (hgs0)

# NIP-29 admin and group-metadata kinds the relay stores in a channel, signed
# by the relay-bot key with no e tag, content empty or JSON as the relay writes it.
ADMIN_KINDS = (9000, 9001, 9005, 9007, 39000, 39001, 39002, 40099)


def admin_rows(created_at=1793865000):
    return [ev(BOT_SEC, "" if k < 39000 else json.dumps({"name": "security-feed"}),
               created_at + i, tags=[("h", FEED_ID)], kind=k)
            for i, k in enumerate(ADMIN_KINDS)]


def test_admin_kinds_dropped_from_every_output(env):
    root = ev(CUR_SEC, advisory_post("Alpha", "Upgrade now."), 1793865600)
    result = run_export(env, rows_reader(admin_rows() + [root], admin_rows() + [root]))
    out = env[2]
    for name in ("feed.json", "critical.json"):
        evs = json.loads((out / name).read_text())["events"]
        assert [e["id"] for e in evs] == [root["id"]] and {e["kind"] for e in evs} == {9}
    entries = ET.parse(out / "feed.atom").getroot().findall(f"{ATOM}entry")
    assert [x.findtext(f"{ATOM}title") for x in entries] == ["Alpha"]
    assert "(untitled)" not in (out / "feed.atom").read_text()
    assert result["channels"]["feed"]["other_kind"] == len(ADMIN_KINDS)
    line = em.summary_line(result)
    assert "feed kept=1 malformed=0 bad_sig=0 other_kind=8 not_poster=0 capped=0" in line
    assert "index advisories=1" in line


def test_blank_root_is_not_an_atom_entry(env):
    run_export(env, rows_reader([ev(BOT_SEC, "  \n\t\n"), ev(BOT_SEC, "")]))
    assert ET.parse(env[2] / "feed.atom").getroot().findall(f"{ATOM}entry") == []


def _pull(out, tmp_path, monkeypatch):
    from aitools_alerts import pull
    from aitools_alerts.state import State
    home = tmp_path / ("home-" + out.name)
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))
    st = State.load()
    res = pull.fetch(out.as_uri() + "/", st, root_pubkey=ROOT_PUB, now=1793866000)
    assert res.error is None, res.error
    return [(t.root_id, t.adv.title, t.adv.level, t.retracted) for t in pull.advisories(State.load())]


def test_filtered_mirror_is_accepted_by_the_cli_reader(env, tmp_path, monkeypatch):
    channels, manifest, out = env
    root = ev(CUR_SEC, advisory_post("Alpha", "Upgrade now."), 1793865600)
    lower = ev(CUR_SEC, "level: notice", 1793865700, tags=[("e", root["id"], "", "root")])
    chat = [root, lower]
    run_export(env, rows_reader(admin_rows() + chat, admin_rows() + [root]))
    with_admin = _pull(out, tmp_path, monkeypatch)
    clean_out = tmp_path / "clean"
    clean_out.mkdir()
    em.export(channels, manifest, clean_out, rows_reader(chat, [root]), now=1793865900)
    assert with_admin == _pull(clean_out, tmp_path, monkeypatch)
    assert with_admin == [(root["id"], "Alpha", "notice", False)]


def _adv_post(title, adv_id="AITA-TEST-0101", level="high", url="https://example.com/advisory"):
    adv = schema.asdict(schema.parse_post(advisory_post(title, "x")))
    adv.update(id=adv_id, title=title, level=level,
               sources=[{"url": url, "published_at": None}])
    return f"{title}\n\n```{schema.INFO_STRING}\n{json.dumps(adv)}\n```\n"


def page(env):
    return (env[2] / "index.html").read_bytes().decode("utf-8")


def test_index_page_lists_advisories(env):
    a = ev(CUR_SEC, _adv_post("Alpha", "AITA-TEST-0001", "critical",
                               "https://github.com/anthropics/claude-code/security/advisories/GHSA-xxxx"), 1793865600)
    b = ev(BOT_SEC, _adv_post("Beta", "AITA-TEST-0002"), 1793952000)
    gone = ev(CUR_SEC, "retract\nwrong product", 1793952100, tags=[("e", b["id"], "", "root")])
    run_export(env, rows_reader(admin_rows() + [a, b, gone]))
    text = page(env)
    assert text.startswith("<!DOCTYPE html>") and '<meta charset="utf-8">' in text
    assert "<script" not in text.lower() and not re.search(r"\son[a-z]+\s*=", text, re.I)
    assert text.count("<section") == 4
    assert [m for m in re.findall(r'<section id="([a-z]+)"', text)] == ["about", "advisories", "subscribe", "ja"]
    about = text.split('<section id="about">')[1].split("</section>")[0]
    assert about.count(". ") + about.count(".</p>") == 2  # two sentences
    items = re.findall(r"<li><span class=\"level level-([a-z]+)\">[a-z]+</span> ([^<]*)<br>", text)
    assert items == [("high", "Retracted: Beta"), ("critical", "Alpha")]
    assert '<time datetime="2026-11-06">' in text and '<time datetime="2026-11-05">' in text
    assert 'href="https://example.com/advisory">' in text and "(not a primary source)" in text
    assert 'href="https://github.com/anthropics/claude-code/security/advisories/GHSA-xxxx"' in text
    assert text.count("(not a primary source)") == 1
    assert (env[2] / "index.html").stat().st_mode & 0o777 == 0o644


def test_index_subscribe_block(env):
    channels, manifest, out = env
    em.export(channels, manifest, out, rows_reader([]), now=1793865900,
              mirror_url="https://mirror.example.invalid/alerts")
    sub = page(env).split('<section id="subscribe">')[1].split("</section>")[0]
    assert 'href="https://mirror.example.invalid/alerts/feed.atom"' in sub
    assert em.PIPX_LINE in sub and em.PIPX_LINE in (ROOT / "README.md").read_text()
    assert "#security-feed" in sub and "#security-critical" in sub and "buzz.ai-tools.md" in sub
    assert f'href="{em.REPO_URL}"' in sub
    assert "No advisories yet." in page(env)


def test_index_escapes_post_text(env):
    hostile = '<script>alert(1)</script> & "q" <img src=x onerror=alert(2)>'
    run_export(env, rows_reader([ev(CUR_SEC, _adv_post(hostile))]))
    text = page(env)
    assert "<script" not in text and "<img" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;q&quot;" in text


def test_index_skips_synthetic_and_untrusted(env):
    synth = ev(BOT_SEC, _adv_post("Probe", "CVE-2099-0001"), 1793865600)
    stranger = ev(STRANGER_SEC, _adv_post("Spoofed"), 1793865610)
    real = ev(BOT_SEC, _adv_post("Real one", "AITA-TEST-0003"), 1793865620)
    result = run_export(env, rows_reader([synth, stranger, real]))
    text = page(env)
    assert "Real one" in text and "Probe" not in text and "Spoofed" not in text
    assert result["index_advisories"] == 1


def test_index_caps_the_list(env):
    roots = [ev(BOT_SEC, _adv_post(f"Item {i:02d}", f"AITA-TEST-{1000 + i}"), 1793865600 + i)
             for i in range(em.INDEX_LIMIT + 5)]
    run_export(env, rows_reader(roots))
    titles = re.findall(r"</span> (Item \d\d)<br>", page(env))
    assert len(titles) == em.INDEX_LIMIT and titles[0] == f"Item {em.INDEX_LIMIT + 4:02d}"


def test_index_reads_both_channels_as_the_cli_does(env):
    root = ev(BOT_SEC, _adv_post("Cross", "AITA-TEST-0004", "critical"), 1793865600)
    gone = ev(CUR_SEC, "retract", 1793865700, tags=[("e", root["id"], "", "root")])
    run_export(env, rows_reader([root], [gone]))  # the retraction is only in critical.json
    assert "Retracted: Cross" in page(env)


def test_index_honours_manifest_retracted_and_curator_level(env, monkeypatch):
    channels, manifest, out = env
    doc = json.loads(manifest.read_text())
    content = json.loads(doc["content"])
    content["retracted"] = ["AITA-TEST-0005"]
    man = nostr.sign_event(ROOT_SEC, {"created_at": doc["created_at"], "kind": doc["kind"],
                                      "tags": doc["tags"], "content": json.dumps(content)})
    manifest.write_text(json.dumps(man))
    listed = ev(BOT_SEC, _adv_post("Listed", "AITA-TEST-0005"), 1793865600)
    lowered = ev(BOT_SEC, _adv_post("Lowered", "AITA-TEST-0006", "critical"), 1793865610)
    lower = ev(CUR_SEC, "level: notice", 1793865620, tags=[("e", lowered["id"], "", "root")])
    run_export(env, rows_reader([listed, lowered, lower]))
    text = page(env)
    assert "Retracted: Listed" in text
    assert '<span class="level level-notice">notice</span> Lowered' in text


def test_index_drops_threads_the_cli_ages_out(env):
    old = ev(BOT_SEC, _adv_post("Ancient", "AITA-TEST-0007"), 1793865900 - pull_retention() - 1)
    fresh = ev(BOT_SEC, _adv_post("Fresh", "AITA-TEST-0008"), 1793865800)
    result = run_export(env, rows_reader([old, fresh]))
    assert "Ancient" not in page(env) and "Fresh" in page(env)
    assert result["index_advisories"] == 1


def pull_retention():
    from aitools_alerts import pull
    return pull.RETENTION_S


def test_index_skips_far_future_advisory(env):
    future = ev(BOT_SEC, _adv_post("Future", "AITA-TEST-0009"), schema.MAX_TIMESTAMP + 1)
    now_one = ev(BOT_SEC, _adv_post("Now", "AITA-TEST-0010"), 1793865600)
    run_export(env, rows_reader([future, now_one]))
    assert "Future" not in page(env) and "Now" in page(env)


@pytest.mark.parametrize("url", ["javascript:alert(1)//", "http://example.com/alerts/",
                                 "https:///alerts/", 'https://example.com/"onmouseover=x',
                                 "https://evil.example\\@buzz.ai-tools.md/alerts/",
                                 "https://buzz.ai-tools.md/al\nerts/"])
def test_mirror_url_must_be_https(env, url):
    channels, manifest, out = env
    with pytest.raises(em.ExportError):
        em.export(channels, manifest, out, rows_reader([]), now=1793865900, mirror_url=url)
    assert list(out.iterdir()) == []


def test_index_source_href_attribute_is_escaped(env):
    from html.parser import HTMLParser
    url = "https://example.com/a?b=\"x'&c=<d>"  # the schema accepts this as an https URL
    run_export(env, rows_reader([ev(BOT_SEC, _adv_post("Quoted", url=url))]))
    hrefs, attrs = [], []

    class P(HTMLParser):
        def handle_starttag(self, tag, a):
            attrs.extend(k for k, _ in a)
            if tag == "a":
                hrefs.extend(v for k, v in a if k == "href")
    P().feed(page(env))
    assert url in hrefs
    assert not any(k.startswith("on") for k in attrs)



def test_only_current_manifest_posters_reach_the_mirror(env):
    """Directive c:yjb4ze: the relay is members-only and the mirror public, so a
    member's reply, and a revoked poster's root, never reach any output."""
    REVOKED_SEC, _ = nostr.keygen()  # signed posts once, no longer in the manifest
    root = ev(CUR_SEC, advisory_post("Kept", "Upgrade now."), 1793865600)
    member = ev(STRANGER_SEC, "I am affected too, my token is in ~/.env", 1793865610,
                tags=[("e", root["id"], "", "root")])
    revoked = ev(REVOKED_SEC, _adv_post("Revoked test", "AITA-TEST-0011"), 1793865620)
    result = run_export(env, rows_reader([root, member, revoked], [root, revoked]))
    out = env[2]
    for name in ("feed.json", "critical.json"):
        assert [e["id"] for e in json.loads((out / name).read_text())["events"]] == [root["id"]]
    every = "".join((out / n).read_text() for n in ("feed.json", "critical.json", "feed.atom", "index.html"))
    assert "my token" not in every and "Revoked test" not in every
    assert result["channels"]["feed"]["not_poster"] == 2
    assert result["channels"]["critical"]["not_poster"] == 1


def test_atom_subtitle_points_agents_at_the_cli(env):
    run_export(env, rows_reader([]))
    sub = ET.parse(env[2] / "feed.atom").getroot().findtext(f"{ATOM}subtitle")
    assert "humans and feed readers" in sub and "CLI" in sub and "verifies" in sub


def test_index_says_channels_are_for_members(env):
    run_export(env, rows_reader([]))
    sub = page(env).split('<section id="subscribe">')[1].split("</section>")[0]
    assert "for ai-tools community members" in sub and "auth token" in sub
    assert "No account is needed" in sub and "feed.json" in sub
    assert "join" not in sub.lower()
    assert sub.count("<ul>") == sub.count("</ul>") == 1


def test_index_marks_expired(env):
    post = _adv_post("Old news", "AITA-TEST-0012")
    adv = json.loads(post.split("```" + schema.INFO_STRING + "\n")[1].split("\n```")[0])
    adv["expires_at"] = 1793865700  # before the export's now (1793865900)
    content = f"Old news\n\n```{schema.INFO_STRING}\n{json.dumps(adv)}\n```\n"
    run_export(env, rows_reader([ev(BOT_SEC, content, 1793865600)]))
    assert "Expired: Old news" in page(env)


def test_index_applies_a_far_future_retraction_as_the_cli_does(env, tmp_path, monkeypatch):
    root = ev(BOT_SEC, _adv_post("Withdrawn", "AITA-TEST-0013"), 1793865600)
    gone = ev(CUR_SEC, "retract", schema.MAX_TIMESTAMP + 1, tags=[("e", root["id"], "", "root")])
    run_export(env, rows_reader([root, gone]))
    assert "Retracted: Withdrawn" in page(env)
    assert _pull(env[2], tmp_path, monkeypatch) == [(root["id"], "Withdrawn", "high", True)]



def test_channel_files_keep_the_newest_events_under_the_caps(env, monkeypatch):
    """Directive c:bv22zx: newest N events, then newest-first under a byte cap,
    counted; the CLI limits are never reached."""
    monkeypatch.setattr(em, "MAX_CHANNEL_EVENTS", 5)
    rows = [ev(BOT_SEC, f"post {i:02d}", 1793865000 + i) for i in range(8)]
    result = run_export(env, rows_reader(list(reversed(rows)), rows[:2]))
    feed = json.loads((env[2] / "feed.json").read_text())["events"]
    # The newest five by created_at, whatever the row order; the row order is kept.
    assert [e["content"] for e in feed] == [f"post {i:02d}" for i in range(7, 2, -1)]
    # posts 00 and 01 are also in critical.json: their threads go from both files.
    assert result["channels"]["feed"]["capped"] == 3 and result["channels"]["critical"]["capped"] == 2
    assert "capped=3" in em.summary_line(result)

    monkeypatch.setattr(em, "MAX_CHANNEL_EVENTS", 2000)
    big = [ev(BOT_SEC, "x" * 3000 + f" {i:03d}", 1793865000 + i) for i in range(40)]
    one = len(json.dumps(big[0], separators=(",", ":"))) + 1
    limit = len(em.channel_doc("feed", [], "2026-11-05T08:05:00Z")) + 10 * one
    monkeypatch.setattr(em, "MAX_CHANNEL_BYTES", limit)
    result = run_export(env, rows_reader(big))
    data = (env[2] / "feed.json").read_bytes()
    assert len(data) <= limit
    kept = json.loads(data)["events"]
    assert [e["id"] for e in kept] == [e["id"] for e in big[-10:]]
    assert result["channels"]["feed"]["capped"] == 30


def test_caps_sit_inside_the_cli_limits():
    from aitools_alerts import pull
    assert em.MAX_CHANNEL_EVENTS <= pull.MAX_EVENTS // 2
    assert em.MAX_CHANNEL_BYTES <= pull.MAX_FETCH_BYTES // 2



def test_cap_keeps_threads_whole_across_channels(env, monkeypatch):
    """Fresheyes on the cap: a root kept in critical.json must keep its
    retraction from feed.json, however many later feed events there are."""
    monkeypatch.setattr(em, "MAX_CHANNEL_EVENTS", 3)
    root = ev(BOT_SEC, _adv_post("Withdrawn", "AITA-TEST-0014", "critical"), 1793865000)
    gone = ev(CUR_SEC, "retract", 1793865010, tags=[("e", root["id"], "", "root")])
    later = [ev(BOT_SEC, f"later {i}", 1793865100 + i) for i in range(3)]
    run_export(env, rows_reader([root, gone] + later, [root]))
    feed = [e["id"] for e in json.loads((env[2] / "feed.json").read_text())["events"]]
    crit = [e["id"] for e in json.loads((env[2] / "critical.json").read_text())["events"]]
    # The thread does not fit: its root goes from both files, its curator
    # retraction stays (cached roots must still be withdrawn).
    assert root["id"] not in feed and crit == []
    assert "Withdrawn" not in page(env)

    monkeypatch.setattr(em, "MAX_CHANNEL_EVENTS", 5)
    run_export(env, rows_reader([root, gone] + later, [root]))
    feed = [e["id"] for e in json.loads((env[2] / "feed.json").read_text())["events"]]
    assert gone["id"] in feed and root["id"] in feed
    assert "Retracted: Withdrawn" in page(env)


def test_cap_skips_an_oversized_event_and_keeps_older_ones(env, monkeypatch):
    small = ev(BOT_SEC, _adv_post("Small", "AITA-TEST-0015"), 1793865000)
    huge = ev(BOT_SEC, "x" * 20000, 1793865100)
    limit = len(em.channel_doc("feed", [], "2026-11-05T08:05:00Z")) + 5000
    monkeypatch.setattr(em, "MAX_CHANNEL_BYTES", limit)
    result = run_export(env, rows_reader([small, huge]))
    assert [e["id"] for e in json.loads((env[2] / "feed.json").read_text())["events"]] == [small["id"]]
    assert result["channels"]["feed"]["capped"] == 1
    assert "Small" in page(env)



def test_retraction_reaches_a_cli_that_cached_an_outgrown_thread(env, tmp_path, monkeypatch):
    """Delta review of the cap: two exports, two pulls into one client state.
    The thread outgrows the cap only when the retraction arrives; the cached
    root must still end retracted."""
    from aitools_alerts import pull
    from aitools_alerts.state import State
    home = tmp_path / "client"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    root = ev(BOT_SEC, _adv_post("Outgrown", "AITA-TEST-0016", "critical"), 1793865000)
    talk = [ev(BOT_SEC, f"note {i}", 1793865010 + i, tags=[("e", root["id"], "", "root")]) for i in range(2)]
    monkeypatch.setattr(em, "MAX_CHANNEL_EVENTS", 3)
    run_export(env, rows_reader([root] + talk, [root]))
    assert pull.fetch(env[2].as_uri() + "/", State.load(), root_pubkey=ROOT_PUB, now=1793866000).error is None
    gone = ev(CUR_SEC, "retract", 1793865100, tags=[("e", root["id"], "", "root")])
    result = run_export(env, rows_reader([root] + talk + [gone], [root]))
    feed = [e["id"] for e in json.loads((env[2] / "feed.json").read_text())["events"]]
    assert feed == [gone["id"]] and result["channels"]["feed"]["capped"] == 3
    assert pull.fetch(env[2].as_uri() + "/", State.load(), root_pubkey=ROOT_PUB, now=1793866000).error is None
    [t] = pull.advisories(State.load())
    assert t.root_id == root["id"] and t.retracted

    # The same under the byte cap.
    big = ev(CUR_SEC, "retract\n" + "y" * 50, 1793865200, tags=[("e", root["id"], "", "root")])
    monkeypatch.setattr(em, "MAX_CHANNEL_EVENTS", 2000)
    limit = len(em.channel_doc("feed", [], "2026-11-05T08:05:00Z")) + em._event_size(big) + 10
    monkeypatch.setattr(em, "MAX_CHANNEL_BYTES", limit)
    run_export(env, rows_reader([root] + talk + [big], [root]))
    assert [e["id"] for e in json.loads((env[2] / "feed.json").read_text())["events"]] == [big["id"]]




# ---------------------------------------------------------------- Japanese feed

def _ja(target, text, at, sec=BOT_SEC, of=None):
    head = "lang: ja\n" + (f"of: {of}\n" if of else "")
    return ev(sec, head + "\n" + text, at, tags=[("e", target["id"], "", "root")])


def test_ja_atom_translated_untranslated_and_retracted(env, tmp_path):
    a = ev(BOT_SEC, advisory_post("Alpha", "English body."), 1793865600)
    b = ev(BOT_SEC, advisory_post("Beta", "Beta body."), 1793865610)
    d = ev(BOT_SEC, advisory_post("Delta", "Delta body."), 1793865620)
    lang = [_ja(a, "アルファ\n日本語の本文", 1793865700),
            _ja(b, "ブロック付き\n\n```aitools-alert\n{}\n```", 1793865710),  # ignored entirely
            _ja(d, "デルタ", 1793865715),
            ev(CUR_SEC, "retract\nwrong", 1793865720, tags=[("e", d["id"], "", "root")])]
    run_export(env, rows_reader([a, b, d, *lang]))
    feed = ET.parse(env[2] / "feed.ja.atom").getroot()
    assert feed.get("{http://www.w3.org/XML/1998/namespace}lang") == "ja"
    assert feed.findtext(f"{ATOM}title") == "ai-tools セキュリティアラート"
    assert feed.findtext(f"{ATOM}id").endswith("/feed.ja.atom")
    entries = {x.findtext(f"{ATOM}id"): x for x in feed.findall(f"{ATOM}entry")}
    en_ids = [x.findtext(f"{ATOM}id") for x in ET.parse(env[2] / "feed.atom").getroot().findall(f"{ATOM}entry")]
    assert list(entries) == [i + ":ja" for i in en_ids]  # same entries, same order
    ea, eb, ed = (entries[f"urn:nostr:event:{x['id']}:ja"] for x in (a, b, d))
    assert (ea.findtext(f"{ATOM}title"), ea.findtext(f"{ATOM}content")) == ("アルファ", "アルファ\n日本語の本文")
    assert ea.findtext(f"{ATOM}updated") == "2026-11-05T08:01:40Z"  # the translation's time
    assert (eb.findtext(f"{ATOM}title"), eb.findtext(f"{ATOM}content")) == ("Beta", "Beta body.")
    assert ed.findtext(f"{ATOM}title") == "撤回: デルタ" and ed.findtext(f"{ATOM}content") == "retract\nwrong"
    assert ed.findtext(f"{ATOM}updated") == "2026-11-05T08:02:01Z"  # past the thread's newest reply
    assert feed.findtext(f"{ATOM}updated") == "2026-11-05T08:02:01Z"
    # feed.atom is the same bytes with or without the lang replies.
    out2 = tmp_path / "out2"
    out2.mkdir()
    em.export(env[0], env[1], out2, rows_reader([a, b, d, lang[-1]]), now=1793865900)
    assert (env[2] / "feed.atom").read_bytes() == (out2 / "feed.atom").read_bytes()


def test_ja_atom_translation_rules_match_the_cli(env):
    a = ev(BOT_SEC, advisory_post("Alpha", "x"), 1793865600)
    c = ev(CUR_SEC, advisory_post("Curated", "x"), 1793865610)
    other = ev(BOT_SEC, advisory_post("Other", "x"), 1793865620)
    rows = [a, c, other,
            _ja(c, "ボットの訳", 1793865700),  # discussion on a curator thread
            ev(BOT_SEC, "lang: ja\n\n言及", 1793865710, tags=[("e", a["id"])]),  # unmarked: a mention
            _ja(other, "別スレッド", 1793865720, of=a["id"]),  # names another thread's root
            ev(BOT_SEC, "lang: ja\n\n同時刻B", 1793865730, tags=[("e", a["id"], "", "root")]),
            ev(BOT_SEC, "lang: ja\n\n同時刻A", 1793865730, tags=[("e", a["id"], "", "root")])]
    run_export(env, rows_reader(rows))
    first = {x.findtext(f"{ATOM}id"): x.findtext(f"{ATOM}title") for x in
                   ET.parse(env[2] / "feed.ja.atom").getroot().findall(f"{ATOM}entry")}
    winner = max(rows[-2:], key=lambda e: e["id"])["content"].split("\n")[-1]
    assert first == {f"urn:nostr:event:{a['id']}:ja": winner, f"urn:nostr:event:{c['id']}:ja": "Curated",
                   f"urn:nostr:event:{other['id']}:ja": "Other"}
    run_export(env, rows_reader(rows[:-2] + rows[-1:] + rows[-2:-1]))  # tie order does not matter
    assert {x.findtext(f"{ATOM}id"): x.findtext(f"{ATOM}title") for x in
            ET.parse(env[2] / "feed.ja.atom").getroot().findall(f"{ATOM}entry")} == first


def test_index_has_a_japanese_section(env):
    channels, manifest, out = env
    em.export(channels, manifest, out, rows_reader([]), now=1793865900,
              mirror_url="https://mirror.example.invalid/alerts")
    ja = page(env).split('<section id="ja" lang="ja">')[1].split("</section>")[0]
    assert "<h2>日本語</h2>" in ja and 'href="https://mirror.example.invalid/alerts/feed.ja.atom"' in ja
    assert em.PIPX_LINE in ja and 'lang = "ja"' in ja and "#security-feed" in ja


def test_ja_atom_updated_moves_forward_when_a_change_drops_a_translation(env):
    a = ev(BOT_SEC, advisory_post("Alpha", "x"), 1793865600)
    rows = [a, _ja(a, "アルファ", 1793865700)]
    run_export(env, rows_reader(rows))
    feed = ET.parse(env[2] / "feed.ja.atom").getroot()
    assert feed.find(f"{ATOM}entry").findtext(f"{ATOM}updated") == "2026-11-05T08:01:40Z"
    run_export(env, rows_reader(rows + [ev(CUR_SEC, "level: notice", 1793865800,
                                           tags=[("e", a["id"], "", "root")])]))
    entry = ET.parse(env[2] / "feed.ja.atom").getroot().find(f"{ATOM}entry")
    assert entry.findtext(f"{ATOM}title") == "Alpha"  # the translation was of the old version
    assert entry.findtext(f"{ATOM}updated") == "2026-11-05T08:03:20Z"


def test_ja_atom_translates_a_plain_digest_root(env):
    digest = ev(BOT_SEC, "Daily digest\nTwo advisories today.", 1793865600)
    curated = ev(CUR_SEC, "Curator note\ntext", 1793865610)
    run_export(env, rows_reader([digest, curated, _ja(digest, "今日のまとめ\n本日は二件", 1793865700),
                                 _ja(curated, "ボット", 1793865710)]))
    titles = {x.findtext(f"{ATOM}id"): (x.findtext(f"{ATOM}title"), x.findtext(f"{ATOM}content"))
              for x in ET.parse(env[2] / "feed.ja.atom").getroot().findall(f"{ATOM}entry")}
    assert titles[f"urn:nostr:event:{digest['id']}:ja"] == ("今日のまとめ", "今日のまとめ\n本日は二件")
    assert titles[f"urn:nostr:event:{curated['id']}:ja"][0] == "Curator note"


def test_ja_atom_survives_a_retraction_at_the_last_timestamp(env):
    a = ev(BOT_SEC, advisory_post("Alpha", "x"), 1793865600)
    run_export(env, rows_reader([a, ev(CUR_SEC, "retract", schema.MAX_TIMESTAMP,
                                       tags=[("e", a["id"], "", "root")])]))
    entry = ET.parse(env[2] / "feed.ja.atom").getroot().find(f"{ATOM}entry")
    assert entry.findtext(f"{ATOM}title") == "撤回: Alpha"
