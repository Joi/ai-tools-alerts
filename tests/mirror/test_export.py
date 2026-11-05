"""Mirror exporter (Task C1). Throwaway keys only; no relay data."""
import importlib.util
import json
import os
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
NAMES = {"manifest.json", "feed.json", "critical.json", "feed.atom"}

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


def ev(sec, content, created_at=1793865600, tags=()):
    return nostr.sign_event(sec, {"created_at": created_at, "kind": 1,
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
    assert seen[0][1].name == "manifest.json" and seen[-1][1].name == "feed.atom"
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
    assert [e["content"] for e in doc["events"]] == ["one", "two\nlines", "three"]
    for e in doc["events"]:
        assert set(e) == set(em.NIP01_KEYS)
        assert nostr.verify_event(e)
    assert json.loads((out / "critical.json").read_text())["events"] == []
    err = capsys.readouterr().err
    assert "feed kept=3 malformed=1 bad_sig=3" in err
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
    run_export(env, rows_reader([a, reply, b, c, d, d_retract, e, e_fake]))
    tree = ET.parse(env[2] / "feed.atom")
    entries = tree.getroot().findall(f"{ATOM}entry")
    assert [x.findtext(f"{ATOM}id") for x in entries] == [
        f"urn:nostr:event:{e['id']}", f"urn:nostr:event:{b['id']}", f"urn:nostr:event:{a['id']}"]
    alpha = entries[2]
    assert alpha.findtext(f"{ATOM}title") == "Alpha"
    assert alpha.findtext(f"{ATOM}content") == "Upgrade Example Tool now.\nSecond line."
    assert alpha.find(f"{ATOM}author/{ATOM}name").text == "Curator"
    assert alpha.find(f"{ATOM}link").get("href") == "https://buzz.ai-tools.md/alerts/feed.json"
    assert entries[1].findtext(f"{ATOM}title") == "First line"
    assert entries[1].findtext(f"{ATOM}content") == "First line\nmore"
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
    assert len(json.load(open(out / "feed.json"))["events"]) == 1
    root = ET.parse(out / "feed.atom").getroot()
    assert root.findall(f"{ATOM}entry") == []  # a non-poster never reaches the Atom
    assert "feed kept=1 malformed=0 bad_sig=0" in proc.stderr


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
    ids = [x.findtext(f"{ATOM}id") for x in
           ET.parse(env[2] / "feed.atom").getroot().findall(f"{ATOM}entry")]
    assert ids == [f"urn:nostr:event:{c['id']}", f"urn:nostr:event:{a['id']}"]


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
