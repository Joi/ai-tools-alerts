"""Poster -> guard's command -> mirror-put -> exporter -> member reader, with throwaway
keys (ai-tools-alerts#nfm3). The relay is a list of rows; posts reach it through a send
function, the checkpoint through an ssh function (the put-only route, vzc3)."""

import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from aitools_alerts import checkpoint as cp
from aitools_alerts import manifest, nostr, pull
from aitools_alerts.poster import signer, transport
from aitools_alerts.state import State
from mirror_helpers import CHANNELS, advisory, released_reader
from test_main import T0, env, finding  # noqa: F401 - env is a fixture

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "mirror"))
import export_mirror as em  # noqa: E402

NAME = {v: k for k, v in CHANNELS.items()}
PUT = "/opt/relay/bin/mirror-put"
BASH = shutil.which("bash")
GHSA2 = "https://github.com/anthropics/claude-code/security/advisories/GHSA-mnop-qrst-uvwx"


class World:
    """A relay (rows per channel), the VM's home with the real mirror-put, the exporter's
    checkout files and output directory, and the keys."""

    def __init__(self, tmp_path, monkeypatch):
        self.root_sec, self.root = nostr.keygen()
        self.cur_sec, self.cur = nostr.keygen()
        self.bot_sec, self.bot = nostr.keygen()
        self.ck_sec, self.ck = nostr.keygen()
        self.rows = {"feed": [], "critical": []}
        self.now = T0
        self.vm_home = tmp_path / "vm-home"
        self.out = tmp_path / "alerts-mirror"
        self.vm_home.mkdir()
        self.out.mkdir()
        man = nostr.sign_event(self.root_sec, {
            "created_at": T0 - 3600, "kind": 30078, "tags": [["d", "aitools-alerts-manifest"]],
            "content": json.dumps({"version": 1, "issued_at": "2026-11-04T20:20:00Z", "posters": [
                {"pubkey": self.cur, "role": "curator", "name": "cur"},
                {"pubkey": self.bot, "role": "relay-bot", "name": "bot"}]})})
        self.manifest_file = tmp_path / "manifest.json"
        self.manifest_file.write_text(json.dumps(man))
        self.man = manifest.load(self.manifest_file)
        self.cert_file = tmp_path / "checkpoint-key.json"
        self.cert_file.write_text(json.dumps(cp.build_cert(self.root_sec, self.man, self.ck, T0 - 3600, T0 + 90 * 86400)))
        self.root_pub = tmp_path / "root.pub"
        self.root_pub.write_text(self.root + "\n")
        self.channels = tmp_path / "channels.json"
        self.channels.write_text(json.dumps(CHANNELS))
        monkeypatch.setattr(em, "TRUST_ROOT_PUBKEY", self.root)
        self.puts = 0

    def relay_store(self, sec, channel, text, reply_to=None, claim=None):
        tags = [["h", CHANNELS[channel]]] + ([["e", reply_to, "", "root"]] if reply_to else []) + ([claim] if claim else [])
        ev = nostr.sign_event(sec, {"created_at": self.now, "kind": 9, "tags": tags, "content": text})
        self.rows[channel].append(ev)
        return ev

    def send(self, channel_id, text, reply_to=None, claim=None):
        """A post as the relay takes it over HTTPS: stored as a bot-signed event."""
        ev = self.relay_store(self.bot_sec, NAME[channel_id], text, reply_to, claim)
        return transport.SendResult(True, ev["id"], 200, "", "ok")

    def ssh(self, argv, **kw):
        """The put-only route: runs the real ops/vm/mirror-put in the VM's home."""
        assert shlex.split(argv[-1]) == [PUT, "checkpoint"], argv
        self.puts += 1
        return subprocess.run([BASH, str(ROOT / "ops" / "vm" / "mirror-put"), "checkpoint"], input=kw["input"],
                              capture_output=True, timeout=30,
                              env={"HOME": str(self.vm_home), "PATH": os.environ["PATH"]})

    def export(self, rows=None):
        rows = rows or self.rows
        return em.export(self.channels, self.manifest_file, self.out, lambda name, cid: list(rows[name]),
                         now=self.now, root_pub=self.root_pub, checkpoint_key=self.cert_file,
                         inbox=self.vm_home / "alerts-inbox")

    def fetch(self, url, timeout=None):
        return (self.out / url.rsplit("/", 1)[1]).read_bytes()

    def member(self, home):
        st = State.load(home)
        res = pull.fetch("https://mirror.example.invalid/alerts", st, fetch=self.fetch, root_pubkey=self.root, now=self.now)
        st = State.load(home)
        return res, st, sorted((t.adv.title, t.retracted) for t in pull.advisories(st))


@pytest.fixture
def world(env, tmp_path, monkeypatch):  # noqa: F811
    w = World(tmp_path, monkeypatch)
    key = tmp_path / "checkpoint.nsec"
    key.write_text(nostr.nsec(w.ck_sec) + "\n")
    key.chmod(0o600)
    env.config = replace(env.config, checkpoint_key_file=key, relay_ssh_host="op@relay.example.net", relay_put_wrapper=PUT)
    signer.init_owed(env.config.owed_state)
    w.env = env

    def poster_run():
        return env.run(now=w.now, relay=w.send, ssh=w.ssh, mirror_fetch=w.fetch, root=w.root)
    w.poster_run = poster_run
    return w


def test_poster_to_member_end_to_end(world, tmp_path):
    w = world
    member = tmp_path / "member-state"
    # A curator alert is on the relay; the exporter runs (no checkpoint has been signed yet).
    w.relay_store(w.cur_sec, "feed", __import__("aitools_alerts.schema", fromlist=["x"]).render_post(
        advisory(title="Curator alert", posted_at=T0 - 600), "Body."))
    assert w.export()["checkpoint"] == "none"
    res, st, shown = w.member(member)
    assert res.error == "no checkpoint" and shown == []  # the certificate is served, no checkpoint yet

    # The poster runs: it posts a finding, pulls the mirror, signs, delivers through mirror-put.
    w.env.collector([finding()])
    code, summary, _ = w.poster_run()
    assert code == 0 and summary.endswith(" checkpoint=sent") and w.puts == 1
    inbox = w.vm_home / "alerts-inbox" / "checkpoint.json"
    c = cp.load_checkpoint(inbox)
    posted = {e["id"] for evs in w.rows.values() for e in evs if e["pubkey"] == w.bot}
    assert posted and posted <= c.events  # owed: acknowledged, not on the mirror when it signed

    # The exporter's next run has the posts: it publishes the checkpoint with them.
    w.now += 300
    assert w.export()["checkpoint"] == f"published seq {c.seq}"
    res, st, shown = w.member(member)
    assert res.error is None and pull.unverified(st, w.now) is None
    assert ("Curator alert", False) in shown and len(shown) >= 2  # the curator's and the poster's

    # An hour on: the poster posts another alert. The exporter's view of the relay lags by one
    # event; it holds the new checkpoint back, and the member stays verified on the earlier one.
    w.now += 3600
    lag = {k: list(v) for k, v in w.rows.items()}
    w.env.collector([finding(fid="GHSA-mnop-qrst-uvwx", sources=(GHSA2,), fixed="2.1.1")])  # btqg: another fix
    code, summary, _ = w.poster_run()
    assert summary.endswith(" checkpoint=sent")
    newer = cp.load_checkpoint(inbox)
    assert newer.seq > c.seq
    w.now += 60
    assert w.export(lag)["checkpoint"].startswith(f"kept seq {c.seq} (candidate lists")
    res, st, shown_then = w.member(member)
    assert res.error is None and pull.unverified(st, w.now) is None and shown_then == shown
    w.now += 300
    assert w.export()["checkpoint"] == f"published seq {newer.seq}"
    res, st, shown_now = w.member(member)
    assert res.error is None and pull.unverified(st, w.now) is None and len(shown_now) == len(shown) + 1
    assert signer.load_owed(w.env.config.owed_state, w.now)["owed"]  # settled at the poster's next run, not before

    # The poster's next run finds its posts on the mirror: nothing is owed any more.
    w.now += 3600
    w.poster_run()
    assert signer.load_owed(w.env.config.owed_state, w.now)["owed"] == []

    # The released reader pulls the same mirror, new files and all.
    old = released_reader(tmp_path)
    files = tmp_path / "served"
    shutil.copytree(w.out, files)
    got = old("pull", "--mirror-url", files.as_uri() + "/", root=w.root)
    assert got.returncode == 0 and "Traceback" not in got.stderr, got.stderr
    got = old("check", root=w.root)
    assert got.returncode == 0 and "advisories" in got.stdout and "Traceback" not in got.stderr


def test_a_relay_that_withholds_an_acknowledged_post_cannot_get_a_clean_checkpoint(world, tmp_path):
    """The relay acknowledges the poster's alert and never exports it. Whatever it does
    with the checkpoints, a member never reads verified on a feed without that alert
    until the poster gives the post up (72 hours), a day after members began reading stale."""
    w = world
    member = tmp_path / "member-state"
    w.relay_store(w.cur_sec, "feed", "Daily digest.")
    w.export()
    w.env.collector([finding()])
    w.poster_run()
    hidden = {e["id"] for evs in w.rows.values() for e in evs if e["pubkey"] == w.bot}
    served = {k: [e for e in v if e["id"] not in hidden] for k, v in w.rows.items()}
    for hour in range(1, 5):
        w.now = T0 + hour * 3600
        w.poster_run()
        result = w.export(served)
        assert result["checkpoint"].startswith("none (candidate lists")  # never publishable
        res, st, shown = w.member(member)
        assert res.error == "no checkpoint" and pull.unverified(st, w.now) is not None
    # Even handed the poster's checkpoint directly, the member refuses the incomplete mirror.
    shutil.copy(w.vm_home / "alerts-inbox" / "checkpoint.json", w.out / "checkpoint.json")
    res, st, shown = w.member(member)
    assert res.error == "mirror incomplete" and pull.unverified(st, w.now) is not None
