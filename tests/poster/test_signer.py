"""The poster signs the feed checkpoint (ai-tools-alerts#nfm3)."""

import json
import os
import shlex
import stat
import subprocess
from dataclasses import replace

import pytest

from aitools_alerts import checkpoint as cp
from aitools_alerts import config as member_config
from aitools_alerts import nostr, pull
from aitools_alerts.poster import inputs, main, signer
from aitools_alerts.state import State
from mirror_helpers import CHANNELS, Mirror, advisory
from test_main import T0, FakeSSH, env, finding  # noqa: F401 - env is a fixture

DAY = 86400
PUT = "/opt/relay/bin/mirror-put"
FEED = frozenset(CHANNELS.values())


class PutSSH(FakeSSH):
    """FakeSSH that also takes the checkpoint delivery: ``puts`` holds each
    document; ``put_ok`` False makes the storing command refuse."""

    def __init__(self, *outcomes, put_ok=True, **kw):
        super().__init__(*outcomes, **kw)
        self.puts, self.put_ok, self.argvs = [], put_ok, []

    def __call__(self, argv, **kw):
        self.argvs.append(list(argv))
        remote = shlex.split(argv[-1])
        if remote == [PUT, "checkpoint"]:
            self.puts.append(kw["input"])
            if not self.put_ok:
                return subprocess.CompletedProcess(argv, 1, b"", b'{"error":"user_error","message":"mirror-put: x"}\n')
            return subprocess.CompletedProcess(argv, 0, b'{"stored":true,"bytes":1}\n', b"")
        return super().__call__(argv, **kw)

    def last(self):
        return cp.load_checkpoint(self.puts[-1])


@pytest.fixture
def signing(env, tmp_path):  # noqa: F811
    """The poster environment with a checkpoint key and a mirror whose manifest and
    certificate (naming that key) are dated before the poster's clock."""
    m = env.mirror
    m.publish_manifest(issued=T0 - 3600)
    key = tmp_path / "checkpoint.nsec"
    key.write_text(nostr.nsec(m.ck_sec) + "\n")
    key.chmod(0o600)
    env.config = replace(env.config, checkpoint_key_file=key, relay_put_wrapper=PUT)
    env.key = key
    return env


def owed_ids(env):  # noqa: F811
    return [o["id"] for o in signer.load_owed(env.config.owed_state)["owed"]]


def on_mirror(m, title, at, sec=None, **kw):
    return m.root_post(sec or m.cur_sec, advisory(id=f"AITA-TEST-{abs(hash(title)) % 9000 + 1000}", title=title),
                       created_at=at, **kw)


# ---------------------------------------------------------------- the key file

def test_keygen_then_read_key(tmp_path):
    path = tmp_path / "k.nsec"
    npub = signer.keygen(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    sec = signer.read_key(path)
    assert nostr.npub(nostr.pubkey_gen(bytes.fromhex(sec)).hex()) == npub
    assert npub.startswith("npub1") and sec not in npub
    with pytest.raises(signer.KeyFileError, match="exists"):
        signer.keygen(path)
    assert signer.read_key(path) == sec  # untouched
    path.write_text(sec)  # hex is accepted too
    assert signer.read_key(path) == sec


@pytest.mark.parametrize("case", ["relative", "missing", "group readable", "world readable", "directory", "symlink",
                                  "not a key", "an npub", "too long", "binary", "zero"])
def test_read_key_refusals_never_show_the_contents(tmp_path, case):
    sec, pub = nostr.keygen()
    path = tmp_path / "k.nsec"
    path.write_text(nostr.nsec(sec))
    path.chmod(0o600)
    arg = path
    if case == "relative":
        arg = "k.nsec"
    elif case == "missing":
        path.unlink()
    elif case == "group readable":
        path.chmod(0o640)
    elif case == "world readable":
        path.chmod(0o604)
    elif case == "directory":
        path.unlink()
        path.mkdir()
    elif case == "symlink":
        real = tmp_path / "real.nsec"
        path.rename(real)
        path.symlink_to(real)
    elif case == "not a key":
        path.write_text("hello")
    elif case == "an npub":
        path.write_text(nostr.npub(pub))
    elif case == "too long":
        path.write_text(nostr.nsec(sec) * 5)
    elif case == "binary":
        path.write_bytes(b"\xff" * 40)
    elif case == "zero":
        path.write_text("0" * 64)
    with pytest.raises(signer.KeyFileError) as e:
        signer.read_key(arg)
    assert sec not in str(e.value) and nostr.nsec(sec) not in str(e.value)


def test_a_fifo_with_no_writer_is_refused_at_once(tmp_path):
    path = tmp_path / "k.nsec"
    os.mkfifo(path, 0o600)
    code = ("import sys; from aitools_alerts.poster import signer\n"
            "try:\n    signer.read_key(sys.argv[1])\nexcept signer.KeyFileError as e:\n    print(e)\n")
    r = subprocess.run([os.sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=20,
                       cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    assert "not a regular file" in r.stdout, r.stderr


def test_key_and_owed_files_join_the_path_collision_check(tmp_path):
    base = dict(ledger=tmp_path / "ledger.json", kev_cache=tmp_path / "kev.json", relay_put_wrapper=PUT)
    for clash in (tmp_path / "kev.json", tmp_path / "ledger.json", tmp_path / "ledger.json.checkpoint.json",
                  tmp_path / "LEDGER.JSON.poster-state.json"):
        with pytest.raises(inputs.ConfigError, match="must differ"):
            inputs.Config(**base, checkpoint_key_file=clash).check_paths()
    with pytest.raises(inputs.ConfigError, match="must differ"):
        inputs.Config(ledger=tmp_path / "ledger.json", kev_cache=tmp_path / "ledger.json.checkpoint.json").check_paths()
    inputs.Config(**base, checkpoint_key_file=tmp_path / "checkpoint.nsec").check_paths()
    assert list(tmp_path.iterdir()) == []  # nothing was written


def test_config_keys_go_together_and_are_absolute(tmp_path):
    def load(text):
        p = tmp_path / "poster.toml"
        p.write_text(f'ledger = "{tmp_path}/l.json"\nkev_cache = "{tmp_path}/k.json"\n' + text)
        return inputs.load_config(p)
    assert load("").checkpoint_key_file is None
    cfg = load(f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_put_wrapper = "{PUT}"\n')
    assert str(cfg.checkpoint_key_file) == f"{tmp_path}/c.nsec" and cfg.relay_put_wrapper == PUT
    for bad in (f'checkpoint_key_file = "{tmp_path}/c.nsec"\n', f'relay_put_wrapper = "{PUT}"\n',
                f'checkpoint_key_file = "c.nsec"\nrelay_put_wrapper = "{PUT}"\n',
                f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_put_wrapper = "mirror-put x"\n'):
        with pytest.raises(inputs.ConfigError):
            load(bad)


def test_checkpoint_keygen_command_prints_only_the_npub(tmp_path, capsys):
    cfg = tmp_path / "poster.toml"
    cfg.write_text(f'ledger = "{tmp_path}/l.json"\nkev_cache = "{tmp_path}/k.json"\n')
    assert main.main(["checkpoint-keygen", "--config", str(cfg)]) == 2  # not configured
    assert "checkpoint_key_file" in capsys.readouterr().err
    cfg.write_text(cfg.read_text() + f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_put_wrapper = "{PUT}"\n')
    assert main.main(["checkpoint-keygen", "--config", str(cfg)]) == 0
    out = capsys.readouterr()
    sec = signer.read_key(tmp_path / "c.nsec")
    assert out.out.strip().startswith("npub1") and sec not in out.out + out.err
    assert nostr.nsec(sec) not in out.out + out.err
    assert main.main(["checkpoint-keygen", "--config", str(cfg)]) == 2  # never replaces a key
    assert signer.read_key(tmp_path / "c.nsec") == sec


# ---------------------------------------------------------------- owed, seq

def test_owed_entries_are_recorded_settled_and_given_up_only_by_time(tmp_path):
    path = tmp_path / "owed.json"
    a, b, root = "a" * 64, "b" * 64, "c" * 64
    signer.record_sent(path, a, 100, None, 1000)
    signer.record_sent(path, b, 50, root, 2000)
    signer.record_sent(path, a, 100, None, 3000)  # once
    signer.record_sent(path, "not-an-id", 5, None, 3000)
    rec = signer.load_owed(path)
    assert rec["owed"] == [{"id": a, "bytes": 100 + signer.ENVELOPE, "since": 1000, "root": None},
                           {"id": b, "bytes": 50 + signer.ENVELOPE, "since": 2000, "root": root}]
    assert signer.settle_owed(rec["owed"], {a}, 3000) == ([rec["owed"][1]], 0)
    assert signer.settle_owed(rec["owed"], set(), 1000 + signer.OWED_S - 1) == (rec["owed"], 0)
    assert signer.settle_owed(rec["owed"], set(), 1000 + signer.OWED_S) == ([rec["owed"][1]], 1)
    many = [{"id": f"{i:064x}", "bytes": 10**6, "since": 5} for i in range(500)]
    assert signer.settle_owed([dict(o, root=None) for o in many], set(), 6)[1] == 0  # never dropped for room
    path.write_text("{")
    assert signer.load_owed(path) == {"last_seq": 0, "owed": []}
    path.write_text(json.dumps({"last_seq": 1, "owed": [{"id": "x"}]}))
    assert signer.load_owed(path) == {"last_seq": 0, "owed": []}


def test_next_seq():
    assert signer.next_seq(1000, 0) == 1000
    assert signer.next_seq(1000, 1000) == 1001  # the same second
    assert signer.next_seq(1000, 1005) == 1006  # the count ran ahead of the clock
    assert signer.next_seq(1000, 0, 1005) == 1006  # the state file was lost: the published checkpoint is the floor
    assert signer.next_seq(900, 1000) == 1001  # the clock went back


# ---------------------------------------------------------------- the window

def _thread(m, title, at, replies=0, sec=None, retract_at=None):
    root = on_mirror(m, title, at, sec=sec or m.bot_sec)
    evs = [root] + [m.post(m.bot_sec, f"note {i}", created_at=at + 1 + i, tags=[("e", root["id"], "", "root")])
                    for i in range(replies)]
    if retract_at is not None:
        evs.append(m.reply(m.cur_sec, root, "retract", created_at=retract_at))
    return evs


def _win(m, owed=(), now=T0):
    events = [e for evs in m.events.values() for e in evs]
    return signer.window({e["id"]: e for e in events}.values(), m.man, list(owed), now, FEED)


def test_window_lists_whole_threads_newest_first_within_the_budget(monkeypatch):
    m = Mirror()
    monkeypatch.setattr(signer, "MAX_LISTED", 20)
    threads = [_thread(m, f"T{i}", T0 - 1000 * (10 - i), replies=5) for i in range(5)]  # six events each, T4 newest
    got = _win(m)
    assert set(got) >= {e["id"] for t in threads[2:] for e in t}  # the three newest, whole (18 events)
    assert len(got) == 20  # ... and the roots of the two that did not fit: a root is always listed
    assert {threads[0][0]["id"], threads[1][0]["id"]} <= set(got)
    assert not {e["id"] for t in threads[:2] for e in t[1:]} & set(got)


def test_window_leaves_out_old_threads_and_events_dated_after_the_signing(monkeypatch):
    m = Mirror()
    edge = T0 - pull.RETENTION_S + signer.MARGIN_S
    old = _thread(m, "Old", edge - 1)
    kept = _thread(m, "At the line", edge)
    ahead = on_mirror(m, "Ahead", T0 + 1)
    got = _win(m)
    assert got == [kept[0]["id"]] and old[0]["id"] not in got and ahead["id"] not in got


def test_curator_replies_are_listed_before_any_other_traffic(monkeypatch):
    """A newer thread of small bot events fills the window; the older thread's curator
    retraction is listed all the same, and so is the retraction in an oversized thread."""
    m = Mirror()
    monkeypatch.setattr(signer, "MAX_LISTED", 12)
    old = _thread(m, "Old alert", T0 - 5000, replies=1, retract_at=T0 - 4000)
    huge = _thread(m, "Bloated", T0 - 3000, replies=30, retract_at=T0 - 2000)
    newer = _thread(m, "Newer", T0 - 100, replies=7)  # eight events
    got = set(_win(m))
    assert {old[0]["id"], old[-1]["id"], huge[0]["id"], huge[-1]["id"]} <= got  # roots and retractions
    assert {e["id"] for e in newer} <= got  # then the newest thread, whole
    assert len(got) == 12 and not {e["id"] for e in huge[1:-1]} & got  # the bloat is what is left out


def test_when_what_must_be_listed_does_not_fit_nothing_is_signed(monkeypatch):
    m = Mirror()
    monkeypatch.setattr(signer, "MAX_LISTED", 5)
    for i in range(6):
        _thread(m, f"T{i}", T0 - 100 * (i + 1))
    assert _win(m) is None  # six roots, room for five
    monkeypatch.setattr(signer, "MAX_LISTED", 6)
    assert len(_win(m)) == 6
    owed = [{"id": f"{i:064x}", "bytes": 10, "since": T0, "root": None} for i in range(3)]
    assert _win(m, owed) is None  # the owed ids are never the ones dropped
    monkeypatch.setattr(signer, "MAX_LISTED", 990)
    big = [{"id": "f" * 64, "bytes": signer.MAX_LISTED_BYTES, "since": T0, "root": None}]
    assert _win(m, big) is None


def test_owed_ids_and_the_roots_they_reply_to_come_first(monkeypatch):
    m = Mirror()
    monkeypatch.setattr(signer, "MAX_LISTED", 4)
    old = _thread(m, "Old parent", T0 - 9000, replies=3)
    _thread(m, "Newer", T0 - 100, replies=1)
    owed = [{"id": "a" * 64, "bytes": 10, "since": T0, "root": old[0]["id"]}]
    got = _win(m, owed)
    assert got[:2] == ["a" * 64, old[0]["id"]]  # the reply the relay acknowledged, and its root
    assert len(got) == 4  # then the newer thread; the old parent's bot replies did not fit


def test_a_salvaged_old_thread_keeps_its_newest_event(monkeypatch):
    """An old root and old curator reply kept alive by recent bot replies in a thread too
    large to list: the newest event is listed too, or the reader's own retention, which
    sees only listed events, would drop them and read unverified."""
    m = Mirror()
    monkeypatch.setattr(signer, "MAX_LISTED", 6)
    edge = T0 - pull.RETENTION_S
    root = on_mirror(m, "Ancient", edge - 50 * DAY, sec=m.bot_sec)
    fix = m.reply(m.cur_sec, root, "level: notice", created_at=edge - 10 * DAY)
    recent = [m.post(m.bot_sec, f"note {i}", created_at=T0 - 1000 + i, tags=[("e", root["id"], "", "root")])
              for i in range(20)]
    got = _win(m)
    assert set(got) == {root["id"], fix["id"], recent[-1]["id"]}
    kept = {e["id"]: e for evs in m.events.values() for e in evs if e["id"] in got}
    assert set(pull._retain(kept, T0, pull.PullResult())) == set(got)  # a reader keeps all three


# ---------------------------------------------------------------- a run

def test_a_run_signs_and_delivers_a_checkpoint(signing, capsys):
    m = signing.mirror
    a = on_mirror(m, "On the mirror", T0 - 500)
    gone = m.reply(m.cur_sec, a, "retract", created_at=T0 - 400)
    signing.collector([finding()])
    code, summary, ssh = signing.run(ssh=PutSSH())
    assert code == 0 and summary.endswith(" checkpoint=sent") and len(ssh.puts) == 1
    c = ssh.last()
    cert = cp.load_cert(json.dumps(m.cert).encode())
    assert cp.verify_checkpoint(c, cert) and cp.checkpoint_problem(c, m.man, T0) is None
    assert c.seq == T0 and c.created_at == T0 and c.valid_until == T0 + DAY
    sent = set(ssh.ids)  # what this run posted: acknowledged, not on the mirror yet
    assert sent and c.events == {a["id"], gone["id"]} | sent | {o for o in owed_ids(signing)}
    assert set(owed_ids(signing)) >= sent
    assert signer.load_owed(signing.config.owed_state)["last_seq"] == T0
    sec = signer.read_key(signing.key)
    seen = capsys.readouterr()
    everything = seen.out + seen.err + summary + " ".join(" ".join(a) for a in ssh.argvs)
    assert sec not in everything and nostr.nsec(sec) not in everything
    assert all(sec.encode() not in p and nostr.nsec(sec).encode() not in p for p in ssh.puts)


def test_without_the_config_keys_nothing_changes(env):  # noqa: F811
    env.collector([finding()])
    code, summary, ssh = env.run(ssh=PutSSH())
    assert code == 0 and "checkpoint" not in summary and ssh.puts == []
    assert not env.config.owed_state.exists()


@pytest.mark.parametrize("case", ["no certificate", "certificate for another key", "certificate expired"])
def test_no_usable_certificate_means_nothing_is_sent(signing, case):
    m = signing.mirror
    if case == "no certificate":
        m.cert = None
    elif case == "certificate for another key":
        m.publish_cert(key=nostr.keygen()[1])
    else:
        m.publish_cert(issued=T0 - 10 * DAY, days=1)
    code, summary, ssh = signing.run(ssh=PutSSH())
    assert code == 0 and summary.endswith(" checkpoint=no-certificate") and ssh.puts == []


def test_a_renewed_certificate_on_the_mirror_is_picked_up(signing, monkeypatch):
    """The poster's bundled certificate is older; the mirror serves the renewal and,
    later, a certificate for a new manifest: no reinstall is needed."""
    m = signing.mirror
    old = cp.load_cert(json.dumps(m.cert).encode())
    monkeypatch.setattr(pull, "TRUST_ROOT_PUBKEY", m.root)
    monkeypatch.setattr(signer, "TRUST_ROOT_PUBKEY", m.root)
    monkeypatch.setattr(pull, "bundled_cert", lambda: old)
    m.publish_cert(issued=T0 - 600)
    _, summary, ssh = signing.run(ssh=PutSSH())
    assert summary.endswith(" checkpoint=sent")
    m.publish_manifest(issued=T0 - 300)  # a new manifest, with its certificate
    _, summary, ssh = signing.run(ssh=PutSSH(), now=T0 + 60)
    assert summary.endswith(" checkpoint=sent") and ssh.last().manifest_id == m.manifest["id"]


def test_failures_never_change_the_runs_exit_code(signing, monkeypatch):
    _, summary, ssh = signing.run(ssh=PutSSH(put_ok=False))
    assert summary.endswith(" checkpoint=failed") and len(ssh.puts) == 1
    signing.mirror.raw["manifest.json"] = None
    code, summary, ssh = signing.run(ssh=PutSSH(), now=T0 + 60)
    assert code == 0 and summary.endswith(" checkpoint=no-mirror") and ssh.puts == []
    signing.mirror.raw.pop("manifest.json")
    signing.key.chmod(0o644)
    code, summary, ssh = signing.run(ssh=PutSSH(), now=T0 + 120)
    assert code == 0 and summary.endswith(" checkpoint=error") and ssh.puts == []


def test_two_runs_in_one_second_and_a_lost_state_file(signing):
    _, _, ssh = signing.run(ssh=PutSSH())
    first = ssh.last()
    _, _, ssh = signing.run(ssh=PutSSH())  # the same second
    second = ssh.last()
    assert (first.seq, second.seq) == (T0, T0 + 1)
    signing.mirror.raw["checkpoint.json"] = json.dumps(second.event).encode()  # the mirror publishes it
    signing.config.owed_state.unlink()  # the count is lost while it is ahead of the clock
    _, _, ssh = signing.run(ssh=PutSSH(), now=T0 + 1)
    third = ssh.last()
    assert third.seq == T0 + 2 and cp.checkpoint_order(third, second) is None


# ---------------------------------------------------------------- the relay withholds a post

def _reader_pull(m, tmp_path, now):
    st = State.load(tmp_path / "reader-state")
    res = pull.fetch("https://mirror.example.invalid/alerts", st, fetch=m.fetch, root_pubkey=m.root, now=now)
    return res, State.load(tmp_path / "reader-state")


@pytest.mark.parametrize("how", ["checkpoint dropped", "the pull fails in that run", "the run dies after the acknowledgement"])
def test_an_acknowledged_post_stays_owed_until_the_mirror_shows_it(signing, tmp_path, monkeypatch, how):
    """The relay acknowledges a post, never exports it, and loses that run's checkpoint.
    Every later checkpoint lists the post, so a reader served one reads incomplete; the
    relay cannot get a clean checkpoint by waiting an hour."""
    m = signing.mirror
    on_mirror(m, "On the mirror", T0 - 500)
    signing.collector([finding()])
    if how == "the pull fails in that run":
        real = signer.run_checkpoint
        monkeypatch.setattr(signer, "run_checkpoint", lambda *a, **k: "no-mirror")
        signing.run(ssh=PutSSH())
        monkeypatch.setattr(signer, "run_checkpoint", real)
    elif how == "the run dies after the acknowledgement":
        class Dies(BaseException):
            pass

        def die(*a, **k):
            raise Dies
        monkeypatch.setattr(signer, "run_checkpoint", die)
        monkeypatch.setattr(main.Run, "_record", die)  # right after the send, before the ledger learns it
        with pytest.raises(Dies):
            signing.run(ssh=PutSSH())
        monkeypatch.undo()
    else:
        signing.run(ssh=PutSSH())
    withheld = owed_ids(signing)
    assert withheld  # written at the acknowledgement
    for hour in (1, 2, 3):
        _, summary, ssh = signing.run(ssh=PutSSH(), now=T0 + hour * 3600)
        assert summary.split(" checkpoint=")[1] == "sent" and set(withheld) <= ssh.last().events
    m.clock = T0 + 3 * 3600
    m.stored_checkpoint = ssh.last().event
    res, st = _reader_pull(m, tmp_path, T0 + 3 * 3600 + 60)
    assert res.error == "mirror incomplete"
    _, summary, ssh = signing.run(ssh=PutSSH(), now=T0 + signer.OWED_S + 3600)
    assert "checkpoint=sent,owed_dropped=" in summary and not set(withheld) & ssh.last().events
    assert not set(withheld) & set(owed_ids(signing))


def test_a_post_seen_on_the_mirror_is_no_longer_owed(signing):
    m = signing.mirror
    signing.collector([finding()])
    _, _, ssh = signing.run(ssh=PutSSH())
    (sent,) = [i for i in owed_ids(signing)][:1]
    ev = on_mirror(m, "Stand-in", T0 + 10)
    rec = signer.load_owed(signing.config.owed_state)
    rec["owed"] = [dict(rec["owed"][0], id=ev["id"])]  # as if the relay exported what was sent
    signer.save_owed(signing.config.owed_state, rec)
    signing.run(ssh=PutSSH(), now=T0 + 3600)
    assert owed_ids(signing) == [] and sent


def test_a_crowded_run_lists_every_acknowledged_post_or_signs_nothing(signing, monkeypatch):
    for i in range(200):
        signer.record_sent(signing.config.owed_state, f"{i:064x}", 300, None, T0)
    _, summary, ssh = signing.run(ssh=PutSSH())
    assert summary.endswith(" checkpoint=sent") and {f"{i:064x}" for i in range(200)} <= ssh.last().events
    monkeypatch.setattr(signer, "MAX_LISTED", 150)
    _, summary, ssh = signing.run(ssh=PutSSH(), now=T0 + 60)
    assert summary.endswith(" checkpoint=too-large") and ssh.puts == []
    assert len(owed_ids(signing)) == 200  # none forgotten


def test_default_second_origin_is_not_consulted_by_the_poster(signing):
    """The poster reads the mirror it signs for and nothing else."""
    assert member_config.DEFAULT_SECOND_ORIGIN.startswith("https://")
    seen = []
    m = signing.mirror

    def fetch(url, timeout=None):
        seen.append(url)
        return m.fetch(url)
    signing.run(ssh=PutSSH(), mirror_fetch=fetch)
    assert seen and all(u.startswith(signing.config.translate_mirror_url) for u in seen)
