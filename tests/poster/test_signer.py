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
from test_main import T0, FakeRelay, env, finding  # noqa: F401 - env is a fixture

DAY = 86400
PUT = "/opt/relay/bin/mirror-put"
HOST = "op@relay.example.net"
FEED = frozenset(CHANNELS.values())


class PutRelay(FakeRelay):
    """FakeRelay that is also the checkpoint route's ssh: posts arrive as sends, a
    checkpoint as ``<PUT> checkpoint`` over ssh. ``puts`` holds each document;
    ``put_ok`` False makes the storing command refuse. Anything else over ssh fails
    the test: the route carries checkpoints only."""

    def __init__(self, *outcomes, put_ok=True, **kw):
        super().__init__(*outcomes, **kw)
        self.puts, self.put_ok, self.argvs = [], put_ok, []

    def __call__(self, *args, **kw):
        if "input" not in kw:  # a post: send(channel_id, text, reply_to)
            return super().__call__(*args, **kw)
        argv = args[0]
        self.argvs.append(list(argv))
        assert shlex.split(argv[-1]) == [PUT, "checkpoint"], argv
        self.puts.append(kw["input"])
        if not self.put_ok:
            return subprocess.CompletedProcess(argv, 1, b"", b'{"error":"user_error","message":"mirror-put: x"}\n')
        return subprocess.CompletedProcess(argv, 0, b'{"stored":true,"bytes":1}\n', b"")

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
    env.config = replace(env.config, checkpoint_key_file=key, relay_ssh_host=HOST, relay_put_wrapper=PUT)
    signer.init_owed(env.config.owed_state)  # as checkpoint-keygen does for a new key
    env.key = key
    return env


def owed_ids(env):  # noqa: F811
    return [o["id"] for o in signer.load_owed(env.config.owed_state, T0)["owed"]]


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
    cfg = load(f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_ssh_host = "{HOST}"\nrelay_put_wrapper = "{PUT}"\n')
    assert str(cfg.checkpoint_key_file) == f"{tmp_path}/c.nsec" and cfg.relay_put_wrapper == PUT
    for bad in (f'checkpoint_key_file = "{tmp_path}/c.nsec"\n', f'relay_ssh_host = "{HOST}"\nrelay_put_wrapper = "{PUT}"\n',
                f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_put_wrapper = "{PUT}"\n',  # no route host
                f'checkpoint_key_file = "c.nsec"\nrelay_ssh_host = "{HOST}"\nrelay_put_wrapper = "{PUT}"\n',
                f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_put_wrapper = "mirror-put x"\n'):
        with pytest.raises(inputs.ConfigError):
            load(bad)


def test_checkpoint_keygen_command_prints_only_the_npub(tmp_path, capsys):
    cfg = tmp_path / "poster.toml"
    cfg.write_text(f'ledger = "{tmp_path}/l.json"\nkev_cache = "{tmp_path}/k.json"\n')
    assert main.main(["checkpoint-keygen", "--config", str(cfg)]) == 2  # not configured
    assert "checkpoint_key_file" in capsys.readouterr().err
    cfg.write_text(cfg.read_text() + f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_ssh_host = "{HOST}"\nrelay_put_wrapper = "{PUT}"\n')
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
    signer.init_owed(path)
    signer.record_sent(path, a, 100, None, 1000)
    signer.record_sent(path, b, 50, root, 2000)
    signer.record_sent(path, a, 100, None, 3000)  # once
    signer.record_sent(path, "not-an-id", 5, None, 3000)
    rec = signer.load_owed(path, 3000)
    assert rec["hold_until"] == 0 and rec["owed"] == [{"id": a, "bytes": 100 + signer.ENVELOPE, "since": 1000, "root": None},
                           {"id": b, "bytes": 50 + signer.ENVELOPE, "since": 2000, "root": root}]
    assert signer.settle_owed(rec["owed"], {a}, 3000) == ([rec["owed"][1]], 0, set())
    assert signer.settle_owed(rec["owed"], set(), 1000 + signer.OWED_S - 1) == (rec["owed"], 0, set())
    assert signer.settle_owed(rec["owed"], set(), 1000 + signer.OWED_S) == ([rec["owed"][1]], 1, set())
    many = [{"id": f"{i:064x}", "bytes": 10**6, "since": 5} for i in range(500)]
    assert signer.settle_owed([dict(o, root=None) for o in many], set(), 6)[1] == 0  # never dropped for room
    signer.init_owed(path)  # never replaces a record
    assert len(signer.load_owed(path, 3000)["owed"]) == 2


@pytest.mark.parametrize("damage", ["missing", "not json", "wrong shape", "old shape"])
def test_a_lost_owed_record_holds_signing_for_the_owed_period(tmp_path, damage, capsys):
    """The record is the only memory of what the relay acknowledged. Lost, the poster
    cannot know what it owes: it signs nothing for 72 hours instead of starting clean."""
    path = tmp_path / "owed.json"
    if damage == "not json":
        path.write_text("{")
    elif damage == "wrong shape":
        path.write_text(json.dumps({"last_seq": 1, "owed": [{"id": "x"}], "hold_until": 0}))
    elif damage == "old shape":
        path.write_text(json.dumps({"last_seq": 1, "owed": []}))
    assert signer.load_owed(path, 5000) == {"last_seq": 0, "owed": [], "hold_until": 5000 + signer.OWED_S, "gone": {}}
    assert "no checkpoint is signed for 72 hours" in capsys.readouterr().err
    signer.record_sent(path, "a" * 64, 10, None, 5000)  # a send in that state writes the hold down with the debt
    rec = signer.load_owed(path, 6000)
    assert rec["hold_until"] == 5000 + signer.OWED_S and [o["id"] for o in rec["owed"]] == ["a" * 64]


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
    assert set(got) == {e["id"] for t in threads[2:] for e in t}  # the three newest, whole (18 events)
    monkeypatch.setattr(signer, "MAX_LISTED", 12)
    small = on_mirror(m, "Small and older", T0 - 99000, sec=m.bot_sec)
    got = _win(m)  # a thread that does not fit is skipped and an older, smaller one still gets in
    assert set(got) == {e["id"] for t in threads[3:] for e in t}
    monkeypatch.setattr(signer, "MAX_LISTED", 13)
    assert set(_win(m)) == {e["id"] for t in threads[3:] for e in t} | {small["id"]}


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
    for i in range(3):
        _thread(m, f"T{i}", T0 - 1000 * (i + 1), retract_at=T0 - 1000 * (i + 1) + 50)
    assert _win(m) is None  # three roots with their retractions: six events, room for five
    monkeypatch.setattr(signer, "MAX_LISTED", 6)
    assert len(_win(m)) == 6
    owed = [{"id": f"{i:064x}", "bytes": 10, "since": T0, "root": None} for i in range(3)]
    assert _win(m, owed) is None  # the owed ids are never the ones dropped
    plain = Mirror()
    monkeypatch.setattr(signer, "MAX_LISTED", 5)
    for i in range(400):
        on_mirror(plain, f"Digest {i}", T0 - 100 * (i + 1), sec=plain.bot_sec)
    events = {e["id"]: e for evs in plain.events.values() for e in evs}
    got = signer.window(events.values(), plain.man, [], T0, FEED)
    assert len(got) == 5  # plain roots are never the reason to refuse: the newest five are listed
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
    assert got[0] == "a" * 64 and old[0]["id"] in got  # the reply the relay acknowledged, and its root
    assert len(got) == 4  # then the newer thread whole; the old parent's bot replies did not fit


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
    code, summary, ssh = signing.run(relay=PutRelay())
    assert code == 0 and summary.endswith(" checkpoint=sent") and len(ssh.puts) == 1
    c = ssh.last()
    cert = cp.load_cert(json.dumps(m.cert).encode())
    assert cp.verify_checkpoint(c, cert) and cp.checkpoint_problem(c, m.man, T0) is None
    assert c.seq == T0 and c.created_at == T0 and c.valid_until == T0 + DAY
    sent = set(ssh.ids)  # what this run posted: acknowledged, not on the mirror yet
    assert sent and c.events == {a["id"], gone["id"]} | sent | {o for o in owed_ids(signing)}
    assert set(owed_ids(signing)) >= sent
    assert signer.load_owed(signing.config.owed_state, T0)["last_seq"] == T0
    sec = signer.read_key(signing.key)
    seen = capsys.readouterr()
    everything = seen.out + seen.err + summary + " ".join(" ".join(a) for a in ssh.argvs)
    assert sec not in everything and nostr.nsec(sec) not in everything
    assert all(sec.encode() not in p and nostr.nsec(sec).encode() not in p for p in ssh.puts)


def test_without_the_config_keys_nothing_changes(env):  # noqa: F811
    env.collector([finding()])
    code, summary, ssh = env.run(relay=PutRelay())
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
    code, summary, ssh = signing.run(relay=PutRelay())
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
    _, summary, ssh = signing.run(relay=PutRelay())
    assert summary.endswith(" checkpoint=sent")
    m.publish_manifest(issued=T0 - 300)  # a new manifest, with its certificate
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 60)
    assert summary.endswith(" checkpoint=sent") and ssh.last().manifest_id == m.manifest["id"]


def test_failures_never_change_the_runs_exit_code(signing, monkeypatch):
    _, summary, ssh = signing.run(relay=PutRelay(put_ok=False))
    assert summary.endswith(" checkpoint=failed") and len(ssh.puts) == 1
    signing.mirror.raw["manifest.json"] = None
    code, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 60)
    assert code == 0 and summary.endswith(" checkpoint=no-mirror") and ssh.puts == []
    signing.mirror.raw.pop("manifest.json")
    signing.key.chmod(0o644)
    code, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 120)
    assert code == 0 and summary.endswith(" checkpoint=error") and ssh.puts == []


def test_two_runs_in_one_second_and_a_lost_state_file(signing):
    _, _, ssh = signing.run(relay=PutRelay())
    first = ssh.last()
    _, _, ssh = signing.run(relay=PutRelay())  # the same second
    second = ssh.last()
    assert (first.seq, second.seq) == (T0, T0 + 1)
    signing.mirror.raw["checkpoint.json"] = json.dumps(second.event).encode()  # the mirror publishes it
    signing.config.owed_state.unlink()  # the record is lost while the count is ahead of the clock
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 1)
    assert summary.endswith(" checkpoint=held") and ssh.puts == []  # what was owed is unknown: nothing is signed
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + signer.OWED_S)
    assert summary.endswith(" checkpoint=held") and ssh.puts == []
    signing.mirror.clock = T0 + signer.OWED_S + 2
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + signer.OWED_S + 1)
    third = ssh.last()  # the hold is over; the published checkpoint supplied the floor for the number
    assert summary.endswith(" checkpoint=sent") and third.seq == T0 + signer.OWED_S + 1
    assert cp.checkpoint_order(third, second) is None
    signing.config.owed_state.write_text(json.dumps({"last_seq": 0, "owed": [], "hold_until": 0, "gone": {}}))
    _, _, ssh = signing.run(relay=PutRelay(), now=T0 + 1)  # a fresh record, the clock behind the published number
    assert ssh.last().seq == T0 + 2


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
        signing.run(relay=PutRelay())
        monkeypatch.setattr(signer, "run_checkpoint", real)
    elif how == "the run dies after the acknowledgement":
        class Dies(BaseException):
            pass

        def die(*a, **k):
            raise Dies
        monkeypatch.setattr(signer, "run_checkpoint", die)
        monkeypatch.setattr(main.Run, "_record", die)  # right after the send, before the ledger learns it
        with pytest.raises(Dies):
            signing.run(relay=PutRelay())
        monkeypatch.undo()
    else:
        signing.run(relay=PutRelay())
    withheld = owed_ids(signing)
    assert withheld  # written at the acknowledgement
    for hour in (1, 2, 3):
        _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + hour * 3600)
        assert summary.split(" checkpoint=")[1] == "sent" and set(withheld) <= ssh.last().events
    m.clock = T0 + 3 * 3600
    m.stored_checkpoint = ssh.last().event
    res, st = _reader_pull(m, tmp_path, T0 + 3 * 3600 + 60)
    assert res.error == "mirror incomplete"
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + signer.OWED_S + 3600)
    assert "checkpoint=sent,owed_dropped=" in summary and not set(withheld) & ssh.last().events
    assert not set(withheld) & set(owed_ids(signing))


def test_a_post_seen_on_the_mirror_is_no_longer_owed(signing):
    m = signing.mirror
    signing.collector([finding()])
    _, _, ssh = signing.run(relay=PutRelay())
    (sent,) = [i for i in owed_ids(signing)][:1]
    ev = on_mirror(m, "Stand-in", T0 + 10)
    rec = signer.load_owed(signing.config.owed_state, T0)
    rec["owed"] = [dict(rec["owed"][0], id=ev["id"])]  # as if the relay exported what was sent
    signer.save_owed(signing.config.owed_state, rec)
    signing.run(relay=PutRelay(), now=T0 + 3600)
    assert owed_ids(signing) == [] and sent


def test_a_crowded_run_lists_every_acknowledged_post_or_signs_nothing(signing, monkeypatch):
    for i in range(200):
        signer.record_sent(signing.config.owed_state, f"{i:064x}", 300, None, T0)
    _, summary, ssh = signing.run(relay=PutRelay())
    assert summary.endswith(" checkpoint=sent") and {f"{i:064x}" for i in range(200)} <= ssh.last().events
    monkeypatch.setattr(signer, "MAX_LISTED", 150)
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 60)
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
    signing.run(relay=PutRelay(), mirror_fetch=fetch)
    assert seen and all(u.startswith(signing.config.translate_mirror_url) for u in seen)


# ---------------------------------------------------------------- findings of the code review

def test_an_owed_reply_brings_its_old_threads_retraction(monkeypatch):
    """A root and its curator retraction are 399 days old: past the 398-day line, still
    in the poster's store. The poster replied to that thread and the relay withholds the
    reply from the mirror. The checkpoint must list the retraction with the root."""
    m = Mirror()
    old = T0 - pull.RETENTION_S + DAY
    root = on_mirror(m, "Retracted long ago", old, sec=m.bot_sec)
    gone = m.reply(m.cur_sec, root, "retract", created_at=old + 60)
    assert _win(m) == []  # by itself the thread is past the line
    owed = [{"id": "a" * 64, "bytes": 10, "since": T0, "root": root["id"]}]
    assert set(_win(m, owed)) == {"a" * 64, root["id"], gone["id"]}


def test_the_event_that_keeps_an_old_thread_alive_is_mandatory(monkeypatch):
    """When root and corrections are all old, the thread's newest event must be listed
    with them; if there is no room for it, nothing is signed."""
    m = Mirror()
    edge = T0 - pull.RETENTION_S
    root = on_mirror(m, "Ancient", edge - 50 * DAY, sec=m.bot_sec)
    fix = m.reply(m.cur_sec, root, "level: notice", created_at=edge - 10 * DAY)
    recent = m.post(m.bot_sec, "note", created_at=T0 - 100, tags=[("e", root["id"], "", "root")])
    for i in range(3):
        _thread(m, f"Recent {i}", T0 - 50 - i)
    monkeypatch.setattr(signer, "MAX_LISTED", 2)
    assert _win(m) is None  # the ancient root and its correction fit, the event that keeps them alive does not
    monkeypatch.setattr(signer, "MAX_LISTED", 3)
    assert set(_win(m)) == {root["id"], fix["id"], recent["id"]}  # before any recent thread
    monkeypatch.setattr(signer, "MAX_LISTED", 990)
    kept = {e["id"]: e for evs in m.events.values() for e in evs if e["id"] in _win(m)}
    assert root["id"] in pull._retain(kept, T0, pull.PullResult())  # a reader keeps the ancient thread


def test_a_debt_that_cannot_be_written_stops_the_run_from_signing(signing, monkeypatch):
    """The relay acknowledged a post and the owed record could not be written. The run
    fails (exit 1) and must not sign: its checkpoint would omit the post. The next run
    replays the journaled item, records the debt, and lists it."""
    signing.collector([finding()])
    real = signer.record_sent

    def fails(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(signer, "record_sent", fails)
    code, summary, ssh = signing.run(relay=PutRelay())
    assert code == 1 and summary.split(" checkpoint=")[1].startswith("owed-unrecorded") and ssh.puts == []
    monkeypatch.setattr(signer, "record_sent", real)
    code, summary, ssh2 = signing.run(relay=PutRelay(), now=T0 + 60)
    assert " checkpoint=sent" in summary and set(ssh.ids) <= ssh2.last().events
    assert set(ssh.ids) <= set(owed_ids(signing))


def test_a_mirror_that_drips_bytes_cannot_hold_the_run(signing, monkeypatch):
    """Every read of the mirror is inside one wall-clock bound, the certificate and the
    published checkpoint included."""
    from aitools_alerts.poster import translate
    seen = []
    real = translate.bounded

    def bounded(fn, deadline):
        seen.append(deadline)
        return real(fn, deadline)
    monkeypatch.setattr(translate, "bounded", bounded)
    fetched = []
    m = signing.mirror

    def fetch(url, timeout=None):
        fetched.append((url.rsplit("/", 1)[1], len(seen)))
        return m.fetch(url)
    signing.run(relay=PutRelay(), mirror_fetch=fetch)
    inside = [name for name, depth in fetched if name in ("checkpoint-key.json", "checkpoint.json")]
    assert "checkpoint-key.json" in inside and "checkpoint.json" in inside
    import inspect
    src = inspect.getsource(signer.run_checkpoint)
    after = src.split("translate.bounded(read_mirror", 1)[1]
    assert "get(base" not in after and "get(url" not in after and "pull.fetch(" not in after  # no read outside the bound

    def stalls(url, timeout=None):
        if url.endswith("checkpoint-key.json"):
            raise translate.CallError("timeout")
        return m.fetch(url)
    monkeypatch.setattr(translate, "bounded", lambda fn, deadline: (_ for _ in ()).throw(translate.CallError("timeout")))
    code, summary, ssh = signing.run(relay=PutRelay(), mirror_fetch=stalls, now=T0 + 60)
    assert code == 0 and " checkpoint=no-mirror" in summary and ssh.puts == []


def test_curator_roots_in_test_salvage_are_listed_first(monkeypatch):
    """Roots matter only with their corrections: a thread with a curator reply has root
    and reply in the must-list; the bloated thread's other replies are what is left out."""
    m = Mirror()
    monkeypatch.setattr(signer, "MAX_LISTED", 4)
    huge = _thread(m, "Bloated", T0 - 3000, replies=30, retract_at=T0 - 2000)
    got = set(_win(m))
    assert got == {huge[0]["id"], huge[-1]["id"]}


def test_keygen_command_starts_the_owed_record_without_a_hold(tmp_path, capsys):
    cfg = tmp_path / "poster.toml"
    cfg.write_text(f'ledger = "{tmp_path}/l.json"\nkev_cache = "{tmp_path}/k.json"\n'
                   f'checkpoint_key_file = "{tmp_path}/c.nsec"\nrelay_ssh_host = "{HOST}"\nrelay_put_wrapper = "{PUT}"\n')
    assert main.main(["checkpoint-keygen", "--config", str(cfg)]) == 0
    rec = signer.load_owed(inputs.load_config(cfg).owed_state, T0)
    assert rec == {"last_seq": 0, "owed": [], "hold_until": 0, "gone": {}}


# ---------------------------------------------------------------- findings of the same-model pass

def test_a_post_stamped_after_the_run_began_stays_owed_until_it_can_be_listed(signing):
    """The relay stamps a post after the run's own start time, and the exporter can show
    it before the run's pull. It cannot be listed yet (it is dated after the signing
    time), so it must not be settled yet either."""
    m = signing.mirror
    late = on_mirror(m, "Stamped five seconds after the run began", T0 + 5, sec=m.bot_sec)
    signer.record_sent(signing.config.owed_state, late["id"], 100, None, T0)
    _, summary, ssh = signing.run(relay=PutRelay())
    assert summary.endswith(" checkpoint=sent")
    assert late["id"] in ssh.last().events and late["id"] in owed_ids(signing)  # listed as owed, still owed
    _, _, ssh = signing.run(relay=PutRelay(), now=T0 + 3600)
    assert late["id"] in ssh.last().events and late["id"] not in owed_ids(signing)  # listed from the mirror


def test_an_event_that_leaves_the_mirror_is_listed_for_three_days_then_given_up(signing, tmp_path):
    """The poster keeps listing an event the mirror stopped serving (readers refuse the
    mirror and read stale: the drop is noticed), and gives it up after 72 hours, or a
    post that was truly deleted would keep every reader stale for a year."""
    m = signing.mirror
    stays = on_mirror(m, "Stays", T0 - 600)
    goes = on_mirror(m, "Goes", T0 - 500)
    signing.run(relay=PutRelay())
    for name in m.events:
        m.events[name] = [e for e in m.events[name] if e["id"] != goes["id"]]
    for hours in (1, 30, 71):
        _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + hours * 3600)
        assert goes["id"] in ssh.last().events and "gone_dropped" not in summary
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 74 * 3600)
    assert "checkpoint=sent,gone_dropped=1" in summary
    assert goes["id"] not in ssh.last().events and stays["id"] in ssh.last().events
    assert goes["id"] not in State.load(signing.config.mirror_dir).events
    m.events["feed.json"].append(goes)  # it comes back: it is simply an event on the mirror again
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 75 * 3600)
    assert goes["id"] in ssh.last().events and "gone_dropped" not in summary


def test_an_owed_reply_records_the_root_of_its_own_channel(signing):
    """A critical has one root per channel; an update's reply in the feed is owed with the
    feed root, not the critical channel's."""
    from test_main import FakeKEV, kev_fixed, kev_item
    kev_fixed(signing)  # 9kgk: KEV plus the vendor's fix makes the critical
    signing.run(relay=PutRelay(), kev=FakeKEV(catalog={"vulnerabilities": [kev_item()]}))
    entries, _ = signing.ledger()
    (entry,) = entries.values() if isinstance(entries, dict) else entries
    roots = entry["channel_ids"]
    assert set(roots) == {"feed", "critical"} and roots["feed"] != roots["critical"]
    rec = signer.load_owed(signing.config.owed_state, T0)
    by_id = {o["id"]: o for o in rec["owed"]}
    assert by_id[roots["feed"]]["root"] is None and by_id[roots["critical"]]["root"] is None
    replies = [o for o in rec["owed"] if o["root"] is not None]
    assert replies and all(o["root"] in roots.values() for o in replies)  # the Japanese replies name their own root
    it = {"kind": "reply", "sent": "e" * 64, "text": "x", "ids": entry["aliases"], "scope": entry["scope"],
          "channel": "feed", "root": roots["critical"]}
    with main.Ledger(signing.config.ledger) as led:
        run = main.Run(T0, signing.config, led, {"outbox": []}, CHANNELS, PutRelay(), None)
        run._owe(it)
    assert {o["id"]: o for o in signer.load_owed(signing.config.owed_state, T0)["owed"]}["e" * 64]["root"] == roots["feed"]


def test_a_crash_between_the_journal_and_the_owed_record_is_made_good_on_replay(signing, monkeypatch):
    """The send's id is in the journal; the process dies before the debt is written.
    The next run replays the item and records the debt before it signs."""
    signing.collector([finding()])

    class Dies(BaseException):
        pass
    real = main.Run._owe

    def die(self, it):
        raise Dies
    monkeypatch.setattr(main.Run, "_owe", die)
    ssh = PutRelay()
    with pytest.raises(Dies):
        signing.run(relay=ssh)
    assert owed_ids(signing) == [] and ssh.ids  # acknowledged, journaled, not yet owed
    monkeypatch.setattr(main.Run, "_owe", real)
    _, summary, ssh2 = signing.run(relay=PutRelay(), now=T0 + 60)
    assert ssh.ids[0] in owed_ids(signing) and ssh.ids[0] in ssh2.last().events


def test_key_file_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "k.nsec"
    signer.keygen(path)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(signer.KeyFileError, match="not owned"):
        signer.read_key(path)


@pytest.mark.parametrize("error", [RuntimeError("x"), ValueError("x"), cp.CheckpointError("x"), OSError(5, "io")])
def test_any_failure_inside_the_signer_leaves_the_runs_exit_code_alone(signing, monkeypatch, error):
    def boom(*a, **k):
        raise error
    monkeypatch.setattr(signer, "window", boom)
    code, summary, ssh = signing.run(relay=PutRelay())
    assert code == 0 and summary.endswith(" checkpoint=error") and ssh.puts == []


def test_a_published_checkpoint_by_another_key_is_no_floor_for_the_number(signing):
    m = signing.mirror
    other = cp.build_checkpoint(nostr.keygen()[0], m.man, T0 + 10**6, [], T0 - 60)
    m.raw["checkpoint.json"] = json.dumps(other).encode()
    _, _, ssh = signing.run(relay=PutRelay())
    assert ssh.last().seq == T0  # a checkpoint anyone could have written does not move the number


def test_settled_debts_are_saved_even_when_nothing_is_signed(signing, monkeypatch):
    m = signing.mirror
    seen = on_mirror(m, "Seen", T0 - 100, sec=m.bot_sec)
    signer.record_sent(signing.config.owed_state, seen["id"], 10, None, T0 - 50)
    signer.record_sent(signing.config.owed_state, "d" * 64, 10, None, T0 - 50)
    monkeypatch.setattr(signer, "MAX_LISTED", 0)
    _, summary, ssh = signing.run(relay=PutRelay())
    assert summary.endswith(" checkpoint=too-large") and owed_ids(signing) == ["d" * 64]


# ---------------------------------------------------------------- findings of the delta review

def test_a_vanished_curator_reply_is_never_given_up_its_thread_is_left_out(signing):
    """The mirror keeps the root and drops the curator's retraction. After 72 hours the
    poster must not sign the root without it: the thread is left out of checkpoints for
    as long as the retraction is missing, and the retraction is never forgotten."""
    m = signing.mirror
    other = on_mirror(m, "Another alert", T0 - 700)
    root = on_mirror(m, "Retracted", T0 - 600)
    gone = m.reply(m.cur_sec, root, "retract", created_at=T0 - 500)
    _, _, ssh = signing.run(relay=PutRelay())
    assert {root["id"], gone["id"]} <= ssh.last().events
    m.events["feed.json"].remove(gone)
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 3600)
    assert {root["id"], gone["id"]} <= ssh.last().events  # still listed: readers refuse the mirror
    for hours in (74, 200):
        _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + hours * 3600)
        listed = ssh.last().events
        assert "threads_suppressed=1" in summary and "gone_dropped" not in summary
        assert root["id"] not in listed and gone["id"] not in listed and other["id"] in listed
        assert gone["id"] in State.load(signing.config.mirror_dir).events  # never forgotten
    m.events["feed.json"].append(gone)  # the mirror serves it again: the thread is back, retracted
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 201 * 3600)
    assert {root["id"], gone["id"]} <= ssh.last().events and "threads_suppressed" not in summary


def test_a_bare_id_or_a_broken_copy_does_not_count_as_served(signing):
    """Only a validly signed event in the fetched files counts as served. A placeholder
    with a known id, or a copy with a bad signature, must not stop the absence clock."""
    m = signing.mirror
    stays = on_mirror(m, "Stays", T0 - 600)
    goes = on_mirror(m, "Goes", T0 - 500)
    signing.run(relay=PutRelay())
    broken = dict(goes, sig="0" * 128)
    for fake in ({"id": goes["id"]}, broken):
        for name in m.events:  # the event was posted to both channel files
            m.events[name] = [e for e in m.events[name] if e.get("id") != goes["id"]] + [fake]
        _, summary, _ = signing.run(relay=PutRelay(), now=T0 + 3600)
        rec = signer.load_owed(signing.config.owed_state, T0 + 3600)
        assert goes["id"] in rec["gone"] and stays["id"] not in rec["gone"], summary
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 80 * 3600)
    assert "gone_dropped=1" in summary and goes["id"] not in ssh.last().events


@pytest.mark.parametrize("drop", ["relay_ssh_host", "relay_put_wrapper", "checkpoint_key_file"])
def test_a_config_built_in_code_with_two_of_the_three_checkpoint_keys_never_posts(signing, drop, capsys):
    """check_relay applies load_config's all-or-none rule (vzc3, after nfm3): a run stops
    before it posts instead of posting with the checkpoint silently off."""
    signing.collector([finding()])
    signing.config = replace(signing.config, **{drop: None})
    relay = PutRelay()
    code, summary, _ = signing.run(relay=relay)
    assert code == 2 and "error=config" in summary and relay.calls == [] and relay.puts == []
    assert "go together" in capsys.readouterr().err


# ---------------------------------------------------------------- renewals (ai-tools-alerts#gtw9)

def _claim(at, checked=None, cve="CVE-2026-0001"):
    """The poster's own claim tag for a KEV reading, confirmed at ``at``."""
    from aitools_alerts import wire
    from aitools_alerts.poster import rules
    obj = json.loads(rules.claim_text([("kev", {"cve_id": cve, "name": "Anthropic Claude Code"})], [cve], "Claude Code", at))
    return wire.claim_tag({**obj, "checked_at": checked or at})


def _renewal(m, root, at, confirmed=None, text="Sources checked. No change to this alert."):
    return m.post(m.bot_sec, text, created_at=at,
                  tags=[["e", root["id"], "", "root"], _claim(confirmed or at, at)])


def test_a_renewal_the_mirror_stops_serving_is_never_given_up_its_thread_is_left_out(signing):
    """The mirror keeps a claimed root and hides its renewal. Listed without it, the
    alert would decay on every reader: after 72 hours the thread is left out instead,
    until the mirror serves that renewal or a later one."""
    m = signing.mirror
    other = on_mirror(m, "Another alert", T0 - 700)
    root = m.root_post(m.bot_sec, advisory(id="CVE-2026-0001", posted_by="relay-bot"), created_at=T0 - 600,
                       tags=[_claim(T0 - 600)], files=("feed.json",))
    hidden = _renewal(m, root, T0 - 500, confirmed=T0 - 600)
    assert signer.renewals_of(hidden, m.man) == [(T0 - 600, T0 - 500)] and signer.renewals_of(root, m.man) == []
    _, _, ssh = signing.run(relay=PutRelay())
    assert {root["id"], hidden["id"]} <= ssh.last().events
    m.events["feed.json"].remove(hidden)
    _, _, ssh = signing.run(relay=PutRelay(), now=T0 + 3600)
    assert {root["id"], hidden["id"]} <= ssh.last().events  # still listed: readers refuse the mirror
    for hours in (74, 200):
        _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + hours * 3600)
        assert "threads_suppressed=1" in summary and "gone_dropped" not in summary
        assert root["id"] not in ssh.last().events and other["id"] in ssh.last().events
    later = _renewal(m, root, T0 + 200 * 3600, confirmed=T0 - 600)  # a later check: the hidden one adds nothing now
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 201 * 3600)
    assert "gone_dropped=1" in summary and "threads_suppressed" not in summary
    assert {root["id"], later["id"]} <= ssh.last().events and hidden["id"] not in ssh.last().events


def test_a_hidden_reply_in_a_thread_whose_root_has_no_claim_is_given_up_as_before(signing):
    m = signing.mirror
    root = on_mirror(m, "Posted before claims", T0 - 600, sec=m.bot_sec)
    reply = _renewal(m, root, T0 - 500)
    signing.run(relay=PutRelay())
    m.events["feed.json"].remove(reply)
    signing.run(relay=PutRelay(), now=T0 + 3600)
    _, summary, ssh = signing.run(relay=PutRelay(), now=T0 + 74 * 3600)
    assert "gone_dropped=1" in summary and "threads_suppressed" not in summary and root["id"] in ssh.last().events


def test_an_owed_renewal_is_kept_past_72_hours_until_a_later_one_is_held(tmp_path):
    path, root, a, b = tmp_path / "owed.json", "c" * 64, "a" * 64, "b" * 64
    signer.init_owed(path)
    signer.record_sent(path, a, 100, root, 1000, renewal=(900, 1000))
    signer.record_sent(path, b, 100, root, 1000)
    signer.record_sent(path, "d" * 64, 100, None, 1000, renewal=(900, 1000))  # no thread: nothing to renew
    owed = signer.load_owed(path, 1000)["owed"]
    assert [o.get("renewal") for o in owed] == [[900, 1000], None, None]
    late = 1000 + signer.OWED_S
    kept, dropped, suppress = signer.settle_owed(owed, set(), late)
    assert [o["id"] for o in kept] == [a] and dropped == 2 and suppress == {root}
    assert signer.settle_owed(owed, set(), late, {root: [(900, 999)]})[2] == {root}  # an earlier check replaces nothing
    assert signer.settle_owed(owed, set(), late, {root: [(900, 1000)]}) == ([], 2, set())
    assert signer.settle_owed(owed, {a}, late)[2] == set()  # the mirror shows it


def test_a_must_listed_thread_that_does_not_fit_whole_lists_the_renewals_that_keep_it_standing(monkeypatch):
    """An owed reply puts the thread on the must-list. Too large to list whole, it used
    to be listed as its root alone, which a reader would decay. Of two renewals with the
    same times one is listed, and one that another makes redundant is not."""
    m = Mirror()
    root = m.root_post(m.bot_sec, advisory(id="CVE-2026-0001", posted_by="relay-bot"), created_at=T0 - 9000,
                       tags=[_claim(T0 - 9000)], files=("feed.json",))
    for i in range(30):
        m.post(m.bot_sec, f"note {i}", created_at=T0 - 8000 + i, tags=[("e", root["id"], "", "root")])
    old = _renewal(m, root, T0 - 5000, confirmed=T0 - 9000)
    twins = sorted([_renewal(m, root, T0 - 100, confirmed=T0 - 9000),
                    _renewal(m, root, T0 - 100, confirmed=T0 - 9000, text="Sources checked again.")], key=lambda e: e["id"])
    assert twins[0]["id"] != twins[1]["id"] and signer.renewals_of(twins[0], m.man) == signer.renewals_of(twins[1], m.man)
    # a reply that names a level renews from its own date: later confirmed than the twins, earlier checked
    raised = m.post(m.bot_sec, m.patch_text(level="critical"), created_at=T0 - 6000, tags=[("e", root["id"], "", "root")])
    monkeypatch.setattr(signer, "MAX_LISTED", 10)
    owed = [{"id": "a" * 64, "bytes": 10, "since": T0, "root": root["id"]}]
    got = set(_win(m, owed))
    assert got == {"a" * 64, root["id"], twins[0]["id"], raised["id"]} and old["id"] not in got


def test_a_root_a_reader_would_decay_unasked_is_left_out_whatever_the_poster_knows(signing):
    """The signer's own rule, which asks nothing of the ledger: a claimed root whose
    renewals, as the poster's copy of the mirror has them, no longer hold the level the
    bot last named is not listed. So a renewal that was never sent (a failed send, a lost
    ledger, a channel a step never reached) pins the alert instead of lowering it."""
    m, DAYS = signing.mirror, 86400
    adv = advisory(id="CVE-2026-0001", posted_by="relay-bot")
    stale = m.root_post(m.bot_sec, adv, created_at=T0 - 15 * DAYS, tags=[_claim(T0 - 15 * DAYS)], files=("feed.json",))
    kept = m.root_post(m.bot_sec, adv, created_at=T0 - 15 * DAYS, tags=[_claim(T0 - 15 * DAYS)], files=("critical.json",))
    m.post(m.bot_sec, "Sources checked. No change to this alert.", created_at=T0 - 8 * DAYS, files=("critical.json",),
           tags=[["e", kept["id"], "", "root"], _claim(T0 - 15 * DAYS, T0 - 8 * DAYS)])
    plain = on_mirror(m, "No claim on its root", T0 - 300 * DAYS, sec=m.bot_sec)
    stepped = m.root_post(m.bot_sec, replace(adv, id="CVE-2026-0002", level="high"), created_at=T0 - 80 * DAYS,
                          tags=[_claim(T0 - 80 * DAYS, cve="CVE-2026-0002")], files=("feed.json",))
    m.post(m.bot_sec, m.patch_text(level="notice"), created_at=T0 - 36 * DAYS, tags=[["e", stepped["id"], "", "root"]])
    events = [e for evs in m.events.values() for e in evs]
    assert signer.lapsed(events, m.man, T0) == {stale["id"]}
    assert signer.lapsed(events, m.man, T0 - 2 * DAYS) == set()  # critical stood for 14 days
    _, summary, ssh = signing.run(relay=PutRelay())
    listed = ssh.last().events
    assert "threads_suppressed=1" in summary and stale["id"] not in listed
    assert {kept["id"], plain["id"], stepped["id"]} <= listed


def _stale_root(m, cve="CVE-2026-0001", days=20):
    return m.root_post(m.bot_sec, advisory(id=cve, posted_by="relay-bot"), created_at=T0 - days * 86400,
                       tags=[_claim(T0 - days * 86400, cve=cve)], files=("feed.json",))


def _lapsed(m, now=T0):
    return signer.lapsed([e for evs in m.events.values() for e in evs], m.man, now)


def test_the_signers_rule_is_the_readers_a_curator_hold_another_ids_claim_and_a_refused_block():
    """What may not excuse a stale root: a curator's discussion or a hold that has run
    out, a recent claim about an id the thread never held, and a block the reader
    refuses that names a lower level."""
    m = Mirror()
    root = _stale_root(m)
    assert _lapsed(m) == {root["id"]}
    m.reply(m.cur_sec, root, "A curator's note, no block.", created_at=T0 - 1000)
    assert _lapsed(m) == {root["id"]}
    m = Mirror()
    root = _stale_root(m, days=40)
    m.reply(m.cur_sec, root, m.patch_text(title="A better title"), created_at=T0 - 30 * 86400)  # its hold ran out 16 days ago
    assert _lapsed(m) == {root["id"]}
    m = Mirror()
    root = _stale_root(m)
    m.reply(m.cur_sec, root, m.patch_text(title="A better title"), created_at=T0 - 86400)  # a hold in force: no decay
    assert _lapsed(m) == set()
    m = Mirror()
    root = _stale_root(m)
    m.post(m.bot_sec, "Sources checked. No change to this alert.", created_at=T0 - 100,
           tags=[["e", root["id"], "", "root"], _claim(T0 - 100, cve="CVE-2026-9999")])
    assert _lapsed(m) == {root["id"]}
    m = Mirror()
    root = _stale_root(m)
    m.post(m.bot_sec, m.patch_text(level="notice", unexpected=True), created_at=T0 - 16 * 86400,
           tags=[["e", root["id"], "", "root"]])
    assert _lapsed(m) == {root["id"]}
    m = Mirror()
    plain = m.root_post(m.bot_sec, advisory(id="CVE-2026-0001", posted_by="relay-bot"), created_at=T0 - 20 * 86400,
                        tags=[_claim(T0 - 20 * 86400, cve="CVE-2026-9999")], files=("feed.json",))
    assert _lapsed(m) == set() and plain  # a root whose claim names another id is not enrolled on a reader


def test_a_signer_that_cannot_load_its_ruleset_signs_nothing(signing, monkeypatch):
    """Members with a sound ruleset would expire what this signer could not judge."""
    from aitools_alerts import ruleset
    signing.run(relay=PutRelay())
    real, load = signer.run_checkpoint, ruleset.load

    def broken():
        raise ruleset.RulesetError("damaged")

    def at_signing(*a, **k):  # the ruleset fails for the signer only: the run before it is whole
        ruleset.load = broken
        try:
            return real(*a, **k)
        finally:
            ruleset.load = load
    monkeypatch.setattr(signer, "run_checkpoint", at_signing)
    relay = PutRelay()
    _, summary, ssh = signing.run(relay=relay, now=T0 + 3600)
    assert "checkpoint=error" in summary and relay.puts == []


def test_the_renewals_of_a_root_the_poster_no_longer_holds_are_kept_for_its_return():
    m = Mirror()
    root = _stale_root(m, days=10)
    renewal = _renewal(m, root, T0 - 5 * 86400, confirmed=T0 - 10 * 86400)
    held = {renewal["id"]: renewal}  # the root was given up for missing; its renewal is still held and missing
    gone, drop, suppress = signer.settle_gone({renewal["id"]: T0 - signer.OWED_S}, held, set(), T0, m.man)
    assert drop == set() and suppress == {root["id"]} and renewal["id"] in gone
