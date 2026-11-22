"""The four attacks of ai-tools-alerts#ek5q, run through the member CLI against an
in-memory mirror with throwaway keys. Each docstring says whether the test shows new
enforcement (the parent reader accepted the mirror) or keeps behaviour the parent had."""

import json
import subprocess

import pytest

from aitools_alerts import cli, config, inventory, pull
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.state import State
from mirror_helpers import (FIXTURE_MIRROR, FIXTURE_ROOT, SECOND, T0, Boom, Mirror, advisory, break_write,
                            released_reader)

DAY = 86400
HOOK = FIXTURE_MIRROR.parents[2] / "hooks" / "claude-code" / "session-start.sh"


@pytest.fixture
def member(home, monkeypatch):
    """A member machine with Claude Code 2.0.0 installed, opted in to auto-apply
    upgrades, reading mirror ``m`` (returned) under its throwaway root."""
    m = Mirror()
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    config.write_default(force=True)
    config.config_path().write_text('trust_root_override = true\nmirror_url = "https://mirror.invalid/"\n'
                                    'auto_apply = ["upgrade"]\nnotify = []\n')
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)

    def no_exec(*a, **k):
        raise AssertionError(f"executed {a!r}")
    monkeypatch.setattr(subprocess, "run", no_exec)
    return m


def run(capsys, *argv):
    capsys.readouterr()
    code = cli.main(list(argv))
    got = capsys.readouterr()
    return code, got.out, got.err


def run_json(capsys):
    code, out, _ = run(capsys, "run", "--json")
    return code, json.loads(out)


def test_attack_1_the_mirror_omits_one_critical(member, capsys):
    """New enforcement. Before: no error, no advisory, stale_since empty."""
    m = member
    m.post(m.bot_sec, "Daily digest.")
    crit = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), created_at=T0 + 300)
    m.checkpoint()
    for name in m.events:
        m.events[name] = [e for e in m.events[name] if e["id"] != crit["id"]]  # served: the digest only
    code, _, err = run(capsys, "pull")
    assert code == 1 and "mirror incomplete" in err
    code, doc = run_json(capsys)
    assert doc["pull_error"] == "mirror incomplete" and doc["matches"] == []
    assert doc["unverified"] == "the last pull failed (mirror incomplete)" and doc["stale_since"] is not None
    _, out, _ = run(capsys, "check")
    assert cli.UNVERIFIED_LINE.format(reason="the last pull failed (mirror incomplete)") in out


def test_attack_2a_a_new_client_is_served_the_alert_without_its_retraction(member, capsys):
    """New enforcement. Before: plan listed the retracted upgrade under auto-apply."""
    m = member
    root = m.root_post(m.cur_sec)
    gone = m.reply(m.cur_sec, root, "retract")
    m.checkpoint()
    m.events["feed.json"].remove(gone)
    code, _, err = run(capsys, "pull")
    assert code == 1 and "mirror incomplete" in err
    code, _, err = run(capsys, "plan", "AITA-TEST-0001")
    assert code == 1 and "no current advisory" in err  # nothing was admitted


def test_attack_2b_a_client_with_an_earlier_fresh_checkpoint(member, capsys):
    """New enforcement, and the spec review's case: the earlier checkpoint is still fresh,
    so only the refused pull stands between the withdrawn upgrade and auto-apply."""
    m = member
    root = m.root_post(m.cur_sec)
    m.checkpoint()
    assert run(capsys, "pull")[0] == 0
    _, out, _ = run(capsys, "plan", "AITA-TEST-0001")
    assert "auto-apply (opted in):" in out and "unverified" not in out  # verified: the opt-in holds
    gone = m.reply(m.cur_sec, root, "retract", created_at=T0 + 300)
    m.checkpoint()
    m.events["feed.json"].remove(gone)
    assert run(capsys, "pull")[0] == 1
    code, out, _ = run(capsys, "plan", "AITA-TEST-0001")
    assert code == 0 and "auto-apply" not in out.replace("nothing is auto-applied", "")
    assert "prepare (ask first):" in out and "npm install -g @anthropic-ai/claude-code@99.0.0" in out
    assert cli.UNVERIFIED_LINE.format(reason="the last pull failed (mirror incomplete)") in out
    m.events["feed.json"].append(gone)  # the mirror serves it again
    assert run(capsys, "pull")[0] == 0
    code, _, err = run(capsys, "plan", "AITA-TEST-0001")
    assert code == 1 and "no current advisory" in err  # retracted


@pytest.mark.parametrize("who", ["a stale genuine checkpoint", "the checkpoint key at a higher number"])
def test_attack_2c_a_client_that_holds_the_retraction_keeps_it(member, capsys, who):
    """Kept behaviour through the new path: the parent reader kept a stored retraction
    when the mirror dropped it. A checkpoint that omits it must not undo that."""
    m = member
    root = m.root_post(m.cur_sec)
    early = m.checkpoint()
    gone = m.reply(m.cur_sec, root, "retract", created_at=T0 + 300)
    if who == "a stale genuine checkpoint":  # the member got the retraction as v0.1.4 did; then the first checkpoint
        st = State.load()
        st.accept(m.root, m.man, {root["id"]: root, gone["id"]: gone})
        st.save_pull()
        m.stored_checkpoint = early
    else:
        m.checkpoint()
        assert run(capsys, "pull")[0] == 0
        m.checkpoint(ids=[root["id"]])
    m.events["feed.json"].remove(gone)
    assert run(capsys, "pull")[0] == 0
    code, _, err = run(capsys, "plan", "AITA-TEST-0001")
    assert code == 1 and "no current advisory" in err


def _revoke_bot(m):
    """Publish manifest v2 without the bot key (and its certificate) on the second origin
    while the mirror keeps serving v1, its certificate and v1 checkpoints."""
    frozen = {"manifest.json": json.dumps(m.manifest).encode(), "checkpoint-key.json": json.dumps(m.cert).encode()}
    v1 = m.man
    m.publish_manifest(posters=[{"pubkey": m.cur, "role": "curator", "name": "cur"}])
    m.second = {"manifest.json": json.dumps(m.manifest).encode(), "checkpoint-key.json": json.dumps(m.cert).encode()}
    m.raw.update(frozen)
    return v1


def test_attack_3_the_mirror_serves_the_manifest_from_before_a_revocation(member, capsys, monkeypatch):
    """New enforcement. Before: a new client accepted the revoked key with no warning."""
    m = member
    m.root_post(m.bot_sec, advisory(posted_by="relay-bot"))
    v1 = _revoke_bot(m)
    m.checkpoint(man=v1)
    config.config_path().write_text(config.config_path().read_text() + f'second_origin = "{SECOND}"\n')
    code, _, err = run(capsys, "pull")
    assert code == 1 and "bad checkpoint" in err  # v2 won; the mirror's checkpoint is v1's
    code, doc = run_json(capsys)
    assert doc["matches"] == [] and doc["unverified"] is not None and State.load().manifest.version == 2


def test_attack_3_without_the_second_origin_the_old_certificate_runs_out(member, capsys, reader_clock):
    """New enforcement: the freeze is bounded by the certificate, and then nothing is auto-applied."""
    m = member
    m.root_post(m.cur_sec)
    m.publish_cert(days=30)
    v1 = _revoke_bot(m)
    m.checkpoint(man=v1)
    assert run(capsys, "pull")[0] == 0  # the member cannot reach the second origin
    reader_clock.at = T0 + 31 * DAY
    m.clock = reader_clock.at
    m.checkpoint(man=v1, now=reader_clock.at - 60)  # the thief keeps signing fresh checkpoints
    code, _, err = run(capsys, "pull")
    assert code == 1 and "no checkpoint key certificate" in err
    _, out, _ = run(capsys, "plan", "AITA-TEST-0001")
    assert "prepare (ask first):" in out and "auto-apply (opted in)" not in out


def test_attack_4_one_event_dated_ten_years_ahead(member, capsys, reader_clock):
    """Kept behaviour (the event is refused since ai-tools-alerts#gefy), and new: a frozen
    mirror reads stale once its checkpoint runs out, 30 and 80 days in."""
    m = member
    m.post(m.cur_sec, "Daily digest.", created_at=T0 + 500)
    m.post(m.bot_sec, "ten years on", created_at=T0 + 3650 * DAY)
    frozen = m.checkpoint()
    code, _, err = run(capsys, "pull")
    assert code == 0 and cli.AHEAD_LINE.format(n=1) in err
    assert run_json(capsys)[1]["stale_since"] is None
    for days in (2, 30, 80):
        reader_clock.at = T0 + days * DAY
        m.stored_checkpoint = frozen
        code, doc = run_json(capsys)
        assert doc["stale_since"] == "2099-01-01T00:08:20Z" and doc["unverified"] == "checkpoint out of date"


# ---------------------------------------------------------------- what a member sees

def test_fresh_install_whose_first_pull_fails_warns_through_the_installed_hook(member, capsys, tmp_path):
    """No manifest was ever accepted: stale_since still carries a time, which is all the
    session-start hook members installed looks for."""
    member.raw["manifest.json"] = None
    code, doc = run_json(capsys)
    assert doc["pull_error"] == "unreachable" and doc["unverified"] == "the last pull failed (unreachable)"
    assert doc["stale_since"] is not None
    raw = json.dumps(doc, indent=2)
    assert '"stale_since": "' in raw  # the hook's match (tests/test_templates.py drives the hook itself)
    assert "may be stale or unverified" in HOOK.read_text()


def test_a_curator_pull_does_not_restore_auto_apply(member, capsys):
    """Member pull refused, then the curator command (writer mode) pulls the same
    incomplete mirror successfully, then plan: still nothing auto-applied."""
    m = member
    root = m.root_post(m.cur_sec)
    m.checkpoint()
    assert run(capsys, "pull")[0] == 0
    gone = m.reply(m.cur_sec, root, "retract", created_at=T0 + 300)
    m.checkpoint()
    m.events["feed.json"].remove(gone)
    assert run(capsys, "pull")[0] == 1
    st = State.load()
    assert pull.fetch("https://mirror.invalid/", st, root_pubkey=m.root, checkpoint=False).error is None
    _, out, _ = run(capsys, "plan", "AITA-TEST-0001")
    assert "prepare (ask first):" in out and "auto-apply (opted in)" not in out
    assert cli.UNVERIFIED_LINE.format(reason="the last pull checked no checkpoint") in out


# ---------------------------------------------------------------- the released reader

def test_released_reader_reads_state_this_reader_wrote(home, tmp_path, monkeypatch):
    """A member who goes back to v0.1.4 keeps working: the new state file is ignored and
    events.json has no key that release refuses. Covered: a finished pull, a state with
    a certificate and no checkpoint, and a save interrupted after the checkpoint file."""
    monkeypatch.setattr(pull, "TRUST_ROOT_PUBKEY", FIXTURE_ROOT)
    url = FIXTURE_MIRROR.as_uri() + "/"
    old = released_reader(tmp_path, home=home)

    def old_check():
        got = old("check")
        assert got.returncode == 0 and "Traceback" not in got.stderr, got.stderr
        return got.stdout

    # 1. a certificate, no checkpoint: this reader refused the pull after saving the certificate
    files = {p.name: p.read_bytes() for p in FIXTURE_MIRROR.iterdir()}
    serve = lambda u: files[u.rsplit("/", 1)[1]]  # noqa: E731
    del files["checkpoint.json"]
    st = State.load()
    assert pull.fetch(url, st, fetch=serve, root_pubkey=FIXTURE_ROOT).error == "no checkpoint"
    assert State.load().cert_for(FIXTURE_ROOT) is not None
    assert "0 advisories" in old_check()
    # 2. interrupted after the checkpoint file
    files["checkpoint.json"] = (FIXTURE_MIRROR / "checkpoint.json").read_bytes()
    mend = break_write(monkeypatch, "events.json", 2)  # the final save's second file
    with pytest.raises(Boom):
        pull.fetch(url, State.load(), fetch=serve, root_pubkey=FIXTURE_ROOT)
    mend()
    assert State.load().checkpoint_for(FIXTURE_ROOT) is not None
    old_check()
    # 3. a finished pull
    assert pull.fetch(url, State.load(), fetch=serve, root_pubkey=FIXTURE_ROOT).error is None
    assert pull.unverified(State.load()) is None
    assert "2 advisories" in old_check()
    got = old("pull", "--mirror-url", url)  # and that release pulls into the same state
    assert got.returncode == 0 and "Traceback" not in got.stderr, got.stderr
    assert State.load().cert_for(FIXTURE_ROOT) is not None  # its pull left the new file alone
    assert pull.unverified(State.load()) == "the last pull checked no checkpoint"  # v0.1.4 wrote last_pull
