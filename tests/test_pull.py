import json
import os
import stat

import pytest

from aitools_alerts import config, manifest, nostr, pull
from aitools_alerts.state import State, StateError
from mirror_helpers import FIXTURE_MIRROR, FIXTURE_ROOT, T0, Mirror, advisory


@pytest.fixture(autouse=True)
def _home(home):
    return home


def do_pull(m: Mirror, st: State | None = None):
    st = st if st is not None else State.load()
    return pull.fetch("https://mirror.example.invalid/alerts", st, fetch=m.fetch,
                      root_pubkey=m.root, now=T0 + 1000), st


def threads(st=None):
    return pull.advisories(st if st is not None else State.load())


# ------------------------------------------------------------ plan tests

def test_pull_verifies_and_stores_fixture_events():
    st = State.load()
    res = pull.fetch(FIXTURE_MIRROR.as_uri() + "/", st, root_pubkey=FIXTURE_ROOT)
    assert res.error is None, res.error
    assert len(res.new_events) == 2 and not res.dropped
    st = State.load()
    assert len(st.events) == 2 and st.manifest_root == FIXTURE_ROOT
    levels = sorted(t.adv.level for t in pull.advisories(st))
    assert levels == ["critical", "high"]
    assert st.last_pull["ok"] is True
    mode = stat.S_IMODE(os.stat(config.state_dir() / "events.json").st_mode)
    assert mode == 0o600


def test_pull_rejects_manifest_not_signed_by_root(mirror):
    mirror.root_post(mirror.cur_sec)
    stranger_sec, _ = nostr.keygen()
    mirror.publish_manifest(signer=stranger_sec)
    res, st = do_pull(mirror)
    assert res.error == "manifest not signed by the trust root"
    assert State.load().events == {} and State.load().manifest is None


def test_pull_drops_event_with_bad_signature(mirror):
    ev = mirror.root_post(mirror.cur_sec, files=("feed.json",))
    bad = dict(ev, content=ev["content"].replace("Body line.", "Body line!"))
    mirror.events["feed.json"] = [bad]
    res, _ = do_pull(mirror)
    assert res.error is None
    assert res.dropped["bad-signature"] == 1
    assert State.load().events == {}


def test_revoked_poster_events_dropped(mirror):
    ev = mirror.root_post(mirror.bot_sec)
    res, _ = do_pull(mirror)
    assert res.error is None and ev["id"] in State.load().events
    # v2 drops the relay-bot key; the mirror still serves its old event
    mirror.publish_manifest(posters=[{"pubkey": mirror.cur, "role": "curator", "name": "cur"}])
    res, _ = do_pull(mirror)
    assert res.error is None
    assert res.dropped["revoked"] == 1
    st = State.load()
    assert ev["id"] not in st.events and threads(st) == []
    # and it is not trusted from cache even when the mirror no longer serves it
    mirror.events = {"feed.json": [], "critical.json": []}
    res, _ = do_pull(mirror)
    assert State.load().events == {}


def test_pull_truncated_json_keeps_previous_state(mirror):
    ev = mirror.root_post(mirror.cur_sec)
    res, _ = do_pull(mirror)
    assert res.error is None
    before = {n: (config.state_dir() / n).read_bytes() for n in ("events.json", "manifest.json")}
    full = mirror.body("feed.json")
    mirror.raw["feed.json"] = full[: len(full) // 2]
    res, _ = do_pull(mirror)
    assert res.error.startswith("mirror unreadable: feed.json")
    after = {n: (config.state_dir() / n).read_bytes() for n in ("events.json", "manifest.json")}
    assert after == before
    st = State.load()
    assert list(st.events) == [ev["id"]] and len(threads(st)) == 1
    assert st.last_pull["ok"] is False and st.last_pull["last_ok_at"] == T0 + 1000


def test_posted_by_role_comes_from_manifest_not_block(mirror):
    mirror.root_post(mirror.bot_sec, advisory(posted_by="curator"))
    do_pull(mirror)
    [t] = threads()
    assert t.adv.posted_by == "relay-bot"


def test_curator_retract_reply_hides_root(mirror):
    root = mirror.root_post(mirror.bot_sec)
    mirror.reply(mirror.cur_sec, root, "retract\nfalse alarm")
    do_pull(mirror)
    [t] = threads()
    assert t.retracted and pull.active([t]) == []


def test_relay_bot_reply_cannot_retract(mirror):
    root = mirror.root_post(mirror.bot_sec)
    mirror.reply(mirror.bot_sec, root, "retract")
    do_pull(mirror)
    [t] = threads()
    assert not t.retracted and pull.active([t]) == [t]


# ------------------------------------------------------- manifest freshness

def test_replayed_older_manifest_refused_after_newer_accepted(mirror):
    mirror.root_post(mirror.cur_sec)
    old = mirror.manifest
    mirror.publish_manifest()
    assert do_pull(mirror)[0].error is None
    mirror.manifest = old
    res, _ = do_pull(mirror)
    assert res.error.startswith("manifest refused")
    assert State.load().manifest.version == 2


def test_manifest_with_older_issued_at_refused(mirror):
    assert do_pull(mirror)[0].error is None
    mirror.publish_manifest(issued=T0 - 10)
    res, _ = do_pull(mirror)
    assert res.error.startswith("manifest refused: issued_at")


def test_bundled_manifest_is_the_floor_for_the_pinned_root():
    b = pull.bundled_manifest()
    assert b is not None and b.version >= 1
    assert pull._floor(State.load(), b.event["pubkey"]) == b
    assert pull._floor(State.load(), "00" * 32) is None


def test_stored_manifest_from_another_root_is_not_a_floor(mirror):
    assert do_pull(mirror)[0].error is None
    other = Mirror()
    other.publish_manifest(version=1)
    res, _ = do_pull(other)
    assert res.error is None and State.load().manifest_root == other.root


def test_unknown_poster_counted(mirror):
    sec, _ = nostr.keygen()
    mirror.root_post(sec)
    res, _ = do_pull(mirror)
    assert res.dropped["unknown-poster"] == 1 and State.load().events == {}


def test_default_fetch_refuses_http():
    with pytest.raises(OSError, match="only https and file"):
        pull.default_fetch("http://example.invalid/feed.json")


def test_missing_mirror_file_is_unreadable(mirror):
    def fetch(url):
        if url.endswith("critical.json"):
            raise OSError("404")
        return mirror.fetch(url)
    st = State.load()
    res = pull.fetch("https://x.invalid/", st, fetch=fetch, root_pubkey=mirror.root)
    assert res.error == "mirror unreadable: critical.json: 404"


# ------------------------------------------------------------------ replies

def test_curator_level_reply_lowers_and_relay_bot_cannot(mirror):
    root = mirror.root_post(mirror.bot_sec)
    mirror.reply(mirror.bot_sec, root, "level: notice", created_at=T0 + 150)
    do_pull(mirror)
    assert threads()[0].adv.level == "critical"
    mirror.reply(mirror.cur_sec, root, "level: high", created_at=T0 + 160)
    mirror.reply(mirror.cur_sec, root, "level: critical", created_at=T0 + 170)  # never raises
    do_pull(mirror)
    assert threads()[0].adv.level == "high"


def test_patch_changes_only_given_fields_and_null_clears(mirror):
    root = mirror.root_post(mirror.cur_sec, advisory(expires_at=T0 + 10**6, advisory_severity="CVSS 9"))
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(
        products=[{"name": "Claude Code", "ecosystem": "claude-code", "affected": "<99.1.0", "fixed": "99.1.0"}],
        expires_at=None))
    do_pull(mirror)
    [t] = threads()
    assert t.adv.products[0].fixed == "99.1.0" and t.adv.expires_at is None
    assert t.adv.advisory_severity == "CVSS 9" and t.adv.title == advisory().title
    assert t.adv.posted_by == "curator"


def test_relay_bot_patch_makes_advisory_relay_bot(mirror):
    root = mirror.root_post(mirror.cur_sec)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(title="New title", posted_by="curator"))
    do_pull(mirror)
    [t] = threads()
    assert t.adv.title == "New title" and t.adv.posted_by == "relay-bot"


def test_relay_bot_patch_cannot_lower_level(mirror):
    root = mirror.root_post(mirror.cur_sec)
    mirror.reply(mirror.bot_sec, root, mirror.patch_text(level="notice", title="T2"))
    do_pull(mirror)
    [t] = threads()
    assert t.adv.level == "critical" and t.adv.title == "T2"


@pytest.mark.parametrize("fields", [
    {"title": None},                       # null on a required field
    {"id": "AITA-OTHER"},                  # another advisory's id
    {"verb": "upgrade"},                   # unknown key
    {"actions": [{"verb": "run_shell", "target": "x", "value": None}]},
])
def test_invalid_patch_is_ignored(mirror, fields):
    root = mirror.root_post(mirror.cur_sec)
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(**fields))
    do_pull(mirror)
    [t] = threads()
    assert t.adv == advisory()


def test_reply_after_retract_changes_nothing(mirror):
    root = mirror.root_post(mirror.cur_sec)
    mirror.reply(mirror.cur_sec, root, "retract", created_at=T0 + 150)
    mirror.reply(mirror.cur_sec, root, mirror.patch_text(title="Back"), created_at=T0 + 160)
    do_pull(mirror)
    assert threads()[0].retracted and threads()[0].adv.title == advisory().title


def test_expired_advisory_not_active(mirror):
    mirror.root_post(mirror.cur_sec, advisory(expires_at=T0 + 1))
    do_pull(mirror)
    assert pull.active(threads(), now=T0 + 2) == []


# -------------------------------------------------------------- state, config

def test_corrupt_state_file_raises(home):
    d = config.state_dir()
    d.mkdir(parents=True)
    (d / "seen.json").write_text("[1, 2")
    with pytest.raises(StateError, match="seen.json"):
        State.load()


def test_state_manifest_record_must_verify(mirror):
    do_pull(mirror)
    p = config.state_dir() / "manifest.json"
    rec = json.loads(p.read_text())
    rec["root"] = nostr.keygen()[1]
    p.write_text(json.dumps(rec))
    with pytest.raises(StateError, match="not signed"):
        State.load()


def test_config_defaults_and_filters(home):
    s = config.load()
    assert s.mirror_url == config.DEFAULT_MIRROR_URL and s.notify == ("desktop",)
    assert s.auto_apply == frozenset()
    config.write_default()
    assert stat.S_IMODE(os.stat(config.config_path()).st_mode) == 0o600
    assert config.load().notify == ("desktop",)
    config.config_path().write_text(
        'auto_apply = ["upgrade", "run_shell"]\nnotify = ["desktop", "pager"]\ntelegram_chat_id = 42\n')
    s = config.load()
    assert s.auto_apply == frozenset({"upgrade"}) and s.notify == ("desktop",)
    assert s.telegram_chat_id == "42" and s.check_config().auto_apply == frozenset({"upgrade"})


@pytest.mark.parametrize("text", [
    'auto_apply = "upgrade"', 'mirror_url = "http://x.invalid/"', 'imessage_to = "-oProxy"',
    'webhook_url = "http://x.invalid"', "notify = [", ])
def test_config_rejects(home, text):
    p = config.config_path()
    p.parent.mkdir(parents=True)
    p.write_text(text + "\n")
    with pytest.raises(config.ConfigError):
        config.load()


def test_write_default_refuses_existing(home):
    config.write_default()
    with pytest.raises(config.ConfigError, match="exists"):
        config.write_default()
    config.write_default(force=True)


def test_fixture_mirror_rejected_under_pinned_root():
    res = pull.fetch(FIXTURE_MIRROR.as_uri() + "/", State.load())
    assert res.error is not None and State.load().events == {}
    assert isinstance(manifest.load(FIXTURE_MIRROR / "manifest.json"), manifest.Manifest)
