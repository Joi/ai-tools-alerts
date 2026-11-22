"""The reader enforces the signed checkpoint (ai-tools-alerts#6whv)."""

import json

import pytest

from aitools_alerts import checkpoint as cp
from aitools_alerts import config, manifest, nostr, pull
from aitools_alerts.state import State, StateError
from mirror_helpers import SECOND, T0, Mirror, advisory

DAY = 86400
URL = "https://mirror.example.invalid/alerts"


@pytest.fixture(autouse=True)
def _home(home):
    return home


def do_pull(m: Mirror, now=T0 + 1000, second=None, **kw):
    st = State.load()
    res = pull.fetch(URL, st, fetch=m.fetch, root_pubkey=m.root, now=now, second_origin=second, **kw)
    return res, State.load()


def titles(st=None, **kw):
    return sorted((t.adv.title, t.retracted) for t in pull.advisories(st or State.load(), **kw))


def trust_file() -> bytes:
    p = config.state_dir() / "checkpoint.json"
    return p.read_bytes() if p.exists() else b""


def events_file() -> bytes:
    return (config.state_dir() / "events.json").read_bytes()


def forgeries(ev: dict, content: dict) -> list[dict]:
    """The signed event with its signature alone corrupted; with other content
    and the id recomputed; with other content under the old id. Each still
    claims the right key."""
    flipped = ev["sig"][:-1] + ("0" if ev["sig"][-1] != "0" else "1")
    other = json.dumps({**json.loads(ev["content"]), **content})
    moved = {**ev, "content": other}
    moved["id"] = nostr.event_id(moved)
    return [dict(ev, sig=flipped), moved, {**ev, "content": other}]


# ---------------------------------------------------------------- the pull

def test_pull_accepts_a_checkpointed_mirror_and_records_it(mirror):
    root = mirror.root_post(mirror.cur_sec)
    res, st = do_pull(mirror)
    assert res.error is None and pull.unverified(st, T0 + 1000) is None
    assert st.cert_for(mirror.root).checkpoint_key == mirror.ck
    assert st.checkpoint_for(mirror.root).events == {root["id"]} == st.applied_for(mirror.root)
    last = st.last_pull
    assert last["checkpoint_ok"] is True and last["checkpoint_seq"] == 1 and last["checkpoint_events"] == 1
    assert last["second_origin"] is None and titles(st) == [(advisory().title, False)]


def test_an_unlisted_event_waits_for_the_checkpoint_that_lists_it(mirror):
    old = mirror.root_post(mirror.cur_sec)
    mirror.checkpoint()  # the signer ran; then a new alert reaches the mirror
    new = mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", title="Second", posted_by="relay-bot"),
                           created_at=T0 + 300)
    res, st = do_pull(mirror)
    assert res.error is None and set(st.events) == {old["id"], new["id"]}  # stored
    assert titles(st) == [(advisory().title, False)]  # not applied
    assert titles(st, checkpointed=False) == [(advisory().title, False), ("Second", False)]  # the writers' view
    mirror.checkpoint()
    res, st = do_pull(mirror)
    assert res.error is None and titles(st) == [(advisory().title, False), ("Second", False)]


def test_an_unlisted_reply_cannot_retract_or_lower(mirror):
    """With the bot key and the mirror but not the checkpoint key: nothing the signer
    did not see is applied."""
    root = mirror.root_post(mirror.cur_sec)
    mirror.checkpoint()
    mirror.reply(mirror.cur_sec, root, "retract", created_at=T0 + 300)
    _, st = do_pull(mirror)
    assert titles(st) == [(advisory().title, False)]


@pytest.mark.parametrize("case, error", [
    ("none anywhere", "no checkpoint key certificate"),
    ("by a stranger", "no checkpoint key certificate"),
    ("for another manifest", "no checkpoint key certificate"),
    ("expired", "no checkpoint key certificate"),
    ("dated ahead", "no checkpoint key certificate"),
    ("garbage", "no checkpoint key certificate"),
    ("no checkpoint", "no checkpoint"),
    ("checkpoint garbage", "bad checkpoint"),
    ("checkpoint by the bot key", "bad checkpoint"),
    ("checkpoint by the root key", "bad checkpoint"),
    ("checkpoint for another manifest", "bad checkpoint"),
    ("checkpoint dated ahead", "checkpoint dated ahead of this clock"),
])
def test_each_way_the_certificate_or_checkpoint_can_be_wrong(mirror, case, error):
    mirror.root_post(mirror.cur_sec)
    stranger, _ = nostr.keygen()
    if case == "none anywhere":
        mirror.raw["checkpoint-key.json"] = None
    elif case == "by a stranger":
        mirror.publish_cert(signer=stranger)
    elif case == "for another manifest":
        cert = mirror.cert
        mirror.publish_manifest(cert=False)
        mirror.cert = cert
    elif case == "expired":
        mirror.publish_cert(issued=T0 - 10 * DAY, days=1)
    elif case == "dated ahead":
        mirror.publish_cert(issued=T0 + 1000 + pull.MAX_AHEAD_S + 1)
    elif case == "garbage":
        mirror.raw["checkpoint-key.json"] = b"{"
    elif case == "no checkpoint":
        mirror.raw["checkpoint.json"] = None
    elif case == "checkpoint garbage":
        mirror.raw["checkpoint.json"] = b"[]"
    elif case == "checkpoint by the bot key":
        mirror.checkpoint(sec=mirror.bot_sec)
    elif case == "checkpoint by the root key":
        mirror.checkpoint(sec=mirror.root_sec)
    elif case == "checkpoint for another manifest":
        other = manifest.load(json.dumps(Mirror().manifest).encode())
        mirror.checkpoint(man=other)
    elif case == "checkpoint dated ahead":
        mirror.checkpoint(now=T0 + 1000 + pull.MAX_AHEAD_S + 1)
    res, st = do_pull(mirror)
    assert res.error == error and error in pull.PULL_ERRORS
    assert st.events == {} and titles(st) == [] and st.checkpoint_for(mirror.root) is None
    assert st.manifest is not None  # the verified manifest is accepted whatever follows
    assert pull.unverified(st, T0 + 1000) == f"the last pull failed ({error})"
    assert st.last_pull["checkpoint_ok"] is False and pull.stale_since(st, T0 + 1000) is not None


def test_checkpoint_at_the_clock_bound_is_accepted(mirror):
    mirror.root_post(mirror.cur_sec)
    mirror.checkpoint(now=T0 + 1000 + pull.MAX_AHEAD_S)
    res, _ = do_pull(mirror)
    assert res.error is None


def test_the_pull_checks_signatures_not_just_keys(mirror):
    """A certificate and a checkpoint that claim the right key but whose signature,
    id or content was altered are refused by the pull itself."""
    mirror.root_post(mirror.cur_sec)
    for forged in forgeries(mirror.cert, {"checkpoint_key": nostr.keygen()[1]}):
        mirror.raw["checkpoint-key.json"] = json.dumps(forged).encode()
        mirror.second["checkpoint-key.json"] = json.dumps(forged).encode()  # no valid one anywhere
        res, st = do_pull(mirror, second=SECOND)
        assert res.error == "no checkpoint key certificate" and st.cert_for(mirror.root) is None
    mirror.raw.pop("checkpoint-key.json")
    good = mirror.checkpoint()
    for forged in forgeries(good, {"events": []}):
        mirror.raw["checkpoint.json"] = json.dumps(forged).encode()
        res, st = do_pull(mirror)
        assert res.error == "bad checkpoint" and st.checkpoint_for(mirror.root) is None
    for forged in forgeries(mirror.manifest, {"version": 9}):  # a second-origin manifest gets the same check
        mirror.second["manifest.json"] = json.dumps(forged).encode()
        res, st = do_pull(mirror, second=SECOND)
        assert st.manifest.version == 1 and st.last_pull["second_origin"] != "ok"


def test_an_older_or_conflicting_checkpoint_is_refused(mirror):
    root = mirror.root_post(mirror.cur_sec)
    first = mirror.checkpoint()  # 1: the root
    do_pull(mirror)
    gone = mirror.reply(mirror.cur_sec, root, "retract", created_at=T0 + 300)
    mirror.checkpoint()  # 2: with the retraction
    _, st = do_pull(mirror)
    assert titles(st) == [(advisory().title, True)]
    mirror.stored_checkpoint = first  # the replay of 1, still inside its validity
    mirror.events["feed.json"].remove(gone)
    res, st = do_pull(mirror)
    assert res.error == "older checkpoint" and titles(st) == [(advisory().title, True)]
    assert st.checkpoint_for(mirror.root).seq == 2
    mirror.checkpoint(seq=2, ids=[root["id"]], now=T0 + 900)  # another statement under number 2
    res, st = do_pull(mirror)
    assert res.error == "conflicting checkpoint" and titles(st) == [(advisory().title, True)]
    mirror.events["feed.json"].append(gone)
    mirror.checkpoint(seq=3)
    res, st = do_pull(mirror)
    assert res.error is None and pull.unverified(st, T0 + 1000) is None


def test_a_new_manifest_applies_at_once_even_when_the_checkpoint_lags(mirror):
    """A revocation must not wait for the signer: the manifest is accepted, the revoked
    key's events go, and the reader is unverified until a checkpoint names the manifest."""
    mirror.root_post(mirror.cur_sec)
    bot = mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", title="Bot", posted_by="relay-bot"))
    old_cp = mirror.checkpoint()
    do_pull(mirror)
    mirror.publish_manifest(posters=[{"pubkey": mirror.cur, "role": "curator", "name": "cur"}])
    mirror.stored_checkpoint = old_cp  # the signer has not run since
    res, st = do_pull(mirror)
    assert res.error == "bad checkpoint" and st.manifest.version == 2
    assert bot["id"] not in st.events and titles(st) == [(advisory().title, False)]
    assert st.cert_for(mirror.root).manifest_version == 2  # the new certificate is kept
    assert pull.unverified(st, T0 + 1000) == "the last pull failed (bad checkpoint)"
    mirror.checkpoint()
    res, st = do_pull(mirror)
    assert res.error is None and pull.unverified(st, T0 + 1000) is None


# ---------------------------------------------------------------- second origin

def test_second_origin_higher_manifest_wins(mirror):
    """ai-tools-alerts#ek5q attack 3: the mirror keeps serving the manifest from before a revocation."""
    mirror.root_post(mirror.cur_sec)
    bot = mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", title="Bot", posted_by="relay-bot"))
    frozen = {"manifest.json": json.dumps(mirror.manifest).encode(), "checkpoint-key.json": json.dumps(mirror.cert).encode()}
    frozen_cp = mirror.checkpoint()
    mirror.publish_manifest(posters=[{"pubkey": mirror.cur, "role": "curator", "name": "cur"}])  # v2 revokes the bot
    mirror.second = {"manifest.json": json.dumps(mirror.manifest).encode(),
                     "checkpoint-key.json": json.dumps(mirror.cert).encode()}
    mirror.raw.update(frozen)  # the mirror serves v1, its certificate and a v1 checkpoint
    mirror.stored_checkpoint = frozen_cp
    res, st = do_pull(mirror)  # without the second origin the reader is none the wiser
    assert res.error is None and bot["id"] in st.events
    res, st = do_pull(mirror, second=SECOND)
    assert st.manifest.version == 2 and bot["id"] not in st.events
    assert st.last_pull["second_origin"] == "ok"
    assert res.error == "bad checkpoint"  # the mirror's checkpoint is for the old manifest
    assert titles(st) == [(advisory().title, False)] and pull.unverified(st, T0 + 1000) is not None
    res, st = do_pull(mirror)  # later, the second origin unreachable: the floor holds
    assert res.error == "bad manifest" and st.manifest.version == 2


@pytest.mark.parametrize("case", ["unreachable", "garbage", "by a stranger", "lower"])
def test_second_origin_that_is_useless_is_not_an_error(mirror, case):
    mirror.root_post(mirror.cur_sec)
    if case == "garbage":
        mirror.second["manifest.json"] = b"{"
    elif case == "by a stranger":
        other = Mirror()
        other.publish_manifest(version=9)
        mirror.second["manifest.json"] = json.dumps(other.manifest).encode()
    elif case == "lower":
        mirror.second["manifest.json"] = json.dumps(mirror.manifest).encode()
        mirror.publish_manifest()  # the mirror is ahead of the second origin
    res, st = do_pull(mirror, second=SECOND)
    assert res.error is None and pull.unverified(st, T0 + 1000) is None
    want = {"unreachable": "unreachable", "garbage": "bad manifest",
            "by a stranger": "manifest not signed by the trust root", "lower": "ok"}[case]
    assert st.last_pull["second_origin"] == want
    assert st.manifest.version == (2 if case == "lower" else 1)


def test_certificate_from_the_second_origin_is_used_when_the_mirror_has_none(mirror):
    mirror.root_post(mirror.cur_sec)
    mirror.second["checkpoint-key.json"] = json.dumps(mirror.cert).encode()
    mirror.raw["checkpoint-key.json"] = None
    res, st = do_pull(mirror, second=SECOND)
    assert res.error is None and st.cert_for(mirror.root) is not None


def test_a_key_rotation_is_recorded_even_when_the_mirror_answers_with_the_old_key(mirror):
    """The root names a new checkpoint key. The mirror keeps serving checkpoints by the
    retired key: the new certificate is saved at once, the reader is unverified, and a
    later pull that cannot reach the second origin still refuses the retired key."""
    mirror.root_post(mirror.cur_sec)
    old_cert = mirror.cert
    do_pull(mirror)
    new_sec, new_pub = nostr.keygen()
    newer = mirror.publish_cert(key=new_pub, issued=T0 + 500)
    mirror.second["checkpoint-key.json"] = json.dumps(newer).encode()
    mirror.cert = old_cert  # the mirror still serves the old certificate
    mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", title="By the thief", posted_by="relay-bot"),
                     created_at=T0 + 600)
    mirror.checkpoint()  # signed with the retired key
    res, st = do_pull(mirror, second=SECOND)
    assert res.error == "bad checkpoint" and st.cert_for(mirror.root).checkpoint_key == new_pub
    assert titles(st) == [(advisory().title, False)]
    res, st = do_pull(mirror)  # no second origin this time
    assert res.error == "bad checkpoint" and st.cert_for(mirror.root).checkpoint_key == new_pub
    assert titles(st) == [(advisory().title, False)] and pull.unverified(st, T0 + 1000) is not None
    st.last_pull["checkpoint_ok"] = True  # even were the pull record clean, the stored checkpoint is the old key's
    assert pull.unverified(st, T0 + 1000) == "checkpoint is not signed by the certified key"
    mirror.cert = newer
    mirror.checkpoint(sec=new_sec, seq=1)  # the new key starts its own count
    res, st = do_pull(mirror)
    assert res.error is None and pull.unverified(st, T0 + 1000) is None and len(titles(st)) == 2


def test_an_older_certificate_never_replaces_a_newer_one(mirror):
    mirror.root_post(mirror.cur_sec)
    first = mirror.cert
    mirror.publish_cert(issued=T0 + 500)
    do_pull(mirror)
    mirror.checkpoint(now=T0 + 600)  # the signer goes on signing; only the certificate served is the old one
    mirror.cert = first
    res, st = do_pull(mirror)
    assert res.error is None and st.cert_for(mirror.root).issued_at == T0 + 500  # the stored one stays


# ---------------------------------------------------------------- the applied set

def test_a_checkpoint_cannot_take_a_retraction_away(mirror):
    """A checkpoint signed with the checkpoint key, at a higher number, that lists only
    the root: the retraction the reader applied stays applied."""
    root = mirror.root_post(mirror.cur_sec)
    gone = mirror.reply(mirror.cur_sec, root, "retract")
    do_pull(mirror)
    mirror.checkpoint(ids=[root["id"]])
    mirror.events["feed.json"].remove(gone)
    res, st = do_pull(mirror)
    assert res.error is None and gone["id"] in st.applied_for(mirror.root)
    assert titles(st) == [(advisory().title, True)]


def test_first_checkpoint_keeps_what_the_older_reader_held(mirror):
    """Upgrade: v0.1.4 stored the upgrade and its retraction. The first checkpoint
    predates the retraction and lists only the upgrade."""
    root = mirror.root_post(mirror.cur_sec)
    gone = mirror.reply(mirror.cur_sec, root, "retract")
    st = State.load()
    st.accept(mirror.root, mirror.man, {root["id"]: root, gone["id"]: gone})
    st.save_pull()
    assert titles() == [(advisory().title, True)] and pull.unverified(State.load(), T0 + 1000) is not None
    mirror.checkpoint(ids=[root["id"]], now=T0 + 150)
    mirror.events["feed.json"].remove(gone)
    res, st = do_pull(mirror)
    assert res.error is None and titles(st) == [(advisory().title, True)]
    assert st.applied_for(mirror.root) == {root["id"], gone["id"]}


def test_legacy_state_is_shown_unverified_and_admits_nothing_new(mirror):
    root = mirror.root_post(mirror.cur_sec)
    st = State.load()
    st.accept(mirror.root, mirror.man, {root["id"]: root})
    st.save_pull()
    mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", title="New", posted_by="relay-bot"))
    mirror.raw["checkpoint.json"] = None  # the mirror serves no checkpoint yet
    res, st = do_pull(mirror)
    assert res.error == "no checkpoint" and set(st.events) == {root["id"]}
    assert titles(st) == [(advisory().title, False)] and st.applied_for(mirror.root) is None
    assert pull.unverified(st, T0 + 1000) == "the last pull failed (no checkpoint)"


def test_revoked_key_events_leave_and_old_threads_age_out_whatever_is_listed(mirror):
    old = mirror.root_post(mirror.cur_sec, created_at=T0 - 500 * DAY)
    gone = mirror.reply(mirror.cur_sec, old, "retract", created_at=T0 - 450 * DAY)
    res, st = do_pull(mirror)  # listed, and older than the reader keeps
    assert res.error is None and st.events == {} and titles(st) == []
    assert res.dropped["aged-out"] == 2
    assert pull.unverified(st, T0 + 1000) == "stored events do not match the checkpoint"
    # an unlisted recent reply does not revive the old root without its retraction
    mirror.reply(mirror.bot_sec, old, "note", created_at=T0 + 100)
    mirror.checkpoint(ids=[old["id"]])
    mirror.events["feed.json"].remove(gone)
    res, st = do_pull(mirror)
    assert res.error is None and titles(st) == [] and old["id"] not in st.events


def test_a_flood_of_unlisted_events_cannot_crowd_listed_ones_out(mirror, monkeypatch):
    listed = [mirror.root_post(mirror.cur_sec, advisory(id=f"AITA-TEST-00{i:02d}", title=f"Kept {i}"),
                               created_at=T0 + i) for i in range(5)]
    mirror.checkpoint()
    for i in range(30):
        mirror.post(mirror.bot_sec, f"flood {i}", created_at=T0 + 200 + i)
    monkeypatch.setattr(pull, "MAX_STORED_EVENTS", 10)
    res, st = do_pull(mirror)
    assert res.error is None and len(st.events) == 10
    assert {e["id"] for e in listed} <= set(st.events) and len(titles(st)) == 5
    kept_flood = sorted(e["content"] for e in st.events.values() if e["content"].startswith("flood"))
    assert kept_flood == [f"flood {i}" for i in range(25, 30)]  # the newest of the rest
    monkeypatch.setattr(pull, "MAX_STORED_EVENTS", 3)  # even the listed ones do not fit
    before = events_file(), trust_file()
    mirror.root_post(mirror.cur_sec, advisory(id="AITA-TEST-0099", title="One more"), created_at=T0 + 400)
    mirror.checkpoint()
    res, st = do_pull(mirror)
    assert res.error == "state limit reached: new events not stored"
    assert st.checkpoint_for(mirror.root).seq == 1 and trust_file() == before[1]
    assert pull.unverified(st, T0 + 1000) is not None


# ---------------------------------------------------------------- incomplete mirror

def test_a_mirror_missing_a_listed_event_is_refused(mirror):
    """ai-tools-alerts#ek5q attack 1, on a reader that holds an earlier fresh checkpoint."""
    mirror.post(mirror.bot_sec, "Daily digest.")
    do_pull(mirror)
    crit = mirror.root_post(mirror.bot_sec, advisory(posted_by="relay-bot"), created_at=T0 + 300)
    mirror.checkpoint()
    for name in ("feed.json", "critical.json"):
        mirror.events[name] = [e for e in mirror.events[name] if e["id"] != crit["id"]]
    before = events_file(), trust_file()
    res, st = do_pull(mirror)
    assert res.error == "mirror incomplete" and (events_file(), trust_file()) == before
    assert st.checkpoint_for(mirror.root).seq == 1 and titles(st) == []
    assert pull.unverified(st, T0 + 1000) == "the last pull failed (mirror incomplete)"  # though seq 1 is still fresh
    assert pull.stale_since(st, T0 + 1000) is not None


def test_a_listed_event_the_reader_refuses_counts_as_missing(mirror):
    mirror.root_post(mirror.cur_sec)
    ahead = mirror.post(mirror.bot_sec, "dated ahead", created_at=T0 + 1000 + pull.MAX_AHEAD_S + 5)
    mirror.checkpoint(ids=mirror.honest_ids(T0 + 10**6), now=T0 + 900)  # a signer that listed it all the same
    res, st = do_pull(mirror)
    assert res.error == "mirror incomplete" and res.dropped == {"future-dated": 1}
    assert ahead["id"] not in st.events


# ---------------------------------------------------------------- interruptions

class Boom(OSError):
    pass


def _break(monkeypatch, what: str):
    """Make one write of the save fail, as a crash at that point would leave things."""
    from aitools_alerts import state as state_mod
    real = state_mod.write_json
    seen = {"last_pull": 0}

    def write(path, obj):
        if path.name == "last_pull.json":
            seen["last_pull"] += 1
        if (what == path.name and path.name != "last_pull.json") or \
                (what == "last_pull.json" and path.name == what and seen["last_pull"] == 2):
            raise Boom(what)
        return real(path, obj)
    monkeypatch.setattr(state_mod, "write_json", write)
    return lambda: monkeypatch.setattr(state_mod, "write_json", real)


@pytest.mark.parametrize("what, reason", [
    ("checkpoint.json", "the last pull was interrupted"),
    ("events.json", "the last pull was interrupted"),
    ("last_pull.json", "the last pull was interrupted"),
])
def test_a_save_interrupted_anywhere_reads_unverified(mirror, monkeypatch, what, reason):
    root = mirror.root_post(mirror.cur_sec)
    do_pull(mirror)
    assert pull.unverified(State.load(), T0 + 1000) is None
    new = mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", title="New", posted_by="relay-bot"),
                           created_at=T0 + 300)
    mirror.checkpoint()
    mirror.post(mirror.bot_sec, "unlisted", created_at=T0 + 400)
    mend = _break(monkeypatch, what)
    with pytest.raises(Boom):
        do_pull(mirror)
    mend()
    st = State.load()
    assert pull.unverified(st, T0 + 1000) == reason
    shown = {t.root_id for t in pull.advisories(st)}
    assert root["id"] in shown and shown <= {root["id"], new["id"]}  # never the unlisted one
    if what == "events.json":  # the new checkpoint is on disk with the old events
        st.last_pull["checkpoint_ok"] = True
        assert pull.unverified(st, T0 + 1000) == "stored events do not match the checkpoint"
    res, st = do_pull(mirror)
    assert res.error is None and pull.unverified(st, T0 + 1000) is None and len(pull.advisories(st)) == 2


def test_a_refused_pull_whose_record_cannot_be_written_is_still_unverified(mirror, monkeypatch):
    """From a verified state: the mirror withholds a listed retraction, the pull is
    refused, and writing that outcome fails. The step 0 record already says so."""
    root = mirror.root_post(mirror.cur_sec)
    do_pull(mirror)
    gone = mirror.reply(mirror.cur_sec, root, "retract", created_at=T0 + 300)
    mirror.checkpoint()
    mirror.events["feed.json"].remove(gone)
    mend = _break(monkeypatch, "last_pull.json")
    with pytest.raises(Boom):
        do_pull(mirror)
    mend()
    st = State.load()
    assert st.checkpoint_for(mirror.root).seq == 1  # the earlier checkpoint, still fresh
    assert pull.unverified(st, T0 + 1000) == "the last pull was interrupted"


def test_first_checkpoint_interrupted_does_not_fall_back_to_showing_staged_events(mirror, monkeypatch):
    root = mirror.root_post(mirror.cur_sec)
    st = State.load()
    st.accept(mirror.root, mirror.man, {root["id"]: root})
    st.save_pull()
    mirror.checkpoint()
    staged = mirror.root_post(mirror.bot_sec, advisory(id="AITA-TEST-0002", title="Staged", posted_by="relay-bot"),
                              created_at=T0 + 300)
    mend = _break(monkeypatch, "last_pull.json")
    with pytest.raises(Boom):
        do_pull(mirror)
    mend()
    st = State.load()
    assert staged["id"] in st.events and titles(st) == [(advisory().title, False)]


def test_interrupted_pruning_never_forgets_a_stored_retraction(mirror, monkeypatch):
    """The plan review's case: a thread with its retraction is on its way out of the
    store when the save is interrupted; afterwards a checkpoint by the checkpoint key
    lists only the root. The thread is retracted or absent, never shown active."""
    now = T0 + 1000
    root = mirror.root_post(mirror.cur_sec, created_at=now - pull.RETENTION_S + 3600)
    gone = mirror.reply(mirror.cur_sec, root, "retract", created_at=now - pull.RETENTION_S + 3700)
    mirror.checkpoint(now=T0 + 900)
    do_pull(mirror, now=now)
    assert titles() == [(advisory().title, True)]
    later = now + 2 * 3600  # both events are now older than the reader keeps
    mirror.checkpoint(ids=[], now=later - 60)
    mend = _break(monkeypatch, "events.json")
    with pytest.raises(Boom):
        do_pull(mirror, now=later)
    mend()
    st = State.load()
    assert {root["id"], gone["id"]} <= set(st.events) and titles(st) == [(advisory().title, True)]
    mirror.reply(mirror.bot_sec, root, "note", created_at=later - 30)  # unlisted, recent
    mirror.checkpoint(ids=[root["id"]], now=later - 20)
    mirror.events["feed.json"].remove(gone)
    res, st = do_pull(mirror, now=later)
    assert res.error is None and all(r for _, r in titles(st))  # retracted, or gone


# ---------------------------------------------------------------- unverified, stale

def test_unverified_reasons_in_order(mirror):
    mirror.root_post(mirror.cur_sec)
    assert pull.unverified(State.load(), T0) == "no pull yet"
    _, st = do_pull(mirror)
    cp_at = st.checkpoint_for(mirror.root).created_at
    assert pull.unverified(st, T0 + 1000) is None and pull.stale_since(st, T0 + 1000) is None
    assert pull.unverified(st, cp_at + DAY) is None
    assert pull.unverified(st, cp_at + DAY + 1) == "checkpoint out of date"
    assert pull.stale_since(st, cp_at + DAY + 1) == cp_at
    # the clock set back behind the stored checkpoint, but not behind the certificate
    back = cp_at - pull.MAX_AHEAD_S - 1
    assert st.cert_for(mirror.root).issued_at <= back + pull.MAX_AHEAD_S
    assert pull.unverified(st, back) == "checkpoint dated ahead of this clock"
    assert pull.unverified(st, T0 - DAY) == "checkpoint key certificate dated ahead of this clock"
    assert pull.unverified(st, T0 + 200 * DAY) == "checkpoint key certificate expired"
    del st.events[next(iter(st.events))]
    assert pull.unverified(st, T0 + 1000) == "stored events do not match the checkpoint"
    st = State.load()
    st.last_pull = {**st.last_pull, "checkpoint_ok": False, "error": None}
    assert pull.unverified(st, T0 + 1000) == "the last pull checked no checkpoint"
    st.last_pull = {k: v for k, v in st.last_pull.items() if k != "checkpoint_ok"}  # as v0.1.4 wrote it
    assert pull.unverified(st, T0 + 1000) == "the last pull checked no checkpoint"


def test_network_failure_reads_unverified_until_a_pull_succeeds(mirror):
    mirror.root_post(mirror.cur_sec)
    do_pull(mirror)

    def down(url):
        raise TimeoutError
    st = State.load()
    res = pull.fetch(URL, st, fetch=down, root_pubkey=mirror.root, now=T0 + 1000)
    assert res.error == "timeout" and pull.unverified(State.load(), T0 + 1000) == "the last pull failed (timeout)"
    assert titles() == [(advisory().title, False)]  # still shown
    _, st = do_pull(mirror)
    assert pull.unverified(st, T0 + 1000) is None


def test_first_pull_failing_before_any_manifest_still_dates_the_warning(mirror):
    mirror.raw["manifest.json"] = None
    res, st = do_pull(mirror)
    assert res.error == "unreachable" and st.manifest is None
    assert pull.unverified(st, T0 + 1000) == "the last pull failed (unreachable)"
    assert pull.stale_since(st, T0 + 1000) == T0 + 1000  # the attempt's own time


def test_bundled_newer_manifest_makes_the_stored_certificate_unusable(mirror, monkeypatch):
    mirror.root_post(mirror.cur_sec)
    _, st = do_pull(mirror)
    newer = Mirror()
    monkeypatch.setattr(pull, "effective_manifest", lambda s: newer.man)
    assert pull.unverified(st, T0 + 1000) == "checkpoint key certificate is for another manifest"


# ---------------------------------------------------------------- the writers' pull

def test_writers_pull_stores_everything_and_never_verifies(mirror):
    root = mirror.root_post(mirror.cur_sec)
    mirror.raw["checkpoint-key.json"] = None
    mirror.raw["checkpoint.json"] = None
    res, st = do_pull(mirror, checkpoint=False)
    assert res.error is None and set(st.events) == {root["id"]} and st.trust == {} and trust_file() == b""
    assert st.last_pull["ok"] is True and st.last_pull["checkpoint_ok"] is False
    assert pull.unverified(st, T0 + 1000) == "the last pull checked no checkpoint"


def test_a_writers_pull_does_not_clear_a_refused_member_pull(mirror):
    """Member pull refused (a listed retraction is withheld), then the curator command
    pulls the same mirror in writer mode and succeeds: the member side stays unverified."""
    root = mirror.root_post(mirror.cur_sec)
    do_pull(mirror)
    gone = mirror.reply(mirror.cur_sec, root, "retract", created_at=T0 + 300)
    mirror.checkpoint()
    mirror.events["feed.json"].remove(gone)
    res, _ = do_pull(mirror)
    assert res.error == "mirror incomplete"
    before = trust_file()
    res, st = do_pull(mirror, checkpoint=False)
    assert res.error is None and st.last_pull["ok"] is True and trust_file() == before
    assert pull.unverified(st, T0 + 1000) == "the last pull checked no checkpoint"
    assert titles(st) == [(advisory().title, False)]  # shown, and never auto-applied (tests/test_attacks.py)


# ---------------------------------------------------------------- the state file

def test_checkpoint_state_round_trip_and_isolation_between_roots(mirror):
    mirror.root_post(mirror.cur_sec)
    do_pull(mirror)
    other = Mirror()
    other.root_post(other.cur_sec, advisory(id="AITA-TEST-0002", title="Other root"))
    st = State.load()
    pull.fetch(URL, st, fetch=other.fetch, root_pubkey=other.root, now=T0 + 1000)
    st = State.load()
    assert set(st.trust) == {mirror.root, other.root}
    assert st.cert_for(mirror.root).checkpoint_key == mirror.ck and st.cert_for(other.root).checkpoint_key == other.ck
    assert st.applied_for(mirror.root).isdisjoint(st.applied_for(other.root))
    assert st.cert_for("0" * 64) is None and st.checkpoint_for("0" * 64) is None and st.applied_for("0" * 64) is None
    rec = json.loads(trust_file())
    assert set(rec[mirror.root]) == {"cert", "checkpoint", "applied"}
    assert (config.state_dir() / "checkpoint.json").stat().st_mode & 0o777 == 0o600


def test_certificate_only_state_keeps_the_legacy_view(mirror):
    root = mirror.root_post(mirror.cur_sec)
    st = State.load()
    st.accept(mirror.root, mirror.man, {root["id"]: root})
    st.save_pull()
    mirror.raw["checkpoint.json"] = None
    do_pull(mirror)
    st = State.load()
    assert st.cert_for(mirror.root) is not None and st.checkpoint_for(mirror.root) is None
    assert st.applied_for(mirror.root) is None and json.loads(trust_file())[mirror.root]["applied"] == []
    assert titles(st) == [(advisory().title, False)]


@pytest.mark.parametrize("damage", [
    "not json", "[]", '{"zz": {}}', "missing key", "applied not a list", "applied not ids",
    "certificate unloadable", "certificate by another root", "checkpoint unloadable", "checkpoint signature"])
def test_malformed_checkpoint_state_is_refused_not_reset(mirror, damage):
    mirror.root_post(mirror.cur_sec)
    do_pull(mirror)
    path = config.state_dir() / "checkpoint.json"
    rec = json.loads(path.read_text())
    r = rec[mirror.root]
    if damage in ("not json", "[]", '{"zz": {}}'):
        path.write_text(damage)
    else:
        if damage == "missing key":
            del r["applied"]
        elif damage == "applied not a list":
            r["applied"] = "x"
        elif damage == "applied not ids":
            r["applied"] = ["nothex"]
        elif damage == "certificate unloadable":
            r["cert"]["kind"] = 1
        elif damage == "certificate by another root":
            other = Mirror()
            r["cert"] = other.cert
        elif damage == "checkpoint unloadable":
            r["checkpoint"]["tags"] = []
        elif damage == "checkpoint signature":
            r["checkpoint"]["sig"] = "0" * 128
        path.write_text(json.dumps(rec))
    with pytest.raises(StateError):
        State.load()
    st = State(dir=config.state_dir())
    with pytest.raises(StateError):  # a pull re-reads state under the lock: it stops too
        pull.fetch(URL, st, fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 1000)


def test_a_stale_state_object_cannot_overwrite_a_newer_certificate(mirror):
    mirror.root_post(mirror.cur_sec)
    do_pull(mirror)
    stale = State.load()  # loaded before another process pulls
    mirror.publish_cert(issued=T0 + 500)
    do_pull(mirror)
    assert State.load().cert_for(mirror.root).issued_at == T0 + 500
    first = cp.load_cert(json.dumps(stale.cert_for(mirror.root).event).encode())
    mirror.checkpoint(now=T0 + 600)
    mirror.cert = first.event  # and the mirror now serves the old one
    res = pull.fetch(URL, stale, fetch=mirror.fetch, root_pubkey=mirror.root, now=T0 + 1000)
    assert res.error is None and State.load().cert_for(mirror.root).issued_at == T0 + 500
