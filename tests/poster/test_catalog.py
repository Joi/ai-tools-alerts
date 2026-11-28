"""The catalog lane (ai-tools-alerts#q03f): every in-scope advisory's block as a root in
the catalog channel, sent after the ledger lock and the checkpoint, never in either."""

import json
from dataclasses import replace

import pytest

import test_main
from aitools_alerts import schema
from aitools_alerts.poster import catalog, inputs, main, signer, transport
from aitools_alerts.poster.ledger import Ledger
from advisories import ghsa_json
from test_signer import PutRelay, signing  # noqa: F401 - the checkpoint fixture
from test_main import CHANNELS, MAC, SYNTHETIC, T0, FakeRelay, at, chans, finding

CATALOG = "0c5d7a9e-3b1f-4c2a-9d8e-6f4a2b1c0e9d"


@pytest.fixture(autouse=True)
def catalog_name(monkeypatch):
    monkeypatch.setitem(test_main.NAME, CATALOG, "catalog")


env = test_main.env  # the poster test environment, shared


def run(env, **kw):
    kw.setdefault("catalog_channel", CATALOG)
    return env.run(**kw)


def blocks(relay):
    return [schema.parse_post(c[2]) for c in relay.calls if c[0] == "catalog"]


def test_off_without_the_spec_file(env, monkeypatch, tmp_path):
    monkeypatch.setattr(inputs, "CATALOG_SPEC", str(tmp_path / "catalog-channel.json"))  # absent
    env.collector([finding()])
    code, summary, relay = env.run(catalog_channel=None)
    assert code == 0 and "catalog=" not in summary and chans(relay) == [("feed", None)]
    assert not env.config.catalog_known.exists() and not env.config.catalog_state.exists()


def test_a_bad_spec_file_turns_the_lane_off_and_alerts_go_on(env, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(inputs, "CATALOG_SPEC", str(tmp_path / "catalog-channel.json"))
    (tmp_path / "catalog-channel.json").write_text(json.dumps({"catalog": CHANNELS["feed"]}))
    env.collector([finding()])
    code, summary, relay = env.run(catalog_channel=None)
    assert code == 0 and summary.endswith(" catalog=off-bad-spec") and chans(relay) == [("feed", None)]
    assert "names an alert channel" in capsys.readouterr().err


@pytest.mark.parametrize("doc, ok", [
    (None, None), ({"catalog": CATALOG}, CATALOG), ({"catalog": CATALOG.upper()}, "bad"),
    ({"catalog": CATALOG, "x": 1}, "bad"), ([], "bad"), ({"catalog": CHANNELS["critical"]}, "bad")])
def test_load_catalog_channel(tmp_path, doc, ok):
    p = tmp_path / "catalog-channel.json"
    if doc is not None:
        p.write_text(json.dumps(doc))
    if ok == "bad":
        with pytest.raises(inputs.ConfigError):
            inputs.load_catalog_channel(CHANNELS, p)
    else:
        assert inputs.load_catalog_channel(CHANNELS, p) == ok


def test_a_high_posts_to_feed_then_its_block_to_the_catalog_once(env):
    env.collector([finding()])
    code, summary, relay = run(env)
    assert code == 0 and summary.endswith(" catalog=1/0"), summary
    assert chans(relay) == [("feed", None), ("catalog", None)]
    (b,) = blocks(relay)
    (e,), _ = env.ledger()
    assert b.id == e["advisory"]["id"] and b.level == "high" and b.products[0].name == "Claude Code"
    assert relay.calls[1][2].startswith("HIGH: Claude Code")
    code, summary, relay = run(env, now=T0 + 3600)  # nothing new: nothing to the catalog
    assert code == 0 and relay.calls == [] and summary.endswith(" catalog=0/0")


def test_a_fix_learned_posts_a_new_catalog_root(env):
    env.collector([finding(fixed=None, severity="high")])
    env.collector([finding()])
    run(env)
    env.collector([finding(fixed="2.1.1")])
    code, _, relay = run(env, now=T0 + 3600)
    assert code == 0 and [c[:2] for c in relay.calls if c[0] == "catalog"] == [("catalog", None)]
    (b,) = blocks(relay)
    assert b.products[0].fixed == "2.1.1"  # a root with the whole current block, never a reply


def test_a_withdrawn_thread_is_not_catalogued_again_until_it_returns(env):
    """kk2q: the ledger keeps a withdrawn thread's level; the catalog announces nothing
    of it, neither a block that waited unsent nor one a fix changed."""
    gid = finding()["id"]
    env.api.put(gid, ghsa_json(gid))  # high by its fields; its prose a notice, so it can be withdrawn
    env.collector([finding(severity="moderate")])
    code, summary, relay = run(env, relay=FakeRelay("ok", "fail"))  # the alert posted; its catalog root did not
    assert summary.endswith(" catalog=0/1"), summary
    with Ledger(env.config.ledger) as led:
        led._state()["entries"][0]["withdrawn"] = ["feed"]
        led._save()
    env.api.put(gid, ghsa_json(gid, withdrawn_at="2026-11-06T00:00:00Z"))
    env.collector([finding(severity="moderate", fixed="2.1.1")])  # a fix learned while withdrawn: a reply in the thread, no catalog root
    code, summary, relay = run(env, now=T0 + 3600)
    assert code == 0 and summary.endswith(" catalog=0/0") and not [c for c in relay.calls if c[0] == "catalog"], summary
    env.api.put(gid, ghsa_json(gid))  # published again: the recompute ends the state
    code, summary, relay = run(env, now=T0 + 7200)
    assert "withdrawn" not in env.ledger()[0][0]
    assert summary.endswith(" catalog=1/0") and [b.products[0].fixed for b in blocks(relay)] == ["2.1.1"], summary


def test_a_withdrawn_key_stays_out_when_an_older_snapshot_merges_after(tmp_path):
    """Two runs' passes can merge in either order (the catalog lock is not the ledger's)."""
    adv = catalog._valid({
        "id": "GHSA-abcd-efgh-ijkl", "aliases": [], "level": "high", "advisory_severity": None, "title": "t",
        "products": [{"name": "Claude Code", "ecosystem": "claude-code", "affected": None, "fixed": "2.1.0"}],
        "actions": [], "sources": [{"url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl", "published_at": None}],
        "posted_by": "relay-bot", "posted_at": 1, "expires_at": None})
    assert adv is not None
    path, k = tmp_path / "known.json", catalog.key("Claude Code", adv["id"])
    assert catalog.remember(path, {k: adv}, at=10) == 1
    assert catalog.remember(path, {k: None}, at=30) == 0  # withdrawn
    assert catalog.remember(path, {k: adv}, at=20) == 0   # the older run's snapshot, merged late
    assert json.loads(path.read_text())["gone"] == {k: 30}
    assert catalog.remember(path, {k: adv}, at=40) == 1   # it left the state: catalogued anew
    assert "gone" not in json.loads(path.read_text())


def test_a_withdrawn_thread_that_no_longer_starts_at_its_level_still_leaves_the_inventory():
    """An out product's thread starts at high only; lowered to notice and then withdrawn,
    its earlier block must still be taken out."""
    from types import SimpleNamespace
    adv = {"id": "CVE-2026-0001", "aliases": [], "level": "notice", "advisory_severity": None, "title": "t",
           "products": [{"name": "Git", "ecosystem": "git", "affected": None, "fixed": "2.50.0"}],
           "actions": [], "sources": [{"url": "https://github.com/git/git/security/advisories/GHSA-abcd-efgh-ijkl",
                                       "published_at": None}],
           "posted_by": "relay-bot", "posted_at": 1, "expires_at": None}
    out = next(e for e in schema.load_scope() if not main.rules.starts(e, "notice") and main.rules.starts(e, "high"))
    adv["products"][0].update(name=out.name, ecosystem=out.ecosystem)
    assert catalog._valid(adv) is not None
    entry = SimpleNamespace(scope=out.name, level="notice", advisory=adv, gone=True)  # aqtf: the standing reply's
    led = SimpleNamespace(entries=lambda: [entry])
    assert catalog.snapshot(led, []) == {catalog.key(out.name, adv["id"]): None}
    entry.gone = False
    assert catalog.snapshot(led, []) == {}  # not withdrawn: a notice of an out product starts nothing, as before


def test_a_held_notice_posts_to_the_catalog_and_not_to_feed(env):
    env.collector([MAC])
    code, summary, relay = run(env)
    assert code == 0 and "held=1" in summary and chans(relay) == [("catalog", None)]
    (b,) = blocks(relay)
    assert b.level == "notice" and b.id == "CVE-2026-5000"


def test_a_held_notice_corrected_by_a_whole_read_posts_a_new_catalog_root(env):  # 6wy8
    """The corrected block is a new root, which a reader takes over the earlier one
    (newest root per id and product): no second mechanism, and nothing waits."""
    test_main.inspector_notice(env, affected=">= 2.0.0, <= 2.16.0", patched=None)
    _, _, relay = run(env)
    (b,) = blocks(relay)
    assert (b.products[0].affected, b.products[0].fixed) == (">=2.0.0,<=2.16.0", None)
    test_main.inspector_notice(env, blocks=test_main.TWO_RANGES)
    _, _, relay = run(env, now=T0 + 3600)
    assert chans(relay) == [("catalog", None)]
    (b,) = blocks(relay)
    assert b.id == "GHSA-4fc4-wcmh-4g86" and (b.products[0].affected, b.products[0].fixed) == (None, "2.17.0")
    test_main.inspector_notice(env, blocks=test_main.TWO_RANGES)
    _, summary, relay = run(env, now=T0 + 7200)
    assert "candidates=1" in summary and relay.calls == []  # the same read again posts nothing


def test_a_notice_first_seen_in_the_digest_run_still_reaches_the_catalog(env):
    run(env)  # qwpw: the state starts in ISO week 2026-W45; Monday's digest carries the weekly summary
    env.collector([MAC])
    code, _, relay = run(env, now=at(9, 9))  # held, then listed by the weekly summary in the same run
    assert code == 0 and [c[0] for c in relay.calls] == ["feed", "catalog"]
    assert "Weekly summary: 1 notice added" in relay.calls[0][2] and env.state()["held"] == []
    assert blocks(relay)[0].id == "CVE-2026-5000"


def test_one_id_in_two_products_is_two_entries(env):
    env.collector([finding(fid="GHSA-mnop-qrst-uvwx", sources=(test_main.GHSA2,)),
                   finding(fid="GHSA-mnop-qrst-uvwx", product="Cursor IDE", severity="high",
                           sources=("https://cursor.com/security/ghsa-mnop",))])
    code, _, relay = run(env)
    assert code == 0
    assert sorted(b.products[0].name for b in blocks(relay)) == ["Claude Code", "Cursor"]


def test_a_synthetic_advisory_never_reaches_the_catalog(env):
    code, summary, relay = run(env, now=at(20, 6), kev_catalog=inputs.read_kev_file(SYNTHETIC))
    assert code == 0 and "roots=1" in summary and chans(relay) == [("feed", None)]
    assert summary.endswith(" catalog=0/0")


def test_a_failed_catalog_send_leaves_the_run_whole_and_waits_for_the_next(env):
    env.collector([finding()])
    code, summary, relay = run(env, relay=FakeRelay("ok", "fail"))
    assert code == 0 and "roots=1" in summary and summary.endswith(" catalog=0/1")
    assert chans(relay) == [("feed", None), ("catalog", None)]
    code, summary, relay = run(env, now=T0 + 3600)
    assert code == 0 and chans(relay) == [("catalog", None)] and summary.endswith(" catalog=1/0")


def test_an_unknown_catalog_send_is_sent_again(env):
    env.collector([finding()])
    run(env, relay=FakeRelay("ok", "unknown"))
    _, _, relay = run(env, now=T0 + 3600)
    assert chans(relay) == [("catalog", None)]  # a duplicate root is harmless


def test_a_refused_catalog_post_is_not_resent_until_it_changes(env):
    env.collector([finding()])
    code, summary, relay = run(env, relay=FakeRelay("ok", "refuse"))
    assert code == 0 and summary.endswith(" catalog=0/0")
    _, _, relay = run(env, now=T0 + 3600)
    assert relay.calls == []


def test_catalog_sends_come_after_the_ledger_lock_and_the_checkpoint(env, monkeypatch):
    env.collector([finding()])
    seen = []

    def sender(channel_id, text, reply_to=None, claim=None):
        if channel_id == CATALOG:
            with Ledger(env.config.ledger):  # another run could take the lock now
                seen.append("ledger free")
            seen.append(("checkpoint ran", bool(order)))
        return FakeRelay()(channel_id, text, reply_to, claim)
    order = []
    real = signer.run_checkpoint
    monkeypatch.setattr(signer, "run_checkpoint", lambda *a, **k: (order.append(1), real(*a, **k))[1])
    code, _, _ = run(env, relay=sender)
    assert code == 0 and seen == ["ledger free", ("checkpoint ran", True)]


def test_a_pass_sends_at_most_max_per_run(env, monkeypatch):
    monkeypatch.setattr(catalog, "MAX_PER_RUN", 2)
    env.collector([finding(fid=f"CVE-2026-500{i}", product="Cursor IDE", severity=None, fixed=None,
                           sources=(test_main.APPLE,)) for i in range(3)])
    code, summary, relay = run(env)
    assert code == 0 and summary.endswith(" catalog=2/1") and len(blocks(relay)) == 2
    _, summary, relay = run(env, now=T0 + 3600)
    assert summary.endswith(" catalog=1/0")


def test_no_catalog_event_is_owed_to_a_checkpoint_or_listed_in_one(signing):
    env = signing
    env.collector([finding()])
    relay = PutRelay()
    code, summary, _ = run(env, relay=relay, ssh=relay)
    assert code == 0 and summary.endswith(" catalog=1/0"), summary
    feed_id, cat_id = relay.ids
    owed = {o["id"] for o in signer.load_owed(env.config.owed_state, T0)["owed"]}
    assert feed_id in owed and cat_id not in owed
    assert relay.puts and feed_id in relay.last().events and cat_id not in relay.last().events


def test_feed_takes_channel_class_and_channel_if_only(env):
    # A catalog-class product at a high reading is a notice: the catalog, never feed.
    sdk = finding(fid="GHSA-aaaa-bbbb-cccc", product="@modelcontextprotocol/sdk",
                  sources=("https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/"
                           "GHSA-aaaa-bbbb-cccc",))
    env.collector([sdk])
    code, summary, relay = run(env)
    assert code == 0 and chans(relay) == [("catalog", None)]
    assert blocks(relay)[0].level == "notice"


def test_the_inventory_outlives_the_held_list_and_drops_out_of_scope(env, tmp_path):
    a = schema.validate({"id": "CVE-2026-5000", "aliases": [], "level": "notice", "advisory_severity": None,
                         "title": "Cursor: a flaw (CVE-2026-5000)",
                         "products": [{"name": "Cursor", "ecosystem": "cursor", "affected": None, "fixed": None}],
                         "actions": [], "sources": [{"url": test_main.APPLE, "published_at": None}],
                         "posted_by": "relay-bot", "posted_at": T0, "expires_at": None})
    from dataclasses import asdict
    adv = asdict(a)
    gone = {**adv, "products": [{**adv["products"][0], "name": "No Such Product"}]}
    path = tmp_path / "known.json"
    catalog.remember(path, {catalog.key("Cursor", adv["id"]): adv, "No Such Product|x": gone})
    assert catalog.remember(path, {}) == 1  # nothing new: kept; the unknown product dropped
    assert list(json.loads(path.read_text())["known"]) == ["Cursor|cve-2026-5000"]


def test_an_out_product_with_channel_if_at_high_posts_to_feed_and_the_catalog(env):
    git = finding(fid="GHSA-dddd-eeee-ffff", product="git scm", severity="remote code execution",
                  sources=("https://github.com/git/git/security/advisories/GHSA-dddd-eeee-ffff",))
    env.collector([git])
    code, summary, relay = run(env)
    assert code == 0 and chans(relay) == [("feed", None), ("catalog", None)], summary
    assert blocks(relay)[0].level == "high" and blocks(relay)[0].products[0].name == "git"


def test_a_busy_catalog_lock_skips_the_pass(env, monkeypatch):
    import fcntl
    monkeypatch.setattr(catalog, "LOCK_WAIT", 0)
    env.collector([finding()])
    env.config.catalog_lock.parent.mkdir(parents=True, exist_ok=True)
    with open(env.config.catalog_lock, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, summary, relay = run(env)
    assert code == 0 and summary.endswith(" catalog=busy") and chans(relay) == [("feed", None)]
    _, summary, relay = run(env, now=T0 + 3600)  # the next run's snapshot carries the thread
    assert chans(relay) == [("catalog", None)]


def test_no_catalog_file_is_touched_under_the_ledger_lock(env, monkeypatch):
    env.collector([finding()])
    seen = []
    real = catalog.remember

    def remember(path, snap, at=0):
        with Ledger(env.config.ledger):  # free: the run has released it
            seen.append(path.name)
        return real(path, snap, at)
    monkeypatch.setattr(catalog, "remember", remember)
    code, _, _ = run(env)
    assert code == 0 and seen == [env.config.catalog_known.name]


def test_a_pass_stops_at_its_deadline(env):
    env.collector([finding()])
    run(env, catalog_channel=False)  # posted with the lane off
    with Ledger(env.config.ledger) as led:
        snap = catalog.snapshot(led, [])
    ticks = iter([0, 0, catalog.DEADLINE, catalog.DEADLINE])
    relay = FakeRelay()
    assert catalog.send_pass(env.config, CATALOG, relay, snap, clock=lambda: next(ticks)) == "0/1"
    assert relay.calls == []
    assert catalog.send_pass(env.config, CATALOG, relay) == "1/0"  # the inventory kept it


def test_catalog_paths_clash_turns_off_the_lane_only(env, tmp_path):
    cfg = inputs.Config(heartbeat_runs=tmp_path, collector_runs=tmp_path, ledger=tmp_path / "ledger.json",
                        kev_cache=tmp_path / "kev.json", **test_main.RELAY)
    cfg.check_paths()
    cfg.check_catalog_paths()
    clash = replace(cfg, kev_cache=cfg.catalog_state)
    clash.check_paths()  # the alert files alone are fine: load_config never refuses for a catalog path
    with pytest.raises(inputs.ConfigError):
        clash.check_catalog_paths()
    env.config = replace(env.config, kev_cache=env.config.catalog_state)
    env.collector([finding()])
    code, summary, relay = run(env)
    assert code == 0 and summary.endswith(" catalog=off-bad-paths") and chans(relay) == [("feed", None)]


def test_the_checkpoint_window_never_lists_a_catalog_event():
    from aitools_alerts import nostr, pull
    sec, _ = nostr.keygen()
    evs = [nostr.sign_event(sec, {"created_at": T0, "kind": 9, "tags": [["h", ch]], "content": "x"})
           for ch in (CHANNELS["feed"], CATALOG)]
    assert pull._bound(evs[0], pull.channel_ids()) and not pull._bound(evs[1], pull.channel_ids())
    assert CATALOG not in pull.channel_ids()


def _adv(product, adv_id="CVE-2026-6000", level="notice", fixed=None, eco="mcp"):
    from dataclasses import asdict
    return asdict(schema.validate({
        "id": adv_id, "aliases": [], "level": level, "advisory_severity": None,
        "title": f"{product}: a flaw ({adv_id})",
        "products": [{"name": product, "ecosystem": eco, "affected": None, "fixed": fixed}],
        "actions": [{"verb": "upgrade", "target": product, "value": fixed}] if fixed else [],
        "sources": [{"url": test_main.APPLE, "published_at": None}],
        "posted_by": "relay-bot", "posted_at": T0, "expires_at": None}))


class _Led:
    def __init__(self, *entries):
        self._e = entries

    def entries(self):
        return list(self._e)


def test_a_thread_or_notice_under_a_former_product_name_is_catalogued(tmp_path):
    from types import SimpleNamespace
    old = "MCP Inspector"  # formerly of @modelcontextprotocol/inspector (wa6n)
    thread = SimpleNamespace(scope=old, level="high", advisory=_adv(old, "CVE-2026-6001", "high", "0.9.0"))
    held = [{"scope": old, "adv": _adv(old, "CVE-2026-6002")}]
    snap = catalog.snapshot(_Led(thread), held)
    assert set(snap) == {f"{old}|cve-2026-6001", f"{old}|cve-2026-6002"}
    path = tmp_path / "known.json"
    assert catalog.remember(path, snap) == 2 and catalog.remember(path, {}) == 2  # not purged as out of scope


def test_an_older_snapshot_never_replaces_a_newer_one(tmp_path):
    k = "Cursor|cve-2026-6000"
    old, new = _adv("Cursor", eco="cursor"), _adv("Cursor", fixed="2.0.0", eco="cursor")
    path = tmp_path / "known.json"
    catalog.remember(path, {k: new}, at=T0 + 3600)  # the later run's pass got the lock first
    catalog.remember(path, {k: old}, at=T0)
    assert catalog._read(path, "known")[k]["products"][0]["fixed"] == "2.0.0"
    catalog.remember(path, {k: old}, at=T0 + 7200)  # a later snapshot does replace it
    assert catalog._read(path, "known")[k]["products"][0]["fixed"] is None


def test_the_byte_bound_is_measured_as_written(tmp_path, monkeypatch):
    snap = {f"Cursor|cve-2026-60{i:02d}": {**_adv("Cursor", f"CVE-2026-60{i:02d}", eco="cursor"),
                                           "title": "Cursor: " + "あ" * 300}  # 1 char, 6 bytes escaped
            for i in range(20)}
    path = tmp_path / "known.json"
    one = catalog._encoded({"v": 1, "known": dict([next(iter(snap.items()))]), "at": {"x": 0}})
    monkeypatch.setattr(catalog, "KEEP_BYTES", 5 * one)
    kept = catalog.remember(path, snap)
    assert 0 < kept < 20 and path.stat().st_size <= catalog.KEEP_BYTES
    monkeypatch.setattr(catalog, "MAX_FILE", catalog.KEEP_BYTES)
    assert len(catalog._read(path, "known")) == kept  # what was written reads back whole


def test_refused_sends_count_against_the_cap(env, monkeypatch):
    monkeypatch.setattr(catalog, "MAX_PER_RUN", 2)
    env.collector([finding(fid=f"CVE-2026-500{i}", product="Cursor IDE", severity=None, fixed=None,
                           sources=(test_main.APPLE,)) for i in range(3)])
    code, summary, relay = run(env, relay=FakeRelay("refuse", "refuse", "refuse"))
    assert code == 0 and len([c for c in relay.calls if c[0] == "catalog"]) == 2 and summary.endswith(" catalog=0/1")


def test_a_fifo_at_the_catalog_spec_turns_the_lane_off_without_blocking(env, monkeypatch, tmp_path):
    import os
    fifo = tmp_path / "catalog-channel.json"
    os.mkfifo(fifo)
    monkeypatch.setattr(inputs, "CATALOG_SPEC", str(fifo))
    env.collector([finding()])
    code, summary, relay = env.run(catalog_channel=None)
    assert code == 0 and summary.endswith(" catalog=off-bad-spec") and chans(relay) == [("feed", None)]


def test_snapshot_stamps_order_runs_within_one_second(tmp_path):
    k = "Cursor|cve-2026-6000"
    first, second = catalog.stamp(), catalog.stamp()
    assert second > first  # nanoseconds: two runs in the same second still order
    path = tmp_path / "known.json"
    catalog.remember(path, {k: _adv("Cursor", fixed="2.0.0", eco="cursor")}, second)
    catalog.remember(path, {k: _adv("Cursor", eco="cursor")}, first)  # the earlier run's pass, merged late
    assert catalog._read(path, "known")[k]["products"][0]["fixed"] == "2.0.0"
