"""The daily digest's short form and the weekly summary (ai-tools-alerts#qwpw, v2 design
section 7): the daily lists the day's new real-time posts and nothing else; the held
notices are counted by product in the first digest of each ISO week."""

import json

import test_main
from aitools_alerts.poster import compose, inputs
from test_main import APPLE, MAC, at, chans, finding

env = test_main.env  # the poster test environment, shared
LINK = "https://buzz.ai-tools.md/alerts/"


def digests(relay):
    return [c[2] for c in relay.calls if c[2].startswith("Daily digest")]


def notice(fid="CVE-2026-5000", observed="2026-11-05T00:00:00Z"):
    return finding(fid=fid, product="Cursor IDE", severity=None, fixed=None, sources=(APPLE,), observed=observed)


def edit_state(env, fn):
    st = env.state()
    fn(st)
    env.config.state.write_text(json.dumps(st))


# ---------------------------------------------------------------- compose


def test_weekly_counts_by_product_most_first_and_caps_the_lines():
    out = compose.weekly(["b"] * 2 + ["a"] * 2 + ["c"] * 3, LINK)
    assert out.split("\n") == ["Weekly summary: 7 notices added to the catalog this week.",
                               "- c: 3", "- a: 2", "- b: 2", f"Catalog: {LINK}"]
    many = [f"p{i:02d}" for i in range(compose.WEEKLY_LINES + 3) for _ in range(1 + (i < 2))]
    lines = compose.weekly(many, LINK).split("\n")
    assert len(lines) == compose.WEEKLY_LINES + 3 and lines[1] == "- p00: 2"
    assert lines[-2] == "- 3 more products: 3"
    assert compose.weekly([], LINK).split("\n") == ["Weekly summary: 0 notices added to the catalog this week.",
                                                     f"Catalog: {LINK}"]
    ja = compose.weekly(["a"], LINK, "ja").split("\n")
    assert ja == ["週間まとめ: 今週カタログに追加された注意は 1 件です。", "- a: 1 件", f"カタログ: {LINK}"]


def test_a_quiet_digest_with_the_summary_drops_its_count():
    summary = compose.weekly(["a"], LINK)
    assert compose.digest([], "2026-11-09", held=1, link=LINK, summary=summary) == \
        "Daily digest for 2026-11-09: no new alerts.\n\n" + summary
    assert compose.digest([], "2026-11-09", held=1, link=LINK) == \
        f"Daily digest for 2026-11-09: no new alerts. 1 notice added to the catalog this week: {LINK}"


# ---------------------------------------------------------------- the run


def test_a_thread_is_listed_once_by_its_root(env):
    env.collector([finding()])
    env.run()
    _, _, relay = env.run(now=at(5, 9))
    (body,) = digests(relay)
    assert body.split("\n")[0] == "Daily digest for 2026-11-05: 1 new alert."
    assert body.split("\n")[1].startswith("- HIGH: ") and "GHSA-abcd-efgh-ijkl" in body
    env.collector([finding(fixed="2.2.0")], name="2026-11-06T010000Z")  # a change: a reply in its thread
    _, summary, relay = env.run(now=at(6, 6))
    assert "replies=1" in summary, summary
    _, _, relay = env.run(now=at(6, 9))
    (body,) = digests(relay)
    assert body == f"Daily digest for 2026-11-06: no new alerts. 0 notices added to the catalog this week: {LINK}"


def test_the_monday_digest_summarizes_the_weeks_notices(env):
    env.collector([notice(), notice("CVE-2026-5001")])
    _, summary, _ = env.run()
    assert "held=2" in summary
    _, _, relay = env.run(now=at(5, 9))  # Thursday: counted, not listed
    assert digests(relay) == [f"Daily digest for 2026-11-05: no new alerts. 2 notices added to the catalog "
                              f"this week: {LINK}"]
    assert len(env.state()["held"]) == 2 and env.state()["weekly"] == "2026-W45"
    _, _, relay = env.run(now=at(9, 9))  # Monday 09:00 Tokyo
    (body,) = digests(relay)
    lines = body.split("\n")
    assert lines[0] == "Daily digest for 2026-11-09: no new alerts."
    assert lines[2:] == ["Weekly summary: 2 notices added to the catalog this week.", "- Cursor: 2",
                         f"Catalog: {LINK}"]
    assert "CVE-2026-500" not in body  # counts only
    st = env.state()
    assert st["held"] == [] and st["weekly"] == "2026-W46"
    assert {"Cursor|cve-2026-5000", "Cursor|cve-2026-5001"} <= set(st["digested"])
    _, _, relay = env.run(now=at(10, 9))
    assert digests(relay) == [f"Daily digest for 2026-11-10: no new alerts. 0 notices added to the catalog "
                              f"this week: {LINK}"]
    env.collector([notice()], name="2026-11-10T010000Z")  # listed once: never held again
    _, summary, _ = env.run(now=at(10, 11))
    assert env.state()["held"] == []


def test_the_summary_has_a_japanese_copy(env):
    env.collector([notice()])
    env.run()
    env.run(now=at(5, 9))
    _, _, relay = env.run(now=at(9, 9))
    (ja,) = [c[2] for c in relay.ja if "デイリーダイジェスト" in c[2]]
    assert "週間まとめ: 今週カタログに追加された注意は 1 件です。" in ja and "- Cursor: 1 件" in ja


def test_a_missed_monday_is_summarized_by_the_next_digest(env):
    env.collector([notice()])
    env.run()
    env.run(now=at(5, 9))
    _, _, relay = env.run(now=at(10, 9))  # no run on Monday
    (body,) = digests(relay)
    assert "Weekly summary: 1 notice added to the catalog this week." in body
    assert env.state()["weekly"] == "2026-W46" and env.state()["held"] == []
    _, _, relay = env.run(now=at(11, 9))
    assert "Weekly summary" not in digests(relay)[0]  # once a week


def test_a_fresh_state_on_a_monday_waits_for_the_next_monday(env):
    env.collector([notice(observed="2026-11-09T00:00:00Z")])
    _, summary, _ = env.run(now=at(9, 6))
    assert "held=1" in summary and env.state()["weekly"] == "2026-W46"
    _, _, relay = env.run(now=at(9, 9))
    assert digests(relay) == [f"Daily digest for 2026-11-09: no new alerts. 1 notice added to the catalog "
                              f"this week: {LINK}"]
    _, _, relay = env.run(now=at(16, 9))
    assert "Weekly summary: 1 notice added" in digests(relay)[0]


def test_an_expired_notice_is_not_counted_and_leaves_the_held_list(env):
    env.collector([notice(), notice("CVE-2026-5001")])
    env.run()
    edit_state(env, lambda st: st["held"][0]["adv"].update(expires_at=at(5, 7)))
    _, _, relay = env.run(now=at(5, 9))
    assert "1 notice added to the catalog this week" in digests(relay)[0]
    assert [h["adv"]["id"] for h in env.state()["held"]] == ["CVE-2026-5001"]  # retired with the daily
    _, _, relay = env.run(now=at(9, 9))
    assert "Weekly summary: 1 notice added" in digests(relay)[0]


def test_a_state_written_before_the_summary_loads_with_this_week(env, tmp_path):
    env.collector([notice()])
    env.run()
    edit_state(env, lambda st: st.pop("weekly"))
    st = inputs.load_state(env.config.state, at(6, 6), 7)
    assert st["weekly"] == "2026-W45"
    edit_state(env, lambda st: st.update(weekly="2026-46"))
    try:
        inputs.load_state(env.config.state, at(6, 6), 7)
    except inputs.LedgerError:
        pass
    else:
        raise AssertionError("a malformed week loads")


def test_a_digest_journaled_before_the_summary_still_settles(env):
    env.collector([notice()])
    env.run()
    _, _, relay = env.run(now=at(9, 9), relay=test_main.FakeRelay("unknown"))  # Monday's digest, unsent
    st = env.state()
    (item,) = [it for it in st["outbox"] if it["kind"] == "digest"]
    assert item["adv"]["week"] == "2026-W46" and inputs._item_ok(item)
    old = {**item, "adv": {k: v for k, v in item["adv"].items() if k != "week"}}
    assert inputs._item_ok(old)  # written before qwpw
    assert not inputs._item_ok({**item, "adv": {**item["adv"], "week": "W46"}})
    edit_state(env, lambda st: st.update(outbox=[old if it["kind"] == "digest" else it for it in st["outbox"]]))
    code, _ = test_main.main.resolve(at(9, 10), env.config, old["key"], delivered="ab" * 32)
    st = env.state()
    assert st["digest_date"] == "2026-11-09" and st["weekly"] == "2026-W45"  # an old item names no week
    assert chans(relay) == [("feed", None)] and code == 0


# ------------------------------------------------ retiring held notices (review of fcaf792)

INSPECTOR = test_main.INSPECTOR
B_ID = "GHSA-2222-3333-4444"


def inspector(**kw):
    f = finding(fid="GHSA-4fc4-wcmh-4g86", product="npm:@modelcontextprotocol/inspector", severity=None,
                fixed=None, sources=(INSPECTOR,))
    return {**f, **kw}


def held_then_posted(env, held_scope=None, extra_alias=None):
    f = inspector()
    env.collector([f])
    env.run()
    if held_scope or extra_alias:
        def fix(st):
            if held_scope:
                st["held"][0]["scope"] = held_scope
            if extra_alias:
                st["held"][0]["adv"]["aliases"].append(extra_alias)
        edit_state(env, fix)
    rce = dict(f, fixed="1.0.3", advisory_severity="high")
    rce["sources"] = [{"url": INSPECTOR, "published_at": None, "title": "Remote code execution through the proxy"}]
    env.collector([rce], name="2026-11-05T020000Z")
    _, summary, _ = env.run(now=test_main.T0 + 3600)
    assert "roots=1" in summary, summary


def test_a_held_notice_that_posted_is_retired_not_counted(env):
    held_then_posted(env)
    _, _, relay = env.run(now=at(5, 9))
    (body,) = digests(relay)
    assert body.startswith("Daily digest for 2026-11-05: 1 new alert.") and "GHSA-4fc4-wcmh-4g86" in body
    st = env.state()
    assert st["held"] == [] and "@modelcontextprotocol/inspector|ghsa-4fc4-wcmh-4g86" in st["digested"]
    _, _, relay = env.run(now=at(9, 9))
    assert "Weekly summary: 0 notices added" in digests(relay)[0]


def test_a_notice_held_under_a_former_name_is_retired_by_the_root_under_the_new_one(env):
    held_then_posted(env, held_scope="MCP Inspector")
    env.run(now=at(5, 9))
    assert env.state()["held"] == []


def test_one_members_root_leaves_the_rest_of_a_held_group_held(env):
    """A held fix group keeps its members as aliases (faxq): one member's root does not
    retire the others, and the weekly summary counts the entry."""
    held_then_posted(env, extra_alias=B_ID)
    _, _, relay = env.run(now=at(5, 9))
    assert "1 new alert." in digests(relay)[0]
    assert [h["adv"]["aliases"] for h in env.state()["held"]] == [[B_ID]]
    _, _, relay = env.run(now=at(9, 9))
    assert "Weekly summary: 1 notice added" in digests(relay)[0]
    st = env.state()
    assert st["held"] == [] and f"@modelcontextprotocol/inspector|{B_ID.casefold()}" in st["digested"]


def test_a_retracted_notice_is_not_counted_and_leaves_the_held_list(env, monkeypatch):
    env.collector([notice(), notice("CVE-2026-5001")])
    env.run()
    monkeypatch.setattr(test_main.main.Run, "_withdrawn", lambda self, root, fetch=None: ({"cve-2026-5000"}, set()))
    _, _, relay = env.run(now=at(5, 9))
    assert "1 notice added to the catalog this week" in digests(relay)[0]
    assert [h["adv"]["id"] for h in env.state()["held"]] == ["CVE-2026-5001"]


def test_a_refused_summary_leaves_the_notices_for_the_next_digest(env, monkeypatch):
    env.collector([notice()])
    env.run()
    real = compose.weekly
    monkeypatch.setattr(compose, "weekly", lambda *a, **k: (_ for _ in ()).throw(ValueError("refused")))
    _, summary, relay = env.run(now=at(9, 9))
    assert digests(relay) == [f"Daily digest for 2026-11-09: no new alerts. 1 notice added to the catalog "
                              f"this week: {LINK}"] and "withheld=1" in summary
    assert env.state()["weekly"] == "2026-W45" and len(env.state()["held"]) == 1
    monkeypatch.setattr(compose, "weekly", real)
    _, _, relay = env.run(now=at(10, 9))
    assert "Weekly summary: 1 notice added" in digests(relay)[0] and env.state()["held"] == []


def test_week_validation_refuses_a_week_that_does_not_exist():
    assert inputs.week_ok("2026-W53") and inputs.week_ok("2027-W01")
    assert not any(inputs.week_ok(w) for w in ("2026-W00", "2026-W99", "2025-W53", "0000-W01", "2026-48"))


def test_the_digest_links_a_public_mirror_and_falls_back_to_the_default(monkeypatch):
    from dataclasses import replace as _replace
    cfg = test_main.inputs.Config(heartbeat_runs="/x", collector_runs="/x", ledger="/x/l.json", **test_main.RELAY)
    custom = "https://mirror.example.org/alerts/"
    assert test_main.main._mirror_link(_replace(cfg, translate_mirror_url=custom)) == custom
    assert test_main.main._mirror_link(_replace(cfg, translate_mirror_url="file:///srv/alerts/")) == LINK
    monkeypatch.setattr(compose.socket, "gethostname", lambda: "host-alpha")
    assert test_main.main._mirror_link(_replace(cfg, translate_mirror_url="https://host-alpha/alerts/")) == LINK
