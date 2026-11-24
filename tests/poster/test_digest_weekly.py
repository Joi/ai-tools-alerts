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
