"""An alert the member's source never supported shows at notice (ai-tools-alerts#0z4e):
the row of the D8 table "contradicted, the source never supported it", the 48 hours of
"supported earlier and no longer", and that a failed read changes nothing."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from aitools_alerts import cli, config, ruleset, verify
from aitools_alerts.schema import Action, Product
from aitools_alerts.state import State, write_json
from mirror_helpers import T0, advisory
from test_unverified_cli import both_installed, clock_at, run_json, sent  # noqa: F401 - sent is a fixture
from test_verify import CVE, G1, G2, KEV_CC, Net, ghsa, gurl, kev
from test_verify_cli import bot, env, feed, out_of, use  # noqa: F401 - env and feed are fixtures

DAY = 86400
ELSEWHERE = kev((CVE, "Cisco", "IOS XE"))  # the catalog lists the CVE, for another vendor's product
FLAG = f"source check: the source does not support {CVE} for Claude Code"
WITHDRAWN = "2026-11-01T00:00:00Z"
DOWN = OSError("down")


def matches(capsys) -> list:
    return json.loads(out_of(capsys, ["check", "--json"])[1])


def level(capsys) -> str:
    (d,) = matches(capsys)
    return d["level"]


def memory(product="Claude Code"):
    (names,) = State.load().supported["threads"].values() or [{}]
    return names.get(product)


def serve_again(m):
    m.write(Path(config.load().mirror_url[len("file://"):]))


def reply(m, **fields):
    root = m.events["feed.json"][0]
    m.post(m.bot_sec, m.patch_text(**fields), created_at=T0 + 300, tags=[["e", root["id"], "", "root"]])
    serve_again(m)


def read_as_unsupported(feed, monkeypatch, level="critical", extra=""):
    """A relay-bot alert for Claude Code on a CVE the catalog lists for another vendor,
    pulled and read once."""
    m = feed([bot(id=CVE, level=level)], extra)
    n = use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    return m, n


# ---------------------------------------------------------------- the record

def test_a_record_written_before_this_change_is_not_damage(tmp_path):
    old = {"lowerings": {"a" * 64: 5}, "refused": ["b" * 64], "interrupts": {}, "held": {}, "reset_at": 7}
    (tmp_path / "unverified.json").write_text(json.dumps(old))
    st = State.load(tmp_path)
    assert not st.unverified_damaged and st.supported == {"ruleset": None, "first": {}, "threads": {}}
    assert (st.lowerings, st.refused, st.reset_at) == ({"a" * 64: 5}, {"b" * 64}, 7)


def test_the_memory_is_saved_and_read_back(tmp_path):
    st = State.load(tmp_path)
    st.supported = {"ruleset": "c" * 64, "first": {"a" * 64: 3}, "threads": {"a" * 64: {"Claude Code": [5, None, None], "Codex": [None, 6, 9]}}}
    st.save_unverified()
    back = State.load(tmp_path)
    assert not back.unverified_damaged and back.supported == st.supported


@pytest.mark.parametrize("bad", [
    [], {"threads": {}}, {"ruleset": None, "threads": {}}, {"ruleset": None, "first": {"not an id": 5}, "threads": {}},
    {"ruleset": None, "first": {"a" * 64: -1}, "threads": {}}, {"ruleset": "c" * 63, "first": {}, "threads": {}}, {"ruleset": None, "first": {}, "threads": []},
    {"ruleset": None, "first": {}, "threads": {"not an id": {"Claude Code": [5, None, None]}}},
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"Claude Code": [5, None]}}},
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"Claude Code": [None, None, None]}}},
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"Claude Code": [None, 6, None]}}},  # gone without seen
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"Claude Code": [5, None, 6]}}},  # seen without gone
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"Claude Code": [None, 6, 5]}}},  # seen before gone
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"Claude Code": [-1, None, None]}}},
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"Claude Code": [True, None, None]}}},
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"": [5, None, None]}}},
    {"ruleset": None, "first": {}, "threads": {"a" * 64: {"x" * 201: [5, None, None]}}},
    {"ruleset": None, "first": {}, "threads": {}, "more": 1},
])
def test_a_malformed_memory_is_damage(tmp_path, bad):
    rec = {"lowerings": {}, "refused": [], "interrupts": {}, "held": {}, "reset_at": None, "supported": bad}
    (tmp_path / "unverified.json").write_text(json.dumps(rec))
    assert State.load(tmp_path).unverified_damaged


# ---------------------------------------------------------------- acceptance 1: never supported

def test_a_critical_the_catalog_lists_for_another_vendor_shows_at_notice_and_does_not_interrupt(feed, sent, monkeypatch,
                                                                                                  capsys):
    read_as_unsupported(feed, monkeypatch)
    status, out, _ = out_of(capsys, ["run"])
    assert status == 0 and sent["texts"] == []  # no exit 2, no notification
    assert "CRITICAL" not in out and "NOTICE: " in out and "; published at critical)" in out
    assert FLAG + "\n" in out and "held, not notified" not in out and "not verified from this machine" not in out
    status, out, _ = out_of(capsys, ["check"])
    assert FLAG + "\n" in out and out.count("source check:") == 1
    status, data = run_json(capsys)
    assert status == 0 and data["unseen_critical"] == [] and data["held_critical"] == []
    (d,) = data["matches"]
    assert (d["level"], d["published_level"]) == ("notice", "critical")
    assert d["source_check"] == {"result": "contradicted", "why": "unsupported", "source_level": "none"}
    status, out, _ = out_of(capsys, ["plan", CVE])
    assert status == 0 and out.startswith("NOTICE: ") and "; published at critical" in out and FLAG in out
    assert out_of(capsys, ["notify"])[0] == 0 and sent["texts"] == [] and State.load().seen == set()
    assert out_of(capsys, ["verify"])[1].startswith("source check: 0 confirmed, 1 contradicted, 0 not verified")
    last, gone, seen = memory()
    assert last is None and gone == seen and State.load().supported["ruleset"] == ruleset.load().digest


def test_the_first_run_interrupts_once_unverified_and_shows_notice_once_the_source_is_read(feed, sent, monkeypatch,
                                                                                             capsys):
    feed([bot(id=CVE, level="critical")])
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    status, out, _ = out_of(capsys, ["run"])  # a critical never waits for a source (tavj)
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1 and sent["texts"][0].endswith(cli.NOT_VERIFIED)
    after = out.partition("After the source check:\n")[2]
    assert "NOTICE: " in after and "CRITICAL" not in after and FLAG in after
    assert out_of(capsys, ["run"])[0] == 0 and len(sent["texts"]) == 1


def test_a_published_high_never_supported_shows_at_notice(feed, monkeypatch, capsys):
    read_as_unsupported(feed, monkeypatch, level="high")
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"]) == ("notice", "high")


def test_a_notice_never_supported_is_flagged_as_before(feed, monkeypatch, capsys):
    read_as_unsupported(feed, monkeypatch, level="notice")
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"]) == ("notice", None) and d["source_check"]["why"] == "unsupported"
    assert FLAG in out_of(capsys, ["check"])[1]


def test_the_hook_s_command_applies_the_memory_and_reads_no_source(feed, sent, monkeypatch, capsys):
    read_as_unsupported(feed, monkeypatch)
    n = use(monkeypatch, Net())
    status, data = run_json(capsys)
    assert status == 0 and n.calls == [] and data["matches"][0]["level"] == "notice" and sent["texts"] == []


def two(first="Claude Code", second="Codex"):
    eco = {"Claude Code": "claude-code", "Codex": "codex"}
    return replace(bot(id=CVE, level="critical"),
                   products=[Product(n, eco[n], "<99.0.0", "99.0.0") for n in (first, second)],
                   actions=[Action("upgrade", n, "99.0.0") for n in (first, second)])


def test_a_supported_product_beside_an_unsupported_one_is_decided_per_match(feed, sent, monkeypatch, capsys):
    both_installed(monkeypatch)
    feed([two()])
    use(monkeypatch, Net().set(verify.KEV_URL, kev((CVE, "OpenAI", "Codex"))))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    got = {d["product"]["name"]: (d["level"], d["published_level"]) for d in matches(capsys)}
    assert got == {"Claude Code": ("notice", "critical"), "Codex": ("critical", None)}
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1 and "Codex" in sent["texts"][0]
    assert FLAG + "\n" in out and out.count("source check:") == 1
    _, out, _ = out_of(capsys, ["plan", CVE])
    assert out.count("NOTICE: ") == 1 and out.count("CRITICAL: ") == 1


def test_a_curator_s_own_critical_is_not_judged(feed, monkeypatch, capsys):
    m = feed([], 'verify = "all"\n')
    m.root_post(m.cur_sec, advisory(id=CVE, level="critical", products=[Product("Claude Code", "claude-code", "<99.0.0",
                                                                               "99.0.0")]), created_at=T0 + 100)
    serve_again(m)
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    assert level(capsys) == "critical" and State.load().supported["threads"] == {}


def test_above_source_keeps_its_published_level(feed, sent, monkeypatch, capsys):
    feed([bot(id=G1, level="critical")])
    use(monkeypatch, Net().set(gurl(G1), ghsa()))  # the source supports high
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"], d["source_check"]["why"]) == ("critical", None, "above-source")
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and sent["texts"][0].endswith(cli.NOT_VERIFIED)
    assert f"source check: {G1} is published at critical for Claude Code; the source supports high" in out


# ---------------------------------------------------------------- what the signer cannot do

def test_dropping_the_alias_the_support_came_through_demotes_nothing(feed, monkeypatch, capsys):
    """Beside a CVE, support comes only through an alias the thread lists, and the aliases
    are the relay bot's to replace. The widest state is what is judged."""
    m = feed([bot(id=CVE, level="critical", aliases=[G1])], 'verify = "all"\n')
    n = use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G1), ghsa(cve=CVE, type="malware")))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    assert level(capsys) == "critical" and memory()[1:] == [None, None]
    reply(m, aliases=[])
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    assert n.urls.count(gurl(G1)) == 1  # the widest state is the one already read and confirmed
    assert level(capsys) == "critical" and memory()[1:] == [None, None]
    assert "does not support" not in out_of(capsys, ["check"])[1]


def test_a_reply_that_changes_a_fabricated_thread_does_not_shed_the_demotion(feed, monkeypatch, capsys):
    m, n = read_as_unsupported(feed, monkeypatch)
    n.set(gurl(G2), DOWN)
    reply(m, aliases=[G2])  # a new published state, which no read completes
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"]) == ("notice", "critical")
    assert FLAG in out_of(capsys, ["check"])[1]


def test_support_read_later_ends_the_demotion_and_the_critical_interrupts_in_that_run(feed, sent, monkeypatch, capsys):
    m, n = read_as_unsupported(feed, monkeypatch)
    clock_at(monkeypatch, verify.time.time() + DAY + 60)
    n.set(verify.KEV_URL, KEV_CC)
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1 and cli.NOT_VERIFIED not in sent["texts"][0]
    assert "CRITICAL: " in out.partition("After the source check:\n")[2] and "does not support" not in out
    assert level(capsys) == "critical" and memory()[1:] == [None, None]


def test_support_read_beside_a_failing_alias_ends_the_demotion(feed, monkeypatch, capsys):
    m, n = read_as_unsupported(feed, monkeypatch)
    n.set(gurl(G2), DOWN).set(verify.KEV_URL, KEV_CC)
    reply(m, aliases=[G2])
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"]) == ("critical", None)
    assert d["source_check"] == {"result": "unknown", "why": "unread", "source_level": "critical"}


# ---------------------------------------------------------------- acceptance 2: supported earlier

def supported_then_withdrawn(feed, monkeypatch, capsys):
    """A confirmed critical; a day later this machine reads that the source withdrew it.
    Returns (the fetch, the time of that read)."""
    feed([bot(id=G1, level="critical")])
    n = use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    start = verify.time.time()
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL  # notified, then read and confirmed
    assert memory()[1:] == [None, None]
    n.set(gurl(G1), ghsa(type="malware", withdrawn_at=WITHDRAWN))
    gone = int(start) + DAY + 60
    clock_at(monkeypatch, gone)
    return n, gone


def test_support_lost_yesterday_keeps_the_level_and_is_flagged_only_past_48_hours(feed, sent, monkeypatch, capsys):
    n, gone = supported_then_withdrawn(feed, monkeypatch, capsys)
    lost = cli.LOST_LINE.format(id=G1, name="Claude Code")
    status, out, _ = out_of(capsys, ["run"])
    assert "source check:" not in out and level(capsys) == "critical" and memory()[1:] == [gone, gone]
    clock_at(monkeypatch, gone + DAY + 60)
    assert "source check:" not in out_of(capsys, ["run"])[1] and level(capsys) == "critical"
    clock_at(monkeypatch, gone + 2 * DAY + 120)
    _, out, _ = out_of(capsys, ["run"])
    assert out.count("source check:") == 1 and lost + "\n" in out
    assert level(capsys) == "critical" and matches(capsys)[0]["published_level"] is None  # the level is kept
    assert lost in out_of(capsys, ["check"])[1]
    n.set(gurl(G1), DOWN)  # a failed read does not end the line
    clock_at(monkeypatch, gone + 3 * DAY + 180)
    assert lost in out_of(capsys, ["run"])[1]
    n.set(gurl(G1), ghsa(type="malware"))  # the source supports it again
    clock_at(monkeypatch, gone + 4 * DAY + 240)
    assert "source check:" not in out_of(capsys, ["run"])[1] and memory()[1:] == [None, None]


def test_time_alone_brings_no_flag_while_reads_fail(feed, sent, monkeypatch, capsys):
    n, gone = supported_then_withdrawn(feed, monkeypatch, capsys)
    cli.main(["run"])
    n.set(gurl(G1), DOWN)
    for days in (1, 3, 7):
        clock_at(monkeypatch, gone + days * DAY + 60)
        assert "source check:" not in out_of(capsys, ["run"])[1]
        assert "source check:" not in out_of(capsys, ["check"])[1]
    assert level(capsys) == "critical" and memory()[1:] == [gone, gone]


def test_a_confirmed_high_is_read_again_and_its_lost_support_is_recorded(feed, monkeypatch, capsys):
    feed([bot(id=G1, level="high")])
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    assert cli.main(["run"]) == 0 and memory()[1:] == [None, None] and len(n.calls) == 1
    assert cli.main(["run"]) == 0 and len(n.calls) == 1  # not within the day
    n.set(gurl(G1), ghsa(withdrawn_at=WITHDRAWN))
    clock_at(monkeypatch, verify.time.time() + DAY + 60)
    assert cli.main(["run"]) == 0 and len(n.calls) == 2
    last, gone, seen = memory()
    assert last is not None and gone == seen and gone > last and level(capsys) == "high"


# ---------------------------------------------------------------- acceptance 3: a failed read changes nothing

def test_a_failed_read_leaves_an_alert_at_notice(feed, sent, monkeypatch, capsys):
    m, n = read_as_unsupported(feed, monkeypatch)
    before = memory()
    n.set(verify.KEV_URL, DOWN)
    for days in (1, 2, 5):
        clock_at(monkeypatch, verify.time.time() + DAY + 60)
        status, out, _ = out_of(capsys, ["run"])
        assert status == 0 and sent["texts"] == [] and "NOTICE: " in out and FLAG in out, days
    (d,) = matches(capsys)
    assert (d["level"], d["source_check"]["why"]) == ("notice", "unsupported") and memory() == before


def test_a_failed_read_leaves_a_supported_critical_as_it_is(feed, sent, monkeypatch, capsys):
    feed([bot(id=CVE, level="critical")])
    n = use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    before = memory()
    n.set(verify.KEV_URL, DOWN)
    clock_at(monkeypatch, verify.time.time() + 3 * DAY)
    status, out, _ = out_of(capsys, ["run"])
    assert "CRITICAL: " in out and "source check:" not in out and memory() == before and level(capsys) == "critical"


def test_an_alert_never_read_is_as_posted(feed, sent, monkeypatch, capsys):
    feed([bot(id=CVE, level="critical")])
    use(monkeypatch, Net().set(verify.KEV_URL, DOWN))
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and level(capsys) == "critical"
    assert State.load().supported["threads"] == {}


# ---------------------------------------------------------------- when the memory is not used

def test_with_the_check_off_the_alert_is_as_posted_and_the_memory_is_kept(feed, monkeypatch, capsys):
    read_as_unsupported(feed, monkeypatch)
    before = memory()
    path = config.config_path()
    path.write_text(path.read_text() + 'verify = "off"\n')
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"]) == ("critical", None) and memory() == before
    assert "source check:" not in out_of(capsys, ["check"])[1]


def test_for_48_hours_after_a_rebuilt_record_nothing_shows_at_notice(feed, sent, monkeypatch, capsys):
    read_as_unsupported(feed, monkeypatch)
    (config.state_dir() / "unverified.json").write_text("{not json")
    _, _, err = out_of(capsys, ["check"])
    assert "has been started again" in err and level(capsys) == "critical"
    assert FLAG in out_of(capsys, ["check"])[1]  # still said
    clock_at(monkeypatch, verify.time.time() + cli.SUPPORT_GAP_S + 60)
    assert level(capsys) == "notice"


def test_no_support_found_under_another_ruleset_is_not_reused(feed, monkeypatch, capsys):
    """The cache is dropped when the ruleset changes; the memory's "none" goes with it."""
    read_as_unsupported(feed, monkeypatch)
    st = State.load()
    st.supported["ruleset"] = "0" * 64
    st.save_unverified()
    (config.state_dir() / verify.FILE).unlink()
    assert level(capsys) == "critical"
    rec = State.load().supported
    assert (rec["ruleset"], rec["threads"]) == (ruleset.load().digest, {})
    assert cli.main(["verify"]) == 0 and level(capsys) == "notice"


def test_a_time_written_while_the_clock_was_ahead_counts_from_now(feed, monkeypatch, capsys):
    real = int(verify.time.time())
    clock_at(monkeypatch, real + 30 * DAY)
    read_as_unsupported(feed, monkeypatch)
    assert memory()[1] == real + 30 * DAY
    clock_at(monkeypatch, real)
    assert level(capsys) == "notice" and memory()[1:] == [real, real]


# ---------------------------------------------------------------- two commands at once

def test_a_read_this_command_made_is_remembered_whatever_another_command_then_wrote(feed, monkeypatch, capsys):
    """verify.json is written outside the state lock: a command that started earlier can
    write its older view over a read. The command that made the read hands it over."""
    feed([bot(id=G1, level="critical")])
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    assert cli.main(["pull"]) == 0
    real = cli._source_check

    def raced(a, st, s, threads, pairs, asked=()):
        got = real(a, st, s, threads, pairs, asked)
        other = json.loads(json.dumps(got))  # the other command's view: an older "no support"
        for r in other["results"].values():
            r["at"] -= 100
            r["products"] = {n: {"result": "contradicted", "why": "unsupported", "source": "none"} for n in r["products"]}
        write_json(config.state_dir() / verify.FILE, other)
        return got
    monkeypatch.setattr(cli, "_source_check", raced)
    assert cli.main(["verify"]) == 0
    last, gone, seen = memory()
    assert last is not None and (gone, seen) == (None, None)
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"]) == ("critical", None)


def test_the_reads_are_ordered_by_their_own_times():
    root, digest = "a" * 64, "c" * 64
    a = bot(id=G1, level="critical")
    entry = cli.Entry(root, (root,), a, {}, judged=a)

    def step(record, result, at, source):
        cache = {"results": {verify.state_key(a): {"at": at, "products": {
            "Claude Code": {"result": result, "why": {"confirmed": "match", "contradicted": "unsupported",
                                                     "unknown": "unread"}[result], "source": source}}}}}
        return cli._support_step(record, [entry], cache, digest, 1000, {root})

    def mem(record):
        return record["threads"].get(root, {}).get("Claude Code")
    rec = step({"ruleset": digest, "first": {root: 0}, "threads": {}}, "contradicted", 100, "none")
    assert mem(rec) == [None, 100, 100]
    assert mem(step(rec, "contradicted", 300, "none")) == [None, 100, 300]  # the first stays, the latest moves
    assert mem(step(rec, "unknown", 400, None)) == [None, 100, 100]  # a failed read
    assert mem(step(rec, "confirmed", 50, "critical")) == [50, 100, 100]  # support read before it clears nothing
    late = step(rec, "confirmed", 200, "critical")
    assert mem(late) == [200, None, None]
    assert mem(step(late, "contradicted", 150, "none")) == [200, None, None]  # "none" read before the support
    assert mem(step(late, "unknown", 500, "high")) == [500, None, None]  # what an incomplete read did read
    ahead = {"ruleset": digest, "first": {root: 9000}, "threads": {root: {"Claude Code": [None, 7000, 8000]}}}
    assert cli._support_step(ahead, [], {"results": {}}, digest, 1000, {root}) == {
        "ruleset": digest, "first": {root: 1000}, "threads": {root: {"Claude Code": [None, 1000, 1000]}}}  # cut
    assert step(rec, "contradicted", 300, "none")["ruleset"] == digest
    assert cli._support_step(rec, [], {"results": {}}, digest, 1000, set())["threads"] == {}  # the root is gone
    assert cli._support_step(late, [], {"results": {}}, "d" * 64, 1000, {root})["threads"] == {root: {
        "Claude Code": [200, None, None]}}
    assert cli._support_step(rec, [], {"results": {}}, "d" * 64, 1000, {root}) == {
        "ruleset": "d" * 64, "first": {root: 0}, "threads": {}}
    # "none" read before this machine first saw the thread is another thread's read: not counted
    new = {"ruleset": digest, "first": {root: 200}, "threads": {}}
    assert step(new, "contradicted", 100, "none")["threads"] == {} and mem(step(new, "confirmed", 100, "high")) == [
        100, None, None]
    assert step({"ruleset": digest, "first": {}, "threads": {}}, "contradicted", 100, "none") == {
        "ruleset": digest, "first": {root: 1000}, "threads": {}}  # first seen now
    # a result dated ahead of the clock says "none" only once it is read again
    assert mem(step(rec, "contradicted", 5000, "none")) == [None, 100, 100]
    assert mem(step(late, "confirmed", 5000, "critical")) == [1000, None, None]  # support is cut to the clock
    # the alert as it stands is what the source says (a withdrawn advisory at notice): "none" is over
    withdrawn = {"results": {verify.state_key(a): {"at": 300, "products": {
        "Claude Code": {"result": "confirmed", "why": "withdrawn", "source": "none"}}}}}
    assert cli._support_step(rec, [entry], withdrawn, digest, 1000, {root})["threads"] == {}
    was = step({"ruleset": digest, "first": {root: 0}, "threads": {}}, "confirmed", 50, "critical")
    assert mem(cli._support_step(step(was, "contradicted", 100, "none"), [entry], withdrawn, digest, 1000, {root})) \
        == [50, None, None]


# ---------------------------------------------------------------- what the plan's review asked for

def test_copies_with_one_content_and_another_history_are_each_judged_on_their_own(feed, monkeypatch, capsys):
    """Two roots whose advisories are equal now. One held the alias the support comes
    through and dropped it; the other never had it."""
    m = feed([bot(id=CVE, level="critical", aliases=[G1])], 'verify = "all"\n')
    m.root_post(m.bot_sec, bot(id=CVE, level="critical"), created_at=T0 + 50)
    reply(m, aliases=[])
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G1), ghsa(cve=CVE, type="malware")))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    got = {d["thread"]: (d["level"], d["published_level"]) for d in matches(capsys)}
    held = m.events["feed.json"][0]["id"]
    assert len(got) == 2 and got[held] == ("critical", None)
    assert [v for k, v in got.items() if k != held] == [("notice", "critical")]
    by_root = State.load().supported["threads"]
    assert by_root[held]["Claude Code"][1] is None and len(by_root) == 2


def test_the_memory_of_a_thread_this_command_did_not_see_is_kept(feed, monkeypatch, capsys):
    """A command that started before another one pulled a thread must not drop what the
    other recorded for it: the record is cut to the stored events, read under the lock."""
    import argparse
    read_as_unsupported(feed, monkeypatch)
    before = State.load().supported
    assert len(before["threads"]) == 1
    s = config.load()
    a = argparse.Namespace(settings=s, raw=[])  # this command's view holds no thread
    a.root, _ = cli._root(s)
    st = State.load()
    assert cli._note_support(a, st, [], {"results": {}}) is False and State.load().supported == before


def test_support_read_before_the_request_budget_ran_out_ends_the_demotion(feed, monkeypatch, capsys):
    m, n = read_as_unsupported(feed, monkeypatch)
    n.set(verify.KEV_URL, KEV_CC).set(gurl(G2), ghsa(G2, cve=CVE))
    reply(m, aliases=[G2])
    monkeypatch.setattr(verify, "MAX_FETCHES", 1)  # the catalog is read; the alias is not
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"]) == ("critical", None) and gurl(G2) not in n.urls
    assert d["source_check"] == {"result": "unknown", "why": "unread", "source_level": "critical"}


def test_an_old_unsupported_is_not_kept_as_found_again_when_the_budget_runs_out(tmp_path, monkeypatch):
    """"A failed read changes nothing": a run that could not read the thread whole must not
    leave the old result with a new time, which would read as "still no support today"."""
    from test_verify import NOW, adv, go, res
    a = adv(id=CVE, aliases=[G2], level="critical")
    n = Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G2), ghsa(G2))  # the alias does not name the CVE
    go(tmp_path, [a], n)
    assert res(tmp_path, a)["Claude Code"]["why"] == "unsupported"
    monkeypatch.setattr(verify, "MAX_FETCHES", 1)
    cache = go(tmp_path, [a], n, now=NOW + DAY + 60)
    assert res(tmp_path, a)["Claude Code"] == {"result": "unknown", "why": "unread", "source": None}
    assert cache["results"][verify.state_key(a)]["at"] == NOW + DAY + 60


def test_a_read_whose_cache_cannot_be_written_still_ends_the_demotion_for_that_command(feed, sent, monkeypatch, capsys):
    m, n = read_as_unsupported(feed, monkeypatch)
    n.set(verify.KEV_URL, KEV_CC)
    clock_at(monkeypatch, verify.time.time() + DAY + 60)

    def full(path, obj):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(verify, "write_json", full)
    status, out, err = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1 and cli.SOURCE_CHECK_FAILED in err
    assert "CRITICAL: " in out.partition("After the source check:\n")[2]
    assert memory()[0] is not None and memory()[1:] == [None, None]


# ---------------------------------------------------------------- what the code's reviews asked for

def test_support_read_while_a_lowering_is_checked_ends_the_demotion(feed, sent, monkeypatch, capsys, reader_clock):
    """The read that refuses a lowering (the source supports more) is support for the thread."""
    from test_curator_hold_cli import serve
    from test_unverified_cli import C0, lower
    m, n = read_as_unsupported(feed, monkeypatch)
    assert level(capsys) == "notice"
    lower(m, m.events["feed.json"][0], "high")
    serve(m, reader_clock, C0)
    n.set(verify.KEV_URL, KEV_CC)  # the catalog now lists it for Claude Code
    status, out, _ = out_of(capsys, ["run"])  # the critical state's own result is too young to be read again
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"], d["lowering_refused"]) == ("critical", None, "high")
    assert memory()[0] is not None and memory()[1:] == [None, None]


def test_a_result_dated_ahead_of_the_clock_is_read_again(feed, sent, monkeypatch, capsys):
    real = int(verify.time.time())
    clock_at(monkeypatch, real + 30 * DAY)
    m, n = read_as_unsupported(feed, monkeypatch)
    clock_at(monkeypatch, real)
    n.set(verify.KEV_URL, KEV_CC)
    before = len(n.calls)
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(n.calls) == before + 1
    assert level(capsys) == "critical"


def test_a_kept_refusal_keeps_only_its_own_product_s_result():
    more = {"result": "contradicted", "why": "below-source", "source": "critical"}
    none = {"result": "contradicted", "why": "unsupported", "source": "none"}
    unread = {"result": "unknown", "why": "unread", "source": None}
    read = {"result": "unknown", "why": "unread", "source": "high"}
    held = {"at": 5, "products": {"A": more, "B": none}}
    assert verify._settled(held, {"A": unread, "B": read}, True) == {"A": more, "B": read}
    assert verify._settled(held, {"A": unread, "B": unread}, True) == {"A": more, "B": unread}
    assert verify._settled(held, {"A": unread, "B": read}, False) == {"A": unread, "B": read}


def test_a_thread_posted_with_the_state_of_an_older_one_does_not_inherit_its_read(feed, sent, monkeypatch, capsys):
    """Results are kept per published state. A root that arrives later must interrupt
    once, unread, like any new alert; an old "no support" was not read about it."""
    m, n = read_as_unsupported(feed, monkeypatch)
    n.set(verify.KEV_URL, KEV_CC)  # since then the catalog lists it for Claude Code
    clock_at(monkeypatch, verify.time.time() + 3600)
    m.root_post(m.bot_sec, bot(id=CVE, level="critical", title="Another post, the same state"), created_at=T0 + 400)
    serve_again(m)
    status, data = run_json(capsys)  # the hook's command: no source is read
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(data["unseen_critical"]) == 1 and len(sent["texts"]) == 1
    got = sorted((d["level"], d["published_level"]) for d in data["matches"])
    assert got == [("critical", None), ("notice", "critical")]


def test_a_thread_no_product_of_which_was_ever_supported_leaves_the_list_of_criticals(feed, monkeypatch, capsys):
    codex = [Product("Codex", "codex", "<99.0.0", "99.0.0")]
    acts = [Action("upgrade", "Codex", "99.0.0")]
    feed([advisory(posted_by="relay-bot", id=CVE, level="critical", products=codex, actions=acts, title="Invented one"),
          advisory(posted_by="relay-bot", id=G1, level="critical", products=codex, actions=acts, title="Invented two")],
         'verify = "all"\n')
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE)
        .set(gurl(G1), ghsa(G1, pkgs=(("npm", "@openai/codex"),), type="malware")))
    _, out, _ = out_of(capsys, ["run"])
    listed = out.rpartition("Critical advisories not installed here:\n")[2]
    assert "Invented two" in listed and "Invented one" not in listed and listed.count("CRITICAL: ") == 1
    assert f"source check: the source does not support {CVE} for Codex" in out
    assert out_of(capsys, ["verify"])[1].startswith("source check: 1 confirmed, 1 contradicted, 0 not verified")


def test_for_48_hours_after_a_rebuild_nothing_shows_at_notice_whatever_the_clock(feed, monkeypatch, capsys):
    read_as_unsupported(feed, monkeypatch)
    (config.state_dir() / "unverified.json").write_text("[]")
    assert level(capsys) == "critical"
    clock_at(monkeypatch, verify.time.time() - 3600)  # the clock is set back: the rebuild is "ahead"
    assert level(capsys) == "critical"


def test_the_record_is_cut_to_the_stored_events_as_read_under_the_lock(feed, monkeypatch, capsys):
    """A command that loaded its state before another command pulled a thread and recorded
    its memory writes a change of its own: the other thread's entry must survive."""
    import argparse
    m = feed([bot(id=CVE, level="critical")], 'verify = "all"\n')
    n = use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G1), ghsa(type="malware")))
    assert cli.main(["pull"]) == 0
    stale = State.load()  # this command's view: one root
    (mine,) = [e["id"] for e in m.events["feed.json"]]
    m.root_post(m.bot_sec, bot(id=G1, level="critical"), created_at=T0 + 400)
    serve_again(m)
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0  # the other command: both roots read
    other = next(r for r in State.load().supported["threads"] if r != mine)
    s = config.load()
    a = argparse.Namespace(settings=s, raw=[])
    a.root, _ = cli._root(s)
    adv = bot(id=CVE, level="critical")
    entry = cli.Entry(mine, (mine,), adv, {}, judged=adv)
    late = {"results": {verify.state_key(adv): {"at": int(verify.time.time()) + 5, "products": {
        "Claude Code": {"result": "confirmed", "why": "match", "source": "critical"}}}}}
    assert other not in stale.events and cli._note_support(a, stale, [entry], late) is True
    now = State.load().supported["threads"]
    assert now[other]["Claude Code"][0] is not None and now[mine]["Claude Code"][0] is not None
