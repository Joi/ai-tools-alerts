"""The member strike rule (ai-tools-alerts#cftg, finding D14): two alerts of one poster key
that this machine's source check found unsupported within seven days put the key on
probation here for 30 days. Its unverified raises are listed and never interrupt; its
lowerings apply only when this machine's check confirms them."""

import json
from pathlib import Path

import pytest

from aitools_alerts import cli, config, nostr, pull, verify
from aitools_alerts.state import MAX_STRIKE_ROOTS, State, no_probation, no_support
from mirror_helpers import T0
from test_curator_hold_cli import ALL, DAY, levels, serve
from test_narrowing_cli import RIGHT, WAITING, fixed, matches, narrow
from test_never_supported_cli import two
from test_unchecked_lowering import claim, ghsa_fields
from test_unverified_cli import C0, WAIT, both_installed, claimed_root, clock_at, lower, run_json, sent  # noqa: F401
from test_verify import CVE, CVE2, G1, G2, Net, ghsa, gurl, kev
from test_verify_cli import bot, env, feed, out_of, use  # noqa: F401 - env and feed are fixtures

ELSEWHERE = kev((CVE, "Cisco", "IOS XE"), (CVE2, "Cisco", "IOS XE"))  # both listed, for another vendor's product
DOWN = OSError("down")
A, B, C, D = "a" * 64, "b" * 64, "c" * 64, "d" * 64
KEY, KEY2 = "e" * 64, "f" * 64


def served(m):
    m.write(Path(config.load().mirror_url[len("file://"):]))


def fabricated(feed, monkeypatch, ids=(CVE, CVE2), extra="", more=()):
    """Relay-bot criticals for Claude Code on CVEs the catalog lists for another vendor,
    pulled and read once: each is found unsupported. ``more``: other alerts in the feed."""
    m = feed([bot(id=i, level="critical") for i in ids] + list(more), extra)
    n = use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    return m, n


def third(m, ident=G1, at=T0 + 400):
    root = m.root_post(m.bot_sec, bot(id=ident, level="critical"), created_at=at)
    served(m)
    return root


def record() -> dict:
    return State.load().probation


# ---------------------------------------------------------------- acceptance 1: two strikes, and the third

def test_two_fabricated_alerts_put_the_key_on_probation_and_a_third_does_not_interrupt(feed, sent, monkeypatch, capsys):
    m, n = fabricated(feed, monkeypatch)
    rec = record()
    assert list(rec["since"]) == [m.bot] and [len(s[1]) for s in rec["strikes"][m.bot]] == [1, 1]
    assert rec["since"][m.bot] == max(s[0] for s in rec["strikes"][m.bot])
    root = third(m)
    n.set(gurl(G1), DOWN)  # this machine cannot verify the third
    status, data = run_json(capsys)  # the session-start hook's command
    assert status == 0 and data["unseen_critical"] == [] and data["held_critical"] == [root["id"]]
    status, out, _ = out_of(capsys, ["run"])  # the hourly job: the source read fails
    assert status == 0 and sent["texts"] == [] and State.load().seen == set()
    assert cli.PROBATION_HELD_LINE.format(title="x", id=G1).partition("CRITICAL")[0] in out
    assert "at most 2 unverified alerts" not in out
    assert f"probation: poster key {m.bot[:12]} is on probation on this machine until " in out
    assert out_of(capsys, ["notify"])[0] == 0 and sent["texts"] == []
    assert State.load().interrupts == {}  # no slot was taken


def test_one_fabricated_alert_is_no_probation_and_the_next_interrupts_unverified(feed, sent, monkeypatch, capsys):
    m, n = fabricated(feed, monkeypatch, ids=(CVE,))
    rec = record()
    assert rec["since"] == {} and len(rec["strikes"][m.bot]) == 1
    third(m)
    n.set(gurl(G1), DOWN)
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1 and "probation" not in out


# ---------------------------------------------------------------- acceptance 2: a genuine alert

def test_a_genuine_alert_that_verifies_still_interrupts_during_probation(feed, sent, monkeypatch, capsys):
    m, n = fabricated(feed, monkeypatch)
    third(m)
    n.set(gurl(G1), ghsa(type="malware", fixed="99.0.0"))  # the fixed version bot() posts
    status, data = run_json(capsys)  # unread: held
    assert status == 0 and len(data["held_critical"]) == 1 and sent["texts"] == []
    status, out, _ = out_of(capsys, ["run"])  # the run that reads the source
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1 and cli.NOT_VERIFIED not in sent["texts"][0]
    assert "held, not notified" not in out.partition("After the source check:\n")[2]


def test_an_alert_that_took_a_slot_before_the_probation_is_held_once_it_begins(feed, sent, monkeypatch, capsys):
    m = feed([bot(id=G1, level="critical"), bot(id=CVE, level="critical"), bot(id=CVE2, level="critical")])
    n = use(monkeypatch, Net().set(verify.KEV_URL, DOWN).set(gurl(G1), DOWN))
    sent["accept"] = False  # nothing is delivered, so nothing is seen
    assert cli.main(["pull"]) == 0
    status, data = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(data["unseen_critical"]) == 2 and len(data["held_critical"]) == 1
    n.set(verify.KEV_URL, ELSEWHERE)
    assert cli.main(["verify"]) == 0 and list(record()["since"]) == [m.bot]
    status, data = run_json(capsys)  # the two fabrications show at notice; the third is the key's and unverified
    assert status == 0 and data["unseen_critical"] == [] and len(data["held_critical"]) == 1


# ---------------------------------------------------------------- acceptance 3: lowerings

@pytest.mark.parametrize("strikes", [1, 2])
def test_an_unconfirmed_lowering_of_a_key_on_probation_is_not_applied_after_72_hours(feed, monkeypatch, capsys,
                                                                                      reader_clock, strikes):
    m = feed([bot(id=i, level="critical") for i in (CVE, CVE2)[:strikes]], ALL)
    root = claimed_root(m, bot(id=G1, level="critical"), claim("ghsa", ghsa_fields(type="malware")))
    low = lower(m, root, "notice")
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G1), DOWN))
    assert levels(capsys)[G1] == "critical"
    assert cli.main(["verify"]) == 0 and bool(record()["since"]) is (strikes == 2)
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys)[G1] == ("critical" if strikes == 2 else "notice")
    if strikes == 1:
        return
    assert State.load().lowerings == {low["id"]: C0 + WAIT}  # the wait does not run: it starts when the probation ends
    serve(m, reader_clock, C0 + WAIT + 5 * DAY)
    assert levels(capsys)[G1] == "critical"
    out = out_of(capsys, ["check"])[1]
    assert "published and not verified" not in out  # no wait runs, so none is announced
    (d,) = [d for d in json.loads(out_of(capsys, ["check", "--json"])[1]) if d["id"] == G1]
    assert d["lowering_waits"] is None
    # this machine's own read confirms the lowering: it applies, probation or not
    n.set(gurl(G1), ghsa(type="malware", withdrawn_at="2026-11-01T00:00:00Z"))
    assert cli.main(["verify"]) == 0 and levels(capsys)[G1] == "notice"


def test_a_lowering_that_applied_unchecked_stops_applying_when_the_probation_begins(feed, monkeypatch, capsys,
                                                                                     reader_clock):
    m = feed([bot(id=i, level="critical") for i in (CVE, CVE2)], ALL)
    root = claimed_root(m, bot(id=G1, level="critical"), claim("ghsa", ghsa_fields(type="malware")))
    lower(m, root, "notice")
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(verify.KEV_URL, DOWN).set(gurl(G1), DOWN))
    assert levels(capsys)[G1] == "critical"
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys)[G1] == "notice" and record()["since"] == {}
    n.set(verify.KEV_URL, ELSEWHERE)
    assert cli.main(["verify"]) == 0 and list(record()["since"]) == [m.bot]
    assert levels(capsys)[G1] == "critical"


def test_a_probation_found_by_run_bars_the_lowering_in_that_run(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=i, level="critical") for i in (CVE, CVE2)], ALL)
    root = claimed_root(m, bot(id=G1, level="critical"), claim("ghsa", ghsa_fields(type="malware")))
    lower(m, root, "notice")
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(verify.KEV_URL, DOWN).set(gurl(G1), DOWN))
    assert levels(capsys)[G1] == "critical"
    serve(m, reader_clock, C0 + WAIT)
    n.set(verify.KEV_URL, ELSEWHERE)
    _, out, _ = out_of(capsys, ["run"])
    after = out.partition("After the source check:\n")[2]
    assert f"(id {G1}," in after and "CRITICAL: " in after and "probation: poster key" in after


# ---------------------------------------------------------------- acceptance 4: it outlives its evidence, and ends

def test_the_probation_outlives_the_threads_and_the_memory_and_ends_after_30_days(feed, sent, monkeypatch, capsys,
                                                                                   reader_clock):
    m, n = fabricated(feed, monkeypatch)
    began = record()["since"][m.bot]
    gone = {e["id"] for e in m.events["feed.json"]}
    root = third(m)
    n.set(gurl(G1), DOWN)
    assert cli.main(["pull"]) == 0
    # The evidence leaves this machine: the mirror serves the fabrications no more, the store
    # holds them no more (as when a thread ages out), and neither the memory of support nor
    # the cached source results name them.
    for name in m.events:
        m.events[name] = [e for e in m.events[name] if e["id"] not in gone]
    m.clock = reader_clock.at = T0 + 2000
    m.checkpoint(ids=[root["id"]], now=T0 + 2000)
    served(m)
    st = State.load()
    for i in gone:
        del st.events[i]
    st.save_events()
    st.supported = no_support()
    st.save_unverified()
    (st.dir / "verify.json").unlink()
    status, data = run_json(capsys)
    st = State.load()
    assert gone.isdisjoint(st.events) and st.supported["threads"] == {} and not (st.dir / "verify.json").exists()
    assert [d["id"] for d in data["matches"]] == [G1]
    assert status == 0 and data["held_critical"] == [root["id"]] and sent["texts"] == []
    assert record()["since"] == {m.bot: began} and len(record()["strikes"][m.bot]) == 2
    real = verify.time.time()
    clock_at(monkeypatch, real + cli.PROBATION_S - 3600)
    status, data = run_json(capsys)
    assert status == 0 and data["held_critical"] == [root["id"]]
    cli.main(["verify"])
    assert record()["strikes"] == {} and record()["since"] == {m.bot: began}  # the strikes are gone; it stands
    clock_at(monkeypatch, real + cli.PROBATION_S + 60)
    status, data = run_json(capsys)  # over: the alert interrupts as any unverified one
    assert status == cli.EXIT_UNSEEN_CRITICAL and data["unseen_critical"] == [root["id"]]
    assert len(sent["texts"]) == 1 and sent["texts"][0].endswith(cli.NOT_VERIFIED) and record() == no_probation()


def test_alerts_that_stay_unsupported_are_not_struck_again_after_seven_days(feed, monkeypatch, capsys):
    m, n = fabricated(feed, monkeypatch)
    real = verify.time.time()
    clock_at(monkeypatch, real + cli.PROBATION_S + DAY)
    assert cli.main(["verify"]) == 0  # read again: still unsupported, found long ago
    assert record() == no_probation()


def test_a_key_that_keeps_fabricating_stays_on_probation(feed, monkeypatch, capsys):
    m, n = fabricated(feed, monkeypatch)
    began = record()["since"][m.bot]
    real = verify.time.time()
    clock_at(monkeypatch, real + cli.PROBATION_S - DAY)
    n.set(verify.KEV_URL, kev((CVE, "Cisco", "IOS XE"), (CVE2, "Cisco", "IOS XE"),
                              ("CVE-2026-3000", "Cisco", "IOS XE"), ("CVE-2026-4000", "Cisco", "IOS XE")))
    for i, ident in enumerate(("CVE-2026-3000", "CVE-2026-4000")):
        m.root_post(m.bot_sec, bot(id=ident, level="critical"), created_at=T0 + 500 + i)
    served(m)
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    assert record()["since"] == {m.bot: began} and len(record()["strikes"][m.bot]) == 2  # written once
    clock_at(monkeypatch, real + cli.PROBATION_S + 60)
    assert cli.main(["check"]) == 0
    again = record()["since"][m.bot]
    assert began < again and again == max(s[0] for s in record()["strikes"][m.bot])


# ---------------------------------------------------------------- what a strike is

def test_copies_of_one_advisory_and_two_products_of_one_alert_are_one_strike(feed, monkeypatch, capsys):
    both_installed(monkeypatch)
    m = feed([two(), two()])  # one advisory, equal content, two roots; neither product is the catalog's
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    rec = record()
    assert rec["since"] == {} and [sorted(s[1]) for s in rec["strikes"][m.bot]] == [sorted(e["id"] for e in m.events["feed.json"])]


def test_a_supported_product_beside_a_never_supported_one_is_a_strike(feed, monkeypatch, capsys):
    both_installed(monkeypatch)
    m = feed([two()])
    use(monkeypatch, Net().set(verify.KEV_URL, kev((CVE, "OpenAI", "Codex"))))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    assert len(record()["strikes"][m.bot]) == 1


@pytest.mark.parametrize("case", ["above-source", "unread", "curator", "off"])
def test_what_is_not_a_strike(feed, monkeypatch, capsys, case):
    if case == "above-source":  # a critical the source supports lower
        m = feed([bot(id=G1, level="critical"), bot(id=G2, level="critical")])
        use(monkeypatch, Net().set(gurl(G1), ghsa(G1, fixed="99.0.0")).set(gurl(G2), ghsa(G2, fixed="99.0.0")))
    elif case == "unread":
        m = feed([bot(id=CVE, level="critical"), bot(id=CVE2, level="critical")])
        use(monkeypatch, Net().set(verify.KEV_URL, DOWN))
    elif case == "curator":
        from mirror_helpers import advisory
        m = feed([])
        for i, ident in enumerate((CVE, CVE2)):
            m.root_post(m.cur_sec, advisory(id=ident, level="critical"), created_at=T0 + 100 + i)
        served(m)
        use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    else:
        m = feed([bot(id=CVE, level="critical"), bot(id=CVE2, level="critical")], 'verify = "off"\n')
        use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    assert cli.main(["pull"]) == 0
    cli.main(["verify"])
    assert cli.main(["run"]) in (0, cli.EXIT_UNSEEN_CRITICAL) and record() == no_probation()


def test_a_stored_probation_is_acted_on_with_the_check_off(feed, sent, monkeypatch, capsys):
    m, n = fabricated(feed, monkeypatch)
    third(m)
    cfg = config.config_path()
    cfg.write_text(cfg.read_text() + 'verify = "off"\n')
    status, data = run_json(capsys)
    # with the check off the fabrications are as posted, critical; all three are the key's and unverified
    assert status == 0 and len(data["held_critical"]) == 3 and sent["texts"] == [] and n.calls != []
    before = len(n.calls)
    assert out_of(capsys, ["run"])[0] == 0 and len(n.calls) == before and list(record()["since"]) == [m.bot]


# ---------------------------------------------------------------- the record

def test_a_record_written_before_this_change_is_not_damage(tmp_path):
    old = {"lowerings": {A: 5}, "refused": [B], "interrupts": {}, "held": {}, "reset_at": 7,
           "supported": {"ruleset": None, "first": {A: 3}, "threads": {A: {"x": [5, None, None]}}}}
    (tmp_path / "unverified.json").write_text(json.dumps(old))
    st = State.load(tmp_path)
    assert not st.unverified_damaged and st.probation == no_probation() and st.supported == old["supported"]
    assert (st.lowerings, st.refused, st.reset_at) == ({A: 5}, {B}, 7)


def test_the_record_is_saved_and_read_back(tmp_path):
    st = State.load(tmp_path)
    st.probation = {"strikes": {KEY: [[5, [A]], [9, [B, C]]]}, "since": {KEY: 9, KEY2: 4}}
    st.save_unverified()
    back = State.load(tmp_path)
    assert not back.unverified_damaged and back.probation == st.probation


@pytest.mark.parametrize("bad", [
    [], {"strikes": {}}, {"strikes": {}, "since": {}, "more": 1}, {"strikes": [], "since": {}}, {"strikes": {}, "since": []},
    {"strikes": {"not a key": [[5, [A]]]}, "since": {}}, {"strikes": {KEY: []}, "since": {}},
    {"strikes": {KEY: [[5, [A]], [6, [B]], [7, [C]]]}, "since": {}},  # more than the rule reads
    {"strikes": {KEY: [[5, []]]}, "since": {}}, {"strikes": {KEY: [[5, ["not an id"]]]}, "since": {}},
    {"strikes": {KEY: [[5, [A] * (MAX_STRIKE_ROOTS + 1)]]}, "since": {}},
    {"strikes": {KEY: [[-1, [A]]]}, "since": {}}, {"strikes": {KEY: [[True, [A]]]}, "since": {}},
    {"strikes": {KEY: [[5, [A], 6]]}, "since": {}}, {"strikes": {KEY: [{"at": 5}]}, "since": {}},
    {"strikes": {}, "since": {"not a key": 5}}, {"strikes": {}, "since": {KEY: -1}}, {"strikes": {}, "since": {KEY: "5"}},
])
def test_a_malformed_record_is_damage(tmp_path, bad):
    rec = {"lowerings": {}, "refused": [], "interrupts": {}, "held": {}, "reset_at": None,
           "supported": no_support(), "probation": bad}
    (tmp_path / "unverified.json").write_text(json.dumps(rec))
    assert State.load(tmp_path).unverified_damaged


def test_a_rebuilt_record_loses_the_probation_and_gives_no_slot_for_a_day(feed, sent, monkeypatch, capsys):
    m, n = fabricated(feed, monkeypatch)
    third(m)
    n.set(gurl(G1), DOWN)
    (State.load().dir / "unverified.json").write_text("{")
    status, data = run_json(capsys)
    assert status == 0 and len(data["held_critical"]) == 3 and sent["texts"] == []  # the day after a rebuild
    assert record() == no_probation() and State.load().reset_at is not None
    cli.main(["verify"])
    assert record() == no_probation()  # and no strike is recorded for 48 hours after it


# ---------------------------------------------------------------- the step

def step(record, found, now=1000 * DAY):
    return cli._probation_step(record, found, now)


NOW = 1000 * DAY


def test_two_strikes_start_a_probation_dated_by_the_later_one():
    one = step(no_probation(), [(KEY, (A,), NOW - 3 * DAY)])
    assert one == {"strikes": {KEY: [[NOW - 3 * DAY, [A]]]}, "since": {}}
    both = step(one, [(KEY, (B,), NOW - DAY)])
    assert both["since"] == {KEY: NOW - DAY} and len(both["strikes"][KEY]) == 2
    assert step(both, []) == both and step(both, [(KEY, (A,), NOW - 3 * DAY), (KEY, (B,), NOW - DAY)]) == both


def test_strikes_more_than_seven_days_apart_start_none():
    one = step(no_probation(), [(KEY, (A,), NOW - 8 * DAY)])
    assert one == no_probation()  # found too long ago to count
    one = step(no_probation(), [(KEY, (A,), NOW)], NOW)
    later = step(one, [(KEY, (B,), NOW + 7 * DAY)], NOW + 7 * DAY)
    assert later == {"strikes": {KEY: [[NOW + 7 * DAY, [B]]]}, "since": {}}


def test_strikes_are_per_key():
    got = step(no_probation(), [(KEY, (A,), NOW), (KEY2, (B,), NOW)])
    assert got["since"] == {} and set(got["strikes"]) == {KEY, KEY2}


def test_an_alert_found_again_is_the_same_strike_and_keeps_its_first_time():
    one = step(no_probation(), [(KEY, (A, B), NOW - 2 * DAY)])
    again = step(one, [(KEY, (B, C), NOW - DAY)])  # a copy left, another came
    assert again == {"strikes": {KEY: [[NOW - 2 * DAY, [B, C]]]}, "since": {}}
    joined = step(step(no_probation(), [(KEY, (A,), NOW - 2 * DAY), (KEY, (B,), NOW - DAY)]), [(KEY, (A, B), NOW)])
    assert joined["strikes"] == {KEY: [[NOW - 2 * DAY, [A, B]]]}  # the probation they began stands
    assert joined["since"] == {KEY: NOW - DAY}


def test_copies_whose_content_now_differs_are_two_strikes():
    one = step(no_probation(), [(KEY, (A, B), NOW - 2 * DAY)])
    split = step(one, [(KEY, (A,), NOW - 2 * DAY), (KEY, (B,), NOW - 2 * DAY)])
    assert split == {"strikes": {KEY: [[NOW - 2 * DAY, [A]], [NOW - 2 * DAY, [B]]]}, "since": {KEY: NOW - 2 * DAY}}
    # and a copy that joined a recorded strike before its content changed
    joined = step(one, [(KEY, (A, B, C), NOW - DAY)])
    assert joined["strikes"] == {KEY: [[NOW - 2 * DAY, [A, B, C]]]} and joined["since"] == {}
    split = step(joined, [(KEY, (A, B), NOW - DAY), (KEY, (C,), NOW - DAY)])
    assert len(split["strikes"][KEY]) == 2 and split["since"] == {KEY: NOW - 2 * DAY}


def test_a_strike_whose_alert_is_no_longer_found_stands():
    one = step(no_probation(), [(KEY, (A,), NOW - DAY)])
    assert step(one, [(KEY, (B,), NOW)]) == {"strikes": {KEY: [[NOW - DAY, [A]], [NOW, [B]]]}, "since": {KEY: NOW}}


def test_a_probation_that_ran_out_is_left_for_the_lowerings_to_end_and_a_new_one_replaces_it():
    old = {"strikes": {}, "since": {KEY: NOW - cli.PROBATION_S - DAY}}
    assert step(old, []) == old
    got = step(old, [(KEY, (A,), NOW - DAY), (KEY, (B,), NOW)])
    assert got["since"] == {KEY: NOW}


def test_the_two_latest_strikes_are_kept_whatever_number_is_found():
    roots = [f"{i:064x}" for i in range(500)]
    got = step(no_probation(), [(KEY, (r,), NOW - 500 + i) for i, r in enumerate(roots)])
    assert got["strikes"] == {KEY: [[NOW - 2, [roots[498]]], [NOW - 1, [roots[499]]]]} and got["since"] == {KEY: NOW - 1}
    wide = step(no_probation(), [(KEY, tuple(roots), NOW)])
    assert wide["strikes"][KEY][0][1] == roots[:MAX_STRIKE_ROOTS]


def test_a_time_written_while_the_clock_was_ahead_counts_from_now():
    ahead = {"strikes": {KEY: [[NOW + 5 * DAY, [A]], [NOW + 9 * DAY, [B]]]}, "since": {KEY: NOW + 9 * DAY}}
    got = step(ahead, [])
    assert got == {"strikes": {KEY: [[NOW, [A]], [NOW, [B]]]}, "since": {KEY: NOW}}
    st = State(dir=Path("."), probation=ahead)
    assert cli._on_probation(st, KEY, NOW) and not cli._on_probation(st, KEY2, NOW)
    assert not cli._on_probation(State(dir=Path("."), probation={"strikes": {}, "since": {KEY: NOW - cli.PROBATION_S}}), KEY, NOW)


def test_the_windows():
    assert (cli.STRIKE_WINDOW_S, cli.PROBATION_S, pull.UNCHECKED_LOWERING_S) == (7 * DAY, 30 * DAY, 72 * 3600)


# ---------------------------------------------------------------- found by the design review of this change

def test_a_copy_whose_content_is_changed_after_the_strike_is_a_second_alert(feed, monkeypatch, capsys):
    """Posting a fabrication as a copy of a struck one, then changing it, must not keep it
    inside the first strike."""
    m = feed([bot(id=CVE, level="critical"), bot(id=CVE, level="critical")])
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    assert record()["since"] == {} and [len(s[1]) for s in record()["strikes"][m.bot]] == [2]
    second = m.events["feed.json"][1]
    m.post(m.bot_sec, m.patch_text(title="Another invented title"), created_at=T0 + 300, tags=[["e", second["id"], "", "root"]])
    served(m)
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    assert list(record()["since"]) == [m.bot] and [len(s[1]) for s in record()["strikes"][m.bot]] == [1, 1]


def test_a_key_on_probation_cannot_lower_another_relay_bot_key_s_thread_unchecked(feed, monkeypatch, capsys, reader_clock):
    """The reply's signer counts, not only the root's: the manifest may name two relay-bot keys."""
    m = feed([], ALL)
    sec2, bot2 = nostr.keygen()
    m.publish_manifest(posters=[{"pubkey": m.cur, "role": "curator", "name": "cur"},
                                {"pubkey": m.bot, "role": "relay-bot", "name": "bot"},
                                {"pubkey": bot2, "role": "relay-bot", "name": "bot2"}])
    root = m.root_post(m.bot_sec, bot(id=G1, level="critical"), created_at=T0 + 100)  # the first key's own thread
    for i, ident in enumerate((CVE, CVE2)):  # the second key fabricates twice
        m.root_post(sec2, bot(id=ident, level="critical"), created_at=T0 + 110 + i)
    low = m.post(sec2, m.patch_text(level="notice"), created_at=T0 + 300, tags=[["e", root["id"], "", "root"]])
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G1), DOWN))
    assert levels(capsys)[G1] == "critical" and cli.main(["verify"]) == 0
    assert list(record()["since"]) == [bot2]  # the strikes are the second key's: its roots
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys)[G1] == "critical" and State.load().lowerings == {low["id"]: C0 + WAIT}
    serve(m, reader_clock, C0 + WAIT + 5 * DAY)
    assert levels(capsys)[G1] == "critical"


def test_a_probation_another_command_began_holds_an_alert_this_one_was_about_to_report(feed, sent, monkeypatch, capsys):
    """Probation is read again under the lock, before anything is reported: for an alert
    with a new grant and for one that already holds a slot."""
    m = feed([bot(id=G1, level="critical"), bot(id=G2, level="critical")], 'verify = "off"\n')
    cli.main(["pull"])
    stale = State.load()
    a = cli._parser().parse_args(["run", "--json"])
    a.root, a.ignored_env, a.settings = m.root, [], config.load()
    _, pairs = cli._matches(a, stale)
    first, second = (t.root_id for t, _ in pairs)
    stale.interrupts = {m.bot: {first: int(verify.time.time())}}  # one holds its slot already
    stale.save_unverified()
    pending, held, grants, loose = cli._interrupts(a, stale, a.settings, pairs)
    assert (len(pending), len(held), len(grants), loose) == (2, 0, 1, {first, second})
    other = State.load()  # a concurrent command records the key's second strike
    other.probation = {"strikes": {}, "since": {m.bot: int(verify.time.time())}}
    other.save_unverified()
    pending, held = cli._reserve(stale, pending, held, grants, loose)
    assert (pending, len(held)) == ([], 2) and set(State.load().interrupts[m.bot]) == {first}
    assert set(State.load().held) == {first, second}
    status, data = run_json(capsys)
    assert status == 0 and data["unseen_critical"] == [] and len(data["held_critical"]) == 2 and sent["texts"] == []


def test_the_72_hours_start_at_the_first_checkpoint_after_the_probation_however_long_the_machine_was_off(
        feed, monkeypatch, capsys, reader_clock):
    """Both clocks run in one era here, so a checkpoint's time and the probation's end
    compare as they do in use."""
    clock_at(monkeypatch, C0)
    m = feed([bot(id=i, level="critical") for i in (CVE, CVE2, G1)], ALL)
    low = lower(m, m.events["feed.json"][2], "notice")  # an unclaimed thread: the check settles nothing, so it waits
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G1), DOWN))
    assert levels(capsys)[G1] == "critical" and cli.main(["verify"]) == 0 and record()["since"] == {m.bot: C0}

    def level() -> str:  # without a pull
        return {d["id"]: d["level"] for d in json.loads(out_of(capsys, ["check", "--json"])[1])}[G1]
    clock_at(monkeypatch, C0 + 26 * DAY)
    serve(m, reader_clock, C0 + 26 * DAY)
    assert levels(capsys)[G1] == "critical" and State.load().lowerings == {low["id"]: C0 + 26 * DAY}
    clock_at(monkeypatch, C0 + 31 * DAY)  # the machine was off across the end of the probation
    reader_clock.at = C0 + 31 * DAY
    # a command before any pull: the stored checkpoint is the one of day 26, from before the end
    assert level() == "critical" and record()["since"] == {m.bot: C0}
    assert State.load().lowerings == {low["id"]: C0 + 26 * DAY}
    serve(m, reader_clock, C0 + 31 * DAY)
    assert levels(capsys)[G1] == "critical"  # five days of checkpoints since the last command: not a wait
    assert State.load().lowerings == {low["id"]: C0 + 31 * DAY} and record()["since"] == {}
    assert cli.WAITING_LINE.format(id=G1, level="notice") in out_of(capsys, ["check"])[1]
    serve(m, reader_clock, C0 + 31 * DAY + WAIT - 1)
    assert levels(capsys)[G1] == "critical"
    serve(m, reader_clock, C0 + 31 * DAY + WAIT)
    assert levels(capsys)[G1] == "notice"


# ---------------------------------------------------------------- narrowings (found by the review of the plan)

def narrowed(feed, monkeypatch, reader_clock, strikes=2):
    """A relay-bot alert for G1 beside ``strikes`` fabrications, with a narrowing of it that
    this machine cannot check; both clocks in one era."""
    clock_at(monkeypatch, C0)
    m = feed([bot(id=i, level="critical") for i in (CVE, CVE2)[:strikes]] + [bot(id=G1)], ALL)
    reply = narrow(m, m.events["feed.json"][strikes], RIGHT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(verify.KEV_URL, ELSEWHERE).set(gurl(G1), DOWN))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0 and bool(record()["since"]) is (strikes == 2)
    return m, n, reply


def waits(capsys):
    (d,) = [d for d in matches(capsys) if d["id"] == G1]
    return d["narrowing_waits"]


@pytest.mark.parametrize("strikes", [1, 2])
def test_an_unconfirmed_narrowing_of_a_key_on_probation_is_not_applied_and_its_wait_starts_after_it(
        feed, monkeypatch, capsys, reader_clock, strikes):
    m, n, reply = narrowed(feed, monkeypatch, reader_clock, strikes)
    serve(m, reader_clock, C0 + WAIT)
    if strikes == 1:  # no probation: it has stood its 72 hours
        assert fixed(capsys)[G1] == "9.9.9"
        return
    assert fixed(capsys)[G1] == "99.0.0" and State.load().lowerings == {reply["id"]: C0 + WAIT}
    assert waits(capsys) is False and WAITING not in out_of(capsys, ["check"])[1]  # no wait runs, none is announced
    clock_at(monkeypatch, C0 + 26 * DAY)
    serve(m, reader_clock, C0 + 26 * DAY)
    assert fixed(capsys)[G1] == "99.0.0"
    clock_at(monkeypatch, C0 + 31 * DAY)  # the probation is over; the stored checkpoint is from before its end
    reader_clock.at = C0 + 31 * DAY
    assert waits(capsys) is False and record()["since"] == {m.bot: C0}
    serve(m, reader_clock, C0 + 31 * DAY)
    assert fixed(capsys)[G1] == "99.0.0" and record()["since"] == {}
    assert State.load().lowerings == {reply["id"]: C0 + 31 * DAY}
    assert waits(capsys) is True and WAITING in out_of(capsys, ["check"])[1]
    serve(m, reader_clock, C0 + 31 * DAY + WAIT - 1)
    assert fixed(capsys)[G1] == "99.0.0"
    serve(m, reader_clock, C0 + 31 * DAY + WAIT)
    assert fixed(capsys)[G1] == "9.9.9"


def test_a_narrowing_this_machine_confirms_applies_during_probation(feed, monkeypatch, capsys, reader_clock):
    m, n, reply = narrowed(feed, monkeypatch, reader_clock)
    assert fixed(capsys)[G1] == "99.0.0"
    n.set(gurl(G1), ghsa())  # the advisory states the narrowed range
    assert cli.main(["verify"]) == 0 and fixed(capsys)[G1] == "9.9.9" and list(record()["since"]) == [m.bot]
