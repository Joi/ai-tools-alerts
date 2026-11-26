"""A relay-bot narrowing through the CLI (ai-tools-alerts#swfe): the acceptance cases of the
issue, the 72 hours of a narrowing nobody can check, and the memory of a refused list."""

import json
import time

import pytest

from aitools_alerts import cli, config, inventory, pull, verify
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.schema import Product
from aitools_alerts.state import State
from mirror_helpers import T0
from test_curator_hold_cli import ALL, AT, CC, DAY, levels, serve
from test_unverified_cli import C0, WAIT, clock_at, lower, refusal
from test_verify import G1, Net, ghsa, gurl
from test_verify_cli import bot, env, feed, out_of, use  # noqa: F401 - env and feed are fixtures

OFF = 'verify = "off"\n'
RIGHT = dict(CC, affected="<9.9.9", fixed="9.9.9")  # what the advisory of test_verify.ghsa states
PAST = dict(CC, affected="<50.0.0", fixed="50.0.0")  # fixed raised past it; still narrower than the thread's
SHORT = dict(CC, affected="<1.0.0", fixed="1.0.0")
REFUSED = cli.NARROW_REFUSED_LINE.format(id=G1)
WAITING = cli.NARROW_WAITING_LINE.format(id=G1)


def narrow(m, root, *entries, at=AT):
    return m.post(m.bot_sec, m.patch_text(products=list(entries)), created_at=at, tags=[["e", root["id"], "", "root"]])


def matches(capsys) -> list:
    return json.loads(out_of(capsys, ["check", "--json"])[1])


def fixed(capsys) -> dict:
    """{advisory id: the fixed version of the entry this machine matches}, after a pull."""
    assert cli.main(["pull"]) == 0
    return {d["id"]: d["product"]["fixed"] for d in matches(capsys)}


def key(root, *entries) -> str:
    return pull.narrow_key(root["id"], [Product(**e) for e in entries])


def start(feed, extra=ALL, **kw):
    m = feed([bot(id=G1)], extra, **kw)
    return m, m.events["feed.json"][0]


# ---------------------------------------------------------------- acceptance 1: fixed raised past the advisory

def test_a_reply_that_raises_fixed_past_the_advisory_is_refused_and_flagged(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, PAST)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    assert fixed(capsys) == {G1: "99.0.0"}
    assert REFUSED in out_of(capsys, ["verify"])[1]
    assert "1 narrowings asked about: 0 confirmed, 1 contradicted, 0 not settled" in out_of(capsys, ["verify"])[1]
    serve(m, reader_clock, C0 + 30 * DAY)  # and no wait ever applies it
    assert fixed(capsys) == {G1: "99.0.0"} and REFUSED in out_of(capsys, ["check"])[1]
    (d,) = matches(capsys)
    assert (d["narrowing_refused"], d["narrowing_waits"], d["product"]["affected"]) == (True, False, "<99.0.0")
    assert State.load().refused == {key(root, PAST)}
    assert REFUSED in out_of(capsys, ["run"])[1]


def test_a_correct_entry_carries_no_wrong_one_through(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, RIGHT, PAST)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1]
    assert {d["product"]["fixed"] for d in matches(capsys)} == {"99.0.0"}


def test_an_entry_moved_to_another_ecosystem_is_refused(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, dict(RIGHT, ecosystem="codex"))
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1]
    serve(m, reader_clock, C0 + 30 * DAY)
    assert fixed(capsys) == {G1: "99.0.0"}  # this machine's Claude Code still matches


# ---------------------------------------------------------------- acceptance 2: it matches the advisory

def test_a_reply_that_matches_the_advisory_applies_in_the_run_that_reads_the_source(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, RIGHT)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    assert fixed(capsys) == {G1: "99.0.0"}  # before any source is read
    _, out, _ = out_of(capsys, ["run"])
    first, _, after = out.partition("After the source check:\n")
    assert WAITING in first and "HIGH: " in after  # listed again: what stood above no longer stands
    # the state the narrowing leaves was read in the same run: nothing is "not verified" after it
    assert "is not applied" not in after and "not verified" not in after
    (d,) = matches(capsys)
    assert (d["product"]["affected"], d["product"]["fixed"]) == ("<9.9.9", "9.9.9")
    assert (d["narrowing_refused"], d["narrowing_waits"], d["level"]) == (False, False, "high")
    assert "1 narrowings asked about: 1 confirmed" in out_of(capsys, ["verify"])[1]
    assert State.load().refused == set()


def test_run_shows_that_a_confirmed_narrowing_ended_this_machine_s_match(feed, monkeypatch, capsys, reader_clock):
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "10.0.0", "/invented/bin/claude")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    m, root = start(feed)
    narrow(m, root, RIGHT)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    _, out, _ = out_of(capsys, ["run"])
    first, _, after = out.partition("After the source check:\n")
    assert "1 matches on this machine" in first and "0 matches on this machine" in after
    assert matches(capsys) == []


def test_a_confirmation_that_goes_stale_and_cannot_be_read_again_falls_back_to_the_wait(feed, monkeypatch, capsys,
                                                                                       reader_clock):
    m, root = start(feed)
    reply = narrow(m, root, RIGHT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    cli.main(["verify"])
    assert fixed(capsys) == {G1: "9.9.9"} and State.load().lowerings == {reply["id"]: C0}
    n.set(gurl(G1), OSError("down"))
    monkeypatch.setattr(verify, "FRESH_S", -1)  # the confirmation is too old to count
    assert fixed(capsys) == {G1: "99.0.0"}
    serve(m, reader_clock, C0 + WAIT)  # the reply has stood 72 hours since its first checkpoint
    assert fixed(capsys) == {G1: "9.9.9"}


# ---------------------------------------------------------------- acceptance 3: the member cannot read

@pytest.mark.parametrize("extra", [ALL, OFF])
@pytest.mark.parametrize("dated", [AT, T0 + 150])  # T0 + 150: backdated to just after the root
def test_with_the_fetch_failing_the_narrowing_applies_after_72_hours(feed, monkeypatch, capsys, reader_clock, extra, dated):
    m, root = start(feed, extra)
    reply = narrow(m, root, RIGHT, at=dated)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), OSError("down")))
    assert fixed(capsys) == {G1: "99.0.0"}
    assert State.load().lowerings == {reply["id"]: C0}  # the checkpoint's time, not the reply's and not this clock's
    out = out_of(capsys, ["run"])[1]
    assert WAITING in out and "After the source check:" not in out  # nothing changed: listed once
    (d,) = matches(capsys)
    assert (d["narrowing_refused"], d["narrowing_waits"]) == (False, True)
    serve(m, reader_clock, C0 + WAIT - 1)
    cli.main(["verify"])
    assert fixed(capsys) == {G1: "99.0.0"}
    serve(m, reader_clock, C0 + WAIT)
    assert fixed(capsys) == {G1: "9.9.9"}
    out = out_of(capsys, ["check"])[1]
    assert WAITING not in out and REFUSED not in out
    assert bool(n.calls) is (extra == ALL)


def test_a_frozen_mirror_never_lets_the_wait_run_out(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed, OFF)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    assert fixed(capsys) == {G1: "99.0.0"}
    reader_clock.at = C0 + 30 * DAY  # this machine's clock moves; the mirror serves the same checkpoint
    cli.main(["pull"])
    assert {d["product"]["fixed"] for d in matches(capsys)} == {"99.0.0"}


@pytest.mark.parametrize("kw", [{"min_cli": "99.0.0"}, {"ruleset_pin": "stale"}])
def test_a_cli_out_of_date_applies_no_narrowing_unchecked(feed, monkeypatch, capsys, reader_clock, kw):
    from aitools_alerts import ruleset
    if "ruleset_pin" in kw:
        kw = {"ruleset_pin": ruleset.Pin(ruleset.load().version, "0" * 64, 1)}
    m, root = start(feed, **kw)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    assert fixed(capsys) == {G1: "99.0.0"}
    serve(m, reader_clock, C0 + WAIT)
    assert fixed(capsys) == {G1: "99.0.0"}


def test_the_hook_s_command_reads_no_source_for_a_narrowing(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, RIGHT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    (d,) = json.loads(out_of(capsys, ["run", "--json"])[1])["matches"]
    assert not n.calls and (d["product"]["fixed"], d["narrowing_waits"]) == ("99.0.0", True)


# ---------------------------------------------------------------- a refused list is remembered by what it says

def test_a_refused_list_sent_again_after_another_was_confirmed_and_the_cache_was_lost_is_still_refused(
        feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1] and State.load().refused == {key(root, SHORT)}
    narrow(m, root, RIGHT, at=AT + 10)  # the corrected list: confirmed and applied
    serve(m, reader_clock, C0 + DAY)
    cli.main(["pull"])
    cli.main(["verify"])
    assert fixed(capsys) == {G1: "9.9.9"}
    assert State.load().refused == {key(root, SHORT)}  # confirming another list forgets nothing
    again = narrow(m, root, SHORT, at=AT + 20)  # the refused list, in a new reply
    (State.load().dir / verify.FILE).unlink()
    n.set(gurl(G1), OSError("down"))
    serve(m, reader_clock, C0 + 2 * DAY)
    assert fixed(capsys) == {G1: "99.0.0"}
    out = out_of(capsys, ["verify"])[1]
    assert REFUSED in out and "1 narrowings asked about: 0 confirmed, 1 contradicted" in out
    serve(m, reader_clock, C0 + 2 * DAY + 3 * WAIT)
    assert fixed(capsys) == {G1: "99.0.0"} and REFUSED in out_of(capsys, ["check"])[1]
    (d,) = matches(capsys)
    assert (d["narrowing_refused"], d["narrowing_waits"]) == (True, False)
    assert json.loads(out_of(capsys, ["run", "--json"])[1])["matches"][0]["product"]["fixed"] == "99.0.0"  # the hook
    # the wait is held at the newest checkpoint while the refusal stands
    assert State.load().lowerings == {again["id"]: C0 + 2 * DAY + 3 * WAIT}


def test_the_source_coming_to_state_a_refused_list_ends_its_refusal_with_nobody_acting(feed, monkeypatch, capsys,
                                                                                      reader_clock):
    """The same list, the same reply, the same cache: only the source changes, and the
    hourly job's own command applies the list at its daily re-read."""
    m, root = start(feed)
    narrow(m, root, PAST)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    assert REFUSED in out_of(capsys, ["run"])[1] and State.load().refused == {key(root, PAST)}
    patched = ghsa()
    patched["vulnerabilities"][0].update(vulnerable_version_range="< 50.0.0", first_patched_version="50.0.0")
    n.set(gurl(G1), patched)
    n.calls.clear()
    assert REFUSED in out_of(capsys, ["run"])[1] and not n.calls  # within the day nothing is read again
    clock_at(monkeypatch, int(time.time()) + verify.RETRY_S + 10)
    serve(m, reader_clock, C0 + 2 * DAY)
    out = out_of(capsys, ["run"])[1]
    assert REFUSED not in out.partition("After the source check:\n")[2]
    assert fixed(capsys) == {G1: "50.0.0"} and State.load().refused == set()


def test_a_remembered_refusal_is_said_with_the_check_turned_off(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1]
    path = config.config_path()
    path.write_text(path.read_text().replace(ALL, OFF))
    serve(m, reader_clock, C0 + 30 * DAY)
    assert fixed(capsys) == {G1: "99.0.0"}  # off settles nothing, and the refusal this machine made stands
    assert REFUSED in out_of(capsys, ["check"])[1] and REFUSED in out_of(capsys, ["run"])[1]


def test_a_refused_list_does_not_stop_another_list_of_the_thread(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1]
    other = narrow(m, root, RIGHT, at=AT + 10)
    n.set(gurl(G1), OSError("down"))
    monkeypatch.setattr(verify, "FRESH_S", -1)  # nothing this machine read earlier counts as fresh
    serve(m, reader_clock, C0 + DAY)
    assert fixed(capsys) == {G1: "99.0.0"} and State.load().lowerings == {other["id"]: C0 + DAY}
    assert WAITING in out_of(capsys, ["check"])[1]
    serve(m, reader_clock, C0 + DAY + WAIT)
    assert fixed(capsys) == {G1: "9.9.9"}  # nobody had to act


def test_a_refused_lowering_and_a_narrowing_do_not_stop_each_other(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    lower(m, root, "notice")
    reply = narrow(m, root, RIGHT, at=AT + 10)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))  # high: the lowering is contradicted, the narrowing confirmed
    cli.main(["pull"])
    out = out_of(capsys, ["verify"])[1]
    assert refusal(G1, "notice", "high") in out and REFUSED not in out
    (d,) = matches(capsys)
    assert (d["level"], d["lowering_refused"], d["product"]["fixed"], d["narrowing_refused"]) == ("high", "notice", "9.9.9", False)
    assert State.load().refused == {root["id"]} and reply["id"] in State.load().lowerings


def test_a_refused_narrowing_does_not_stop_the_lowering_s_wait(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1]
    lower(m, root, "notice", at=AT + 10)
    n.set(gurl(G1), OSError("down"))
    serve(m, reader_clock, C0 + DAY)
    assert levels(capsys) == {G1: "high"}
    serve(m, reader_clock, C0 + DAY + WAIT)
    assert levels(capsys) == {G1: "notice"} and fixed(capsys) == {G1: "99.0.0"}


def test_the_memory_of_a_list_goes_with_its_thread(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    cli.main(["verify"])
    st = State.load()
    st.refused |= {"ab" * 32}  # a list no stored thread has published
    st.save_unverified()
    cli.main(["check"])
    assert State.load().refused == {key(root, SHORT)}
