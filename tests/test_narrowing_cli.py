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


def memory(root, *lists) -> set:
    """What unverified.json remembers of a thread whose lists ``lists`` were refused: each
    list's key and the thread's mark."""
    return {key(root, *entries) for entries in lists} | {pull.narrow_key(root["id"])}


def early_command(m, argv=("check",)):
    """(args, state) of a command that has loaded the state as it is now and done nothing yet."""
    a = cli._parser().parse_args(list(argv))
    a.root, a.ignored_env, a.settings = m.root, [], config.load()
    return a, State.load()


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
    assert State.load().refused == memory(root, [PAST])
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
    assert REFUSED in out_of(capsys, ["verify"])[1] and State.load().refused == memory(root, [SHORT])
    narrow(m, root, RIGHT, at=AT + 10)  # the corrected list: confirmed and applied
    serve(m, reader_clock, C0 + DAY)
    cli.main(["pull"])
    cli.main(["verify"])
    assert fixed(capsys) == {G1: "9.9.9"}
    assert State.load().refused == memory(root, [SHORT])  # confirming another list forgets nothing
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
    assert REFUSED in out_of(capsys, ["run"])[1] and State.load().refused == memory(root, [PAST])
    patched = ghsa()
    patched["vulnerabilities"][0].update(vulnerable_version_range="< 50.0.0", first_patched_version="50.0.0")
    n.set(gurl(G1), patched)
    n.calls.clear()
    assert REFUSED in out_of(capsys, ["run"])[1] and not n.calls  # within the day nothing is read again
    clock_at(monkeypatch, int(time.time()) + verify.RETRY_S + 10)
    serve(m, reader_clock, C0 + 2 * DAY)
    out = out_of(capsys, ["run"])[1]
    assert REFUSED not in out.partition("After the source check:\n")[2]
    assert fixed(capsys) == {G1: "50.0.0"} and State.load().refused == memory(root)  # the list is forgotten, the mark stays


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


GIT = dict(CC, name="git")  # a scope product the advisory of test_verify.ghsa states nothing about


def test_on_a_thread_with_a_refused_list_another_list_waits_only_behind_whole_reads(feed, monkeypatch, capsys, reader_clock):
    """A refused list stops no other list for good, and nobody has to act: the other list
    takes its 72 hours once whole reads do not contradict it. Behind failing reads it does
    not: a thread whose key has sent one contradicted list gets no unchecked narrowing."""
    m = feed([bot(id=G1, products=("Claude Code", "git"))], ALL)
    root = m.events["feed.json"][0]
    narrow(m, root, SHORT, GIT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1]
    other = narrow(m, root, CC, at=AT + 10)  # git left out: no authority states versions for it, so nothing settles it
    began = int(time.time())

    def hourly(at):
        """The checkpoint of ``at`` served, this machine's clock moved with it, and the job's commands."""
        clock_at(monkeypatch, began + at - C0)
        serve(m, reader_clock, at)
        cli.main(["pull"])
        cli.main(["verify"])

    n.set(gurl(G1), OSError("down"))
    for at in (C0 + DAY, C0 + 2 * DAY, C0 + DAY + 2 * WAIT):  # no read succeeds: the wait is held at the newest checkpoint
        hourly(at)
        assert {d["narrowing_waits"] for d in matches(capsys)} == {True}
        assert State.load().lowerings == {other["id"]: at}
    n.set(gurl(G1), ghsa())  # the reads work again, and are made again every day
    back = C0 + DAY + 2 * WAIT + 100
    for at in (back, back + DAY, back + 2 * DAY, back + WAIT - 1):
        hourly(at)
        assert State.load().lowerings == {other["id"]: back} and matches(capsys)[0]["narrowing_waits"] is True
    hourly(back + WAIT)
    (d,) = matches(capsys)
    assert (d["narrowing_waits"], d["narrowing_refused"]) == (False, False)  # applied: neither waiting nor refused
    a, st = early_command(m)
    assert [t.adv.products for t in cli._matches(a, st)[0]] == [[Product(**CC)]]


@pytest.mark.parametrize("again", [[SHORT, SHORT], [dict(SHORT, affected="<1.0"), SHORT], [dict(SHORT, affected="<1.0", fixed="1.0")]],
                         ids=["twice over", "with a respelled copy", "respelled"])
def test_a_refused_list_written_another_way_does_not_apply_behind_failing_reads(feed, monkeypatch, capsys, reader_clock, again):
    m, root = start(feed)
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    assert REFUSED in out_of(capsys, ["verify"])[1]
    narrow(m, root, *again, at=AT + 10)
    (State.load().dir / verify.FILE).unlink()  # the cache is lost and no read succeeds
    n.set(gurl(G1), OSError("down"))
    for at in (C0 + DAY, C0 + DAY + WAIT, C0 + DAY + 5 * WAIT):
        serve(m, reader_clock, at)
        assert fixed(capsys) == {G1: "99.0.0"}
        cli.main(["verify"])
    if again == [SHORT, SHORT]:  # the same entries: the same refusal, said as one
        assert State.load().refused == memory(root, [SHORT]) and REFUSED in out_of(capsys, ["check"])[1]


def test_a_command_that_started_before_a_narrowing_arrived_does_not_drop_its_refusal(feed, monkeypatch, capsys, reader_clock):
    m, root = start(feed)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    a, early = early_command(m)  # it has read the events: no narrowing among them
    a.raw = pull.advisories(early)
    now, listed = pull.head_clock(early)
    early.lowerings = {"ab" * 32: C0}  # and it has a change of its own to write
    narrow(m, root, SHORT)
    serve(m, reader_clock, C0 + 100)
    cli.main(["pull"])
    cli.main(["verify"])  # meanwhile another command pulls the narrowing and its check refuses it
    assert State.load().refused == memory(root, [SHORT])
    cli._note_offers(a, early, now, listed, None)
    assert State.load().refused == memory(root, [SHORT])
    assert [t.narrowed for t in a.raw] == [(Product(**SHORT),)]  # and it goes on with the threads as they are now


def test_a_confirmation_read_before_the_source_changed_does_not_apply_over_a_newer_refusal(feed, monkeypatch, capsys,
                                                                                         reader_clock):
    m, root = start(feed)
    narrow(m, root, RIGHT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    cli.main(["verify"])
    assert fixed(capsys) == {G1: "9.9.9"}
    a, early = early_command(m, ["run", "--json"])  # the hook's command, started while the list was confirmed
    early.lowerings = {}  # with a change of its own to write, so it brings the record up to date under the lock
    a.raw = pull.advisories(early)
    stale = cli._lowering_check(a, early)
    assert stale.narrowing(pull.widest(a.raw[0]), a.raw[0].narrowed) is True
    longer = ghsa()
    longer["vulnerabilities"][0].update(vulnerable_version_range="< 50.0.0", first_patched_version="50.0.0")
    n.set(gurl(G1), longer)
    clock_at(monkeypatch, int(time.time()) + verify.RETRY_S + 10)
    serve(m, reader_clock, C0 + 2 * DAY)
    cli.main(["pull"])
    cli.main(["verify"])  # another command reads the source again: the list is contradicted now
    assert State.load().refused == memory(root, [RIGHT])
    real = cli._lowering_check
    first = [stale]
    monkeypatch.setattr(cli, "_lowering_check", lambda a, st: first.pop() if first else real(a, st))
    threads, pairs = cli._matches(a, early)  # its own check still confirms; the record it brings up to date does not
    assert [(t.adv.products[0].fixed, t.narrow_refused) for t in threads] == [("99.0.0", True)]


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
    assert State.load().refused == memory(root, [SHORT])


def test_a_fixed_version_planted_by_an_earlier_reply_does_not_make_a_wrong_list_read_as_unchanged(
        feed, monkeypatch, capsys, reader_clock):
    """The sources are asked about the widest state, in which an entry with no fixed version
    takes the first one the thread stated. A reply first states one, then publishes the
    list that filled state gives: compared with what the thread shows, it is a change the
    advisory contradicts. Found by the same-model review of this change."""
    from dataclasses import replace
    bare = dict(CC, affected=">=2.0.0,<99.0.0", fixed=None)
    planted = dict(CC, affected="<1.0.0", fixed="1.0.0")
    m = feed([replace(bot(id=G1), products=[Product(**bare)])], ALL)
    root = m.events["feed.json"][0]
    narrow(m, root, planted)
    narrow(m, root, dict(bare, fixed="1.0.0"), planted, at=AT + 10)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    _, out, _ = out_of(capsys, ["run"])
    assert REFUSED in out and "0 matches on this machine" not in out
    assert "1 narrowings asked about: 0 confirmed, 1 contradicted" in out_of(capsys, ["verify"])[1]
    serve(m, reader_clock, C0 + 30 * DAY)
    assert fixed(capsys) == {G1: None}  # the installed 2.0.0 still matches the entry the root posted


def test_a_save_that_fails_under_the_lock_does_not_put_the_older_record_beside_the_newer_threads(
        feed, monkeypatch, capsys, reader_clock):
    """An older command holds a wait that has run out. Another command refuses the list. The
    older one refreshes under the lock, cannot save, and must still go by the refusal.
    Found by the delta review of this change."""
    m, root = start(feed)
    reply = narrow(m, root, SHORT)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(gurl(G1), OSError("down")))
    cli.main(["pull"])
    a, early = early_command(m)
    a.raw = pull.advisories(early)
    # its own record: the 72 hours are over; and an entry to drop, so it has a change to write
    early.lowerings = {reply["id"]: C0 - WAIT, "ab" * 32: C0}
    n.set(gurl(G1), ghsa())
    cli.main(["verify"])  # meanwhile another command reads the source: the list is refused
    assert State.load().refused == memory(root, [SHORT])
    (State.load().dir / verify.FILE).unlink()  # and the results are lost, so no check says False again

    def full(self):
        raise OSError("disk full")
    monkeypatch.setattr(State, "save_unverified", full)
    threads, _ = cli._matches(a, early)
    assert [(t.adv.products[0].fixed, t.narrow_refused) for t in threads] == [("99.0.0", True)]
    assert early.refused == memory(root, [SHORT])
