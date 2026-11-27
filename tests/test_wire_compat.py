"""The released readers against a feed in the self-correcting format (ai-tools-alerts#t8jr,
finding D12 of the design review on ai-tools-alerts#h29n).

Each released reader is unpacked from its tag and run as a member would run it. The
feed carries what the new format adds: a claim tag on roots and replies, a relay-bot
lowering in a reply of its own, a raise after it in a reply of its own, and ``min_cli``
and the ruleset pin (ai-tools-alerts#ed7n) in the checkpoint key certificate. Every alert must still be active there, now and a
month on, at the level this reader shows or a higher one, and must still match the
installation it matches here.

When a later slice adds something signed to the feed, add it to ``feed`` here first.
"""

import json
import subprocess
from dataclasses import asdict
from pathlib import Path

import pytest

from aitools_alerts import check, nostr, pull, ruleset, schema, wire
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.poster import compose, rules, transport
from aitools_alerts.schema import Action, Product
from aitools_alerts.state import State
from mirror_helpers import CHANNELS, advisory, mirror_now, released_reader

RELEASED = ("v0.1.4", "v0.1.5", "v0.1.6", "v0.1.7")
CLAIM_READERS = ("v0.1.8", "v0.2.0", "v0.2.1", "v0.3.0")  # they compute expiry from the claim tag (r0ra)
REPO = Path(__file__).resolve().parents[1]
MONTH = 30 * 86400
# What a member is shown: the active threads at a given time, and which of them match
# an installed Claude Code 2.0.0. Written against the modules as v0.1.4 has them.
DUMP = """
import json
from aitools_alerts import check, pull
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.state import State
INV = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/claude")],
                          "mcp": [Installed("mcp-server-git", None, "/invented/.claude.json")]})
out = {}
for at in (int(sys.argv[2]), int(sys.argv[2]) + %d):
    ts = pull.active(pull.advisories(State.load()), at)
    hit = {m.adv.id for m in check.match([t.adv for t in ts], INV)}
    out[str(at)] = {t.adv.id: [t.adv.level, sorted(p.fixed or "" for p in t.adv.products), t.adv.id in hit]
                    for t in ts}
print(json.dumps(out))
""" % MONTH
INV = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/claude")],
                          "mcp": [Installed("mcp-server-git", None, "/invented/.claude.json")]})
FIX = [Product("Claude Code", "claude-code", "<99.1.0", "99.1.0")]


def claim(adv_id, level, at):
    """A claim the reader takes as a renewal (the test ids have the shape of OSV ids)."""
    return wire.claim_tag({"id": adv_id, "source": "osv", "ruleset": 1, "level": level, "confirmed_at": at,
                           "checked_at": at, "fields": {"osv_id": adv_id, "withdrawn": None, "packages": []}})


def with_block_key(text: str, **extra) -> str:
    """A post whose aitools-alert block carries keys the schema does not know."""
    block = schema._last_block(text)
    return text.replace(block, json.dumps({**json.loads(block), **extra}))


def feed():
    """(mirror, clock). Threads: 0001 a bot critical with a claim; 0002 a bot high raised
    to critical with a fix, in one reply with a claim (no lowering came before: readers
    agree on the level, so the raise may share a reply); 0003 a bot critical, then a
    lowering to notice in a reply of its own, then a raise to high in a reply of its
    own (a lowering, to a reader that kept critical), then a fix in another; 0004 a
    curator critical; 0005 a bot critical whose block carries a new key, which is what
    the format must never do; 0006 a bot high for an MCP server, named by its package
    as the scope file's entry names it (wa6n), which a member with that server
    configured is told about. Every relay-bot root has ``expires_at`` null; no reply
    names it. The certificate names ``min_cli`` and pins this reader's own ruleset, so
    this reader is not out of date and computes expiry as usual."""
    rs = ruleset.load()
    m, now = mirror_now(min_cli="99.0.0", ruleset_pin=ruleset.Pin(version=rs.version, sha256=rs.digest, min_version=1))
    t = now - 3600
    bot = lambda n, **kw: advisory(id=f"AITA-TEST-000{n}", posted_by="relay-bot", **kw)  # noqa: E731
    reply = lambda root, text, at, *tags: m.post(  # noqa: E731
        m.bot_sec, text, created_at=at, tags=[["e", root["id"], "", "root"], *tags])
    m.root_post(m.bot_sec, bot(1), created_at=t, tags=[claim("AITA-TEST-0001", "critical", t)])
    r2 = m.root_post(m.bot_sec, bot(2, level="high"), created_at=t, files=("feed.json",),
                     tags=[claim("AITA-TEST-0002", "high", t)])
    reply(r2, m.patch_text(level="critical", products=[asdict(p) for p in FIX]), t + 100,
          claim("AITA-TEST-0002", "critical", t + 100))
    r3 = m.root_post(m.bot_sec, bot(3), created_at=t, tags=[claim("AITA-TEST-0003", "critical", t)])
    reply(r3, compose.level_post(bot(3), "notice"), t + 200, claim("AITA-TEST-0003", "notice", t + 200))
    reply(r3, compose.level_post(bot(3, level="notice"), "high"), t + 250, claim("AITA-TEST-0003", "high", t + 250))
    reply(r3, m.patch_text(products=[asdict(p) for p in FIX]), t + 300, claim("AITA-TEST-0003", "high", t + 300))
    m.root_post(m.cur_sec, advisory(id="AITA-TEST-0004"), created_at=t)
    m.post(m.bot_sec, with_block_key(schema.render_post(bot(5), "Body line."), rule_version=1), created_at=t)
    mcp = rules.scope_of("pypi:mcp-server-git")  # the product compose.root_post names: the entry's name and ecosystem
    m.root_post(m.bot_sec, bot(6, level="high", products=[Product(mcp.name, mcp.ecosystem, "<2026.11.18", "2026.11.18")],
                               actions=[Action("upgrade", mcp.name, "2026.11.18")]),
                created_at=t, tags=[claim("AITA-TEST-0006", "high", t)])
    return m, now


def shown(threads, at) -> dict:
    """DUMP's view, of this reader's threads."""
    ts = pull.active(threads, at)
    hit = {m.adv.id for m in check.match([t.adv for t in ts], INV)}
    return {t.adv.id: [t.adv.level, sorted(p.fixed or "" for p in t.adv.products), t.adv.id in hit] for t in ts}


def this_reader(m, now, tmp_path) -> dict:
    """What this reader shows, at ``now`` and a month on, keyed as DUMP keys it."""
    st = State.load(tmp_path / "this-reader")
    res = pull.fetch("https://mirror.example.invalid/", st, fetch=m.fetch, root_pubkey=m.root, now=now)
    assert res.error is None, res.error
    assert pull.head_clock(st)[0] is not None  # a head is held: expiry is judged, as the CLI judges it
    return {str(at): shown(pull.advisories(st), at) for at in (now, now + MONTH)}


def released(tmp_path, tag, m, now) -> dict:
    """What the released reader ``tag`` shows after pulling ``m``, as DUMP prints it."""
    (tmp_path / "mirror").mkdir(exist_ok=True)
    run = released_reader(tmp_path, tag=tag)
    got = run("pull", "--mirror-url", m.write(tmp_path / "mirror"), root=m.root)
    assert got.returncode == 0 and "Traceback" not in got.stderr, (got.stdout, got.stderr)
    if tuple(map(int, tag[1:].split("."))) >= (0, 1, 6):  # a checked pull: the certificate, min_cli, pin and all, was accepted
        assert "; checkpoint " in got.stdout and " lists " in got.stdout and "unverified" not in got.stderr, got
    out = run.py(DUMP, str(now), root=m.root)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.parametrize("tag", RELEASED)
def test_every_alert_still_appears_on_a_released_reader_at_the_same_or_a_higher_level(tmp_path, tag):
    m, now = feed()
    mine, theirs = this_reader(m, now, tmp_path), released(tmp_path, tag, m, now)
    for at in (str(now), str(now + MONTH)):
        assert sorted(mine[at]) == [f"AITA-TEST-000{n}" for n in (1, 2, 3, 4, 6)]
        assert sorted(theirs[at]) == sorted(mine[at])  # every alert; the one with a new block key on neither
        for adv_id, (level, fixed, matched) in mine[at].items():
            assert pull._RANK[theirs[at][adv_id][0]] >= pull._RANK[level], (adv_id, theirs[at][adv_id])
            assert matched and theirs[at][adv_id][2], adv_id  # the member with the tool installed is told
        # Level changes in replies of their own cost nothing else: the level stays, the fix arrives.
        assert theirs[at]["AITA-TEST-0003"] == ["critical", ["99.1.0"], True]
        assert theirs[at]["AITA-TEST-0002"] == ["critical", ["99.1.0"], True]  # a raise applies, claim tag and all
    assert mine[str(now)]["AITA-TEST-0003"] == ["critical", ["99.1.0"], True]
    # The four relay-bot threads carry claims this reader takes (r0ra): with no renewal, a month
    # on (as under a head issued then) they have decayed to notice here; the curator's has not.
    # A released reader computes no expiry and still shows critical: the same or higher.
    st = State.load(tmp_path / "this-reader")
    assert sorted(t.adv.id for t in pull.advisories(st) if t.enrolled_at is not None) == [f"AITA-TEST-000{n}" for n in (1, 2, 3, 6)]
    assert {i: v[0] for i, v in mine[str(now + MONTH)].items()} == {
        "AITA-TEST-0001": "notice", "AITA-TEST-0002": "notice", "AITA-TEST-0003": "notice", "AITA-TEST-0004": "critical",
        "AITA-TEST-0006": "notice"}
    assert mine[str(now + MONTH)]["AITA-TEST-0003"][1] == ["99.1.0"]


@pytest.mark.parametrize("tag", ("v0.1.4", "v0.1.6"))
@pytest.mark.parametrize("mixed", ["a lowering with a fix", "a raise with a fix, after a lowering"])
def test_what_the_format_avoids_a_level_change_mixed_with_a_fix_loses_the_fix(tmp_path, mixed, tag):
    """The control for "a level change travels alone": a reply that lowers and fixes is
    skipped whole by readers before 0.1.7, so the member never learns the fixed version.
    After a lowering such a reader still holds critical, so a raise from notice to high
    is a lowering to it, and a fix in that reply is lost the same way."""
    m, now = mirror_now()
    root = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), created_at=now - 3600)
    reply = lambda text, at: m.post(m.bot_sec, text, created_at=at, tags=[["e", root["id"], "", "root"]])  # noqa: E731
    fix = [asdict(p) for p in FIX]
    if mixed == "a lowering with a fix":
        reply(m.patch_text(level="notice", products=fix), now - 3000)
    else:
        reply(compose.level_post(advisory(posted_by="relay-bot"), "notice"), now - 3000)
        reply(m.patch_text(level="high", products=fix), now - 2000)
    assert released(tmp_path, tag, m, now)[str(now)] == {"AITA-TEST-0001": ["critical", ["99.0.0"], True]}


@pytest.mark.parametrize("tag", RELEASED)
def test_what_the_format_avoids_an_expiry_in_a_relay_bot_block_ends_the_alert(tmp_path, tag):
    """Why a relay-bot block sets no expiry (null in a root, absent in a reply): every released reader stops
    showing the alert at that time, and none of them takes a renewal from the relay
    bot. This reader does not read a relay-bot block's expiry at all
    (ai-tools-alerts#r0ra): it computes expiry from the claim, outside the block, so
    it goes on showing the alert."""
    m, now = mirror_now()
    week = 7 * 86400
    adv = advisory(posted_by="relay-bot", posted_at=now - 3600, expires_at=now + week)
    root = m.root_post(m.bot_sec, adv, created_at=now - 3600)
    m.post(m.bot_sec, m.patch_text(expires_at=now + 9 * week), created_at=now - 3000,
           tags=[["e", root["id"], "", "root"]])  # the renewal
    theirs, mine = released(tmp_path, tag, m, now), this_reader(m, now, tmp_path)
    live = {"AITA-TEST-0001": ["critical", ["99.0.0"], True]}
    assert theirs[str(now)] == live and mine[str(now)] == live
    assert theirs[str(now + MONTH)] == {}  # gone, renewal or not
    assert mine[str(now + MONTH)] == live


@pytest.mark.parametrize("tag", ("v0.1.4", "v0.1.7"))
def test_what_the_format_avoids_a_new_manifest_key_fails_the_released_pull(tmp_path, tag):
    """Why min_cli is in the certificate: a manifest with one more content key is no
    manifest to a released reader, or to this one."""
    m, now = mirror_now()
    m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), created_at=now - 3600)
    content = {**json.loads(m.manifest["content"]), "min_cli": "99.0.0"}
    m.raw["manifest.json"] = json.dumps(nostr.sign_event(m.root_sec, {
        "created_at": m.manifest["created_at"], "kind": 30078, "tags": m.manifest["tags"],
        "content": json.dumps(content)})).encode()
    (tmp_path / "mirror").mkdir()
    got = released_reader(tmp_path, tag=tag)("pull", "--mirror-url", m.write(tmp_path / "mirror"), root=m.root)
    assert got.returncode == 1 and "bad manifest" in got.stderr, (got.stdout, got.stderr)
    st = State.load(tmp_path / "this-reader")
    assert pull.fetch("https://mirror.example.invalid/", st, fetch=m.fetch, root_pubkey=m.root,
                      now=now).error == "bad manifest"


@pytest.mark.parametrize("tag", ("v0.1.6", "v0.1.7", "v0.1.8"))
def test_a_pin_of_a_later_ruleset_does_not_disturb_a_released_reader(tmp_path, tag):
    """The ruleset pin is in the certificate (ai-tools-alerts#ed7n). The root pins a
    ruleset no reader here has: the released readers that read the certificate ignore
    the key, pull checked and show exactly what they show with no pin; this reader
    reads the pin, says it is out of date, and still shows the alert at its level."""
    def one(pin):
        m, now = mirror_now(ruleset_pin=pin)
        m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), created_at=now - 3600,
                    tags=[claim("AITA-TEST-0001", "critical", now - 3600)])
        return m, now
    m, now = one(ruleset.Pin(version=99, sha256="0" * 64, min_version=99))
    live = {"AITA-TEST-0001": ["critical", ["99.0.0"], True]}
    (tmp_path / "pin").mkdir()
    (tmp_path / "plain").mkdir()
    theirs = released(tmp_path / "pin", tag, m, now)  # asserts the pull was a checked one
    plain = released(tmp_path / "plain", tag, *one(None))
    assert theirs[str(now)] == live and list(theirs.values()) == list(plain.values())  # the pin changes nothing there
    if tag != "v0.1.8":  # 0.1.8 computes expiry with its own table; the earlier two compute none
        assert theirs[str(now + MONTH)] == live
    st = State.load(tmp_path / "this-reader")
    assert pull.fetch("https://mirror.example.invalid/", st, fetch=m.fetch, root_pubkey=m.root, now=now).error is None
    pin = st.cert_for(m.root).ruleset
    assert (pin.version, pin.min_version) == (99, 99) and ruleset.outdated(pin)
    threads, head = pull.advisories(st), pull.head_clock(st)
    assert shown(threads, now) == live
    # a month on, under a head issued then: decayed by this reader's own table, kept when it judges nothing
    assert shown(threads, now + MONTH) == {"AITA-TEST-0001": ["notice", ["99.0.0"], True]}
    kept = pull.active(threads, now + MONTH, head[1], decay=False)
    assert [(t.adv.id, t.adv.level) for t in kept] == [("AITA-TEST-0001", "critical")]


def test_the_alert_block_schema_is_the_released_one(tmp_path):
    """The block does not change in the self-correcting slices: the schema file is the
    v0.1.4 file byte for byte, and the dataclasses the block is read into have its fields."""
    old = subprocess.run(["git", "-C", str(REPO), "show", "v0.1.4:spec/advisory.schema.json"], capture_output=True)
    if old.returncode != 0:
        pytest.fail("tag v0.1.4 is not in this clone (git fetch --tags): the schema check cannot run")
    assert old.stdout == (REPO / "spec" / "advisory.schema.json").read_bytes()
    names = ("Advisory", "Product", "Action", "Source")
    out = released_reader(tmp_path).py(
        "from aitools_alerts import schema\nimport dataclasses, json\n"
        f"print(json.dumps({{n: [f.name for f in dataclasses.fields(getattr(schema, n))] for n in {names!r}}}))")
    assert out.returncode == 0, out.stderr
    import dataclasses
    assert json.loads(out.stdout) == {n: [f.name for f in dataclasses.fields(getattr(schema, n))] for n in names}


@pytest.mark.parametrize("tag", ("v0.1.4", "v0.1.7"))
def test_the_exception_a_curator_s_lowering_of_a_bot_thread_lasts_for_good_on_a_released_reader(tmp_path, tag):
    """The one place a released reader may show less than this one (ai-tools-alerts#c1g2,
    spec/wire.md). A curator's lowering of a relay-bot thread is final to a released
    reader. Here it holds 14 days and then the thread's widest state shows again, unless
    the member's own source check confirms the lowering. No wire format differs: the
    released reader reads the same events."""
    m, now = mirror_now()
    root = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), created_at=now - 3600)
    m.post(m.cur_sec, "level: notice", created_at=now - 3000, tags=[["e", root["id"], "", "root"]])
    mine, theirs = this_reader(m, now, tmp_path), released(tmp_path, tag, m, now)
    level = lambda got, at: got[str(at)]["AITA-TEST-0001"][0]  # noqa: E731
    assert (level(theirs, now), level(theirs, now + MONTH)) == ("notice", "notice")
    assert (level(mine, now), level(mine, now + MONTH)) == ("notice", "critical")


NARROWER = [asdict(Product("Claude Code", "claude-code", "<1.0.0", "1.0.0"))]  # the installed 2.0.0 is outside it


def narrowed_feed():
    """A relay-bot critical, then a relay-bot reply whose products are narrower (ai-tools-alerts#swfe)."""
    m, now = mirror_now()
    root = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), created_at=now - 3600)
    reply = m.post(m.bot_sec, m.patch_text(products=NARROWER), created_at=now - 3000, tags=[["e", root["id"], "", "root"]])
    return m, now, reply


@pytest.mark.parametrize("tag", ("v0.1.7", "v0.1.8", "v0.2.0", "v0.2.1"))
def test_a_relay_bot_narrowing_leaves_the_wider_entry_on_a_released_reader(tmp_path, tag):
    """The narrowing travels in the block, as the poster has always sent it. A reader from
    0.1.7 on joins the list, so it keeps the wider entry and the member is still told.
    This reader shows the same until its own source check confirms the narrowing or the
    reply has stood 72 hours in checkpoints: never less than a released reader before then."""
    m, now, reply = narrowed_feed()
    wide = {"AITA-TEST-0001": ["critical", ["99.0.0"], True]}
    assert released(tmp_path, tag, m, now)[str(now)] == wide
    assert this_reader(m, now, tmp_path)[str(now)] == wide
    st = State.load(tmp_path / "this-reader")
    (t,) = pull.advisories(st)
    assert t.narrowed_by == reply["id"] and [asdict(p) for p in t.narrowed] == NARROWER
    at, listed = pull.head_clock(st)
    since = pull.offers([t], {}, at, listed)
    assert since == {reply["id"]: at}
    assert shown([t], at + pull.UNCHECKED_LOWERING_S - 1) == wide  # no record given: nothing applies
    (later,) = pull.active([t], at + pull.UNCHECKED_LOWERING_S, None, None, since=since)
    assert [asdict(p) for p in later.adv.products] == NARROWER  # here, after the 72 hours, and on no released reader


@pytest.mark.parametrize("tag", ("v0.1.4", "v0.1.6"))
def test_what_the_format_does_not_avoid_a_reader_before_0_1_7_applies_a_narrowing_whole(tmp_path, tag):
    """Why 0.1.7 joined (ai-tools-alerts#tyje): these readers take any relay-bot products
    list whole, at once and unchecked, and nothing on the feed reaches them to say so."""
    m, now, _ = narrowed_feed()
    assert released(tmp_path, tag, m, now)[str(now)] == {"AITA-TEST-0001": ["critical", ["1.0.0"], False]}


@pytest.mark.parametrize("tag", RELEASED + CLAIM_READERS)
def test_a_relay_bot_withdrawal_is_refused_by_every_released_reader(tmp_path, tag):
    """The withdrawal (ai-tools-alerts#y484) is a reply whose block is exactly
    ``{"level":"withdrawn"}``. The word is no level to any released reader: the reply is
    refused and the alert stays at its level, matched as before. This reader shows the
    same until its own source check confirms the withdrawal, and then shows the thread
    nowhere; unchecked it is a lowering to notice after 72 hours, never a hiding."""
    m, now = mirror_now()
    root = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), created_at=now - 3600)
    text = f"Withdrawn by its source.\n\n```{schema.INFO_STRING}\n" + '{"level":"withdrawn"}\n```\n'
    # with the claim of the withdrawn reading, level "none", as a level change carries its claim (hh5s)
    reply = m.post(m.bot_sec, text, created_at=now - 3000,
                   tags=[["e", root["id"], "", "root"], claim("AITA-TEST-0001", "none", now - 3000)])
    assert wire.claim_of(reply)["level"] == "none" and wire.is_withdrawal(json.loads(schema._last_block(text)))
    live = {"AITA-TEST-0001": ["critical", ["99.0.0"], True]}
    theirs = released(tmp_path, tag, m, now)
    assert theirs[str(now)] == live and theirs[str(now + MONTH)] == live  # no claim on the root: nothing decays
    assert this_reader(m, now, tmp_path) == {str(now): live, str(now + MONTH): live}
    st = State.load(tmp_path / "this-reader")
    (t,) = pull.advisories(st)
    assert (t.offered, t.offered_by) == (pull.WITHDRAWN, reply["id"])
    at, listed = pull.head_clock(st)
    since = pull.offers([t], {}, at, listed)
    assert since == {reply["id"]: at}
    confirms = lambda adv, level, stated=(): True  # noqa: E731 - the member's own check, when it confirms
    assert pull.active([t], at, listed, confirms, since=since) == []  # shown nowhere, matched by nothing
    (later,) = pull.active([t], at + pull.UNCHECKED_LOWERING_S, None, None, since=since)
    assert later.adv.level == "notice"  # unchecked: a lowering, as the poster of 3qyq sends for a withdrawn advisory
    (never,) = pull.active([t], at + 10 * MONTH, None, None, since=since)
    assert never.adv.level == "notice"


# ---------------------------------------------------------------- the poster's own events (hh5s)

CVE = "CVE-2026-0001"


def poster_event(m, text, at, reply_to=None, claim=None, files=("feed.json",)):
    """An event exactly as the poster signs it (``transport.message_event``), on the mirror."""
    ev = transport.message_event(CHANNELS["feed"], text, reply_to, created_at=at, claim=claim)
    got = m.post(m.bot_sec, text, created_at=at, tags=ev["tags"], files=files)
    assert got["tags"] == ev["tags"] and got["content"] == ev["content"] and nostr.verify_event(got)
    return got


def kev_claim(at):
    """The claim tag the poster's own builder makes for the thread's KEV reading."""
    text = rules.claim_text([("kev", {"cve_id": CVE, "name": "Anthropic Claude Code"})], [CVE], "Claude Code", at)
    obj = json.loads(text)
    assert ruleset.check_claim(obj, "Claude Code") == "ok" and obj["level"] == "critical"
    return [wire.CLAIM_TAG, text]


@pytest.mark.parametrize("tag", RELEASED + CLAIM_READERS)
def test_the_posters_events_as_shipped_show_at_the_same_level_on_every_reader(tmp_path, tag):
    """What the poster sends from hh5s on: a root with no claim, and a level change with
    its claim (here a raise that shares a reply with the fix). Every released reader
    and this one show the alert at critical, now and a month on: a claim in a reply
    never starts an expiry, because the root carries none."""
    m, now = mirror_now()
    t = now - 3600
    root = poster_event(m, schema.render_post(advisory(id=CVE, level="high", posted_by="relay-bot"), "Body line."), t)
    raised = poster_event(m, m.patch_text(level="critical", products=[asdict(p) for p in FIX]), t + 100,
                          reply_to=root["id"], claim=kev_claim(t + 100))
    assert wire.claim_of(root) is None and wire.claim_of(raised)["id"] == CVE
    mine, theirs = this_reader(m, now, tmp_path), released(tmp_path, tag, m, now)
    live = {CVE: ["critical", ["99.1.0"], True]}
    for at in (str(now), str(now + MONTH)):
        assert mine[at] == live and theirs[at] == live, (at, mine[at], theirs[at])


@pytest.mark.parametrize("tag", RELEASED + CLAIM_READERS)
def test_why_the_poster_renews_a_claimed_root_decays_where_claims_are_read(tmp_path, tag):
    """The same tag on a root (``poster.main.ROOT_CLAIMS``, on since ai-tools-alerts#gtw9).
    Every reader shows the alert now. A month on with no renewal, the readers that compute
    expiry from claims (0.1.8 and later, and this one) have stepped a true critical down;
    the older ones keep it. So the poster renews every thread whose root carries a claim
    (``Run.renew``; the next test)."""
    m, now = mirror_now()
    t = now - 3600
    root = poster_event(m, schema.render_post(advisory(id=CVE, posted_by="relay-bot"), "Body line."), t,
                        claim=kev_claim(t))
    assert wire.claim_of(root)["level"] == "critical"
    mine, theirs = this_reader(m, now, tmp_path), released(tmp_path, tag, m, now)
    live = {CVE: ["critical", ["99.0.0"], True]}
    assert mine[str(now)] == live and theirs[str(now)] == live
    later = str(now + MONTH)
    assert pull._RANK[mine[later][CVE][0]] < pull._RANK["critical"]
    if tag in CLAIM_READERS:
        assert pull._RANK[theirs[later][CVE][0]] < pull._RANK["critical"], theirs[later]
    else:
        assert theirs[later] == live


DAY = 86400


@pytest.mark.parametrize("tag", RELEASED + CLAIM_READERS)
def test_a_renewed_thread_and_its_step_down_never_show_lower_on_a_released_reader(tmp_path, tag):
    """What the poster sends from ai-tools-alerts#gtw9 on, for a critical whose source it
    could not read for 44 days: a claimed root, a renewal every seven days (a reply with
    no block, the first confirmation and a new check time), then the step down with its
    reason. This reader shows critical on day 30 (the renewals hold it); no released
    reader shows less than this one, now or a month on."""
    m, now = mirror_now()
    t0 = now - 44 * DAY - 3600
    root = poster_event(m, schema.render_post(advisory(id=CVE, posted_by="relay-bot"), "Body line."), t0, claim=kev_claim(t0))
    first = json.loads(kev_claim(t0)[1])

    def checked(at):
        return wire.claim_tag({**first, "checked_at": at})
    renewals = [poster_event(m, compose.renewal_post(), t0 + d * DAY, reply_to=root["id"], claim=checked(t0 + d * DAY))
                for d in (7, 14, 21, 28, 35)]
    assert all(pull._renewal(e, "relay-bot")[1:3] == (t0, e["created_at"]) for e in renewals)
    rs = ruleset.load()
    held = [(t0, t0)] + [(t0, e["created_at"]) for e in renewals]
    assert rs.level_at("critical", held[:5], t0 + 30 * DAY) == "critical"  # day 30, by the renewals to day 28
    assert rs.level_at("critical", held[:1], t0 + 30 * DAY) == "high"  # and without them: decayed
    text = compose.level_post(advisory(id=CVE, posted_by="relay-bot"), "high", compose.UNCONFIRMED.format(days=44))
    assert text.startswith("Level is now high. No source has confirmed the higher level for 44 days.")
    poster_event(m, text, now - 3600, reply_to=root["id"], claim=checked(now - 3600))
    mine, theirs = this_reader(m, now, tmp_path), released(tmp_path, tag, m, now)
    for at in (str(now), str(now + MONTH)):
        assert CVE in theirs[at], (at, theirs[at])
        if CVE in mine[at]:
            assert pull._RANK[theirs[at][CVE][0]] >= pull._RANK[mine[at][CVE][0]], (at, mine[at], theirs[at])
    assert mine[str(now)][CVE][0] == "critical"  # the step is an offer this reader has not applied yet
    if tag in RELEASED:
        assert theirs[str(now + MONTH)][CVE][0] == "critical"  # they refuse a relay-bot lowering for good


# What a member is shown under the checkpoint the reader holds: its date (the clock expiry
# is judged by) and each thread's level. Written against the modules as v0.1.8 has them.
HEAD_DUMP = """
import json
from aitools_alerts import pull
from aitools_alerts.state import State
st = State.load()
at, listed = pull.head_clock(st)
print(json.dumps([at, {t.adv.id: t.adv.level for t in pull.active(pull.advisories(st), at, listed)}]))
"""


def late_feed(renewed=True, checked_after=None):
    """(mirror, clock): a claimed critical root 20 days old, whose own claim holds critical
    for 14 days and high to day 30, and a checkpoint dated ten minutes ago that lists it.
    ``renewed``: also a renewal dated five minutes ago, after that checkpoint, which lists
    it too: what a poster to 0.3.0 signs after a run that posted (it dates the checkpoint
    at the start of its run), and what a later poster signs when its clock was set back.
    ``checked_after``: the renewal's claim was checked that long after the root (not five
    minutes ago), so a day gives a claim that holds critical to day 15 and no longer."""
    m, now = mirror_now()
    t0 = now - 20 * DAY
    root = poster_event(m, schema.render_post(advisory(id=CVE, posted_by="relay-bot"), "Body line."), t0, claim=kev_claim(t0))
    ids = [root["id"]]
    if renewed:
        checked = wire.claim_tag({**json.loads(kev_claim(t0)[1]), "checked_at": t0 + checked_after if checked_after else now - 300})
        ids.append(poster_event(m, compose.renewal_post(), now - 300, reply_to=root["id"], claim=checked)["id"])
    m.checkpoint(ids=ids, now=now - 600)
    return m, now


def head_view(st) -> list:
    at, listed = pull.head_clock(st)
    return [at, {t.adv.id: t.adv.level for t in pull.active(pull.advisories(st), at, listed)}]


@pytest.mark.parametrize("tag", CLAIM_READERS)
def test_an_event_dated_after_the_checkpoint_that_lists_it_is_admitted_and_its_claim_waits(tmp_path, tag):
    """The rule of spec/wire.md for an event dated after its checkpoint (ai-tools-alerts#p93w),
    on every reader that computes expiry and on this one. The checkpoint is not refused
    and the event is admitted. While the checkpoint the reader holds is dated before
    the renewal, the thread is not judged: it shows critical, where the root's claim
    alone, judged at that time, gives high (the control: the same root with no renewal).
    Under the next checkpoint, dated after the renewal, the thread is judged with the
    renewal counted and shows critical by it. A third feed tells that hold from a reader
    that counts the late claim at once: its late claim holds critical to day 15 only, so
    the thread shows critical while the claim waits and high once it is counted."""
    def both(m, now, name):
        st = State.load(tmp_path / f"this-{name}")
        run = released_reader(tmp_path / name, tag=tag)

        def pulled():
            res = pull.fetch("https://mirror.example.invalid/", st, fetch=m.fetch, root_pubkey=m.root, now=now)
            assert res.error is None, res.error
            got = run("pull", "--mirror-url", m.write(tmp_path / name), root=m.root)
            assert got.returncode == 0 and "unverified" not in got.stderr, (got.stdout, got.stderr)
            out = run.py(HEAD_DUMP, root=m.root)
            assert out.returncode == 0, out.stderr
            return head_view(st), json.loads(out.stdout)
        return pulled
    for name in ("control", "late", "short"):
        (tmp_path / name).mkdir()
    m, now = late_feed(renewed=False)
    assert both(m, now, "control")() == ([now - 600, {CVE: "high"}],) * 2
    m, now = late_feed()
    pulled = both(m, now, "late")
    assert pulled() == ([now - 600, {CVE: "critical"}],) * 2  # held: the renewal is dated after the checkpoint
    m.checkpoint(now=now - 100)
    assert pulled() == ([now - 100, {CVE: "critical"}],) * 2  # judged, the renewal counted
    rs = ruleset.load()
    assert rs.level_at("critical", [(now - 20 * DAY, now - 20 * DAY)], now - 100) == "high"  # without it: decayed
    m, now = late_feed(checked_after=DAY)
    pulled = both(m, now, "short")
    assert pulled() == ([now - 600, {CVE: "critical"}],) * 2  # not judged: counted now, this claim would give high
    m.checkpoint(now=now - 100)
    assert pulled() == ([now - 100, {CVE: "high"}],) * 2  # judged, and the claim does not hold critical
