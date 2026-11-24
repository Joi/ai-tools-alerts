"""The released readers against a feed in the self-correcting format (ai-tools-alerts#t8jr,
finding D12 of the design review on ai-tools-alerts#h29n).

Each released reader is unpacked from its tag and run as a member would run it. The
feed carries what the new format adds: a claim tag on roots and replies, a relay-bot
lowering in a reply of its own, a raise after it in a reply of its own, and ``min_cli``
in the checkpoint key certificate. Every alert must still be active there, now and a
month on, at the level this reader shows or a higher one, and must still match the
installation it matches here.

When a later slice adds something signed to the feed, add it to ``feed`` here first.
"""

import json
import subprocess
from dataclasses import asdict
from pathlib import Path

import pytest

from aitools_alerts import check, nostr, pull, schema, wire
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.poster import compose
from aitools_alerts.schema import Product
from aitools_alerts.state import State
from mirror_helpers import advisory, mirror_now, released_reader

RELEASED = ("v0.1.4", "v0.1.5", "v0.1.6", "v0.1.7")
REPO = Path(__file__).resolve().parents[1]
MONTH = 30 * 86400
# What a member is shown: the active threads at a given time, and which of them match
# an installed Claude Code 2.0.0. Written against the modules as v0.1.4 has them.
DUMP = """
import json
from aitools_alerts import check, pull
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.state import State
INV = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/claude")]})
out = {}
for at in (int(sys.argv[2]), int(sys.argv[2]) + %d):
    ts = pull.active(pull.advisories(State.load()), at)
    hit = {m.adv.id for m in check.match([t.adv for t in ts], INV)}
    out[str(at)] = {t.adv.id: [t.adv.level, sorted(p.fixed or "" for p in t.adv.products), t.adv.id in hit]
                    for t in ts}
print(json.dumps(out))
""" % MONTH
INV = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/claude")]})
FIX = [Product("Claude Code", "claude-code", "<99.1.0", "99.1.0")]


def claim(adv_id, level):
    return wire.claim_tag({"id": adv_id, "source": "kev", "fields": {"listed": True}, "ruleset": 1,
                           "level": level, "confirmed_at": 1, "checked_at": 2})


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
    the format must never do. Every relay-bot root has ``expires_at`` null; no reply
    names it."""
    m, now = mirror_now(min_cli="99.0.0")
    t = now - 3600
    bot = lambda n, **kw: advisory(id=f"AITA-TEST-000{n}", posted_by="relay-bot", **kw)  # noqa: E731
    reply = lambda root, text, at, *tags: m.post(  # noqa: E731
        m.bot_sec, text, created_at=at, tags=[["e", root["id"], "", "root"], *tags])
    m.root_post(m.bot_sec, bot(1), created_at=t, tags=[claim("AITA-TEST-0001", "critical")])
    r2 = m.root_post(m.bot_sec, bot(2, level="high"), created_at=t, files=("feed.json",),
                     tags=[claim("AITA-TEST-0002", "high")])
    reply(r2, m.patch_text(level="critical", products=[asdict(p) for p in FIX]), t + 100,
          claim("AITA-TEST-0002", "critical"))
    r3 = m.root_post(m.bot_sec, bot(3), created_at=t, tags=[claim("AITA-TEST-0003", "critical")])
    reply(r3, compose.level_post(bot(3), "notice"), t + 200, claim("AITA-TEST-0003", "notice"))
    reply(r3, compose.level_post(bot(3, level="notice"), "high"), t + 250, claim("AITA-TEST-0003", "high"))
    reply(r3, m.patch_text(products=[asdict(p) for p in FIX]), t + 300, claim("AITA-TEST-0003", "high"))
    m.root_post(m.cur_sec, advisory(id="AITA-TEST-0004"), created_at=t)
    m.post(m.bot_sec, with_block_key(schema.render_post(bot(5), "Body line."), rule_version=1), created_at=t)
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
    return {str(at): shown(pull.advisories(st), at) for at in (now, now + MONTH)}


def released(tmp_path, tag, m, now) -> dict:
    """What the released reader ``tag`` shows after pulling ``m``, as DUMP prints it."""
    (tmp_path / "mirror").mkdir(exist_ok=True)
    run = released_reader(tmp_path, tag=tag)
    got = run("pull", "--mirror-url", m.write(tmp_path / "mirror"), root=m.root)
    assert got.returncode == 0 and "Traceback" not in got.stderr, (got.stdout, got.stderr)
    if tuple(map(int, tag[1:].split("."))) >= (0, 1, 6):  # a checked pull: the certificate, min_cli key and all, was accepted
        assert "; checkpoint " in got.stdout and " lists " in got.stdout and "unverified" not in got.stderr, got
    out = run.py(DUMP, str(now), root=m.root)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.parametrize("tag", RELEASED)
def test_every_alert_still_appears_on_a_released_reader_at_the_same_or_a_higher_level(tmp_path, tag):
    m, now = feed()
    mine, theirs = this_reader(m, now, tmp_path), released(tmp_path, tag, m, now)
    for at in (str(now), str(now + MONTH)):
        assert sorted(mine[at]) == [f"AITA-TEST-000{n}" for n in (1, 2, 3, 4)]
        assert sorted(theirs[at]) == sorted(mine[at])  # every alert; the one with a new block key on neither
        for adv_id, (level, fixed, matched) in mine[at].items():
            assert pull._RANK[theirs[at][adv_id][0]] >= pull._RANK[level], (adv_id, theirs[at][adv_id])
            assert matched and theirs[at][adv_id][2], adv_id  # the member with the tool installed is told
        # Level changes in replies of their own cost nothing else: the level stays, the fix arrives.
        assert theirs[at]["AITA-TEST-0003"] == ["critical", ["99.1.0"], True] == mine[at]["AITA-TEST-0003"]
        assert theirs[at]["AITA-TEST-0002"] == ["critical", ["99.1.0"], True]  # a raise applies, claim tag and all


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
