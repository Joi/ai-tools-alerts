"""The claim tag and the lowering event (spec/wire.md, ai-tools-alerts#t8jr)."""

import json
from dataclasses import replace

import pytest

from aitools_alerts import pull, schema, wire
from aitools_alerts.poster import compose, rules
from mirror_helpers import T0, Mirror, advisory

CLAIM = {"id": "CVE-2026-0001", "source": "kev", "fields": {"listed": True}, "ruleset": 1, "level": "critical"}


def test_ranks_are_the_readers():
    assert wire._RANK == pull._RANK and wire.LEVELS == set(pull._RANK)


def test_claim_round_trip_is_sorted_and_compact():
    tag = wire.claim_tag({"b": 1, "a": {"z": "é", "y": None}})
    assert tag == ["claim", '{"a":{"y":null,"z":"é"},"b":1}']
    assert wire.claim_of({"tags": [["h", "x"], tag]}) == {"b": 1, "a": {"z": "é", "y": None}}


@pytest.mark.parametrize("obj", [None, [], "x", 1, {1: "a non-string key"}, {"a": float("nan")}, {"a": object()},
                                 {"a": "x" * wire.MAX_CLAIM_BYTES}, {"a": "\ud800"}])
def test_claim_tag_refuses(obj):
    with pytest.raises(ValueError):
        wire.claim_tag(obj)


def test_claim_tag_limit_is_in_bytes():
    fits = {"a": "x" * (wire.MAX_CLAIM_BYTES - len('{"a":""}'))}
    assert len(wire.claim_tag(fits)[1]) == wire.MAX_CLAIM_BYTES
    with pytest.raises(ValueError):
        wire.claim_tag({"a": "é" * (wire.MAX_CLAIM_BYTES // 2)})  # under the limit in characters, over in bytes


@pytest.mark.parametrize("event", [
    None, [], {}, {"tags": None}, {"tags": "claim"}, {"tags": [["h", "x"]]},
    {"tags": [["claim"]]},
    {"tags": [["claim", "{}", "extra"]]},
    {"tags": [["claim", "{}"], ["claim", "{}"]]},  # which one is the claim is not for a reader to pick
    {"tags": [["claim", {"a": 1}]]},
    {"tags": [["claim", "[]"]]}, {"tags": [["claim", "1"]]}, {"tags": [["claim", "not json"]]},
    {"tags": [["claim", '{"a":1,"a":2}']]},
    {"tags": [["claim", '{"a":NaN}']]},
    {"tags": [["claim", '{"a":"' + "x" * wire.MAX_CLAIM_BYTES + '"}']]},
    {"tags": [["claim", "[" * 100000]]},
    {"tags": [["claim", "[" * 2000]]},  # within the limit: too deep to parse
    {"tags": [["claim", '{"a":1e999}']]}, {"tags": [["claim", '{"a":-1e999}']]},  # infinity, without the word
    {"tags": [["claim", '{"a":"\\ud800"}']]},  # an escaped lone surrogate
    {"tags": [["claim", "\ud800"]]},
])
def test_claim_of_is_none_and_never_raises(event):
    assert wire.claim_of(event) is None


def test_claim_of_ignores_what_is_not_a_tag_list():
    assert wire.claim_of({"tags": ["claim", None, [], ["claim", "{}"]]}) == {}


def test_is_lowering():
    assert wire.is_lowering({"level": "notice"}, "critical") and wire.is_lowering({"level": "high"}, "critical")
    assert not wire.is_lowering({"level": "critical"}, "critical")
    assert not wire.is_lowering({"level": "critical"}, "high")
    for patch in ({}, {"level": None}, {"level": "withdrawn"}, {"level": ["notice"]}, None, "notice"):
        assert not wire.is_lowering(patch, "critical")


# ---------------------------------------------------------------- the lowering event

def bot_adv(**over):
    return advisory(posted_by="relay-bot", **over)


@pytest.mark.parametrize("prev, level", [("critical", "high"), ("critical", "notice"), ("notice", "high"),
                                         ("high", "critical")])
def test_level_post_is_one_line_and_a_one_key_block(prev, level):
    text = compose.level_post(bot_adv(level=prev), level)
    assert text.split("\n")[0] == f"Level is now {level}."
    assert json.loads(schema._last_block(text)) == {"level": level}
    assert compose.parse_reply(text, bot_adv(level=prev)) == replace(bot_adv(level=prev), level=level)


@pytest.mark.parametrize("prev, level", [("critical", "critical"), ("notice", "notice"), ("critical", "withdrawn"),
                                         ("critical", None), ("critical", ["high"])])
def test_level_post_refuses_no_change_and_unknown_levels(prev, level):
    with pytest.raises(ValueError):
        compose.level_post(bot_adv(level=prev), level)


def test_reply_post_refuses_a_lowering_alone_or_with_a_fix():
    """A lowering mixed with a fix would cost released readers the fix: they skip the whole reply."""
    from poster.test_compose import cand
    prev = compose.root_post(cand(), ("critical", "injection-exec-fixed"),
                             rules.scope_of(cand().product_text), posted_at=T0)[1]
    fixed = [replace(prev.products[0], fixed="2.2.0")]
    for changes in ({"level": "notice"}, {"level": "high", "products": fixed}):
        with pytest.raises(ValueError, match="a lowering travels alone"):
            compose.reply_post(prev, cand(), changes)
    assert '"fixed": "2.2.0"' in compose.reply_post(prev, cand(), {"products": fixed})  # the fix alone still posts
    # Rule 2: once a thread was lowered, a raise travels alone too; other changes still post.
    was_lowered = replace(prev, level="notice")
    assert '"level": "high"' in compose.reply_post(was_lowered, cand(), {"level": "high", "products": fixed})
    for changes in ({"level": "high", "products": fixed}, {"level": "high"}):
        with pytest.raises(ValueError, match="was lowered"):
            compose.reply_post(was_lowered, cand(), changes, lowered=True)
    assert '"fixed": "2.2.0"' in compose.reply_post(was_lowered, cand(), {"products": fixed}, lowered=True)


def test_this_reader_keeps_the_higher_level_and_ignores_the_claim_tag():
    """Replay keeps the higher level: a relay-bot lowering is published on the thread
    (``offered``, ai-tools-alerts#c1g2), applied only by a member whose source check
    confirms it; and an event reads the same with a claim tag as without one."""
    m = Mirror()
    plain = m.root_post(m.bot_sec, bot_adv(id="AITA-TEST-0001"), files=("feed.json",))
    tagged = m.root_post(m.bot_sec, bot_adv(id="AITA-TEST-0002"), files=("feed.json",),
                         tags=[wire.claim_tag(CLAIM)])
    low = m.post(m.bot_sec, compose.level_post(bot_adv(), "notice"), created_at=T0 + 200,
                 tags=[["e", tagged["id"], "", "root"], wire.claim_tag({**CLAIM, "level": "notice"})])
    assert wire.claim_of(tagged) == CLAIM and wire.claim_of(plain) is None
    assert wire.claim_of(low)["level"] == "notice"
    dropped = pull.Counter()
    got = {t.adv.id: t for t in pull.threads_from(m.events["feed.json"], m.man, dropped)}
    assert got["AITA-TEST-0002"].adv == replace(got["AITA-TEST-0001"].adv, id="AITA-TEST-0002")
    assert got["AITA-TEST-0002"].adv.level == "critical" and dropped == {}
    assert (got["AITA-TEST-0002"].offered, got["AITA-TEST-0001"].offered) == ("notice", None)
