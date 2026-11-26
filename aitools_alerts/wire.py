"""What travels beside the alert block, where released readers ignore it.

Readers at 0.1.7 and earlier refuse an ``aitools-alert`` block with a key
they do not know (the root is never an advisory), a manifest with a key they
do not know (the pull fails), and a relay-bot reply that lowers a level (the
reply is skipped; 0.1.7 alone still joins its products, actions and sources).
They ignore an event tag they do not know. So the
block and the manifest do not change, and what the self-correcting design
adds goes here (spec/wire.md; tests/test_wire_compat.py runs the released
readers against it):

The claim, the signed statement of what an alert's state rests on, is one
event tag, ``["claim", "<JSON object text>"]``, on the event whose state it
describes. This module fixes the carrier only: one tag, an object, at most
MAX_CLAIM_BYTES. What the object holds and its canonical form are the level
function's (ai-tools-alerts#s6mt). A claim never decides whether an event is
read.

A lowering is its own reply: its block is exactly ``{"level": "<lower>"}``
(poster.compose.level_post). A reader that refuses it loses nothing else. So
is every later level change on that thread: a reader that kept the higher
level may refuse a raise too.

A withdrawal (ai-tools-alerts#y484) is a reply of the same kind whose block is
exactly ``{"level": "withdrawn"}``. The word is no level: every released reader
refuses the reply and keeps the alert.
"""

from __future__ import annotations

import json

from . import schema

__all__ = ["CLAIM_TAG", "MAX_CLAIM_BYTES", "LEVELS", "claim_tag", "claim_of", "tag_bytes", "is_lowering",
           "WITHDRAWN", "is_withdrawal"]

CLAIM_TAG = "claim"
MAX_CLAIM_BYTES = 2048
_RANK = {"notice": 1, "high": 2, "critical": 3}  # pull._RANK; tests/test_wire.py checks the two are equal
LEVELS = frozenset(_RANK)
# y484: the state a relay-bot reply moves its thread to when the source withdrew the
# advisory. Not a level: no root may name it, and it is in no rank table.
WITHDRAWN = "withdrawn"


def claim_tag(obj) -> list:
    """The event tag carrying ``obj`` (a dict): sorted keys, no spaces.
    ValueError for anything but an object JSON can hold within the limit."""
    if not isinstance(obj, dict):
        raise ValueError("claim: not an object")
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        size = len(text.encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        raise ValueError("claim: not JSON") from None
    if size > MAX_CLAIM_BYTES:
        raise ValueError(f"claim: larger than {MAX_CLAIM_BYTES} bytes")
    if claim_of({"tags": [[CLAIM_TAG, text]]}) != obj:  # e.g. a non-string key, which JSON renames
        raise ValueError("claim: does not read back as written")
    return [CLAIM_TAG, text]


def claim_of(event) -> dict | None:
    """The claim an event carries, or None: exactly one ``claim`` tag, of two
    elements, whose value is an object within the limit, strictly parsed (no
    duplicate key, no NaN, no number or string that JSON text cannot carry
    back: ``1e999``, an escaped lone surrogate). Whatever it returns,
    ``claim_tag`` can write. Never raises. Verify the event's signature first:
    a tag proves nothing by itself."""
    tags = event.get("tags") if isinstance(event, dict) else None
    if not isinstance(tags, list):
        return None
    found = [t for t in tags if isinstance(t, list) and t and t[0] == CLAIM_TAG]
    if len(found) != 1 or len(found[0]) != 2 or not isinstance(found[0][1], str):
        return None
    text = found[0][1]
    try:
        if len(text.encode("utf-8")) > MAX_CLAIM_BYTES:
            return None
        obj = json.loads(text, object_pairs_hook=schema._no_duplicates, parse_constant=schema._reject_constant)
        if not isinstance(obj, dict):
            return None
        # 1e999 parses to infinity and "\ud800" to a lone surrogate: neither can be written again
        json.dumps(obj, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError):  # not JSON, a lone surrogate, nested too deeply
        return None
    return obj


def tag_bytes(tag) -> int:
    """The bytes one tag adds to an event as a channel file holds it: its JSON text
    (the quotes and backslashes of a claim's text escaped) and the comma before it."""
    return len(json.dumps(tag, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1


def is_lowering(patch, level: str) -> bool:
    """``patch`` names a level below ``level``."""
    new = patch.get("level") if isinstance(patch, dict) else None
    return isinstance(new, str) and new in _RANK and level in _RANK and _RANK[new] < _RANK[level]


def is_withdrawal(patch) -> bool:
    """``patch`` is the withdrawal block, exactly ``{"level": "withdrawn"}`` (spec/wire.md).
    Released readers refuse a reply that carries it: to them it names no level."""
    return isinstance(patch, dict) and len(patch) == 1 and patch.get("level") == WITHDRAWN \
        and type(patch["level"]) is str
