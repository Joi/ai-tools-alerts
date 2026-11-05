"""Version comparison for the advisory grammar A2 fixed.

A version is 1 to 5 dotted integers with an optional lowercase suffix
(``9.9p1``, ``1.0rc1``). ``affected`` is ``*`` or 1 to 4 comparators
(``<``, ``<=``, ``>``, ``>=``, ``=``) joined by ``,``. Anything this module
cannot read is never a match: ``check`` returns None for it and the caller
reports ``unparsable-version``.
"""

from __future__ import annotations

import re

_SUFFIX = r"(?:[a-z][a-z0-9]{0,15})?"
_VERSION = re.compile(rf"([0-9]{{1,9}}(?:\.[0-9]{{1,9}}){{0,4}})({_SUFFIX})")
_COMPARATOR = re.compile(r"(<=|>=|<|>|=)(.+)")
_TAG = re.compile(r"([a-z]+)([0-9]*)")
# Suffix tags with a known order (PEP 440 spellings): dev < a < b < rc <
# release < p (a patch level, OpenSSH's 9.9p1). Any other tag is unreadable.
_TAG_ALIAS = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}
_TAG_RANK = {"dev": 0, "a": 1, "b": 2, "rc": 3, "p": 5}
_RELEASE_RANK = 4
_PARTS = 5


def normalize(s: str | None) -> str | None:
    """An installed-version string in the grammar, or None.

    Keeps the text before the first space, strips a ``claude-code/`` prefix,
    then one leading ``v``."""
    if not isinstance(s, str):
        return None
    words = s.strip().split(maxsplit=1)
    if not words:
        return None
    v = words[0]
    if v.startswith("claude-code/"):
        v = v[len("claude-code/"):]
    if v.startswith("v"):
        v = v[1:]
    return v if _VERSION.fullmatch(v) else None


def parse(s: str | None) -> tuple | None:
    """A sort key for a version in the grammar, or None.

    Numbers are padded to five parts. A suffix is a tag and a number, ordered
    by _TAG_RANK after _TAG_ALIAS; a tag outside both is unreadable (None)."""
    if not isinstance(s, str):
        return None
    m = _VERSION.fullmatch(s)
    if not m:
        return None
    nums = [int(p) for p in m.group(1).split(".")]
    nums += [0] * (_PARTS - len(nums))
    suffix = m.group(2)
    if not suffix:
        return (tuple(nums), (_RELEASE_RANK, 0))
    t = _TAG.fullmatch(suffix)
    if not t:  # a suffix such as "a1b": in the grammar, but no order
        return None
    tag = _TAG_ALIAS.get(t.group(1), t.group(1))
    if tag not in _TAG_RANK:
        return None
    return (tuple(nums), (_TAG_RANK[tag], int(t.group(2) or 0)))


def _holds(key: tuple, comparator: str) -> bool | None:
    m = _COMPARATOR.fullmatch(comparator)
    if not m:
        return None
    other = parse(m.group(2))
    if other is None:
        return None
    op = m.group(1)
    if op == "<":
        return key < other
    if op == "<=":
        return key <= other
    if op == ">":
        return key > other
    if op == ">=":
        return key >= other
    return key == other


def check(installed: str | None, affected: str | None, fixed: str | None) -> bool | None:
    """True if installed is affected, False if not, None if anything present
    cannot be read (installed included: a missing installed version is
    unreadable here; callers decide whether to compare at all)."""
    key = parse(normalize(installed))
    if key is None:
        return None
    result = True
    if affected is not None:
        if not isinstance(affected, str):
            return None
        if affected != "*":
            parts = affected.split(",")
            if not 1 <= len(parts) <= 4:
                return None
            for comparator in parts:
                holds = _holds(key, comparator)
                if holds is None:
                    return None
                result = result and holds
    if fixed is not None:
        fixed_key = parse(fixed) if isinstance(fixed, str) else None
        if fixed_key is None:
            return None
        result = result and key < fixed_key
    return result


def affected(installed: str, affected: str | None, fixed: str | None) -> bool:
    """The plan's interface: True only when installed is readably affected."""
    return check(installed, affected, fixed) is True
