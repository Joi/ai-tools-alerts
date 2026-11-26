"""Match advisories against the inventory and decide what may auto-apply.

This is the boundary between a post and an action. An action reaches
``auto_apply`` only when the post came from a curator key, the member opted
into the verb, the verb is in the fixed vocabulary, the match is a readable
version inside the range, and the action is complete (an upgrade needs the
product's ``fixed``). Everything else is notify-only, in ``prepare``.
Nothing here executes anything: actions are data (verb, target, value);
command templates belong to the CLI (A5) and skills (A6).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import lru_cache

from . import ruleset, schema, versions
from .inventory import Installed, Inventory
from .schema import Action, Advisory, Product

AFFECTED = "affected"
# A match by a name alone, or with no version to compare to a range: it is
# reported, and never interrupts (no exit 2, no notification, no auto-apply).
MAY_APPLY = "may apply"
UNPARSABLE = "unparsable-version"
_NAME_ECOSYSTEMS = frozenset({"skill", "mcp"})
# Verbs whose target must name the matched installation, and the ecosystem
# that installation must be in (None: any tool ecosystem, not skill or mcp).
_TARGETED = {"upgrade": None, "disable_skill": "skill", "remove_mcp_server": "mcp"}
# Names that identify the probed tool itself. Not scope.json's match
# patterns: those also name components (containerd under docker, rustup
# under rust) whose versions are not the tool's. A component installation
# (inventory's containerd and runc probes) is known by its own name only.
IDENTITY = {
    "claude-code": {"claude code", "claude-code", "@anthropic-ai/claude-code"},
    "codex": {"codex", "codex cli", "codex-cli", "openai codex", "@openai/codex"},
    "cursor": {"cursor"},
    "gemini-cli": {"gemini cli", "gemini-cli", "@google/gemini-cli"},
    "node": {"node", "node.js", "nodejs"},
    "python": {"python", "cpython"},
    "go": {"go", "golang"},
    "rust": {"rust", "rustc"},
    "docker": {"docker", "docker engine"},
    "tailscale": {"tailscale"},
    "openssh": {"openssh"},
    "git": {"git"},
    "macos": {"macos"},
    "openclaw": {"openclaw"},
    "hermes": {"hermes", "hermes agent", "hermes-agent"},
}


@dataclass(frozen=True)
class Config:
    """Member settings A5 loads from the config file. Unknown verbs in
    auto_apply are ignored."""
    auto_apply: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Match:
    adv: Advisory
    installed: Installed
    actions_allowed: list[Action]
    reason: str
    product: Product | None = None  # the matched product; None: upgrades stay notify-only


@dataclass(frozen=True)
class Plan:
    notify: bool
    auto_apply: list[Action]
    prepare: list[Action]


@lru_cache(maxsize=1)
def _scope_packages() -> dict[str, str]:
    """identity (lowercase) -> package, for every mcp scope entry and
    component that has a package. A scope file that does not load: {}."""
    try:
        out = {}
        for e in schema.load_scope():
            if e.ecosystem != "mcp":
                continue
            for x in (e, *e.components):
                if x.package:
                    for ident in (x.name, *x.match):
                        out[ident.lower()] = x.package.lower()
        return out
    except Exception:
        return {}


def _identity(product: Product, inst: Installed) -> bool | None:
    """Whether the installation is the product by more than a name: True
    when its package (mcp) or its marketplace (a plugin) says so, False when
    they say it is another product (no match at all), None when nothing
    beyond the name is known."""
    name = product.name.lower()
    if product.ecosystem == "mcp":
        want = name if name.startswith(("npm:", "pypi:")) else _scope_packages().get(name)
        if want is None or inst.package is None:
            return None
        return inst.package == want
    if product.ecosystem == "skill" and name.rfind("@") > 0:  # not a leading @scope
        # Source-qualified: only an installation from that marketplace is it.
        return inst.source is not None and f"{inst.name}@{inst.source}".lower() == name
    return None


def _aliases(ecosystem: str, installed: Installed) -> set[str]:
    names = {installed.name.lower()}
    if ecosystem == "mcp":
        names |= {x.lower() for x in (installed.package, installed.server) if x}
    if ecosystem == "skill" and installed.source:
        names.add(f"{installed.name}@{installed.source}".lower())
    tool = IDENTITY.get(ecosystem, set()) | {ecosystem}
    if ecosystem not in _NAME_ECOSYSTEMS and names & tool:  # the ecosystem's own tool
        names |= tool
    return names


def _owns(ecosystem: str, installed: Installed) -> bool:
    """The installation is the ecosystem's tool (its collector names it from
    the scope entry, which IDENTITY lists); skill and mcp names are free."""
    return (ecosystem in _NAME_ECOSYSTEMS
            or installed.name.lower() in IDENTITY.get(ecosystem, set()))


@lru_cache(maxsize=1)
def scope_products() -> dict[str, tuple]:
    """ecosystem -> ((scope product name, its package in lowercase or None), ...) for
    every product a reading can support (``Ruleset.products``: entries and components,
    a component under its entry's ecosystem). A scope file that does not load: {}."""
    try:
        out: dict = {}
        for e in {x.name: x for x in ruleset.index(schema.load_scope()).values()}.values():
            out.setdefault(e.ecosystem, []).append((e.name, e.package.lower() if e.package else None))
        return {k: tuple(v) for k, v in out.items()}
    except Exception:
        return {}


def scope_name(name: str, ecosystem: str) -> str | None:
    """The scope product a posted product is, or None (ai-tools-alerts#2mgd): the one
    scope product of ``ecosystem`` that ``match`` cannot tell from it. ``match`` compares
    names in lower case and, for a tool, treats every name of its IDENTITY as one; an
    mcp installation is also known by its package. So ``claude code`` and
    ``@anthropic-ai/claude-code`` under ``claude-code`` are ``Claude Code``, and
    ``Claude Code`` under ``skill`` is not: what interrupts through an installation is
    judged as the product that installation is. None when no scope product, or more
    than one, fits. Never raises."""
    try:
        n = name.lower()
        tool = IDENTITY.get(ecosystem, set()) | {ecosystem} if ecosystem not in _NAME_ECOSYSTEMS else set()
        hits = {s for s, package in scope_products().get(ecosystem, ())
                if s.lower() == n or (n in tool and s.lower() in tool) or (ecosystem == "mcp" and package == n)}
        return hits.pop() if len(hits) == 1 else None
    except Exception:
        return None


def _concerns(action: Action, ecosystem: str, aliases: set[str]) -> bool:
    if action.verb in _TARGETED:
        want = _TARGETED[action.verb]
        in_ecosystem = (ecosystem == want if want is not None
                        else ecosystem not in _NAME_ECOSYSTEMS)
        return (in_ecosystem and isinstance(action.target, str)
                and action.target.lower() in aliases)
    return True  # advisory-wide verbs, and unknown verbs (planned notify-only)


def match(advs: list[Advisory], inv: Inventory) -> list[Match]:
    """One Match per (advisory, installation, range, reason, scope product): product
    entries that repeat the same range and fixed version for one installation with
    the same reason, and are the same scope product (``scope_name``) or none, collapse; entries with different constraints, or one that
    may apply beside one that is affected, each yield their own Match."""
    out = []
    for adv in advs:
        seen = set()
        for product in adv.products:
            for inst in inv.products.get(product.ecosystem, []):
                aliases = _aliases(product.ecosystem, inst)
                if product.name.lower() not in aliases:
                    continue
                ident = _identity(product, inst)
                if ident is False:
                    continue
                if (ident is True and product.affected == "*" and product.fixed is None):
                    reason = AFFECTED  # every version, and it is this installation
                elif inst.version is None or (product.affected is None
                                              and product.fixed is None):
                    reason = MAY_APPLY
                else:
                    hit = versions.check(inst.version, product.affected, product.fixed)
                    if hit is False:
                        continue
                    reason = AFFECTED if hit else UNPARSABLE
                # The reason is in the key: a may-apply product cannot hide
                # an affected one for the same installation and range.
                # And the scope product (2mgd): an entry that is no scope product (an MCP
                # server's configured key, say) cannot hide one the source check can judge.
                key = (product.ecosystem, inst, product.affected, product.fixed, reason,
                       scope_name(product.name, product.ecosystem))
                if key in seen:
                    continue
                seen.add(key)
                allowed = ([] if reason == UNPARSABLE else
                           [a for a in adv.actions
                            if _concerns(a, product.ecosystem, aliases)])
                out.append(Match(adv=adv, installed=inst, actions_allowed=allowed,
                                 reason=reason, product=product))
    return out


def plan(m: Match, config: Config) -> Plan:
    """Split m's actions into auto_apply and prepare. Re-checks everything
    match() established, so a hand-built Match cannot widen auto_apply.
    A5 builds any command from m.product.ecosystem, never from a target."""
    auto, prepare = [], []
    opted = frozenset(config.auto_apply) & schema.VERBS
    p = m.product
    aliases = _aliases(p.ecosystem, m.installed) if p is not None else set()
    trusted = (m.adv.posted_by == "curator" and m.reason == AFFECTED
               and p is not None and p in m.adv.products
               and p.name.lower() in aliases and _owns(p.ecosystem, m.installed)
               and (p.affected is not None or p.fixed is not None)
               and versions.check(m.installed.version, p.affected, p.fixed) is True)
    fixed = p.fixed if p is not None else None
    for a in m.actions_allowed:
        ready = (trusted and a.verb in schema.VERBS and a.verb in opted
                 and a in m.adv.actions and _concerns(a, p.ecosystem, aliases))
        if a.verb == "upgrade":
            # products[].fixed is authoritative (spec/actions.json), for a
            # prepared upgrade too; without it the upgrade is notify-only.
            a = replace(a, value=fixed)
            ready = ready and fixed is not None and m.installed.version is not None
        (auto if ready else prepare).append(a)
    return Plan(notify=True, auto_apply=auto, prepare=prepare)


def describe(action: Action) -> str:
    """A one-line, notify-only description of an action (never a command)."""
    if action.verb not in schema.VERBS:
        return f"unknown action {action.verb!r} (notify only)"
    if action.verb == "upgrade":
        return (f"upgrade {action.target} to {action.value} or later"
                if action.value else f"upgrade {action.target} (no fixed version given)")
    text = f"{action.verb.replace('_', ' ')}: {action.target}"
    return f"{text} (recommended: {action.value})" if action.value else text
