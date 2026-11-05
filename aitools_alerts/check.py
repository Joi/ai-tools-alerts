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

from . import schema, versions
from .inventory import Installed, Inventory
from .schema import Action, Advisory, Product

AFFECTED = "affected"
NAME = "name"
UNPARSABLE = "unparsable-version"
_NAME_ECOSYSTEMS = frozenset({"skill", "mcp"})
# Verbs whose target must name the matched installation, and the ecosystem
# that installation must be in (None: any tool ecosystem, not skill or mcp).
_TARGETED = {"upgrade": None, "disable_skill": "skill", "remove_mcp_server": "mcp"}
# Names that identify the probed tool itself. Not scope.json's match
# patterns: those also name components (containerd under docker, rustup
# under rust) whose versions are not the tool's.
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


def _aliases(ecosystem: str, installed: Installed) -> set[str]:
    names = {installed.name.lower()}
    if ecosystem not in _NAME_ECOSYSTEMS:
        names |= IDENTITY.get(ecosystem, set()) | {ecosystem}
    return names


def _owns(ecosystem: str, installed: Installed) -> bool:
    """The installation is the ecosystem's tool (its collector names it from
    the scope entry, which IDENTITY lists); skill and mcp names are free."""
    return (ecosystem in _NAME_ECOSYSTEMS
            or installed.name.lower() in IDENTITY.get(ecosystem, set()))


def _concerns(action: Action, ecosystem: str, aliases: set[str]) -> bool:
    if action.verb in _TARGETED:
        want = _TARGETED[action.verb]
        in_ecosystem = (ecosystem == want if want is not None
                        else ecosystem not in _NAME_ECOSYSTEMS)
        return (in_ecosystem and isinstance(action.target, str)
                and action.target.lower() in aliases)
    return True  # advisory-wide verbs, and unknown verbs (planned notify-only)


def match(advs: list[Advisory], inv: Inventory) -> list[Match]:
    """One Match per (advisory, installation, range): product entries that
    repeat the same range and fixed version for one installation collapse;
    entries with different constraints each yield their own Match."""
    out = []
    for adv in advs:
        seen = set()
        for product in adv.products:
            for inst in inv.products.get(product.ecosystem, []):
                aliases = _aliases(product.ecosystem, inst)
                key = (product.ecosystem, inst.name.lower(), product.affected, product.fixed)
                if product.name.lower() not in aliases or key in seen:
                    continue
                if inst.version is None or (product.affected is None
                                            and product.fixed is None):
                    reason = NAME
                else:
                    hit = versions.check(inst.version, product.affected, product.fixed)
                    if hit is False:
                        continue
                    reason = AFFECTED if hit else UNPARSABLE
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
