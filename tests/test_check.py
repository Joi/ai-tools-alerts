import pytest
import dataclasses
from pathlib import Path

from aitools_alerts import check, versions
from aitools_alerts.check import Config
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.schema import Action, Advisory, Product, Source


def adv(products, actions, posted_by="curator"):
    return Advisory(
        id="TEST-0001", aliases=[], level="critical", advisory_severity=None,
        title="Invented advisory", products=products, actions=actions,
        sources=[Source(url="https://example.invalid/a", published_at=None)],
        posted_by=posted_by, posted_at=1_700_000_000, expires_at=None)


def inv(**products):
    return Inventory(products={k.replace("_", "-"): v for k, v in products.items()})


CLAUDE_213 = inv(claude_code=[Installed("Claude Code", "2.1.3", "claude")])
UPGRADE = Action(verb="upgrade", target="Claude Code", value=None)
UPGRADE_FIXED = Action(verb="upgrade", target="Claude Code", value="2.1.4")
OPT_IN = Config(auto_apply=frozenset({"upgrade"}))


def claude_adv(affected="<2.1.4", fixed="2.1.4", actions=(UPGRADE,), posted_by="curator",
               name="Claude Code"):
    return adv([Product(name=name, ecosystem="claude-code", affected=affected, fixed=fixed)],
               list(actions), posted_by)


def test_version_affected_ranges():
    assert versions.affected("2.1.3", "<2.1.4", None)
    assert not versions.affected("2.1.4", "<2.1.4", None)
    assert versions.affected("1.5", ">=1.0,<2.0", None)
    assert not versions.affected("2.0", ">=1.0,<2.0", None)
    assert versions.affected("0.1", "*", "9.0")
    assert not versions.affected("9.0", "*", "9.0")
    assert versions.affected("1.2.3", None, "1.2.4")
    assert versions.affected("1.2", "=1.2.0", None)
    assert versions.affected("3", ">2.9.9", None)
    assert not versions.affected("1.0", ">1.0", None)
    # unreadable: never a match, and check() says so
    for args in (("garbage", "*", None), ("1.0", "~1.0", None), ("1.0", None, "1.0; rm"),
                 ("1.0", "<1,<2,<3,<4,<5", None), (None, "*", None)):
        assert not versions.affected(*args)
        assert versions.check(*args) is None


def test_normalize_installed_strings():
    assert versions.normalize("v22.1.0") == "22.1.0"
    assert versions.normalize("claude-code/2.1.3") == "2.1.3"
    assert versions.normalize("2.1.3 (Claude Code)") == "2.1.3"
    assert versions.normalize(" 9.9p1 ") == "9.9p1"
    for bad in ("garbage", "", None, "1.2.3.4.5.6", "1.0-beta", "V1.0"):
        assert versions.normalize(bad) is None


def test_suffix_ordering():
    assert versions.affected("9.9", "<9.9p1", None)
    assert versions.affected("1.0rc1", "<1.0", None)
    assert versions.affected("1.0rc1", "<1.0rc2", None)
    assert not versions.affected("9.9p2", "<9.9p1", None)
    # PEP 440 spellings and phase order: dev < a < b < rc < release < p
    assert not versions.affected("3.14.0a2", "*", "3.14.0alpha1")
    assert versions.affected("3.14.0alpha1", "*", "3.14.0a2")
    assert versions.affected("1.0dev1", "<1.0b1", None)
    assert not versions.affected("1.0b2", None, "1.0beta1")
    assert versions.affected("1.0b9", None, "1.0c1")
    # a tag with no known order is unreadable, never compared by spelling
    assert versions.check("1.0q1", "<1.0", None) is None
    assert versions.check("1.0", None, "1.0zz1") is None


def test_match_claude_code_below_fixed():
    [m] = check.match([claude_adv()], CLAUDE_213)
    assert m.reason == "affected" and m.installed.version == "2.1.3"
    assert m.actions_allowed == [UPGRADE]


def test_no_match_when_version_at_fixed():
    at = inv(claude_code=[Installed("Claude Code", "2.1.4", "claude")])
    assert check.match([claude_adv()], at) == []
    assert check.match([claude_adv(affected=None)], at) == []


def test_scope_aliases_name_the_tool():
    for name in ("claude-code", "CLAUDE CODE", "@anthropic-ai/claude-code"):
        assert len(check.match([claude_adv(name=name)], CLAUDE_213)) == 1


def test_other_product_in_tool_ecosystem_does_not_match():
    node = inv(node=[Installed("Node.js", "22.11.0", "node")])
    a = adv([Product(name="undici", ecosystem="node", affected="<99", fixed="99")],
            [Action(verb="upgrade", target="undici", value=None)])
    assert check.match([a], node) == []


def test_skill_match_by_name():
    skills = inv(skill=[Installed("example-notes", None, "/x"), Installed("other", None, "/y")])
    disable = Action(verb="disable_skill", target="Example-Notes", value=None)
    elsewhere = Action(verb="disable_skill", target="other", value=None)
    a = adv([Product(name="EXAMPLE-NOTES", ecosystem="skill", affected="*", fixed=None)],
            [disable, elsewhere])
    [m] = check.match([a], skills)
    assert m.installed.name == "example-notes" and m.reason == check.MAY_APPLY
    assert m.actions_allowed == [disable]


def test_relay_bot_post_never_auto_applies():
    every = Config(auto_apply=frozenset(check.schema.VERBS))
    [m] = check.match([claude_adv(posted_by="relay-bot")], CLAUDE_213)
    p = check.plan(m, every)
    assert p.notify and p.auto_apply == [] and p.prepare == [UPGRADE_FIXED]


def test_curator_upgrade_auto_applies_when_opted_in():
    [m] = check.match([claude_adv()], CLAUDE_213)
    p = check.plan(m, OPT_IN)
    assert p.notify and p.prepare == []
    assert p.auto_apply == [UPGRADE_FIXED]


def test_curator_upgrade_not_opted_in_is_prepared():
    [m] = check.match([claude_adv()], CLAUDE_213)
    p = check.plan(m, Config())
    assert p.notify and p.auto_apply == [] and p.prepare == [UPGRADE_FIXED]


def test_upgrade_without_fixed_is_notify_only():
    [m] = check.match([claude_adv(affected="<2.1.4", fixed=None)], CLAUDE_213)
    assert m.reason == "affected"
    p = check.plan(m, OPT_IN)
    assert p.notify and p.auto_apply == [] and p.prepare == [UPGRADE]
    assert "no fixed version" in check.describe(p.prepare[0])


def test_unknown_verb_is_notify_only():
    odd = Action(verb="run_script", target="Claude Code", value="curl x | sh")
    [m] = check.match([claude_adv(actions=(odd, UPGRADE))], CLAUDE_213)
    p = check.plan(m, Config(auto_apply=frozenset({"upgrade", "run_script"})))
    assert p.notify and odd in p.prepare and odd not in p.auto_apply
    assert [a.verb for a in p.auto_apply] == ["upgrade"]
    assert "notify only" in check.describe(odd)


def test_unparsable_version_notifies_without_actions():
    weird = inv(claude_code=[Installed("Claude Code", "2.1.3", "claude")])
    [m] = check.match([claude_adv(affected="<2.1.4", fixed="2.1.4a1b")], weird)
    assert m.reason == "unparsable-version" and m.actions_allowed == []
    p = check.plan(m, OPT_IN)
    assert p.notify and p.auto_apply == [] and p.prepare == []


def test_upgrade_value_comes_from_product_fixed():
    stale = Action(verb="upgrade", target="Claude Code", value="2.0.0")
    for config in (OPT_IN, Config()):
        [m] = check.match([claude_adv(actions=(stale,))], CLAUDE_213)
        p = check.plan(m, config)
        assert (p.auto_apply + p.prepare) == [UPGRADE_FIXED]
    assert check.describe(UPGRADE_FIXED) == "upgrade Claude Code to 2.1.4 or later"


def test_scope_component_patterns_are_not_the_tool():
    docker = inv(docker=[Installed("Docker", "27.0.3", "docker")])
    for name in ("containerd", "moby", "opencontainers runc"):
        a = adv([Product(name=name, ecosystem="docker", affected=None, fixed="99")],
                [Action(verb="upgrade", target=name, value=None)])
        assert check.match([a], docker) == []


def test_destructive_verbs_need_their_own_ecosystem():
    both = inv(codex=[Installed("Codex", "0.50.0", "codex")],
               mcp=[Installed("codex", None, "/m")], skill=[Installed("codex", None, "/s")])
    remove = Action(verb="remove_mcp_server", target="codex", value=None)
    disable = Action(verb="disable_skill", target="codex", value=None)
    a = adv([Product(name="Codex", ecosystem="codex", affected="<1.0", fixed="1.0")],
            [remove, disable])
    every = Config(auto_apply=frozenset(check.schema.VERBS))
    [m] = check.match([a], both)
    assert m.installed.path == "codex" and m.actions_allowed == []
    assert check.plan(m, every).auto_apply == []
    a = adv([Product(name="codex", ecosystem="mcp", affected=None, fixed=None)], [remove, disable])
    [m] = check.match([a], both)
    assert m.actions_allowed == [remove]


def test_match_constructs_with_the_plan_fields():
    m = check.Match(claude_adv(), CLAUDE_213.products["claude-code"][0], [UPGRADE], "affected")
    assert m.product is None
    p = check.plan(m, OPT_IN)
    assert p.auto_apply == [] and p.prepare == [UPGRADE]


def test_hand_built_match_cannot_widen_auto_apply():
    claude = CLAUDE_213.products["claude-code"][0]
    every = Config(auto_apply=frozenset(check.schema.VERBS))
    evil = Action(verb="disable_skill", target="evil", value=None)
    other_tool = Action(verb="upgrade", target="codex", value=None)
    product = Product(name="Claude Code", ecosystem="claude-code", affected="<2.1.4", fixed="2.1.4")
    for m in (check.Match(claude_adv(), claude, [evil, other_tool], "affected", product),
              check.Match(claude_adv(fixed="2.1.0"), claude, [UPGRADE], "affected",
                          Product(name="Claude Code", ecosystem="claude-code",
                                  affected=None, fixed="2.1.0"))):
        assert check.plan(m, every).auto_apply == []


def test_name_matches_never_auto_apply():
    every = Config(auto_apply=frozenset(check.schema.VERBS))
    both = inv(skill=[Installed("demo", None, "/s")], mcp=[Installed("demo", None, "/m")])
    acts = [Action(verb="disable_skill", target="demo", value=None),
            Action(verb="remove_mcp_server", target="demo", value=None)]
    a = adv([Product(name="demo", ecosystem="skill", affected="*", fixed=None),
             Product(name="demo", ecosystem="mcp", affected=None, fixed=None)], acts)
    ms = check.match([a], both)
    assert [m.reason for m in ms] == [check.MAY_APPLY, check.MAY_APPLY]
    for m in ms:
        p = check.plan(m, every)
        assert p.notify and p.auto_apply == [] and len(p.prepare) == 1


def test_upgrade_naming_another_tool_is_dropped():
    a = claude_adv(actions=(Action(verb="upgrade", target="codex", value=None),))
    [m] = check.match([a], CLAUDE_213)
    assert m.actions_allowed == []


def test_products_with_different_ranges_each_match():
    a = adv([Product(name="Claude Code", ecosystem="claude-code", affected=None, fixed=f)
             for f in ("2.1.4", "2.1.5")], [UPGRADE])
    ms = check.match([a], CLAUDE_213)
    assert sorted(check.plan(m, OPT_IN).auto_apply[0].value for m in ms) == ["2.1.4", "2.1.5"]
    a = adv([Product(name="Claude Code", ecosystem="claude-code", affected="<2.1.4", fixed="2.1.4zz1"),
             Product(name="Claude Code", ecosystem="claude-code", affected="<2.1.4", fixed="2.1.4")],
            [UPGRADE])
    assert [m.reason for m in check.match([a], CLAUDE_213)] == ["unparsable-version", "affected"]


def test_hand_built_match_must_agree_with_its_advisory():
    every = Config(auto_apply=frozenset(check.schema.VERBS))
    claude = CLAUDE_213.products["claude-code"][0]
    product = Product(name="Claude Code", ecosystem="claude-code", affected="<2.1.4", fixed="2.1.4")
    rotate = Action(verb="rotate_credential", target="api key", value=None)
    bare = Product(name="Claude Code", ecosystem="claude-code", affected=None, fixed=None)
    cases = [
        check.Match(claude_adv(actions=()), claude, [UPGRADE], "affected", product),
        check.Match(claude_adv(fixed="2.1.9"), claude, [UPGRADE], "affected", product),
        check.Match(claude_adv(), Installed("Codex", "2.1.3", "codex"), [UPGRADE], "affected", product),
        check.Match(adv([bare], [rotate]), claude, [rotate], "affected", bare),
    ]
    for m in cases:
        assert check.plan(m, every).auto_apply == []


def test_two_products_naming_one_install_match_once():
    rotate = Action(verb="rotate_credential", target="api key", value=None)
    a = adv([Product(name=n, ecosystem="claude-code", affected="<2.1.4", fixed="2.1.4")
             for n in ("Claude Code", "claude-code")], [rotate])
    [m] = check.match([a], CLAUDE_213)
    assert m.actions_allowed == [rotate]


def test_prerelease_install_is_unparsable_end_to_end():
    from aitools_alerts import inventory
    outputs = {"node --version": "v22.1.0-rc.1\n", "claude --version": "claude-code/2.1.3\n",
               "docker --version": "Docker version 27.0.0-rc.1, build abc\n"}
    got = inventory.collect(Path("/nonexistent"), runner=lambda argv: outputs.get(" ".join(argv)),
                            apps_dirs=[])
    assert got.products["claude-code"][0].version == "2.1.3"
    assert got.products["node"][0].version == "22.1.0-rc.1"
    a = adv([Product(name="Node.js", ecosystem="node", affected="<22.2.0", fixed="22.2.0")],
            [Action(verb="upgrade", target="node", value=None)])
    [m] = check.match([a], got)
    assert m.reason == "unparsable-version" and m.actions_allowed == []
    p = check.plan(m, OPT_IN)
    assert p.notify and p.auto_apply == []


# ------------------------------------------------ components (ai-tools-alerts#qme5)

def _containerd_post(posted_by="curator"):
    from aitools_alerts import schema
    from aitools_alerts.poster import candidates, compose, rules
    c = candidates.Candidate(
        id="CVE-2026-0901", aliases=(), product_text="containerd containerd", advisory_severity=None,
        local_level_hint=None, exploited=True, trojanized=False, injection_exec=False, fixed="1.7.29",
        affected="< 1.7.29", observed_at=None,
        sources=(candidates.Source("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", None),))
    text, _ = compose.root_post(c, "critical", rules.scope_of(c.product_text), posted_at=1_700_000_000)
    a = schema.parse_post(text)
    return dataclasses.replace(a, posted_by=posted_by)


CONTAINERD = Installed("containerd", "1.7.20", "containerd")


def test_component_advisory_matches_component_installation():
    [m] = check.match([_containerd_post()], inv(docker=[CONTAINERD]))
    assert m.reason == check.AFFECTED and m.installed == CONTAINERD
    assert check.match([_containerd_post()], inv(docker=[Installed("Docker", "27.3.1", "docker")])) == []


def test_docker_advisory_does_not_match_containerd():
    a = adv([Product(name="Docker", ecosystem="docker", affected="<27.4.0", fixed="27.4.0")],
            [Action(verb="upgrade", target="Docker", value="27.4.0")])
    assert check.match([a], inv(docker=[CONTAINERD])) == []


def test_component_installation_never_auto_applies():
    [m] = check.match([_containerd_post()], inv(docker=[CONTAINERD]))
    p = check.plan(m, Config(auto_apply=frozenset({"upgrade"})))
    assert p.auto_apply == [] and [a.target for a in p.prepare] == ["containerd"]


def test_aggregate_components_match_by_name():
    remote = adv([Product(name="mcp-remote", ecosystem="mcp", affected=None, fixed="0.1.16")], [])
    assert len(check.match([remote], inv(mcp=[Installed("mcp-remote", None, "/m")]))) == 1
    assert check.match([remote], inv(mcp=[Installed("filesystem", None, "/m")])) == []


# ---------------------------------------------- package and source identity (0xq6)

def _mcp(name, version=None, package=None, server=None, path="/c"):
    return Installed(name, version, path, package=package, server=server)


GIT = Product(name="mcp-server-git", ecosystem="mcp", affected="<0.6.3", fixed="0.6.3")


def test_mcp_package_match_compares_the_pinned_version():
    a = adv([GIT], [Action("remove_mcp_server", "mcp-server-git", None)])
    pinned = _mcp("mcp-server-git", "0.6.2", "pypi:mcp-server-git", "git")
    [m] = check.match([a], inv(mcp=[pinned]))
    assert m.reason == check.AFFECTED and m.actions_allowed == a.actions
    assert check.match([a], inv(mcp=[_mcp("mcp-server-git", "0.6.3", "pypi:mcp-server-git")])) == []
    [m] = check.match([a], inv(mcp=[_mcp("mcp-server-git", None, "pypi:mcp-server-git")]))
    assert m.reason == check.MAY_APPLY


def test_an_npm_package_with_a_pypi_servers_name_does_not_match():
    a = adv([GIT], [])
    assert check.match([a], inv(mcp=[_mcp("mcp-server-git", "0.1.0", "npm:mcp-server-git")])) == []
    [m] = check.match([a], inv(mcp=[_mcp("mcp-server-git")]))  # a key alone: by name
    assert m.reason == check.MAY_APPLY


def test_the_configured_key_still_matches_and_names_the_server():
    a = adv([Product("my-git", "mcp", None, None)], [Action("remove_mcp_server", "my-git", None)])
    [m] = check.match([a], inv(mcp=[_mcp("mcp-server-git", "0.6.2", "pypi:mcp-server-git", "my-git")]))
    assert m.reason == check.MAY_APPLY and m.actions_allowed == a.actions


def test_every_version_with_package_identity_is_affected():
    every = Product("mcp-server-git", "mcp", "*", None)
    a = adv([every], [Action("remove_mcp_server", "mcp-server-git", None)])
    [m] = check.match([a], inv(mcp=[_mcp("mcp-server-git", None, "pypi:mcp-server-git")]))
    assert m.reason == check.AFFECTED
    opted = Config(auto_apply=frozenset({"remove_mcp_server"}))
    assert check.plan(m, opted).auto_apply == []  # no readable version: never auto-applied
    [m] = check.match([a], inv(mcp=[_mcp("mcp-server-git")]))  # name only
    assert m.reason == check.MAY_APPLY


@pytest.mark.parametrize("order", [0, 1])
def test_an_uncertain_installation_does_not_hide_an_affected_one(order):
    a = adv([GIT], [])
    both = [_mcp("mcp-server-git", None, "pypi:mcp-server-git", "a", "/one"),
            _mcp("mcp-server-git", "0.6.2", "pypi:mcp-server-git", "b", "/two")]
    ms = check.match([a], inv(mcp=both[::-1] if order else both))
    assert sorted(m.reason for m in ms) == sorted([check.AFFECTED, check.MAY_APPLY])


def test_a_marketplace_qualified_product_matches_only_that_plugin():
    plugin = Installed("demo", None, "/p", source="market")
    other_market = Installed("demo", None, "/q", source="elsewhere")
    named_dir = Installed("demo@market", None, "/s")  # a skill directory with that literal name
    a = adv([Product("demo@market", "skill", "*", None)], [Action("disable_skill", "demo@market", None)])
    [m] = check.match([a], inv(skill=[plugin, other_market, named_dir]))
    assert m.installed == plugin and m.reason == check.AFFECTED and m.actions_allowed == a.actions
    b = adv([Product("demo", "skill", "*", None)], [])
    assert {m.installed for m in check.match([b], inv(skill=[plugin, other_market]))} == {plugin, other_market}
    assert all(m.reason == check.MAY_APPLY for m in check.match([b], inv(skill=[plugin, other_market])))


def test_hermes_and_openclaw_match_their_scope_products():
    for name, eco in (("Hermes", "hermes"), ("OpenClaw", "openclaw")):
        a = adv([Product(name, eco, "<2.0", "2.0")], [])
        [m] = check.match([a], inv(**{eco: [Installed(name, "1.0", "/x")]}))
        assert m.reason == check.AFFECTED


@pytest.mark.parametrize("order", [0, 1])
def test_a_may_apply_product_cannot_hide_an_affected_one(order):
    plugin = Installed("demo", None, "/p", source="market")
    prods = [Product("demo", "skill", "*", None), Product("demo@market", "skill", "*", None)]
    a = adv(prods[::-1] if order else prods, [])
    assert sorted(m.reason for m in check.match([a], inv(skill=[plugin]))) == sorted([check.AFFECTED, check.MAY_APPLY])


def test_a_scoped_plugin_name_matches_unqualified():
    plugin = Installed("@scope/x", None, "/p", source="market")
    a = adv([Product("@scope/x", "skill", "*", None)], [])
    [m] = check.match([a], inv(skill=[plugin]))
    assert m.reason == check.MAY_APPLY
    b = adv([Product("@scope/x@market", "skill", "*", None)], [])
    [m] = check.match([b], inv(skill=[plugin]))
    assert m.reason == check.AFFECTED


# ------------------------------------------------------------------ one product identity (ai-tools-alerts#2mgd)

def _scope():
    from aitools_alerts import ruleset, schema
    return {e.name: e for e in ruleset.index(schema.load_scope()).values()}


def test_every_scope_product_is_itself_under_its_ecosystem():
    scope = _scope()
    assert scope and all(check.scope_name(n, e.ecosystem) == n for n, e in scope.items())


@pytest.mark.parametrize("name, ecosystem, want", [
    ("claude code", "claude-code", "Claude Code"), ("claude-code", "claude-code", "Claude Code"),
    ("@anthropic-ai/claude-code", "claude-code", "Claude Code"), ("CLAUDE CODE", "claude-code", "Claude Code"),
    ("codex", "codex", "Codex"), ("rustc", "rust", "Rust"), ("rustup", "rust", "rustup"),
    ("containerd", "docker", "containerd"), ("docker", "docker", "Docker"),
    ("pypi:mcp-server-git", "mcp", "mcp-server-git"), ("MCP-Server-Git", "mcp", "mcp-server-git"),
    ("Claude Code", "skill", None),  # an installed skill of that name is not the tool
    ("Claude Code", "codex", None), ("claude-code-router", "claude-code", None), ("claude", "claude-code", None),
    ("MCP servers and clients", "mcp", None),  # a former name stands for several entries
    ("Claude Code", "no-such-ecosystem", None), ("", "claude-code", None),
])
def test_a_posted_product_is_the_scope_product_match_cannot_tell_it_from(name, ecosystem, want):
    assert check.scope_name(name, ecosystem) == want


def test_scope_name_never_raises():
    assert check.scope_name(None, "claude-code") is None and check.scope_name("Claude Code", None) is None


def test_a_name_resolves_to_a_tool_exactly_when_match_takes_it_for_the_tool_s_installation():
    """The rule is match's own: for every tool, every name of its identity set, and a
    name outside it, the tool's installation matches the posted name if and only if it
    matches the scope product the name resolves to."""
    scope = _scope()
    for ecosystem, names in check.IDENTITY.items():
        tool = next(n for n, e in scope.items() if e.ecosystem == ecosystem and n.lower() in names | {ecosystem})
        there = Inventory(products={ecosystem: [Installed(tool, "1.0.0", "/invented")]})

        def hit(name):
            return bool(check.match([adv([Product(name, ecosystem, "*", None)], [])], there))
        for name in sorted(names | {ecosystem, tool, tool.upper(), "no such product"}):
            got = check.scope_name(name, ecosystem)
            assert hit(name) == (got is not None and hit(got)), (ecosystem, name)
            assert got in (None, tool), (ecosystem, name)


@pytest.mark.parametrize("order", [("my-git", "mcp-server-git"), ("mcp-server-git", "my-git")])
def test_an_entry_that_is_no_scope_product_does_not_hide_one_that_is(order):
    """An MCP installation is matched by its package and by its configured key. An entry
    under the key, with the same range, must not stand in for the entry under the scope
    name: that one is what the source check can judge. Two spellings of one scope
    product still collapse."""
    there = inv(mcp=[Installed("mcp-server-git", "0.6.2", "/m", package="pypi:mcp-server-git", server="my-git")])
    ms = check.match([adv([Product(n, "mcp", "*", "0.7.0") for n in order], [])], there)
    assert [m.product.name for m in ms] == list(order)
    same = check.match([adv([Product(n, "mcp", "*", "0.7.0") for n in ("MCP-Server-Git", "mcp-server-git")], [])], there)
    assert [m.product.name for m in same] == ["MCP-Server-Git"]
