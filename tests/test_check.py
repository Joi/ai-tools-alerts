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
    assert m.installed.name == "example-notes" and m.reason == "name"
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
    assert [m.reason for m in ms] == ["name", "name"]
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
