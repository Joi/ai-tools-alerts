import json
from dataclasses import fields, replace
from pathlib import Path

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import rules
from aitools_alerts.schema import (
    LEVELS, ROLES, VERBS, Action, Advisory, Product, Source,
    is_primary, load_primary_domains, load_scope, parse_post, render_post,
)

ROOT = Path(__file__).resolve().parent.parent
POSTS = ROOT / "tests" / "fixtures" / "posts"
SPEC = ROOT / "spec"


def valid_text() -> str:
    return (POSTS / "valid-critical.md").read_text()


def valid_block() -> dict:
    text = valid_text()
    return json.loads(text.split("```aitools-alert\n", 1)[1].split("\n```", 1)[0])


def post_with(block) -> str:
    raw = block if isinstance(block, str) else json.dumps(block)
    return f"body\n\n```aitools-alert\n{raw}\n```\n"


# ------------------------------------------------------------- plan tests

def test_parse_valid_post_fixture():
    adv = parse_post(valid_text())
    assert adv is not None
    assert adv.id == "AITA-TEST-0001"
    assert adv.level == "critical"
    assert adv.products == [Product("Claude Code", "claude-code", "<2.1.0", "2.1.0")]
    assert adv.actions == [Action("upgrade", "Claude Code", "2.1.0")]
    assert adv.sources[0].url.startswith("https://github.com/anthropics/")
    assert adv.posted_by == "relay-bot"
    assert adv.expires_at is None


def test_parse_ignores_block_without_info_string():
    assert parse_post((POSTS / "no-info-string.md").read_text()) is None


def test_unknown_verb_rejected():
    assert parse_post((POSTS / "unknown-verb.md").read_text()) is None


def test_unknown_level_rejected():
    b = valid_block()
    b["level"] = "urgent"
    assert parse_post(post_with(b)) is None


def test_render_then_parse_roundtrip():
    adv = parse_post(valid_text())
    out = render_post(adv, "CRITICAL: a body line\n")
    assert out.startswith("CRITICAL: a body line\n\n```aitools-alert\n")
    assert parse_post(out) == adv
    other = replace(adv, title="日本語のタイトル", aliases=[], expires_at=adv.posted_at + 1)
    assert parse_post(render_post(other, "body")) == other


def test_primary_domain_github_only_under_advisories_paths():
    assert is_primary("https://github.com/anthropics/claude-code/security/advisories/GHSA-x")
    assert is_primary("https://github.com/advisories/GHSA-x")
    assert not is_primary("https://github.com/foo/bar/issues/1")
    assert not is_primary("https://github.com/foo/bar")
    assert is_primary("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")


def test_scope_classes_loaded():
    by_name = {e.name: e for e in load_scope()}
    assert by_name["Claude Code"].scope_class == "channel"
    assert by_name["@modelcontextprotocol/sdk"].scope_class == "catalog"
    assert by_name["macOS"].scope_class == by_name["OpenSSH"].scope_class == "out"
    assert len(by_name) == 29
    assert {e.scope_class for e in by_name.values()} == {"channel", "catalog", "out"}
    assert {n for n, e in by_name.items() if e.channel_if} == {"@modelcontextprotocol/inspector", "git"}


def test_mcp_items_are_named_by_their_package():
    """wa6n: no pseudo-product; an MCP server or client is the package a member installs."""
    entries = load_scope()
    names = {n for e in entries for n in (e.name, *(c.name for c in e.components))}
    old = {"MCP servers and clients", "MCP Inspector", "MCP Python SDK", "MCP TypeScript SDK"}
    assert not old & names and {f for e in entries for f in e.formerly} == old
    mcp = [e for e in entries if e.package and ("modelcontextprotocol" in e.package or "mcp" in e.package.split(":")[1])]
    assert len(mcp) == 11
    for e in mcp:
        # The wire keeps ecosystem mcp: released readers list MCP servers under it.
        assert e.ecosystem == "mcp" and e.package.split(":", 1)[1] == e.name and e.package in e.match, e.name
    assert rules.scope_of("pypi:mcp-server-git").name == rules.scope_of("pip:mcp-server-git").name == "mcp-server-git"
    assert rules.scope_of("npm:@anthropic-ai/claude-code").name == "Claude Code"  # a package is an identity
    for text in ("mcp server", "model context protocol", "modelcontextprotocol/servers", "mcp-server-gitlab"):
        assert rules.scope_of(text) is None, text


# ---------------------------------------------------------- contract tests

def test_dataclass_fields_equal_schema_required_keys():
    js = json.loads((SPEC / "advisory.schema.json").read_text())
    assert [f.name for f in fields(Advisory)] == js["required"]
    for cls, key in ((Product, "product"), (Action, "action"), (Source, "source")):
        d = js["$defs"][key]
        assert [f.name for f in fields(cls)] == d["required"]
        assert set(d["properties"]) == set(d["required"])
    assert set(js["properties"]) == set(js["required"])


def test_spec_files_agree_with_constants():
    loaded = {p.name: json.loads(p.read_text()) for p in SPEC.glob("*.json")}
    assert set(loaded) == {"advisory.schema.json", "actions.json", "scope.json",
                           "primary-domains.json", "channels.json", "ruleset.json", "claim-vectors.json",
                           "catalog-channel.json"}
    # the catalog channel (q3fd) loads as the poster reads it, and names neither alert channel
    from aitools_alerts.poster import inputs
    assert inputs.load_catalog_channel(loaded["channels.json"]) == loaded["catalog-channel.json"]["catalog"]
    assert {v["verb"] for v in loaded["actions.json"]["verbs"]} == VERBS
    js = loaded["advisory.schema.json"]
    assert set(js["$defs"]["action"]["properties"]["verb"]["enum"]) == VERBS
    assert set(js["properties"]["level"]["enum"]) == LEVELS
    assert set(js["properties"]["posted_by"]["enum"]) == ROLES
    assert sorted(VERBS) == ["disable_skill", "remove_mcp_server", "review_setting",
                             "rotate_credential", "stop_using", "upgrade"]
    assert sorted(LEVELS) == ["critical", "high", "notice"]


# ------------------------------------------------------- hardening tests

def test_last_block_wins():
    first = valid_block()
    second = dict(valid_block(), id="AITA-TEST-0002", level="high")
    content = post_with(first) + "\nupdate\n\n" + post_with(second)
    assert parse_post(content).id == "AITA-TEST-0002"


def test_invalid_last_block_does_not_fall_back():
    bad = dict(valid_block(), level="urgent")
    assert parse_post(post_with(valid_block()) + post_with(bad)) is None


def test_block_quoted_inside_longer_fence_is_ignored():
    quoted = "example:\n\n````markdown\n" + post_with(valid_block()) + "````\n"
    assert parse_post(quoted) is None
    # a real block after the quote still parses
    assert parse_post(quoted + post_with(valid_block())) is not None


def test_unclosed_block_ignored():
    content = "body\n\n```aitools-alert\n" + json.dumps(valid_block()) + "\n"
    assert parse_post(content) is None


def test_unfinished_last_block_does_not_restore_earlier_block():
    content = post_with(valid_block()) + "\nupdate\n\n```aitools-alert\n{\"id\": \"AITA"
    assert parse_post(content) is None


def test_block_inside_tilde_or_indented_fence_is_ignored():
    inner = post_with(valid_block())
    assert parse_post("~~~\n" + inner + "~~~\n") is None
    assert parse_post("   ```text\n" + inner + "   ```\n") is None
    assert parse_post("  ```aitools-alert\n" + json.dumps(valid_block()) + "\n```\n") is None
    with pytest.raises(ValueError):
        render_post(parse_post(valid_text()), "look:\n~~~\nunclosed")


def test_deep_nesting_rejected_without_exception():
    deep = '{"id": ' + "[" * 30000 + "]" * 30000 + "}"
    assert len(deep.encode()) < schema.MAX_BLOCK_BYTES  # reaches the decoder
    with pytest.raises(ValueError):  # RecursionError on some builds; never escapes
        schema.decode_block(deep)
    assert parse_post(post_with(deep)) is None


def test_recursion_error_is_contained(monkeypatch):
    post = post_with(valid_block())

    def boom(*a, **k):
        raise RecursionError
    monkeypatch.setattr(schema.json, "loads", boom)
    with pytest.raises(ValueError, match="nested"):
        schema.decode_block("{}")
    assert parse_post(post) is None


def test_surrogates_rejected():
    raw = json.dumps(valid_block()).replace("Claude Code test advisory", "\\ud800")
    assert "\\ud800" in raw
    assert parse_post(post_with(raw)) is None


def test_info_string_is_exact():
    raw = json.dumps(valid_block())
    for opener in ("```aitools-alert-v2", "```aitools-alertx", " ```aitools-alert",
                   "~~~aitools-alert"):
        assert parse_post(f"b\n\n{opener}\n{raw}\n```\n") is None
    assert parse_post(f"b\n\n```aitools-alert  \n{raw}\n```  \n") is not None


def test_duplicate_keys_rejected():
    raw = json.dumps(valid_block())[:-1] + ', "level": "notice"}'
    assert parse_post(post_with(raw)) is None


def test_unknown_or_missing_key_rejected():
    assert parse_post(post_with(dict(valid_block(), run="sh -c x"))) is None
    b = valid_block()
    del b["expires_at"]
    assert parse_post(post_with(b)) is None
    b = valid_block()
    b["products"][0]["install"] = "curl x | sh"
    assert parse_post(post_with(b)) is None


def test_bool_is_not_an_int():
    assert parse_post(post_with(dict(valid_block(), posted_at=True))) is None
    assert parse_post(post_with(dict(valid_block(), posted_at=1.5))) is None
    assert parse_post(post_with(valid_block()).replace("4070908800", "NaN")) is None


def test_shell_metacharacters_in_versions_rejected():
    for fixed in ("2.1.0; rm -rf ~", "2.1.0 && x", "$(id)", "2.1.0`x`", "2.1.0\n"):
        b = valid_block()
        b["products"][0]["fixed"] = fixed
        assert parse_post(post_with(b)) is None, fixed
    for affected in (">=1.0,<2.1.0 | x", "garbage", "<latest", ""):
        b = valid_block()
        b["products"][0]["affected"] = affected
        assert parse_post(post_with(b)) is None, affected
    for fixed in ("latest", "---", "v2.1.0"):
        b = valid_block()
        b["products"][0]["fixed"] = fixed
        assert parse_post(post_with(b)) is None, fixed
    for affected, fixed in (("*", "9.9p1"), (">=1.0,<2.1.0", "2.1.0"), ("<=3", None)):
        b = valid_block()
        b["products"][0].update(affected=affected, fixed=fixed)
        assert parse_post(post_with(b)) is not None, affected


def test_action_arguments_have_no_shell_syntax():
    for target in ("x; rm -rf ~", "$(id)", "`id`", "-rf", "a'b", 'a"b', "a|b", "a>b"):
        b = valid_block()
        b["actions"][0]["target"] = target
        assert parse_post(post_with(b)) is None, target
        b = valid_block()
        b["actions"][0]["value"] = target
        assert parse_post(post_with(b)) is None, target
    b = valid_block()
    b["actions"] = [{"verb": "review_setting", "target": "~/.claude/settings.json",
                     "value": "permissions.allow"},
                    {"verb": "stop_using", "target": "@scope/pkg", "value": None}]
    assert parse_post(post_with(b)) is not None


def test_schema_file_patterns_match_module():
    js = json.loads((SPEC / "advisory.schema.json").read_text())
    prod = js["$defs"]["product"]["properties"]
    import re
    cases = ["*", "<2.1.0", ">=1.0,<2.1.0", "9.9p1", "2.1.0", "garbage", "<2 | x", "latest"]
    for key, rx in (("affected", schema._AFFECTED), ("fixed", schema._FIXED)):
        for c in cases:
            assert bool(re.search(prod[key]["pattern"], c)) == bool(rx.fullmatch(c)), (key, c)
    arg = js["$defs"]["arg"]["pattern"]
    for c in ["Claude Code", "-rf", "a;b", "~/.x", "@s/p", "$(id)"]:
        assert bool(re.search(arg, c)) == bool(schema._ARG.fullmatch(c)), c


def test_newline_or_bidi_in_text_rejected():
    for title in ("a\nb", "a‮b", "a\x00b", ""):
        assert parse_post(post_with(dict(valid_block(), title=title))) is None
    b = valid_block()
    b["actions"][0]["target"] = "Claude Code\r\nrm -rf /"
    assert parse_post(post_with(b)) is None


def test_non_https_source_rejected():
    for url in ("http://cisa.gov/x", "file:///etc/passwd", "javascript:alert(1)", "https://"):
        b = valid_block()
        b["sources"][0]["url"] = url
        assert parse_post(post_with(b)) is None, url
    assert parse_post(post_with(dict(valid_block(), sources=[]))) is None
    assert parse_post(post_with(dict(valid_block(), products=[]))) is None


def test_expires_before_posted_rejected():
    assert parse_post(post_with(dict(valid_block(), expires_at=1))) is None


def test_oversized_block_rejected():
    raw = json.dumps(valid_block())
    big = raw[:-1] + " " * schema.MAX_BLOCK_BYTES + "}"
    assert schema.validate(json.loads(big)) is not None  # valid JSON, only too big
    assert parse_post(post_with(big)) is None
    many = "\n".join("x" * 100 for _ in range(1000))  # 101 kB in 1000 lines
    assert parse_post(f"b\n\n```aitools-alert\n{many}\n```\n" + post_with(raw)) is not None
    assert parse_post(post_with(raw) + f"```aitools-alert\n{many}\n```\n") is None
    post = post_with(raw)
    pad = "x" * (schema.MAX_POST_CHARS - len(post) - 1) + "\n"
    assert parse_post(pad + post) is not None  # exactly at the post limit
    assert parse_post("x" + pad + post) is None  # one character over


def test_block_exactly_at_byte_limit_accepted():
    raw = json.dumps(valid_block())
    exact = raw[:-1] + " " * (schema.MAX_BLOCK_BYTES - len(raw.encode())) + "}"
    assert len(exact.encode()) == schema.MAX_BLOCK_BYTES
    assert parse_post(post_with(exact)) is not None
    assert parse_post(post_with(exact[:-1] + " }")) is None


def test_render_rejects_body_with_unclosed_fence():
    adv = parse_post(valid_text())
    with pytest.raises(ValueError):
        render_post(adv, "look:\n````\nunclosed")
    with pytest.raises(ValueError):
        render_post(replace(adv, level="urgent"), "body")


def test_is_primary_rejects_lookalikes():
    for url in (
        "https://cisa.gov@evil.example/",
        "https://evil.example@cisa.gov/",
        "http://www.cisa.gov/x",
        "https://www.cisa.gov:8443/x",
        "https://cisa.gov.evil.example/x",
        "https://evilcisa.gov/x",
        "https://community.openai.com/t/1",
        "https://forum.cursor.com/t/1",
        "https://discuss.python.org/t/1",
        "https://github.com/a/b/security/advisories/../../issues/1",
        "https://github.com/a/b/security/advisories/%2e%2e/x",
        "https://github.com/a/security/advisories/x",
        "https://github.com/a/b/security/advisories/",
        "https://github.com/advisories/",
        "https://github.com/attacker/claude-code/security/advisories/GHSA-x",
        "https://go.dev/play/p/abc123",
        "https://go.dev/issue/1",
        "https://www.python.org/jobs/8195/",
        "https://www.python.org/community/jobs/howto/",
        "https://github.com//advisories/x",
        "https://gist.github.com/advisories/x",
        "https://github.com\\@evil.example/advisories/x",
        "https://www.cisa.gov /x",
        "https://cisa.gov../x",
        "not a url",
        "",
    ):
        assert not is_primary(url), url


def test_is_primary_accepts_www_trailing_dot_and_case():
    assert is_primary("https://cisa.gov./x")
    assert is_primary("https://WWW.CISA.GOV/x")
    assert is_primary("https://kb.cert.org/vuls/id/1")
    assert is_primary("https://cisa.gov:443/x")
    assert is_primary("https://github.com/anthropics/claude-code/security/advisories/GHSA-x/")
    assert is_primary("https://github.com/advisories/GHSA-x?q=1#f")
    assert is_primary("https://github.com/Anthropics/claude-code/security/advisories/GHSA-x")
    assert is_primary("https://go.dev/doc/security/vuln/")
    assert is_primary("https://www.python.org/downloads/release/python-3135/")


def test_load_scope_rejects_bad_entries(tmp_path):
    good = {"name": "X", "ecosystem": "x", "class": "channel", "match": ["x", "npm:@x/y"],
            "authority": ["anthropic.com/", "github.com/anthropics/claude-code/"]}
    p = tmp_path / "scope.json"

    def load(*entries, **top):
        p.write_text(json.dumps({"version": 6, "entries": list(entries), **top}))
        return load_scope(p)

    assert load(good)[0].authority == ("anthropic.com/", "github.com/anthropics/claude-code/")  # the control
    for bad in (dict(good, match=["Upper"]), dict(good, match=[]), dict(good, match=["two  spaces"]),
                dict(good, match=[" x"]), dict(good, match=["x", "x"]),  # an identity listed twice
                dict(good, match=["tool\u2013code"]),  # the lookup reads a Unicode dash as "-": one spelling only
                dict(good, tier=1), dict(good, **{"class": "tier1"}), dict(good, **{"class": True}),
                dict(good, extra=1), dict(good, channel_if="code-execution"),  # a channel entry needs none
                dict(good, **{"class": "out"}, channel_if="any"), dict(good, package="npm:@x/y"),  # listed twice
                dict(good, package="NPM:z"), dict(good, package="z"), dict(good, package="npm:Z"),
                dict(good, package=["npm:z"]), dict(good, components=[{"name": "C"}]),
                dict(good, **{"class": "out"}, channel_if=[]), dict(good, **{"class": "out"}, channel_if={}),
                dict(good, **{"class": ["out"]}), dict(good, formerly=[]), dict(good, formerly="Old"), dict(good, formerly=["X"]),  # its own name
                dict(good, match_mode="word"), dict(good, not_match=["y"]),  # the word rule is gone (h340)
                dict(good, authority=["github.com/anthropics/"]),  # an owner is not a product
                dict(good, authority=["github.com/attacker/claude-code-router/"]),  # owner not on the primary list
                dict(good, authority=["github.com/anthropics/claude-code/security/"]),
                dict(good, authority=["outside.example/"]), dict(good, authority=["Anthropic.com/"]),
                dict(good, authority=["anthropic.com"]), dict(good, authority=["https://anthropic.com/"]),
                dict(good, authority="anthropic.com/"),
                dict(good, components=[{"name": "C", "match": ["c"], "not_match": ["d"]}]),
                dict(good, components=[{"name": "C", "match": ["x"]}])):  # an identity of its own entry
        with pytest.raises(ValueError):
            load(bad)
    with pytest.raises(ValueError):
        load(good, good)
    with pytest.raises(ValueError):  # the same identity under two products
        load(good, {"name": "Y", "ecosystem": "y", "class": "channel", "match": ["npm:@x/y"]})
    got = load(dict(good, **{"class": "out"}, channel_if="code-execution", package="pypi:x-y"))[0]
    assert (got.scope_class, got.channel_if, got.package, got.match[-1]) == ("out", "code-execution", "pypi:x-y", "pypi:x-y")
    with pytest.raises(ValueError):
        load(good, match_mode="word")
    for version in (4, 5, 7, "6", True):  # version 6 is the only one read: an old poster cannot word-match this file
        p.write_text(json.dumps({"version": version, "entries": [good]}))
        with pytest.raises(ValueError):
            load_scope(p)
    comp = load(dict(good, components=[{"name": "C", "match": ["c"], "authority": []}, {"name": "D", "match": ["d"]}]))
    assert [c.authority for c in comp[0].components] == [(), None]


def test_authority_is_inside_primary_domains():
    """Every authority prefix of the shipped scope file is on the primary-source list,
    and on github.com names one repository of a listed owner."""
    domains = load_primary_domains()
    seen = 0
    for e in load_scope():
        for prefix in [*e.authority, *(a for c in e.components for a in c.authority or ())]:
            host, *segs = prefix[:-1].split("/")
            assert host in domains, prefix
            if host == "github.com":
                assert len(segs) == 2 and segs[0] in domains[host]["owners"], prefix
            assert is_primary(f"https://{prefix}security/advisories/GHSA-x" if host == "github.com"
                              else f"https://{prefix}security/x") or domains[host]["paths"], prefix
            seen += 1
    assert seen > 20


# ------------------------------------------------- stage-1 review fixes

def test_only_commonmark_line_endings_split_lines():
    hidden = dict(valid_block(), id="HIDDEN")
    for sep in (" ", "\x0c", "\x0b", "\x85", " "):
        assert parse_post(f"intro{sep}```aitools-alert\n{json.dumps(hidden)}\n```\n") is None, sep
    crlf = post_with(valid_block()).replace("\n", "\r\n")
    assert parse_post(crlf) is not None


def test_line_separators_and_zero_width_rejected_in_text():
    for title in ("a b", "a b", "a​b", "a﻿b"):
        assert parse_post(post_with(dict(valid_block(), title=title))) is None, repr(title)
    assert not is_primary("https://github.com/advisories/GHSA-x​")


def test_action_arguments_per_verb():
    def with_action(verb, target, value=None):
        b = valid_block()
        b["actions"] = [{"verb": verb, "target": target, "value": value}]
        return parse_post(post_with(b))
    assert with_action("upgrade", "Claude Code", "2.1.0 --registry=https://evil.example") is None
    assert with_action("upgrade", "Claude Code", "latest") is None
    assert with_action("upgrade", "Claude Code --global", "2.1.0") is None
    for name in ("../../..", "/", "a/b", "x..y", "~/.claude"):
        assert with_action("disable_skill", name) is None, name
        assert with_action("remove_mcp_server", name) is None, name
    assert with_action("review_setting", "~/.claude/../.ssh/config") is None
    assert with_action("disable_skill", "evil-skill") is not None
    assert with_action("remove_mcp_server", "@scope/server-x") is not None


def test_timestamps_bounded():
    assert parse_post(post_with(dict(valid_block(), posted_at=10**300))) is None
    assert parse_post(post_with(dict(valid_block(), expires_at=schema.MAX_TIMESTAMP + 1))) is None
    assert parse_post(post_with(dict(valid_block(), expires_at=schema.MAX_TIMESTAMP))) is not None


def test_uppercase_scheme_rejected_like_the_schema():
    b = valid_block()
    b["sources"][0]["url"] = "HTTPS://cisa.gov/x"
    assert parse_post(post_with(b)) is None


def test_render_post_type_errors_are_value_errors():
    with pytest.raises(ValueError):
        render_post({"id": "x"}, "body")
    with pytest.raises(ValueError):
        render_post(parse_post(valid_text()), None)


def test_scope_identities_and_ecosystems():
    entries = load_scope()
    ids = [m for e in entries for m in [*e.match, *(m for c in e.components for m in c.match)]]
    assert len(ids) == len(set(ids)) and all(m == m.lower().strip() for m in ids)
    for text in ("rust cargo", "truncate", "cargo", "python", "go", "git", "rust", "cursor", "anthropic"):
        assert text not in ids, text  # a bare common word is nobody's identity
    for text in ("anthropic claude code", "apple macos", "opencontainers runc", "npm:@anthropic-ai/claude-code"):
        assert text in ids, text
    assert [e.ecosystem for e in entries] == [
        "claude-code", "codex", "cursor", "gemini-cli", "hermes", "openclaw",
        *["mcp"] * 11, "skill",
        "node", "python", "go", "rust", "docker", "tailscale", "openssh", "git",
        "macos", "linux", "browser"]


def test_primary_domains_are_the_plan_hosts():
    hosts = set(schema.load_primary_domains())
    assert hosts == {"cisa.gov", "kb.cert.org", "osv.dev", "support.apple.com", "nodejs.org",
                     "python.org", "go.dev", "ubuntu.com", "debian.org", "tailscale.com",
                     "openssh.com", "docs.docker.com", "cursor.com", "openai.com",
                     "anthropic.com", "blog.google", "github.com"}


def test_load_primary_domains_rejects_bad_entries(tmp_path):
    p = tmp_path / "d.json"
    for bad in ([{"host": "CISA.gov"}], [{"host": "www.cisa.gov"}],
                [{"host": "a.org"}, {"host": "a.org"}], [{"host": "a.org", "paths": ["x"]}],
                [{"host": "a.org", "paths": ["*/x/"]}],
                [{"host": "github.com", "paths": ["*/security/advisories/"]}],
                [{"host": "a.org", "extra": 1}]):
        p.write_text(json.dumps({"domains": bad}))
        with pytest.raises(ValueError):
            schema.load_primary_domains(p)


def test_reserved_id_title_is_marked_by_the_reader():
    blk = {**valid_block(), "id": "CVE-2099-0010", "title": "Claude Code: looks real"}
    assert schema.validate(blk).title == "SYNTHETIC TEST: Claude Code: looks real"
    assert schema.validate({**blk, "title": "SYNTHETIC TEST: x"}).title == "SYNTHETIC TEST: x"
    assert schema.parse_post(post_with(blk)).title == "SYNTHETIC TEST: Claude Code: looks real"
    long = schema.validate({**blk, "title": "x" * 300}).title  # cut to fit, never refused
    assert len(long) == 300 and long.startswith("SYNTHETIC TEST: x")
    real = {**valid_block(), "id": "CVE-2026-0010", "aliases": ["CVE-2099-0010"], "title": "Real"}
    assert schema.validate(real).title == "Real"
