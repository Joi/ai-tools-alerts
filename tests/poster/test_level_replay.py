"""Acceptance for ai-tools-alerts#9kgk: the alerts on the public feed, replayed through
the level rule of version 3 of the ruleset.

Each row is one alert root on https://buzz.ai-tools.md/alerts/feed.json (generated
2026-11-24T07:20:27Z; 28 at the v2 design's count, plus Hermes of 11-24) as the poster
would see it now: the product text a collector gives, the fixed version the thread ended
with after its fix replies, the KEV flag and reading for the two KEV entries, the
source's own title as the advisory text, and the severity word "high" that every one of
them was posted under. The expected level is this ruleset's.
"""

import json

import pytest

from aitools_alerts import ruleset
from aitools_alerts.poster import compose, rules
from aitools_alerts.poster.candidates import Candidate, Source

GH = "https://github.com/"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
MCP_GIT = "pip:mcp-server-git"

# (id, product text, fixed, KEV name or None, title, expected level)
ALERTS = [
    ("CVE-2026-103435", "claude code", "2.1.129", None,
     "Arbitrary File Write via Write-Time Symlink Following (TOCTOU) in Claude Code", "notice"),
    ("CVE-2026-88968", "claude code", "2.1.251", None,
     "TOCTOU Race in Edit Tool Allows File Writes Outside the Workspace", "high"),
    ("CVE-2026-86063", "claude code", "2.1.179", None,
     "Plugin Commit SHA Pin Bypass Allows Installation of Attacker-Controlled Code", "high"),
    ("GHSA-4fc4-wcmh-4g86", "mcp inspector", "1.0.3", None,
     "Malicious MCP OAuth callback can switch transport to stdio and execute arbitrary local commands (RCE)",
     "high"),
    ("GHSA-6x67-4w4w-9f3w", "mcp inspector", "1.0.3", None,
     "Remote MCP App can steal proxy auth token and execute arbitrary local commands (RCE)", "high"),
    ("GHSA-q978-78c7-phqw", "mcp inspector", "2.12.0", None,
     "A remote MCP server can execute arbitrary code on the user's machine through the OAuth authorization URL "
     "(PowerShell subexpression injection on Windows and WSL)", "notice"),  # channel_if: says no "remote code execution"
    ("GHSA-vcc9-3xgm-p9v4", "mcp inspector", "2.12.0", None,
     "Incomplete fix for CVE-2025-49596: DNS-rebinding info disclosure (API token + stored OAuth tokens) "
     "in MCP Inspector", "notice"),
    ("GHSA-wmjf-2m46-2352", "mcp inspector", "1.0.3", None,
     "Missing Authentication for Critical Function in @modelcontextprotocol/inspector", "notice"),
    ("CVE-2026-59951", "mcp python sdk", None, None,
     "Streamable HTTP sessions were never reclaimed by default and kept their initialize payloads", "notice"),
    ("CVE-2026-109527", "mcp python sdk", None, None,
     "HTTP server transports and OAuth endpoints read request bodies with no size limit", "notice"),
    ("CVE-2026-115563", "mcp python sdk", None, None,
     "OAuth client could send credentials to an authorization server chosen by the MCP server", "notice"),
    ("CVE-2026-111767", "mcp typescript sdk", "1.32.0", None,
     "Experimental tasks were not tied to the session that created them", "notice"),
    ("CVE-2026-111768", "mcp typescript sdk", None, None,
     "One HTTP request within the default size limit could exhaust server memory during validation", "notice"),
    ("CVE-2026-104850", "mcp typescript sdk", None, None,
     "OAuth client could send credentials to an authorization server chosen by the MCP server", "notice"),
    ("GHSA-f897-62hf-6gxq", "mcp typescript sdk", None, None,
     "HTTP server transports and handlers did not limit request body size or JSON-RPC batch length", "notice"),
    ("CVE-2026-111770", "mcp typescript sdk", "2.3.0", None,
     "Shared transport or server instances delivered one HTTP client's messages to another", "notice"),
    ("CVE-2026-32846", "openclaw", "2026.3.28", None,
     "OpenClaw is vulnerable to Path Traversal through path validation bypass", "notice"),
    ("CVE-2026-123158", "openssh", None, "OpenBSD OpenSSH",
     "OpenBSD OpenSSH Unexpected Status Code or Return Value Vulnerability", "notice"),
    ("CVE-2026-125350", "chromium", None, "Google Chromium", "Google Chromium vulnerability", "notice"),
    ("CVE-2026-111760", "git/git", "2.56.1", None, "Recursive clones are susceptible to Remote Code Execution", "high"),
    ("GHSA-6hqx-gqrx-c5r2", MCP_GIT, "2026.11.11", None,
     "mcp-server-git: arbitrary command execution via a repository's own Git configuration (core.fsmonitor) "
     "during read-only tools", "high"),
    ("GHSA-87qg-cmw8-jc5m", MCP_GIT, "2026.11.18", None,
     "mcp-server-git: a repository's promisor configuration runs a program during a lazy fetch", "high"),
    ("GHSA-9vjp-x34c-xg6v", MCP_GIT, "2026.11.18", None,
     "mcp-server-git: a config include created by the merged branch runs a command during git_merge", "high"),
    ("GHSA-h2g3-rwxm-xfm3", MCP_GIT, "2026.11.18", None,
     "mcp-server-git 2026.11.11: git_merge runs gc.recentObjectsHook from the repository's own config", "high"),
    ("GHSA-8wv7-r664-7594", MCP_GIT, "2026.11.18", None,
     "mcp-server-git: a submodule's own configuration still runs programs on git_diff (with diff.submodule=diff) "
     "and on git_checkout / git_add", "high"),
    ("GHSA-pm7p-vphh-2cg7", MCP_GIT, "2026.11.18", None,
     "mcp-server-git: a repository's own config runs a command, because the hardening misses an empty driver name",
     "high"),
    ("GHSA-pw3x-g8v8-fvj2", "openclaw", None, None,
     "OpenClaw delegation could skip approval for restricted agents", "notice"),  # an approval bypass, no fix yet
    ("CVE-2026-95839", "containerd", None, None,
     "containerd image-triggered daemon crash via malformed digest in subject-annotated descriptor", "notice"),
    ("CVE-2026-130164", "hermes-agent", "0.23.2", None,
     "Bot Desktop screen env file from the terminal backend sets arbitrary environment variables for "
     "agent-machine processes", "notice"),
]
DENIAL = {"CVE-2026-95839", "CVE-2026-109527", "CVE-2026-111768", "GHSA-f897-62hf-6gxq", "CVE-2026-59951"}


def candidate(adv_id, product, fixed, kev, title) -> Candidate:
    readings = ()
    if kev:
        readings = (("kev", ruleset.canonical({"cve_id": adv_id, "name": kev}).decode()),)
    return Candidate(
        id=adv_id, aliases=(), product_text=product, advisory_severity=title, local_level_hint=None,
        exploited=kev is not None, trojanized=False, injection_exec=False, fixed=fixed, affected=None,
        sources=(Source(KEV_PAGE if kev else GH + "advisories/" + adv_id, None),), observed_at=None,
        severity_word="high", readings=readings)


def test_the_live_alerts_replayed():
    assert len(ALERTS) == 29
    rs, seen = ruleset.load(), {}
    for adv_id, product, fixed, kev, title, want in ALERTS:
        c = candidate(adv_id, product, fixed, kev, title)
        scope = rules.scope_of(product)
        assert scope is not None, product
        lvl, reason = rules.level_for(c, scope, True)
        seen[adv_id] = lvl
        if lvl != "notice":
            _, adv = compose.root_post(c, (lvl, reason), scope, posted_at=1795504800)
            # The post's level is what its own actions allow (9kgk): no critical without one.
            assert rs.action_level(adv.level, adv.actions, scope.name, adv.products[0].fixed,
                                   [(s, json.loads(f)) for s, f in c.readings]) == adv.level, adv_id
    assert seen == {a[0]: a[5] for a in ALERTS}
    assert "critical" not in seen.values()
    assert all(seen[i] == "notice" for i in DENIAL)  # the containerd crash and the SDK size limits


@pytest.mark.parametrize("fixed,want", [(None, ("high", "no-action")), ("2.1.300", ("critical", "kev-tier1"))])
def test_an_exploited_channel_flaw_is_high_until_its_fix(fixed, want):
    """Design section 4: exploited with no fix posts at high, and is raised when the fix exists."""
    c = candidate("CVE-2026-0001", "claude code", fixed, "Anthropic Claude Code", "Claude Code flaw")
    scope = rules.scope_of("claude code")
    assert rules.level_for(c, scope, True) == want
    _, adv = compose.root_post(c, want, scope, posted_at=1795504800)
    assert [(a.verb, a.value) for a in adv.actions] == ([("upgrade", fixed)] if fixed else [])
