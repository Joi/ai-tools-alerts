"""The level as a function of structured source fields (s6mt): the ruleset file, the
binding, the authoritative-source table, the claim's canonical form and the pin."""

import copy
import hashlib
import json
import subprocess
import sys

import pytest

from aitools_alerts import ruleset, schema
from aitools_alerts.ruleset import NONE, RulesetError

RS = ruleset.load()
VECTORS = json.loads((schema.SPEC_DIR / "claim-vectors.json").read_text(encoding="utf-8"))
RAW = json.loads((schema.SPEC_DIR / "ruleset.json").read_text(encoding="utf-8"))
SCOPE = json.loads((schema.SPEC_DIR / "scope.json").read_text(encoding="utf-8"))
CC = "Claude Code"


def build(data=RAW, scope=SCOPE):
    return ruleset.Ruleset(data, scope, schema.load_scope())


def changed(path, value):
    data = copy.deepcopy(RAW)
    node = data
    for key in path[:-1]:
        node = node[key]
    if value is ...:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return data


def pkg(name="@anthropic-ai/claude-code", ecosystem="npm", range="< 2.1.0", first_patched="2.1.0"):
    return {"ecosystem": ecosystem, "name": name, "range": range, "first_patched": first_patched}


def ghsa(**kw):
    f = {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "type": None, "withdrawn_at": None, "repository": None,
         "severity": None, "cvss_vector": None, "cwes": [], "packages": [pkg()]}
    f.update(kw)
    return ("ghsa", f)


def osv(osv_id="MAL-2026-1234", **kw):
    f = {"osv_id": osv_id, "withdrawn": None, "packages": [pkg(range=None, first_patched=None)]}
    f.update(kw)
    return ("osv", f)


def kev(name="Anthropic Claude Code", cve="CVE-2026-0001"):
    return ("kev", {"cve_id": cve, "name": name})


VENDOR = "anthropics/claude-code"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


# ------------------------------------------------------------------ the file

def test_the_shipped_ruleset_loads():
    assert RS.version == ruleset.VERSION == 3
    assert RS.ttl_days == {"critical": 14, "high": 30, "notice": 90}  # 9kgk: a critical stands 14 days unless renewed
    assert RS.reading_cap == "high"
    assert RS.action_cap == "high"  # 9kgk: a critical needs a complete action
    assert len(RS.digest) == 64 and int(RS.digest, 16) >= 0


@pytest.mark.parametrize("data", [
    changed(["extra"], 1),
    changed(["version"], 1),
    changed(["version"], 2),
    changed(["version"], 4),
    changed(["action_cap"], "critical"),
    changed(["action_cap"], None),
    changed(["rules", 1, "stop_using"], False),
    changed(["rules", 1, "stop_using"], "yes"),
    changed(["levels"], ["notice", "high", "critical", "extreme"]),
    changed(["reading_cap"], "critical"),
    changed(["ttl_days", "high"], 0),
    changed(["class_cap", "out"], "extreme"),
    changed(["class_cap"], {"channel": "critical", "catalog": "notice"}),
    changed(["channel_if_cap"], "extreme"),
    changed(["fields", "kev"], ["cve_id"]),
    changed(["sources", 1, "when"], {"smells": "bad"}),
    changed(["sources", 4, "alone"], "high"),          # ghsa-other cannot lower, so it sets notice at most
    changed(["sources", 5, "second"], True),           # nothing adds readings up
    changed(["sources", 5, "with_second"], "critical"),
    changed(["sources", 4, "when"], {"type": "unreviewed"}),  # ghsa has no catch-all row left
    changed(["sources"], [RAW["sources"][i] for i in (0, 4, 1, 2, 3, 5, 6)]),  # the catch-all ahead of the rest
    changed(["sources", 1, "when"], {"type": []}),
    changed(["sources", 1, "source"], []),
    changed(["rules", 0, "class"], []),
    changed(["rules", 3, "when", "severity_in"], ["high"]),  # 9kgk: the severity word sets no level
    changed(["rules", 2, "when", "cwe_any"], ["506"]),
    changed(["rules", 4, "when", "cvss_av"], ["network"]),
    changed(["rules", 1, "when", "scope"], [1]),
    changed(["rules", 1, "when", "scope"], ["tier1"]),
    changed(["sources", 1, "class"], "kev"),
    changed(["rules", 0, "level"], "extreme"),
    changed(["rules", 0, "class"], "nobody"),
    changed(["rules", 1, "when"], {"vibes": True}),
    changed(["rules", 1, "when"], {"scope": []}),
    changed(["rules", 6, "when", "channel_if"], False),
    changed(["rules", 1, "when"], {"tier": [1]}),  # version 1's condition
    changed(["rules", 4, "when", "patched"], False),
], ids=lambda d: "")
def test_a_ruleset_this_reader_does_not_fully_know_is_refused(data):
    with pytest.raises(RulesetError):
        build(data)


def test_the_module_does_not_import_the_poster():
    code = "import sys, aitools_alerts.ruleset as r; r.load(); sys.exit('aitools_alerts.poster' in sys.modules)"
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


# ------------------------------------------------------------------ binding and levels

@pytest.mark.parametrize("case", VECTORS["levels"], ids=lambda c: c["name"])
def test_level_vectors(case):
    assert RS.level([tuple(r) for r in case["readings"]], case["product"]) == case["level"]


@pytest.mark.parametrize("case", VECTORS["actions"], ids=lambda c: c["name"])
def test_action_vectors(case):
    """9kgk: a critical needs a complete action; the vectors a member's CLI shares."""
    got = RS.action_level(case["level"], [tuple(a) for a in case["actions"]], case["product"], case["fixed"],
                          [tuple(r) for r in case["readings"]])
    assert got == case["want"]


def test_action_level_takes_the_blocks_own_actions_and_former_names():
    act = schema.Action("upgrade", CC, "2.1.0")
    assert RS.action_level("critical", [act], CC, "2.1.0", [kev()]) == "critical"
    # products[].fixed decides, as the member's planner does: a value with no stated fix is not one
    assert RS.action_level("critical", [act], CC, None) == "high"
    assert RS.action_level("critical", [schema.Action("upgrade", CC, None)], CC, "2.1.0") == "critical"
    assert RS.action_level(NONE, [], CC, None) == NONE and RS.action_level("notice", [], CC, None) == "notice"
    withdrawn = ghsa(type="malware", withdrawn_at="2026-11-20T00:00:00Z", packages=[pkg("@anthropic-ai/claude-code")])
    assert RS.action_level("critical", [("stop_using", CC, None)], CC, None, [withdrawn]) == "high"
    assert RS.read(*withdrawn)[CC].stop_using is False


def test_kev_binds_by_cisas_vendor_and_product_only():
    assert RS.level([kev()], CC) == "critical"
    assert RS.level([kev("Linux Kernel")], "Linux kernel") == "notice"  # out of the community service (wa6n)
    other = kev("Cisco IOS XE")
    assert RS.read(*other) == {} and RS.level([other], CC) == NONE
    assert RS.level([kev(None)], CC) == NONE  # the catalog does not list it
    assert RS.level([kev("Anthropic Claude Code Router")], CC) == NONE


def test_an_osv_mal_entry_alone_is_high_and_nothing_adds_up():
    mal = osv()
    assert RS.level([mal], CC) == "high"
    assert RS.level([mal, ghsa(type="malware")], CC) == "critical"  # that reading is critical alone
    assert RS.level([ghsa(type="malware")], CC) == "critical"
    # An unrelated real advisory for the same product lends an attacker's entry nothing.
    low = ghsa(repository=VENDOR, type="reviewed", severity="low")
    assert RS.level([low], CC) == "notice" and RS.level([mal, low], CC) == "high"
    assert RS.level([mal, ghsa(type="reviewed", severity="critical")], CC) == "high"
    assert RS.level([mal, kev("Cisco IOS XE")], CC) == "high"
    assert RS.level([osv(packages=[pkg("claude-code-router", range=None, first_patched=None)])], CC) == NONE
    assert RS.level([osv("PYSEC-2026-12")], CC) == "notice"  # an OSV entry that is not MAL-


def test_an_attacker_writable_source_sets_notice_at_most_and_cannot_lower():
    loud = dict(severity="critical", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwes=["CWE-506", "CWE-78"])
    for reading in (ghsa(type="unreviewed", **loud), ghsa(**loud),
                    ghsa(repository="attacker/claude-code", **loud), osv("PYSEC-2026-12")):
        s = RS.read(*reading)[CC]
        assert (s.level, s.lowers) == ("notice", False), reading
    for reading in (kev(), ghsa(type="malware"), ghsa(repository=VENDOR), ghsa(type="reviewed"), osv()):
        assert RS.read(*reading)[CC].lowers is True


def test_the_vendors_own_advisory_is_rated_by_its_fields():
    assert RS.read(*ghsa(repository=VENDOR))[CC].cls == "ghsa-vendor"
    assert RS.level([ghsa(repository=VENDOR)], CC) == "notice"
    assert RS.level([ghsa(repository=VENDOR, severity="high")], CC) == "notice"  # 9kgk: the word sets nothing
    assert RS.level([ghsa(repository=VENDOR, severity="critical")], CC) == "notice"
    assert RS.level([ghsa(repository=VENDOR, severity="medium")], CC) == "notice"
    assert RS.level([ghsa(repository=VENDOR, cwes=["CWE-506"])], CC) == "critical"
    rce = dict(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", cwes=["CWE-78"])
    assert RS.level([ghsa(repository=VENDOR, **rce)], CC) == "high"
    assert RS.level([ghsa(type="reviewed", **rce)], CC) == "high"
    assert RS.level([ghsa(type="reviewed", cwes=["CWE-506"], severity="critical")], CC) == "notice"
    unpatched = [pkg(first_patched=None)]
    assert RS.level([ghsa(repository=VENDOR, packages=unpatched, **rce)], CC) == "notice"
    local = dict(rce, cvss_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    # 9kgk: a channel row needs no attack vector; an agent meets a local flaw in the content it reads
    assert RS.level([ghsa(repository=VENDOR, **local)], CC) == "high"
    for cwe in ("CWE-22", "CWE-59", "CWE-693", "CWE-862", "CWE-863", "CWE-522"):  # sandbox, approval, credential
        assert RS.level([ghsa(repository=VENDOR, cwes=[cwe])], CC) == "high", cwe
    assert RS.level([ghsa(repository=VENDOR, cwes=["CWE-400"], severity="critical")], CC) == "notice"  # denial of service
    # Another product's repository is not this product's vendor.
    assert RS.read(*ghsa(repository="openai/codex", severity="high"))[CC].cls == "ghsa-other"
    # A patch for another product's package is not a patch for this one.
    mixed = [pkg(first_patched=None), pkg("@openai/codex")]
    assert RS.level([ghsa(repository=VENDOR, packages=mixed, **rce)], CC) == "notice"


def test_a_withdrawn_reading_supports_nothing():
    gone = ghsa(type="malware", withdrawn_at="2026-11-20T00:00:00Z")
    assert RS.read(*gone)[CC].level == NONE and RS.level([gone], CC) == NONE
    assert RS.level([osv(withdrawn="2026-11-20T00:00:00Z")], CC) == NONE
    assert RS.level([gone, osv()], CC) == "high"


def test_withdrawal_keeps_the_class_and_its_lowering_authority():
    when = "2026-11-20T00:00:00Z"
    for reading in (ghsa(withdrawn_at=when, severity="critical"), ghsa(type="unreviewed", withdrawn_at=when),
                    osv("PYSEC-2026-12", withdrawn=when)):
        s = RS.read(*reading)[CC]
        assert (s.level, s.lowers) == (NONE, False), reading  # its withdrawal justifies no lowering
    for reading in (ghsa(type="malware", withdrawn_at=when), ghsa(repository=VENDOR, withdrawn_at=when),
                    osv(withdrawn=when)):
        s = RS.read(*reading)[CC]
        assert (s.level, s.lowers) == (NONE, True), reading


def test_one_vector_is_spelled_out_here_so_the_file_cannot_certify_itself():
    v = next(v for v in VECTORS["claims"] if v["name"] == "poster-kev")
    assert v["canonical"] == ('{"checked_at":1795000000,"confirmed_at":1795000000,'
                              '"fields":{"cve_id":"CVE-2026-0001","name":"Anthropic Claude Code"},'
                              '"id":"CVE-2026-0001","level":"critical","ruleset":3,"source":"kev"}')
    assert VECTORS["ruleset"] == RS.version


def test_a_package_with_no_ecosystem_binds_by_name():
    soft = ghsa(repository="openssh/openssh-portable", severity="high",
                packages=[pkg("OpenSSH", ecosystem="")])
    assert RS.level([soft], "OpenSSH") == "notice"  # OpenSSH is out (wa6n)
    mcp = ghsa(repository="modelcontextprotocol/servers", cwes=["CWE-78"], packages=[pkg("mcp-server-git", ecosystem="pypi")])
    assert RS.level([mcp], "mcp-server-git") == "high"  # an MCP server is named by its package (wa6n)
    assert RS.level([mcp], "MCP servers and clients") == "high"  # its thread under the old name keeps the level
    assert RS.level([mcp], "MCP Inspector") == NONE
    sdk = ghsa(repository="modelcontextprotocol/typescript-sdk", severity="critical", type="reviewed", cvss_vector=V31,
               cwes=["CWE-94"], packages=[pkg("@modelcontextprotocol/sdk", ecosystem="npm")])
    assert RS.level([sdk], "@modelcontextprotocol/sdk") == "notice"  # catalog: never the channel
    rce = ghsa(repository="modelcontextprotocol/inspector", severity="critical", type="reviewed", cvss_vector=V31,
               cwes=["CWE-94"], packages=[pkg("@modelcontextprotocol/inspector", ecosystem="npm")])
    assert RS.level([rce], "@modelcontextprotocol/inspector") == "high"  # channel_if: remote code execution
    dos = ("ghsa", dict(rce[1], cwes=["CWE-400"]))
    assert RS.level([dos], "@modelcontextprotocol/inspector") == "notice"  # not code execution
    git = ghsa(repository="git/git", severity="critical", type="reviewed", cvss_vector=V31, cwes=["CWE-78"],
               packages=[pkg("git-scm", ecosystem="")])
    assert RS.level([git], "git") == "high"  # out, but a code-execution flaw agents reach posts, at high at most
    assert RS.level([ghsa(repository="git/git", severity="critical", packages=[pkg("git-scm", ecosystem="")])], "git") == "notice"
    by = {e.name: e for e in schema.load_scope()}
    parent = schema.ScopeEntry("P", "p", "channel", ["p"], package="npm:p", components=(
        schema.ScopeComponent("C", ("c", "npm:c"), package="npm:c"),))
    assert ruleset.index([parent])["npm:c"].package == "npm:c" and ruleset.index([parent])["p"].package == "npm:p"
    assert [RS.class_level("kev", by[n]) for n in ("Claude Code", "mcp", "OpenSSH", "git")] \
        == ["critical", "notice", "notice", "notice"]  # KEV alone never meets channel_if


@pytest.mark.parametrize("reading", [
    ("kev", {"cve_id": "CVE-2026-0001"}),
    ("kev", {"cve_id": "CVE-2026-0001", "name": "x", "extra": 1}),
    ("kev", {"cve_id": "cve-2026-0001", "name": "x"}),
    ("kev", {"cve_id": "CVE-2026-0001", "name": " padded "}),
    ("kev", {"cve_id": "CVE-2026-0001", "name": 1.5}),
    ("nvd", {"cve_id": "CVE-2026-0001", "name": "x"}),
    ghsa(ghsa_id="GHSA-AAAA-BBBB-CCCC"),
    ghsa(type="rumour"),
    ghsa(severity="moderate"),
    ghsa(cwes=None),
    ghsa(cwes=["CWE-78", "CWE-506"]),
    ghsa(cwes=["CWE-78", "CWE-78"]),
    ghsa(cvss_vector="AV:N"),
    ghsa(cvss_vector="CVSS:4.0/AV:N"),  # cut short: the base metrics are missing
    ghsa(cvss_vector=V31 + "/AV:L"),    # a metric stated twice
    ghsa(cvss_vector=V31.replace("AV:N", "AV:X")),
    ghsa(cvss_vector=V31.replace("/AC:L", "")),
    ghsa(cvss_vector=V31.replace("CVSS:3.1", "CVSS:2.0")),
    ghsa(cvss_vector=V31 + "/"),
    ghsa(cvss_vector=["CVSS:3.1"]),
    ghsa(type=[]), ghsa(type={}), ghsa(severity={}), ghsa(severity=["high"]), ghsa(severity=1),
    ghsa(withdrawn_at="not-a-date"), ghsa(withdrawn_at="2026-11-20"), ghsa(withdrawn_at="2026-13-40T00:00:00Z"),
    ghsa(withdrawn_at="2026-11-20T00:00:00+09:00"), ghsa(withdrawn_at=True), ghsa(withdrawn_at=""),
    osv(withdrawn="yes"), osv(withdrawn=1795000000), osv(withdrawn=[]),
    ("kev", {"cve_id": "CVE-2026-0001", "name": "x", 1: 2}),
    ("kev", {"cve_id": ["CVE-2026-0001"], "name": "x"}),
    ("kev", ["cve_id", "name"]),
    (["kev"], {"cve_id": "CVE-2026-0001", "name": "x"}),
    ghsa(repository="Anthropics/claude-code"),
    ghsa(packages=[pkg(ecosystem="NPM")]),
    ghsa(packages=[pkg(range="< 2"), pkg(range="< 1")]),
    ghsa(packages=[pkg(), pkg()]),
    ghsa(packages=[pkg(range="")]),
    ghsa(packages=[{"ecosystem": "npm", "name": "x"}]),
    ghsa(packages=[pkg("npm:@anthropic-ai/claude-code", ecosystem="")]),
    osv("CVE-2026-0001"),
    osv("GHSA-aaaa-bbbb-cccc"),
    osv(packages=None),
], ids=lambda r: "")
def test_a_malformed_reading_is_refused(reading):
    with pytest.raises(RulesetError):
        RS.read(*reading)


def test_a_malformed_reading_never_raises_anything_but_a_refusal():
    """Every public path refuses with RulesetError or the verdict "refused": a poster
    run and a member's check never meet a TypeError from a hostile value."""
    good = RS.claim(*ghsa(repository=VENDOR, severity="high"), CC, 1795000000, 1795000000)
    for key, bad in (("type", []), ("type", {}), ("severity", {}), ("severity", []), ("cvss_vector", {}),
                     ("withdrawn_at", "not-a-date"), ("withdrawn_at", []), ("cwes", "CWE-78"), ("packages", {}),
                     ("repository", []), ("ghsa_id", None)):
        claim = copy.deepcopy(good)
        claim["fields"][key] = bad
        with pytest.raises(RulesetError):
            ruleset.parse_claim(claim)
        assert ruleset.check_claim(claim, CC) == "refused", (key, bad)
        assert ruleset.check_claim(dict(claim, level="none"), CC) == "refused", (key, bad)
    for bad in (None, [], {}, 7, "kev"):
        assert ruleset.check_claim(dict(good, fields=bad), CC) == "refused"
        assert ruleset.check_claim(dict(good, source=bad), CC) == "refused"
        assert ruleset.check_claim(bad, CC) == "refused"
    assert ruleset.check_claim(good, None) == ruleset.check_claim(good, ["Claude Code"]) == "refused"
    assert ruleset.check_claim(good, CC) == "ok"


def test_a_withdrawal_is_a_time_the_source_states_and_nothing_else():
    """Arbitrary text in the withdrawal field is malformed data, never leave to lower."""
    mal = RS.claim(*osv(), CC, 1795000000, 1795000000)
    forged = copy.deepcopy(mal)
    forged["fields"]["withdrawn"], forged["level"] = "not-a-date", "none"
    assert ruleset.check_claim(forged, CC) == "refused"
    for when in ("2026-11-20T00:00:00Z", "2026-11-20T00:00:00.123456Z"):
        assert RS.read(*osv(withdrawn=when))[CC].level == NONE
        assert RS.read(*ghsa(type="malware", withdrawn_at=when))[CC].level == NONE


def test_only_a_complete_cvss_vector_has_an_attack_vector():
    assert ruleset.cvss_metrics(V31)["AV"] == "N" and ruleset.cvss_metrics(V40)["AV"] == "A"
    assert ruleset.cvss_metrics(V31.replace("3.1", "3.0"))["S"] == "U"
    full = V40 + "/E:A/CR:H/MAV:N/S:P/AU:Y/R:I/V:C/RE:M/U:Green"  # FIRST's own supplemental values
    assert ruleset.cvss_metrics(full)["U"] == "Green"
    assert ruleset.cvss_metrics(V31 + "/E:P/RL:O/RC:C/CR:H/MAV:L")["MAV"] == "L"
    shuffled = "CVSS:3.1/AC:L/AV:N/PR:N/UI:R/S:U/C:H/I:H/A:H"  # 3.x readers take the metrics in any order
    assert ruleset.cvss_metrics(shuffled) == ruleset.cvss_metrics(V31)
    assert ruleset.cvss_metrics("CVSS:3.0/E:P/A:H/I:H/C:H/S:U/UI:R/PR:N/AC:L/AV:A")["AV"] == "A"
    assert RS.level([ghsa(cvss_vector=shuffled, cwes=["CWE-78"], type="reviewed")], CC) == "high"
    for bad in ("CVSS:4.0/AV:N", V31 + "/AV:L", V40 + "/E:A/E:P", V40.replace("AV:A/AC:L", "AC:L/AV:A"),
                "CVSS:4.0/E:A/" + V40[9:], shuffled.replace("/PR:N", ""), shuffled.replace("UI:R", "UI:X"),
                V40.replace("AT:N/", ""), V31.lower(), " " + V31, V31 + "/x:y", V31 + "/E:", None, 7, "x" * 400):
        assert ruleset.cvss_metrics(bad) is None, bad
    cwe = dict(cwes=["CWE-78"], type="reviewed")
    assert RS.level([ghsa(cvss_vector=V40, **cwe)], CC) == "high"  # adjacent, patched, command injection
    assert RS.level([ghsa(cvss_vector=V40.replace("AV:A", "AV:P"), **cwe)], CC) == "high"  # 9kgk: no AV on channel rows
    assert RS.level([ghsa(cvss_vector=full, **cwe)], CC) == "high"


def test_registries_as_the_sources_name_them_fit_the_form():
    for eco in ("npm", "pip", "crates.io", "debian:12", "github actions", "go", ""):
        RS.read(*osv(packages=[pkg("some-package", ecosystem=eco, range=None, first_patched=None)]))
    for eco in ("NPM", "npm ", " npm", "-npm", "npm:", "n" * 65):
        with pytest.raises(RulesetError):
            RS.read(*osv(packages=[pkg("some-package", ecosystem=eco)]))
    many = ruleset.ordered(pkg(f"p{i}", range=None, first_patched=None) for i in range(600))
    assert RS.read(*osv(packages=many)) == {}  # a long advisory is read, and binds nothing here
    with pytest.raises(RulesetError):
        RS.read(*osv(packages=ruleset.ordered(pkg(f"p{i}") for i in range(1001))))


def test_ordered_puts_a_builders_packages_in_the_one_order():
    a, b, c = pkg(range="< 1"), pkg(range="< 2"), pkg(range=None, first_patched=None)
    assert ruleset.ordered([b, a, c, dict(a)]) == [c, a, b]
    assert RS.read(*ghsa(packages=ruleset.ordered([b, a, c, a])))[CC].level == "notice"


# ------------------------------------------------------------------ claims

@pytest.mark.parametrize("v", VECTORS["claims"], ids=lambda v: v["name"])
def test_claim_vectors_have_one_byte_form(v):
    raw = ruleset.canonical(v["claim"])
    assert raw.decode("utf-8") == v["canonical"]
    assert hashlib.sha256(raw).hexdigest() == v["sha256"]
    assert ruleset.check_claim(v["claim"], v["product"]) == "ok"
    assert RS.claim(v["claim"]["source"], v["claim"]["fields"], v["product"],
                    v["claim"]["confirmed_at"], v["claim"]["checked_at"]) == v["claim"]
    assert json.loads(v["canonical"]) == v["claim"]


def test_the_vectors_cover_what_the_form_has_to_settle():
    names = {v["name"] for v in VECTORS["claims"]}
    assert {"poster-kev", "poster-ghsa-page"} <= names
    assert all(v["canonical"].isascii() for v in VECTORS["claims"])
    assert any('\\"' in v["canonical"] and "\\\\" in v["canonical"] for v in VECTORS["claims"])  # the two escapes
    assert any(v["claim"]["level"] == NONE for v in VECTORS["claims"])
    two = next(v for v in VECTORS["claims"] if v["name"] == "poster-ghsa-page")["claim"]["fields"]
    assert two["cwes"] == [] and len(two["packages"]) == 2
    assert len({(p["ecosystem"], p["name"]) for p in two["packages"]}) == 1


@pytest.mark.parametrize("value", [1.0, float("nan"), 2**53, "é", "a\u0000b", "a‎b", "a" + chr(0xE000) + "b", "a" + chr(0xD800), "caf" + chr(0xE9), "a" + chr(0xA0) + "b", "a\tb", "a\nb", "a" + chr(0x7F), chr(0x1CCD8), chr(0x50000), b"x", (1,),
                                   {"kéy": 1}, {1: 1}], ids=lambda v: "")
def test_canonical_refuses_what_two_readers_could_write_differently(value):
    with pytest.raises(RulesetError):
        ruleset.canonical({"v": value})


def test_canonical_sorts_keys_and_escapes_only_the_quote_and_the_backslash():
    assert ruleset.canonical({"b": [1, None, True], "a": {"d": 'x"y\\z', "c": -1}}) \
        == b'{"a":{"c":-1,"d":"x\\"y\\\\z"},"b":[1,null,true]}'


def test_a_name_outside_ascii_is_refused_so_no_unicode_version_decides_a_level():
    """U+1CCD8 folds to "C" under NFKC in Unicode 16 and is unassigned in Unicode 14:
    a reader on each would bind "Anthropic <that>laude Code" differently under one
    digest. No string of a reading leaves printable ASCII, so neither binds it."""
    for name in ("Anthropic " + chr(0x1CCD8) + "laude Code", "Anthropic " + chr(0xFF23) + "laude Code",
                 "Anthropic Claude" + chr(0xA0) + "Code", "Anthropic Claude Cod" + chr(0xE9), "Anthropic\tClaude Code"):
        with pytest.raises(RulesetError):
            RS.read(*kev(name))
        forged = dict(RS.claim(*kev(), CC, 1795000000, 1795000000))
        forged["fields"] = {"cve_id": "CVE-2026-0001", "name": name}
        assert ruleset.check_claim(forged, CC) == "refused"
    with pytest.raises(RulesetError):
        RS.read(*osv(packages=[pkg("@anthropic-ai/" + chr(0x441) + "laude-code", range=None, first_patched=None)]))
    assert all(m.isascii() for e in SCOPE["entries"] for m in [*e.get("match", []),
               *(i for c in e.get("components", []) for i in c["match"])])


def claim(reading=None, product=CC, **kw):
    c = RS.claim(*(reading or osv()), product, 1795000000, 1795003600)
    c.update(kw)
    return c


@pytest.mark.parametrize("kw", [
    {"id": "MAL-2026-9999"}, {"source": "ghsa"}, {"ruleset": 0}, {"ruleset": True}, {"ruleset": "1"},
    {"level": "extreme"}, {"level": None}, {"confirmed_at": 1795003601}, {"checked_at": 1.5},
    {"confirmed_at": -1}, {"extra": 1},
], ids=lambda k: next(iter(k)))
def test_a_malformed_claim_is_refused(kw):
    bad = claim(**kw)
    with pytest.raises(RulesetError):
        ruleset.parse_claim(bad)
    assert ruleset.check_claim(bad, CC) == "refused"


def test_the_id_decides_the_source():
    assert ruleset.source_of("CVE-2026-0001") == "kev"
    assert ruleset.source_of("GHSA-aaaa-bbbb-cccc") == "ghsa"
    assert ruleset.source_of("MAL-2026-1234") == ruleset.source_of("PYSEC-2026-12") == "osv"
    for bad in ("cve-2026-0001", "GHSA-AAAA-BBBB-CCCC", "https://osv.dev/MAL-1", "MAL", "", None, 7,
                "CVE-2026-1", "ghsa-aaaa-bbbb-cccc"):
        assert ruleset.source_of(bad) is None, bad


def test_check_claim_computes_with_the_readers_own_ruleset():
    good = claim()
    assert good["level"] == "high" and ruleset.check_claim(good, CC) == "ok"
    assert ruleset.check_claim(claim(level="critical"), CC) == "mismatch"
    assert ruleset.check_claim(claim(level="notice"), CC) == "mismatch"  # a forged lowering
    assert ruleset.check_claim(good, "Codex") == "mismatch"  # another product's alert
    assert ruleset.check_claim(claim(kev("Cisco IOS XE"), level="critical"), CC) == "mismatch"
    assert ruleset.check_claim(claim(ruleset=4), CC) == "unknown"
    assert ruleset.check_claim(claim(ruleset=4, level="critical"), CC) == "unknown"
    assert ruleset.check_claim(claim(ruleset=1), CC) == "ok"  # a version-1 claim is judged by this reader's rules
    assert ruleset.check_claim(claim(ruleset=2), CC) == "ok"


def pin(version=3, min_version=1, sha256=None):
    return ruleset.parse_pin({"version": version, "min_version": min_version, "sha256": sha256 or RS.digest})


def test_the_pin():
    good = claim()
    assert ruleset.check_claim(good, CC, pin()) == "ok"
    assert ruleset.check_claim(good, CC, pin(version=5, min_version=4)) == "outdated"
    assert ruleset.check_claim(good, CC, pin(sha256="0" * 64)) == "outdated"
    assert ruleset.check_claim(good, CC, pin(version=4, sha256="0" * 64)) == "ok"  # a newer pin, still allowed
    assert ruleset.check_claim(claim(ruleset=4), CC, pin(version=4, sha256="0" * 64)) == "unknown"
    for bad in ({"version": 1, "min_version": 2, "sha256": "0" * 64}, {"version": 1, "min_version": 0, "sha256": "0" * 64},
                {"version": 1, "min_version": 1, "sha256": "ABC"}, {"version": True, "min_version": 1, "sha256": "0" * 64},
                {"version": 1, "min_version": 1}, {"version": 1, "min_version": 1, "sha256": "0" * 64, "x": 1}, None):
        with pytest.raises(RulesetError):
            ruleset.parse_pin(bad)


def test_a_claim_citing_an_older_ruleset_under_which_the_level_was_lower_is_refused(monkeypatch):
    """Version 3 rates a MAL- entry high. A later ruleset that rates it critical: the
    thief's claim "ruleset 3, high" is a mismatch for a reader on 4 (it computes with
    its own rules), and refused outright once the root sets min_version to 4."""
    old = claim()
    assert (old["ruleset"], old["level"]) == (3, "high")
    data = changed(["version"], 4)
    data["sources"][5]["alone"] = "critical"
    data["rules"][7]["level"] = "critical"
    monkeypatch.setattr(ruleset, "VERSION", 4)
    rs2 = build(data)
    assert rs2.digest != RS.digest
    assert rs2.level([osv()], CC) == "critical"
    assert ruleset.check_claim(old, CC, rs=rs2) == "mismatch"
    two = ruleset.parse_pin({"version": 4, "min_version": 4, "sha256": rs2.digest})
    assert ruleset.check_claim(old, CC, two, rs=rs2) == "refused"
    assert ruleset.check_claim(dict(old, ruleset=4, level="critical"), CC, two, rs=rs2) == "ok"
    monkeypatch.undo()
    assert ruleset.check_claim(old, CC, two) == "outdated"  # a reader still on 3 judges nothing


def test_the_digest_covers_the_tables_and_the_scope_file():
    assert build().digest == RS.digest
    assert build(changed(["ttl_days", "notice"], 91)).digest != RS.digest
    assert build(changed(["rules", 3, "when", "cwe_any"], ["CWE-79"])).digest != RS.digest
    assert build(changed(["action_cap"], "notice")).digest != RS.digest
    assert build(changed(["sources", 3, "alone"], "notice")).digest != RS.digest
    scope = copy.deepcopy(SCOPE)
    scope["entries"][0]["authority"].append("example.com/")
    assert build(scope=scope).digest != RS.digest


def test_the_wire_tag_carries_the_canonical_bytes():
    """t8jr's carrier and this form are one serialisation: the tag's text is the claim's
    canonical bytes, and the tag reads back as the claim."""
    from aitools_alerts import wire
    for v in VECTORS["claims"]:
        tag = wire.claim_tag(v["claim"])
        assert tag == [wire.CLAIM_TAG, v["canonical"]] and len(v["canonical"]) <= wire.MAX_CLAIM_BYTES
        got = wire.claim_of({"tags": [tag]})
        assert got == v["claim"] and ruleset.check_claim(got, v["product"]) == "ok"


def test_a_published_version_2_claim_is_judged_by_this_readers_rules():
    """9kgk: claims already signed under ruleset 2 stay well formed. This reader computes
    with version 3: a KEV claim still agrees; a claim whose high rested on the severity
    word alone is now a mismatch, so it can no longer support a high."""
    kev2 = {"id": "CVE-2026-0001", "source": "kev", "fields": dict(kev()[1]), "ruleset": 2, "level": "critical",
            "confirmed_at": 1795000000, "checked_at": 1795000000}
    assert ruleset.check_claim(kev2, CC) == "ok"
    word = ghsa(repository=VENDOR, severity="high", packages=[pkg()])
    word2 = {"id": word[1]["ghsa_id"], "source": "ghsa", "fields": word[1], "ruleset": 2, "level": "high",
             "confirmed_at": 1795000000, "checked_at": 1795000000}
    assert ruleset.check_claim(word2, CC) == "mismatch"
    assert ruleset.check_claim(dict(word2, level="notice"), CC) == "ok"
