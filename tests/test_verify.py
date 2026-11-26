"""The member's source check (ai-tools-alerts#fv4g): three fixed endpoints, three results.

Every response here is invented. ``SENTINEL`` marks text of a response that must
never be stored or printed."""

import json
import time

import pytest

from aitools_alerts import ruleset, schema, verify
from aitools_alerts.schema import Product, Source
from mirror_helpers import advisory

G1, G2, G3 = "GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "GHSA-gggg-hhhh-jjjj"
CVE, CVE2 = "CVE-2026-1000", "CVE-2026-2000"
CC = ("npm", "@anthropic-ai/claude-code")
SENTINEL = "ZZ-SENTINEL"
NOW = 1_800_000_000
REAL_FETCH = verify.default_fetch  # taken at import: a fixture replaces the module's in every test


def gurl(i):
    return "https://api.github.com/advisories/" + i


def ourl(i):
    return "https://api.osv.dev/v1/vulns/" + i


ECO = {e.name: e.ecosystem for e in ruleset.index(schema.load_scope()).values()}  # scope product -> its ecosystem


def K(name="Claude Code", ecosystem=None):
    """The key of a product's result (``verify.pkey``); a scope product is under its own ecosystem."""
    return verify.pkey(Product(name, ecosystem or ECO.get(name, "claude-code"), None, None))


def adv(id=G1, aliases=(), level="high", products=("Claude Code",), **kw):
    """``products``: names, or (name, ecosystem) for a product posted another way."""
    pairs = [p if isinstance(p, tuple) else (p, ECO.get(p, "claude-code")) for p in products]
    kw.setdefault("actions", [schema.Action("upgrade", n, "99.0.0") for n, _ in pairs])  # as the poster writes it
    return advisory(posted_by="relay-bot", id=id, aliases=list(aliases), level=level,
                    products=[Product(n, e, "<99.0.0", "99.0.0") for n, e in pairs], **kw)


def ghsa(i=G1, pkgs=(CC,), type="reviewed", cve=None, high=True, **over):
    """An api.github.com/advisories response. ``high``: fields the ruleset reads as high."""
    obj = {"ghsa_id": i, "cve_id": cve, "type": type, "severity": "high", "withdrawn_at": None,
           "summary": f"{SENTINEL}-1", "description": f"{SENTINEL}-2", "source_code_location": f"https://{SENTINEL}-3/",
           "repository_advisory_url": None, f"{SENTINEL}-4": f"{SENTINEL}-5",
           "identifiers": [{"type": "GHSA", "value": i}] + ([{"type": "CVE", "value": cve}] if cve else []),
           "cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
                               "cvss_v4": {"vector_string": None, "score": 0.0}},
           "cwes": [{"cwe_id": "CWE-78", "name": f"{SENTINEL}-6"}] if high else [],
           "vulnerabilities": [{"package": {"ecosystem": e, "name": n}, "vulnerable_version_range": "< 9.9.9",
                                "first_patched_version": "9.9.9", "vulnerable_functions": []} for e, n in pkgs]}
    obj.update(over)
    return obj


def osv(i, pkgs=(CC,), aliases=(), **over):
    obj = {"id": i, "summary": f"{SENTINEL}-7", "aliases": list(aliases) if isinstance(aliases, (tuple, list)) else aliases,
           "affected": [{"package": {"ecosystem": e, "name": n, "purl": f"{SENTINEL}-8"}, "ranges": []} for e, n in pkgs]}
    obj.update(over)
    return obj


def kev(*entries):
    """A catalog: (cve, vendorProject, product) entries."""
    items = [{"cveID": c, "vendorProject": v, "product": p, "vulnerabilityName": f"{SENTINEL}-9"} for c, v, p in entries]
    return {"catalogVersion": "2026.11.24", "count": len(items), "vulnerabilities": items}


KEV_CC = kev((CVE, "Anthropic", "Claude Code"))


class Net:
    """A fetch that answers from a table and records every call."""

    def __init__(self, **by_url):
        self.table = dict(by_url)
        self.calls = []

    def set(self, url, answer):
        self.table[url] = answer
        return self

    def __call__(self, url, etag, limit, timeout):
        self.calls.append((url, etag, limit, timeout))
        answer = self.table.get(url, 404)
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, int):
            return answer, None, b""
        if isinstance(answer, tuple):
            etag_out, answer = answer
        else:
            etag_out = None
        return 200, etag_out, answer if isinstance(answer, bytes) else json.dumps(answer).encode()

    @property
    def urls(self):
        return [c[0] for c in self.calls]


def net(*pairs):
    n = Net()
    for url, answer in pairs:
        n.set(url, answer)
    return n


def go(tmp_path, advs, fetch, wanted=None, **kw):
    kw.setdefault("now", NOW)
    return verify.run(advs, advs if wanted is None else wanted, tmp_path, fetch=fetch, **kw)


def res(tmp_path, a):
    return verify.result_for(a, verify.load(tmp_path))


def one(tmp_path, a, product="Claude Code"):
    r = res(tmp_path, a)[K(product)]
    return r["result"], r["why"]


# ------------------------------------------------------------------ ids and URLs

@pytest.mark.parametrize("given, want", [
    ("cve-2026-1234", "CVE-2026-1234"), ("CVE-2026-1234", "CVE-2026-1234"),
    ("GHSA-ABCD-EFGH-IJKL", "GHSA-abcd-efgh-ijkl"), ("ghsa-abcd-efgh-ijkl", "GHSA-abcd-efgh-ijkl"),
    ("MAL-2026-77", "MAL-2026-77"),
    ("CVE-2026-123158:openssh", "CVE-2026-123158"), ("GHSA-87qg-cmw8-jc5m:mcp-server", "GHSA-87qg-cmw8-jc5m"),
])
def test_norm_id_gives_the_lookup_form(given, want):
    assert verify.norm_id(given) == want


@pytest.mark.parametrize("given", [
    "AITA-TEST 1", "https://evil.example/x", "../x", "GHSA-aaaa-bbbb", "CVE-2026-1/..", "MAL-1?x=1", "MAL-1/2",
    "CVE-2099-0001", "", None, 7, "MAL-2026-1" + "x" * 200, "GHSA-aaaa-bbbb-cccc\n",
    "LEAD-9a4d0dc65b79:docker", "AITA-TEST-0001", "PYSEC-2026-1", "RUSTSEC-2026-0001", "mal-2026-1",
    "CVE-2026-1000:", "CVE-2026-1000:a/b", "CVE-2026-1000:a:b", "MAL-2026-1:slug x", "CVE-2099-0001:openssh",
])
def test_norm_id_refuses_what_names_no_source(given):
    assert verify.norm_id(given) is None


def test_url_of_builds_only_the_three_shapes():
    assert verify.url_of(CVE) == verify.KEV_URL
    assert verify.url_of(G1) == gurl(G1)
    assert verify.url_of("MAL-2026-7:a.b") == "https://api.osv.dev/v1/vulns/MAL-2026-7%3Aa.b"
    for bad in ("GHSA-AAAA-BBBB-CCCC", "https://evil.example/", "x/../y", "CVE-2099-0001", "CVE-2026-1000:openssh"):
        with pytest.raises(ValueError):
            verify.url_of(bad)


# ------------------------------------------------------------------ the ruleset's two methods

def test_products_are_the_scope_names():
    names = ruleset.load().products()
    assert {"Claude Code", "Codex", "containerd", "git"} <= names and "claude code" not in names


@pytest.mark.parametrize("source, fields, want", [
    ("kev", {"cve_id": CVE, "name": None}, True),
    ("ghsa", {"type": "reviewed"}, True), ("ghsa", {"type": "malware"}, True),
    ("ghsa", {"type": "unreviewed"}, False), ("ghsa", {"type": None}, False),
    ("ghsa", {"type": "unreviewed", "repository": "anthropics/claude-code"}, False),  # no product in hand
    ("osv", {"osv_id": "MAL-2026-1"}, True), ("osv", {"osv_id": "PYSEC-2026-1"}, False),
])
def test_lowers_of_a_reading_without_a_product(source, fields, want):
    base = {"ghsa": {"ghsa_id": G1, "type": None, "withdrawn_at": None, "repository": None, "severity": None,
                     "cvss_vector": None, "cwes": [], "packages": []},
            "osv": {"osv_id": "X-1", "withdrawn": None, "packages": []}, "kev": {}}[source]
    assert ruleset.load().lowers(source, {**base, **fields}) is want


def test_lowers_refuses_a_malformed_reading():
    with pytest.raises(ruleset.RulesetError):
        ruleset.load().lowers("kev", {"cve_id": "nope", "name": None})


# ------------------------------------------------------------------ typed fields

def test_ghsa_fields_are_the_ruleset_s():
    fields, named = verify._ghsa_reading(ghsa(cve=CVE, repository_advisory_url=(
        "https://api.github.com/repos/Anthropics/Claude-Code/security-advisories/" + G1)), G1)
    assert fields == {"ghsa_id": G1, "type": "reviewed", "withdrawn_at": None, "repository": "anthropics/claude-code",
                      "severity": "high", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      "cwes": ["CWE-78"], "packages": [{"ecosystem": "npm", "name": CC[1], "range": "< 9.9.9",
                                                        "first_patched": "9.9.9"}]}
    assert CVE in named and G1 in named
    assert ruleset.load().read("ghsa", fields)["Claude Code"].level == "high"


def test_ghsa_vector_falls_back_and_unknown_severity_is_null():
    fields, _ = verify._ghsa_reading(ghsa(severity="unknown", cvss_severities=None,
                                          cvss={"vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}), G1)
    assert fields["severity"] is None and fields["cvss_vector"].startswith("CVSS:3.1/AV:L")


@pytest.mark.parametrize("over", [
    {"ghsa_id": G2}, {"ghsa_id": None}, {"type": 3}, {"withdrawn_at": 0}, {"severity": ["high"]},
    {"repository_advisory_url": "https://evil.example/repos/a/b/security-advisories/" + G1},
    {"repository_advisory_url": "https://api.github.com/repos/a/b/security-advisories/" + G2},
    {"repository_advisory_url": 5}, {"cvss_severities": "x"}, {"cvss": {"vector_string": 4}},
    {"cwes": [{"cwe_id": 78}]}, {"cwes": ["CWE-78"]}, {"vulnerabilities": [{"package": None}]},
    {"vulnerabilities": [{"package": {"ecosystem": "npm", "name": 4}}]}, {"vulnerabilities": "x"},
    {"vulnerabilities": [{"package": {"ecosystem": "npm", "name": "a"}, "first_patched_version": {"identifier": "1"}}]},
    {"identifiers": "x"},
])
def test_a_ghsa_response_of_another_shape_is_refused(over):
    with pytest.raises(verify._Bad):
        verify._ghsa_reading(ghsa(**over), G1)


@pytest.mark.parametrize("over", [
    {"cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L"}}},  # a vector cut short
    {"withdrawn_at": "yesterday"}, {"type": "rumour"}, {"severity": "severe"},
    {"vulnerabilities": [{"package": {"ecosystem": "npm", "name": "café"}}]},
])
def test_what_the_ruleset_refuses_is_a_failed_read(tmp_path, over):
    a = adv()
    go(tmp_path, [a], net((gurl(G1), ghsa(**over))))
    assert one(tmp_path, a) == ("unknown", "unread")


def test_osv_fields():
    fields, named = verify._osv_reading(osv("MAL-2026-1", aliases=[G1], withdrawn="2026-01-01T00:00:00Z"), "MAL-2026-1")
    assert fields == {"osv_id": "MAL-2026-1", "withdrawn": "2026-01-01T00:00:00Z",
                      "packages": [{"ecosystem": "npm", "name": CC[1], "range": None, "first_patched": None}]}
    assert named == [G1]
    for over in ({"id": "MAL-2026-2"}, {"withdrawn": 1}, {"affected": "x"}, {"aliases": "x"},
                 {"affected": [{"package": {"ecosystem": 1, "name": "a"}}]}):
        with pytest.raises(verify._Bad):
            verify._osv_reading(osv("MAL-2026-1", **over), "MAL-2026-1")


def test_kev_readings():
    cat = verify._kev_catalog(kev((CVE, " Anthropic ", "Claude Code "), ("CVE-2026-3", "Cisco", "IOS"), ("CVE-2026-4", "", "Git")))
    assert verify._kev_readings(cat, CVE) == [{"cve_id": CVE, "name": "Anthropic Claude Code"}]
    assert verify._kev_readings(cat, CVE2) == [{"cve_id": CVE2, "name": None}]
    assert verify._kev_readings(cat, "CVE-2026-4") == [{"cve_id": "CVE-2026-4", "name": "Git"}]
    whole = kev((CVE, "Anthropic", "Claude Code"))
    for broken in ({**whole, "count": 5}, {**whole, "catalogVersion": None}, {**whole, "vulnerabilities": [3, 4]},
                   {"vulnerabilities": []}, [], {**whole, "count": 2, "vulnerabilities": [{"cveID": 1}, {"cveID": "x"}]}):
        with pytest.raises(verify._Bad):
            verify._kev_catalog(broken)
    whole["vulnerabilities"][0]["product"] = 5
    with pytest.raises(verify._Bad):
        verify._kev_readings(verify._kev_catalog(whole), CVE)


def test_a_response_that_names_too_many_ids_is_a_failed_read(tmp_path):
    a = adv()
    many = [{"type": "CVE", "value": f"CVE-2026-{5000 + i}"} for i in range(verify.MAX_NAMES + 1)]
    go(tmp_path, [a], net((gurl(G1), ghsa(identifiers=many))))
    assert one(tmp_path, a) == ("unknown", "unread")

# ------------------------------------------------------------------ one product's result

def rec(support=None, lowers=True):
    support = {k: v if len(v) == 3 else [*v, False] for k, v in (support or {}).items()}  # [level, lowers, stop_using]
    return {"etag": None, "at": 0, "lowers": lowers, "support": support, "names": []}


@pytest.mark.parametrize("level, records, complete, want", [
    ("high", [rec({"Claude Code": ["critical", True]})], False, ("contradicted", "below-source", "critical")),  # read bodies say more
    # a missing read could say more: unread, and what was read is reported as a lower bound (0z4e)
    ("high", [rec({"Claude Code": ["high", True]})], False, ("unknown", "unread", "high")),
    ("critical", [rec()], False, ("unknown", "unread", None)),
    ("high", [rec({"Claude Code": ["critical", True]})], True, ("contradicted", "below-source", "critical")),
    ("high", [rec({"Claude Code": ["high", True]})], True, ("confirmed", "match", "high")),
    ("critical", [rec()], True, ("contradicted", "unsupported", "none")),
    ("critical", [rec({"git": ["critical", True]})], True, ("contradicted", "unsupported", "none")),
    ("critical", [rec({"Claude Code": ["none", True]})], True, ("contradicted", "unsupported", "none")),  # withdrawn, reviewed
    ("critical", [rec({"Claude Code": ["none", False]})], True, ("unknown", "unauthoritative", "none")),  # withdrawn by its author
    ("critical", [rec(lowers=False)], True, ("unknown", "unauthoritative", "none")),
    ("critical", [rec({"Claude Code": ["high", True]}), rec(lowers=False)], True, ("unknown", "unauthoritative", "high")),
    ("critical", [rec({"Claude Code": ["high", True]})], True, ("contradicted", "above-source", "high")),
    ("critical", [rec({"Claude Code": ["notice", True]})], True, ("contradicted", "above-source", "notice")),
    ("high", [rec({"Claude Code": ["notice", True]})], True, ("unknown", "reading", "notice")),
    ("notice", [rec({"Claude Code": ["notice", True]})], True, ("confirmed", "match", "notice")),
    # what its subject's attacker can write confirms nothing, at any level
    ("notice", [rec({"Claude Code": ["notice", False]}, lowers=False)], True, ("unknown", "unauthoritative", "none")),
    ("high", [rec({"Claude Code": ["high", False]})], True, ("unknown", "unauthoritative", "none")),
])
def test_judge(level, records, complete, want):
    up = [("upgrade", "Claude Code", "99.0.0")]  # a complete action, so the source's level is not held (9kgk)
    r = verify.judge(level, "Claude Code", records, complete, ruleset.load(), up, "99.0.0")
    assert (r["result"], r["why"], r["source"]) == want


@pytest.mark.parametrize("actions, fixed, stop, want", [
    ([], None, False, ("confirmed", "match", "high")),  # KEV with no fix known: a published high is right
    ([("upgrade", "Claude Code", "99.0.0")], None, False, ("confirmed", "match", "high")),  # the version decides
    ([("upgrade", "Claude Code", "99.0.0")], "99.0.0", False, ("contradicted", "below-source", "critical")),
    ([("stop_using", "Claude Code", None)], None, False, ("confirmed", "match", "high")),
    ([("stop_using", "Claude Code", None)], None, True, ("contradicted", "below-source", "critical")),
])
def test_the_source_s_level_is_what_the_post_s_action_allows(actions, fixed, stop, want):
    """9kgk: a critical needs a complete action. The member holds the source's level to
    what the published actions and fixed version allow, as the poster does."""
    records = [rec({"Claude Code": ["critical", True, stop]})]
    r = verify.judge("high", "Claude Code", records, True, ruleset.load(), actions, fixed)
    assert (r["result"], r["why"], r["source"]) == want


def test_a_product_outside_this_reader_s_scope_file_is_not_judged():
    rs = ruleset.load()
    for complete in (True, False):
        r = verify.judge("high", "Nobody Runs This", [rec()], complete, rs)
        assert (r["result"], r["why"]) == ("unknown", "no-source")

def test_summary_is_the_worst_product():
    def p(result, why):
        return {"result": result, "why": why, "source": None}
    assert verify.summary({"a": p("confirmed", "match"), "b": p("contradicted", "unsupported")}) == ("contradicted", "unsupported")
    assert verify.summary({"a": p("confirmed", "match"), "b": p("unknown", "reading")}) == ("unknown", "reading")
    assert verify.summary({"a": p("contradicted", "below-source"), "b": p("contradicted", "above-source")})[1] == "above-source"
    assert verify.summary({"a": p("confirmed", "match")}) == ("confirmed", "match")


# ------------------------------------------------------------------ criterion 5: the product binding

def test_a_real_exploited_cve_on_the_wrong_product_is_contradicted(tmp_path):
    a = adv(id=CVE, level="critical")
    n = net((verify.KEV_URL, kev((CVE, "Cisco", "IOS XE"))))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("contradicted", "unsupported")
    go(tmp_path / "right", [a], net((verify.KEV_URL, KEV_CC)))  # another member's state: the entry names the product
    assert one(tmp_path / "right", a) == ("confirmed", "match")


def test_one_supported_product_does_not_confirm_another(tmp_path):
    a = adv(id=CVE, level="critical", products=("Codex", "Claude Code"))
    go(tmp_path, [a], net((verify.KEV_URL, kev((CVE, "OpenAI", "Codex")))))
    r = res(tmp_path, a)
    assert (r[K("Codex")]["result"], r[K()]["result"], r[K()]["why"]) == \
        ("confirmed", "contradicted", "unsupported")
    assert verify.summary(r) == ("contradicted", "unsupported")


# ------------------------------------------------------------------ criterion 6: no borrowed authority

def test_an_alias_no_source_ties_to_the_first_id_adds_nothing(tmp_path):
    """The bot lists a real, critical-making malware advisory for the same product as an alias."""
    a = adv(id=CVE, aliases=[G2], level="critical")
    n = net((verify.KEV_URL, kev()), (gurl(G2), ghsa(G2, type="malware", cve=CVE2)))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("unknown", "unauthoritative")  # never confirmed; KEV's silence contradicts nothing


def test_an_alias_tied_only_by_a_source_anyone_can_write_adds_nothing(tmp_path):
    a = adv(id=CVE, aliases=[G2], level="notice")
    go(tmp_path, [a], net((verify.KEV_URL, kev()), (gurl(G2), ghsa(G2, type="unreviewed", cve=CVE))))
    assert one(tmp_path, a) == ("unknown", "unauthoritative")


def test_an_attacker_written_first_id_cannot_borrow_a_real_exploited_cve(tmp_path):
    """An unreviewed advisory names a CVE that KEV truly lists for the product."""
    a = adv(id=G1, aliases=[CVE], level="critical")
    n = net((gurl(G1), ghsa(type="unreviewed", cve=CVE)), (verify.KEV_URL, KEV_CC))
    go(tmp_path, [a], n)
    assert n.urls == [gurl(G1)]  # what it names is not even read
    assert one(tmp_path, a) == ("unknown", "unauthoritative")


def test_a_fabricated_notice_is_not_confirmed_by_a_source_anyone_can_write(tmp_path):
    a = adv(level="notice")
    go(tmp_path, [a], net((gurl(G1), ghsa(type="unreviewed"))))
    assert one(tmp_path, a) == ("unknown", "unauthoritative")
    go(tmp_path / "reviewed", [a], net((gurl(G1), ghsa(type="reviewed", high=False))))
    assert one(tmp_path / "reviewed", a) == ("confirmed", "match")


def test_dropping_an_alias_never_turns_a_true_alert_into_a_contradiction(tmp_path):
    n = net((verify.KEV_URL, kev()), (gurl(G2), ghsa(G2, type="malware", cve=CVE)))
    a = adv(id=CVE, aliases=[G2], level="critical")
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("confirmed", "match")
    stripped = adv(id=CVE, aliases=[], level="critical")  # a bot patch replaced the aliases
    go(tmp_path, [stripped], n)
    assert one(tmp_path, stripped) == ("unknown", "unauthoritative")


def test_the_ids_an_authoritative_first_response_names_are_read_whatever_the_thread_lists(tmp_path):
    n = net((gurl(G1), ghsa(cve=CVE)), (verify.KEV_URL, KEV_CC))
    a = adv(id=G1, aliases=[], level="critical")  # the bot lists no alias, or dropped it
    go(tmp_path, [a], n)
    assert n.urls == [gurl(G1), verify.KEV_URL]
    assert one(tmp_path, a) == ("confirmed", "match")

def test_an_alias_whose_own_response_names_the_first_id_counts(tmp_path):
    a = adv(id=CVE, aliases=[G2], level="critical")
    go(tmp_path, [a], net((verify.KEV_URL, kev()), (gurl(G2), ghsa(G2, type="malware", cve=CVE))))
    assert one(tmp_path, a) == ("confirmed", "match")


def test_an_alias_the_first_response_does_not_name_is_never_requested(tmp_path):
    a = adv(id=G1, aliases=[G2, CVE, "MAL-2026-5"], level="high")
    n = net((gurl(G1), ghsa(cve=CVE)), (verify.KEV_URL, kev()), (gurl(G2), ghsa(G2, type="malware")))
    go(tmp_path, [a], n)
    assert sorted(n.urls) == sorted([gurl(G1), verify.KEV_URL])  # the CVE it names, and nothing else
    assert one(tmp_path, a) == ("confirmed", "match")


def test_more_eligible_aliases_than_are_read_leave_the_thread_unread(tmp_path):
    many = [f"GHSA-{c * 4}-{c * 4}-{c * 4}" for c in "2345"]
    a = adv(id=CVE, aliases=many, level="critical")
    n = net((verify.KEV_URL, KEV_CC), *((gurl(g), ghsa(g, cve=CVE)) for g in many))
    go(tmp_path, [a], n)
    assert len(n.calls) == 1 + verify.MAX_ALIASES
    assert one(tmp_path, a) == ("unknown", "unread")


def test_an_attacker_written_source_gives_no_downward_contradiction(tmp_path):
    a = adv(level="critical")
    go(tmp_path, [a], net((gurl(G1), ghsa(type="unreviewed", withdrawn_at="2026-01-01T00:00:00Z"))))
    assert one(tmp_path, a) == ("unknown", "unauthoritative")
    go(tmp_path / "b", [a], net((gurl(G1), ghsa(type="reviewed", withdrawn_at="2026-01-01T00:00:00Z"))))
    assert one(tmp_path / "b", a) == ("contradicted", "unsupported")
    # an unreviewed advisory that no longer lists the package
    go(tmp_path / "c", [a], net((gurl(G1), ghsa(type="unreviewed", pkgs=()))))
    assert one(tmp_path / "c", a) == ("unknown", "unauthoritative")


# ------------------------------------------------------------------ criterion 4: a failed read is unknown

TRUNCATED = json.dumps(ghsa()).encode()[:200]
FAILURES = {
    "404": 404, "429": 429, "403": 403, "500": 500, "301": 301, "timeout": TimeoutError(SENTINEL),
    "reset": OSError(SENTINEL), "truncated": TRUNCATED, "duplicate key": b'{"ghsa_id": 1, "ghsa_id": 2}',
    "nan": b'{"ghsa_id": NaN}', "not utf-8": b"\xff\xfe", "another id": ghsa(G2), "a list": [], "304 unasked": 304,
    "oversize": b" " * ((256 << 10) + 1),
}


@pytest.mark.parametrize("name", FAILURES)
def test_every_failure_is_unknown_and_is_asked_again(tmp_path, name):
    a = adv()
    n = net((gurl(G1), FAILURES[name]))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("unknown", "unread")
    go(tmp_path, [a], n)
    assert n.urls == [gurl(G1)] * 2
    n.set(gurl(G1), ghsa())
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("confirmed", "match")


@pytest.mark.parametrize("name", ["404", "429", "truncated"])
def test_a_failed_read_never_falls_back_to_what_was_cached(tmp_path, name):
    a = adv()
    n = net((gurl(G1), ('"e1"', ghsa())))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("confirmed", "match")
    raised = adv(level="critical")  # the published state changed: it is read again
    n.set(gurl(G1), FAILURES[name])
    go(tmp_path, [a, raised], n, wanted=[raised])
    assert one(tmp_path, raised) == ("unknown", "unread")
    assert n.calls[-1][1] == '"e1"'
    go(tmp_path, [raised], n)
    assert len(n.calls) == 3 and one(tmp_path, raised) == ("unknown", "unread")


def test_with_one_read_failed_nothing_is_confirmed(tmp_path):
    a = adv(id=CVE, aliases=[G2], level="high")
    n = net((verify.KEV_URL, kev()), (gurl(G2), 500))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("unknown", "unread")
    n.set(gurl(G2), ghsa(G2, type="malware", cve=CVE))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("contradicted", "below-source")


def test_a_failed_kev_read_is_unknown_for_every_cve_thread(tmp_path):
    advs = [adv(id=CVE, level="critical"), adv(id=CVE2, level="critical")]
    for broken in (503, b'{"catalogVersion": "x", "count": 9, "vulnerabilities": []}', json.dumps(KEV_CC).encode()[:60]):
        n = net((verify.KEV_URL, broken))
        go(tmp_path, advs, n)
        assert len(n.calls) == 1
        assert [one(tmp_path, a) for a in advs] == [("unknown", "unread")] * 2


# ------------------------------------------------------------------ criterion 1: only the three URLs

def test_no_url_of_an_event_is_requested(tmp_path):
    evil = "https://evil.example/x"
    a = adv(id=G1, aliases=[evil, "https://evil.example/GHSA-dddd-eeee-ffff", CVE], title=f"see {evil}",
            sources=[Source(evil, None), Source("https://api.github.com.evil.example/advisories/" + G1, None)])
    b = adv(id=evil, aliases=[G2], title="b")
    n = net((gurl(G1), ghsa(cve=CVE)), (verify.KEV_URL, KEV_CC))
    go(tmp_path, [a, b], n)
    assert set(n.urls) == {gurl(G1), verify.KEV_URL}
    assert res(tmp_path, b)[K()]["why"] == "no-source"
    assert all(u == verify.KEV_URL or u.startswith(("https://api.github.com/advisories/GHSA-", "https://api.osv.dev/v1/vulns/"))
               for u in n.urls)


# ------------------------------------------------------------------ criterion 2: the budget

def many_ghsa(count):
    out = []
    for i in range(count):
        s = f"{i:012d}".translate(str.maketrans("0123456789", "abcdefghij"))
        out.append(adv(id=f"GHSA-{s[:4]}-{s[4:8]}-{s[8:]}", title=f"t{i}"))
    return out


def test_ten_thousand_alerts_make_at_most_ten_requests(tmp_path):
    advs = many_ghsa(10_000)
    n = Net()
    go(tmp_path, advs, n)
    assert len(n.calls) == verify.MAX_FETCHES == 10
    n2 = Net()
    go(tmp_path, advs, n2)  # the next run goes on with threads not tried yet
    assert len(n2.calls) == 10 and not set(n.urls) & set(n2.urls)


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_a_run_stops_after_thirty_seconds_and_a_late_request_gets_what_is_left(tmp_path):
    clock, timeouts = Clock(), []

    def slow(url, etag, limit, timeout):
        timeouts.append(timeout)
        clock.t += 12.5
        raise OSError("slow")
    go(tmp_path, many_ghsa(50), slow, clock=clock)
    assert timeouts == [10, 10, 5.0]


def test_limits_per_source(tmp_path):
    n = net((verify.KEV_URL, KEV_CC))
    go(tmp_path, [adv(id=CVE, level="critical"), adv(id=G1, title="g"), adv(id="MAL-2026-1", title="m")], n)
    assert {u: lim for u, _, lim, _ in n.calls} == {verify.KEV_URL: 8 << 20, gurl(G1): 256 << 10,
                                                    ourl("MAL-2026-1"): 256 << 10}


# ------------------------------------------------------------------ the cache

def test_one_kev_request_serves_every_cve_thread_and_a_304_keeps_the_support(tmp_path):
    a, b = adv(id=CVE, level="critical"), adv(id=CVE2, level="critical", title="b")
    n = net((verify.KEV_URL, ('"k1"', KEV_CC)))
    go(tmp_path, [a, b], n)
    assert n.urls == [verify.KEV_URL]
    assert one(tmp_path, a) == ("confirmed", "match") and one(tmp_path, b) == ("unknown", "unauthoritative")
    go(tmp_path, [a, b], n)
    assert len(n.calls) == 1  # decisive results stand until the published state changes
    lower = adv(id=CVE, level="high")
    n.set(verify.KEV_URL, 304)
    go(tmp_path, [lower, b], n)
    assert n.calls[-1][1] == '"k1"'
    assert one(tmp_path, lower) == ("contradicted", "below-source")
    new = adv(id="CVE-2026-3000", level="critical", title="new")  # not read at that ETag: the body is needed
    n.set(verify.KEV_URL, ('"k1"', KEV_CC))
    go(tmp_path, [lower, b, new], n)
    assert n.calls[-1][1] is None and one(tmp_path, new) == ("unknown", "unauthoritative")


def test_a_304_with_nothing_stored_decides_nothing(tmp_path):
    a = adv(id=CVE, level="critical")
    go(tmp_path, [a], net((verify.KEV_URL, 304)))
    assert one(tmp_path, a) == ("unknown", "unread")


def test_state_changes_are_read_again_over_what_is_stored(tmp_path):
    a = adv(id=CVE, level="critical", products=("Claude Code",))
    n = net((verify.KEV_URL, ('"k1"', KEV_CC)))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("confirmed", "match")
    wider = adv(id=CVE, level="critical", products=("Claude Code", "git"))  # a bot patch added a product
    go(tmp_path, [wider], n)
    r = res(tmp_path, wider)
    assert (r[K()]["result"], r[K("git")]["result"], r[K("git")]["why"]) == ("confirmed", "contradicted", "unsupported")
    aliased = adv(id=CVE, aliases=[G2], level="critical")  # a bot patch added an alias, and its read fails
    n.set(gurl(G2), 500)
    go(tmp_path, [aliased], n)
    assert one(tmp_path, aliased) == ("unknown", "unread")
    assert verify.state_key(a) != verify.state_key(wider) != verify.state_key(aliased)
    assert verify.state_key(a) != verify.state_key(adv(id=CVE, level="high"))


def test_waiting_threads_go_highest_level_first_then_longest_untried(tmp_path):
    lo, hi = adv(id=G1, level="notice"), adv(id=G2, level="critical", title="hi")
    n = Net()
    go(tmp_path, [lo, hi], n)
    assert n.urls == [gurl(G2), gurl(G1)]
    newer = adv(id=G3, level="notice", title="newer")
    n2 = Net()
    go(tmp_path, [lo, newer], n2, now=NOW + 5)
    assert n2.urls == [gurl(G3), gurl(G1)]  # never tried comes before tried


@pytest.mark.parametrize("etag", ['"a"b"', '"line\nbreak"', '"' + "x" * 200 + '"', "bare", 7, f'"{SENTINEL} x"'])
def test_an_etag_of_another_shape_is_not_stored(tmp_path, etag):
    cache = go(tmp_path, [adv()], net((gurl(G1), (etag, ghsa()))))
    assert cache["sources"][G1]["etag"] is None


def test_nothing_a_source_says_is_stored(tmp_path):
    a = adv(id=CVE, aliases=[G1, "MAL-2026-1"], level="critical", products=("Claude Code", "git"))
    b = adv(id=G2, title="b")
    n = net((verify.KEV_URL, ('W/"kev-1"', KEV_CC)), (gurl(G1), ('"g-1"', ghsa(cve=CVE))),
            (ourl("MAL-2026-1"), osv("MAL-2026-1", aliases=[CVE, f"{SENTINEL}-10", "CVE-2026-9999"])),
            (gurl(G2), ghsa(G2, cve="CVE-2026-8888", pkgs=(CC, ("npm", f"{SENTINEL}-11")))))
    go(tmp_path, [a, b], n)
    text = (tmp_path / verify.FILE).read_text()
    assert SENTINEL not in text
    assert "9.9.9" not in text and "CVSS" not in text and "anthropic" not in text.lower()
    cache = json.loads(text)
    assert set(cache) == {"version", "ruleset", "kev", "sources", "results"}
    # ids the threads carried, and one an authoritative response named, in the exact form of an id
    assert set(cache["sources"]) == {CVE, G1, "MAL-2026-1", G2, "CVE-2026-8888"}
    scope, levels = ruleset.load().products(), {"none", "notice", "high", "critical"}
    for r in cache["sources"].values():
        assert set(r) == {"etag", "at", "lowers", "support", "names"}
        assert r["etag"] in (None, 'W/"kev-1"', '"g-1"') and type(r["lowers"]) is bool and type(r["at"]) is int
        assert all(k in scope and v[0] in levels and type(v[1]) is bool for k, v in r["support"].items())
        assert all(verify.norm_id(d) == d for d in r["names"])
    for r in cache["results"].values():
        for name, p in r["products"].items():
            assert name in (K(), K("git")) and set(p) == {"result", "why", "source"}
            assert p["source"] in levels | {None}


def test_a_cache_from_another_ruleset_is_not_used(tmp_path):
    a = adv()
    n = net((gurl(G1), ('"e1"', ghsa())))
    go(tmp_path, [a], n)
    scope = json.loads((schema.SPEC_DIR / "scope.json").read_text())
    scope["entries"][0]["match"].append("npm:another-name-for-claude-code")
    other = ruleset.Ruleset(json.loads((schema.SPEC_DIR / "ruleset.json").read_text()), scope, schema.load_scope())
    assert other.digest != ruleset.load().digest
    go(tmp_path, [a], n, rs=other)
    assert len(n.calls) == 2 and n.calls[-1][1] is None  # no ETag: the body is read again under the new rules
    assert verify.result_for(a, verify.load(tmp_path, other))[K()]["result"] == "confirmed"
    assert verify.result_for(a, verify.load(tmp_path))[K()]["why"] == "unread"


@pytest.mark.parametrize("text", ["", "{", "[]", '{"version": 2}', '{"version": 1, "version": 1}'])
def test_a_damaged_cache_is_an_empty_one(tmp_path, text):
    (tmp_path / verify.FILE).write_text(text)
    assert verify.load(tmp_path) == verify._empty(ruleset.load().digest)


def test_a_cache_with_one_wrong_value_is_an_empty_one(tmp_path):
    a = adv()
    go(tmp_path, [a], net((gurl(G1), ('"e1"', ghsa()))))
    good = json.loads((tmp_path / verify.FILE).read_text())
    assert verify.load(tmp_path) == good
    for path, value in ((("sources", G1, "etag"), "https://evil.example"), (("sources", G1, "support"), {"x": ["urgent", True]}),
                        (("sources", G1, "names"), ["text"]), (("results", verify.state_key(a), "products"),
                                                               {"Claude Code": {"result": "confirmed", "why": "x", "source": None}})):
        bad = json.loads(json.dumps(good))
        node = bad
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
        (tmp_path / verify.FILE).write_text(json.dumps(bad))
        assert verify.load(tmp_path)["sources"] == {}
    bad = json.loads(json.dumps(good))
    bad["sources"]["https://evil.example/x"] = bad["sources"][G1]
    (tmp_path / verify.FILE).write_text(json.dumps(bad))
    assert verify.load(tmp_path)["sources"] == {}


def test_threads_and_ids_no_longer_current_are_dropped(tmp_path):
    a, b = adv(), adv(id=G2, title="b")
    n = net((gurl(G1), ghsa()), (gurl(G2), ghsa(G2)))
    go(tmp_path, [a, b], n)
    cache = go(tmp_path, [b], n)
    assert set(cache["sources"]) == {G2} and set(cache["results"]) == {verify.state_key(b)}


def test_only_wanted_relay_bot_threads_are_read(tmp_path):
    a, b = adv(), adv(id=G2, title="b")
    cur = advisory(id=G3, posted_by="curator")
    n = Net()
    go(tmp_path, [a, b, cur], n, wanted=[a, cur])
    assert n.urls == [gurl(G1)]
    assert verify.result_for(cur, verify.load(tmp_path)) is None
    assert res(tmp_path, b)[K()]["why"] == "unread"


def test_off_shows_unknown_and_touches_no_file(tmp_path):
    a = adv()
    go(tmp_path, [a], net((gurl(G1), ghsa())))
    assert verify.result_for(a, None) == {K(): {"result": "unknown", "why": "off", "source": None}}
    assert one(tmp_path, a) == ("confirmed", "match")  # still there when the check is turned back on


def test_copies_of_one_advisory_share_one_read(tmp_path):
    n = net((gurl(G1), ghsa()))
    go(tmp_path, [adv(), adv(), adv(title="another title, the same published state")], n)
    assert n.urls == [gurl(G1)]


# ------------------------------------------------------------------ default_fetch, with no network

class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"{}", read_delay=0.0):
        self.status, self.headers, self.body, self.read_delay = status, headers or {}, body, read_delay

    def getheader(self, name, default=None):
        return {k.lower(): v for k, v in self.headers.items()}.get(name.lower(), default)

    def read(self, n):
        time.sleep(self.read_delay)
        out, self.body = self.body[:n], self.body[n:]
        return out


class FakeSock:
    def __init__(self):
        self.calls = []

    def settimeout(self, t):
        self.calls.append("settimeout")

    def shutdown(self, how):
        self.calls.append("shutdown")

    def close(self):
        self.calls.append("close")


def fake_connection(monkeypatch, response=None, connect_delay=0.0, response_delay=0.0, sock=None):
    log = []
    sock_of = {"sock": sock}

    class Conn:
        def __init__(self, host, timeout=None):
            log.append(("open", host, timeout))

        sock = None

        def connect(self):
            time.sleep(connect_delay)
            self.sock = sock_of.get("sock")

        def request(self, method, path, headers=None):
            log.append((method, path, headers))

        def getresponse(self):
            time.sleep(response_delay)
            self.sock = None  # as http.client does when the response will close the connection
            return response

        def close(self):
            pass
    monkeypatch.setattr(verify, "_CONNECTION", Conn)
    return log


@pytest.mark.parametrize("url", [
    "http://api.github.com/advisories/" + G1, "https://evil.example/advisories/" + G1,
    "https://api.github.com@evil.example/advisories/" + G1, "https://api.github.com:444/advisories/" + G1,
    "https://API.github.com.evil.example/x", "file:///etc/passwd", "https://api.github.com/advisories/x?y=1",
    "https://user:pw@api.github.com/advisories/" + G1,
])
def test_default_fetch_refuses_any_other_url(monkeypatch, url):
    log = fake_connection(monkeypatch, FakeResponse())
    with pytest.raises(OSError):
        REAL_FETCH(url, None, 1000, 1)
    assert log == []


def test_default_fetch_returns_a_whole_body_and_sends_four_headers(monkeypatch):
    log = fake_connection(monkeypatch, FakeResponse(headers={"Content-Length": "2", "ETag": '"e"'}))
    assert REAL_FETCH(gurl(G1), '"old"', 1000, 1) == (200, '"e"', b"{}")
    assert log == [("open", "api.github.com", 1), ("GET", "/advisories/" + G1, {
        "User-Agent": "aitools-alerts", "Accept": "application/json", "Accept-Encoding": "identity",
        "If-None-Match": '"old"'})]
    log = fake_connection(monkeypatch, FakeResponse(headers={"Transfer-Encoding": "chunked"}, body=b'{"a": 1}'))
    assert REAL_FETCH(verify.KEV_URL, None, 1000, 1)[2] == b'{"a": 1}'
    assert "If-None-Match" not in log[1][2]


def test_default_fetch_follows_no_redirect(monkeypatch):
    log = fake_connection(monkeypatch, FakeResponse(302, {"Location": "https://evil.example/", "Content-Length": "0"}, b""))
    assert REAL_FETCH(gurl(G1), None, 1000, 1) == (302, None, b"")
    assert [x[0] for x in log] == ["open", "GET"]


@pytest.mark.parametrize("headers, body", [
    ({"Content-Length": "500"}, b'{"complete": "json"}' + b" " * 80),  # shorter than declared, and it parses
    ({}, b"{}"),  # nothing says where it ends
    ({"Content-Length": "2", "Content-Encoding": "gzip"}, b"{}"),
    ({"Content-Length": "5000"}, b" " * 5000),  # declared past the limit
    ({"Transfer-Encoding": "chunked"}, b" " * 5000),  # runs past the limit
    ({"Content-Length": "x"}, b"{}"), ({"Content-Length": "-2"}, b"{}"),
    ({"Transfer-Encoding": "gzip, chunked"}, b"{}"),
])
def test_default_fetch_refuses_a_body_that_did_not_arrive_whole(monkeypatch, headers, body):
    fake_connection(monkeypatch, FakeResponse(headers=headers, body=body))
    with pytest.raises(OSError):
        REAL_FETCH(gurl(G1), None, 1000, 1)


@pytest.mark.parametrize("where", ["connect_delay", "response_delay", "read"])
def test_default_fetch_gives_up_at_the_deadline_in_every_phase(monkeypatch, where):
    resp = FakeResponse(headers={"Content-Length": "2"}, read_delay=5 if where == "read" else 0)
    fake_connection(monkeypatch, resp, **({where: 5} if where != "read" else {}))
    start = time.monotonic()
    with pytest.raises(OSError):
        REAL_FETCH(gurl(G1), None, 1000, 0.2)
    assert time.monotonic() - start < 1


def test_the_deadline_is_for_the_whole_request_not_each_phase(monkeypatch):
    resp = FakeResponse(headers={"Content-Length": "2"}, read_delay=0.15)
    fake_connection(monkeypatch, resp, connect_delay=0.15, response_delay=0.15)
    start = time.monotonic()
    with pytest.raises(OSError):
        REAL_FETCH(gurl(G1), None, 1000, 0.3)
    assert 0.25 < time.monotonic() - start < 1  # no phase took 0.3 s; the three together did


def test_a_request_that_outlived_its_wait_sends_nothing(monkeypatch):
    log = fake_connection(monkeypatch, FakeResponse(headers={"Content-Length": "2"}), connect_delay=0.4)
    with pytest.raises(OSError):
        REAL_FETCH(gurl(G1), None, 1000, 0.1)
    time.sleep(0.6)  # the name lookup returns after the caller has gone
    assert [x[0] for x in log] == ["open"]


def test_a_slow_body_is_cut_at_the_deadline_inside_the_request(monkeypatch):
    body = b" " * (65536 * 4)
    resp = FakeResponse(headers={"Content-Length": str(len(body))}, body=body, read_delay=0.1)
    fake_connection(monkeypatch, resp)
    box = []
    with pytest.raises(OSError):
        verify._request("api.github.com", "/x", None, 1 << 20, 0.15, box, __import__("threading").Event())
    assert len(resp.body) > 0  # it stopped reading: the deadline is the request's own, not only the caller's wait


def test_the_last_request_of_a_run_gets_only_what_is_left(monkeypatch, tmp_path):
    fake_connection(monkeypatch, FakeResponse(headers={"Content-Length": "2"}), connect_delay=5)
    ticks = iter([100.0])  # the run begins; every later reading is 29.8 seconds on

    def clock():
        return next(ticks, 129.8)
    start = time.monotonic()
    go(tmp_path, [adv()], REAL_FETCH, clock=clock)
    assert 0.15 < time.monotonic() - start < 1  # about 0.2 s, not the 10 s a request may take


def test_a_fetch_error_carries_no_text_of_the_response(monkeypatch):

    class Boom:
        def __init__(self, *a, **k):
            raise OSError(SENTINEL)
    monkeypatch.setattr(verify, "_CONNECTION", Boom)
    with pytest.raises(OSError) as e:
        REAL_FETCH(gurl(G1), None, 1000, 1)
    assert SENTINEL not in str(e.value)


# ------------------------------------------------------------------ review fixes

def test_the_thirty_seconds_also_end_work_that_needs_no_request(tmp_path):
    """One KEV answer serves every CVE thread; the clock still stops the run."""
    advs = [adv(id=f"CVE-2026-{7000 + i}", level="critical") for i in range(50)]
    clock = Clock()

    def slow(url, etag, limit, timeout):
        clock.t += 31
        return 200, None, json.dumps(kev()).encode()
    cache = go(tmp_path, advs, slow, clock=clock)
    assert len(cache["results"]) == 1  # the thread whose request was sent in time is finished; no other is begun
    cache = go(tmp_path, advs, lambda *a: (200, None, json.dumps(kev()).encode()), clock=Clock())
    assert len(cache["results"]) == 50


def test_threads_that_keep_failing_do_not_starve_the_rest(tmp_path):
    junk = [adv(id=f"CVE-2026-{8000 + i}", aliases=[f"GHSA-{c * 4}-{c * 4}-{i}{c * 3}" for c in "234"], level="critical")
            for i in range(3)]
    quiet = adv(id=G1, level="notice")
    n = net((verify.KEV_URL, kev()), (gurl(G1), ghsa(type="malware")))
    go(tmp_path, junk + [quiet], n)
    assert len(n.calls) == 10 and gurl(G1) not in n.urls  # 1 + 3 x 3: the budget is gone
    go(tmp_path, junk + [quiet], n, now=NOW + 3600)
    assert n.urls[10] == gurl(G1)  # never tried goes before tried
    assert one(tmp_path, quiet) == ("contradicted", "below-source")


def test_a_result_that_is_not_confirmed_is_read_again_after_a_day(tmp_path):
    a = adv(id=CVE, level="critical")
    n = net((verify.KEV_URL, kev((CVE, "Cisco", "IOS XE"))))
    go(tmp_path, [a], n)
    assert one(tmp_path, a) == ("contradicted", "unsupported")
    go(tmp_path, [a], n, now=NOW + verify.RETRY_S - 1)
    assert len(n.calls) == 1
    n.set(verify.KEV_URL, KEV_CC)  # CISA has listed it for the product since
    go(tmp_path, [a], n, now=NOW + verify.RETRY_S)
    assert one(tmp_path, a) == ("confirmed", "match")
    go(tmp_path, [a], n, now=NOW + 10 * verify.RETRY_S)
    assert len(n.calls) == 2  # confirmed stands


@pytest.mark.parametrize("path, value", [
    (("results", "KEY", "products", K(), "result"), []), (("results", "KEY", "products", K(), "why"), {}),
    (("results", "KEY", "products", K(), "source"), []), (("sources", G1, "support", "Claude Code"), [[], True]),
    (("sources", G1, "names"), [[]]), (("sources", G1, "names"), [None]), (("version",), 1), (("sources", G1, "etag"), []), (("kev",), []), (("ruleset",), []), (("version",), []),
    (("results", "KEY", "products"), [["Claude Code"]]), (("sources", G1), None), (("results",), None),
])
def test_a_cache_with_a_value_of_the_wrong_kind_is_an_empty_one_not_a_crash(tmp_path, path, value):
    a = adv()
    go(tmp_path, [a], net((gurl(G1), ('"e1"', ghsa()))))
    bad = json.loads((tmp_path / verify.FILE).read_text())
    node = bad
    for k in path[:-1]:
        node = node[verify.state_key(a) if k == "KEY" else k]
    node[path[-1]] = value
    (tmp_path / verify.FILE).write_text(json.dumps(bad))
    assert verify.load(tmp_path) == verify._empty(ruleset.load().digest)
    assert verify.result_for(a, verify.load(tmp_path))[K()]["why"] == "unread"


def test_a_thread_key_of_the_poster_s_is_read_by_its_public_id(tmp_path):
    a = adv(id=f"{CVE}:claude-code", level="critical")
    n = net((verify.KEV_URL, KEV_CC))
    go(tmp_path, [a], n)
    assert n.urls == [verify.KEV_URL] and one(tmp_path, a) == ("confirmed", "match")
    internal = adv(id="LEAD-9a4d0dc65b79:docker", aliases=["AITA-TEST-0001", "PYSEC-2026-1"], level="high")
    n2 = Net()
    go(tmp_path, [internal], n2)
    assert n2.calls == [] and res(tmp_path, internal)[K()]["why"] == "no-source"


def test_the_socket_is_still_reached_after_the_response_took_it_over(monkeypatch):
    """http.client clears conn.sock for a response that closes the connection; the body is still to come."""
    sock = FakeSock()
    resp = FakeResponse(headers={"Content-Length": "2"}, read_delay=0.5)
    fake_connection(monkeypatch, resp, sock=sock)
    with pytest.raises(OSError):
        REAL_FETCH(gurl(G1), None, 1000, 0.15)
    assert "shutdown" in sock.calls  # the blocked read is woken
    assert sock.calls.count("settimeout") >= 3  # connect, send, headers: each sets what is left on the kept socket


def test_a_thread_cut_off_by_the_budget_has_had_its_turn(tmp_path):
    greedy = adv(id=CVE, aliases=[G2, G3], level="critical")
    other = adv(id=G1, level="notice")
    clock = Clock()

    asked = []

    def slow(url, etag, limit, timeout):
        asked.append(url)
        clock.t += 16
        if url == verify.KEV_URL:
            return 200, None, json.dumps(kev()).encode()
        raise OSError("slow")
    cache = go(tmp_path, [greedy, other], slow, clock=clock)  # KEV, one alias, and the 30 seconds are gone
    assert asked == [verify.KEV_URL, gurl(G2)]
    assert res(tmp_path, greedy)[K()]["why"] == "unread"
    assert verify.state_key(other) not in cache["results"]
    n = net((gurl(G1), ghsa(high=False)))
    go(tmp_path, [greedy, other], n, now=NOW + 3600)
    assert n.urls[0] == gurl(G1)  # the thread that was cut off no longer comes first


# ------------------------------------------------------------------ one product identity (ai-tools-alerts#2mgd)

OTHER_VENDOR = kev((CVE, "Cisco", "IOS XE"))


@pytest.mark.parametrize("name", ["Claude Code", "claude code", "claude-code", "CLAUDE CODE", "@anthropic-ai/claude-code"])
def test_a_respelled_product_is_judged_as_the_scope_product_it_is(tmp_path, name):
    """The acceptance case: a critical for ``claude code`` that the catalog lists for
    another vendor is contradicted like one for ``Claude Code``; listed for the product,
    it is confirmed, its upgrade action naming it in the same spelling."""
    a = adv(id=CVE, level="critical", products=[(name, "claude-code")])
    go(tmp_path, [a], net((verify.KEV_URL, OTHER_VENDOR)))
    assert res(tmp_path, a) == {K(name, "claude-code"): {"result": "contradicted", "why": "unsupported", "source": "none"}}
    go(tmp_path / "listed", [a], net((verify.KEV_URL, KEV_CC)))
    assert res(tmp_path / "listed", a)[K(name, "claude-code")] == {"result": "confirmed", "why": "match", "source": "critical"}


@pytest.mark.parametrize("name, ecosystem", [("claude-code-router", "claude-code"), ("Claude Code", "skill"),
                                             ("Claude Code", "codex"), ("MCP servers and clients", "mcp")])
def test_a_product_that_is_no_scope_product_is_not_judged(tmp_path, name, ecosystem):
    a = adv(id=CVE, level="critical", products=[(name, ecosystem)])
    go(tmp_path, [a], net((verify.KEV_URL, KEV_CC)))
    assert res(tmp_path, a) == {K(name, ecosystem): {"result": "unknown", "why": "no-source", "source": None}}


def test_an_entry_of_the_same_name_under_another_ecosystem_is_another_product(tmp_path):
    """Results are per ecosystem and name. A signer who adds ``Claude Code`` under
    ``skill`` gets a second result and changes nothing of the tool's: not its
    confirmation, and not the refusal of a lowering."""
    plain = adv(id=CVE, level="critical")
    both = adv(id=CVE, level="critical", products=["Claude Code", ("Claude Code", "skill")],
               actions=[schema.Action("upgrade", "Claude Code", "99.0.0")])
    n = net((verify.KEV_URL, KEV_CC))
    go(tmp_path, [plain, both], n)
    r = res(tmp_path, both)
    assert r[K()] == res(tmp_path, plain)[K()] == {"result": "confirmed", "why": "match", "source": "critical"}
    assert r[K("Claude Code", "skill")]["why"] == "no-source" and len(r) == 2
    assert verify.state_key(plain) != verify.state_key(both)
    ask = verify.at_level(both, "high")
    go(tmp_path, [both, ask], n)
    assert verify.lowering(both, "high", verify.load(tmp_path), NOW) is False


def test_the_product_key_cannot_be_forged_by_a_post():
    """``pkey`` joins ecosystem and name with a line feed: the schema refuses one in either."""
    block = {"id": CVE, "aliases": [], "level": "high", "advisory_severity": None, "title": "t",
             "products": [{"name": "Claude Code", "ecosystem": "claude-code", "affected": None, "fixed": None}],
             "actions": [], "sources": [{"url": "https://example.invalid/a", "published_at": None}],
             "posted_by": "relay-bot", "posted_at": NOW, "expires_at": None}
    schema.validate(block)
    for field, value in (("name", "skill\nClaude Code"), ("ecosystem", "skill\nx")):
        with pytest.raises(ValueError):
            schema.validate({**block, "products": [{**block["products"][0], field: value}]})


def test_a_run_cut_off_by_the_request_budget_leaves_a_product_unread_and_the_next_run_judges_it(tmp_path, monkeypatch):
    a = adv(id=G1, level="high")
    monkeypatch.setattr(verify, "MAX_FETCHES", 1)
    n = net((gurl(G1), ghsa(cve=CVE)), (verify.KEV_URL, kev()))
    go(tmp_path, [a], n)  # the advisory is read; the CVE it names is not
    assert n.urls == [gurl(G1)] and one(tmp_path, a) == ("unknown", "unread")
    monkeypatch.setattr(verify, "MAX_FETCHES", 10)
    go(tmp_path, [a], n, now=NOW + 3600)
    assert one(tmp_path, a) == ("confirmed", "match")


def test_a_cache_of_the_version_before_is_an_empty_one(tmp_path):
    a = adv()
    go(tmp_path, [a], net((gurl(G1), ghsa())))
    old = json.loads((tmp_path / verify.FILE).read_text())
    assert old["version"] == 4
    old["version"] = 3
    (tmp_path / verify.FILE).write_text(json.dumps(old))
    assert verify.load(tmp_path) == verify._empty(ruleset.load().digest)
