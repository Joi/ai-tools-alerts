import json
from pathlib import Path

import pytest

from aitools_alerts.poster.candidates import (
    KEV_CATALOG_URL,
    Candidate,
    Source,
    from_collector,
    from_heartbeat,
    from_kev,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
HEARTBEAT = FIXTURES / "heartbeat"
COLLECTOR = FIXTURES / "collector" / "run-record.json"
# Placeholder deployment names, set as the poster config's strip_hosts and
# internal_host_suffixes would set them; the real ones live only in the live config.
FLEET_NAMES = ("hostalpha", "hostbeta", "hostgamma")


@pytest.fixture(autouse=True)
def _deployment(monkeypatch):
    from aitools_alerts.poster import candidates
    monkeypatch.setattr(candidates, "FLEET_HOSTS", FLEET_NAMES)
    monkeypatch.setattr(candidates, "INTERNAL_SUFFIXES", (".corp.example",))


def _by_id(cands):
    return {c.id: c for c in cands}


def _fixture_hosts(record):
    hosts = {h["host"] for h in record.get("host_coverage", [])}
    findings = record["findings"]
    items = findings.items() if isinstance(findings, dict) else [(None, f) for f in findings]
    for key, f in items:
        if key:
            hosts.update(key.split("|")[1:-1])
        for h in f.get("hosts", []) + f.get("affected_hosts", []):
            hosts.add(h if isinstance(h, str) else h["host"])
    return hosts


def _write_run(tmp_path, record):
    (tmp_path / "run.json").write_text(json.dumps(record))
    return tmp_path


def test_from_heartbeat_maps_fixture():
    cands = from_heartbeat(HEARTBEAT)
    assert all(isinstance(c, Candidate) for c in cands)
    by = _by_id(cands)
    assert set(by) == {"CVE-2026-86950", "CVE-2026-112697", "WordPress-7.1.4", "Tailworm"}

    cg = by["CVE-2026-86950"]
    assert cg.product_text == "CoreGraphics"
    assert cg.sources == (Source("https://support.apple.com/en-us/149228", None),)
    assert cg.local_level_hint is None
    assert cg.advisory_severity == "code execution; exploitation reported on iOS"
    assert cg.exploited is False and cg.trojanized is False and cg.injection_exec is False

    wk = by["CVE-2026-112697"]
    assert wk.product_text == "WebKit"
    assert wk.local_level_hint == "high"
    assert len(wk.aliases) == 7 and "CVE-2026-112655" in wk.aliases

    wp = by["WordPress-7.1.4"]
    assert wp.aliases == ("CVE-2026-119977",)
    assert wp.local_level_hint is None  # "Unknown"
    assert wp.exploited is False  # free text "CISA KEV added" never sets the flag

    assert cands.skipped["no source"] == 1  # other-leads


def test_heartbeat_adapter_never_emits_hosts_or_evidence():
    record = json.loads((HEARTBEAT / "run.json").read_text())
    hosts = _fixture_hosts(record)
    assert hosts, "fixture must name placeholder hosts for this test to mean anything"
    blob = json.dumps([c.to_dict() for c in from_heartbeat(HEARTBEAT)]).lower()
    for name in sorted(hosts) + list(FLEET_NAMES):
        assert name.lower() not in blob, name
    for marker in ("/users/", "evidence", "tracker#", "alert_decision", "prioritize"):
        assert marker not in blob, marker


def test_heartbeat_scrubs_hosts_in_text_and_drops_host_urls(tmp_path):
    record = {
        "host_coverage": [{"host": "node-7"}],
        "findings": {
            "CVE-2026-1|node-9|curl": {
                "advisory_severity": "RCE seen on node-7 and NODE-9",
                "source": "https://example.com/a",
                "fixed": "8.1 (hostalpha has 8.0)",
            },
            "CVE-2026-2": {"product": "tool", "source": "https://node-7.example.net/x"},
            "node-7": {"source": "https://example.com/b"},
        },
    }
    cands = from_heartbeat(_write_run(tmp_path, record))
    by = _by_id(cands)
    c = by["CVE-2026-1"]
    assert c.product_text == "curl"
    assert c.advisory_severity is None  # a free-text field naming a host is dropped
    assert c.fixed is None  # the heartbeat never fills fixed/affected
    assert "CVE-2026-2" not in by  # only source named a host: dropped, so no source
    assert cands.skipped["no source"] == 1
    assert cands.skipped["id names a host or private detail"] == 1


def test_heartbeat_unreadable_or_malformed_never_raises(tmp_path):
    assert list(from_heartbeat(tmp_path / "missing")) == []
    (tmp_path / "run.json").write_text("{not json")
    assert from_heartbeat(tmp_path).skipped["run.json unreadable"] == 1
    for bad in ([], {"findings": "x"}, {"findings": None}):
        out = from_heartbeat(_write_run(tmp_path, bad))
        assert list(out) == [] and sum(out.skipped.values()) == 1 and out.rejected is not None
    record = {"findings": {
        "a": ["not", "a", "dict"],
        "b": {"id": 5, "ids": "x", "aliases": "y", "source": ["https://x.example"],
              "local_severity": 3, "exploited": "true"},
        "CVE-2026-3": {"source": "https://example.com/c", "exploited": 1, "trojanized": "yes",
                       "aliases": [1, None, "GHSA-x", "GHSA-x"], "local_severity": " Medium ",
                       "published_at": {"x": 1}},
        "CVE-2026-4": {"source": "javascript:alert(1)"},
        "CVE-2026-5": {"source": "https://exa mple.com/"},
    }}
    out = from_heartbeat(_write_run(tmp_path, record))
    by = _by_id(out)
    assert set(by) == {"CVE-2026-3"}
    c = by["CVE-2026-3"]
    assert c.exploited is False and c.trojanized is False
    assert c.aliases == ("GHSA-x",)
    assert c.local_level_hint == "medium"
    assert c.sources == (Source("https://example.com/c", None),)
    assert out.skipped["finding not an object"] == 1
    assert out.skipped["no source"] == 3


def test_from_kev_maps_feed_items():
    feeds = json.loads((HEARTBEAT / "feeds.json").read_text())
    cands = from_kev(feeds["cisa-kev"], "2026-11-01")
    assert len(cands) == 1
    c = cands[0]
    assert c.id == "CVE-2026-119977"
    assert c.exploited is True
    assert c.product_text == "WordPress WordPress Core"
    assert c.sources[0] == Source(KEV_CATALOG_URL, "2026-11-03")
    assert c.observed_at == "2026-11-03"


def test_kev_adapter_filters_by_date_added():
    kev = {"items": [
        {"cveID": "CVE-2026-0001", "dateAdded": "2026-10-31", "vendorProject": "A", "product": "a"},
        {"cveID": "CVE-2026-0002", "dateAdded": "2026-11-01", "vendorProject": "B", "product": "b"},
        {"cveID": "CVE-2026-0003", "dateAdded": "2026-11-02", "vendorProject": "C", "product": "c"},
    ]}
    assert [c.id for c in from_kev(kev, "2026-11-01")] == ["CVE-2026-0002", "CVE-2026-0003"]
    assert [c.id for c in from_kev(kev, "2026-11-03")] == []


def test_kev_catalog_shape_and_notes_urls():
    kev = {"catalogVersion": "2026.11.04", "vulnerabilities": [
        {"cveID": "CVE-2026-1111", "dateAdded": "2026-11-04", "vendorProject": "Anthropic",
         "product": "Claude Code", "shortDescription": "ignored",
         "notes": "https://vendor.example/sa-1 ; https://nvd.nist.gov/vuln/detail/CVE-2026-1111 "
                  "ftp://x.example/ junk https://vendor.example/sa-1"},
        {"cveID": "CVE-26-1", "dateAdded": "2026-11-04", "vendorProject": "X", "product": "y"},
        {"cveID": "CVE-2026-2222", "dateAdded": "2026-13-40", "vendorProject": "X", "product": "y"},
        {"cveID": "CVE-2026-3333", "dateAdded": "2026-11-04", "vendorProject": "", "product": "y"},
        "not a dict",
    ]}
    out = from_kev(kev, "2026-11-01")
    assert [c.id for c in out] == ["CVE-2026-1111"]
    assert [s.url for s in out[0].sources] == [
        KEV_CATALOG_URL,
        "https://vendor.example/sa-1",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
    ]
    assert out[0].product_text == "Anthropic Claude Code"
    assert out.skipped == {"bad cveID": 1, "bad dateAdded": 1, "no product": 1,
                           "kev item not an object": 1}
    assert from_kev(None, "2026-11-01").skipped["kev not an object"] == 1
    assert from_kev({"items": "x"}, "2026-11-01").skipped["kev items not a list"] == 1


@pytest.mark.parametrize("bad", ["2026-11", "11/01/2026", "2026-02-30", None, 20261101])
def test_kev_rejects_bad_since_date(bad):
    with pytest.raises(ValueError):
        from_kev({"items": []}, bad)


def test_from_collector_maps_fixture():
    record = json.loads(COLLECTOR.read_text())
    cands = from_collector(record)
    by = _by_id(cands)
    assert set(by) == {"CVE-2026-1001", "GHSA-dddd-eeee-ffff", "CVE-2026-2002", "CVE-2026-6006"}
    ssh = by["CVE-2026-1001"]
    assert ssh.product_text == "OpenSSH"
    assert ssh.aliases == ("GHSA-aaaa-bbbb-cccc",)
    assert ssh.exploited is False  # exploited is KEV-only; from_kev carries it
    assert ssh.local_level_hint == "critical"
    assert ssh.sources == (Source(KEV_CATALOG_URL, "2026-10-25T20:00:00Z"),)
    assert by["GHSA-dddd-eeee-ffff"].exploited is False
    blob = json.dumps([c.to_dict() for c in cands]).lower()
    for name in sorted(_fixture_hosts(record)) + list(FLEET_NAMES):
        assert name.lower() not in blob, name
    for marker in ("rationale", "recommended_action", "affected_hosts", "tailnet", "guest"):
        assert marker not in blob, marker


def test_collector_untrusted_input():
    for bad in (None, [], {"schema_version": 2, "findings": []}, {"schema_version": True, "findings": []},
                {"schema_version": "1", "findings": []}):
        assert from_collector(bad).skipped["schema_version"] == 1
        assert from_collector(bad).rejected == "schema_version"
    assert from_collector({"schema_version": 1, "findings": {}}).skipped["findings not a list"] == 1
    assert from_collector({"schema_version": 1, "findings": {}}).rejected == "findings not a list"
    assert from_collector({"schema_version": 1, "findings": [1]}).rejected is None  # one bad item only
    src = [{"url": "https://example.com/x", "published_at": "2026-11-01"}]
    record = {"schema_version": 1, "unknown": object(), "findings": [
        {"id": "CVE-2026-7", "product": "P", "sources": src, "exploited": "true",
         "aliases": [f"A-{i}" for i in range(100)]},
        {"id": "X" * 500, "product": "P", "sources": src},
        {"id": "CVE-2026-8", "sources": src},
        {"id": "CVE-2026-9", "product": "P", "sources": [{"url": 5}, "https://example.com/y"]},
        {"id": "CVE-2026-10", "product": "P", "sources": src, "injection_exec": True,
         "fixed": "1.2.3", "affected": "< 1.2.3"},
        {"id": "CVE-2026-11", "product": "P", "sources": src, "fixed": "no fix available",
         "affected": "unknown"},
        "nope",
    ]}
    out = from_collector(record)
    by = _by_id(out)
    assert set(by) == {"CVE-2026-7", "CVE-2026-10", "CVE-2026-11"}
    assert (by["CVE-2026-11"].fixed, by["CVE-2026-11"].affected) == (None, None)
    assert by["CVE-2026-7"].exploited is False
    assert len(by["CVE-2026-7"].aliases) == 32
    assert by["CVE-2026-10"].injection_exec is True
    assert (by["CVE-2026-10"].fixed, by["CVE-2026-10"].affected) == ("1.2.3", "< 1.2.3")
    assert out.skipped == {"no id": 1, "no product": 1, "no source": 1, "finding not an object": 1}


def test_fixtures_contain_no_fleet_names():
    paths = [HEARTBEAT / "run.json", HEARTBEAT / "feeds.json", COLLECTOR]
    for p in paths:
        text = p.read_text().lower()
        assert "/users/" not in text, p.name  # deployment host names: scripts/public-scan.sh
        assert "jibot-code#" not in text, p.name


PRIVATE = {
    "advisory_severity": "RCE; see /Users/op/security/evidence.txt",
    "local_severity": "high on node-7",
    "observed_at": "2026-11-01 on node-7",
    "published_at": "node-7 2026-11-01",
    "fixed": "9.9p1 (/home/op/notes)",
    "affected": "node-7 runs 9.8p1",
    "exploited": True,
}
PRIVATE_SOURCES = [
    "https://user:pw@example.com/a",
    "https://example.com/Users/op/evidence.json",
    "https://example.com/q?file=/Users/op/x",
    "https://node-7.example.net/a",
]


def _assert_clean(cands):
    blob = json.dumps([c.to_dict() for c in cands]).lower()
    for marker in ("node-7", "/users/", "/home/", "jibot-code#", "user:pw", "9.8p1", "evidence"):
        assert marker not in blob, marker


def _check_private_case(cands):
    by = _by_id(cands)
    assert set(by) == {"CVE-2026-50"}, cands.skipped
    c = by["CVE-2026-50"]
    assert c.exploited is False  # a forged boolean is ignored outside from_kev
    assert c.advisory_severity is None and c.local_level_hint is None and c.observed_at is None
    assert c.fixed is None and c.affected is None
    assert c.aliases == ("GHSA-ok",)
    assert c.sources == (Source("https://example.com/advisory", None),)
    _assert_clean(cands)


def test_heartbeat_private_values_in_retained_fields(tmp_path):
    finding = dict(PRIVATE, source="https://example.com/advisory#frag",
                   aliases=["GHSA-ok", "jibot-code#ab12", "/Users/op/x"])
    record = {"host_coverage": [{"host": "node-7"}], "findings": {
        "CVE-2026-50": finding,
        "CVE-2026-51": {"product": "see jibot-code#ab12", "source": "https://example.com/b"},
        **{f"CVE-2026-6{i}": {"source": u} for i, u in enumerate(PRIVATE_SOURCES)},
    }}
    out = from_heartbeat(_write_run(tmp_path, record))
    _check_private_case(out)
    assert out.skipped["no source"] == len(PRIVATE_SOURCES)
    assert out.skipped["no product"] == 1


def test_collector_private_values_in_retained_fields():
    sources = [{"url": "https://example.com/advisory#frag", "published_at": PRIVATE["published_at"]}]
    record = {"schema_version": 1, "host_coverage": [{"host": "node-7"}], "findings": [
        dict(PRIVATE, id="CVE-2026-50", product="P", sources=sources,
             aliases=["GHSA-ok", "jibot-code#ab12"]),
        *[{"id": f"CVE-2026-6{i}", "product": "P", "sources": [{"url": u}]}
          for i, u in enumerate(PRIVATE_SOURCES)],
    ]}
    out = from_collector(record)
    _check_private_case(out)
    assert out.skipped["no source"] == len(PRIVATE_SOURCES)


def test_kev_private_values_in_notes_and_fields():
    kev = {"items": [
        {"cveID": "CVE-2026-0050", "dateAdded": "2026-11-02", "vendorProject": "V",
         "product": "P", "notes": " ".join(PRIVATE_SOURCES[:3]) + " https://example.com/ok"},
        {"cveID": "CVE-2026-0052", "dateAdded": "2026-11-02", "vendorProject": "V",
         "product": "P on hostbeta"},
        {"cveID": "CVE-2026-0051", "dateAdded": "2026-11-02", "vendorProject": "V",
         "product": "see /Users/op/x"},
    ]}
    out = from_kev(kev, "2026-11-01")
    assert [c.id for c in out] == ["CVE-2026-0050"]
    assert out[0].product_text == "V P"
    assert [s.url for s in out[0].sources] == [KEV_CATALOG_URL, "https://example.com/ok"]
    assert out.skipped["no product"] == 2
    _assert_clean(out)


@pytest.mark.parametrize("field, value", [
    ("product", "Claude Code at `/Users/op/private.txt`"),
    ("product", "Claude Code 9.8p1 installed on node-7"),
    ("product", "Claude Code on %6Eode-7"),
    ("id", "CVE-2026-1|`~/notes`"),
])
def test_private_detail_in_product_or_id_drops_the_item(field, value):
    f = {"id": "CVE-2026-70", "product": "P", "sources": [{"url": "https://example.com/a"}]}
    f[field] = value
    record = {"schema_version": 1, "host_coverage": [{"host": "node-7"}], "findings": [f]}
    out = from_collector(record)
    assert list(out) == [] and sum(out.skipped.values()) == 1


@pytest.mark.parametrize("url", [
    "https://example.com/?host=%6Eode-7",
    "https://example.com/?file=%2FUsers%2Fop%2Fprivate.txt",
    "https://example.com/?issue=jibot-code%23ab12",
    "https://example.com/%2575sers/x?f=%252FUsers%252Fop",
    "https://example.com/a/%7E/notes",
    "https://example.org/advisory?evidence=/Volumes/Work/scan.json",
    "https://example.org/advisory?log=%2Fopt%2Fwatch%2Fout.txt",
    "https://example.com/advisory?file=C:/work/incident.txt",
    "https://example.com/advisory?file=C%3A%2Fwork%2Fincident.txt",
    "https://example.com/advisory?share=%5C%5Cfileserver%5Ccase",
    "https://example.org/advisory?evidence=/Library/Logs/private.log",
    "https://example.org/advisory?evidence=%2FLibrary%2FLogs%2Fprivate.log",
    "https://example.org/advisory?file=/library/Logs/private.log",
    "https://example.org/advisory?app=/applications/Secret.app/Contents",
    "https://example.org/advisory?d=/Volumes/Work/x",
    "https://example.org/advisory?evidence=/volumes/Work/confidential-report.json",
    "https://example.org/advisory?evidence=%2FvOlUmEs%2FWork%2Fx.json",
    "https://example.org/advisory?d=/srv/data/x", "https://example.org/advisory?d=/mnt/x/y",
    "https://example.org/advisory?d=/root/notes", "https://example.org/advisory?d=/usr/local/etc/x",
    "https://example.org/advisory?d=/media/joi/usb", "https://example.org/advisory?d=/run/user/501/x",
    "https://example.org/advisory?d=/Applications/X.app", "https://example.org/advisory?d=/System/Volumes/Data",
    "https://example.org/advisory?d=C:%5CUsers%5Cx", "https://example.org/advisory?d=%5C%5Cserver%5Cshare",
])
def test_percent_encoded_private_detail_in_source_url_is_dropped(url):
    record = {"schema_version": 1, "host_coverage": [{"host": "node-7"}], "findings": [
        {"id": "CVE-2026-71", "product": "P",
         "sources": [{"url": url}, {"url": "https://example.com/clean"}]},
    ]}
    out = from_collector(record)
    assert [s.url for s in out[0].sources] == ["https://example.com/clean"]


@pytest.mark.parametrize("fixed", ["1.x", "2.*", "unknown", "no fix", "v", "1.2.3 or later"])
def test_fixed_rejects_placeholders(fixed):
    record = {"schema_version": 1, "findings": [
        {"id": "CVE-2026-72", "product": "P", "sources": [{"url": "https://example.com/a"}],
         "injection_exec": True, "fixed": fixed},
    ]}
    assert from_collector(record)[0].fixed is None


def test_affected_range_parser_is_linear():
    import time
    hostile = "1" + "  1" * 60 + "?"
    record = {"schema_version": 1, "findings": [
        {"id": "CVE-2026-73", "product": "P", "sources": [{"url": "https://example.com/a"}],
         "affected": hostile},
        {"id": "CVE-2026-74", "product": "P", "sources": [{"url": "https://example.com/a"}],
         "affected": ">= 1.0, < 2.0 || 3.x"},
    ]}
    start = time.monotonic()
    out = _by_id(from_collector(record))
    assert time.monotonic() - start < 1.0
    assert out["CVE-2026-73"].affected is None
    assert out["CVE-2026-74"].affected == ">= 1.0, < 2.0 || 3.x"


def test_heartbeat_deeply_nested_json_never_raises(tmp_path):
    deep = "[" * 100000 + "]" * 100000
    (tmp_path / "run.json").write_text('{"x": ' + deep + ', "findings": {}}')
    out = from_heartbeat(tmp_path)  # a decoder RecursionError is caught; newer decoders parse it
    assert list(out) == []


@pytest.mark.parametrize("url", [
    "http://localhost:8080/evidence",
    "http://127.0.0.1/x",
    "http://100.101.102.103/x",
    "http://10.0.0.5/x",
    "http://[fd7a:115c:a1e0::1]/x",
    "https://buzz-ops.corp.example/x",
    "https://printer.local/x",
    "https://intranet/x",
])
def test_internal_source_hosts_are_dropped(url):
    record = {"schema_version": 1, "findings": [
        {"id": "CVE-2026-75", "product": "P",
         "sources": [{"url": url}, {"url": "https://example.com/clean"}]},
    ]}
    assert [s.url for s in from_collector(record)[0].sources] == ["https://example.com/clean"]


@pytest.mark.parametrize("severity", [
    "see /users/op/x", "log>/Users/op/x", "file:///Users/op/x", "a|/home/op/x",
    "tracked in Jibot-Code#ab12", "bad \ud800 surrogate", "rtl \u202e text", "bell \x07",
])
def test_private_or_unsafe_text_is_dropped(severity):
    record = {"schema_version": 1, "findings": [
        {"id": "CVE-2026-76", "product": "P", "sources": [{"url": "https://example.com/a"}],
         "advisory_severity": severity, "observed_at": "2026-99-99T99:99Z"},
    ]}
    c = from_collector(record)[0]
    assert c.advisory_severity is None and c.observed_at is None


def test_hosts_named_in_other_shapes_are_scrubbed(tmp_path):
    record = {"host_coverage": ["str-host"], "findings": {
        "CVE-2026-77|node-9": {"advisory_severity": "seen on node-9", "source": "https://example.com/a"},
        "CVE-2026-78": {"host": {"host": "zz-box"}, "advisory_severity": "zz-box and str-host",
                        "source": "https://example.com/b"},
    }}
    by = _by_id(from_heartbeat(_write_run(tmp_path, record)))
    assert by["CVE-2026-77"].advisory_severity is None
    assert by["CVE-2026-78"].advisory_severity is None


@pytest.mark.parametrize("url", [
    "https://printer.%6cocal/advisory",
    "https://%31%30.0.0.5/x",
    "https://example.com/\ud800",
    "https://example.com/%E2%80%AEx",
])
def test_encoded_or_unsafe_source_urls_are_dropped(url):
    record = {"schema_version": 1, "findings": [
        {"id": "CVE-2026-79", "product": "P",
         "sources": [{"url": url}, {"url": "https://example.com/clean"}]},
    ]}
    assert [s.url for s in from_collector(record)[0].sources] == ["https://example.com/clean"]


def test_heartbeat_unsafe_id_from_ids_is_not_used(tmp_path):
    record = {"findings": {"CVE-2026-80": {"ids": ["CVE-\u202e2026-1", "CVE-2026-81"],
                                           "source": "https://example.com/a"}}}
    by = _by_id(from_heartbeat(_write_run(tmp_path, record)))
    assert set(by) == {"CVE-2026-81"}


@pytest.mark.parametrize("fixed, kept", [
    ("1" * 64, True), ("v" + "1" * 63, True), ("1" * 65, False),
    ("v1.2.3+" + "a" * 64, False),
])
def test_fixed_length_boundary_never_truncates(fixed, kept):
    record = {"schema_version": 1, "findings": [
        {"id": "CVE-2026-82", "product": "P", "sources": [{"url": "https://example.com/a"}],
         "fixed": fixed},
    ]}
    assert from_collector(record)[0].fixed == (fixed if kept else None)


def test_apple_developer_library_url_is_kept():
    url = "https://developer.apple.com/library/archive/releasenotes/x.html"
    record = {"schema_version": 1, "findings": [{"id": "CVE-2026-72", "product": "P", "sources": [{"url": url}]}]}
    assert [s.url for s in from_collector(record)[0].sources] == [url]


@pytest.mark.parametrize("url", ["https://kubernetes.io/docs/concepts/storage/volumes/",
                                 "https://docs.docker.com/engine/storage/volumes/",
                                 "https://example.com/jdbc:h2://x"])
def test_public_volume_docs_and_double_slash_schemes_are_kept(url):
    record = {"schema_version": 1, "findings": [{"id": "CVE-2026-73", "product": "P", "sources": [{"url": url}]}]}
    assert [s.url for s in from_collector(record)[0].sources] == [url]


APPLE = "https://support.apple.com/en-us/149521"
APPLE_TITLE = "APPLE-SA-2026-11-03-1 macOS Example 27.2 (macOS 27 fixed in 27.2): WebKit: a crafted page may run code"


def _apple(*sources, product="macos", **kw):
    f = {"id": "CVE-2099-0101", "product": product, "sources": list(sources), **kw}
    return from_collector({"schema_version": 1, "findings": [f]})[0].fixed


def _src(title, url=APPLE + "#CVE-2099-0101", role="primary"):
    return {"url": url, "role": role, "title": title, "published_at": None}


def test_collector_apple_release_title_gives_the_fix_version():
    kev = _src("CISA KEV entry", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    assert _apple(_src(APPLE_TITLE)) == "27.2"
    assert _apple(kev, _src(APPLE_TITLE)) == "27.2"  # other publishers state no version
    assert _apple(_src(APPLE_TITLE), fixed="27.3") == "27.3"  # the record's own field wins


@pytest.mark.parametrize("sources,product", [
    ([_src(APPLE_TITLE), _src(APPLE_TITLE.replace("27.2", "27.1"), url="https://support.apple.com/en-us/149522")], "macos"),
    ([_src(APPLE_TITLE), _src(None, url="https://support.apple.com/en-us/149522")], "macos"),
    ([_src("APPLE-SA-1 macOS Example 27.2: WebKit (component fixed in 1.2): code")], "macos"),
    ([_src("APPLE-SA-1 macOS Example 26.9 (macOS 27 fixed in 26.9): code")], "macos"),
    ([_src(APPLE_TITLE)], "safari"),
    ([_src(APPLE_TITLE, url="https://vendor.example.com/en-us/149521")], "macos"),
    # A rejected source supplies nothing, though a public one keeps the candidate.
    ([_src(APPLE_TITLE, url="https://support.apple.com/Users/alice/x"),
      _src("CISA KEV entry", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog")], "macos"),
])
def test_collector_apple_title_fails_closed(sources, product):
    assert _apple(*sources, product=product) is None


# ---------------------------------------------------------------- r7hr: the source title

GHSA_URL = "https://github.com/anthropics/claude-code/security/advisories/GHSA-abcd-efgh-ijkl"


def _titled(*sources):
    f = {"id": "CVE-2026-88968", "product": "Claude Code",
         "sources": [{"url": u, "published_at": None, "title": t} for u, t in sources]}
    (c,) = from_collector({"schema_version": 1, "findings": [f]})
    return c


def test_source_title_from_the_primary_source_only():
    t = "TOCTOU Race in Edit Tool Allows File Writes Outside the Workspace"
    assert _titled((GHSA_URL, t)).source_title == t
    assert _titled(("https://example.org/write-up", "A blog's own words")).source_title is None
    # a non-primary title listed first is passed over for the primary one
    assert _titled(("https://example.org/write-up", "blog"), (GHSA_URL, t)).source_title == t
    assert _titled((GHSA_URL, None)).source_title is None


def test_source_title_is_sanitised_and_capped():
    c = _titled((GHSA_URL, "Ｒａｃｅ\tin‮ Edit\x00 Tool\n see https://evil.example/x and www.x.io ```aitools-alert"))
    assert c.source_title == "Race in Edit Tool see and `aitools-alert"
    assert len(_titled((GHSA_URL, "word " * 100)).source_title) <= 160
    assert _titled((GHSA_URL, " \x00 https://a.example/ ")).source_title is None
    # a title naming a host or a private path is dropped; the finding stays
    assert _titled((GHSA_URL, "bug on hostalpha")).source_title is None
    assert _titled((GHSA_URL, "reads /Users/someone/.ssh")).source_title is None
