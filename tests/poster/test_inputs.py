"""The poster's inputs (Task B4): config, run state, the KEV fetch, run dirs. No network."""

import dataclasses
import json
import threading
import time
from collections import Counter

import pytest

from aitools_alerts.poster import inputs
from aitools_alerts.poster.ledger import LedgerError

ADV = {"id": "CVE-2026-0001", "aliases": [], "level": "high", "advisory_severity": None,
       "title": "Claude Code: security advisory (CVE-2026-0001)",
       "products": [{"name": "Claude Code", "ecosystem": "claude-code", "affected": None, "fixed": "2.1.0"}],
       "actions": [{"verb": "upgrade", "target": "Claude Code", "value": "2.1.0"}],
       "sources": [{"url": "https://github.com/anthropics/claude-code/security/advisories/GHSA-abcd-efgh-ijkl",
                    "published_at": None}],
       "posted_by": "relay-bot", "posted_at": 1_800_000_000, "expires_at": None}


def item(**kw):
    base = {"key": "root:Claude Code:CVE-2026-0001:feed", "kind": "root", "scope": "Claude Code",
            "ids": ["CVE-2026-0001"], "channel": "feed", "text": "t", "adv": ADV, "exploited": False,
            "date": None, "sent": None, "root": None}
    base.update(kw)
    return base


def digest_item(**kw):
    base = dict(key="digest:2026-11-05", kind="digest", scope=None, ids=["digest:2026-11-05"],
                adv={"held": [], "cutoff": 1, "roots": []}, date="2026-11-05")
    base.update(kw)
    return item(**base)

LM = "Tue, 03 Nov 2026 10:00:00 GMT"
CATALOG = {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}


# ---------------------------------------------------------------- config


def test_load_config_defaults_and_expands(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('heartbeat_runs = "~/hb"\ncollector_runs = "/srv/c"\n')
    c = inputs.load_config(cfg)
    assert c.heartbeat_runs.is_absolute() and "~" not in str(c.heartbeat_runs)
    assert (c.digest_hour, c.backfill_days) == (9, 2)
    assert c.state == c.ledger.with_name("ledger.json.poster-state.json")


def test_config_unknown_key_is_error(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('private_key = "no"\n')
    with pytest.raises(inputs.ConfigError, match="unknown keys"):
        inputs.load_config(cfg)


@pytest.mark.parametrize("text", ["digest_hour = 24\n", "digest_hour = true\n", "backfill_days = -1\n",
                                  "ledger = 3\n", 'ledger = ""\n', "not toml =\n"])
def test_config_bad_types_are_errors(tmp_path, text):
    cfg = tmp_path / "config.toml"
    cfg.write_text(text)
    with pytest.raises(inputs.ConfigError):
        inputs.load_config(cfg)


def test_deployment_keys_default_empty_and_load(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("")
    c = inputs.load_config(cfg)
    assert (c.strip_hosts, c.internal_host_suffixes, c.relay_ssh_host, c.relay_send_wrapper) == ((), (), None, None)
    with pytest.raises(inputs.ConfigError, match="relay_ssh_host and relay_send_wrapper"):
        c.check_relay()
    cfg.write_text('strip_hosts = ["HostAlpha", "hostbeta"]\ninternal_host_suffixes = [".corp.example"]\n'
                   'relay_ssh_host = "op@relay.example.net"\nrelay_send_wrapper = "/opt/relay/bin/buzz-send"\n')
    c = inputs.load_config(cfg)
    assert c.strip_hosts == ("hostalpha", "hostbeta") and c.internal_host_suffixes == (".corp.example",)
    assert (c.relay_ssh_host, c.relay_send_wrapper) == ("op@relay.example.net", "/opt/relay/bin/buzz-send")
    c.check_relay()


@pytest.mark.parametrize("text", ['strip_hosts = "hostalpha"\n', 'strip_hosts = [""]\n', "strip_hosts = [3]\n",
                                  'strip_hosts = ["a b"]\n', 'internal_host_suffixes = ["corp.example"]\n',
                                  'relay_ssh_host = "-oProxyCommand=x"\n', 'relay_ssh_host = "a b"\n',
                                  'relay_ssh_host = ""\n', 'relay_send_wrapper = "bin/buzz-send"\n',
                                  'relay_send_wrapper = "~/bin/buzz-send"\n', 'relay_send_wrapper = "/a;b"\n',
                                  'strip_hosts = ["a"]\n', 'strip_hosts = [".."]\n', 'strip_hosts = [".corp"]\n',
                                  'internal_host_suffixes = ["."]\n'])
def test_deployment_keys_bad_values_are_errors(tmp_path, text):
    cfg = tmp_path / "config.toml"
    cfg.write_text(text)
    with pytest.raises(inputs.ConfigError):
        inputs.load_config(cfg)


def test_missing_config_is_error(tmp_path):
    with pytest.raises(inputs.ConfigError):
        inputs.load_config(tmp_path / "absent.toml")


# ---------------------------------------------------------------- state


def test_state_fresh_has_backfill_floor(tmp_path):
    st = inputs.load_state(tmp_path / "s.json", 1_800_000_000, 2)
    assert st["since"] == st["digest_at"] == 1_800_000_000 - 2 * 86400
    assert st["outbox"] == [] and st["heartbeat"] is None


def test_state_roundtrip_atomic(tmp_path):
    path = tmp_path / "d" / "s.json"
    st = inputs.new_state(1_800_000_000, 2)
    st["outbox"] += [item(), item(key="copy:Claude Code:CVE-2026-0001:critical", kind="copy",
                                  channel="critical", adv=None, sent="ab" * 32), digest_item()]
    st["held"].append({"scope": "Claude Code", "adv": ADV})
    inputs.save_state(path, st)
    assert inputs.load_state(path, 0, 0) == st
    assert [p.name for p in path.parent.iterdir()] == ["s.json"]


@pytest.mark.parametrize("mutate", [
    lambda st: st.pop("outbox"),
    lambda st: st.update(since="0"),
    lambda st: st.update(extra=1),
    lambda st: st["outbox"].append({"key": "k"}),
    lambda st: st["outbox"].append({"key": "k", "kind": "post", "scope": None, "ids": ["a"], "channel": "feed",
                                    "text": "t", "adv": None, "exploited": False, "date": None, "sent": None}),
    lambda st: st["held"].append({"adv": {}}),
    lambda st: st["held"].append({"scope": "X", "adv": ADV, "extra": 1}),
    lambda st: st["outbox"].extend([item(), item()]),  # one key twice
    lambda st: st["outbox"].append(item(sent="")),
    lambda st: st["outbox"].append(item(sent="AB" * 32)),
    lambda st: st["outbox"].append(item(adv={})),
    lambda st: st["outbox"].append(item(adv=None)),
    lambda st: st["outbox"].append(item(scope=None)),
    lambda st: st["outbox"].append(item(kind=[])),
    lambda st: st["outbox"].append(item(ids=[])),
    lambda st: st["outbox"].append(item(exploited=1)),
    lambda st: st["outbox"].append(item(channel="other")),
    lambda st: st["outbox"].append(digest_item(date="2026-13-40")),
    lambda st: st["outbox"].append(item(key="digest:x", kind="digest", scope=None, adv={"held": []},
                                        date="2026-11-05")),
    lambda st: st.update(schema_version=True),
    lambda st: st.update(since=True),
    lambda st: st.update(kev_since="junk"),
    lambda st: st.update(heartbeat="~"),
    lambda st: st.update(digest_date="2026-02-30"),
    lambda st: st["outbox"].append(item(key="reply:x", kind="reply")),  # a reply names its root
    lambda st: st["outbox"].append(item(root="ab" * 32)),  # a root names none
    lambda st: st["deferred"].append({"id": "x"}),
])
def test_malformed_state_is_ledger_error(tmp_path, mutate):
    st = inputs.new_state(0, 0)
    mutate(st)
    path = tmp_path / "s.json"
    path.write_text(json.dumps(st))
    with pytest.raises(LedgerError):
        inputs.load_state(path, 0, 0)


def test_unreadable_state_is_ledger_error(tmp_path):
    path = tmp_path / "s.json"
    path.write_text("{not json")
    with pytest.raises(LedgerError):
        inputs.load_state(path, 0, 0)


# ---------------------------------------------------------------- KEV


class Fetch:
    def __init__(self, status=200, body=None, headers=None, exc=None):
        self.status, self.exc = status, exc
        self.body = json.dumps(CATALOG).encode() if body is None else body
        self.headers_out = {"Last-Modified": LM} if headers is None else headers
        self.seen = []

    def __call__(self, url, headers):
        assert url == inputs.KEV_URL
        self.seen.append(dict(headers))
        if self.exc:
            raise self.exc
        return self.status, self.headers_out, b"" if self.status == 304 else self.body


def test_kev_fetch_not_modified_uses_cache(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps({"last_modified": LM, "catalog": CATALOG}))
    f = Fetch(status=304)
    assert inputs.load_kev(cache, f) == CATALOG
    assert f.seen == [{"If-Modified-Since": LM}]


def test_kev_200_writes_cache(tmp_path):
    cache = tmp_path / "kev.json"
    f = Fetch(headers={"last-modified": LM})
    assert inputs.load_kev(cache, f) == CATALOG and f.seen == [{}]
    assert json.loads(cache.read_text()) == {"last_modified": LM, "catalog": CATALOG}


def test_kev_304_without_cache_is_none(tmp_path):
    assert inputs.load_kev(tmp_path / "kev.json", Fetch(status=304)) is None


@pytest.mark.parametrize("fetch", [Fetch(status=500), Fetch(exc=OSError("down")),
                                   Fetch(body=b"not json"), Fetch(body=b"[]"),
                                   Fetch(body=json.dumps({"vulnerabilities": {}}).encode())])
def test_kev_error_or_bad_shape_returns_none(tmp_path, fetch):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps({"last_modified": LM, "catalog": CATALOG}))
    assert inputs.load_kev(cache, fetch) is None
    assert json.loads(cache.read_text())["catalog"] == CATALOG  # a bad fetch never overwrites the cache


def test_kev_oversize_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(inputs, "MAX_KEV", 10)
    assert inputs.load_kev(tmp_path / "kev.json", Fetch()) is None


def test_kev_stalled_fetch_hits_deadline(tmp_path):
    release = threading.Event()

    def stall(url, headers):
        release.wait(10)
        return 200, {}, json.dumps(CATALOG).encode()

    t0 = time.monotonic()
    try:
        assert inputs.load_kev(tmp_path / "kev.json", stall, deadline=0.2) is None
        assert time.monotonic() - t0 < 1.0
    finally:
        release.set()


# ---------------------------------------------------------------- run dirs


def _mk(root, name, *files):
    d = root / name
    d.mkdir(parents=True)
    for f in files:
        (d / f).write_text("{}")
    return d


def test_heartbeat_dirs_after_watermark(tmp_path):
    for n in ("2026-11-04T000000Z", "2026-11-04T060000Z", "2026-11-04T120000Z"):
        _mk(tmp_path, n, "run.json")
    _mk(tmp_path, "2026-11-04T180000Z", "feeds.json")  # in progress: no run.json
    _mk(tmp_path, "2026-11-04", "run.json")  # not a run dir name
    names = lambda ds: [d.name for d in ds]
    assert names(inputs.heartbeat_dirs(tmp_path, None)) == ["2026-11-04T120000Z"]
    assert names(inputs.heartbeat_dirs(tmp_path, "2026-11-04T000000Z")) == \
        ["2026-11-04T060000Z", "2026-11-04T120000Z"]
    assert inputs.heartbeat_dirs(tmp_path, "2026-11-04T120000Z") == []
    assert inputs.heartbeat_dirs(tmp_path / "absent", None) == []


def test_heartbeat_dirs_cap(tmp_path):
    for h in range(60):
        _mk(tmp_path, f"2026-11-04T{h // 6:02d}{h % 6 * 10:02d}00Z", "run.json")
    dirs = inputs.heartbeat_dirs(tmp_path, "2026-01-01T000000Z")
    assert len(dirs) == inputs.MAX_RUN_DIRS and dirs[-1].name == "2026-11-04T095000Z"


def _collector(root, name, validate="ok", record=None):
    d = root / name
    d.mkdir(parents=True)
    (d / "run-record.json").write_text(json.dumps(record or {"schema_version": 1, "findings": []}))
    (d / "job.json").write_text(json.dumps({"steps": {"validate": {"out": validate}}}))


def test_collector_newest_validated_only(tmp_path):
    counts = Counter()
    _collector(tmp_path, "2026-11-05T030000Z")
    _mk(tmp_path, "2026-11-05", "run-record.json")  # the collector's date-only copy
    name, rec = inputs.collector_record(tmp_path, None, counts)
    assert name == "2026-11-05T030000Z" and rec["schema_version"] == 1
    assert inputs.collector_record(tmp_path, "2026-11-05T030000Z", counts) is None
    _collector(tmp_path, "2026-11-05T040000Z", validate="failed")
    assert inputs.collector_record(tmp_path, "2026-11-05T030000Z", counts) is None
    assert counts["collector not validated"] == 1
    (tmp_path / "2026-11-05T050000Z").mkdir()
    (tmp_path / "2026-11-05T050000Z" / "run-record.json").write_text("{}")  # no job.json
    assert inputs.collector_record(tmp_path, None, counts) is None


def test_load_channels_reads_spec():
    ch = inputs.load_channels()
    assert set(ch) >= {"feed", "critical"}


def test_duplicate_json_keys_in_state_are_refused(tmp_path):
    st = inputs.new_state(0, 0)
    st["outbox"].append(item(sent="ab" * 32))
    text = json.dumps(st).replace('"sent": "' + "ab" * 32 + '"', '"sent": "' + "ab" * 32 + '", "sent": null')
    path = tmp_path / "s.json"
    path.write_text(text)
    with pytest.raises(LedgerError):
        inputs.load_state(path, 0, 0)


@pytest.mark.parametrize("text", [
    'ledger = "/s/l.json"\nkev_cache = "/s/l.json"\n',
    'ledger = "/s/l.json"\nkev_cache = "/s/l.json.lock"\n',
    'ledger = "/s/l.json"\nkev_cache = "/s/l.json.poster-state.json"\n',
    'ledger = "relative/l.json"\n',
    'ledger = "/s/ledger.json"\nkev_cache = "/s/LEDGER.json"\n',
    'ledger = "/s/ledger.json"\nkev_cache = "/s/LEDGER.json.lock"\n',
])
def test_overlapping_or_relative_paths_are_refused(tmp_path, text):
    cfg = tmp_path / "config.toml"
    cfg.write_text(text)
    with pytest.raises(inputs.ConfigError):
        inputs.load_config(cfg)


def test_two_ledgers_in_one_directory_have_two_journals():
    a = inputs.Config(ledger=inputs.Path("/s/a.json"))
    assert a.state != dataclasses.replace(a, ledger=inputs.Path("/s/b.json")).state


@pytest.mark.parametrize("catalog", [{"vulnerabilities": {}}, {"items": []},
                                     {"vulnerabilities": [], "items": [{"cveID": "CVE-2026-1"}]}])
def test_bad_cached_catalog_means_an_unconditional_fetch(tmp_path, catalog):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps({"last_modified": LM, "catalog": catalog}))
    f = Fetch(status=304)
    assert inputs.load_kev(cache, f) is None and f.seen == [{}]


def test_fetch_kev_reports_status(tmp_path):
    cache = tmp_path / "kev.json"
    assert inputs.fetch_kev(cache, Fetch(status=304)) == (None, "unavailable")  # no cache to serve
    assert inputs.fetch_kev(cache, Fetch(headers={"last-modified": LM})) == (CATALOG, "ok")
    assert inputs.fetch_kev(cache, Fetch(status=304)) == (CATALOG, "304")
    assert inputs.fetch_kev(cache, Fetch(status=500)) == (None, "unavailable")


def test_read_kev_file_never_fetches_or_caches(tmp_path, monkeypatch):
    monkeypatch.setattr(inputs, "urllib_fetch", None)
    monkeypatch.setattr(inputs, "write_json", None)
    f = tmp_path / "k.json"
    f.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2099-0001", "vulnerabilityName": "SYNTHETIC TEST x"}]}))
    assert inputs.read_kev_file(f)["vulnerabilities"][0]["cveID"] == "CVE-2099-0001"
    f.write_text('{"vulnerabilities": [{"vulnerabilityName": "SYNTHETIC TEST"}], "vulnerabilities": []}')
    with pytest.raises(inputs.ConfigError):
        inputs.read_kev_file(f)  # duplicate keys are refused, as every strict read


def test_ssh_alias_with_underscore_loads(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('relay_ssh_host = "relay_vm"\nrelay_send_wrapper = "/opt/relay/bin/buzz-send"\n')
    inputs.load_config(cfg).check_relay()


@pytest.mark.parametrize("host, wrapper", [("-oProxyCommand=x", "/opt/w"), ("relay.example.net", "~/w"),
                                           ("relay.example.net", "w"), (3, "/opt/w")])
def test_check_relay_validates_a_config_built_in_code(host, wrapper):
    with pytest.raises(inputs.ConfigError):
        inputs.Config(relay_ssh_host=host, relay_send_wrapper=wrapper).check_relay()
