import copy
import importlib.util
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from aitools_alerts import TRUST_ROOT_PUBKEY, manifest, nostr
from aitools_alerts.manifest import ManifestError

ROOT = Path(__file__).resolve().parent.parent
COMMITTED = ROOT / "trust" / "manifest.json"
JOI = "18eafd07cca9f24eac1a62d8155f5e9cdabc7552357abca8a1fcced45d05fe29"
JIBOT = "d4f04ff67b3fa209cefdce90ca6e07df8bcb1aea72b9d49f31935c55601839c1"

ROOT_SEC, ROOT_PUB = nostr.keygen()
CUR_SEC, CUR_PUB = nostr.keygen()
BOT_SEC, BOT_PUB = nostr.keygen()


def content(version=1, **over) -> dict:
    c = {
        "version": version,
        "issued_at": "2026-11-05T08:00:00Z",
        "posters": [
            {"pubkey": CUR_PUB, "role": "curator", "name": "Curator"},
            {"pubkey": BOT_PUB, "role": "relay-bot", "name": "bot"},
        ],
    }
    c.update(over)
    return c


def event(sec=ROOT_SEC, body=None, kind=30078, tags=None, raw_content=None) -> dict:
    return nostr.sign_event(sec, {
        "created_at": 1793865600,
        "kind": kind,
        "tags": [["d", "aitools-alerts-manifest"]] if tags is None else tags,
        "content": raw_content if raw_content is not None else json.dumps(content() if body is None else body),
    })


def make(**kw) -> bytes:
    return json.dumps(event(**kw)).encode()


# ---------------------------------------------------------------- plan tests

def test_manifest_signed_by_root_verifies():
    m = manifest.load(make())
    assert manifest.verify(m, ROOT_PUB)
    assert m.version == 1
    assert m.issued_at == "2026-11-05T08:00:00Z"
    assert [p.pubkey for p in m.posters] == [CUR_PUB, BOT_PUB]


@pytest.mark.parametrize("signer", [CUR_SEC, BOT_SEC, nostr.keygen()[0]], ids=["curator", "bot", "stranger"])
def test_manifest_signed_by_other_key_rejected(signer):
    m = manifest.load(make(sec=signer))
    assert not manifest.verify(m, ROOT_PUB)


def test_manifest_version_must_increase():
    m2 = manifest.load(make(body=content(2)))
    with pytest.raises(ManifestError):
        manifest.load(make(body=content(1)), previous=m2)
    # same version, different content
    other = content(2, posters=[{"pubkey": CUR_PUB, "role": "curator", "name": "Curator"}])
    with pytest.raises(ManifestError):
        manifest.load(make(body=other), previous=m2)
    # the same manifest again, and a higher version, are accepted
    assert manifest.load(json.dumps(m2.event).encode(), previous=m2).version == 2
    assert manifest.load(make(body=content(3)), previous=m2).version == 3


def test_role_lookup():
    m = manifest.load(make())
    assert manifest.role_of(m, CUR_PUB) == "curator"
    assert manifest.role_of(m, BOT_PUB) == "relay-bot"
    assert manifest.role_of(m, ROOT_PUB) is None
    assert manifest.role_of(m, CUR_PUB.upper()) is None
    assert manifest.role_of(m, None) is None


def test_committed_manifest_verifies_against_pinned_root():
    m = manifest.load(COMMITTED)
    assert manifest.verify(m, TRUST_ROOT_PUBKEY)
    assert m.version == 1
    assert manifest.role_of(m, JOI) == "curator"
    assert manifest.role_of(m, JIBOT) == "relay-bot"
    assert {p.name for p in m.posters} == {"Joi", "jibot"}
    assert len(m.posters) == 2


# ---------------------------------------------------------------- inputs

def test_load_accepts_path_str_and_bytes(tmp_path):
    raw = make()
    f = tmp_path / "m.json"
    f.write_bytes(raw)
    for src in (f, str(f), raw):
        assert manifest.verify(manifest.load(src), ROOT_PUB)


def test_load_rejects_other_input_types():
    with pytest.raises(ManifestError):
        manifest.load(12)
    with pytest.raises(ManifestError):
        manifest.load(None)


def test_load_missing_file_raises_manifest_error(tmp_path):
    with pytest.raises(ManifestError):
        manifest.load(tmp_path / "absent.json")


def test_load_copies_the_event():
    ev = event()
    m = manifest.load(json.dumps(ev).encode())
    m.event["content"] = "x"
    assert manifest.load(json.dumps(ev).encode()).event["content"] != "x"


# ---------------------------------------------------------------- rejections

def _mutate_event(fn):
    ev = event()
    fn(ev)
    return json.dumps(ev).encode()


def poster(**over):
    p = {"pubkey": CUR_PUB, "role": "curator", "name": "Curator"}
    p.update(over)
    return p


BAD = {
    "kind": lambda: make(kind=1),
    "no_d_tag": lambda: make(tags=[]),
    "wrong_d_tag": lambda: make(tags=[["d", "other"]]),
    "two_d_tags": lambda: make(tags=[["d", "aitools-alerts-manifest"], ["d", "aitools-alerts-manifest"]]),
    "long_d_tag": lambda: make(tags=[["d", "aitools-alerts-manifest", "x"]]),
    "extra_event_key": lambda: _mutate_event(lambda e: e.update(extra=1)),
    "missing_event_key": lambda: _mutate_event(lambda e: e.pop("sig")),
    "uppercase_id": lambda: _mutate_event(lambda e: e.update(id=e["id"].upper())),
    "extra_content_key": lambda: make(body=content(extra=1)),
    "missing_content_key": lambda: make(body={k: v for k, v in content().items() if k != "issued_at"}),
    "content_not_object": lambda: make(raw_content="[1]"),
    "content_not_json": lambda: make(raw_content="{"),
    "version_bool": lambda: make(body=content(True)),
    "version_zero": lambda: make(body=content(0)),
    "version_negative": lambda: make(body=content(-1)),
    "version_str": lambda: make(body=content("1")),
    "version_float": lambda: make(body=content(1.0)),
    "version_huge": lambda: make(body=content(2**31)),
    "issued_at_no_z": lambda: make(body=content(issued_at="2026-11-05T08:00:00")),
    "issued_at_offset": lambda: make(body=content(issued_at="2026-11-05T08:00:00+00:00")),
    "issued_at_bad_date": lambda: make(body=content(issued_at="2026-13-05T08:00:00Z")),
    "issued_at_int": lambda: make(body=content(issued_at=1)),
    "posters_empty": lambda: make(body=content(posters=[])),
    "posters_not_list": lambda: make(body=content(posters={})),
    "posters_too_many": lambda: make(body=content(posters=[poster(pubkey=nostr.keygen()[1], name=f"p{i}") for i in range(65)])),
    "poster_extra_key": lambda: make(body=content(posters=[poster(extra=1)])),
    "poster_missing_key": lambda: make(body=content(posters=[{"pubkey": CUR_PUB, "role": "curator"}])),
    "poster_not_object": lambda: make(body=content(posters=["x"])),
    "role_unknown": lambda: make(body=content(posters=[poster(role="admin")])),
    "role_case": lambda: make(body=content(posters=[poster(role="Curator")])),
    "pubkey_upper": lambda: make(body=content(posters=[poster(pubkey=CUR_PUB.upper())])),
    "pubkey_short": lambda: make(body=content(posters=[poster(pubkey=CUR_PUB[:-2])])),
    "pubkey_not_on_curve": lambda: make(body=content(posters=[poster(pubkey="00" * 32)])),
    "pubkey_duplicate": lambda: make(body=content(posters=[poster(), poster(role="relay-bot", name="dup")])),
    "name_empty": lambda: make(body=content(posters=[poster(name="")])),
    "name_control": lambda: make(body=content(posters=[poster(name="a\nb")])),
    "name_bidi": lambda: make(body=content(posters=[poster(name="a‮b")])),
    "name_zero_width": lambda: make(body=content(posters=[poster(name="a​b")])),
    "name_too_long": lambda: make(body=content(posters=[poster(name="x" * 65)])),
    "name_not_str": lambda: make(body=content(posters=[poster(name=1)])),
    "duplicate_json_key": lambda: make()[:-1] + b',"kind":30078}',
    "nan": lambda: make(raw_content='{"version": NaN, "issued_at": "2026-11-05T08:00:00Z", "posters": []}'),
    "not_utf8": lambda: b"\xff\xfe{}",
    "top_level_list": lambda: b"[]",
    "oversize": lambda: b" " * (manifest.MAX_BYTES + 1) + make(),
    "deep_nesting": lambda: b"[" * 100000 + b"]" * 100000,
}


@pytest.mark.parametrize("case", sorted(BAD))
def test_load_rejects(case):
    with pytest.raises(ManifestError):
        manifest.load(BAD[case]())


def test_load_accepts_64_posters_and_64_char_name():
    posters = [poster(pubkey=nostr.keygen()[1], name=f"p{i}") for i in range(63)]
    posters.append(poster(name="x" * 64))
    m = manifest.load(make(body=content(posters=posters)))
    assert len(m.posters) == 64
    assert manifest.verify(m, ROOT_PUB)


def test_load_accepts_exactly_max_bytes(tmp_path):
    raw = make()
    padded = raw[:-1] + b" " * (manifest.MAX_BYTES - len(raw)) + b"}"
    assert len(padded) == manifest.MAX_BYTES
    assert manifest.verify(manifest.load(padded), ROOT_PUB)


def test_load_rejects_previous_that_is_not_a_manifest():
    with pytest.raises(ManifestError):
        manifest.load(make(), previous={"version": 0})


# ---------------------------------------------------------------- verify

def test_verify_rejects_tampered_content():
    ev = event()
    ev["content"] = json.dumps(content(posters=[poster(pubkey=nostr.keygen()[1])]))
    assert not manifest.verify(manifest.load(json.dumps(ev).encode()), ROOT_PUB)


def test_verify_rejects_tampered_sig():
    ev = event()
    ev["sig"] = ev["sig"][:-1] + ("0" if ev["sig"][-1] != "0" else "1")
    assert not manifest.verify(manifest.load(json.dumps(ev).encode()), ROOT_PUB)


def test_verify_rejects_fields_that_disagree_with_the_event():
    m = manifest.load(make())
    stranger = manifest.Poster(pubkey=nostr.keygen()[1], role="curator", name="x")
    assert not manifest.verify(replace(m, posters=m.posters + (stranger,)), ROOT_PUB)
    assert not manifest.verify(replace(m, version=9), ROOT_PUB)
    assert not manifest.verify(replace(m, issued_at="2030-01-01T00:00:00Z"), ROOT_PUB)


def test_verify_rejects_event_mutated_after_load():
    m = manifest.load(make())
    m.event["content"] = json.dumps(content(posters=[poster(pubkey=nostr.keygen()[1])]))
    assert not manifest.verify(m, ROOT_PUB)


def test_verify_rejects_wrong_kind_or_tag_built_by_hand():
    m = manifest.load(make())
    ev = event(kind=1)
    assert not manifest.verify(replace(m, event=ev), ROOT_PUB)


@pytest.mark.parametrize("root", [None, 1, "", ROOT_PUB.upper(), ROOT_PUB[:-2], "zz" * 32])
def test_verify_bad_root_is_false_never_raises(root):
    assert manifest.verify(manifest.load(make()), root) is False


def test_verify_non_manifest_is_false():
    assert manifest.verify(None, ROOT_PUB) is False
    assert manifest.verify({"event": event()}, ROOT_PUB) is False


# ---------------------------------------------------------------- sign script

def _script():
    spec = importlib.util.spec_from_file_location("sign_manifest", ROOT / "scripts" / "sign-manifest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeRunner:
    def __init__(self, stdout=b"", returncode=0, stderr=b""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr
        self.calls = []

    def __call__(self, argv, **kw):
        env = kw["env"]
        cache = env["SECRETS_CACHE_DIR"]
        call = {"argv": argv, "kw": kw, "cache": cache, "cache_existed": os.path.isdir(cache)}
        self.calls.append(call)
        # get_secret writes a cache entry here; the directory must refuse it
        try:
            Path(cache, ".value.tmp").write_text("cached")
            call["write_blocked"] = False
        except PermissionError:
            call["write_blocked"] = True
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def leaked_env(monkeypatch):
    monkeypatch.setenv("AITOOLS_ALERTS_ROOT_NSEC", "f" * 64)


def test_sign_script_reads_secret_with_throwaway_cache(leaked_env):
    sec, _ = nostr.keygen()
    runner = FakeRunner(stdout=(sec + "\n").encode())
    assert _script().read_root_secret(runner=runner) == sec
    call = runner.calls[0]
    assert call["cache_existed"]
    assert call["write_blocked"]
    assert not os.path.exists(call["cache"])
    env = call["kw"]["env"]
    assert "AITOOLS_ALERTS_ROOT_NSEC" not in env
    assert call["kw"]["stdin"] is subprocess.DEVNULL
    assert call["kw"]["capture_output"] is True
    assert sec not in " ".join(call["argv"])
    assert "get_secret AITOOLS_ALERTS_ROOT_NSEC" in call["argv"][-1]


def test_sign_script_accepts_nsec_value():
    sec, _ = nostr.keygen()
    runner = FakeRunner(stdout=(nostr.nsec(sec) + "\n").encode())
    assert _script().read_root_secret(runner=runner) == sec


@pytest.mark.parametrize("runner", [
    FakeRunner(returncode=1, stderr=b"Error: Secret not found SENSITIVE-STDERR"),
    FakeRunner(stdout=b"not-a-key-SENSITIVE\n"),
    FakeRunner(stdout=b""),
    FakeRunner(stdout=b"ab" * 32 + b"\n" + b"cd" * 32 + b"\n"),
], ids=["exit1", "garbage", "empty", "two_lines"])
def test_sign_script_secret_errors_leak_nothing(runner, capsys):
    with pytest.raises(SystemExit) as ei:
        _script().read_root_secret(runner=runner)
    assert "SENSITIVE" not in str(ei.value.code)
    out = capsys.readouterr()
    assert "SENSITIVE" not in out.out + out.err
    assert not os.path.exists(runner.calls[0]["cache"])


def test_sign_script_refuses_when_helper_wrote_to_cache():
    sec, _ = nostr.keygen()

    def runner(argv, **kw):
        cache = kw["env"]["SECRETS_CACHE_DIR"]
        os.chmod(cache, 0o700)  # a helper that forces its way in
        Path(cache, "AITOOLS_ALERTS_ROOT_NSEC").write_text(sec)
        runner.cache = cache
        return subprocess.CompletedProcess(argv, 0, sec.encode(), b"")

    with pytest.raises(SystemExit) as ei:
        _script().read_root_secret(runner=runner)
    assert sec not in str(ei.value.code)
    assert not os.path.exists(runner.cache)


def test_sign_script_timeout_cleans_cache():
    seen = {}

    def runner(argv, **kw):
        seen["cache"] = kw["env"]["SECRETS_CACHE_DIR"]
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))

    with pytest.raises(SystemExit):
        _script().read_root_secret(runner=runner)
    assert not os.path.exists(seen["cache"])


def test_sign_script_builds_verifiable_event():
    sec, pub = nostr.keygen()
    ev = _script().build_event(content(), sec)
    m = manifest.load(json.dumps(ev).encode())
    assert manifest.verify(m, pub)
    assert ev["created_at"] == 1793865600  # 2026-11-05T08:00:00Z


def test_sign_script_refuses_non_root_key(tmp_path, capsys):
    mod = _script()
    sec, _ = nostr.keygen()
    src = tmp_path / "content.json"
    src.write_text(json.dumps(content()))
    out = tmp_path / "manifest.json"
    with pytest.raises(SystemExit) as ei:
        mod.main([str(src), "--out", str(out)], runner=FakeRunner(stdout=sec.encode()))
    assert ei.value.code not in (0, None)
    assert not out.exists()
    assert sec not in capsys.readouterr().out


def test_sign_script_refuses_bad_content_before_reading_key(tmp_path):
    mod = _script()
    src = tmp_path / "content.json"
    src.write_text(json.dumps(content(posters=[])))
    runner = FakeRunner(stdout=b"")
    with pytest.raises(SystemExit):
        mod.main([str(src), "--out", str(tmp_path / "m.json")], runner=runner)
    assert runner.calls == []


def test_sign_script_main_writes_and_prints_id(tmp_path, capsys, monkeypatch):
    mod = _script()
    sec, pub = nostr.keygen()
    monkeypatch.setattr(mod, "TRUST_ROOT_PUBKEY", pub)
    src = tmp_path / "content.json"
    src.write_text(json.dumps(content()))
    out = tmp_path / "manifest.json"
    assert mod.main([str(src), "--out", str(out)], runner=FakeRunner(stdout=sec.encode())) == 0
    m = manifest.load(out)
    assert manifest.verify(m, pub)
    printed = capsys.readouterr()
    assert printed.out == m.event["id"] + "\n"
    assert printed.err == ""
    assert sec not in out.read_text()
    assert oct(out.stat().st_mode & 0o777) == "0o644"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["content.json", "manifest.json"]


def test_sign_script_previous_version_must_increase(tmp_path, monkeypatch):
    mod = _script()
    sec, pub = nostr.keygen()
    monkeypatch.setattr(mod, "TRUST_ROOT_PUBKEY", pub)
    out = tmp_path / "manifest.json"
    src = tmp_path / "content.json"
    src.write_text(json.dumps(content(2)))
    assert mod.main([str(src), "--out", str(out)], runner=FakeRunner(stdout=sec.encode())) == 0
    before = out.read_bytes()
    src.write_text(json.dumps(content(2, issued_at="2026-11-06T08:00:00Z")))
    with pytest.raises(SystemExit):
        mod.main([str(src), "--out", str(out)], runner=FakeRunner(stdout=sec.encode()))
    assert out.read_bytes() == before
