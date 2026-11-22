"""The checkpoint key certificate and the signed checkpoint (ai-tools-alerts#zb8b)."""

import importlib.util
import json
from dataclasses import replace
from pathlib import Path

import pytest

from aitools_alerts import checkpoint as cp
from aitools_alerts import manifest, nostr, pull
from mirror_helpers import T0, Mirror

ROOT = Path(__file__).resolve().parent.parent
DAY = 86400
IDS = sorted(f"{i:064x}" for i in (3, 1, 2))


class World:
    """A throwaway root, a manifest it signed, a checkpoint key, one certificate."""

    def __init__(self):
        self.m = Mirror()
        self.man = manifest.load(json.dumps(self.m.manifest).encode())
        self.ck_sec, self.ck = nostr.keygen()
        self.cert_ev = cp.build_cert(self.m.root_sec, self.man, self.ck, T0, T0 + 120 * DAY)
        self.cert = cp.load_cert(json.dumps(self.cert_ev).encode())

    def checkpoint(self, seq=1, ids=IDS, now=T0 + 100, sec=None, **kw):
        return cp.load_checkpoint(json.dumps(cp.build_checkpoint(sec or self.ck_sec, self.man, seq, ids, now, **kw)).encode())

    def resign(self, sec, ev, content=None, **over):
        """The event again with fields or content keys changed, signed by ``sec``."""
        c = json.loads(ev["content"])
        c.update(content or {})
        c = {k: v for k, v in c.items() if v is not DROP}
        base = {"created_at": ev["created_at"], "kind": ev["kind"], "tags": ev["tags"], "content": json.dumps(c)}
        base.update(over)
        return nostr.sign_event(sec, base)


DROP = object()


@pytest.fixture
def w():
    return World()


def raw(ev) -> bytes:
    return json.dumps(ev).encode()


# ---------------------------------------------------------------- certificate

def test_certificate_round_trip(w):
    assert w.cert.checkpoint_key == w.ck and w.cert.manifest_id == w.man.event["id"]
    assert w.cert.manifest_version == w.man.version
    assert (w.cert.issued_at, w.cert.expires_at) == (T0, T0 + 120 * DAY)
    assert cp.verify_cert(w.cert, w.m.root) and cp.cert_problem(w.cert, w.man, T0 + 5) is None
    assert w.cert_ev["kind"] == 30078 and w.cert_ev["tags"] == [["d", "aitools-alerts-checkpoint-key"]]


def test_max_ahead_matches_the_reader():
    assert cp.MAX_AHEAD_S == pull.MAX_AHEAD_S


@pytest.mark.parametrize("change", [
    dict(kind=1), dict(tags=[["d", manifest.D_TAG]]), dict(tags=[["d", cp.CHECKPOINT_D_TAG]]),
    dict(tags=[["d", cp.CERT_D_TAG], ["d", "x"]]), dict(tags=[]), dict(created_at=T0 + 1),
    dict(content={"expires_at": "2099-01-01T00:00:00Z"}),  # not after issued_at
    dict(content={"expires_at": "2098-12-31T23:59:59Z"}),
    dict(content={"issued_at": "2099-01-01 00:00:00"}), dict(content={"issued_at": "2099-02-30T00:00:00Z"}),
    dict(content={"expires_at": "2099-05-01t00:00:00z"}),  # 20 characters, not canonical
    dict(content={"expires_at": "２０９９-05-01T00:00:00Z"}), dict(content={"expires_at": "2099-5-01T00:00:00Z "}),
    dict(content={"issued_at": 4070908800}), dict(content={"expires_at": None}),
    dict(content={"checkpoint_key": "zz" * 32}), dict(content={"checkpoint_key": "AB" * 32}),
    dict(content={"checkpoint_key": "ff" * 32}),  # 64 hex, not on the curve
    dict(content={"checkpoint_key": DROP}), dict(content={"manifest_id": "12"}),
    dict(content={"manifest_id": DROP}), dict(content={"manifest_version": 0}),
    dict(content={"manifest_version": True}), dict(content={"manifest_version": "3"}),
    dict(content={"manifest_version": 2**31}),
    dict(content={"v": DROP}), dict(content={"v": 2}), dict(content={"v": True}), dict(content={"v": "1"}),
    dict(content={"v": 1.0}),
])
def test_certificate_shape_is_checked(w, change):
    content = change.pop("content", None)
    ev = w.resign(w.m.root_sec, w.cert_ev, content, **change)
    with pytest.raises(cp.CheckpointError):
        cp.load_cert(raw(ev))


@pytest.mark.parametrize("data", [
    b"", b"not json", b"[]", b'"x"', b"\xff\xfe", b'{"id": 1, "id": 2}', b'{"a": NaN}',
    b"[" * 100000, b"1" * 5000, b'{"kind": 30078}'])
def test_certificate_and_checkpoint_refuse_junk(data):
    for load in (cp.load_cert, cp.load_checkpoint):
        with pytest.raises(cp.CheckpointError):
            load(data)


def test_loaders_refuse_bad_sources_and_sizes(w, tmp_path):
    with pytest.raises(cp.CheckpointError, match="cannot read"):
        cp.load_cert(tmp_path / "absent.json")
    with pytest.raises(cp.CheckpointError, match="path or bytes"):
        cp.load_cert(42)
    big = w.resign(w.m.root_sec, w.cert_ev, {"note": "x" * cp.MAX_CERT_BYTES})
    with pytest.raises(cp.CheckpointError, match="larger than"):
        cp.load_cert(raw(big))
    extra = dict(w.cert_ev, relay="wss://example.invalid")
    with pytest.raises(cp.CheckpointError, match="NIP-01 keys"):
        cp.load_cert(raw(extra))
    p = tmp_path / "checkpoint-key.json"
    p.write_bytes(raw(w.cert_ev))
    assert cp.load_cert(p) == w.cert


def test_certificate_must_be_signed_by_the_root(w):
    stranger, _ = nostr.keygen()
    forged = cp.load_cert(raw(w.resign(stranger, w.cert_ev)))
    assert not cp.verify_cert(forged, w.m.root)
    assert not cp.verify_cert(replace(w.cert, checkpoint_key=nostr.keygen()[1]), w.m.root)  # a changed dataclass
    assert not cp.verify_cert(replace(w.cert, expires_at=w.cert.expires_at + DAY), w.m.root)
    other = w.resign(w.m.root_sec, w.cert_ev, {"expires_at": "2100-01-01T00:00:00Z"})
    tampered = cp.load_cert(raw(dict(other, sig=w.cert_ev["sig"])))  # new content, old signature
    assert not cp.verify_cert(tampered, w.m.root)
    bad_id = cp.load_cert(raw(dict(w.cert_ev, id="0" * 64)))
    assert not cp.verify_cert(bad_id, w.m.root)
    for junk in (None, "x", w.cert_ev, replace(w.cert, event=None), replace(w.cert, event={"pubkey": w.m.root})):
        assert cp.verify_cert(junk, w.m.root) is False
    assert cp.verify_cert(w.cert, "nothex") is False and cp.verify_cert(w.cert, None) is False


def test_certificate_is_bound_to_one_manifest_and_a_time(w):
    old_id = w.man.event["id"]
    w.m.publish_manifest()  # version 2: another event id
    newer = manifest.load(raw(w.m.manifest))
    assert newer.event["id"] != old_id
    assert cp.cert_problem(w.cert, newer, T0 + 5) == "other manifest"
    same_version = manifest.load(raw(w.m.publish_manifest(version=1, issued=T0 + 9)))  # version alone never binds
    assert cp.cert_problem(w.cert, same_version, T0 + 5) == "other manifest"
    assert cp.cert_problem(w.cert, w.man, T0 - cp.MAX_AHEAD_S) is None
    assert cp.cert_problem(w.cert, w.man, T0 - cp.MAX_AHEAD_S - 1) == "dated ahead"
    assert cp.cert_problem(w.cert, w.man, w.cert.expires_at) is None
    assert cp.cert_problem(w.cert, w.man, w.cert.expires_at + 1) == "expired"


def test_certificate_order(w):
    assert cp.cert_order(w.cert, None) is None and cp.cert_order(w.cert, w.cert) is None
    again = cp.load_cert(raw(w.cert_ev))
    assert cp.cert_order(again, w.cert) is None  # the same event
    later = cp.load_cert(raw(cp.build_cert(w.m.root_sec, w.man, w.ck, T0 + 1, T0 + 10 * DAY)))
    assert cp.cert_order(later, w.cert) is None and cp.cert_order(w.cert, later) == "older certificate"
    twin = cp.load_cert(raw(cp.build_cert(w.m.root_sec, w.man, nostr.keygen()[1], T0, T0 + 120 * DAY)))
    assert cp.cert_order(twin, w.cert) == "conflicting certificate"


def test_build_cert_refuses_bad_input(w):
    for key in ("ff" * 32, "xyz", None, nostr.npub(w.ck)):
        with pytest.raises(cp.CheckpointError):
            cp.build_cert(w.m.root_sec, w.man, key, T0, T0 + DAY)
    for issued, expires in ((T0, T0), (T0, T0 - 1), (T0, float(T0 + 9)), (True, T0), (-1, T0)):
        with pytest.raises(cp.CheckpointError):
            cp.build_cert(w.m.root_sec, w.man, w.ck, issued, expires)


# ---------------------------------------------------------------- checkpoint

def test_checkpoint_round_trip(w):
    c = w.checkpoint(seq=7, ids=[IDS[2], IDS[0], IDS[0], IDS[1]])  # sorted and de-duplicated by the builder
    assert c.seq == 7 and c.created_at == T0 + 100 and c.valid_until == T0 + 100 + DAY
    assert c.events == frozenset(IDS) and json.loads(c.event["content"])["events"] == IDS
    assert c.manifest_id == w.man.event["id"] and c.manifest_version == w.man.version
    assert cp.verify_checkpoint(c, w.cert) and cp.checkpoint_problem(c, w.man, T0 + 200) is None
    assert c.event["tags"] == [["d", "aitools-alerts-checkpoint"]] and c.event["pubkey"] == w.ck
    empty = w.checkpoint(ids=[])
    assert empty.events == frozenset() and cp.verify_checkpoint(empty, w.cert)


@pytest.mark.parametrize("change", [
    dict(kind=9), dict(kind=1), dict(kind=30079), dict(tags=[["d", cp.CERT_D_TAG]]),
    dict(tags=[["d", manifest.D_TAG]]), dict(tags=[]), dict(tags=[["e", cp.CHECKPOINT_D_TAG]]),
    dict(tags=[["d", cp.CHECKPOINT_D_TAG], ["h", "x"]]), dict(tags=[["d", cp.CHECKPOINT_D_TAG, "x"]]),
    dict(content={"seq": 0}), dict(content={"seq": -1}), dict(content={"seq": True}),
    dict(content={"seq": 1.0}), dict(content={"seq": "1"}), dict(content={"seq": DROP}),
    dict(content={"seq": 2**53}), dict(created_at=cp.MAX_TIME + 1),
    dict(content={"valid_until": "2099-01-02T00:00:00Z"}), dict(content={"valid_until": DROP}),
    dict(content={"valid_until": -1}), dict(content={"valid_until": 1.5}),
    dict(content={"events": "x"}), dict(content={"events": DROP}), dict(content={"events": [IDS[1], IDS[0]]}),
    dict(content={"events": [IDS[0], IDS[0]]}), dict(content={"events": [IDS[0], "AB" * 32]}),
    dict(content={"events": [IDS[0], 5]}), dict(content={"events": ["12"]}),
    dict(content={"events": [f"{i:064x}" for i in range(cp.MAX_EVENT_IDS + 1)]}),
    dict(content={"manifest_id": "x"}), dict(content={"manifest_version": 0}),
    dict(content={"v": 2}), dict(content={"v": DROP}), dict(content={"v": False}),
])
def test_checkpoint_shape_is_checked(w, change):
    content = change.pop("content", None)
    ev = w.resign(w.ck_sec, w.checkpoint().event, content, **change)
    with pytest.raises(cp.CheckpointError):
        cp.load_checkpoint(raw(ev))


def _forgeries(sec, ev, content):
    """Three events that differ from the signed ``ev`` only in ways a signature
    check catches: the signature alone corrupted; other content with its id
    recomputed and the old signature; other content under the old id."""
    flipped = ev["sig"][:-1] + ("0" if ev["sig"][-1] != "0" else "1")
    other = json.dumps({**json.loads(ev["content"]), **content})
    moved = {**ev, "content": other}
    moved["id"] = nostr.event_id(moved)
    return [dict(ev, sig=flipped), moved, {**ev, "content": other}]


def test_a_forged_certificate_loads_but_never_verifies(w):
    """Each forgery parses into a consistent dataclass, so only the signature check stands in its way."""
    for forged in _forgeries(w.m.root_sec, w.cert_ev, {"checkpoint_key": nostr.keygen()[1]}):
        cert = cp.load_cert(raw(forged))  # the shape is fine
        assert cert.event["pubkey"] == w.m.root and not cp.verify_cert(cert, w.m.root)


def test_a_forged_checkpoint_loads_but_never_verifies(w):
    good = w.checkpoint()
    assert cp.verify_checkpoint(good, w.cert)
    for forged in _forgeries(w.ck_sec, good.event, {"events": IDS[:1]}):
        c = cp.load_checkpoint(raw(forged))
        assert c.event["pubkey"] == w.ck and not cp.verify_checkpoint(c, w.cert)


def test_checkpoint_refuses_an_extra_event_key(w):
    with pytest.raises(cp.CheckpointError, match="NIP-01 keys"):
        cp.load_checkpoint(raw(dict(w.checkpoint().event, relay="wss://example.invalid")))
    short = {k: v for k, v in w.checkpoint().event.items() if k != "sig"}
    with pytest.raises(cp.CheckpointError, match="NIP-01 keys"):
        cp.load_checkpoint(raw(short))


def test_every_dataclass_field_is_compared_with_the_event(w):
    """verify_* compares each field the later checks read (the manifest id among them)
    with the signed event: a dataclass changed after loading never verifies."""
    w.m.publish_manifest()  # version 2, so no field equals a default
    man2 = manifest.load(raw(w.m.manifest))
    cert = cp.load_cert(raw(cp.build_cert(w.m.root_sec, man2, w.ck, T0, T0 + DAY)))
    assert cert.manifest_version == 2 and cp.verify_cert(cert, w.m.root)
    for change in (dict(manifest_id="0" * 64), dict(manifest_version=1), dict(checkpoint_key=w.m.bot),
                   dict(issued_at=T0 - 1), dict(expires_at=T0 + 2 * DAY)):
        assert not cp.verify_cert(replace(cert, **change), w.m.root), change
    c = cp.load_checkpoint(raw(cp.build_checkpoint(w.ck_sec, man2, 5, IDS, T0 + 100)))
    assert c.manifest_version == 2 and cp.verify_checkpoint(c, cert)
    for change in (dict(seq=6), dict(created_at=T0 + 99), dict(valid_until=T0), dict(manifest_id="0" * 64),
                   dict(manifest_version=1), dict(events=frozenset())):
        assert not cp.verify_checkpoint(replace(c, **change), cert), change


def test_loaders_copy_the_event_and_refuse_odd_json_inside_it(w):
    ev = json.loads(raw(w.cert_ev))
    cert = cp.load_cert(raw(ev))
    assert cert.event == w.cert_ev and cert.event is not w.cert_ev
    body = raw(w.cert_ev).decode()
    twice = body.replace('"kind": 30078', '"kind": 30078, "kind": 30078')  # a duplicate key in a valid event
    assert twice != body
    with pytest.raises(cp.CheckpointError, match="duplicate key"):
        cp.load_cert(twice.encode())
    # Content that is valid but for one thing, so only the check named can refuse it: a
    # repeated key (the second copy could differ from what a looser parser kept) and a
    # non-standard constant in a field the parser otherwise ignores.
    for sec, src, load in ((w.m.root_sec, w.cert_ev, cp.load_cert),
                           (w.ck_sec, w.checkpoint().event, cp.load_checkpoint)):
        good = src["content"]
        assert good.endswith("}") and load(raw(src))
        cases = ((good[:-1] + ',"v":1}', "duplicate key"), (good[:-1] + ',"note":NaN}', "non-standard JSON constant"),
                 (good[:-1] + ',"note":Infinity}', "non-standard JSON constant"))
        for content, why in cases:
            odd = nostr.sign_event(sec, {**{k: src[k] for k in ("created_at", "kind", "tags")}, "content": content})
            with pytest.raises(cp.CheckpointError, match=why):
                load(raw(odd))


@pytest.mark.parametrize("data", [b"[" * 500 + b"]" * 500, b'{"a":' * 600 + b"1" + b"}" * 600])
def test_deeply_nested_json_is_a_checkpoint_error(data):
    """Unauthenticated mirror input: nesting the JSON decoder accepts must not escape
    as a RecursionError from copying it."""
    for load in (cp.load_cert, cp.load_checkpoint):
        with pytest.raises(cp.CheckpointError):
            load(data)


def test_nested_tags_in_a_signed_looking_event_are_a_checkpoint_error(w):
    deep = "[" * 600 + "]" * 600
    for src, load in ((w.cert_ev, cp.load_cert), (w.checkpoint().event, cp.load_checkpoint)):
        body = raw(src).decode().replace('"tags": [["d"', '"tags": [' + deep + ', ["d"', 1)
        assert deep in body
        with pytest.raises(cp.CheckpointError):
            load(body.encode())


def test_checkpoint_size_cap_and_the_full_list(w):
    full = w.checkpoint(ids=[f"{i:064x}" for i in range(cp.MAX_EVENT_IDS)])
    assert len(full.events) == cp.MAX_EVENT_IDS and len(raw(full.event)) < cp.MAX_CHECKPOINT_BYTES
    assert cp.verify_checkpoint(full, w.cert)
    fat = w.resign(w.ck_sec, full.event, {"note": "x" * cp.MAX_CHECKPOINT_BYTES})
    with pytest.raises(cp.CheckpointError, match="larger than"):
        cp.load_checkpoint(raw(fat))


def test_checkpoint_must_be_signed_by_the_certified_key(w):
    c = w.checkpoint()
    stranger_sec, stranger = nostr.keygen()
    assert not cp.verify_checkpoint(w.checkpoint(sec=stranger_sec), w.cert)
    assert not cp.verify_checkpoint(w.checkpoint(sec=w.m.root_sec), w.cert)  # not even the root
    assert not cp.verify_checkpoint(w.checkpoint(sec=w.m.bot_sec), w.cert)  # nor a poster in the manifest
    other_cert = cp.load_cert(raw(cp.build_cert(w.m.root_sec, w.man, stranger, T0, T0 + DAY)))
    assert not cp.verify_checkpoint(c, other_cert)
    assert not cp.verify_checkpoint(replace(c, events=frozenset(IDS[:2])), w.cert)  # a changed dataclass
    assert not cp.verify_checkpoint(replace(c, seq=c.seq + 1), w.cert)
    assert not cp.verify_checkpoint(replace(c, valid_until=c.valid_until + DAY), w.cert)
    shorter = w.resign(w.ck_sec, c.event, {"events": IDS[:2]})
    assert not cp.verify_checkpoint(cp.load_checkpoint(raw(dict(shorter, sig=c.event["sig"]))), w.cert)
    for junk in (None, c.event, replace(c, event=None)):
        assert cp.verify_checkpoint(junk, w.cert) is False
    assert cp.verify_checkpoint(c, None) is False


def test_checkpoint_is_bound_to_one_manifest_and_a_time(w):
    c = w.checkpoint(now=T0 + 1000)
    w.m.publish_manifest()
    assert cp.checkpoint_problem(c, manifest.load(raw(w.m.manifest)), T0 + 1000) == "other manifest"
    assert cp.checkpoint_problem(c, w.man, T0 + 1000 - cp.MAX_AHEAD_S) is None
    assert cp.checkpoint_problem(c, w.man, T0 + 1000 - cp.MAX_AHEAD_S - 1) == "dated ahead"


def test_fresh_until_honours_at_most_two_days(w):
    assert cp.fresh_until(w.checkpoint(now=T0)) == T0 + DAY  # the signer's default
    assert cp.fresh_until(w.checkpoint(now=T0, valid_s=3600)) == T0 + 3600
    assert cp.fresh_until(w.checkpoint(now=T0, valid_s=3650 * DAY)) == T0 + 2 * DAY  # ten years asked
    assert cp.fresh_until(w.checkpoint(now=T0, valid_s=2 * DAY)) == T0 + 2 * DAY
    assert cp.fresh_until(w.checkpoint(now=T0, valid_s=2 * DAY + 1)) == T0 + 2 * DAY
    assert cp.fresh_until(w.checkpoint(now=T0, valid_s=2 * DAY - 1)) == T0 + 2 * DAY - 1
    past = w.resign(w.ck_sec, w.checkpoint(now=T0).event, {"valid_until": T0 - 5})
    assert cp.fresh_until(cp.load_checkpoint(raw(past))) == T0 - 5  # never fresh


def test_checkpoint_order(w):
    a = w.checkpoint(seq=100, now=T0 + 100)
    assert cp.checkpoint_order(a, None) is None and cp.checkpoint_order(a, a) is None
    assert cp.checkpoint_order(cp.load_checkpoint(raw(a.event)), a) is None  # retransmission
    b = w.checkpoint(seq=101, now=T0 + 200, ids=IDS[:2])
    assert cp.checkpoint_order(b, a) is None
    assert cp.checkpoint_order(a, b) == "older checkpoint"  # the replay of 100 after 101
    twin = w.checkpoint(seq=100, now=T0 + 100, ids=IDS[:1])
    assert cp.checkpoint_order(twin, a) == "conflicting checkpoint"
    assert cp.checkpoint_order(w.checkpoint(seq=100, now=T0 + 900), a) == "conflicting checkpoint"
    assert cp.checkpoint_order(w.checkpoint(seq=102, now=T0 + 50), a) == "older checkpoint"  # higher seq, dated earlier
    assert cp.checkpoint_order(w.checkpoint(seq=102, now=T0 + 100), a) is None
    new_sec, _ = nostr.keygen()  # a new certificate named a new key: seq starts again
    assert cp.checkpoint_order(w.checkpoint(seq=1, now=T0 + 100, sec=new_sec), a) is None
    assert cp.checkpoint_order(w.checkpoint(seq=500, now=T0 + 99, sec=new_sec), a) == "older checkpoint"


def test_build_checkpoint_refuses_bad_input(w):
    bad = [dict(ids=["xyz"]), dict(ids=["AB" * 32]), dict(ids=[5]), dict(ids=[IDS[0], 5, None]),
           dict(ids=[f"{i:064x}" for i in range(cp.MAX_EVENT_IDS + 1)]),
           dict(seq=0), dict(seq=True), dict(seq=1.0), dict(seq=2**53), dict(now=1.5), dict(now=-1),
           dict(valid_s=0), dict(valid_s=1.5), dict(now=cp.MAX_TIME)]
    for kw in bad:
        args = dict(seq=1, ids=IDS, now=T0)
        args.update(kw)
        with pytest.raises(cp.CheckpointError):
            cp.build_checkpoint(w.ck_sec, w.man, args["seq"], args["ids"], args["now"],
                                **({"valid_s": args["valid_s"]} if "valid_s" in args else {}))


def test_unknown_content_keys_are_ignored(w):
    cert = cp.load_cert(raw(w.resign(w.m.root_sec, w.cert_ev, {"comment": "x", "ruleset": {"n": 1}})))
    assert cp.verify_cert(cert, w.m.root) and cp.cert_problem(cert, w.man, T0 + 5) is None
    c = cp.load_checkpoint(raw(w.resign(w.ck_sec, w.checkpoint().event, {"comment": ["y"]})))
    assert cp.verify_checkpoint(c, w.cert) and c.events == frozenset(IDS)


def test_another_format_version_is_refused_with_its_reason(w):
    for load, ev, sec in ((cp.load_cert, w.cert_ev, w.m.root_sec),
                          (cp.load_checkpoint, w.checkpoint().event, w.ck_sec)):
        with pytest.raises(cp.CheckpointError, match="unsupported format.*upgrade aitools-alerts"):
            load(raw(w.resign(sec, ev, {"v": 2, "min_cli": "9.9"})))


def test_no_document_passes_for_another(w):
    c = w.checkpoint()
    for load in (cp.load_cert, cp.load_checkpoint):
        with pytest.raises(cp.CheckpointError):
            load(raw(w.m.manifest))
    with pytest.raises(cp.CheckpointError):
        cp.load_cert(raw(c.event))
    with pytest.raises(cp.CheckpointError):
        cp.load_checkpoint(raw(w.cert_ev))
    for ev in (w.cert_ev, c.event):
        with pytest.raises(manifest.ManifestError):
            manifest.load(raw(ev))
    # the same content under the other d tag, signed by the right key, still does not load
    swapped = w.resign(w.m.root_sec, w.cert_ev, tags=[["d", cp.CHECKPOINT_D_TAG]])
    with pytest.raises(cp.CheckpointError):
        cp.load_cert(raw(swapped))


# ---------------------------------------------------------------- scripts/sign-checkpoint-key.py

@pytest.fixture
def script(w, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("sign_checkpoint_key", ROOT / "scripts" / "sign-checkpoint-key.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "TRUST_ROOT_PUBKEY", w.m.root)
    mod.calls = []

    def fake_secret(**kw):
        mod.calls.append(kw)
        return mod.answer
    mod.answer = w.m.root_sec
    monkeypatch.setattr(mod, "read_root_secret", fake_secret)
    monkeypatch.setattr(mod.time, "time", lambda: T0 + 50.9)
    mod.man = tmp_path / "manifest.json"
    mod.man.write_bytes(raw(w.m.manifest))
    mod.out = tmp_path / "checkpoint-key.json"
    mod.argv = lambda *a: [*a, "--manifest", str(mod.man), "--out", str(mod.out)]
    return mod


def test_script_signs_a_certificate_that_verifies(w, script, capsys):
    assert script.main(script.argv(nostr.npub(w.ck))) == 0
    cert = cp.load_cert(script.out)
    assert cp.verify_cert(cert, w.m.root) and cp.cert_problem(cert, w.man, T0 + 50) is None
    assert cert.checkpoint_key == w.ck and cert.issued_at == T0 + 50
    assert cert.expires_at - cert.issued_at == 120 * DAY
    out = capsys.readouterr()
    assert out.out == cert.event["id"] + "\n" and out.err == ""
    assert script.out.stat().st_mode & 0o777 == 0o644 and len(script.calls) == 1
    assert [p.name for p in script.out.parent.iterdir() if p.name.startswith(".")] == []
    for text in (out.out, out.err, script.out.read_text()):
        assert w.m.root_sec not in text and nostr.nsec(w.m.root_sec) not in text


def test_script_takes_an_npub_and_a_number_of_days(w, script):
    assert script.main(script.argv(nostr.npub(w.ck), "--days", "30")) == 0
    cert = cp.load_cert(script.out)
    assert cert.checkpoint_key == w.ck and cert.expires_at - cert.issued_at == 30 * DAY


@pytest.mark.parametrize("args", [["zz" * 32], ["ff" * 32], ["npub1qqqq"], ["HEX"], ["KEY", "--days", "0"],
                                  ["KEY", "--days", "401"], ["KEY", "--days", "-3"]])
def test_script_checks_its_inputs_before_reading_the_root_key(w, script, capsys, args):
    args = [{"KEY": nostr.npub(w.ck), "HEX": w.ck}.get(a, a) for a in args]
    with pytest.raises(SystemExit) as e:
        script.main(script.argv(*args))
    assert str(e.value).startswith("sign-checkpoint-key: ") or e.value.code == 2  # argparse for --days
    assert script.calls == [] and not script.out.exists()


def test_script_refuses_a_secret_key_as_the_checkpoint_key(w, script):
    """A 64-hex secret is a valid x coordinate about half the time, so hex is not taken
    at all: the key comes as an npub, which a secret cannot be."""
    for _ in range(20):
        sec, pub = nostr.keygen()
        for secret in (sec, nostr.nsec(sec)):
            with pytest.raises(SystemExit) as e:
                script.main(script.argv(secret))
            assert "npub" in str(e.value) and secret not in str(e.value)
    assert script.calls == [] and not script.out.exists()


def test_script_refuses_the_root_and_the_posters_as_the_checkpoint_key(w, script):
    """The checkpoint must come from a key the relay machine does not hold."""
    for pub in (w.m.root, w.m.bot, w.m.cur):
        with pytest.raises(SystemExit, match="its own key"):
            script.main(script.argv(nostr.npub(pub)))
    assert script.calls == [] and not script.out.exists()


def test_script_never_signs_a_certificate_readers_would_refuse(w, script, monkeypatch):
    """cert_order: a certificate issued before, or in the same second as, the one
    already published is refused by every reader that holds that one."""
    assert script.main(script.argv(nostr.npub(w.ck))) == 0  # issued at T0 + 50
    first = script.out.read_bytes()
    for clock in (T0 + 10.0, T0 + 50.2):  # set back; the same second
        monkeypatch.setattr(script.time, "time", lambda: clock)
        with pytest.raises(SystemExit, match="check the clock"):
            script.main(script.argv(nostr.npub(nostr.keygen()[1])))
    assert script.out.read_bytes() == first and len(script.calls) == 1
    monkeypatch.setattr(script.time, "time", lambda: T0 + 51.0)
    assert script.main(script.argv(nostr.npub(w.ck), "--days", "5")) == 0
    assert cp.cert_order(cp.load_cert(script.out), cp.load_cert(first)) is None
    script.out.write_text("{")
    with pytest.raises(SystemExit, match="unreadable"):
        script.main(script.argv(nostr.npub(w.ck)))
    stranger, _ = nostr.keygen()
    script.out.write_bytes(raw(cp.build_cert(stranger, w.man, w.ck, T0, T0 + DAY)))
    with pytest.raises(SystemExit, match="not signed by the trust root"):
        script.main(script.argv(nostr.npub(w.ck)))
    with pytest.raises(SystemExit, match="is the manifest"):
        script.main([nostr.npub(w.ck), "--manifest", str(script.man), "--out", str(script.man)])
    assert len(script.calls) == 2


def test_script_checks_what_it_signed_before_writing(w, script, monkeypatch):
    monkeypatch.setattr(script.checkpoint, "verify_cert", lambda *a: False)
    with pytest.raises(SystemExit, match="does not verify"):
        script.main(script.argv(nostr.npub(w.ck)))
    assert not script.out.exists()


def test_script_refuses_a_manifest_it_cannot_trust(w, script, tmp_path):
    stranger, _ = nostr.keygen()
    script.man.write_bytes(raw(w.m.publish_manifest(signer=stranger)))
    with pytest.raises(SystemExit, match="not signed by the trust root"):
        script.main(script.argv(nostr.npub(w.ck)))
    script.man.write_text("{")
    with pytest.raises(SystemExit, match="manifest"):
        script.main(script.argv(nostr.npub(w.ck)))
    script.man.write_bytes(raw(w.m.publish_manifest()))
    with pytest.raises(SystemExit, match="output directory"):
        script.main([nostr.npub(w.ck), "--manifest", str(script.man), "--out", str(tmp_path / "absent" / "c.json")])
    assert script.calls == [] and not script.out.exists()


def test_script_refuses_a_key_that_is_not_the_root(w, script):
    script.answer = w.m.cur_sec
    with pytest.raises(SystemExit, match="not the trust root"):
        script.main(script.argv(nostr.npub(w.ck)))
    assert len(script.calls) == 1 and not script.out.exists()


def test_script_reuses_the_manifest_script_for_the_root_key():
    """One implementation of the root key handling: this script defines none."""
    text = (ROOT / "scripts" / "sign-checkpoint-key.py").read_text()
    assert "sign-manifest.py" in text and "get_secret" not in text and "subprocess" not in text
