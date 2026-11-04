import copy
import csv
import json
from pathlib import Path

import pytest

from aitools_alerts import nostr

FIXTURES = Path(__file__).parent / "fixtures"


def _bip340_vectors():
    with open(FIXTURES / "bip340-test-vectors.csv", newline="") as f:
        return list(csv.DictReader(f))


VECTORS = _bip340_vectors()


def test_bip340_vector_1():
    v = VECTORS[0]
    assert v["public key"] == "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    sec = bytes.fromhex(v["secret key"])
    msg = bytes.fromhex(v["message"])
    sig = bytes.fromhex(v["signature"])
    assert nostr.pubkey_gen(sec).hex().upper() == v["public key"]
    assert nostr.schnorr_sign(msg, sec, bytes.fromhex(v["aux_rand"])) == sig
    assert nostr.schnorr_verify(msg, bytes.fromhex(v["public key"]), sig) is True


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: f"vector{v['index']}")
def test_bip340_published_vectors(v):
    pub = bytes.fromhex(v["public key"])
    msg = bytes.fromhex(v["message"])
    sig = bytes.fromhex(v["signature"])
    if v["secret key"]:
        sec = bytes.fromhex(v["secret key"])
        assert nostr.pubkey_gen(sec) == pub
        assert nostr.schnorr_sign(msg, sec, bytes.fromhex(v["aux_rand"])) == sig
    expected = v["verification result"] == "TRUE"
    assert nostr.schnorr_verify(msg, pub, sig) is expected


def _template():
    return {
        "created_at": 1730764800,
        "kind": 1,
        "tags": [["t", "test"]],
        "content": 'hello "nostr"\nline two\ttab \\ backslash é ☃',
    }


def test_sign_then_verify_roundtrip():
    sec, pub = nostr.keygen()
    tmpl = _template()
    before = copy.deepcopy(tmpl)
    ev = nostr.sign_event(sec, tmpl)
    assert tmpl == before  # input not mutated
    assert ev["pubkey"] == pub
    assert ev["id"] == nostr.event_id(ev)
    assert len(ev["sig"]) == 128
    assert nostr.verify_event(ev) is True
    # survives a JSON roundtrip, as events do on the wire
    assert nostr.verify_event(json.loads(json.dumps(ev))) is True


def test_tampered_content_fails_verify():
    sec, _ = nostr.keygen()
    ev = nostr.sign_event(sec, _template())
    bad = dict(ev, content=ev["content"] + "!")
    assert nostr.verify_event(bad) is False
    # content changed and id recomputed: the signature no longer matches
    bad["id"] = nostr.event_id(bad)
    assert nostr.verify_event(bad) is False


def test_tampered_fields_fail_verify():
    sec, _ = nostr.keygen()
    _, other_pub = nostr.keygen()
    ev = nostr.sign_event(sec, _template())
    assert nostr.verify_event(dict(ev, created_at=ev["created_at"] + 1)) is False
    assert nostr.verify_event(dict(ev, tags=[])) is False
    assert nostr.verify_event(dict(ev, kind=2)) is False
    flipped = ("0" if ev["sig"][-1] != "0" else "1")
    assert nostr.verify_event(dict(ev, sig=ev["sig"][:-1] + flipped)) is False
    swapped = dict(ev, pubkey=other_pub)
    swapped["id"] = nostr.event_id(swapped)
    assert nostr.verify_event(swapped) is False


def test_event_id_matches_known_event():
    # A kind-1 event as published on a public relay (fixture), with its id and sig.
    ev = json.loads((FIXTURES / "nip01_event.json").read_text())
    assert nostr.event_id(ev) == ev["id"]
    assert nostr.verify_event(ev) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: "not a dict",
        lambda e: {k: v for k, v in e.items() if k != "sig"},
        lambda e: {k: v for k, v in e.items() if k != "tags"},
        lambda e: dict(e, sig="zz" * 64),
        lambda e: dict(e, sig=e["sig"][:-2]),
        lambda e: dict(e, id=e["id"].upper()),
        lambda e: dict(e, pubkey=e["pubkey"][:-2]),
        lambda e: dict(e, pubkey="ff" * 32),  # not an x coordinate on the curve
        lambda e: dict(e, created_at="1"),
        lambda e: dict(e, created_at=True),
        lambda e: dict(e, kind=-1),
        lambda e: dict(e, tags=[["ok"], [1]]),
        lambda e: dict(e, tags="[]"),
        lambda e: dict(e, content=None),
    ],
)
def test_verify_malformed_returns_false(mutate):
    ev = json.loads((FIXTURES / "nip01_event.json").read_text())
    assert nostr.verify_event(mutate(ev)) is False


def test_nsec_roundtrip():
    sec_hex = VECTORS[1]["secret key"].lower()
    encoded = nostr.nsec(sec_hex)
    assert encoded.startswith("nsec1")
    assert nostr.nsec_to_hex(encoded) == sec_hex
    assert nostr.nsec_to_hex(encoded.upper()) == sec_hex


def test_npub_known_value():
    # NIP-19 examples
    pub = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
    enc = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
    assert nostr.npub(pub) == enc
    assert nostr.npub_to_hex(enc) == pub


def test_bech32_rejects_bad_input():
    enc = nostr.npub("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")
    last = "q" if enc[-1] != "q" else "p"
    with pytest.raises(ValueError):
        nostr.npub_to_hex(enc[:-1] + last)  # bad checksum
    with pytest.raises(ValueError):
        nostr.nsec_to_hex(enc)  # wrong prefix
    with pytest.raises(ValueError):
        nostr.npub_to_hex(enc[:10] + enc[10:].upper())  # mixed case
    with pytest.raises(ValueError):
        nostr.npub("ab" * 31)


def test_keygen_shape():
    sec, pub = nostr.keygen()
    assert len(sec) == 64 and len(pub) == 64
    assert nostr.pubkey_gen(bytes.fromhex(sec)).hex() == pub
    assert nostr.keygen()[0] != sec


def test_sign_event_rejects_bad_key_and_shape():
    with pytest.raises(ValueError):
        nostr.sign_event("00" * 32, _template())  # zero is not a valid key
    with pytest.raises(ValueError):
        nostr.sign_event("ab", _template())
    sec, _ = nostr.keygen()
    with pytest.raises(ValueError):
        nostr.sign_event(sec, dict(_template(), tags=[[1]]))
