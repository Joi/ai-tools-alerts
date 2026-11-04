"""Nostr primitives in pure Python: BIP-340 Schnorr signatures over secp256k1,
NIP-01 event ids, and NIP-19 bech32 keys.

The signing and verification follow the BIP-340 reference implementation
(https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py). Point
arithmetic runs in Jacobian coordinates internally for speed; results are
converted back to affine before any comparison or encoding.

This module is not constant-time. It is meant for verifying events and for
signing on a trusted machine, not for signing on a shared host.
"""

from __future__ import annotations

import hashlib
import json
import secrets

__all__ = [
    "keygen",
    "sign_event",
    "verify_event",
    "event_id",
    "npub",
    "nsec",
    "npub_to_hex",
    "nsec_to_hex",
]

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# ---------------------------------------------------------------- point math
# Affine points are (x, y) tuples; None is the point at infinity.
# Jacobian points are (X, Y, Z) with x = X/Z^2, y = Y/Z^3; Z == 0 is infinity.

_INF_J = (1, 1, 0)


def _to_jacobian(pt):
    if pt is None:
        return _INF_J
    return (pt[0], pt[1], 1)


def _to_affine(pt):
    x, y, z = pt
    if z == 0:
        return None
    zinv = pow(z, -1, P)
    zinv2 = zinv * zinv % P
    return (x * zinv2 % P, y * zinv2 * zinv % P)


def _j_double(pt):
    x, y, z = pt
    if z == 0 or y == 0:
        return _INF_J
    ysq = y * y % P
    s = 4 * x * ysq % P
    m = 3 * x * x % P  # a = 0 for secp256k1
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * ysq * ysq) % P
    nz = 2 * y * z % P
    return (nx, ny, nz)


def _j_add(p1, p2):
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1sq = z1 * z1 % P
    z2sq = z2 * z2 % P
    u1 = x1 * z2sq % P
    u2 = x2 * z1sq % P
    s1 = y1 * z2sq * z2 % P
    s2 = y2 * z1sq * z1 % P
    if u1 == u2:
        if s1 != s2:
            return _INF_J
        return _j_double(p1)
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    nx = (r * r - h3 - 2 * u1h2) % P
    ny = (r * (u1h2 - nx) - s1 * h3) % P
    nz = h * z1 * z2 % P
    return (nx, ny, nz)


def _j_mul(pt, k):
    result = _INF_J
    addend = pt
    while k:
        if k & 1:
            result = _j_add(result, addend)
        addend = _j_double(addend)
        k >>= 1
    return result


def point_mul(pt, k):
    """Return k*pt as an affine point (None for infinity)."""
    return _to_affine(_j_mul(_to_jacobian(pt), k % N))


def _has_even_y(pt) -> bool:
    return pt[1] % 2 == 0


def _lift_x(x: int):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


# ---------------------------------------------------------------- BIP-340


def _bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pubkey_gen(seckey: bytes) -> bytes:
    d0 = _int_from_bytes(seckey)
    if not (1 <= d0 <= N - 1):
        raise ValueError("secret key must be an integer in 1..n-1")
    pt = point_mul(G, d0)
    return _bytes_from_int(pt[0])


def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    d0 = _int_from_bytes(seckey)
    if not (1 <= d0 <= N - 1):
        raise ValueError("secret key must be an integer in 1..n-1")
    pt = point_mul(G, d0)
    d = d0 if _has_even_y(pt) else N - d0
    t = _xor(_bytes_from_int(d), _tagged_hash("BIP0340/aux", aux_rand))
    k0 = _int_from_bytes(_tagged_hash("BIP0340/nonce", t + _bytes_from_int(pt[0]) + msg)) % N
    if k0 == 0:
        raise RuntimeError("nonce is zero; retry with different aux_rand")
    r_pt = point_mul(G, k0)
    k = k0 if _has_even_y(r_pt) else N - k0
    e = _int_from_bytes(
        _tagged_hash("BIP0340/challenge", _bytes_from_int(r_pt[0]) + _bytes_from_int(pt[0]) + msg)
    ) % N
    sig = _bytes_from_int(r_pt[0]) + _bytes_from_int((k + e * d) % N)
    if not schnorr_verify(msg, _bytes_from_int(pt[0]), sig):
        raise RuntimeError("created signature does not verify")
    return sig


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    pt = _lift_x(_int_from_bytes(pubkey))
    if pt is None:
        return False
    r = _int_from_bytes(sig[0:32])
    s = _int_from_bytes(sig[32:64])
    if r >= P or s >= N:
        return False
    e = _int_from_bytes(_tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % N
    # R = s*G - e*P
    r_j = _j_add(_j_mul(_to_jacobian(G), s), _j_mul(_to_jacobian(pt), N - e))
    r_pt = _to_affine(r_j)
    if r_pt is None or not _has_even_y(r_pt) or r_pt[0] != r:
        return False
    return True


# ---------------------------------------------------------------- NIP-01

_HEX = frozenset("0123456789abcdef")


def _is_hex(s, nbytes: int) -> bool:
    return isinstance(s, str) and len(s) == 2 * nbytes and all(c in _HEX for c in s)


def _serialize(event: dict) -> bytes:
    payload = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def event_id(event: dict) -> str:
    """sha256 hex of the NIP-01 serialization [0,pubkey,created_at,kind,tags,content]."""
    return hashlib.sha256(_serialize(event)).hexdigest()


def keygen() -> tuple[str, str]:
    """Return a new (secret key hex, x-only public key hex) pair."""
    while True:
        d = _int_from_bytes(secrets.token_bytes(32))
        if 1 <= d <= N - 1:
            sec = _bytes_from_int(d)
            return sec.hex(), pubkey_gen(sec).hex()


def sign_event(sec_hex: str, event: dict) -> dict:
    """Return a copy of event with pubkey, id and sig filled in.

    The event must carry created_at (int), kind (int), tags (list of lists of
    str) and content (str). The input dict is not modified.
    """
    if not _is_hex(sec_hex, 32):
        raise ValueError("secret key must be 64 lowercase hex characters")
    sec = bytes.fromhex(sec_hex)
    out = {
        "pubkey": pubkey_gen(sec).hex(),
        "created_at": event["created_at"],
        "kind": event["kind"],
        "tags": [list(t) for t in event["tags"]] if isinstance(event["tags"], list) else event["tags"],
        "content": event["content"],
    }
    _check_shape(out)
    out["id"] = event_id(out)
    out["sig"] = schnorr_sign(bytes.fromhex(out["id"]), sec, secrets.token_bytes(32)).hex()
    return out


def _check_shape(event: dict) -> None:
    if not _is_hex(event.get("pubkey"), 32):
        raise ValueError("pubkey must be 64 lowercase hex characters")
    ca = event.get("created_at")
    if not isinstance(ca, int) or isinstance(ca, bool) or ca < 0:
        raise ValueError("created_at must be a non-negative integer")
    kind = event.get("kind")
    if not isinstance(kind, int) or isinstance(kind, bool) or not (0 <= kind <= 65535):
        raise ValueError("kind must be an integer in 0..65535")
    tags = event.get("tags")
    if not isinstance(tags, list) or not all(
        isinstance(t, list) and t and all(isinstance(v, str) for v in t) for t in tags
    ):
        raise ValueError("tags must be a list of non-empty lists of strings")
    if not isinstance(event.get("content"), str):
        raise ValueError("content must be a string")


def verify_event(event: dict) -> bool:
    """True only if the event is well formed, its id matches its content, and
    its signature verifies under its pubkey. Never raises on bad input."""
    try:
        if not isinstance(event, dict):
            return False
        _check_shape(event)
        if not _is_hex(event.get("id"), 32) or not _is_hex(event.get("sig"), 64):
            return False
        if event_id(event) != event["id"]:
            return False
        return schnorr_verify(
            bytes.fromhex(event["id"]),
            bytes.fromhex(event["pubkey"]),
            bytes.fromhex(event["sig"]),
        )
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


# ---------------------------------------------------------------- NIP-19 bech32

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values) -> int:
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= _GEN[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid data for bit conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding")
    return ret


def _bech32_encode(hrp: str, data: bytes) -> str:
    five = _convertbits(data, 8, 5, True)
    values = _hrp_expand(hrp) + five
    pm = _polymod(values + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in five + checksum)


def _bech32_decode(expected_hrp: str, s: str) -> bytes:
    if not isinstance(s, str) or any(ord(c) < 33 or ord(c) > 126 for c in s):
        raise ValueError("invalid bech32 characters")
    if s.lower() != s and s.upper() != s:
        raise ValueError("mixed-case bech32")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("invalid bech32 separator position")
    hrp, rest = s[:pos], s[pos + 1 :]
    if hrp != expected_hrp:
        raise ValueError(f"expected prefix {expected_hrp!r}")
    if any(c not in _CHARSET for c in rest):
        raise ValueError("invalid bech32 data character")
    data = [_CHARSET.find(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad bech32 checksum")
    decoded = bytes(_convertbits(data[:-6], 5, 8, False))
    if len(decoded) != 32:
        raise ValueError("key must be 32 bytes")
    return decoded


def npub(pub_hex: str) -> str:
    if not _is_hex(pub_hex, 32):
        raise ValueError("public key must be 64 lowercase hex characters")
    return _bech32_encode("npub", bytes.fromhex(pub_hex))


def npub_to_hex(npub_str: str) -> str:
    raw = _bech32_decode("npub", npub_str)
    if _lift_x(_int_from_bytes(raw)) is None:
        raise ValueError("npub is not a valid x-only public key")
    return raw.hex()


def nsec(sec_hex: str) -> str:
    if not _is_hex(sec_hex, 32):
        raise ValueError("secret key must be 64 lowercase hex characters")
    return _bech32_encode("nsec", bytes.fromhex(sec_hex))


def nsec_to_hex(nsec_str: str) -> str:
    raw = _bech32_decode("nsec", nsec_str)
    if not (1 <= _int_from_bytes(raw) <= N - 1):
        raise ValueError("nsec is not a valid secret key")
    return raw.hex()
