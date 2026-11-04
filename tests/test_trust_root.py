from pathlib import Path

from aitools_alerts import TRUST_ROOT_PUBKEY, nostr

ROOT_PUB = Path(__file__).resolve().parent.parent / "trust" / "root.pub"


def test_trust_root_pubkey_is_pinned_and_matches_file():
    assert len(TRUST_ROOT_PUBKEY) == 64
    assert all(c in "0123456789abcdef" for c in TRUST_ROOT_PUBKEY)
    assert ROOT_PUB.read_text().strip() == TRUST_ROOT_PUBKEY


def test_trust_root_pubkey_is_a_curve_point():
    # a valid x-only key encodes to an npub and round-trips
    assert nostr.npub_to_hex(nostr.npub(TRUST_ROOT_PUBKEY)) == TRUST_ROOT_PUBKEY
    assert nostr._lift_x(int(TRUST_ROOT_PUBKEY, 16)) is not None


def test_readme_pins_the_same_key():
    readme = (ROOT_PUB.parent.parent / "README.md").read_text()
    assert TRUST_ROOT_PUBKEY in readme
