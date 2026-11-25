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


def test_committed_certificate_fits_the_manifest_and_pins_this_ruleset():
    """The shipped certificate is the root's, bound to the shipped manifest, and a
    ruleset pin it carries does not call this checkout's own ruleset out of date:
    a release whose spec files changed without a new ruleset version, or without a
    certificate signed again, would stop its own readers judging any level
    (ai-tools-alerts#46yr)."""
    from aitools_alerts import checkpoint, manifest, ruleset
    trust = ROOT_PUB.parent
    cert = checkpoint.load_cert(trust / "checkpoint-key.json")
    m = manifest.load(trust / "manifest.json")
    assert checkpoint.verify_cert(cert, TRUST_ROOT_PUBKEY)
    assert (cert.manifest_id, cert.manifest_version) == (m.event["id"], m.version)
    assert not cert.ruleset_unreadable
    if cert.ruleset is not None:
        assert not ruleset.outdated(cert.ruleset, ruleset.load())
