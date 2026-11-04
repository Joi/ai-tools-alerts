"""ai-tools security alerts: signed advisories for people running AI agents."""

__version__ = "0.1.0"

# x-only public key (hex) of the trust root that signs the poster manifest.
# Must equal trust/root.pub; tests/test_trust_root.py checks it.
TRUST_ROOT_PUBKEY = "afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4"
