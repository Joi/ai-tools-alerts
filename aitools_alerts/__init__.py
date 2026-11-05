"""ai-tools security alerts: signed advisories for people running AI agents."""

__version__ = "0.1.0"

from pathlib import Path as _Path

_HERE = _Path(__file__).resolve().parent


def _data_dir(name: str) -> _Path:
    """spec/ and trust/ ship inside the installed package (package data);
    in a source checkout they are at the repo root."""
    inside = _HERE / name
    return inside if inside.is_dir() else _HERE.parent / name


TRUST_DIR = _data_dir("trust")

# x-only public key (hex) of the trust root that signs the poster manifest.
# Must equal trust/root.pub; tests/test_trust_root.py checks it.
TRUST_ROOT_PUBKEY = "afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4"
