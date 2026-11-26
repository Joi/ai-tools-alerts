# 26f0: the empty projects that hold the PyPI names. They must stay empty (no code, no
# command, no dependency, no author) and must say that nothing is published there,
# without an install command.
import re
import tomllib
from pathlib import Path

import pytest

from test_install_path import INSTALL

ROOT = Path(__file__).resolve().parent.parent
HOME = ROOT / "pypi-placeholder"
NAMES = {"aitools-alerts": "0.0.2", "ai-tools-alerts": "0.0.1"}
URL = "https://github.com/Joi/ai-tools-alerts"
SUMMARY = ("Empty placeholder. No release of ai-tools-alerts is published on PyPI; the only supported "
           f"install is the verified signed release described in the README at {URL}")


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
    assert data["tool"] == {"setuptools": {"packages": [], "py-modules": []}}
    root = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert data["build-system"] == root["build-system"]
    assert sorted(p.name for p in (HOME / name).iterdir()) == ["README.md", "pyproject.toml"]


@pytest.mark.parametrize("name", sorted(NAMES))
def test_placeholder_text_has_no_install_command(name):
    text = (HOME / name / project_readme(name)).read_text()
    flat = " ".join(text.split())
    assert "No release of ai-tools-alerts is published on PyPI" in flat
    assert f"the verified signed release described in the README at {URL}" in flat
    for line in text.splitlines():
        assert not INSTALL.search(line), line
        assert not re.search(r"\b(?:pip|pipx|uv|uvx|git clone)\b", line), line


def project_readme(name):
    return load(name)["project"]["readme"]


def test_the_placeholder_texts_differ_only_in_the_name():
    texts = {n: (HOME / n / "README.md").read_text().replace(f"# {n}\n", "# NAME\n", 1) for n in NAMES}
    assert len(set(texts.values())) == 1
