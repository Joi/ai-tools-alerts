"""check-wheel.py <wheel> <name> <version> <repo-root>: refuse anything but an empty placeholder wheel.

Run it on the exact file before that file is uploaded. Build the wheel from a copy of
pypi-placeholder/<name>/ as a wheel only: installing an sdist would run the setuptools backend
on the installer's machine, and installing a wheel runs nothing.
"""
import email.parser
import re
import sys
import zipfile

wheel, name, version, root = sys.argv[1:5]
sys.path.insert(0, root + "/tests")  # the install guard's regex and the approved summary
from test_install_path import INSTALL  # noqa: E402
from test_pypi_placeholder import SUMMARY  # noqa: E402

dist = name.replace("-", "_")
info = f"{dist}-{version}.dist-info"
want = {f"{info}/{f}" for f in ("METADATA", "WHEEL", "top_level.txt", "RECORD")}
z = zipfile.ZipFile(wheel)
names = set(z.namelist())
assert names == want, f"members: {sorted(names ^ want)}"
assert z.read(f"{info}/top_level.txt").strip() == b"", "top_level.txt names a module"
raw = z.read(f"{info}/METADATA").decode()
meta = email.parser.Parser().parsestr(raw)
assert (meta["Name"], meta["Version"]) == (name, version), (meta["Name"], meta["Version"])
assert meta["Summary"] == SUMMARY, meta["Summary"]
for h in ("Requires-Dist", "Author", "Author-email", "Maintainer", "Maintainer-email", "Provides-Extra",
          "Requires-Python"):
    assert h not in meta, f"header {h} present"
assert "@" not in raw, "an @ in METADATA (an email address?)"
body = meta.get_payload()
assert "No release of ai-tools-alerts is published on PyPI" in " ".join(body.split())
for line in body.splitlines():
    assert not INSTALL.search(line), line
    assert not re.search(r"\b(?:pip|pipx|uv|uvx)\b", line), line
print(f"ok {wheel.rsplit('/', 1)[-1]}: {sorted(n.rsplit('/', 1)[-1] for n in names)}")
