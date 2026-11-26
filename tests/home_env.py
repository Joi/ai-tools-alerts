"""The test suite's home: never the member's (ai-tools-alerts#3h9j).

The reader takes its home from the password database, never HOME
(``config.home``), so a test that reaches ``config.config_dir()`` or
``config.state_dir()`` without a redirect reads and writes the real member's
config and state. On 2026-11-24 a test run did that on a member's machine: the
real config.toml pointed at a pytest temp mirror and the real state carried
2099-dated test data, so the reader there said "no checkpoint" from then on.

So, at import (before collection, and so before any test module or
import-time ``Path.home()``):

- HOME and the XDG base directories point into a fresh temporary directory for
  the whole session;
- ``config.home`` in this process is a guarded resolver returning HOME:
  resolving the real home, or a path below it, fails the test, even inside code
  that catches Exception (``pytest.fail`` raises a BaseException, and the
  violation is recorded and asserted again at teardown);
- a Python child started with the inherited environment loads a
  ``sitecustomize`` (on PYTHONPATH) that makes the password database report the
  session home for this uid, before any of the child's code runs;
- the real reader and poster config and state directories are fingerprinted,
  so a test (or collection, or a session fixture) that changed them fails.

This module is imported by tests/conftest.py, right after git_env, and has its
own name for the same reason that module does.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import pwd
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest

XDG = ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")
MARKER = "AITOOLS_ALERTS_TEST_HOME"


def _passwd_home() -> Path | None:
    # In a Python child of a test run (a nested pytest), the hook below has
    # already redirected pwd.getpwuid; it keeps the true lookup beside it.
    lookup = getattr(pwd, "_aitools_alerts_true_getpwuid", pwd.getpwuid)
    try:
        d = lookup(os.getuid()).pw_dir
    except KeyError:
        return None
    return Path(d).resolve() if d.startswith("/") else None


def _within(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


REAL_HOME = _passwd_home()

# The directories a member's machine keeps real data in, from the real home.
# EXTRA_GUARDED (an os.pathsep list) adds directories, never removes one: the
# suite's own tests use it to watch a stand-in in an inner pytest run.
GUARDED = (() if REAL_HOME is None else (
    REAL_HOME / ".config" / "aitools-alerts",
    REAL_HOME / ".local" / "state" / "aitools-alerts",
    REAL_HOME / ".config" / "aitools-alerts-poster",
    REAL_HOME / ".local" / "state" / "aitools-alerts-poster",
)) + tuple(Path(p) for p in os.environ.get("AITOOLS_ALERTS_TEST_EXTRA_GUARDED", "").split(os.pathsep) if p)


def overlaps_guarded(p, holds=True) -> Path | None:
    """The guarded directory ``p`` is in or is (or, with ``holds``, holds);
    None if none."""
    p = Path(p).resolve()
    for g in GUARDED:
        g = g.resolve()
        if _within(p, g) or (holds and _within(g, p)):
            return g
    return None


# Checked before tempfile looks at them: finding the temp dir writes a probe
# file in it. A temp dir that merely holds a guarded one is fine.
for _k in ("TMPDIR", "TEMP", "TMP"):
    if os.environ.get(_k) and (_g := overlaps_guarded(os.environ[_k], holds=False)):
        raise RuntimeError(f"{_k}={os.environ[_k]} overlaps the real {_g}: set it elsewhere")

SESSION_HOME = Path(tempfile.mkdtemp(prefix="aitools-alerts-test-home-")).resolve()
atexit.register(shutil.rmtree, SESSION_HOME, True)
if _g := overlaps_guarded(SESSION_HOME):
    raise RuntimeError(f"the test home {SESSION_HOME} overlaps the real {_g}: set TMPDIR elsewhere")

# The system temp dir is exempt from the real-home test (TMPDIR=~/tmp is common)
# unless it is the real home or holds it, where exempting it would exempt everything.
_TEMP = Path(tempfile.gettempdir()).resolve()
TEMP_EXEMPT = None if REAL_HOME is not None and _within(REAL_HOME, _TEMP) else _TEMP
EXEMPT: list[Path] = []  # more test roots, added by exempt()


def exempt(root) -> bool:
    """Treat ``root`` (pytest's basetemp) as a test root, not the real home,
    when it neither is nor holds the real home and is not in or above a guarded
    directory. Returns whether it was added."""
    root = Path(root).resolve()
    if REAL_HOME is not None and _within(REAL_HOME, root):
        return False
    if overlaps_guarded(root):
        return False
    EXEMPT.append(root)
    return True


# A sitecustomize, not a usercustomize: Python imports it inside a venv and with
# the user site off (PYTHONNOUSERSITE, -s); only -S and -I skip it. It runs the
# sitecustomize it shadows (some Python builds ship one) after its own patch.
SIGNATURE = "Written by tests/home_env.py"
SITECUSTOMIZE = f'''"""{SIGNATURE}: in a Python child of the test suite, the
password database reports the test home (${MARKER}) for this uid."""
import os as _os, pwd as _pwd
_home = _os.environ.get("{MARKER}")
if _home:
    _real = getattr(_pwd, "_aitools_alerts_true_getpwuid", _pwd.getpwuid)
    def _getpwuid(uid, _real=_real, _home=_home):
        e = _real(uid)
        if uid != _os.getuid():
            return e
        return _pwd.struct_passwd((e.pw_name, e.pw_passwd, e.pw_uid, e.pw_gid,
                                   e.pw_gecos, _home, e.pw_shell))
    _pwd._aitools_alerts_true_getpwuid = _real
    _pwd.getpwuid = _getpwuid


def _chain():
    """Run the first sitecustomize on sys.path that is not one of these hooks
    (a nested test run adds a second one; skipping all of them ends the chain)."""
    import importlib.machinery, importlib.util, sys
    for d in sys.path:
        spec = importlib.machinery.PathFinder.find_spec("sitecustomize", [d or "."])
        if spec is None or spec.loader is None or not spec.origin:
            continue
        try:
            with open(spec.origin, encoding="utf-8", errors="replace") as f:
                if "{SIGNATURE}" in f.read(200):
                    continue
        except OSError:
            continue
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return


_chain()
'''
PYHOOK = SESSION_HOME / ".pyhook"
PYHOOK.mkdir()
(PYHOOK / "sitecustomize.py").write_text(SITECUSTOMIZE)

ENV = {"HOME": str(SESSION_HOME), MARKER: str(SESSION_HOME)}
ENV.update({k: str(SESSION_HOME / k.lower()) for k in XDG})
ENV["PYTHONPATH"] = os.pathsep.join([str(PYHOOK)] + [p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p])
os.environ.update(ENV)


def under_real_home(p) -> bool:
    """True when ``p`` is the real home or below it. A path in the session home
    never is; one under the system temp directory is not either, unless that
    directory is the real home or holds it."""
    if REAL_HOME is None:
        return False
    p = Path(p).resolve()
    if _within(p, SESSION_HOME) or (TEMP_EXEMPT is not None and _within(p, TEMP_EXEMPT)) \
            or any(_within(p, r) for r in EXEMPT):
        return False
    return _within(p, REAL_HOME)


def _entry(f: Path, base: Path) -> tuple | None:
    try:
        st = f.lstat()
    except FileNotFoundError:
        return None
    return (str(f.relative_to(base)), stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode),
            st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def fingerprint(dirs=None) -> dict[str, tuple | None]:
    """Each directory's entries (files and directories) as sorted (relative
    path, type, mode, inode, size, mtime_ns, ctime_ns), with the directory
    itself as "."; None when it does not exist. Metadata only: the config
    directory can hold the member's key, and nothing here reads a file. ctime
    moves on every write, chmod or utime, so a change that keeps the size and
    restores the mtime still shows; the directory's own times show an entry
    created and deleted inside it."""
    _auditing[0] = False
    try:
        return _fingerprint(dirs)
    finally:
        _auditing[0] = True


def _fingerprint(dirs) -> dict[str, tuple | None]:
    out: dict[str, tuple | None] = {}
    for d in GUARDED if dirs is None else dirs:
        d = Path(d)
        if not d.is_dir():
            out[str(d)] = None
            continue
        rows = [e for e in (_entry(f, d) for f in [d, *sorted(d.rglob("*"))]) if e is not None]
        out[str(d)] = tuple(rows)
    return out


def changed(before: dict, after: dict) -> list[str]:
    """The fingerprinted directories whose contents differ, each with the
    entries that changed."""
    msgs = []
    for d in before:
        a, b = before[d], after.get(d)
        if a == b:
            continue
        if a is None:
            msgs.append(f"{d} was created")
        elif b is None:
            msgs.append(f"{d} was removed")
        else:
            old, new = {r[0]: r[1:] for r in a}, {r[0]: r[1:] for r in b}
            diff = sorted(k for k in old.keys() | new.keys() if old.get(k) != new.get(k))
            msgs.append(f"{d}: {', '.join(diff)}")
    return msgs


class Guard:
    """A guarded ``config.home``: HOME, refusing the real home."""

    def __init__(self):
        self.violations: list[str] = []

    def check(self, p) -> Path:
        p = Path(p)
        if under_real_home(p):
            self.violations.append(str(p))
            pytest.fail(f"the reader's home resolved to {p}, the real home: tests use the "
                        "session home or the home fixture (tests/conftest.py)", pytrace=False)
        return p

    def home(self) -> Path:
        return self.check(Path.home())


@contextlib.contextmanager
def watching(dirs=None):
    """One test: yields a fresh Guard; afterwards fails the test if the guard
    caught a real-home resolution or the fingerprinted directories changed."""
    guard = Guard()
    before = fingerprint(dirs)
    CURRENT[0] = guard
    try:
        yield guard
    finally:
        CURRENT[0] = SESSION
    if guard.violations:
        pytest.fail(f"this test resolved the real home: {', '.join(guard.violations)}", pytrace=False)
    moved = changed(before, fingerprint(dirs))
    if moved:
        pytest.fail("this test changed the real reader or poster files (or a reader on this "
                    "machine wrote them while it ran): " + "; ".join(moved), pytrace=False)


_GUARDED_ABS = tuple(os.path.abspath(g) for g in GUARDED)
_GUARDED_REAL = tuple(os.path.realpath(g) for g in GUARDED)
# event -> (path index, dir_fd index or None) for each path argument. Every
# "os.*" event carries its dir_fd; "open" does not, so os.open is wrapped below.
_FILE_EVENTS = {
    "open": ((0, None),), "os.listdir": ((0, None),), "os.scandir": ((0, None),),
    "os.mkdir": ((0, 2),), "os.rmdir": ((0, 1),), "os.remove": ((0, 1),),
    "os.rename": ((0, 2), (1, 3)), "os.replace": ((0, 2), (1, 3)), "os.chmod": ((0, 2),),
    "os.chown": ((0, 3),), "os.utime": ((0, 3),), "os.truncate": ((0, None),),
    "os.link": ((0, 2), (1, 3)), "os.symlink": ((1, 2),), "os.chdir": ((0, None),),
    "shutil.rmtree": ((0, 1),), "shutil.copyfile": ((0, None), (1, None)),
    "shutil.move": ((0, None), (1, None)),
}
_auditing = [True]  # off only while fingerprint() looks at the guarded directories


def _fd_path(fd: int) -> str | None:
    """The path an open descriptor names, where the platform says."""
    try:
        import fcntl
        if hasattr(fcntl, "F_GETPATH"):  # macOS
            return os.fsdecode(fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024))).rstrip("\0")
        return os.readlink(f"/proc/self/fd/{fd}")  # Linux
    except (OSError, ValueError, ImportError):
        return None


def _in(p: str, roots) -> bool:
    return any(p == g or p.startswith(g + os.sep) for g in roots)


def _guarded_path(p, dir_fd=None) -> str | None:
    """The guarded path ``p`` names (relative to ``dir_fd`` when given), by the
    path as written or by where it resolves; None if neither is guarded."""
    if isinstance(p, bytes):
        p = os.fsdecode(p)
    if isinstance(p, int) and not isinstance(p, bool):
        p = _fd_path(p)  # a descriptor: the file or directory it is open on
        if p is None:
            return None
    elif not isinstance(p, (str, os.PathLike)):
        return None
    p = os.fspath(p)
    if isinstance(dir_fd, int) and not os.path.isabs(p):
        base = _fd_path(dir_fd)
        if base is None:
            return None
        p = os.path.join(base, p)
    a, r = os.path.abspath(p), os.path.realpath(p)
    # Both: a link inside a guarded directory pointing out, and one outside pointing in.
    if _in(a, _GUARDED_ABS) or _in(a, _GUARDED_REAL):
        return a
    if _in(r, _GUARDED_REAL) or _in(r, _GUARDED_ABS):
        return r
    return None


def _refuse(event, hit):
    _auditing[0] = False  # pytest.fail's own reporting must not re-enter
    try:
        CURRENT[0].violations.append(f"{event} {hit}")
        pytest.fail(f"{event} on {hit}: tests never read or write the real reader or "
                    "poster files (tests/home_env.py)", pytrace=False)
    finally:
        _auditing[0] = True


def _audit(event, args):
    spec = _FILE_EVENTS.get(event)
    if spec is None or not _auditing[0]:
        return
    for i, j in spec:
        if i >= len(args):
            continue
        fd = args[j] if j is not None and j < len(args) else None
        if (hit := _guarded_path(args[i], fd)) is not None:
            _refuse(event, hit)


_os_open = os.open


def _guarded_open(path, flags, mode=0o777, *, dir_fd=None):
    """os.open, whose audit event leaves out dir_fd."""
    if dir_fd is not None and _auditing[0] and (hit := _guarded_path(path, dir_fd)) is not None:
        _refuse("os.open", hit)
    return _os_open(path, flags, mode, dir_fd=dir_fd)


from aitools_alerts import config  # noqa: E402 - after HOME is redirected

PASSWD_HOME = config.home  # the shipped resolver, for tests/test_home.py
SESSION = Guard()
CURRENT = [SESSION]  # the guard a refused file operation is recorded on
config.home = SESSION.home
BASELINE = fingerprint()
sys.addaudithook(_audit)  # Python offers no removal: _auditing turns it off
os.open = _guarded_open

__all__ = ["BASELINE", "ENV", "GUARDED", "Guard", "PASSWD_HOME", "REAL_HOME", "SESSION",
           "SESSION_HOME", "TEMP_EXEMPT", "exempt", "overlaps_guarded", "changed", "fingerprint", "under_real_home", "watching"]
