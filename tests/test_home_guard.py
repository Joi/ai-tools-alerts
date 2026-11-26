"""The suite never resolves or changes the member's real home (ai-tools-alerts#3h9j)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import home_env
from aitools_alerts import config

needs_real_home = pytest.mark.skipif(home_env.REAL_HOME is None, reason="no password-database home")


def test_environment_points_at_the_session_home():
    assert Path(os.environ["HOME"]) == home_env.SESSION_HOME
    for k in home_env.XDG:
        assert Path(os.environ[k]).parent == home_env.SESSION_HOME
    assert not home_env.under_real_home(os.environ["HOME"])


def test_reader_paths_resolve_into_the_session_home():
    assert config.home() == home_env.SESSION_HOME
    for p in (config.config_dir(), config.state_dir(), config.config_path(), config.key_path()):
        assert home_env.SESSION_HOME in p.parents


@needs_real_home
@pytest.mark.parametrize("sub", ["", ".config/aitools-alerts", ".local/state/aitools-alerts/last_pull.json"])
def test_guard_refuses_the_real_home(sub):
    g = home_env.Guard()
    with pytest.raises(pytest.fail.Exception, match="real home"):
        g.check(home_env.REAL_HOME / sub)
    assert g.violations == [str(home_env.REAL_HOME / sub)]


def test_guard_refusal_survives_except_exception():
    """A CLI that catches Exception still lets the refusal through."""
    assert not issubclass(pytest.fail.Exception, Exception)


def test_guard_accepts_the_session_home_and_temp(tmp_path):
    g = home_env.Guard()
    assert g.check(home_env.SESSION_HOME / "x") == home_env.SESSION_HOME / "x"
    assert g.check(tmp_path / "home") == tmp_path / "home"
    assert g.violations == []


@needs_real_home
def test_a_temp_dir_that_holds_the_real_home_exempts_nothing(monkeypatch):
    monkeypatch.setattr(home_env, "TEMP_EXEMPT", None)
    assert home_env.under_real_home(home_env.REAL_HOME / ".config" / "aitools-alerts")
    assert not home_env.under_real_home(home_env.SESSION_HOME / ".config")


@needs_real_home
def test_temp_exempt_is_never_the_real_home_or_above_it():
    t = home_env.TEMP_EXEMPT
    assert t is None or not (t == home_env.REAL_HOME or t in home_env.REAL_HOME.parents)


TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent


def _inner(tmp_path, body, extra=None, env=None, inherit=False):
    """Run ``body`` as a test module in a child pytest that uses this suite's
    own tests/conftest.py, with ``extra`` watched like a real guarded directory."""
    (tmp_path / "conftest.py").write_text(
        f"import sys\nsys.path[:0] = [{str(TESTS)!r}, {str(REPO)!r}]\n"
        f"exec(compile(open({str(TESTS / 'conftest.py')!r}).read(), {str(TESTS / 'conftest.py')!r}, 'exec'))\n")
    (tmp_path / "test_inner.py").write_text(body)
    e = dict(os.environ) if inherit else {k: v for k, v in os.environ.items() if k not in home_env.ENV}
    if extra is not None:
        e["AITOOLS_ALERTS_TEST_EXTRA_GUARDED"] = str(extra)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:randomly",
                           "--rootdir", str(tmp_path), str(tmp_path)],
                          capture_output=True, text=True, timeout=300, cwd=tmp_path, env=e)


def _bait(tmp_path):
    b = tmp_path.parent / f"{tmp_path.name}-bait"
    b.mkdir()
    (b / "config.toml").write_text("mirror_url = 'https://example.invalid/'\n")
    return b


def test_teardown_fails_a_test_whose_subprocess_changed_a_guarded_directory(tmp_path):
    """A child that is not Python (or runs with -I) is outside the audit hook
    and the pwd redirect: the fingerprint names what it changed."""
    bait = _bait(tmp_path)
    r = _inner(tmp_path, f"""
import subprocess
def test_writes():
    subprocess.run(["sh", "-c", 'printf x > "$1/config.toml"', "sh", {str(bait)!r}], check=True)
def test_reads_only():
    pass
""", extra=bait)
    assert "2 passed, 1 error" in r.stdout, r.stdout + r.stderr
    assert "changed the real reader or poster files" in r.stdout and "config.toml" in r.stdout


def test_an_in_process_read_or_write_is_refused_before_it_happens(tmp_path):
    bait = _bait(tmp_path)
    link = tmp_path.parent / f"{tmp_path.name}-link"
    link.symlink_to(bait)
    r = _inner(tmp_path, f"""
import os, pytest
from pathlib import Path
from aitools_alerts import config, state
BAIT, LINK = Path({str(bait)!r}), Path({str(link)!r})
def test_explicit_config_path():
    config.load(BAIT / "config.toml")
def test_write_through_a_symlink():
    (LINK / "config.toml").write_text("trust_root_override = true")
def test_state_dir():
    state.State.load(dir=BAIT)
def test_listing():
    os.listdir(BAIT)
def test_elsewhere(tmp_path):
    (tmp_path / "x").write_text("ok")
""", extra=bait)
    assert "4 failed, 1 passed" in r.stdout, r.stdout + r.stderr
    assert r.stdout.count("tests never read or write the real reader") >= 4
    assert (bait / "config.toml").read_text() == "mirror_url = 'https://example.invalid/'\n"
    assert sorted(p.name for p in bait.iterdir()) == ["config.toml"]


@needs_real_home
def test_teardown_fails_a_test_whose_code_swallowed_the_refusal(tmp_path):
    r = _inner(tmp_path, f"""
from aitools_alerts import config
def test_swallows(monkeypatch):
    monkeypatch.setenv("HOME", {str(home_env.REAL_HOME)!r})
    try:
        config.state_dir()
    except BaseException:  # worse than any CLI: hides even pytest.fail
        pass
""")
    assert "1 passed, 1 error" in r.stdout, r.stdout + r.stderr
    assert "this test resolved the real home" in r.stdout


def test_the_session_fails_when_collection_changed_a_guarded_directory(tmp_path):
    bait = _bait(tmp_path)
    r = _inner(tmp_path, f"""
from pathlib import Path
import subprocess
subprocess.run(["sh", "-c", 'printf x > "$1/seen.json"', "sh", {str(bait)!r}], check=True)  # at import
def test_nothing():
    pass
""", extra=bait)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "1 passed" in r.stdout and "the test session touched the real home" in r.stdout
    assert "seen.json" in r.stdout


def test_the_session_fails_on_a_refused_access_during_collection(tmp_path):
    bait = _bait(tmp_path)
    r = _inner(tmp_path, f"""
from pathlib import Path
try:
    Path({str(bait)!r}, "config.toml").read_text()  # at import, and the refusal swallowed
except BaseException:
    pass
def test_nothing():
    pass
""", extra=bait)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "the test session touched the real home" in r.stdout and "config.toml" in r.stdout


def test_the_session_refuses_a_tmpdir_inside_a_guarded_directory(tmp_path):
    bait = _bait(tmp_path)
    before = sorted(p.name for p in bait.iterdir())
    r = _inner(tmp_path, "def test_nothing():\n    pass\n", extra=bait, env={"TMPDIR": str(bait / "tmp")})
    assert r.returncode != 0 and "overlaps the real" in r.stdout + r.stderr, r.stdout + r.stderr
    assert sorted(p.name for p in bait.iterdir()) == before


def _tree(tmp_path):
    d = tmp_path / "guarded"
    d.mkdir()
    (d / "config.toml").write_text("a = 1\n")
    return d


def test_fingerprint_sees_a_created_file(tmp_path):
    d = _tree(tmp_path)
    before = home_env.fingerprint([d])
    (d / "seen.json").write_text("{}")
    assert home_env.changed(before, home_env.fingerprint([d])) == [f"{d}: ., seen.json"]


def test_fingerprint_sees_an_empty_directory(tmp_path):
    d = _tree(tmp_path)
    before = home_env.fingerprint([d])
    (d / "sub").mkdir()
    assert "sub" in home_env.changed(before, home_env.fingerprint([d]))[0]


def test_fingerprint_sees_a_mode_change(tmp_path):
    d = _tree(tmp_path)
    before = home_env.fingerprint([d])
    (d / "config.toml").chmod(0o600)
    assert "config.toml" in home_env.changed(before, home_env.fingerprint([d]))[0]


def test_fingerprint_sees_a_same_size_change_with_the_mtime_put_back(tmp_path):
    d = _tree(tmp_path)
    f = d / "config.toml"
    st = f.stat()
    before = home_env.fingerprint([d])
    f.write_text("a = 2\n")
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert "config.toml" in home_env.changed(before, home_env.fingerprint([d]))[0]


def test_fingerprint_sees_a_directory_created_and_removed(tmp_path):
    d = tmp_path / "absent"
    before = home_env.fingerprint([d])
    assert before == {str(d): None}
    d.mkdir()
    assert home_env.changed(before, home_env.fingerprint([d])) == [f"{d} was created"]


def _child_home(python, env=None):
    code = "from aitools_alerts import config; print(config.home())"
    e = dict(os.environ)
    e.update(env or {})
    r = subprocess.run([str(python), "-c", code], capture_output=True, text=True, timeout=60, cwd=REPO, env=e)
    assert r.returncode == 0, r.stderr
    return Path(r.stdout.strip())


def test_a_python_child_takes_the_session_home():
    """A child reader started with the inherited environment resolves the
    session home from the password database, before any of its code runs."""
    assert _child_home(sys.executable) == home_env.SESSION_HOME


def test_a_python_child_with_the_user_site_off_takes_the_session_home():
    assert _child_home(sys.executable, {"PYTHONNOUSERSITE": "1"}) == home_env.SESSION_HOME


def test_a_nested_run_keeps_the_true_home_and_its_children_start_cleanly(tmp_path):
    """A pytest run inside this one (inheriting the redirect) still guards the
    true real home, and a Python child two generations down starts without a
    sitecustomize error."""
    r = _inner(tmp_path, f"""
import subprocess, sys
import home_env
def test_true_home():
    assert str(home_env.REAL_HOME) == {str(home_env.REAL_HOME)!r}
    assert home_env.SESSION_HOME != home_env.REAL_HOME
def test_grandchild():
    c = subprocess.run([sys.executable, "-c", "from aitools_alerts import config; print(config.home())"],
                       capture_output=True, text=True, cwd={str(REPO)!r})
    assert c.returncode == 0 and c.stderr == "", c.stderr
    assert c.stdout.strip() == str(home_env.SESSION_HOME)
""", inherit=True)
    assert "2 passed" in r.stdout, r.stdout + r.stderr


def test_a_python_child_in_a_venv_takes_the_session_home(tmp_path):
    import venv
    venv.EnvBuilder(with_pip=False, system_site_packages=False).create(tmp_path / "venv")
    assert _child_home(tmp_path / "venv" / "bin" / "python") == home_env.SESSION_HOME


@needs_real_home
def test_reader_code_that_reaches_the_real_home_fails(monkeypatch):
    """HOME set to the real home (as a test without the redirect would have it):
    the reader's state_dir() fails, and catching Exception does not hide it."""
    g = home_env.Guard()
    monkeypatch.setattr(config, "home", g.home)
    monkeypatch.setenv("HOME", str(home_env.REAL_HOME))
    with pytest.raises(pytest.fail.Exception, match="real home"):
        try:
            config.state_dir()
        except Exception:  # what a CLI command does
            pass
    assert g.violations == [str(home_env.REAL_HOME)]


@needs_real_home
def test_a_basetemp_under_the_home_is_a_test_root(monkeypatch, tmp_path):
    monkeypatch.setattr(home_env, "EXEMPT", [])
    monkeypatch.setattr(home_env, "TEMP_EXEMPT", None)
    bt = home_env.REAL_HOME / ".cache" / "aitools-alerts-basetemp-never-created"
    assert home_env.under_real_home(bt / "home")
    assert home_env.exempt(bt)
    assert not home_env.under_real_home(bt / "home")
    assert not bt.exists()


@needs_real_home
def test_a_basetemp_that_holds_the_home_or_a_guarded_dir_is_not_exempt(monkeypatch):
    monkeypatch.setattr(home_env, "EXEMPT", [])
    assert not home_env.exempt(home_env.REAL_HOME)
    assert not home_env.exempt(home_env.REAL_HOME.parent)
    assert not home_env.exempt(home_env.REAL_HOME / ".local" / "state" / "aitools-alerts" / "bt")
    assert home_env.EXEMPT == []
