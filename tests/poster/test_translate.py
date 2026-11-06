"""Curator translation (ai-tools-alerts#bq8v): a fake call, a fake mirror; no network, no secret."""

import http.client
import io
import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import main, translate
from mirror_helpers import Mirror, advisory
from test_main import CHANNELS, T0, FakeSSH, env, finding  # noqa: F401 - env is a fixture

SRC = ("CRITICAL: Invented critical for tests\nAffected: Claude Code <99.0.0. Fixed in 99.0.0.\n"
       "Source: https://example.invalid/advisory")


def ja_of(text):  # a translation that keeps every token
    return "重大: テスト\n" + " ".join(sorted(translate.tokens(text)))


class Call:
    def __init__(self, fn=ja_of):
        self.fn, self.texts = fn, []

    def __call__(self, system, text):
        assert system == translate.SYSTEM
        self.texts.append(text)
        return self.fn(text)


def test_translate_keeps_tokens_or_returns_none():
    assert translate.tokens(SRC + " GHSA-abcd-efgh-ijkl USN-1234-1 v2.0.1-rc1.") == {
        "99.0.0", "https://example.invalid/advisory", "GHSA-abcd-efgh-ijkl", "USN-1234-1", "v2.0.1-rc1"}
    assert translate.translate(SRC, call=Call()) == ja_of(SRC)
    for drop in ("99.0.0", "https://example.invalid/advisory"):
        assert translate.translate(SRC, call=Call(lambda t: ja_of(t).replace(drop, "X"))) is None
    assert translate.translate(SRC, call=Call(lambda t: "  ")) is None
    assert translate.tokens("9.9p1, 1.0rc1a and 22.") == {"9.9p1", "1.0rc1a", "22"}  # whole, never a prefix
    for out in ("11.2.30 https://v.example/fix", "1.2.3 https://v.example/fix-old"):
        assert translate.translate("1.2.3 https://v.example/fix", call=Call(lambda t: out)) is None
    for src, out in (("Fixed in 2.1.", "2.10 で修正"), ("CRITICAL: 3 packages", "重大: 13 パッケージ")):
        assert translate.translate(src, call=Call(lambda t: out)) is None
    assert translate.translate("x" * 6001, call=Call(lambda t: pytest.fail("called"))) is None


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_api_call_request_and_errors():
    seen = []

    def ok(req, timeout):
        seen.append((req, timeout))
        return Resp(json.dumps({"stop_reason": "end_turn", "content": [
            {"type": "thinking", "thinking": ""}, {"type": "text", "text": "訳"}]}).encode())
    assert translate.api_call("k-test", opener=ok)("sys", "hello") == "訳"
    req, timeout = seen[0]
    body = json.loads(req.data)
    assert timeout == 30 and req.full_url == translate.API_URL and req.get_header("X-api-key") == "k-test"
    assert body["model"] == "claude-sonnet-5-5" and "temperature" not in body and body["system"] == "sys"

    def status(code):
        def opener(req, timeout):
            raise urllib.error.HTTPError(req.full_url, code, "x", {}, io.BytesIO(b"k-test"))
        return opener
    for code in (401, 403):
        with pytest.raises(translate.AuthError):
            translate.api_call("k-test", opener=status(code))("s", "t")
    with pytest.raises(translate.CallError) as e:
        translate.api_call("k-test", opener=status(500))("s", "t")
    assert "k-test" not in str(e.value)
    refusal = lambda req, timeout: Resp(b'{"stop_reason": "refusal", "content": []}')  # noqa: E731
    assert translate.api_call("k-test", opener=refusal)("s", "t") == ""  # untranslated, never retried
    with pytest.raises(translate.CallError):
        translate.api_call("k-test", opener=lambda req, timeout: Resp(b"<html>"))("s", "t")

    def truncated(req, timeout):
        raise http.client.IncompleteRead(b"k-test")
    with pytest.raises(translate.CallError) as e:  # a protocol error counts toward MAX_TRIES
        translate.api_call("k-test", opener=truncated)("s", "t")
    assert str(e.value) == "unreachable"


def test_read_key_uses_a_throwaway_cache_and_never_argv(tmp_path, monkeypatch):
    helper = tmp_path / "secrets.sh"
    helper.write_text("")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "stale")
    calls = []

    def runner(argv, env, **kw):
        calls.append((argv, env))
        return subprocess.CompletedProcess(argv, 0, b"k-test\n", b"")
    assert translate.read_key(helper, runner=runner) == "k-test"
    argv, env = calls[0]
    assert "k-test" not in " ".join(argv) and "ANTHROPIC_API_KEY" not in env
    assert env["AITOOLS_ALERTS_SECRET_NAME"] == "ANTHROPIC_API_KEY" and not Path(env["SECRETS_CACHE_DIR"]).exists()
    fail = lambda argv, env, **kw: subprocess.CompletedProcess(argv, 1, b"k-test\n", b"")  # noqa: E731
    with pytest.raises(translate.CallError) as e:
        translate.read_key(helper, runner=fail)
    assert "k-test" not in str(e.value)


# ------------------------------------------------------------ the poster pass

def h(ch="feed"):
    return ("h", CHANNELS[ch])


@pytest.fixture
def cur(env):  # noqa: F811
    env.config = replace(env.config, translate_curator=True, secrets_helper=Path("/nonexistent/secrets.sh"))
    env.mirror = Mirror()

    def run(call=None, now=T0, **kw):
        return env.run(now=now, mirror_fetch=env.mirror.fetch, translate_call=call, root=env.mirror.root, **kw)
    env.trun = run
    return env


def root(m, sec=None, ch="feed", title="Invented critical for tests", at=T0 + 100):
    return m.post(sec or m.cur_sec, schema.render_post(advisory(title=title), SRC.replace(
        "Invented critical for tests", title)), created_at=at, tags=[h(ch)])


def test_config_off_reads_nothing(env):  # noqa: F811
    env.mirror = Mirror()
    root(env.mirror)
    code, summary, ssh = env.run(mirror_fetch=lambda url: pytest.fail("fetched"),
                                 translate_call=lambda s, t: pytest.fail("called"))
    assert code == 0 and " translate=off " in summary and ssh.ja == []


def test_curator_root_and_amendment_are_translated_once(cur):
    r = root(cur.mirror)
    fixed = [{"name": "Claude Code", "ecosystem": "claude-code", "affected": "<99.0.1", "fixed": "99.0.1"}]
    amend = cur.mirror.post(cur.mirror.cur_sec, cur.mirror.patch_text(products=fixed).replace("Update.", "Amended: x"),
                            created_at=T0 + 200, tags=[h(), ("e", r["id"], "", "root")])
    cur.mirror.post(cur.mirror.cur_sec, "retract\nwrong", created_at=T0 + 300, tags=[h(), ("e", r["id"], "", "root")])
    root(cur.mirror, sec=cur.mirror.bot_sec, title="A relay-bot post")  # templated by rd8t: no call
    call = Call()
    code, summary, ssh = cur.trun(call)
    assert code == 0 and " translate=ok " in summary and len(call.texts) == 2
    assert call.texts[0] == SRC  # a change only in the block still reaches the Japanese text:
    assert call.texts[1].startswith("Amended: x\n\nCRITICAL: ") and "Fixed in 99.0.1." in call.texts[1]
    (c1, to1, t1), (c2, to2, t2) = ssh.ja
    assert (c1, to1, c2, to2) == ("feed", r["id"], "feed", r["id"])
    assert t1 == "lang: ja\n\n" + ja_of(SRC) + "\n\n" + translate.MARK
    assert t2.startswith(f"lang: ja\nof: {amend['id']}\n\n")
    code, summary, ssh = cur.trun(Call(lambda t: pytest.fail("called twice")))
    assert code == 0 and ssh.ja == []


def test_mismatch_is_skipped_counted_and_never_retried(cur):
    root(cur.mirror)
    code, summary, ssh = cur.trun(Call(lambda t: "重大: テスト"))
    assert code == 0 and " untranslated=1 " in summary and ssh.ja == []
    code, summary, ssh = cur.trun(Call(lambda t: pytest.fail("retried")))
    assert " untranslated=0 " in summary


def test_auth_failure_holds_until_a_human_clears_it(cur, capsys):
    root(cur.mirror)

    def refused(system, text):
        raise translate.AuthError("http 401")
    code, summary, ssh = cur.trun(refused)
    assert code == 0 and " translate=held " in summary and ssh.ja == []
    assert "translate-clear-hold" in capsys.readouterr().err
    code, summary, _ = cur.trun(Call(lambda t: pytest.fail("called while held")))
    assert " translate=held " in summary
    assert main.clear_hold(cur.config)[0] == 0
    code, summary, ssh = cur.trun(Call())
    assert " translate=ok " in summary and len(ssh.ja) == 1


def test_budget_is_twenty_calls_a_utc_day(cur):
    for i in range(21):
        root(cur.mirror, title=f"Invented critical {i}", at=T0 + 100 + i)
    call = Call()
    cur.trun(call)
    assert len(call.texts) == 20
    cur.trun(call, now=T0 + 3600)
    assert len(call.texts) == 20  # same UTC day
    cur.trun(call, now=T0 + 86400)
    assert len(call.texts) == 21


def test_english_is_sent_and_saved_before_any_translation_work(cur):
    root(cur.mirror)
    cur.collector([finding()])
    order = []
    ssh = FakeSSH()

    def broken(system, text):
        outbox = json.loads(cur.config.state.read_text())["outbox"]
        order.append(("call", all(o["kind"] == "ja" for o in outbox)))  # only Japanese replies wait
        raise RuntimeError("boom")

    def fetch(url):
        order.append(("fetch", len(ssh.calls)))
        return cur.mirror.fetch(url)
    code, summary, _ = cur.run(ssh=ssh, mirror_fetch=fetch, translate_call=broken, root=cur.mirror.root)
    assert code == 0 and " roots=1 " in summary and " translate=error " in summary
    assert order[0] == ("fetch", 1) and order[-1] == ("call", True)  # English sent and saved first

    def slow(system, text):
        return translate.bounded(lambda: __import__("time").sleep(5), 0.1)
    code, summary, _ = cur.trun(slow)  # a stalled call ends at its deadline, counted as a failure
    assert code == 0 and " translate_failed=1 " in summary


def test_a_failing_event_is_given_up_after_three_runs(cur):
    root(cur.mirror)

    def down(system, text):
        raise translate.CallError("http 529")
    for _ in range(3):
        code, summary, _ = cur.trun(down)
        assert code == 0 and " translate_failed=1 " in summary
    assert " untranslated=1 " in summary
    assert " translate_failed=0 " in cur.trun(Call(lambda t: pytest.fail("retried")))[1]


def test_a_journaled_translation_is_never_requested_again(cur):
    r = root(cur.mirror)
    cur.trun(Call(), ssh=FakeSSH(ja=["fail"]))  # journaled, its send failed: waits in the journal
    tr = json.loads(cur.config.translate_state.read_text())
    tr["done"].pop(r["id"])  # as if the run stopped between the journal and this file
    cur.config.translate_state.write_text(json.dumps(tr))
    code, summary, ssh = cur.trun(Call(lambda t: pytest.fail("called again")))
    assert code == 0 and len(ssh.ja) == 1
    code, summary, ssh = cur.trun(Call(lambda t: pytest.fail("called after the send")))
    assert code == 0 and ssh.ja == []


def test_redirects_are_refused_and_translation_paths_checked(tmp_path):
    handlers = translate._OPENER.__self__.handlers  # the key is never re-sent to a Location
    assert [type(x) for x in handlers if isinstance(x, urllib.request.HTTPRedirectHandler)] == [translate._NoRedirect]
    assert translate._NoRedirect().redirect_request(urllib.request.Request("https://api.example.invalid/"),
                                                    io.BytesIO(), 302, "Found", {}, "http://elsewhere.invalid/") is None
    from aitools_alerts.poster import inputs
    for kev in ("l.json.translate.json", "l.json.mirror/events.json"):
        with pytest.raises(inputs.ConfigError):
            inputs.Config(ledger=tmp_path / "l.json", kev_cache=tmp_path / kev).check_paths()


def test_a_malformed_translate_state_fails_closed(cur):
    root(cur.mirror)
    for bad in ({}, {"hold": None, "day": None, "calls": -1, "done": {}}):
        cur.config.translate_state.parent.mkdir(parents=True, exist_ok=True)
        cur.config.translate_state.write_text(json.dumps(bad))
        code, summary, _ = cur.trun(Call(lambda t: pytest.fail("called")))
        assert code == 0 and " translate=state-error " in summary


def test_a_missing_key_is_never_charged_to_an_event(cur):
    root(cur.mirror)

    def no_key(helper):
        raise translate.CallError("api key unavailable")
    for _ in range(4):
        code, summary, _ = cur.run(mirror_fetch=cur.mirror.fetch, root=cur.mirror.root, read_key=no_key)
        assert code == 0 and " translate=key-error " in summary and " untranslated=0 " in summary
    assert " translate=ok " in cur.trun(Call())[1]


def test_a_translation_already_in_the_mirror_is_not_posted_again(cur):
    r = root(cur.mirror)
    cur.mirror.post(cur.mirror.bot_sec, "lang: ja\n\n既訳", created_at=T0 + 150, tags=[h(), ("e", r["id"], "", "root")])
    cur.mirror.post(cur.mirror.cur_sec, schema.render_post(advisory(), SRC), tags=[("h", "f" * 36)])  # no channel
    code, summary, ssh = cur.trun(Call(lambda t: pytest.fail("translated again")))
    assert code == 0 and ssh.ja == []
