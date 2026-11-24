"""The model-written headline and Who line (ai-tools-alerts#c6ak): a fake call; no network, no secret."""

import json
from dataclasses import replace

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import candidates, compose, inputs, main, rules, translate, wording
from pages import advisory_page
from test_main import GHSA, MAC, T0, env, finding  # noqa: F401 - env is a fixture

NAMES = {"Claude Code", "@anthropic-ai/claude-code"}
TITLE = "Remote Code Execution via Symlink Following in Claude Code"
TEXT = ("Claude Code validated that a target file path resided within the project working directory at "
        "permission-check time, but re-resolved the path at write time. This allowed an attacker who could "
        "write to the workspace to redirect a write outside the project. Fixed in 2.1.0.")
ADVISORY = TITLE + "\n" + TEXT
GOOD = wording.Wording("Claude Code writes files outside the project through a symlink",
                       "Anyone who runs Claude Code in a workspace an attacker can write to.")


def test_a_grounded_draft_passes():
    assert wording.check(GOOD, ADVISORY, NAMES) is None
    # a version the source states, the scoped package name, a possessive
    assert wording.check(wording.Wording("@anthropic-ai/claude-code before 2.1.0 writes outside the project",
                                         "Anyone whose workspace an attacker can write to."), ADVISORY, NAMES) is None


@pytest.mark.parametrize("headline, who, why", [
    ("x" * 91, GOOD.who, "length"),
    (GOOD.headline, "anyone " * 29, "length"),
    ("", GOOD.who, "length"),
    (GOOD.headline + "\nAffected: nothing", GOOD.who, "character"),
    ("Claude Code `rm` writes files", GOOD.who, "character"),
    ("Claude Code ~~~ writes files", GOOD.who, "character"),
    ("Claude Code writes files | anyone", GOOD.who, "character"),
    ("Claude Code writes files > project", GOOD.who, "character"),
    ("Claude Code writes files $HOME", GOOD.who, "character"),
    ("Claude Code writes files [link](x)", GOOD.who, "character"),
    ("Claude Code writes files ’outside’", GOOD.who, "character"),
    ("Claude Code writes files, see https://example.com", GOOD.who, "url"),
    ("Claude Code writes files, see www.example", GOOD.who, "url"),
    ("Claude Code writes files, see example.com", GOOD.who, "url"),
    ("Claude Code writes files javascript:alert('x')", GOOD.who, "url"),
    ("Claude Code writes files, run npm install claude", GOOD.who, "command"),
    ("Claude Code writes files with --dangerously-skip", GOOD.who, "command"),
    ("Claude Code writes files; curl the project", GOOD.who, "command"),
    (GOOD.headline, "Anyone who runs printf compromised to the project.", "command"),
    (GOOD.headline, "Users of Pages are exposed.", "name"),  # a vocabulary word is no name
    (GOOD.headline, "Run install file directory.", "name"),  # a capital the source does not write
    (GOOD.headline, "run install file directory.", "subject"),  # an instruction, not who is exposed
    (GOOD.headline, "Anyone; users need not upgrade.", "name"),  # no negation or modal from the vocabulary
    ("the Claude Code project writes files", GOOD.who, "subject"),
    ("Claude Code writes files to/evil-c2.com", GOOD.who, "url"),
    ("Claude Code writes files to //evil-c2", GOOD.who, "url"),
    ("Claude Code writes files, see example.com,example.org", GOOD.who, "url"),
    ("Claude Code writes files, see ghsa-abcd-efgh-ijkl", GOOD.who, "id"),
    ("Claude Code writes files after cargo install claude", GOOD.who, "command"),
    ("Claude Code writes files '--yes'", GOOD.who, "command"),
    (GOOD.headline, "Users running firefox are exposed.", "name"),
    (GOOD.headline, "Firefox users are exposed.", "name"),
    ("Claude Code writes files outside Kubernetes", GOOD.who, "name"),
    ("Claude Code before 2.1.1 writes files", GOOD.who, "name"),
    ("Claude Code CVE-2026-1234 writes files", GOOD.who, "id"),
    ("Claude Code GHSA-abcd-efgh-ijkl writes files", GOOD.who, "id"),
    (GOOD.headline, "Ask @someone about the project.", "mention"),
    (GOOD.headline, "Anyone who writes to attacker@project.", "mention"),
])
def test_each_refusal(headline, who, why):
    # what the source states is still refused when it is an id, a URL or a command
    advisory = ADVISORY + (" CVE-2026-1234 GHSA-abcd-efgh-ijkl ghsa-abcd-efgh-ijkl evil-c2.com example.com,example.org"
                           " printf cargo need")
    assert wording.check(wording.Wording(headline, who), advisory, NAMES) == why


def test_a_fleet_host_or_local_path_is_refused(monkeypatch):
    monkeypatch.setattr(candidates, "FLEET_HOSTS", frozenset({"buildhost"}))
    assert wording.check(wording.Wording("Claude Code on buildhost writes files", GOOD.who),
                         ADVISORY + " buildhost", NAMES) == "guard"


@pytest.mark.parametrize("answer", [
    None, "", "Headline: x", "Who: y\nHeadline: x", "Headline: x\nWho: y\nmore", "Headline: \nWho: y",
    "headline: x\nwho: y",
])
def test_parse_takes_exactly_two_labelled_lines(answer):
    assert wording.parse(answer) is None


def test_parse_reads_the_two_lines():
    assert wording.parse(f"  Headline: {GOOD.headline}\nWho: {GOOD.who}\n") == GOOD


class Scope:
    name, package, ecosystem, components = "Claude Code", "npm:@anthropic-ai/claude-code", "npm", ()


def cand(**kw):
    c = candidates.Candidate(id="GHSA-abcd-efgh-ijkl", aliases=(), product_text="Claude Code",
                             advisory_severity=None, local_level_hint=None, exploited=False, trojanized=False,
                             injection_exec=False, fixed="2.1.0", affected="<2.1.0",
                             sources=(candidates.Source(GHSA, None),), observed_at=None,
                             source_title=TITLE, source_text=TEXT)
    return replace(c, **kw)


def answer(w=GOOD):
    return f"Headline: {w.headline}\nWho: {w.who}"


def test_draft_outcomes():
    seen = []

    def call(system, text):
        seen.append((system, text))
        return answer()
    assert wording.draft(cand(), Scope, call=call) == (GOOD, "ok")
    assert seen[0][0] == wording.SYSTEM and TEXT in seen[0][1] and "@anthropic-ai/claude-code" in seen[0][1]
    assert wording.draft(cand(), Scope, call=lambda s, t: "nonsense") == (None, "refused")
    assert wording.draft(cand(), Scope, call=lambda s, t: answer(replace(GOOD, who="Firefox users."))) == \
        (None, "refused")
    for exc in (translate.CallError("http 500"), RuntimeError("x"), ValueError("x")):
        def boom(s, t, exc=exc):
            raise exc
        assert wording.draft(cand(), Scope, call=boom) == (None, "failed")

    def auth(s, t):
        raise translate.AuthError("http 401")
    with pytest.raises(translate.AuthError):
        wording.draft(cand(), Scope, call=auth)
    assert not wording.usable(cand(source_title=None, source_text=None))


def test_root_post_wording_is_body_text_only():
    plain, adv = compose.root_post(cand(), ("high", None), Scope, posted_at=T0)
    worded, adv2 = compose.root_post(cand(), ("high", None), Scope, posted_at=T0, wording=GOOD)
    lines = worded.split("\n")
    assert lines[0] == f"HIGH: {GOOD.headline}" and lines[1] == f"Who: {GOOD.who}"
    assert plain.split("\n")[0].startswith("HIGH: Remote Code Execution") and "\nWho: " not in plain
    assert adv2 == adv and schema.parse_post(worded) == schema.parse_post(plain) == adv  # the block is the same
    assert adv.title == "Claude Code: security advisory (GHSA-abcd-efgh-ijkl)"  # the template form, with the id
    assert worded.split("\n")[2:] == plain.split("\n")[1:]  # every other line unchanged
    ja = compose.root_post_ja(adv, None, False, TITLE, wording=GOOD)
    assert ja.split("\n")[0] == f"重要: {GOOD.headline}" and "Who" not in ja


def test_a_headline_that_would_be_cut_is_not_used():
    long = replace(GOOD, headline="Claude Code writes files outside the project through a symlink "
                                  "in the workspace directory")  # fits alone, not after the head
    assert len("CRITICAL: ") + len(long.headline) > compose.HEADLINE_MAX >= len(long.headline)
    assert wording.check(long, ADVISORY + " directory", NAMES) is None
    assert not compose.worded(compose.head_of("critical", "GHSA-abcd-efgh-ijkl"), "Claude Code", long)
    text, _ = compose.root_post(cand(), ("high", None), Scope, posted_at=T0, wording=long)
    assert "Who:" not in text and text.split("\n")[0] == f"HIGH: {TITLE}"


def test_the_vendor_page_description_and_kev_text_reach_the_candidate():
    page = rules.read_advisory(advisory_page("GHSA-abcd-efgh-ijkl", description=TEXT))
    assert page.description == TEXT
    out = candidates.from_kev({"vulnerabilities": [{
        "cveID": "CVE-2026-0001", "vendorProject": "Anthropic", "product": "Claude Code", "dateAdded": "2026-11-05",
        "vulnerabilityName": "Claude Code flaw", "shortDescription": "Claude Code lets an attacker run code."}]},
        "2026-11-01")
    assert out[0].source_text == "Claude Code lets an attacker run code."


def test_source_text_is_never_kept_and_old_state_loads():
    d = cand().to_dict()
    assert "source_text" not in d and inputs.candidate_from(d).source_text is None  # a deferred one reads it again


# ------------------------------------------------------------------ the run


class Call:
    def __init__(self, fn=lambda s, t: answer()):
        self.fn, self.texts = fn, []

    def __call__(self, system, text):
        assert system == wording.SYSTEM
        self.texts.append(text)
        return self.fn(system, text)


@pytest.fixture
def word(env):  # noqa: F811
    env.config = replace(env.config, model_wording=True)
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", title=TITLE, description=TEXT, severity="High",
                                      affected="< 2.1.0", patched="2.1.0"))
    return env


def test_off_calls_nothing_and_the_summary_is_unchanged(env, monkeypatch):  # noqa: F811
    monkeypatch.setattr(translate, "read_key", lambda *a, **k: pytest.fail("key read"))
    monkeypatch.setattr(translate, "api_call", lambda *a, **k: pytest.fail("call made"))
    env.collector([finding()])
    code, summary, relay = env.run()
    assert code == 0 and "roots=1" in summary and "\nWho: " not in relay.calls[0][2]
    assert summary.endswith(" translate=off inputs=kev:ok,collector:ok,heartbeat:0/0")  # nothing after it


def test_on_a_high_posts_the_model_headline_and_who_line(word):
    word.collector([finding()])
    call = Call()
    code, summary, relay = word.run(wording_call=call)
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=1/1")
    assert relay.calls[0][2].startswith(f"HIGH: {GOOD.headline}\nWho: {GOOD.who}\n")
    assert len(call.texts) == 1 and TEXT in call.texts[0]
    assert relay.ja and relay.ja[0][2].split("\n")[2] == f"重要: {GOOD.headline}" and "Who:" not in relay.ja[0][2]


@pytest.mark.parametrize("fn, status", [
    (lambda s, t: answer(replace(GOOD, who="Firefox users are exposed.")), "0/1"),
    (lambda s, t: (_ for _ in ()).throw(translate.CallError("http 529")), "0/1"),
    (lambda s, t: (_ for _ in ()).throw(KeyError("x")), "0/1"),
])
def test_a_refusal_or_error_posts_the_source_title(word, fn, status):
    word.collector([finding()])
    code, summary, relay = word.run(wording_call=Call(fn))
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=" + status)
    assert relay.calls[0][2].startswith(f"HIGH: {TITLE}\nAffected: ")


def test_an_unreadable_key_posts_the_source_title(word):
    word.collector([finding()])  # the helper path in the test config does not exist
    code, summary, relay = word.run()
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=key-error")
    assert relay.calls[0][2].startswith(f"HIGH: {TITLE}\n")


def test_an_auth_failure_holds_until_cleared_and_posts_go_on(word):
    def refused(s, t):
        raise translate.AuthError("http 401")
    word.collector([finding()])
    code, summary, relay = word.run(wording_call=Call(refused))
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=held")
    assert relay.calls[0][2].startswith(f"HIGH: {TITLE}\n")
    tr = json.loads(word.config.translate_state.read_text())
    assert tr["hold"]["why"] == "wording: http 401"
    word.collector([finding(fid="GHSA-mnop-qrst-uvwx")])
    code, summary, relay = word.run(wording_call=lambda s, t: pytest.fail("called while held"))
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=held")
    assert main.clear_hold(word.config)[0] == 0
    assert json.loads(word.config.translate_state.read_text())["hold"] is None


def test_an_unreadable_translate_state_or_failed_hold_write_never_stops_a_post(word, monkeypatch):
    word.config.translate_state.parent.mkdir(parents=True, exist_ok=True)
    word.config.translate_state.write_text("{not json")
    word.collector([finding()])
    code, summary, relay = word.run(wording_call=lambda s, t: pytest.fail("called"))
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=error")
    word.config.translate_state.unlink()
    real = inputs.write_json

    def write_json(path, data):
        if path == word.config.translate_state:
            raise OSError("read-only file system")  # the hold cannot be written
        return real(path, data)
    monkeypatch.setattr(inputs, "write_json", write_json)

    def refused(s, t):
        raise translate.AuthError("http 403")
    word.collector([finding(fid="GHSA-mnop-qrst-uvwx")])
    code, summary, relay = word.run(wording_call=Call(refused))
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=held")


def test_a_notice_makes_no_call_and_a_run_makes_at_most_four(word, monkeypatch):
    word.collector([MAC])
    code, summary, _ = word.run(wording_call=lambda s, t: pytest.fail("called for a notice"))
    assert code == 0 and "held=1" in summary
    call = Call()
    monkeypatch.setattr(wording, "check", lambda *a: None)  # every draft accepted: counting calls only
    ids = [f"GHSA-{a}{a}{a}{a}-efgh-ijkl" for a in "mnpqrs"]
    word.collector([finding(fid=i, fixed=f"2.1.{k}") for k, i in enumerate(ids)])  # six fixes: six roots
    code, summary, relay = word.run(wording_call=call)
    assert code == 0 and "roots=6" in summary and len(call.texts) == main.WORDING_CALLS


def test_a_copy_to_a_new_channel_is_worded_too(word):
    """A thread raised to critical posts its root again in the critical channel: a post, so worded."""
    from test_main import kev_item
    word.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", title=TITLE, description=TEXT, severity="High",
                                       affected="< 2.1.0", patched="2.1.0", cve="CVE-2026-0001"))
    word.collector([finding(fid="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",), affected="<2.1.0")])
    call = Call()
    assert "roots=1" in word.run(wording_call=call)[1]
    word.collector([])
    word.kev.catalog = {"vulnerabilities": [{**kev_item(), "vulnerabilityName": TITLE, "shortDescription": TEXT}]}
    code, summary, relay = word.run(now=T0 + 3600, wording_call=call)
    assert code == 0 and "copies=1" in summary and relay.calls[0][0] == "critical", summary
    assert relay.calls[0][2].startswith(f"CRITICAL: {GOOD.headline}\nWho: {GOOD.who}\n")
    assert len(call.texts) == 2


@pytest.mark.parametrize("state", [{}, {"hold": None, "day": None, "calls": -1, "done": {}}])
def test_a_translate_state_translation_would_refuse_means_no_call_and_is_not_rewritten(word, state):
    word.config.translate_state.parent.mkdir(parents=True, exist_ok=True)
    word.config.translate_state.write_text(json.dumps(state))
    word.collector([finding()])
    code, summary, relay = word.run(wording_call=lambda s, t: pytest.fail("called"))
    assert code == 0 and "roots=1" in summary and summary.endswith(" wording=error")
    assert json.loads(word.config.translate_state.read_text()) == state


def test_a_refused_key_stops_every_call_this_run_even_when_the_hold_cannot_be_written(word, monkeypatch):
    real = inputs.write_json

    def write_json(path, data):
        if path == word.config.translate_state:
            raise OSError("read-only file system")
        return real(path, data)
    monkeypatch.setattr(inputs, "write_json", write_json)
    word.config = replace(word.config, translate_curator=True)
    calls = []

    def refused(s, t):
        calls.append(t)
        raise translate.AuthError("http 401")
    word.collector([finding(fid=i, fixed=f"2.1.{k}") for k, i in enumerate(["GHSA-mmmm-efgh-ijkl",
                                                                         "GHSA-nnnn-efgh-ijkl"])])
    code, summary, relay = word.run(wording_call=Call(refused), translate_call=lambda s, t: pytest.fail("translated"))
    assert code == 0 and "roots=2" in summary and " translate=held " in summary and summary.endswith(" wording=held")
    assert len(calls) == 1
