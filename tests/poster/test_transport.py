"""The relay transport (Task B4): one ssh call to the VM's buzz-send wrapper per post.

Every test passes a fake ``ssh`` callable; no test ever spawns ssh.
"""

import json
import shlex
import subprocess

import pytest

from aitools_alerts.poster import transport

FEED = "599adb9f-4f9f-4b19-aee3-66667c3293e8"
ROOT = "ab" * 32
EID = "cd" * 32


class FakeSSH:
    def __init__(self, rc=0, stdout=b"", stderr=b"", raise_=None):
        self.calls = []
        self.rc, self.stdout, self.stderr, self.raise_ = rc, stdout, stderr, raise_

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.raise_ is not None:
            raise self.raise_
        return subprocess.CompletedProcess(argv, self.rc, self.stdout, self.stderr)


def accepted(eid=EID, ok=True):
    return json.dumps({"accepted": ok, "event_id": eid, "mention_pubkeys": [], "message": ""}).encode()


def test_argv_is_ssh_host_and_one_joined_remote_command():
    ssh = FakeSSH(stdout=accepted())
    transport.send(FEED, "hello $(rm -rf ~) `x`", ssh=ssh)
    (argv, kw), = ssh.calls
    assert argv[:-1] == ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                         "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
                         "-o", "RequestTTY=no", "-o", "RemoteCommand=none",
                         "--", "relay-vm.example"]
    assert shlex.split(argv[-1]) == ["/home/relay/bin/buzz-send", "messages", "send",
                                     "--channel", FEED, "--content", "-"]
    assert kw["input"] == "hello $(rm -rf ~) `x`".encode()
    assert kw["timeout"] == transport.TIMEOUT and kw["capture_output"] is True


def test_reply_to_adds_flag():
    ssh = FakeSSH(stdout=accepted())
    transport.send(FEED, "a reply", reply_to=ROOT, ssh=ssh)
    assert shlex.split(ssh.calls[0][0][-1])[-2:] == ["--reply-to", ROOT]


def test_no_key_material_on_argv():
    ssh = FakeSSH(stdout=accepted())
    transport.send(FEED, "x", reply_to=ROOT, ssh=ssh)
    flat = " ".join(ssh.calls[0][0])
    for bad in ("nsec", "--private-key", "--relay", ".buzz-keys", "PRIVATE_KEY"):
        assert bad not in flat


@pytest.mark.parametrize("channel, content, reply_to", [
    ("not-a-uuid", "x", None),
    (FEED.upper(), "x", None),
    (FEED, "x", "ab" * 31),
    (FEED, "x", ROOT.upper()),
    (FEED, "", None),
    (FEED, "a\x00b", None),
    (FEED, b"bytes", None),
    (FEED, "x" * (transport.MAX_CONTENT + 1), None),
])
def test_bad_arguments_raise_before_ssh(channel, content, reply_to):
    ssh = FakeSSH(stdout=accepted())
    with pytest.raises(ValueError):
        transport.send(channel, content, reply_to=reply_to, ssh=ssh)
    assert ssh.calls == []


def test_success_parses_event_id():
    r = transport.send(FEED, "x", ssh=FakeSSH(stdout=accepted() + b"\n"))
    assert (r.ok, r.event_id, r.exit_code, r.outcome) == (True, EID, 0, "ok")


def test_exit0_not_accepted_is_failed():
    r = transport.send(FEED, "x", ssh=FakeSSH(stdout=accepted(ok=False)))
    assert (r.ok, r.event_id, r.outcome) == (False, None, "failed")


@pytest.mark.parametrize("stdout", [b"", b"not json", b"[]", accepted(eid="zz"), accepted(eid="CD" * 32),
                                    accepted(eid="c" * 63),
                                    json.dumps({"accepted": True}).encode(), b"\xff\xfe"])
def test_exit0_garbage_is_unknown(stdout):
    r = transport.send(FEED, "x", ssh=FakeSSH(stdout=stdout))
    assert (r.ok, r.event_id, r.outcome) == (False, None, "unknown")


@pytest.mark.parametrize("rc", [1, 3, 4, 5, 126, 127])
def test_cli_exit_codes_are_failed(rc):
    r = transport.send(FEED, "x", ssh=FakeSSH(rc=rc, stderr=b"auth error: denied"))
    assert (r.ok, r.exit_code, r.outcome) == (False, rc, "failed")


@pytest.mark.parametrize("rc", [-9, -15, 6, 130, 137])
def test_other_exits_are_unknown(rc):
    r = transport.send(FEED, "x", ssh=FakeSSH(rc=rc))
    assert (r.ok, r.exit_code, r.outcome) == (False, rc, "unknown")


def cli_error(category, message):
    return json.dumps({"error": category, "message": message, "retryable": False}).encode() + b"\n"


@pytest.mark.parametrize("stderr", [
    cli_error("delivery_unknown", "delivery unknown: timed out after send"),
    b"", b"something odd", b"network error: error sending request",  # free text never decides
    cli_error("relay_error", "relay error 503: unavailable"),
    cli_error("relay_error", "relay error 503: upstream network error"),
    cli_error("relay_error", "relay error 408: timeout"),
    cli_error("network_error", "network error: reset") + cli_error("delivery_unknown", "delivery unknown: x"),
])
def test_exit2_delivery_unknown_is_unknown(stderr):
    assert transport.send(FEED, "x", ssh=FakeSSH(rc=2, stderr=stderr)).outcome == "unknown"


@pytest.mark.parametrize("stderr", [
    cli_error("network_error", "network error: error sending request: connection refused"),
    b"warning: retrying\n" + cli_error("relay_error", "relay error 400: bad event"),
])
def test_exit2_network_or_4xx_is_failed(stderr):
    assert transport.send(FEED, "x", ssh=FakeSSH(rc=2, stderr=stderr)).outcome == "failed"


@pytest.mark.parametrize("stderr", [
    b"ssh: connect to host relay-vm.example port 22: Connection refused",
    b"ssh: Could not resolve hostname relay-vm.example: nodename nor servname provided",
    b"relay@relay-vm.example: Permission denied (publickey).",
    b"Host key verification failed.",
])
def test_ssh_connect_failure_is_failed(stderr):
    assert transport.send(FEED, "x", ssh=FakeSSH(rc=255, stderr=stderr)).outcome == "failed"


@pytest.mark.parametrize("stderr", [b"Connection to relay-vm.example closed by remote host.",
                                    b"client_loop: send disconnect: Broken pipe", b""])
def test_ssh_drop_is_unknown(stderr):
    assert transport.send(FEED, "x", ssh=FakeSSH(rc=255, stderr=stderr)).outcome == "unknown"


def test_timeout_is_unknown():
    r = transport.send(FEED, "x", ssh=FakeSSH(raise_=subprocess.TimeoutExpired("ssh", 120)))
    assert (r.ok, r.exit_code, r.outcome) == (False, None, "unknown")


def test_oserror_is_failed():
    r = transport.send(FEED, "x", ssh=FakeSSH(raise_=FileNotFoundError("ssh")))
    assert (r.ok, r.exit_code, r.outcome) == (False, None, "failed")


def test_stderr_is_capped_and_decoded():
    r = transport.send(FEED, "x", ssh=FakeSSH(rc=4, stderr=b"\xff" + b"e" * 5000))
    assert len(r.stderr) == transport.MAX_STDERR and r.stderr.endswith("e")


def test_duplicate_answer_is_unknown():
    body = json.dumps({"accepted": False, "event_id": EID, "message": "duplicate: already have this event"})
    assert transport.send(FEED, "x", ssh=FakeSSH(stdout=body.encode())).outcome == "unknown"


def test_remote_connect_text_after_a_drop_is_unknown():
    stderr = (b"network error: error sending request: connection refused (retrying)\n"
              b"Connection to relay-vm.example closed by remote host.\n")
    assert transport.send(FEED, "x", ssh=FakeSSH(rc=255, stderr=stderr)).outcome == "unknown"


def test_ssh_message_with_remote_output_is_unknown():
    stderr = b"ssh: connect to host relay-vm.example port 22: Connection refused\n"
    assert transport.send(FEED, "x", ssh=FakeSSH(rc=255, stdout=b"{", stderr=stderr)).outcome == "unknown"


def test_classification_reads_the_whole_stderr():
    # The whole line is a network_error (failed); its last 2000 characters alone are not
    # JSON (unknown), so a classifier that saw only the stored copy would say unknown.
    stderr = cli_error("network_error", "network error: connection refused " + "x" * 2100)
    r = transport.send(FEED, "x", ssh=FakeSSH(rc=2, stderr=stderr))
    assert r.outcome == "failed" and len(r.stderr) == transport.MAX_STDERR
    assert transport._classify(2, b"", r.stderr)[0] == "unknown"


def test_host_option_injection_refused():
    ssh = FakeSSH(stdout=accepted())
    with pytest.raises(ValueError):
        transport.send(FEED, "x", ssh=ssh, host="-oProxyCommand=evil")
    assert ssh.calls == []


def test_default_ssh_is_blocked_in_tests():
    with pytest.raises(RuntimeError, match="real ssh"):
        transport.send(FEED, "x")
