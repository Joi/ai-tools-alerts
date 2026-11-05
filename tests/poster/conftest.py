"""Poster tests never touch the network: any connect or name lookup raises, and the
transport's real ssh is replaced by one that raises."""

import socket

import pytest


def _no_network(*args, **kwargs):
    raise RuntimeError("network access in a poster test")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.setattr(socket.socket, "connect_ex", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(socket, "gethostbyname", _no_network)
    monkeypatch.setattr(socket, "gethostbyname_ex", _no_network)


def _no_ssh(*args, **kwargs):
    raise RuntimeError("real ssh in a poster test")


@pytest.fixture(autouse=True)
def no_real_ssh(monkeypatch):
    from aitools_alerts.poster import transport
    monkeypatch.setattr(transport, "_default_ssh", _no_ssh)
