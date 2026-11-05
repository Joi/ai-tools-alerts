"""Poster tests never touch the network: any connect or name lookup raises."""

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
