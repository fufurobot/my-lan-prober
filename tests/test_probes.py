"""Tests for :mod:`my_lan_prober.probes`.

Ports the *tested* identification logic from ``tplogin-minimal.py``: raw HTTP
GET, TCP banner grab, Jupyter detection, and the per-port service table.
"""

from __future__ import annotations

import json

import pytest

from my_lan_prober.probes import (
    COMMON_PORTS,
    HTTP_PROBE_PORTS,
    ServiceIdentifier,
    probe_service,
    split_http_response,
)


# ---------------------------------------------------------------------------
# HTTP response splitting
# ---------------------------------------------------------------------------
def test_split_http_response_separates_head_and_body():
    raw = (
        "HTTP/1.1 302 Found\r\n"
        "server: TornadoServer/6.5.10\r\n"
        "content-length: 0\r\n"
        "\r\n"
    )

    status, head, body = split_http_response(raw)

    assert status == "HTTP/1.1 302 Found"
    assert "TornadoServer" in head
    assert body == ""


def test_split_http_response_handles_no_blank_line():
    status, head, body = split_http_response("HTTP/1.0 404 Not found")

    assert status == "HTTP/1.0 404 Not found"
    assert body == ""


def test_split_http_response_keeps_the_body():
    raw = "HTTP/1.1 200 OK\r\n\r\n<html>hi</html>"

    _status, _head, body = split_http_response(raw)

    assert body == "<html>hi</html>"


# ---------------------------------------------------------------------------
# Jupyter detection (the heuristics that mattered in practice)
# ---------------------------------------------------------------------------
def test_identifier_detects_jupyter_from_the_tornado_server_header():
    identifier = ServiceIdentifier(deep_probe=False)
    banner = (
        "HTTP/1.1 302 Found\n"
        "server: TornadoServer/6.5.10\n"
        "x-jupyterhub-version: 6.0.1\n"
        "location: /hub/\n"
    )

    assert identifier.identify(banner, 8000) == "JupyterHub"


def test_identifier_detects_jupyter_on_port_8888():
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify("HTTP/1.1 200 OK\n_xsrf: abc", 8888) == "Jupyter Server"


def test_identifier_detects_plain_jupyter_marker():
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify("HTTP/1.1 200 OK\nserver: jupyter_server/2.0", 8888) == (
        "Jupyter Server"
    )


def test_identifier_port_8888_without_jupyter_markers_is_http():
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify("HTTP/1.1 200 OK\nserver: nginx", 8888) == "HTTP (Alt)"


# ---------------------------------------------------------------------------
# Service identification table (values taken from tplogin-minimal.py)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("banner", "port", "expected"),
    [
        ("SSH-2.0-OpenSSH_10.5\r\n", 22, "SSH"),
        ("SSH-2.0-OpenSSH_9.0\r\n", 2222, "SSH (Alt)"),
        ("SSH-2.0-OpenSSH_9.0\r\n", 8022, "SSH (Termux)"),
        ("RFB 003.008\n", 5900, "VNC"),
        ("HTTP/1.1 200 OK\r\nserver: nginx\r\n", 80, "HTTP"),
        ("HTTP/1.1 200 OK\r\nserver: nginx\r\n", 443, "HTTPS"),
        ("HTTP/1.0 404 Not found\r\nconnection: close\r\n", 5800, "HTTP"),
        ("HTTP/1.1 301 Moved Permanently\r\nX-Powered-By: Express\r\n", 6099, "NapCatQQ WebUI"),
        ("HTTP/1.1 200 OK\r\nserver: caddy\r\n", 3080, "DeepSeek Harness"),
        ("HTTP/1.1 200 OK\r\nserver: nonebot2\r\n", 8080, "NoneBot2"),
        ("HTTP/1.1 200 OK\r\n", 11434, "Ollama (HTTP)"),
        ("HTTP/1.1 200 OK\r\n", 4000, "LiteLLM (HTTP)"),
        ("HTTP/1.1 200 OK\r\n", 30000, "SGLang (HTTP)"),
        ("HTTP/1.1 200 OK\r\n", 2358, "Judge0 (HTTP)"),
    ],
)
def test_identify_known_services(banner, port, expected):
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify(banner, port) == expected


def test_identify_returns_none_for_an_empty_banner():
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify(None, 22) is None
    assert identifier.identify("", 22) is None


def test_identify_returns_none_for_unrecognised_traffic():
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify("gibberish\r\n", 12345) is None


def test_identify_detects_http_generically_from_the_status_line():
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify("HTTP/1.1 200 OK\r\n", 9999) == "HTTP"


def test_novnc_on_5800_is_recognised():
    identifier = ServiceIdentifier(deep_probe=False)

    assert identifier.identify("HTTP/1.1 200 OK\r\nnovnc", 5800) == "noVNC"


# ---------------------------------------------------------------------------
# Deep probes (network-touching) are opt-in
# ---------------------------------------------------------------------------
def test_deep_probe_is_off_by_default_for_constructed_identifiers():
    """Without deep_probe the identifier must not touch the network."""
    identifier = ServiceIdentifier()

    assert identifier.identify("HTTP/1.1 200 OK\r\n", 4000) == "LiteLLM (HTTP)"


def test_ollama_deep_probe_uses_the_tags_endpoint(monkeypatch):
    identifier = ServiceIdentifier(deep_probe=True)
    calls = []

    def fake_http_get(ip, port, path="/", **kwargs):
        calls.append((ip, port, path))
        if path == "/api/tags":
            return "HTTP/1.1 200 OK", "", json.dumps({"models": [{"name": "x"}]})
        return None, None, None

    monkeypatch.setattr("my_lan_prober.probes._http_get", fake_http_get)

    result = identifier.identify("HTTP/1.1 200 OK\r\n", 11434, ip="10.0.0.5")

    assert result == "Ollama"
    assert ("10.0.0.5", 11434, "/api/tags") in calls


def test_litellm_deep_probe_checks_the_health_endpoint(monkeypatch):
    identifier = ServiceIdentifier(deep_probe=True)

    def fake_http_get(ip, port, path="/", **kwargs):
        if path == "/health":
            return "HTTP/1.1 200 OK", "x-litellm-version: 1.0", ""
        return None, None, None

    monkeypatch.setattr("my_lan_prober.probes._http_get", fake_http_get)

    assert identifier.identify("HTTP/1.1 200 OK\r\n", 4000, ip="10.0.0.5") == "LiteLLM"


def test_sglang_deep_probe_checks_health(monkeypatch):
    identifier = ServiceIdentifier(deep_probe=True)

    monkeypatch.setattr(
        "my_lan_prober.probes._http_get",
        lambda ip, port, path="/", **kw: ("HTTP/1.1 200 OK", "", "") if path == "/health" else (None, None, None),
    )

    assert identifier.identify("HTTP/1.1 200 OK\r\n", 30000, ip="10.0.0.5") == "SGLang"


def test_judge0_deep_probe_reads_about(monkeypatch):
    identifier = ServiceIdentifier(deep_probe=True)

    monkeypatch.setattr(
        "my_lan_prober.probes._http_get",
        lambda ip, port, path="/", **kw: ("HTTP/1.1 200 OK", "", "<h1>Judge0</h1>")
        if path == "/about"
        else (None, None, None),
    )

    assert identifier.identify("HTTP/1.1 200 OK\r\n", 2358, ip="10.0.0.5") == "Judge0"


def test_jupyter_status_endpoint_probe(monkeypatch):
    identifier = ServiceIdentifier(deep_probe=True)

    def fake_http_get(ip, port, path="/", **kwargs):
        if path == "/api/status":
            return "HTTP/1.1 200 OK", "", json.dumps({"kernels": [], "sessions": []})
        return None, None, None

    monkeypatch.setattr("my_lan_prober.probes._http_get", fake_http_get)

    assert identifier.identify("HTTP/1.1 200 OK\nserver: nginx", 8888, ip="10.0.0.5") == (
        "Jupyter Server"
    )


# ---------------------------------------------------------------------------
# Port constants (must match the tested original)
# ---------------------------------------------------------------------------
def test_common_ports_match_the_tested_original():
    assert COMMON_PORTS == [
        22, 80, 443, 2222, 8022, 5800, 5900, 8080, 6099, 3080,
        11434, 8000, 8501, 4000, 30000, 2358, 8888,
    ]


def test_http_probe_ports_are_a_subset_of_common_ports():
    assert set(HTTP_PROBE_PORTS) <= set(COMMON_PORTS)


def test_http_probe_ports_exclude_raw_banner_ports():
    assert 22 not in HTTP_PROBE_PORTS
    assert 5900 not in HTTP_PROBE_PORTS


# ---------------------------------------------------------------------------
# probe_service dispatch
# ---------------------------------------------------------------------------
def test_probe_service_uses_http_get_for_http_ports(monkeypatch):
    seen = {}

    def fake_http_get(ip, port, path="/", **kwargs):
        seen["port"] = port
        return "HTTP/1.1 200 OK", "server: x", "body"

    monkeypatch.setattr("my_lan_prober.probes._http_get", fake_http_get)

    result = probe_service("10.0.0.5", 80)

    assert seen["port"] == 80
    assert "HTTP/1.1 200 OK" in result


def test_probe_service_uses_a_banner_grab_for_other_ports(monkeypatch):
    seen = {}

    def fake_banner(ip, port, timeout=None):
        seen["port"] = port
        return "SSH-2.0-OpenSSH_10.5\r\n"

    monkeypatch.setattr("my_lan_prober.probes._probe_tcp_banner", fake_banner)

    assert probe_service("10.0.0.5", 22) == "SSH-2.0-OpenSSH_10.5\r\n"
    assert seen["port"] == 22


def test_probe_service_returns_none_when_the_port_is_closed(monkeypatch):
    monkeypatch.setattr(
        "my_lan_prober.probes._probe_tcp_banner", lambda ip, port, timeout=None: None
    )

    assert probe_service("10.0.0.5", 22) is None


def test_probe_service_truncates_large_bodies(monkeypatch):
    monkeypatch.setattr(
        "my_lan_prober.probes._http_get",
        lambda ip, port, path="/", **kw: ("HTTP/1.1 200 OK", "", "x" * 100_000),
    )

    result = probe_service("10.0.0.5", 80)

    assert len(result) < 20_000
