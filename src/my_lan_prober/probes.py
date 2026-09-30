"""Port probing and service identification.

This is a faithful port of the *tested* logic from ``tplogin-minimal.py``,
restructured so the network-touching parts (``_http_get``,
``_probe_tcp_banner``) are small, mockable functions and the identification
rules live in a :class:`ServiceIdentifier` with an explicit ``deep_probe``
switch.

``deep_probe=False`` guarantees no network access during identification.
"""

from __future__ import annotations

import json
import logging
import platform
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

log = logging.getLogger(__name__)

__all__ = [
    "COMMON_PORTS",
    "HTTP_PROBE_PORTS",
    "DEFAULT_PORT_TIMEOUT",
    "HTTP_TIMEOUT",
    "PING_TIMEOUT",
    "split_http_response",
    "icmp_ping",
    "probe_service",
    "ServiceIdentifier",
]

# Hosts probed directly, before the router lease table is consulted.
RESOLVE_HOSTS: List[str] = ["tplogin.cn", "localhost"]

#: Ports probed for every discovered host (matches the tested original).
COMMON_PORTS: List[int] = [
    22,
    80,
    443,
    2222,
    8022,
    5800,
    5900,
    8080,
    6099,
    3080,
    11434,
    8000,
    8501,
    4000,
    30000,
    2358,
    8888,
]

#: Ports where an HTTP GET beats a raw banner grab.
HTTP_PROBE_PORTS: List[int] = [
    80,
    443,
    5800,
    8080,
    6099,
    3080,
    8000,
    8888,
    4000,
    30000,
    2358,
    11434,
]

DEFAULT_PORT_TIMEOUT: float = 0.1
HTTP_TIMEOUT: int = 5
PING_TIMEOUT: int = 2

#: Cap on how much of a response body is retained.
MAX_BODY_BYTES = 4096


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------
def icmp_ping(host: str, timeout: int = PING_TIMEOUT) -> bool:
    """Ping ``host`` with the platform's own ``ping`` command."""
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
            shell=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# ---------------------------------------------------------------------------
# Raw HTTP
# ---------------------------------------------------------------------------
def split_http_response(raw: str) -> Tuple[str, str, str]:
    """Split a raw HTTP response into ``(status_line, head, body)``."""
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 1:
        # Tolerate servers that use bare LF line endings.
        parts = raw.split("\n\n", 1)
    head = parts[0] if parts else ""
    body = parts[1] if len(parts) > 1 else ""
    lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
    return (lines[0] if lines else ""), head, body


def _http_get(
    ip: str,
    port: int,
    path: str = "/",
    timeout: int = HTTP_TIMEOUT,
    connect_timeout: Optional[float] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Minimal raw HTTP GET.  Returns ``(status, head, body)`` or Nones."""
    effective_connect_timeout = DEFAULT_PORT_TIMEOUT if connect_timeout is None else connect_timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(effective_connect_timeout)
            sock.connect((ip, port))
            sock.settimeout(timeout)

            request = f"GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n"
            for key, value in (extra_headers or {}).items():
                request += f"{key}: {value}\r\n"
            request += "\r\n"

            sock.sendall(request.encode("utf-8", errors="ignore"))

            raw = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                raw += chunk
    except (TimeoutError, ConnectionRefusedError, OSError):
        return None, None, None

    text = raw.decode("utf-8", errors="ignore")
    status, head, body = split_http_response(text)
    return status, head, body[:MAX_BODY_BYTES]


def _probe_tcp_banner(ip: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
    """Connect and read whatever the peer volunteers first."""
    effective_timeout = DEFAULT_PORT_TIMEOUT if timeout is None else timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(effective_timeout)
            sock.connect((ip, port))
            return sock.recv(1024).decode("utf-8", errors="ignore")
    except (TimeoutError, ConnectionRefusedError, OSError):
        return None


def probe_service(ip: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
    """Identify what is listening on ``ip:port``, or ``None`` if closed."""
    effective_timeout = DEFAULT_PORT_TIMEOUT if timeout is None else timeout

    if port in HTTP_PROBE_PORTS:
        status, head, body = _http_get(ip, port, connect_timeout=effective_timeout)
        if status is None:
            return None
        return f"{status}\n{head}\n{body[:MAX_BODY_BYTES]}"

    return _probe_tcp_banner(ip, port, timeout=effective_timeout)


def _check_openai_compatible(ip: str, port: int, timeout: int = HTTP_TIMEOUT) -> bool:
    """Whether ``/v1/models`` answers with an OpenAI-style model list."""
    try:
        from openai import OpenAI

        client = OpenAI(base_url=f"http://{ip}:{port}/v1", api_key="not-needed")
        models = client.models.list()
        return hasattr(models, "data") and len(models.data) > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------
class ServiceIdentifier:
    """Assign a service name to a banner / HTTP response.

    ``deep_probe=True`` enables the extra endpoint checks (``/api/status``,
    ``/health``, ``/v1/models``, …) that the tested original performed.
    With ``deep_probe=False`` this is a pure, offline function.
    """

    JUPYTER_MARKERS = (
        "jupyter",
        "jupyterlab",
        "jupyter_server",
        "_xsrf",
        "lab?",
        "tree?",
        "/static/lab/",
        "notebook",
    )

    def __init__(self, *, deep_probe: bool = False, http_timeout: int = HTTP_TIMEOUT) -> None:
        self.deep_probe = deep_probe
        self.http_timeout = http_timeout

    # -- public --------------------------------------------------------
    def identify(self, banner: Optional[str], port: int, ip: Optional[str] = None) -> Optional[str]:
        if banner is None or (isinstance(banner, float) and pd.isnull(banner)):
            return None
        if not banner:
            return None

        lower = banner.lower()

        if port == 8888:
            if ip and self._is_jupyter(ip, port, banner):
                return "Jupyter Server"
            return "HTTP (Alt)"

        if "ssh-" in lower:
            if port == 8022:
                return "SSH (Termux)"
            if port == 2222:
                return "SSH (Alt)"
            return "SSH"

        if "rfb" in lower:
            return "VNC"

        if port == 11434:
            if "ollama" in lower:
                return "Ollama"
            if ip and self.deep_probe and self._has_models(ip, 11434, "/api/tags"):
                return "Ollama"
            return "Ollama (HTTP)"

        if port == 4000:
            if "x-litellm" in lower or "litellm" in lower:
                return "LiteLLM"
            if ip and self.deep_probe:
                _status, headers, _body = _http_get(
                    ip, 4000, path="/health", timeout=self.http_timeout
                )
                if headers and "x-litellm" in headers.lower():
                    return "LiteLLM"
            return "LiteLLM (HTTP)"

        if port == 30000:
            if "sglang" in lower:
                return "SGLang"
            if ip and self.deep_probe:
                status, _headers, _body = _http_get(
                    ip, 30000, path="/health", timeout=self.http_timeout
                )
                if status and "200" in status:
                    return "SGLang"
            return "SGLang (HTTP)"

        if port == 2358:
            if "judge0" in lower or "x-auth-token" in lower:
                return "Judge0"
            if ip and self.deep_probe:
                _status, _headers, body = _http_get(
                    ip, 2358, path="/about", timeout=self.http_timeout
                )
                if body and "judge0" in body.lower():
                    return "Judge0"
            return "Judge0 (HTTP)"

        if port == 8000:
            if "jupyter" in lower:
                return "JupyterHub"
            if "vllm" in lower:
                return "vLLM"
            if ip and self.deep_probe and _check_openai_compatible(ip, port):
                return "OpenAI-compatible (vLLM/other)"
            return "HTTP (Alt)"

        if port == 80:
            return "HTTP"
        if port == 443:
            return "HTTPS"
        if port == 5800 and ("novnc" in lower or "vnc" in lower):
            return "noVNC"
        if port == 6099 and ("napcat" in lower or "webui" in lower):
            return "NapCatQQ WebUI"
        # Generic HTTP detection must come *after* every port-specific rule,
        # otherwise "HTTP/1.1 ..." matches here and shadows ports like 6099.
        if port == 3080:
            if "caddy" in lower or "deepseek" in lower:
                return "DeepSeek Harness"
            return "DeepSeek Harness (HTTP)"
        if port == 8080:
            if "nonebot" in lower:
                return "NoneBot2"
            return "HTTP (Alt)"

        if "http/" in lower or "server:" in lower:
            return "HTTP"

        return None

    # -- heuristics ----------------------------------------------------
    def _is_jupyter(self, ip: str, port: int, banner: str) -> bool:
        """Any of five independent Jupyter signatures is enough."""
        lower = banner.lower()

        if re.search(r"server:\s*tornadoserver", lower):
            return True

        for marker in self.JUPYTER_MARKERS:
            if marker in lower:
                return True

        if not self.deep_probe:
            return False

        _status, _headers, body = _http_get(ip, port, path="/api/status", timeout=self.http_timeout)
        parsed = self._load_json(body)
        if isinstance(parsed, dict) and "kernels" in parsed and "sessions" in parsed:
            return True

        _status, _headers, body = _http_get(ip, port, path="/api", timeout=self.http_timeout)
        if body:
            body_lower = body.lower()
            if "jupyter server" in body_lower or '"version"' in body_lower:
                return True
            parsed = self._load_json(body)
            if isinstance(parsed, dict) and ("version" in parsed or "app" in parsed):
                return True

        return "302" in banner and ("/lab" in lower or "/tree" in lower)

    def _has_models(self, ip: str, port: int, path: str) -> bool:
        _status, _headers, body = _http_get(ip, port, path=path, timeout=self.http_timeout)
        if not body:
            return False
        return '"models"' in body

    @staticmethod
    def _load_json(body: Optional[str]) -> Any:
        if not body:
            return None
        try:
            return json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None
