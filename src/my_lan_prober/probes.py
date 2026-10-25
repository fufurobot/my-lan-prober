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
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
        log.debug("icmp_ping: windows ping argv for %s: %s", host, command)
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), host]
        log.debug("icmp_ping: posix ping argv for %s (platform %s): %s", host, system, command)

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
            shell=False,
        )
        log.debug("icmp_ping: %s exited with %s", host, result.returncode)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.debug("icmp_ping: %s could not be pinged (%s): %s", host, type(exc).__name__, exc)
        return False


# ---------------------------------------------------------------------------
# Raw HTTP
# ---------------------------------------------------------------------------
def split_http_response(raw: str) -> Tuple[str, str, str]:
    """Split a raw HTTP response into ``(status_line, head, body)``."""
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 1:
        # Tolerate servers that use bare LF line endings.
        log.debug("split_http_response: no CRLFCRLF in %d byte(s); retrying on bare LF", len(raw))
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
    log.debug(
        "_http_get: GET %s:%s%s read_timeout=%s connect_timeout=%s headers=%s",
        ip,
        port,
        path,
        timeout,
        effective_connect_timeout,
        sorted(extra_headers) if extra_headers else [],
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(effective_connect_timeout)
            sock.connect((ip, port))
            sock.settimeout(timeout)
            log.debug("_http_get: connected to %s:%s", ip, port)

            request = f"GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n"
            if extra_headers:
                headers = extra_headers
            else:
                headers = {}
                log.debug("_http_get: %s:%s%s sends no extra request headers", ip, port, path)
            for key, value in headers.items():
                log.debug("_http_get: adding request header %s for %s:%s", key, ip, port)
                request += f"{key}: {value}\r\n"
            request += "\r\n"

            sock.sendall(request.encode("utf-8", errors="ignore"))
            log.debug("_http_get: sent %d byte(s) of request to %s:%s", len(request), ip, port)

            raw = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    log.debug(
                        "_http_get: read timeout after %d byte(s) from %s:%s",
                        len(raw),
                        ip,
                        port,
                    )
                    break
                if not chunk:
                    log.debug("_http_get: peer %s:%s closed after %d byte(s)", ip, port, len(raw))
                    break
                raw += chunk
    except (TimeoutError, ConnectionRefusedError, OSError) as exc:
        log.debug("_http_get: %s:%s%s failed (%s): %s", ip, port, path, type(exc).__name__, exc)
        return None, None, None

    text = raw.decode("utf-8", errors="ignore")
    status, head, body = split_http_response(text)
    log.debug(
        "_http_get: %s:%s%s -> status %r, %d byte(s) of body kept (of %d)",
        ip,
        port,
        path,
        status,
        min(len(body), MAX_BODY_BYTES),
        len(body),
    )
    return status, head, body[:MAX_BODY_BYTES]


def _probe_tcp_banner(ip: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
    """Connect and read whatever the peer volunteers first."""
    effective_timeout = DEFAULT_PORT_TIMEOUT if timeout is None else timeout
    log.debug(
        "_probe_tcp_banner: reading first bytes from %s:%s (timeout %.3fs)",
        ip,
        port,
        effective_timeout,
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(effective_timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            log.debug("_probe_tcp_banner: %s:%s sent %d byte(s)", ip, port, len(banner))
            return banner
    except (TimeoutError, ConnectionRefusedError, OSError) as exc:
        log.debug(
            "_probe_tcp_banner: %s:%s gave no banner (%s): %s", ip, port, type(exc).__name__, exc
        )
        return None


def probe_service(ip: str, port: int, timeout: Optional[float] = None) -> Optional[str]:
    """Identify what is listening on ``ip:port``, or ``None`` if closed."""
    effective_timeout = DEFAULT_PORT_TIMEOUT if timeout is None else timeout
    log.debug("probe_service: probing %s:%s with timeout %.3fs", ip, port, effective_timeout)

    if port in HTTP_PROBE_PORTS:
        log.debug(
            "probe_service: %s:%s is an HTTP port; sending a GET rather than a banner grab",
            ip,
            port,
        )
        status, head, body = _http_get(ip, port, connect_timeout=effective_timeout)
        if status is None:
            log.debug(
                "probe_service: %s:%s did not answer HTTP; treating the port as closed", ip, port
            )
            return None
        log.debug("probe_service: %s:%s answered HTTP with %r", ip, port, status)
        return f"{status}\n{head}\n{body[:MAX_BODY_BYTES]}"

    log.debug("probe_service: %s:%s is not an HTTP port; falling back to a TCP banner", ip, port)
    return _probe_tcp_banner(ip, port, timeout=effective_timeout)


def _check_openai_compatible(ip: str, port: int, timeout: int = HTTP_TIMEOUT) -> bool:
    """Whether ``/v1/models`` answers with an OpenAI-style model list."""
    try:
        from openai import OpenAI

        client = OpenAI(base_url=f"http://{ip}:{port}/v1", api_key="not-needed")
        models = client.models.list()
        if hasattr(models, "data"):
            count = len(models.data)
            log.debug(
                "_check_openai_compatible: %s:%s /v1/models returned %d model(s)", ip, port, count
            )
            return count > 0
        log.debug("_check_openai_compatible: %s:%s response has no .data attribute", ip, port)
        return False
    except Exception as exc:
        log.debug(
            "_check_openai_compatible: %s:%s is not OpenAI-compatible (%s): %s",
            ip,
            port,
            type(exc).__name__,
            exc,
        )
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
            log.debug(
                "identify: no banner for %s:%s (banner=%r); cannot identify", ip, port, banner
            )
            return None
        if not banner:
            log.debug("identify: empty banner for %s:%s; cannot identify", ip, port)
            return None

        lower = banner.lower()
        log.debug(
            "identify: %s:%s banner of %d char(s), deep_probe=%s",
            ip,
            port,
            len(banner),
            self.deep_probe,
        )

        if port == 8888:
            log.debug("identify: %s:%s is port 8888; checking the Jupyter signatures", ip, port)
            if ip:
                jupyter = self._is_jupyter(ip, port, banner)
            else:
                jupyter = False
                log.debug(
                    "identify: %s:%s has no ip to probe 8888 with; assuming not Jupyter", ip, port
                )
            if jupyter:
                log.debug("identify: %s:%s matched a Jupyter signature", ip, port)
                return "Jupyter Server"
            log.debug(
                "identify: %s:%s is 8888 but not Jupyter (ip=%r); reporting generic HTTP",
                ip,
                port,
                ip,
            )
            return "HTTP (Alt)"

        if "ssh-" in lower:
            log.debug("identify: %s:%s banner contains an SSH identification string", ip, port)
            if port == 8022:
                log.debug("identify: %s:%s is the Termux SSH port 8022", ip, port)
                return "SSH (Termux)"
            log.debug("identify: %s:%s is SSH but not port 8022", ip, port)
            if port == 2222:
                log.debug("identify: %s:%s is the alternate SSH port 2222", ip, port)
                return "SSH (Alt)"
            log.debug("identify: %s:%s speaks SSH on a non-standard port", ip, port)
            return "SSH"

        if "rfb" in lower:
            log.debug("identify: %s:%s banner carries the RFB handshake; it is VNC", ip, port)
            return "VNC"

        if port == 11434:
            if "ollama" in lower:
                log.debug("identify: %s:%s banner names ollama; it is Ollama", ip, port)
                return "Ollama"
            log.debug("identify: %s:%s is 11434 but the banner does not name ollama", ip, port)
            if ip:
                probe_models = self.deep_probe
            else:
                probe_models = False
                log.debug("identify: %s:%s has no ip to probe /api/tags with", ip, port)
            # Deliberately two statements rather than one `and`: the logging-coverage
            # rule wants each decision to be a real, individually loggable branch.
            if probe_models:  # noqa: SIM102
                if self._has_models(ip, 11434, "/api/tags"):
                    log.debug("identify: %s:%s /api/tags listed models", ip, port)
                    return "Ollama"
            log.debug(
                "identify: %s:%s has no model list either (ip=%r, deep_probe=%s); HTTP Ollama",
                ip,
                port,
                ip,
                self.deep_probe,
            )
            return "Ollama (HTTP)"

        if port == 4000:
            if "x-litellm" in lower or "litellm" in lower:
                log.debug(
                    "identify: %s:%s banner carries a litellm marker; it is LiteLLM", ip, port
                )
                return "LiteLLM"
            log.debug("identify: %s:%s is 4000 with no litellm marker in the banner", ip, port)
            if ip and self.deep_probe:
                log.debug("identify: %s:%s probing /health for the litellm header", ip, port)
                _status, headers, _body = _http_get(
                    ip, 4000, path="/health", timeout=self.http_timeout
                )
                if headers and "x-litellm" in headers.lower():
                    log.debug("identify: %s:%s /health returned the litellm header", ip, port)
                    return "LiteLLM"
            log.debug(
                "identify: %s:%s answered no litellm header (ip=%r, deep_probe=%s); HTTP LiteLLM",
                ip,
                port,
                ip,
                self.deep_probe,
            )
            return "LiteLLM (HTTP)"

        if port == 30000:
            if "sglang" in lower:
                log.debug("identify: %s:%s banner names sglang; it is SGLang", ip, port)
                return "SGLang"
            log.debug("identify: %s:%s is 30000 with no sglang marker in the banner", ip, port)
            if ip and self.deep_probe:
                log.debug("identify: %s:%s probing /health for an SGLang status", ip, port)
                status, _headers, _body = _http_get(
                    ip, 30000, path="/health", timeout=self.http_timeout
                )
                if status and "200" in status:
                    log.debug("identify: %s:%s /health answered %r; it is SGLang", ip, port, status)
                    return "SGLang"
            log.debug(
                "identify: %s:%s is not SGLang by status (ip=%r, deep_probe=%s); HTTP SGLang",
                ip,
                port,
                ip,
                self.deep_probe,
            )
            return "SGLang (HTTP)"

        if port == 2358:
            if "judge0" in lower or "x-auth-token" in lower:
                log.debug("identify: %s:%s banner carries a judge0 marker; it is Judge0", ip, port)
                return "Judge0"
            log.debug("identify: %s:%s is 2358 with no judge0 marker in the banner", ip, port)
            if ip and self.deep_probe:
                log.debug("identify: %s:%s probing /about for a judge0 body", ip, port)
                _status, _headers, body = _http_get(
                    ip, 2358, path="/about", timeout=self.http_timeout
                )
                if body and "judge0" in body.lower():
                    log.debug("identify: %s:%s /about mentions judge0", ip, port)
                    return "Judge0"
            log.debug(
                "identify: %s:%s /about did not mention judge0 (ip=%r, deep_probe=%s); HTTP Judge0",
                ip,
                port,
                ip,
                self.deep_probe,
            )
            return "Judge0 (HTTP)"

        if port == 8000:
            if "jupyter" in lower:
                log.debug("identify: %s:%s banner names jupyter; it is JupyterHub", ip, port)
                return "JupyterHub"
            log.debug("identify: %s:%s is 8000 but the banner does not name jupyter", ip, port)
            if "vllm" in lower:
                log.debug("identify: %s:%s banner names vllm; it is vLLM", ip, port)
                return "vLLM"
            log.debug(
                "identify: %s:%s is 8000 with neither jupyter nor vllm in the banner", ip, port
            )
            if ip and self.deep_probe and _check_openai_compatible(ip, port):
                log.debug("identify: %s:%s answered an OpenAI-style model list", ip, port)
                return "OpenAI-compatible (vLLM/other)"
            log.debug(
                "identify: %s:%s has no OpenAI-style model list either (ip=%r, deep_probe=%s)",
                ip,
                port,
                ip,
                self.deep_probe,
            )
            return "HTTP (Alt)"

        if port == 80:
            log.debug("identify: %s:%s is plain port 80; reporting HTTP", ip, port)
            return "HTTP"
        if port == 443:
            log.debug("identify: %s:%s is port 443; reporting HTTPS", ip, port)
            return "HTTPS"
        if port == 5800 and ("novnc" in lower or "vnc" in lower):
            log.debug("identify: %s:%s serves noVNC on 5800", ip, port)
            return "noVNC"
        if port == 6099 and ("napcat" in lower or "webui" in lower):
            log.debug("identify: %s:%s serves the NapCatQQ WebUI on 6099", ip, port)
            return "NapCatQQ WebUI"
        # Generic HTTP detection must come *after* every port-specific rule,
        # otherwise "HTTP/1.1 ..." matches here and shadows ports like 6099.
        if port == 3080:
            if "caddy" in lower or "deepseek" in lower:
                log.debug(
                    "identify: %s:%s banner names caddy/deepseek; it is the Harness", ip, port
                )
                return "DeepSeek Harness"
            log.debug("identify: %s:%s is 3080 without a caddy/deepseek marker", ip, port)
            return "DeepSeek Harness (HTTP)"
        if port == 8080:
            if "nonebot" in lower:
                log.debug("identify: %s:%s banner names nonebot; it is NoneBot2", ip, port)
                return "NoneBot2"
            log.debug("identify: %s:%s is 8080 without a nonebot marker; reporting HTTP", ip, port)
            return "HTTP (Alt)"

        if "http/" in lower or "server:" in lower:
            log.debug(
                "identify: %s:%s is an unclassified port but the banner looks like HTTP", ip, port
            )
            return "HTTP"

        log.debug(
            "identify: %s:%s matched no rule for port %s; leaving it unidentified", ip, port, port
        )
        return None

    # -- heuristics ----------------------------------------------------
    def _is_jupyter(self, ip: str, port: int, banner: str) -> bool:
        """Any of five independent Jupyter signatures is enough."""
        lower = banner.lower()

        if re.search(r"server:\s*tornadoserver", lower):
            log.debug("_is_jupyter: %s:%s Server header is TornadoServer; it is Jupyter", ip, port)
            return True

        for marker in self.JUPYTER_MARKERS:
            if marker in lower:
                log.debug("_is_jupyter: %s:%s banner carries the marker %r", ip, port, marker)
                return True

        if not self.deep_probe:
            log.debug("_is_jupyter: %s:%s has no banner marker and deep probing is off", ip, port)
            return False

        log.debug(
            "_is_jupyter: %s:%s probing /api/status for a kernels/sessions document", ip, port
        )
        _status, _headers, body = _http_get(ip, port, path="/api/status", timeout=self.http_timeout)
        parsed = self._load_json(body)
        if isinstance(parsed, dict) and "kernels" in parsed and "sessions" in parsed:
            log.debug("_is_jupyter: %s:%s /api/status lists kernels and sessions", ip, port)
            return True

        log.debug("_is_jupyter: %s:%s probing /api as a second signature", ip, port)
        _status, _headers, body = _http_get(ip, port, path="/api", timeout=self.http_timeout)
        if body:
            body_lower = body.lower()
            if "jupyter server" in body_lower or '"version"' in body_lower:
                log.debug("_is_jupyter: %s:%s /api body names a jupyter server", ip, port)
                return True
            parsed = self._load_json(body)
            if isinstance(parsed, dict) and ("version" in parsed or "app" in parsed):
                log.debug("_is_jupyter: %s:%s /api parsed as a versioned app document", ip, port)
                return True
        else:
            log.debug("_is_jupyter: %s:%s /api returned an empty body", ip, port)

        is_redirect = "302" in banner
        names_lab = "/lab" in lower
        names_tree = "/tree" in lower
        matched = False
        if is_redirect:
            if names_lab or names_tree:
                matched = True
                log.debug(
                    "_is_jupyter: %s:%s banner is a 302 at /lab or /tree (lab=%s, tree=%s)",
                    ip,
                    port,
                    names_lab,
                    names_tree,
                )
            else:
                log.debug(
                    "_is_jupyter: %s:%s banner is a 302 but names neither lab nor tree", ip, port
                )
        else:
            log.debug("_is_jupyter: %s:%s banner carries no 302 redirect", ip, port)
        return matched

    def _has_models(self, ip: str, port: int, path: str) -> bool:
        _status, _headers, body = _http_get(ip, port, path=path, timeout=self.http_timeout)
        if not body:
            log.debug("_has_models: %s:%s%s returned an empty body", ip, port, path)
            return False
        found = '"models"' in body
        log.debug("_has_models: %s:%s%s -> models key present=%s", ip, port, path, found)
        return found

    @staticmethod
    def _load_json(body: Optional[str]) -> Any:
        if not body:
            log.debug("_load_json: nothing to parse (body=%r)", body)
            return None
        try:
            return json.loads(body)
        except (json.JSONDecodeError, TypeError) as exc:
            log.debug("_load_json: body of %d char(s) is not JSON (%s)", len(body), exc)
            return None
