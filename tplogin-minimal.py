"""
Network service discovery and router DHCP lease scraper.

Resolves configured hostnames, probes common ports, identifies services
(including Jupyter on port 8888), scrapes TP-Link router DHCP leases via
Playwright, and enriches lease data with ICMP ping and port scan results.

All outputs (HTML dump, CSVs, per-host SSH scripts) are written under the
``data/`` directory, which is created automatically.

Port detection timeout (TCP connect phase) can be configured via:
  * CLI:  --port-timeout SECONDS  (or -t SECONDS)
  * ENV:  PORT_TIMEOUT=SECONDS
  * Default: 0.1s (LAN probes should be near-instant)

Precedence: CLI flag > environment variable > default.

The router scrape needs a Playwright browser *binary*, which
``pip install playwright`` does not install — the binaries come from a
separate ``playwright install``.  The engine is therefore detected at run
time (see :func:`first_available_browser`) instead of assuming chromium, and
when no engine at all is available the scan falls back to the OS ARP table
(see :func:`local_arp_leases`) so it still produces a useful result.
"""

import argparse
import contextlib
import ipaddress
import re
import socket
import subprocess
import platform
import os
import json
import logging
import tempfile
import threading
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

import pandas as pd
from tqdm.auto import tqdm

# ``playwright`` is imported lazily, inside the functions that need it.  A
# module-level import would make this whole script unrunnable on a machine
# without the (optional) package — which is exactly the situation the local
# ARP fallback exists to handle.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COMMON_PORTS: List[int] = [
    22, 80, 443, 2222, 8022, 5800, 5900, 8080, 6099, 3080,
    11434, 8000, 8501, 4000, 30000, 2358, 8888,
]

# Hosts to resolve before testing
RESOLVE_HOSTS: List[str] = ["tplogin.cn", "localhost"]

# Default port detection timeout (seconds). LAN probes should be near-instant.
DEFAULT_PORT_TIMEOUT: float = 0.1

# Runtime-resolved port detection timeout (set in run() from CLI/env).
PORT_SCAN_TIMEOUT: float = DEFAULT_PORT_TIMEOUT

# Other timeouts (seconds)
HTTP_TIMEOUT: int = 5
PING_TIMEOUT: int = 2

# Playwright's three engines, in order of preference.  Chromium leads because
# it is what this script has always used, so a machine with several engines
# installed keeps behaving exactly as before.
BROWSER_NAMES: Tuple[str, ...] = ("chromium", "firefox", "webkit")

# ``auto`` is accepted as an explicit spelling of the default.
BROWSER_CHOICES: Tuple[str, ...] = BROWSER_NAMES + ("auto",)

# Command that downloads a missing browser binary.
BROWSER_INSTALL_HINT: str = "playwright install"

# ---------------------------------------------------------------------------
# Output directory: everything goes under ./data
# ---------------------------------------------------------------------------
DATA_DIR: Path = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Output files (all under DATA_DIR)
SSH_CONFIG_FILENAME: str = "ssh.sh"
ROUTER_HTML_FILE: Path = DATA_DIR / "tplogin-arp.html"
DNS_CSV_FILE: Path = DATA_DIR / "dns-resolved-hosts.csv"
ENRICHED_CSV_FILE: Path = DATA_DIR / "tplogin-arp-enriched.csv"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

tqdm.pandas()

# ---------------------------------------------------------------------------
# CLI / configuration resolution
# ---------------------------------------------------------------------------

def parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="network-scraper",
        description=(
            "Network service discovery and router DHCP lease scraper. "
            "Resolves hostnames, probes ports, identifies services, and "
            "scrapes TP-Link DHCP leases via Playwright."
        ),
    )
    parser.add_argument(
        "-t", "--port-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "Timeout in seconds for TCP port detection (connect phase). "
            f"Default: {DEFAULT_PORT_TIMEOUT}s. "
            "Can also be set via the PORT_TIMEOUT environment variable. "
            "CLI flag takes precedence over the env var."
        ),
    )
    parser.add_argument(
        "--browser",
        choices=BROWSER_CHOICES,
        default=None,
        metavar="NAME",
        help=(
            "Playwright browser engine to use when scraping the router, or "
            "'auto' to detect the first installed engine ("
            + ", ".join(BROWSER_NAMES)
            + "). Default: auto. Note that installing the Python package does "
            f"not install a browser; run `{BROWSER_INSTALL_HINT}` for that. "
            "When no engine is available at all, the scan falls back to the "
            "local ARP table."
        ),
    )
    return parser.parse_args(argv)


def resolve_port_timeout(cli_value: Optional[float]) -> float:
    """
    Resolve the effective port detection timeout.

    Precedence:
        1. CLI flag (``--port-timeout`` / ``-t``)
        2. ``PORT_TIMEOUT`` environment variable
        3. ``DEFAULT_PORT_TIMEOUT``
    """
    if cli_value is not None:
        if cli_value <= 0:
            raise ValueError(f"--port-timeout must be > 0 (got {cli_value!r})")
        return float(cli_value)

    env_value = os.environ.get("PORT_TIMEOUT", "").strip()
    if env_value:
        try:
            parsed = float(env_value)
            if parsed <= 0:
                raise ValueError
            return parsed
        except ValueError:
            log.warning(
                "Ignoring invalid PORT_TIMEOUT env value %r "
                "(must be a positive number). Falling back to default.",
                env_value,
            )

    return DEFAULT_PORT_TIMEOUT


# ---------------------------------------------------------------------------
# DNS Resolution
# ---------------------------------------------------------------------------

def resolve_host(hostname: str) -> Optional[str]:
    """Resolve a hostname to an IPv4 address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        log.warning("DNS resolution failed for %s: %s", hostname, exc)
        return None


# ---------------------------------------------------------------------------
# ICMP Ping
# ---------------------------------------------------------------------------

def icmp_ping(host: str, timeout: int = PING_TIMEOUT) -> bool:
    """Perform an ICMP ping using the system's ping command."""
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(
    ip: str,
    port: int,
    path: str = "/",
    timeout: int = HTTP_TIMEOUT,
    extra_headers: Optional[Dict[str, str]] = None,
    connect_timeout: Optional[float] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Perform a minimal raw HTTP GET.

    Args:
        timeout: Read timeout (seconds) after the TCP connection is
            established.
        connect_timeout: TCP connect timeout (seconds).  Defaults to the
            module-level ``PORT_SCAN_TIMEOUT``.

    Returns:
        (status_line, response_headers, response_body) or (None, None, None)
        on failure.
    """
    effective_connect_timeout = (
        PORT_SCAN_TIMEOUT if connect_timeout is None else connect_timeout
    )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(effective_connect_timeout)
            sock.connect((ip, port))
            sock.settimeout(timeout)

            headers = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {ip}:{port}\r\n"
                f"Connection: close\r\n"
            )
            if extra_headers:
                for key, value in extra_headers.items():
                    headers += f"{key}: {value}\r\n"
            headers += "\r\n"

            sock.sendall(headers.encode("utf-8", errors="ignore"))

            raw = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                except socket.timeout:
                    break

            text = raw.decode("utf-8", errors="ignore")
            parts = text.split("\r\n\r\n", 1)
            head = parts[0] if parts else ""
            body = parts[1] if len(parts) > 1 else ""
            lines = head.split("\r\n")
            status = lines[0] if lines else ""
            return status, head, body

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None, None, None


def _probe_tcp_banner(
    ip: str,
    port: int,
    timeout: Optional[float] = None,
) -> Optional[str]:
    """Connect to a port and read the initial banner (if any)."""
    effective_timeout = PORT_SCAN_TIMEOUT if timeout is None else timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(effective_timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


# ---------------------------------------------------------------------------
# Port probing
# ---------------------------------------------------------------------------

# Ports that should be probed with an HTTP GET rather than raw banner grabbing
HTTP_PROBE_PORTS: List[int] = [
    80, 443, 5800, 8080, 6099, 3080, 8000, 8888, 4000, 30000, 2358, 11434,
]


def probe_service(
    ip: str,
    port: int,
    timeout: Optional[float] = None,
) -> Optional[str]:
    """
    Connect to a port and try to identify the service.

    For HTTP-like ports, performs a raw GET request and returns the combined
    status line, headers, and a truncated body.  For other ports, attempts to
    read an immediate banner.

    ``timeout`` controls the TCP connect phase and defaults to the
    module-level ``PORT_SCAN_TIMEOUT`` (which is set from CLI/env).

    Returns a decoded string or None on failure.
    """
    effective_timeout = PORT_SCAN_TIMEOUT if timeout is None else timeout

    if port in HTTP_PROBE_PORTS:
        status, headers, body = _http_get(
            ip, port, connect_timeout=effective_timeout
        )
        if status is None:
            return None
        return f"{status}\n{headers}\n{body[:4096]}"

    return _probe_tcp_banner(ip, port, timeout=effective_timeout)


# ---------------------------------------------------------------------------
# Jupyter-specific detection
# ---------------------------------------------------------------------------

def _is_jupyter(ip: str, port: int, banner: str) -> bool:
    """
    Detect whether the service on ``port`` is a Jupyter server.

    Detection heuristics (any match is sufficient):
      1. ``Server: TornadoServer/<version>`` header (Jupyter uses Tornado).
      2. Body contains Jupyter-specific markers (``jupyter``, ``lab``, ``tree``,
         ``_xsrf``, ``jupyterlab``).
      3. ``/api/status`` returns JSON with ``kernels`` and ``sessions`` keys.
      4. ``/api`` returns JSON with a ``version`` field or ``Jupyter Server``
         in the response.
      5. Root path returns a 302 redirect to ``/lab`` or ``/tree`` with Jupyter
         HTML markers.
    """
    banner_lower = banner.lower()

    # --- Heuristic 1: TornadoServer header ---
    if re.search(r"server:\s*tornadoserver", banner_lower):
        log.debug("Jupyter signature found via TornadoServer header on %s:%d", ip, port)
        return True

    # --- Heuristic 2: body / header markers ---
    jupyter_markers = [
        "jupyter",
        "jupyterlab",
        "jupyter_server",
        "_xsrf",
        "lab?",
        "tree?",
        "/static/lab/",
        "notebook",
    ]
    for marker in jupyter_markers:
        if marker in banner_lower:
            log.debug("Jupyter signature found via marker '%s' on %s:%d", marker, ip, port)
            return True

    # --- Heuristic 3: /api/status endpoint ---
    status_line, headers, body = _http_get(ip, port, path="/api/status", timeout=HTTP_TIMEOUT)
    if body:
        try:
            data = json.loads(body)
            if isinstance(data, dict) and "kernels" in data and "sessions" in data:
                log.debug("Jupyter signature found via /api/status on %s:%d", ip, port)
                return True
        except (json.JSONDecodeError, TypeError):
            pass

    # --- Heuristic 4: /api endpoint ---
    status_line, headers, body = _http_get(ip, port, path="/api", timeout=HTTP_TIMEOUT)
    if body:
        body_lower = body.lower()
        if "jupyter server" in body_lower or '"version"' in body_lower:
            log.debug("Jupyter signature found via /api on %s:%d", ip, port)
            return True
        try:
            data = json.loads(body)
            if isinstance(data, dict) and ("version" in data or "app" in data):
                log.debug("Jupyter signature found via /api JSON on %s:%d", ip, port)
                return True
        except (json.JSONDecodeError, TypeError):
            pass

    # --- Heuristic 5: root redirect to /lab or /tree ---
    if "302" in banner and ("/lab" in banner_lower or "/tree" in banner_lower):
        log.debug("Jupyter signature found via redirect on %s:%d", ip, port)
        return True

    return False


# ---------------------------------------------------------------------------
# Service identification
# ---------------------------------------------------------------------------

def identify_service(
    banner: Optional[str],
    port: int,
    ip: Optional[str] = None,
) -> Optional[str]:
    """
    Parse the banner/HTTP response to assign a service name.

    ``ip`` is optional and used for deeper checks (e.g., Jupyter, Ollama).
    """
    if banner is None or (isinstance(banner, float) and pd.isnull(banner)):
        return None

    banner_lower = banner.lower()

    # =================================================================
    # Port 8888 — Jupyter
    # =================================================================
    if port == 8888:
        if ip and _is_jupyter(ip, port, banner):
            return "Jupyter Server"
        return "HTTP (Alt)"

    # =================================================================
    # SSH
    # =================================================================
    if "ssh-" in banner_lower:
        if port == 8022:
            return "SSH (Termux)"
        if port == 2222:
            return "SSH (Alt)"
        return "SSH"

    # =================================================================
    # VNC
    # =================================================================
    if "rfb" in banner_lower:
        return "VNC"

    # =================================================================
    # Ollama
    # =================================================================
    if port == 11434:
        if "ollama" in banner_lower:
            return "Ollama"
        if ip:
            _, _, body = _http_get(ip, 11434, path="/api/tags", timeout=HTTP_TIMEOUT)
            if body and '"models"' in body:
                return "Ollama"
        return "Ollama (HTTP)"

    # =================================================================
    # Streamlit (port 8888 previously used here — now handled above)
    # =================================================================

    # =================================================================
    # LiteLLM
    # =================================================================
    if port == 4000:
        if "x-litellm" in banner_lower or "litellm" in banner_lower:
            return "LiteLLM"
        if ip:
            _, headers, _ = _http_get(ip, 4000, path="/health", timeout=HTTP_TIMEOUT)
            if headers and "x-litellm" in headers.lower():
                return "LiteLLM"
        return "LiteLLM (HTTP)"

    # =================================================================
    # SGLang
    # =================================================================
    if port == 30000:
        if "sglang" in banner_lower:
            return "SGLang"
        if ip:
            status, _, _ = _http_get(ip, 30000, path="/health", timeout=HTTP_TIMEOUT)
            if status and "200" in status:
                return "SGLang"
        return "SGLang (HTTP)"

    # =================================================================
    # Judge0
    # =================================================================
    if port == 2358:
        if "judge0" in banner_lower or "x-auth-token" in banner_lower:
            return "Judge0"
        if ip:
            _, _, body = _http_get(ip, 2358, path="/about", timeout=HTTP_TIMEOUT)
            if body and "judge0" in body.lower():
                return "Judge0"
        return "Judge0 (HTTP)"

    # =================================================================
    # OpenAI-compatible / vLLM / JupyterHub on port 8000
    # =================================================================
    if port == 8000:
        if "jupyter" in banner_lower:
            return "JupyterHub"
        if "vllm" in banner_lower:
            return "vLLM"
        if ip and _check_openai_compatible(ip, port):
            return "OpenAI-compatible (vLLM/other)"
        return "HTTP (Alt)"

    # =================================================================
    # Standard ports
    # =================================================================
    if port == 80:
        return "HTTP"
    if port == 443:
        return "HTTPS"
    if port == 5800 and ("novnc" in banner_lower or "vnc" in banner_lower):
        return "noVNC"
    if port == 6099 and ("napcat" in banner_lower or "webui" in banner_lower):
        return "NapCatQQ WebUI"
    if port == 3080:
        if "caddy" in banner_lower or "deepseek" in banner_lower:
            return "DeepSeek Harness"
        return "DeepSeek Harness (HTTP)"
    if port == 8080:
        if "nonebot" in banner_lower:
            return "NoneBot2"
        return "HTTP (Alt)"

    # Generic HTTP detection
    if "http/" in banner_lower or "server:" in banner_lower:
        return "HTTP"

    return None


def _check_openai_compatible(ip: str, port: int, timeout: int = HTTP_TIMEOUT) -> bool:
    """
    Try calling the /v1/models endpoint (OpenAI-compatible).

    Returns True if the response looks like an OpenAI-style model list.
    """
    try:
        from openai import OpenAI

        client = OpenAI(base_url=f"http://{ip}:{port}/v1", api_key="not-needed")
        models = client.models.list()
        return hasattr(models, "data") and len(models.data) > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# SSH config writing
# ---------------------------------------------------------------------------

def write_ssh_config(
    host: str,
    ip: str,
    port: int,
    tunnels: Optional[List[Tuple[int, int]]] = None,
    local_port_offset: int = 0,
) -> None:
    """
    Write an SSH helper script for the given host.

    The script is written to ``data/<host>/ssh.sh``.

    Args:
        host: Logical host name (used as the subdirectory under ``data/``).
        ip: Target IP for SSH.
        port: SSH port on the target.
        tunnels: Optional list of ``(local_port, remote_port)`` pairs. Each
            pair is emitted as ``-L local_port:localhost:remote_port`` so the
            remote service becomes reachable on the local machine.
        local_port_offset: Added to every local port to avoid collisions when
            several host scripts are run simultaneously (e.g. 1000 -> 8888
            becomes local 9888).
    """
    path = DATA_DIR / host
    path.mkdir(parents=True, exist_ok=True)
    config_path = path / SSH_CONFIG_FILENAME

    parts: List[str] = [
        "ssh",
        f"-p {port}",
        # Keep the tunnel alive across idle periods and fail fast if a
        # local port is already bound (so we don't silently drop tunnels).
        "-o ServerAliveInterval=30",
        "-o ServerAliveCountMax=3",
        "-o ExitOnForwardFailure=yes",
    ]

    if tunnels:
        seen: set = set()
        for local_port, remote_port in tunnels:
            if remote_port in seen:
                continue
            seen.add(remote_port)
            parts.append(
                f"-L {local_port + local_port_offset}:localhost:{remote_port}"
            )

    parts.append(ip)

    # Write as a single logical command with backslash continuations so the
    # file is both readable and runnable as a shell script.
    with open(config_path, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env bash\n")
        fh.write(" \\\n    ".join(parts))
        fh.write("\n")
    config_path.chmod(0o755)

    if tunnels:
        fwd = ", ".join(
            f"{lp + local_port_offset}->{rp}" for lp, rp in tunnels
        )
        log.info(
            "Wrote SSH config for %s -> %s:%d (%d tunnel(s): %s)",
            host, ip, port, len(tunnels), fwd,
        )
    else:
        log.info("Wrote SSH config for %s -> %s:%d (no tunnels)", host, ip, port)


# ---------------------------------------------------------------------------
# Router scraping (Playwright)
# ---------------------------------------------------------------------------

def get_password() -> str:
    """Prompt user for password if not set in environment."""
    env_password = os.environ.get("TPLOGIN_PASSWORD", "").strip()
    if env_password:
        return env_password

    import getpass

    password = getpass.getpass("Please enter the router admin password: ")
    if not password:
        raise ValueError("Password cannot be empty.")
    return password


# ---------------------------------------------------------------------------
# Browser engine detection
# ---------------------------------------------------------------------------

class BrowserNotInstalled(RuntimeError):
    """No usable Playwright browser binary was found on this machine."""


def _driver_env() -> Dict[str, str]:
    """
    Environment for Playwright's Node driver, with a writable temp dir.

    The driver picks its artifacts directory with ``os.tmpdir()``, which
    honours ``TMPDIR`` -> ``TMP`` -> ``TEMP`` with no fallback of its own.  An
    MSYS2 shell exports those as its own ``/tmp``, which a native Windows
    process cannot write to, and the browser launch then dies with ``EPERM``
    at ``mkdtemp`` (CPython 3.13) or ``WinError 5`` while creating the
    driver's pipes (CPython 3.10).  CPython's own ``tempfile`` probes and
    falls through, which is why the failure looks so confusing.

    Writability is tested by creating a real file: ``os.access`` reports
    ``True`` on Windows for directories whose writes fail.
    """
    candidates: List[Path] = []

    for name in ("TMPDIR", "TMP", "TEMP"):
        raw = os.environ.get(name, "").strip()
        # A POSIX-style path only exists inside MSYS2; a native Windows child
        # cannot use one, so it is never a candidate there.
        if raw and not (os.name == "nt" and raw.startswith("/")):
            candidates.append(Path(raw))

    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    if local_appdata:
        candidates.append(Path(local_appdata) / "Temp")

    candidates.append(Path.cwd() / "playwright-temp")

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        if _temp_dir_is_writable(candidate):
            chosen = str(candidate.resolve())
            env = dict(os.environ)
            for name in ("TMPDIR", "TMP", "TEMP"):
                env[name] = chosen
            return env

    return dict(os.environ)


def _temp_dir_is_writable(path: Path, timeout: float = 2.0) -> bool:
    """Whether a file can really be created in ``path``, bounded by a timeout.

    The probe runs in a worker thread because a wedged ``%LOCALAPPDATA%\\Temp``
    can *block* the create indefinitely rather than failing it.
    """
    result: Dict[str, bool] = {}

    def probe() -> None:
        handle = None
        name = None
        try:
            if not path.is_dir():
                result["ok"] = False
                return
            handle, name = tempfile.mkstemp(dir=str(path), prefix=".probe-")
            result["ok"] = True
        except OSError:
            result["ok"] = False
        finally:
            if handle is not None:
                with contextlib.suppress(OSError):
                    os.close(handle)
            if name is not None:
                with contextlib.suppress(OSError):
                    os.unlink(name)

    worker = threading.Thread(target=probe, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        log.warning("temp directory %s did not respond within %.1fs", path, timeout)
        return False
    return result.get("ok", False)


def is_browser_installed(browser_type: Any) -> bool:
    """
    Whether one Playwright ``BrowserType`` has a binary that exists on disk.

    ``executable_path`` is ``""`` when Playwright has no binary for that
    engine, and ``Path("").exists()`` is ``True`` — the empty path resolves to
    the current directory — so the emptiness check has to come first or every
    engine would look installed.
    """
    try:
        raw = browser_type.executable_path
    except Exception:
        # A driver that already exited raises on attribute access.
        return False
    if not raw:
        return False
    try:
        return Path(str(raw)).is_file()
    except OSError:
        return False


@contextlib.contextmanager
def _driver_env_applied(env: Dict[str, str]):
    """Apply ``env`` to the process for the duration of the block.

    ``sync_playwright()`` spawns the driver as a child process, so the temp
    variables must be in ``os.environ`` when it starts.  They are restored
    afterwards so an overridden temp dir does not leak into the rest of the
    scan, which starts subprocesses of its own (``icmp_ping``).
    """
    saved = {name: os.environ.get(name) for name in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def detect_browsers(playwright: Optional[Any] = None) -> Dict[str, bool]:
    """
    Map every engine name to whether its binary is present.

    Args:
        playwright: An existing Playwright object.  When omitted, one is
            started; if the optional package is missing, or its driver cannot
            be spawned at all, every engine reports ``False`` rather than
            raising.  "Cannot tell" must read as "not installed", because the
            caller's correct response is to fall back to the local ARP table.
    """
    detected: Dict[str, bool] = dict.fromkeys(BROWSER_NAMES, False)

    started = playwright is None
    if started:
        try:
            import playwright as _playwright_package  # noqa: F401

            from playwright.sync_api import sync_playwright

            with _driver_env_applied(_driver_env()):
                playwright = sync_playwright().start()
        except Exception as exc:
            log.debug("could not start the Playwright driver: %s", exc)
            return detected

    try:
        for name in BROWSER_NAMES:
            engine = getattr(playwright, name, None)
            detected[name] = engine is not None and is_browser_installed(engine)
            if detected[name]:
                log.debug("playwright engine %s is installed", name)
    finally:
        # Only stop a driver *we* started.  Shutting down a caller's driver
        # would pull it out from under them.
        if started:
            stop = getattr(playwright, "stop", None)
            if stop is not None:
                with contextlib.suppress(Exception):
                    stop()

    return detected


def first_available_browser(
    playwright: Optional[Any] = None,
    order: Optional[Tuple[str, ...]] = None,
    requested: Optional[str] = None,
) -> str:
    """
    Name of the first installed engine, in preference order.

    Args:
        playwright: Reuse an existing Playwright object.
        order: Engines to try, most preferred first.  Defaults to
            :data:`BROWSER_NAMES`.
        requested: An explicit engine (``--browser`` / ``PW_BROWSER``).  Used
            verbatim, and it is an error if it is not installed — silently
            substituting a different engine would hide a broken setup.

    Raises:
        BrowserNotInstalled: When no usable engine is found.  The message
            names the missing engines and the command that fixes it.
    """
    candidates = order or BROWSER_NAMES

    if requested:
        if requested not in BROWSER_NAMES:
            raise BrowserNotInstalled(
                f"unknown browser engine {requested!r}; "
                f"expected one of {', '.join(BROWSER_NAMES)}"
            )
        detected = detect_browsers(playwright)
        if not detected.get(requested):
            raise BrowserNotInstalled(
                f"the requested browser engine {requested!r} is not installed; "
                f"run `{BROWSER_INSTALL_HINT} {requested}`"
            )
        return requested

    detected = detect_browsers(playwright)
    for name in candidates:
        if detected.get(name):
            log.info("Using Playwright browser engine: %s", name)
            return name

    raise BrowserNotInstalled(
        "no Playwright browser is installed "
        f"({', '.join(f'{name}=no' for name in candidates)}); "
        f"run `{BROWSER_INSTALL_HINT}` to download one"
    )


# ---------------------------------------------------------------------------
# Local ARP table fallback
# ---------------------------------------------------------------------------
#: Columns every local ARP result carries.
ARP_COLUMNS: Tuple[str, ...] = ("host", "mac_address", "ip_address", "valid_time")

_ALL_ZERO_MAC = "00:00:00:00:00:00"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def _normalise_mac(raw: str) -> str:
    """Return ``aa:bb:cc:dd:ee:ff`` lower-case, padding short BSD octets."""
    text = (raw or "").strip().lower()
    if not text:
        return ""
    if ":" in text:
        octets = text.split(":")
    elif "-" in text:
        octets = text.split("-")
    else:
        cleaned = re.sub(r"[^0-9a-f]", "", text)
        if len(cleaned) != 12:
            return text
        octets = [cleaned[i:i + 2] for i in range(0, 12, 2)]

    if len(octets) != 6 or any(
        not re.fullmatch(r"[0-9a-f]{1,2}", octet) for octet in octets
    ):
        return text
    return ":".join(octet.rjust(2, "0") for octet in octets)


def _is_usable_host(ip: str, mac: str) -> bool:
    """Filter out broadcast/multicast addresses and unresolved entries."""
    if mac in (_ALL_ZERO_MAC, _BROADCAST_MAC):
        return False
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (address.is_multicast or address.is_unspecified)


def _run_command(command: List[str], timeout: float = 10.0) -> str:
    """Run a command with a list argv — never a shell string."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout or ""


def parse_proc_net_arp(output: str) -> List[Dict[str, Any]]:
    """Parse ``/proc/net/arp`` (Linux)."""
    rows: List[Dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0].lower() == "ip":
            continue
        ip, _hwtype, flags, mac, _mask, device = parts[:6]
        if flags.lower() in ("0x0", "0x00"):
            continue
        mac = _normalise_mac(mac)
        if not _is_usable_host(ip, mac):
            continue
        rows.append({"ip": ip, "mac_address": mac, "mode": "arp", "interface": device})
    return rows


def parse_ip_neigh(output: str) -> List[Dict[str, Any]]:
    """Parse ``ip neigh show`` (Linux)."""
    rows: List[Dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split()
        if "lladdr" not in parts:
            continue
        ip = parts[0]
        mac = parts[parts.index("lladdr") + 1]
        interface = parts[parts.index("dev") + 1] if "dev" in parts else None
        mac = _normalise_mac(mac)
        if not _is_usable_host(ip, mac):
            continue
        rows.append({"ip": ip, "mac_address": mac, "mode": "arp", "interface": interface})
    return rows


def parse_windows_arp(output: str) -> List[Dict[str, Any]]:
    """Parse ``arp -a`` on Windows."""
    rows: List[Dict[str, Any]] = []
    interface: Optional[str] = None

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        header = re.match(r"^Interface:\s*(\S+)", stripped)
        if header:
            interface = header.group(1)
            continue
        if stripped.lower().startswith("internet address"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        ip, mac, entry_type = parts[0], parts[1], parts[2]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            continue
        mac = _normalise_mac(mac)
        if entry_type.lower() != "dynamic" or not _is_usable_host(ip, mac):
            continue
        rows.append({"ip": ip, "mac_address": mac, "mode": "arp", "interface": interface})
    return rows


def parse_bsd_arp(output: str) -> List[Dict[str, Any]]:
    """Parse ``arp -an`` on macOS/BSD."""
    rows: List[Dict[str, Any]] = []
    # The MAC is hex octets; ``(incomplete)`` must not be mistaken for one.
    pattern = re.compile(
        r"^[?\w.-]*\s*\((?P<ip>[\d.]+)\)\s+at\s+"
        r"(?P<mac>[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
        r"(?:\s+on\s+(?P<iface>\S+))?"
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        ip = match.group("ip")
        mac = _normalise_mac(match.group("mac"))
        if not _is_usable_host(ip, mac):
            continue
        rows.append({
            "ip": ip,
            "mac_address": mac,
            "mode": "arp",
            "interface": match.group("iface"),
        })
    return rows


def local_arp_leases() -> pd.DataFrame:
    """
    Read this machine's ARP table, with no third-party dependency.

    This is the OS-independent fallback for when Playwright has no browser to
    launch: the router's web UI is unreachable without one, but the neighbour
    table already lists every host this machine has talked to.  Every platform
    route is tried in turn, so the same code works on Linux, macOS, BSD and
    Windows:

    * Linux    — ``/proc/net/arp``, then ``ip neigh show``
    * BSD/macOS — ``arp -an``
    * Windows  — ``arp -a``

    Returns a DataFrame with ``host``, ``mac_address``, ``ip_address`` and
    ``valid_time``, matching what the router scrape produces so the rest of
    the pipeline cannot tell the difference.
    """
    rows: List[Dict[str, Any]] = []

    proc = Path("/proc/net/arp")
    try:
        if proc.exists():
            rows = parse_proc_net_arp(proc.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        rows = []

    if not rows:
        for command, parser in (
            (["ip", "neigh", "show"], parse_ip_neigh),
            (["arp", "-an"], parse_bsd_arp),
            (["arp", "-a"], parse_windows_arp if platform.system().lower() == "windows"
             else parse_bsd_arp),
        ):
            output = _run_command(command)
            if not output.strip():
                continue
            rows = parser(output)
            if rows:
                log.info("Local ARP table from `%s` (%d entries)", " ".join(command), len(rows))
                break

    if not rows:
        log.warning("No local ARP entries found; the lease table will be empty.")

    frame = pd.DataFrame(rows, columns=["ip", "mac_address", "mode", "interface"])
    if frame.empty:
        frame = pd.DataFrame(columns=["ip", "mac_address", "mode"])

    frame["ip_address"] = frame["ip"]
    # An ARP table carries no hostname, so the address is the only label.
    frame["host"] = frame["ip_address"]
    frame["valid_time"] = None
    return frame


def scrape_router_dhcp(requested_browser: Optional[str] = None) -> pd.DataFrame:
    """
    Scrape the TP-Link router DHCP lease table via Playwright.

    The browser engine is detected at run time: ``pip install playwright``
    does not install a browser binary, and launching an engine whose binary is
    missing fails with "Executable doesn't exist".  Pass ``requested_browser``
    to force one; otherwise the first installed engine wins.

    The raw HTML dump is written to ``data/tplogin-arp.html``.

    Returns a DataFrame with columns:
        host, mac_address, ip_address, valid_time
    """
    from playwright.sync_api import sync_playwright

    # Detect the engine *before* prompting for a password: there is no point
    # asking for credentials we cannot use, and the missing-browser error is
    # the useful thing to surface.
    engine_name = first_available_browser(requested=requested_browser)
    password = get_password()

    with _driver_env_applied(_driver_env()), sync_playwright() as playwright:
        browser = getattr(playwright, engine_name).launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        try:
            page.goto("http://tplogin.cn/", timeout=30_000)
            page.get_by_role("textbox", name="密码 请输入管理员密码").click()
            page.get_by_role("textbox", name="密码 请输入管理员密码").fill(password)
            page.get_by_role("button", name="确 定").click()
            page.get_by_role("heading", name="路由设置").click()
            page.wait_for_timeout(3000)
            page.locator("#dhcpServer_rsMenu").get_by_text("DHCP服务器").click()
            page.wait_for_timeout(1000)

            table = page.locator("#dhcpLeaseTbl")
            table.scroll_into_view_if_needed()
            page.wait_for_timeout(1000)

            html = table.evaluate("el => el.outerHTML")
            with open(ROUTER_HTML_FILE, "w", encoding="utf-8") as fh:
                fh.write('<meta charset="utf-8">\n')
                fh.write(html)

        finally:
            context.close()
            browser.close()

    df = pd.read_html(ROUTER_HTML_FILE)[0]
    df.columns = ["host", "mac_address", "ip_address", "valid_time"]
    df = df.iloc[1:, :].reset_index(drop=True)
    return df


def fetch_leases(requested_browser: Optional[str] = None) -> pd.DataFrame:
    """
    The router's DHCP lease table, or this machine's ARP table as a fallback.

    A browser is needed to drive the router's web UI.  When none is installed
    the router is simply unreachable, so instead of dying the scan degrades to
    the OS-independent local ARP table — no browser, no credentials, no extra
    dependency — and still reports every host this machine can see.
    """
    try:
        return scrape_router_dhcp(requested_browser=requested_browser)
    except BrowserNotInstalled as exc:
        log.warning("Cannot scrape the router with Playwright: %s", exc)
        log.warning("Falling back to the local ARP table.")
        return local_arp_leases()


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

def resolve_and_test_hosts() -> pd.DataFrame:
    """
    Resolve configured hosts, run ICMP ping, and probe common ports.

    Returns a DataFrame with the results.
    """
    log.info("=" * 60)
    log.info("DNS Resolution & Target Testing")
    log.info("=" * 60)

    rows: List[Dict[str, Any]] = []

    for hostname in RESOLVE_HOSTS:
        ip = resolve_host(hostname)
        if ip is None:
            rows.append({
                "hostname": hostname,
                "resolved_ip": None,
                "icmp_ping": False,
                "detected_services": None,
            })
            continue

        log.info("[+] %s resolved to %s", hostname, ip)
        ping_ok = icmp_ping(ip)
        log.info("    ICMP ping: %s", "OK" if ping_ok else "FAILED")

        services: List[str] = []
        for port in tqdm(COMMON_PORTS, desc=f"  Probing {hostname}", leave=False):
            banner = probe_service(ip, port)
            svc = identify_service(banner, port, ip=ip)
            if svc:
                services.append(f"{port}:{svc}")
                log.info("    Port %d: %s", port, svc)

        rows.append({
            "hostname": hostname,
            "resolved_ip": ip,
            "icmp_ping": ping_ok,
            "detected_services": "; ".join(services) if services else None,
        })

    return pd.DataFrame(rows)


def run(
    port_timeout: Optional[float] = None,
    browser: Optional[str] = None,
) -> pd.DataFrame:
    """
    Main entry point: DNS resolution, router scrape, port scan, export.

    Args:
        port_timeout: Override for the port detection timeout (seconds).
            If ``None``, the value is resolved from the ``PORT_TIMEOUT``
            environment variable, then ``DEFAULT_PORT_TIMEOUT``.
        browser: Playwright engine to use for the router scrape.  If ``None``,
            the ``PW_BROWSER`` environment variable is consulted, and failing
            that the first installed engine is used.
    """
    global PORT_SCAN_TIMEOUT
    PORT_SCAN_TIMEOUT = resolve_port_timeout(port_timeout)
    log.info("Port detection timeout: %.3fs", PORT_SCAN_TIMEOUT)
    log.info("Output directory: %s", DATA_DIR.resolve())

    # ------------------------------------------------------------------
    # 1. DNS resolution & direct host testing
    # ------------------------------------------------------------------
    dns_df = resolve_and_test_hosts()
    dns_df.to_csv(DNS_CSV_FILE, index=False)
    log.info("[+] DNS resolution results saved to %s", DNS_CSV_FILE)

    # ------------------------------------------------------------------
    # 2. Router DHCP scrape, or the local ARP table when no browser exists
    # ------------------------------------------------------------------
    engine = (browser or os.environ.get("PW_BROWSER", "").strip() or None)
    # "auto" is an explicit spelling of the default, not an engine name.
    if engine is not None and engine.lower() == "auto":
        engine = None
    df = fetch_leases(requested_browser=engine)

    # ------------------------------------------------------------------
    # 3. ICMP ping check for each lease
    # ------------------------------------------------------------------
    log.info("Performing ICMP ping check...")
    df["icmp_ping"] = df.ip_address.progress_apply(icmp_ping)

    # ------------------------------------------------------------------
    # 4. Port probing & service identification
    # ------------------------------------------------------------------
    for port in tqdm(COMMON_PORTS, desc="Probing ports"):
        banners = df.ip_address.progress_apply(lambda ip: probe_service(ip, port))
        df[f"port_{port}_banner"] = banners
        df[f"port_{port}_service"] = banners.progress_apply(
            lambda banner, p=port: identify_service(banner, p, ip=None)
        )

    # ------------------------------------------------------------------
    # 5. Summarise detected services
    # ------------------------------------------------------------------
    def _summarise(row: pd.Series) -> Optional[str]:
        services: List[str] = []
        for port in COMMON_PORTS:
            svc = row.get(f"port_{port}_service")
            if pd.notna(svc):
                services.append(f"{port}:{svc}")
        return "; ".join(services) if services else None

    df["detected_services"] = df.progress_apply(_summarise, axis=1)

    # ------------------------------------------------------------------
    # 6. Write SSH helper scripts (under data/<host>/ssh.sh)
    # ------------------------------------------------------------------
    for entry in df.itertuples():
        # Find the SSH port (try common alternatives in priority order).
        ssh_port: Optional[int] = None
        for candidate in (22, 2222, 8022):
            svc = getattr(entry, f"port_{candidate}_service", None)
            if pd.notna(svc) and "SSH" in str(svc):
                ssh_port = candidate
                break
        if ssh_port is None:
            continue

        # Forward every other detected service through the SSH tunnel so that,
        # e.g., a Jupyter server detected on :8888 is reachable at
        # http://localhost:8888 on this machine.
        tunnels: List[Tuple[int, int]] = []
        for port in COMMON_PORTS:
            if port == ssh_port:
                continue
            svc = getattr(entry, f"port_{port}_service", None)
            if pd.notna(svc):
                tunnels.append((port, port))

        write_ssh_config(
            entry.host,
            entry.ip_address,
            ssh_port,
            tunnels=tunnels or None,
        )

    # ------------------------------------------------------------------
    # 7. Export enriched results
    # ------------------------------------------------------------------
    df.to_csv(ENRICHED_CSV_FILE, index=False)
    log.info("Analysis complete. Results saved to %s", ENRICHED_CSV_FILE)
    return df


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from dotenv import load_dotenv
    import os

    load_dotenv()  # loads .env from the current working directory
    args = parse_cli_args()
    run(port_timeout=args.port_timeout, browser=args.browser)