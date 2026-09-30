"""
Network service discovery and router DHCP lease scraper.

Resolves configured hostnames, probes common ports, identifies services
(including Jupyter on port 8888), scrapes TP-Link router DHCP leases via
Playwright, and enriches lease data with ICMP ping and port scan results.

Port detection timeout (TCP connect phase) can be configured via:
  * CLI:  --port-timeout SECONDS  (or -t SECONDS)
  * ENV:  PORT_TIMEOUT=SECONDS
  * Default: 0.1s (LAN probes should be near-instant)

Precedence: CLI flag > environment variable > default.
"""

import argparse
import re
import socket
import subprocess
import platform
import os
import json
import logging
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

import pandas as pd
from tqdm.auto import tqdm
from playwright.sync_api import Playwright, sync_playwright

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

# Output files
SSH_CONFIG_FILENAME: str = "ssh.sh"
ROUTER_HTML_FILE: str = "tplogin-arp.html"
DNS_CSV_FILE: str = "dns-resolved-hosts.csv"
ENRICHED_CSV_FILE: str = "tplogin-arp-enriched.csv"

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

    Args:
        host: Logical host name (used as the output directory).
        ip: Target IP for SSH.
        port: SSH port on the target.
        tunnels: Optional list of ``(local_port, remote_port)`` pairs. Each
            pair is emitted as ``-L local_port:localhost:remote_port`` so the
            remote service becomes reachable on the local machine.
        local_port_offset: Added to every local port to avoid collisions when
            several host scripts are run simultaneously (e.g. 1000 -> 8888
            becomes local 9888).
    """
    path = Path(host)
    path.mkdir(exist_ok=True)
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


def scrape_router_dhcp() -> pd.DataFrame:
    """
    Scrape the TP-Link router DHCP lease table via Playwright.

    Returns a DataFrame with columns:
        host, mac_address, ip_address, valid_time
    """
    password = get_password()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=False)
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


def run(port_timeout: Optional[float] = None) -> pd.DataFrame:
    """
    Main entry point: DNS resolution, router scrape, port scan, export.

    Args:
        port_timeout: Override for the port detection timeout (seconds).
            If ``None``, the value is resolved from the ``PORT_TIMEOUT``
            environment variable, then ``DEFAULT_PORT_TIMEOUT``.
    """
    global PORT_SCAN_TIMEOUT
    PORT_SCAN_TIMEOUT = resolve_port_timeout(port_timeout)
    log.info("Port detection timeout: %.3fs", PORT_SCAN_TIMEOUT)

    # ------------------------------------------------------------------
    # 1. DNS resolution & direct host testing
    # ------------------------------------------------------------------
    dns_df = resolve_and_test_hosts()
    dns_df.to_csv(DNS_CSV_FILE, index=False)
    log.info("[+] DNS resolution results saved to %s", DNS_CSV_FILE)

    # ------------------------------------------------------------------
    # 2. Router DHCP scrape
    # ------------------------------------------------------------------
    df = scrape_router_dhcp()

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
    # 6. Write SSH helper scripts
    # ------------------------------------------------------------------
    for entry in df.itertuples():
        # if not entry.icmp_ping:
        #     continue
        for ssh_port in (22, 2222, 8022):
            svc = getattr(entry, f"port_{ssh_port}_service", None)
            if pd.notna(svc) and "SSH" in str(svc):
                write_ssh_config(entry.host, entry.ip_address, ssh_port)
                break

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
    args = parse_cli_args()
    run(port_timeout=args.port_timeout)