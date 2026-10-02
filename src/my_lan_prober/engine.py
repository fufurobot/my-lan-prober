"""The engine: the pipeline that ports ``tplogin-minimal.py``'s ``run()``.

Steps, in the order of the tested original:

1. resolve the configured hostnames, ping them, probe their common ports;
2. fetch the router's DHCP lease table (with source fallback);
3. ping every lease;
4. probe every common port on every lease and identify the service;
5. summarise ``port:service`` per host;
6. write a per-host ``ssh.sh`` that tunnels every other detected service;
7. export the unified CSV.

Each step is a method so tests can substitute any of them.
"""

from __future__ import annotations

import contextlib
import logging
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from .config import Config
from .fetchers import (
    TPLoginFetcher,
    UnixArpFetcher,
    WindowsArpFetcher,
    default_fetcher_chain,
)
from .probes import ServiceIdentifier, icmp_ping, probe_service

log = logging.getLogger(__name__)

__all__ = ["Engine", "write_ssh_config", "build_fetcher"]

#: SSH ports tried in priority order when writing the helper script.
SSH_PORT_CANDIDATES = (22, 2222, 8022)

SSH_CONFIG_FILENAME = "ssh.sh"


def write_ssh_config(
    data_dir: Path,
    host: str,
    ip: str,
    port: int,
    tunnels: Optional[List[Tuple[int, int]]] = None,
    local_port_offset: int = 0,
) -> Path:
    """Write ``<data_dir>/<host>/ssh.sh`` forwarding each tunnelled service.

    Args:
        local_port_offset: Added to every local port so several host scripts
            can run at once without colliding (e.g. 1000 turns local 8888
            into 9888).
    """
    directory = Path(data_dir) / host
    directory.mkdir(parents=True, exist_ok=True)
    config_path = directory / SSH_CONFIG_FILENAME

    parts: List[str] = [
        "ssh",
        f"-p {port}",
        # Keep the tunnel alive across idle periods, and fail fast if a local
        # port is already bound so a tunnel is never silently dropped.
        "-o ServerAliveInterval=30",
        "-o ServerAliveCountMax=3",
        "-o ExitOnForwardFailure=yes",
    ]

    if tunnels:
        seen = set()
        for local_port, remote_port in tunnels:
            if remote_port in seen:
                continue
            seen.add(remote_port)
            parts.append(f"-L {local_port + local_port_offset}:localhost:{remote_port}")

    parts.append(ip)

    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write("#!/usr/bin/env bash\n")
        handle.write(" \\\n    ".join(parts))
        handle.write("\n")

    # The script must be runnable, but Windows filesystems often refuse the
    # mode bits outright — that is not a reason to fail the whole scan.
    with contextlib.suppress(OSError):
        config_path.chmod(0o755)

    if tunnels:
        forwarded = ", ".join(f"{lp + local_port_offset}->{rp}" for lp, rp in tunnels)
        log.info(
            "Wrote SSH config for %s -> %s:%d (%d tunnel(s): %s)",
            host,
            ip,
            port,
            len(tunnels),
            forwarded,
        )
    else:
        log.info("Wrote SSH config for %s -> %s:%d (no tunnels)", host, ip, port)
    return config_path


def build_fetcher(kind: str, browser: Optional[str] = None) -> Any:
    """Instantiate the requested ARP source.

    ``browser`` names the Playwright engine to use; ``None`` auto-detects the
    first engine this machine actually has installed.
    """
    if kind == "tplogin":
        return TPLoginFetcher(browser=browser)
    if kind == "unix":
        return UnixArpFetcher()
    if kind == "windows":
        return WindowsArpFetcher()
    if kind == "openwrt":
        from .fetchers import OpenWRTFetcher

        return OpenWRTFetcher()
    # "auto"/anything else: router first, then the local table.
    return default_fetcher_chain(browser=browser)


class Engine:
    """Run the full LAN-probing pipeline."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.identifier = ServiceIdentifier(
            deep_probe=True, http_timeout=int(max(1, config.port_timeout * 10))
        )

    # -- overridable steps ---------------------------------------------
    def resolve(self, hostname: str) -> Optional[str]:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror as exc:
            log.warning("DNS resolution failed for %s: %s", hostname, exc)
            return None

    def ping(self, ip: str) -> bool:
        return icmp_ping(ip)

    def probe(self, ip: str, port: int) -> Optional[str]:
        return probe_service(ip, port, timeout=self.config.port_timeout)

    def fetch_leases(self) -> pd.DataFrame:
        return build_fetcher(self.config.fetcher, browser=self.config.browser).iptable()

    def identify(self, banner: Optional[str], port: int, ip: Optional[str] = None):
        return self.identifier.identify(banner, port, ip=ip)

    # -- pipeline -------------------------------------------------------
    def run(self) -> pd.DataFrame:
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        log.info("Port detection timeout: %.3fs", self.config.port_timeout)
        log.info("Output directory: %s", self.config.data_dir.resolve())

        # 1. Resolve & directly test the configured hostnames.
        dns_frame = self.resolve_and_test_hosts()
        dns_frame.to_csv(self.config.dns_csv, index=False)
        log.info("[+] DNS resolution results saved to %s", self.config.dns_csv)

        # 2. Router DHCP lease table.
        frame = self.normalise_leases(self.fetch_leases())

        # 3. ICMP ping each lease.
        log.info("Performing ICMP ping check...")
        if len(frame):
            frame["icmp_ping"] = frame["ip_address"].map(self.ping)
        else:
            frame["icmp_ping"] = pd.Series(dtype=bool)

        # 4. Port probing & service identification.
        for port in self.config.ports:
            if len(frame):
                banners = frame["ip_address"].map(lambda ip, p=port: self.probe(ip, p))
            else:
                banners = pd.Series(dtype=object)
            frame[f"port_{port}_banner"] = banners
            frame[f"port_{port}_service"] = banners.map(
                lambda banner, p=port: self.identify(banner, p, ip=None)
            )

        # 5. Summarise detected services per host.
        frame["detected_services"] = frame.apply(self._summarise, axis=1)

        # 6. Write SSH helper scripts.
        self.write_ssh_scripts(frame)

        # 7. Export.
        frame.to_csv(self.config.output, index=False)
        log.info("Analysis complete. Results saved to %s", self.config.output)
        return frame

    # -- helpers --------------------------------------------------------
    @staticmethod
    def normalise_leases(frame: pd.DataFrame) -> pd.DataFrame:
        """Give every ARP/DHCP source the same shape.

        The DHCP scrapers return ``ip_address``/``host``, while the ARP
        fetchers return ``ip``/``mac_address``.  Downstream steps only need
        ``ip_address``, ``mac_address``, and something to call the host.
        """
        frame = frame.copy()

        if "ip_address" not in frame.columns and "ip" in frame.columns:
            frame["ip_address"] = frame["ip"]
        if "ip" not in frame.columns:
            frame["ip"] = frame.get("ip_address")

        if "mac_address" not in frame.columns:
            frame["mac_address"] = None

        if "host" not in frame.columns:
            # ARP tables carry no hostname, so fall back to the address.
            frame["host"] = frame["ip_address"]

        if "valid_time" not in frame.columns:
            frame["valid_time"] = None

        frame["host"] = frame["host"].fillna(frame["ip_address"])
        return frame

    def resolve_and_test_hosts(self) -> pd.DataFrame:
        rows: List[Dict[str, Any]] = []
        for hostname in self.config.resolve_hosts:
            ip = self.resolve(hostname)
            if ip is None:
                rows.append(
                    {
                        "hostname": hostname,
                        "resolved_ip": None,
                        "icmp_ping": False,
                        "detected_services": None,
                    }
                )
                continue

            log.info("[+] %s resolved to %s", hostname, ip)
            services: List[str] = []
            for port in self.config.ports:
                banner = self.probe(ip, port)
                service = self.identify(banner, port, ip=None)
                if service:
                    services.append(f"{port}:{service}")
                    log.info("    Port %d: %s", port, service)

            rows.append(
                {
                    "hostname": hostname,
                    "resolved_ip": ip,
                    "icmp_ping": self.ping(ip),
                    "detected_services": "; ".join(services) if services else None,
                }
            )
        return pd.DataFrame(rows)

    def _summarise(self, row: pd.Series) -> Optional[str]:
        services: List[str] = []
        for port in self.config.ports:
            service = row.get(f"port_{port}_service")
            if pd.notna(service):
                services.append(f"{port}:{service}")
        return "; ".join(services) if services else None

    def _ssh_port(self, row: pd.Series) -> Optional[int]:
        for candidate in SSH_PORT_CANDIDATES:
            service = row.get(f"port_{candidate}_service")
            if pd.notna(service) and "SSH" in str(service):
                return candidate
        return None

    def write_ssh_scripts(self, frame: pd.DataFrame) -> None:
        for _, row in frame.iterrows():
            ssh_port = self._ssh_port(row)
            if ssh_port is None:
                continue

            # Forward every *other* detected service so, e.g., a Jupyter
            # server on :8888 becomes reachable at http://localhost:8888.
            tunnels: List[Tuple[int, int]] = []
            for port in self.config.ports:
                if port == ssh_port:
                    continue
                if pd.notna(row.get(f"port_{port}_service")):
                    tunnels.append((port, port))

            write_ssh_config(
                self.config.data_dir,
                str(row["host"]),
                str(row["ip_address"]),
                ssh_port,
                tunnels=tunnels or None,
            )
