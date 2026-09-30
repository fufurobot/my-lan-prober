"""Configuration: CLI flag > environment variable > default.

``design.md`` § 9.  Nothing is hard-coded; every knob has all three levels.
The password is deliberately excluded from ``repr`` so a logged config can
never leak it.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from .probes import COMMON_PORTS, DEFAULT_PORT_TIMEOUT, RESOLVE_HOSTS

__all__ = ["Config", "parse_cli_args", "resolve_port_timeout", "FETCHER_CHOICES"]

FETCHER_CHOICES = ("tplogin", "unix", "windows", "openwrt", "auto")

DEFAULT_OUTPUT = "data/tplogin-arp-enriched.csv"


def parse_cli_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="my-lan-prober",
        description=(
            "Probe a LAN, identify the services behind every open port, and "
            "enrich the router's DHCP lease table."
        ),
    )
    parser.add_argument(
        "-t", "--port-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "TCP connect timeout for port detection. "
            f"Default: {DEFAULT_PORT_TIMEOUT}s. "
            "Overrides the PORT_TIMEOUT environment variable."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help="Parallel worker threads. Defaults to os.cpu_count().",
    )
    parser.add_argument(
        "--resolve-host",
        action="append",
        default=None,
        metavar="HOST",
        help="Hostname to resolve and probe directly. Repeatable.",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="PATH",
        help=f"Unified output CSV. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--fetcher",
        choices=FETCHER_CHOICES,
        default=None,
        help="Preferred source of the LAN address table.",
    )
    parser.add_argument(
        "--unsafe-tplogin-password",
        default=None,
        metavar="PW",
        help=(
            "NON-INTERACTIVE router password. WARNING: argv is visible to "
            "other processes and lands in shell history. Prefer the "
            "TPLOGIN_PASSWORD environment variable."
        ),
    )
    parser.add_argument(
        "--browser",
        default=None,
        metavar="NAME",
        help="Playwright browser engine (chromium/firefox/webkit).",
    )
    return parser.parse_args(argv)


def resolve_port_timeout(cli_value: Optional[float]) -> float:
    """Effective port timeout: CLI, then ``PORT_TIMEOUT``, then default."""
    if cli_value is not None:
        if cli_value <= 0:
            raise ValueError(f"--port-timeout must be > 0 (got {cli_value!r})")
        return float(cli_value)

    env_value = os.environ.get("PORT_TIMEOUT", "").strip()
    if env_value:
        try:
            parsed = float(env_value)
            if parsed > 0:
                return parsed
        except ValueError:
            pass
    return DEFAULT_PORT_TIMEOUT


def _env_float(name: str) -> Optional[float]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _env_int(name: str) -> Optional[int]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class Config:
    """Every runtime knob, fully resolved."""

    port_timeout: float = DEFAULT_PORT_TIMEOUT
    workers: int = 1
    resolve_hosts: List[str] = field(default_factory=lambda: list(RESOLVE_HOSTS))
    output: str = DEFAULT_OUTPUT
    fetcher: str = "tplogin"
    password: Optional[str] = None
    browser: Optional[str] = None
    log_level: str = "INFO"
    ports: List[int] = field(default_factory=lambda: list(COMMON_PORTS))

    #: Kept out of ``repr`` so a logged config never leaks the password.
    _SECRET_FIELDS = ("password",)

    def __repr__(self) -> str:  # pragma: no cover - trivial formatting
        shown = {
            key: ("***" if key in self._SECRET_FIELDS else value)
            for key, value in self.__dict__.items()
        }
        parts = ", ".join(f"{key}={value!r}" for key, value in shown.items())
        return f"Config({parts})"

    @property
    def data_dir(self) -> Path:
        """Directory the outputs live in, derived from ``output``."""
        parent = Path(self.output).parent
        return parent if str(parent) else Path(".")

    @property
    def dns_csv(self) -> Path:
        return self.data_dir / "dns-resolved-hosts.csv"

    @property
    def router_html(self) -> Path:
        return self.data_dir / "tplogin-arp.html"

    @classmethod
    def resolve(cls, argv: Optional[Sequence[str]] = None) -> "Config":
        """Build a config from ``argv``, the environment, and the defaults."""
        args = parse_cli_args(argv)

        # resolve_port_timeout already handles CLI > ENV > default.
        port_timeout = resolve_port_timeout(args.port_timeout)

        workers = args.workers or _env_int("SCAN_WORKERS") or (os.cpu_count() or 1)
        if workers < 1:
            workers = 1

        resolve_hosts = args.resolve_host or _env_list("RESOLVE_HOSTS", RESOLVE_HOSTS)

        output = args.output or os.environ.get("OUTPUT_CSV", "").strip() or DEFAULT_OUTPUT

        fetcher = args.fetcher or os.environ.get("ARP_FETCHER", "").strip() or "tplogin"

        password = (
            args.unsafe_tplogin_password
            or os.environ.get("TPLOGIN_PASSWORD", "").strip()
            or None
        )

        browser = args.browser or os.environ.get("PW_BROWSER", "").strip() or None

        log_level = os.environ.get("PROBESTACK_LOG_LEVEL", "").strip().upper() or "INFO"

        return cls(
            port_timeout=port_timeout,
            workers=workers,
            resolve_hosts=list(resolve_hosts),
            output=output,
            fetcher=fetcher,
            password=password,
            browser=browser,
            log_level=log_level,
        )
