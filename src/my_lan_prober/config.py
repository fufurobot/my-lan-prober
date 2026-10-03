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
from typing import Dict, List, Optional, Sequence

from .browsers import BROWSER_NAMES
from .probes import COMMON_PORTS, DEFAULT_PORT_TIMEOUT, RESOLVE_HOSTS

__all__ = [
    "Config",
    "parse_cli_args",
    "resolve_port_timeout",
    "ensure_temp_env",
    "FETCHER_CHOICES",
    "BROWSER_NAMES",
    "BROWSER_CHOICES",
]

FETCHER_CHOICES = (
    "tplogin",
    "unix",
    "windows",
    "openwrt",
    "hosts",
    "dns",
    "resolved",
    "ssh",
    "all",
    "auto",
)

#: ``auto`` is accepted as an explicit spelling of the default, so a user can
#: write the behaviour the help text and `design.md` describe.
BROWSER_CHOICES = (*BROWSER_NAMES, "auto")

DEFAULT_OUTPUT = "data/tplogin-arp-enriched.csv"

#: Default bound on the SSH expansion walk: how many neighbour tables it
#: collects.  One is "just the hop I named"; more follows what that hop saw.
DEFAULT_EXPAND_DEPTH = 2

#: Variables every child process consults, in Playwright's own priority order.
TEMP_ENV_VARS: Sequence[str] = ("TMPDIR", "TMP", "TEMP")

#: Working directory for :func:`ensure_temp_env`.
TEMP_ENV_CWD = Path.cwd()


def _temp_dir_is_usable(path: Path) -> bool:
    """Whether a file can really be created in ``path`` (see ``fetchers``)."""
    from .fetchers import PlaywrightFetcher

    return PlaywrightFetcher.temp_dir_is_usable(path)


def ensure_temp_env(base_dir: Optional[Path] = None) -> Optional[Path]:
    """Point ``TMPDIR``/``TMP``/``TEMP`` at a writable directory.

    Playwright on CPython 3.10 on Windows fails to launch its Node driver when
    the inherited temp directory is not writable::

        PermissionError: [WinError 5] Access is denied
          ... asyncio\\windows_utils.py: pipe() -> CreateFile()

    (note that this surfaces as a *pipe* failure while the driver starts, not
    as the ``mkdtemp`` EPERM of the 3.13-era traceback — same root cause, a
    temp directory the process cannot use).

    Call this once, as early as possible in ``main()``, so the whole process
    tree inherits the repaired values.  Playwright's Node driver reads
    ``os.tmpdir()``, which honours ``TMPDIR`` → ``TMP`` → ``TEMP`` without any
    fallback of its own, while CPython's own ``tempfile`` silently probes and
    falls through.  That asymmetry is why the fix has to be an environment
    variable rather than a Python-level fallback.

    Returns the directory that was exported, or ``None`` when no candidate was
    usable (in which case the environment is left exactly as it was — a broken
    temp directory is a better failure than a silently substituted one).
    """
    base = Path(base_dir) if base_dir is not None else TEMP_ENV_CWD

    candidates: List[Path] = []
    for name in TEMP_ENV_VARS:
        raw = os.environ.get(name, "").strip()
        # A POSIX-style path only exists inside MSYS2; a native Windows child
        # cannot use it, so it is never a candidate there.
        if raw and not (os.name == "nt" and raw.startswith("/")):
            candidates.append(Path(raw))
    candidates.append(base / "playwright-temp")

    seen = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        if _temp_dir_is_usable(candidate):
            exported = str(candidate.resolve())
            for name in TEMP_ENV_VARS:
                os.environ[name] = exported
            return Path(exported)

    return None


def _fetcher_selection(raw: str) -> str:
    """Validate a ``--fetcher`` value without importing the registry eagerly.

    The value is a *set* of sources, so argparse's ``choices=`` cannot express
    it.  Validation happens here so a typo fails at argument parsing, with the
    list of known names, rather than deep inside a scan.
    """
    names = [part.strip() for part in raw.split(",") if part.strip()]
    if not names:
        raise argparse.ArgumentTypeError("--fetcher needs at least one source name")

    modes = {"auto", "all"}
    unknown = [name for name in names if name not in FETCHER_CHOICES and name not in modes]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown ARP source {', '.join(repr(name) for name in unknown)}; "
            f"known sources: {', '.join(FETCHER_CHOICES)}"
        )
    # A mode and a name in one selection would be ambiguous ("all,unix"), and
    # commas are how the modes are told apart from names, so they are exclusive.
    if len(names) > 1 and any(name in modes for name in names):
        raise argparse.ArgumentTypeError(
            f"'auto' and 'all' must be used alone, not mixed with source names: {raw!r}"
        )
    return ",".join(names)


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
        "-t",
        "--port-timeout",
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
        type=_fetcher_selection,
        default=None,
        metavar="NAME[,NAME...]",
        help=(
            "ARP source(s) to consult, comma-separated, or 'all' for every "
            "implemented source, or 'auto' for the non-invasive set. "
            f"Known: {', '.join(FETCHER_CHOICES)}. Default: tplogin."
        ),
    )
    parser.add_argument(
        "--ssh-hop",
        default=None,
        metavar="HOST",
        help=("SSH host to expand through: its neighbour table is read and merged. Env: SSH_HOP."),
    )
    parser.add_argument(
        "--expand",
        action="store_true",
        default=None,
        help=(
            "Enable ARP expansion (the SSH walk). Off by default: logging "
            "into other machines is invasive. Env: ARP_EXPAND."
        ),
    )
    parser.add_argument(
        "--expand-depth",
        type=int,
        default=None,
        metavar="N",
        help=(
            "How many neighbour tables the SSH walk collects. Default: "
            f"{DEFAULT_EXPAND_DEPTH}. Env: ARP_EXPAND_DEPTH."
        ),
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
        choices=BROWSER_CHOICES,
        default=None,
        metavar="NAME",
        help=(
            "Playwright browser engine to use, or 'auto' to detect the first "
            "installed engine ("
            + ", ".join(BROWSER_NAMES)
            + "). Default: auto. Installing the Python package does not "
            "install a browser; run `playwright install` for that."
        ),
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


def _env_flag(name: str) -> bool:
    """Whether a boolean environment variable is switched on.

    Accepts the spellings people actually write in a shell or a ``.env`` file
    (``1``, ``true``, ``yes``, ``on``) and treats anything else — including a
    variable that is merely present — as off, so ``ARP_EXPAND=0`` means what it
    says rather than "set, therefore true".
    """
    raw = os.environ.get(name, "").strip().lower()
    return raw in ("1", "true", "yes", "on")


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
    #: SSH host to expand the ARP table through (``--ssh-hop``/``SSH_HOP``).
    ssh_hop: Optional[str] = None
    #: Whether expansion is switched on at all (``--expand``/``ARP_EXPAND``).
    expand: bool = False
    #: How many neighbour tables the expansion walk collects.
    expand_depth: int = DEFAULT_EXPAND_DEPTH

    #: Kept out of ``repr`` so a logged config never leaks the password.
    _SECRET_FIELDS = ("password",)

    def __repr__(self) -> str:  # pragma: no cover - trivial formatting
        shown: Dict[str, object] = {
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
            args.unsafe_tplogin_password or os.environ.get("TPLOGIN_PASSWORD", "").strip() or None
        )

        browser = args.browser or os.environ.get("PW_BROWSER", "").strip() or None
        # "auto" is an explicit spelling of the default, not an engine name.
        if browser is not None and browser.lower() == "auto":
            browser = None

        log_level = os.environ.get("PROBESTACK_LOG_LEVEL", "").strip().upper() or "INFO"

        ssh_hop = args.ssh_hop or os.environ.get("SSH_HOP", "").strip() or None

        expand = bool(args.expand) or _env_flag("ARP_EXPAND")

        expand_depth = args.expand_depth or _env_int("ARP_EXPAND_DEPTH") or DEFAULT_EXPAND_DEPTH
        if expand_depth < 1:
            expand_depth = 1

        return cls(
            port_timeout=port_timeout,
            workers=workers,
            resolve_hosts=list(resolve_hosts),
            output=output,
            fetcher=fetcher,
            password=password,
            browser=browser,
            log_level=log_level,
            ssh_hop=ssh_hop,
            expand=expand,
            expand_depth=expand_depth,
        )
