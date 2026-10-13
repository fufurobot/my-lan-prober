"""Configuration: CLI flag > environment variable > default.

``design.md`` § 9.  Nothing is hard-coded; every knob has all three levels.
The password is deliberately excluded from ``repr`` so a logged config can
never leak it.
"""

from __future__ import annotations

import argparse
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .browsers import BROWSER_NAMES
from .probes import COMMON_PORTS, DEFAULT_PORT_TIMEOUT, RESOLVE_HOSTS

log = logging.getLogger(__name__)

__all__ = [
    "Config",
    "parse_cli_args",
    "resolve_port_timeout",
    "ensure_temp_env",
    "configure_logging",
    "LOG_LEVELS",
    "VERBOSE_DEFAULT_LEVEL",
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
    "mdns",
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

#: Default cap on how many ARP sources run at once inside one priority level.
#: Chosen to be comfortably above the number of *local* sources (which are
#: cheap and should all go at once) while still bounding a selection that
#: fans out over SSH.
DEFAULT_MAX_TASK = 8

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
            log.debug("temp candidate from %s: %s", name, raw)
            candidates.append(Path(raw))
        else:
            log.debug(
                "ignoring %s=%r: empty, or an MSYS2 path a native child cannot use", name, raw
            )
    candidates.append(base / "playwright-temp")

    seen = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            log.debug("skipping duplicate temp candidate %s", candidate)
            continue
        seen.add(key)
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.debug("temp candidate %s is not creatable: %s", candidate, exc)
            continue
        if _temp_dir_is_usable(candidate):
            exported = str(candidate.resolve())
            for name in TEMP_ENV_VARS:
                log.debug("exporting %s=%s for child processes", name, exported)
                os.environ[name] = exported
            log.info("using %s for TMPDIR/TMP/TEMP", exported)
            return Path(exported)
        log.debug("temp candidate %s exists but is not writable; trying the next", candidate)

    log.warning(
        "no usable temp directory among %d candidate(s); leaving the environment unchanged",
        len(candidates),
    )
    return None


def _fetcher_selection(raw: str) -> str:
    """Validate a ``--fetcher`` value without importing the registry eagerly.

    The value is a *set* of sources, so argparse's ``choices=`` cannot express
    it.  Validation happens here so a typo fails at argument parsing, with the
    list of known names, rather than deep inside a scan.
    """
    names = [part.strip() for part in raw.split(",") if part.strip()]
    if not names:
        log.warning("--fetcher %r names no source at all", raw)
        raise argparse.ArgumentTypeError("--fetcher needs at least one source name")

    modes = {"auto", "all"}
    unknown: List[str] = []
    for name in names:
        if name in FETCHER_CHOICES:
            log.debug("%r is a known source name", name)
            continue
        if name in modes:
            log.debug("%r is a selection mode, not a source name", name)
            continue
        log.debug("%r is neither a known source nor a mode", name)
        unknown.append(name)
    if unknown:
        log.warning(
            "--fetcher %r names %d unknown source(s): %s", raw, len(unknown), ", ".join(unknown)
        )
        raise argparse.ArgumentTypeError(
            f"unknown ARP source {', '.join(repr(name) for name in unknown)}; "
            f"known sources: {', '.join(FETCHER_CHOICES)}"
        )
    # A mode and a name in one selection would be ambiguous ("all,unix"), and
    # commas are how the modes are told apart from names, so they are exclusive.
    if len(names) > 1 and any(name in modes for name in names):
        log.warning("--fetcher %r mixes a mode with explicit source names", raw)
        raise argparse.ArgumentTypeError(
            f"'auto' and 'all' must be used alone, not mixed with source names: {raw!r}"
        )
    log.debug("--fetcher %r accepted as %s", raw, ",".join(names))
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
        "--verbose",
        "-v",
        action=_VerboseAction,
        nargs="?",
        default=None,
        metavar="LEVEL",
        help=(
            "Log more. Bare --verbose means DEBUG; an explicit level may "
            f"follow ({', '.join(LOG_LEVELS)}). Overrides "
            "PROBESTACK_LOG_LEVEL."
        ),
    )
    parser.add_argument(
        "--max-task",
        type=int,
        default=None,
        metavar="N",
        help=(
            "How many ARP sources may run at once within one priority level. "
            "Sources on the same level already run concurrently; this bounds "
            f"them. Default: {DEFAULT_MAX_TASK}. Env: ARP_MAX_TASK."
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


def _first_set(*sources: Tuple[str, Any]) -> Any:
    """The first value that is neither ``None`` nor empty, logging each step.

    The precedence chains in :meth:`Config.resolve` used to be ``a or b or c``
    expressions, which are a single decision nobody can see the outcome of.
    Naming each source turns "why is this value what it is?" into a log line.
    """
    for label, value in sources:
        if value:
            log.debug("%s supplied %r", label, value)
            return value
        log.debug("%s supplied nothing; trying the next source", label)
    return None


def resolve_port_timeout(cli_value: Optional[float]) -> float:
    """Effective port timeout: CLI, then ``PORT_TIMEOUT``, then default."""
    if cli_value is not None:
        if cli_value <= 0:
            log.warning("--port-timeout %r is not positive", cli_value)
            raise ValueError(f"--port-timeout must be > 0 (got {cli_value!r})")
        log.debug("port timeout %.3fs came from --port-timeout", float(cli_value))
        return float(cli_value)

    env_value = os.environ.get("PORT_TIMEOUT", "").strip()
    if env_value:
        try:
            parsed = float(env_value)
            if parsed > 0:
                log.debug("port timeout %.3fs came from PORT_TIMEOUT", parsed)
                return parsed
            log.debug("PORT_TIMEOUT=%r is not positive; using the default instead", env_value)
        except ValueError as exc:
            log.debug("PORT_TIMEOUT=%r is not a number (%s); using the default", env_value, exc)
    else:
        log.debug("PORT_TIMEOUT is unset; using the default")
    log.debug("port timeout falls back to the default %.3fs", DEFAULT_PORT_TIMEOUT)
    return DEFAULT_PORT_TIMEOUT


def _env_float(name: str) -> Optional[float]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        log.debug("%s is unset or blank; no value", name)
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        log.debug("%s=%r is not a number (%s); ignoring it", name, raw, exc)
        return None
    if value > 0:
        log.debug("%s=%s accepted", name, value)
        return value
    log.debug("%s=%s is not positive; ignoring it", name, value)
    return None


def _env_int(name: str) -> Optional[int]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        log.debug("%s is unset or blank; no value", name)
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        log.debug("%s=%r is not an integer (%s); ignoring it", name, raw, exc)
        return None
    if value > 0:
        log.debug("%s=%d accepted", name, value)
        return value
    log.debug("%s=%d is not positive; ignoring it", name, value)
    return None


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        log.debug("%s is unset or blank; using the %d default item(s)", name, len(default))
        return list(default)
    items = [item.strip() for item in raw.split(",") if item.strip()]
    log.debug("%s=%r parsed into %d item(s): %s", name, raw, len(items), ", ".join(items))
    return items


def _env_flag(name: str) -> bool:
    """Whether a boolean environment variable is switched on.

    Accepts the spellings people actually write in a shell or a ``.env`` file
    (``1``, ``true``, ``yes``, ``on``) and treats anything else — including a
    variable that is merely present — as off, so ``ARP_EXPAND=0`` means what it
    says rather than "set, therefore true".
    """
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        log.debug("%s=%r reads as on", name, raw)
        return True
    log.debug("%s=%r does not read as on; treating it as off", name, raw)
    return False


#: Logging levels ``--verbose`` accepts, in ``logging``'s own order.
LOG_LEVELS: Sequence[str] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: What a bare ``--verbose`` means.
VERBOSE_DEFAULT_LEVEL = "DEBUG"


class _VerboseAction(argparse.Action):
    """``--verbose`` with an *optional* value.

    ``nargs="?"`` is the obvious spelling and it is wrong here: it consumes any
    following token that does not look like an option, so ``--verbose
    --output`` is fine but a bare ``--verbose`` followed by a positional would
    silently swallow it — and ``--verbose WARNING`` and ``--verbose localhost``
    become indistinguishable, so a typo'd level is accepted as a value and the
    run continues at a level nobody asked for.

    This action consumes the next token only when it *is* a known level name,
    which makes the two cases unambiguous:

    * the token is a level → use it;
    * anything else → bare ``--verbose``, meaning DEBUG, and the token is left
      for the rest of the parser.

    The one thing it cannot do is accept a level name that is also a legitimate
    positional. No such collision exists here (the values are hostnames and
    paths), and the alternative — requiring ``--verbose=LEVEL`` — is worse
    ergonomics for the common case.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        level = VERBOSE_DEFAULT_LEVEL
        if values is not None:
            candidate = str(values).strip().upper()
            if candidate not in LOG_LEVELS:
                logging.getLogger(__name__).warning(
                    "%s got %r, which is not one of %s",
                    option_string,
                    values,
                    ", ".join(LOG_LEVELS),
                )
                parser.error(
                    f"argument {option_string}: invalid level {values!r} "
                    f"(choose from {', '.join(LOG_LEVELS)})"
                )
            level = candidate
            logging.getLogger(__name__).debug("%s selected level %s", option_string, level)
        else:
            logging.getLogger(__name__).debug(
                "bare %s; using the default level %s", option_string, VERBOSE_DEFAULT_LEVEL
            )
        # Repeating the flag must not *lower* the level: `--verbose -v` is a
        # person double-tapping, not a request for less output.
        previous = getattr(namespace, self.dest, None)
        if previous is not None and LOG_LEVELS.index(previous) < LOG_LEVELS.index(level):
            logging.getLogger(__name__).debug(
                "%s repeats the flag; keeping the lower level %s over %s",
                option_string,
                previous,
                level,
            )
            level = previous
        setattr(namespace, self.dest, level)


def _resolve_log_level(verbose: Optional[str]) -> str:
    """Effective level: ``--verbose`` > ``PROBESTACK_LOG_LEVEL`` > ``INFO``.

    The flag is an explicit request for this run, so it beats the ambient
    environment variable, in the same direction as every other knob.
    """
    if verbose:
        log.debug("log level %s came from --verbose", verbose.strip().upper())
        return verbose.strip().upper()

    env_level = os.environ.get("PROBESTACK_LOG_LEVEL", "").strip().upper()
    if env_level in LOG_LEVELS:
        log.debug("log level %s came from PROBESTACK_LOG_LEVEL", env_level)
        return env_level
    # An unparseable level is not worth failing a scan over, but going silent
    # about it would be worse: the user would think they had set it.
    if env_level:
        logging.getLogger(__name__).warning(
            "ignoring PROBESTACK_LOG_LEVEL=%r; expected one of %s",
            env_level,
            ", ".join(LOG_LEVELS),
        )
    else:
        log.debug("PROBESTACK_LOG_LEVEL is unset; defaulting to INFO")
    return "INFO"


def configure_logging(level: str) -> int:
    """Apply ``level`` to the root logger, and return it as a number.

    Nothing did this before: ``Config.log_level`` was resolved from the
    environment and then never used, so ``PROBESTACK_LOG_LEVEL=DEBUG`` was
    silently inert and every ``log.debug`` in the codebase was unreachable.

    ``force=True`` replaces a handler another library installed (some
    entry points do call ``basicConfig`` first); without it the first caller
    wins and our level would be ignored.
    """
    numeric = logging.getLevelName(level.strip().upper())
    if not isinstance(numeric, int):  # pragma: no cover - argparse validates
        logging.getLogger(__name__).warning("unknown log level %r; falling back to INFO", level)
        numeric = logging.INFO
    logging.basicConfig(
        level=numeric,
        format="%(levelname)-8s %(name)s: %(message)s",
        force=True,
    )
    logging.getLogger(__name__).debug("root logger set to %s (%d)", level, numeric)
    return numeric


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
    #: How many ARP sources may run at once within one priority level.
    max_task: int = DEFAULT_MAX_TASK

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

        workers = _first_set(
            ("--workers", args.workers),
            ("SCAN_WORKERS", _env_int("SCAN_WORKERS")),
            ("os.cpu_count()", os.cpu_count()),
        )
        if workers is None:
            log.debug("no worker count from any source; assuming a single worker")
            workers = 1
        if workers < 1:
            log.warning("worker count %d is below 1; clamping it", workers)
            workers = 1

        resolve_hosts = _first_set(
            ("--resolve-host", args.resolve_host),
            ("RESOLVE_HOSTS", _env_list("RESOLVE_HOSTS", RESOLVE_HOSTS)),
        )
        if resolve_hosts is None:
            log.debug("no resolve hosts from any source; falling back to the default list")
            resolve_hosts = list(RESOLVE_HOSTS)

        output = _first_set(
            ("--output", args.output),
            ("OUTPUT_CSV", os.environ.get("OUTPUT_CSV", "").strip()),
            ("default", DEFAULT_OUTPUT),
        )

        fetcher = _first_set(
            ("--fetcher", args.fetcher),
            ("ARP_FETCHER", os.environ.get("ARP_FETCHER", "").strip()),
            ("default", "tplogin"),
        )

        password = _first_set(
            ("--unsafe-tplogin-password", args.unsafe_tplogin_password),
            ("TPLOGIN_PASSWORD", os.environ.get("TPLOGIN_PASSWORD", "").strip()),
        )
        if password is None:
            log.debug("no router password supplied on the command line or in the environment")

        browser = _first_set(
            ("--browser", args.browser),
            ("PW_BROWSER", os.environ.get("PW_BROWSER", "").strip()),
        )
        # "auto" is an explicit spelling of the default, not an engine name.
        if browser is None:
            log.debug("no browser named; the engine will auto-detect one")
        elif browser.lower() == "auto":
            log.debug("browser %r means auto-detection, not an engine name", browser)
            browser = None

        # --verbose > PROBESTACK_LOG_LEVEL > INFO.  The flag is the *explicit*
        # request, so it wins; the environment is the ambient default.
        log_level = _resolve_log_level(args.verbose)

        ssh_hop = _first_set(
            ("--ssh-hop", args.ssh_hop),
            ("SSH_HOP", os.environ.get("SSH_HOP", "").strip()),
        )

        expand = bool(args.expand)
        if expand:
            log.debug("ARP expansion enabled by --expand")
        else:
            expand = _env_flag("ARP_EXPAND")
            if expand:
                log.debug("ARP expansion enabled by ARP_EXPAND")

        expand_depth = _first_set(
            ("--expand-depth", args.expand_depth),
            ("ARP_EXPAND_DEPTH", _env_int("ARP_EXPAND_DEPTH")),
            ("default", DEFAULT_EXPAND_DEPTH),
        )
        if expand_depth < 1:
            log.warning("expansion depth %d is below 1; clamping it", expand_depth)
            expand_depth = 1

        max_task = _first_set(
            ("--max-task", args.max_task),
            ("ARP_MAX_TASK", _env_int("ARP_MAX_TASK")),
            ("default", DEFAULT_MAX_TASK),
        )
        if max_task < 1:
            log.warning("--max-task %d is below 1", max_task)
            raise ValueError(f"--max-task must be >= 1 (got {max_task!r})")

        log.debug(
            "resolved config: timeout=%.3fs workers=%d output=%s fetcher=%s hosts=%d "
            "log_level=%s expand=%s depth=%d max_task=%d",
            port_timeout,
            workers,
            output,
            fetcher,
            len(resolve_hosts),
            log_level,
            expand,
            expand_depth,
            max_task,
        )
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
            max_task=max_task,
        )
