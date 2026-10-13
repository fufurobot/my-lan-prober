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
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from .config import Config
from .expanders import SSHArpTableExpander, TableUnion
from .probes import ServiceIdentifier, icmp_ping, probe_service
from .registry import default_fetcher_registry

log = logging.getLogger(__name__)

__all__ = ["Engine", "write_ssh_config", "build_fetcher", "build_fetchers"]

#: SSH ports tried in priority order when writing the helper script.
SSH_PORT_CANDIDATES = (22, 2222, 8022)

SSH_CONFIG_FILENAME = "ssh.sh"


#: How many consecutive ports to try before giving up on finding a free one.
PORT_SEARCH_TRIES = 200

#: Addresses a local listener might be occupying.  A forward binds a local
#: port, so a listener on *any* of these blocks it — and on a dual-stack host a
#: process bound only to ``::1`` can still collide with a ``127.0.0.1`` bind,
#: depending on the socket options in play.  All of them are checked.
LOOPBACK_ADDRESSES = ("127.0.0.1", "::1", "localhost")


def _port_is_free(port: int, hosts: Sequence[str] = LOOPBACK_ADDRESSES) -> bool:
    """Whether nothing is listening on ``port`` on any loopback address.

    Two checks are needed and neither is sufficient alone:

    * ``connect_ex`` catches a listener that is *running* — the case that makes
      a second ``ssh.sh`` die at startup;
    * ``bind`` catches a port in ``TIME_WAIT`` or held by a socket that is not
      accepting, which a connect test would report as free.
    """
    for host in hosts:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            probe = socket.socket(family, socket.SOCK_STREAM)
        except OSError:  # pragma: no cover - no IPv6 stack
            continue
        try:
            probe.settimeout(0.2)
            if probe.connect_ex((host, port)) == 0:
                return False
        except OSError:
            # A connect that cannot even be attempted (no such address family
            # route, for instance) tells us nothing about occupancy.
            pass
        finally:
            probe.close()

        try:
            holder = socket.socket(family, socket.SOCK_STREAM)
        except OSError:  # pragma: no cover - no IPv6 stack
            continue
        try:
            # No SO_REUSEADDR: the question is precisely whether *we* could
            # bind here, and reuse would let us bind a port in TIME_WAIT that
            # ssh would then refuse.
            holder.bind((host, port))
        except OSError:
            return False
        finally:
            holder.close()
    return True


def next_free_local_port(
    port: int,
    *,
    tries: int = PORT_SEARCH_TRIES,
    hosts: Sequence[str] = LOOPBACK_ADDRESSES,
) -> int:
    """The first free port at or above ``port``.

    Raising is deliberate: a silent fallback to the occupied port would produce
    a script that fails the moment it runs, which is worse than an error at the
    point the script is written.
    """
    if tries < 1:
        raise RuntimeError(f"no free local port at or above {port}: search disabled")

    for candidate in range(port, port + tries):
        if _port_is_free(candidate, hosts):
            return candidate
    raise RuntimeError(
        f"no free local port in {port}-{port + tries - 1}; "
        "close something, or pass a different --output per run"
    )


def _format_jump(user: Optional[str], host: str) -> str:
    return f"{user}@{host}" if user else host


def write_ssh_config(
    data_dir: Path,
    host: str,
    ip: str,
    port: int,
    tunnels: Optional[List[Tuple[int, int]]] = None,
    local_port_offset: int = 0,
    *,
    jumps: Optional[Sequence[str]] = None,
    jump_user: Optional[str] = None,
    remote_address: Optional[str] = None,
    avoid_occupied_ports: bool = True,
) -> Path:
    """Write ``<data_dir>/<host>/ssh.sh`` forwarding each tunnelled service.

    Args:
        local_port_offset: Added to every local port so several host scripts
            can run at once without colliding (e.g. 1000 turns local 8888
            into 9888).
        jumps: SSH hosts to reach the target *through*, ordered from this
            machine outwards.  A host the scan found behind a hop is not
            routable from here, so the script must go via the hop.  Rendered as
            ``-J a,b`` — one ssh invocation, chained on the client side.
        jump_user: Username for the jump hosts, when it differs.
        remote_address: The address the *far end* of the connection can use for
            the tunnelled service.  Defaults to ``ip``.  It must never default
            to ``localhost`` when jumping: that would ask the last hop to
            forward a port on itself rather than on the target.
        avoid_occupied_ports: Step the local port upwards when something is
            already listening on it.  On by default, because a script that
            cannot bind is a script that does not work.
    """
    directory = Path(data_dir) / host
    directory.mkdir(parents=True, exist_ok=True)
    config_path = directory / SSH_CONFIG_FILENAME

    hop_chain: List[str] = []
    for hop in jumps or ():
        name = str(hop).strip()
        if name and name not in hop_chain:
            hop_chain.append(name)

    # Behind a hop, the service lives at the far end of the chain, so the
    # remote half of -L names the target explicitly.  Directly reachable, the
    # conventional `localhost` is right (and survives the target moving).
    forward_host = (remote_address or ip) if hop_chain else "localhost"

    parts: List[str] = [
        "ssh",
        f"-p {port}",
        # Keep the tunnel alive across idle periods, and fail fast if a local
        # port is already bound so a tunnel is never silently dropped.
        "-o ServerAliveInterval=30",
        "-o ServerAliveCountMax=3",
        "-o ExitOnForwardFailure=yes",
    ]

    if hop_chain:
        parts.append("-J " + ",".join(_format_jump(jump_user, hop) for hop in hop_chain))

    forwarded: List[Tuple[int, int]] = []
    if tunnels:
        seen_remote = set()
        taken_locals: set = set()
        for local_port, remote_port in tunnels:
            if remote_port in seen_remote:
                continue
            seen_remote.add(remote_port)

            requested = local_port + local_port_offset
            chosen = requested
            if avoid_occupied_ports:
                # Skip anything already listening, and anything already claimed
                # by an earlier forward in this same script.
                while chosen in taken_locals or not _port_is_free(chosen):
                    chosen += 1
            taken_locals.add(chosen)

            forwarded.append((chosen, remote_port))
            parts.append(f"-L {chosen}:{forward_host}:{remote_port}")

    parts.append(ip)

    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write("#!/usr/bin/env bash\n")
        handle.write(" \\\n    ".join(parts))
        handle.write("\n")

    # The script must be runnable, but Windows filesystems often refuse the
    # mode bits outright — that is not a reason to fail the whole scan.
    with contextlib.suppress(OSError):
        config_path.chmod(0o755)

    via = f" via {','.join(hop_chain)}" if hop_chain else ""
    if forwarded:
        rendered = ", ".join(f"{local}->{remote}" for local, remote in forwarded)
        log.info(
            "Wrote SSH config for %s -> %s:%d%s (%d tunnel(s): %s)",
            host,
            ip,
            port,
            via,
            len(forwarded),
            rendered,
        )
        requested_ports = {local for local, _remote in tunnels}
        moved = [chosen for chosen, _remote in forwarded if chosen not in requested_ports]
        if moved:
            # Say so: the numbers in the script are not the numbers the caller
            # asked for, and the reason is on this machine, not on the target.
            log.info("  local port(s) moved to avoid a busy port: %s", ", ".join(map(str, moved)))
    else:
        log.info("Wrote SSH config for %s -> %s:%d%s (no tunnels)", host, ip, port, via)
    return config_path


def build_fetcher(
    kind: str,
    browser: Optional[str] = None,
    *,
    ssh_hop: Optional[str] = None,
    expand: bool = False,
    expand_depth: int = 1,
) -> Any:
    """Build the ARP source(s) named by ``kind``.

    ``kind`` is a registry selection: one name (``unix``), several
    (``unix,dns,hosts``), ``all`` for every implemented source, or ``auto`` for
    the non-invasive set.  Anything but a single name comes back as a
    :class:`~my_lan_prober.expanders.TableUnion`, because the engine's contract
    is now "every selected source contributes" rather than "the first one that
    answers wins".
    """
    registry = default_fetcher_registry()
    selection = registry.parse_selection(kind)

    kwargs = {
        "browser": browser,
        "ssh_hop": ssh_hop,
        "expand": expand,
        "expand_depth": expand_depth,
    }
    fetchers = [registry.create(name, **kwargs) for name in selection]

    if len(fetchers) == 1:
        return fetchers[0]
    return TableUnion(fetchers)


def build_fetchers(config: Config) -> List[Any]:
    """Every source the run should consult, in registry order.

    Kept separate from :func:`build_fetcher` because the engine's SSH expansion
    needs the *list*: the expander's upstream is whatever the other selected
    sources produced, which is only knowable once they have all been built.
    """
    registry = default_fetcher_registry()
    selection = registry.parse_selection(config.fetcher)
    kwargs = {
        "browser": config.browser,
        "ssh_hop": config.ssh_hop,
        "expand": config.expand,
        "expand_depth": config.expand_depth,
    }
    return [registry.create(name, **kwargs) for name in selection]


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
        """Every selected source's table, merged into one.

        The merge happens *before* a single port is probed, which is the point:
        a host only the hosts file knows about, or only a resolver knows about,
        or only an SSH hop can see, is probed exactly like a DHCP lease.  The
        old behaviour — take the first non-empty table and stop — silently
        discarded every host the other sources had found.
        """
        fetchers = build_fetchers(self.config)

        if self.config.expand:
            fetchers = self._with_ssh_expansion(fetchers)

        if not fetchers:
            raise RuntimeError("no ARP source was selected")

        union = TableUnion(fetchers, max_task=self.config.max_task)
        frame = union.iptable()
        log.info(
            "ARP table: %d host(s) from %s",
            len(frame),
            ", ".join(sorted({str(name) for name in frame.get("source", [])})) or "no source",
        )
        return frame

    def _with_ssh_expansion(self, fetchers: List[Any]) -> List[Any]:
        """Add the SSH walk, with the other sources as its upstream.

        The expander is appended rather than wrapped: the union then holds the
        plain tables *and* the expansion, so a hop that fails still leaves the
        direct sources intact instead of taking them down with it.
        """
        direct = [fetcher for fetcher in fetchers if not isinstance(fetcher, SSHArpTableExpander)]
        already = [fetcher for fetcher in fetchers if isinstance(fetcher, SSHArpTableExpander)]
        if already:
            return fetchers

        expander = SSHArpTableExpander(
            direct or fetchers,
            hop=self.config.ssh_hop,
            enabled=True,
            max_depth=self.config.expand_depth,
        )
        log.info(
            "SSH expansion enabled (hop=%s, depth=%d)",
            self.config.ssh_hop or "<from known_hosts>",
            self.config.expand_depth,
        )
        return [*fetchers, expander]

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

    def _jumps_for(self, row: pd.Series) -> List[str]:
        """The SSH hop chain this host was discovered through, nearest first.

        ``SSHArpTableExpander`` records the hop a host was seen from in ``via``
        and how many hops out it was in ``depth``.  A row that came in that way
        is not routable from here, so its script has to go through the hop —
        without this the generated command connects directly and simply hangs.
        """
        raw = row.get("via")
        if raw is None or (isinstance(raw, float) and pd.isna(raw)):
            return []

        # ``via`` accumulates when several hops saw the same host, so it is a
        # comma-separated list.  Ordered as recorded, duplicates dropped.
        hops: List[str] = []
        for part in str(raw).split(","):
            name = part.strip()
            if name and name not in hops:
                hops.append(name)
        return hops

    def write_ssh_scripts(self, frame: pd.DataFrame) -> None:
        for _, row in frame.iterrows():
            ssh_port = self._ssh_port(row)
            if ssh_port is None:
                continue

            # Forward every *other* port the scan actually reached, so a
            # Jupyter server on :8888 becomes http://localhost:8888.  The test
            # is "was anything there", not "was it identified": a port that
            # answered with a banner we could not name, or that timed out under
            # a short --port-timeout, is still a port worth forwarding.
            tunnels: List[Tuple[int, int]] = []
            for port in self.config.ports:
                if port == ssh_port:
                    continue
                if self._port_responded(row, port):
                    tunnels.append((port, port))

            write_ssh_config(
                self.config.data_dir,
                str(row["host"]),
                str(row["ip_address"]),
                ssh_port,
                tunnels=tunnels or None,
                jumps=self._jumps_for(row) or None,
                remote_address=str(row["ip_address"]),
            )

    @staticmethod
    def _port_responded(row: pd.Series, port: int) -> bool:
        """Whether the scan got *anything* back from ``port``.

        A service name means yes.  So does a banner, or any response bytes:
        those are recorded even when identification failed, and dropping them
        from the tunnel list was why ports the scan had clearly connected to
        were missing from the generated script.
        """
        for column in (f"port_{port}_service", f"port_{port}_banner"):
            value = row.get(column)
            if value is None:
                continue
            if isinstance(value, float) and pd.isna(value):
                continue
            if str(value).strip():
                return True
        return False
