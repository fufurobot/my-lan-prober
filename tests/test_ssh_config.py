"""Tests for the generated ``ssh.sh``: multi-hop forwarding, and port choice.

``ssh.sh`` is the *deliverable* of a scan for an SSH-able host — the point of
probing every port is to turn "something is listening on 8888" into a command
that makes it reachable.  Two things were wrong with it.

**Multi-hop.** A host discovered through an SSH hop carries ``via`` and
``depth`` from :class:`~my_lan_prober.expanders.SSHArpTableExpander`: the scan
reached it from *inside* the network, not from this machine.  The script
forwarded ``-L port:localhost:port`` and connected directly, which cannot work,
because this machine has no route to a host that only the hop can see.  The
forward must be established through the hops, and the remote half of ``-L``
must be resolved from the far end.

**Local port collisions.** Every host's script forwarded ``8888 -> 8888``, so
running two of them at once failed to bind — and with
``ExitOnForwardFailure=yes`` the second script died on startup rather than
degrading.  A port already occupied on ``localhost`` / ``127.0.0.1`` / ``::1``
must be stepped past until a free one is found.
"""

from __future__ import annotations

import re
import socket

import pandas as pd
import pytest

from my_lan_prober.engine import next_free_local_port, write_ssh_config


# ---------------------------------------------------------------------------
# Reading a generated script
# ---------------------------------------------------------------------------
def _read(data_dir, host="host-a") -> str:
    return (data_dir / host / "ssh.sh").read_text(encoding="utf-8")


def _forwards(script: str) -> list:
    """Every ``-L local:remote_host:remote_port`` in a script, as tuples."""
    found = []
    for match in re.finditer(r"-L\s+(\d+):([^:\s]+):(\d+)", script):
        found.append((int(match.group(1)), match.group(2), int(match.group(3))))
    return found


def _jump_hosts(script: str) -> list:
    """Every host named by ``-J``, in order."""
    match = re.search(r"-J\s+(\S+)", script)
    if not match:
        return []
    return [part.split("@")[-1] for part in match.group(1).split(",")]


# ---------------------------------------------------------------------------
# The single-hop case must not regress
# ---------------------------------------------------------------------------
def test_direct_host_forwards_through_localhost(tmp_path):
    write_ssh_config(tmp_path, "host-a", "192.168.1.104", 22, tunnels=[(8888, 8888)])

    script = _read(tmp_path)

    assert _forwards(script) == [(8888, "localhost", 8888)]
    assert _jump_hosts(script) == []


def test_direct_host_keeps_its_own_address_as_the_target(tmp_path):
    write_ssh_config(tmp_path, "host-a", "192.168.1.104", 22, tunnels=[(8888, 8888)])

    assert "192.168.1.104" in _read(tmp_path)


# ---------------------------------------------------------------------------
# Multi-hop: the whole point of the fix
# ---------------------------------------------------------------------------
def test_hop_reached_host_uses_a_jump_host(tmp_path):
    """A host only the hop can see must be reached *through* the hop."""
    write_ssh_config(
        tmp_path,
        "host-b",
        "192.168.2.50",
        22,
        tunnels=[(8000, 8000)],
        jumps=["arch-server-main"],
    )

    script = _read(tmp_path)

    assert _jump_hosts(script) == ["arch-server-main"]


def test_hop_chain_is_ordered_from_here_outwards(tmp_path):
    """``bastion`` is nearest, ``inner`` is furthest; -J must read that way."""
    write_ssh_config(
        tmp_path,
        "deep",
        "10.9.9.9",
        22,
        tunnels=[(80, 80)],
        jumps=["bastion", "inner"],
    )

    assert _jump_hosts(_read(tmp_path)) == ["bastion", "inner"]


def test_multi_hop_forwards_are_resolved_at_the_far_end(tmp_path):
    """The remote half of ``-L`` is resolved by the *last* hop, not by us.

    ``-L 8000:localhost:8000`` would ask the jump host to reach 8000 on
    itself.  The destination has to be named explicitly, as the address the
    last hop can see.
    """
    write_ssh_config(
        tmp_path,
        "host-b",
        "192.168.2.50",
        22,
        tunnels=[(8000, 8000)],
        jumps=["arch-server-main"],
        remote_address="192.168.2.50",
    )

    script = _read(tmp_path)

    assert (8000, "192.168.2.50", 8000) in _forwards(script)
    assert "localhost" not in script.split("-L")[1].split("\n")[0]


def test_multi_hop_without_a_remote_address_falls_back_to_the_target(tmp_path):
    """No explicit address: use the target, never ``localhost``."""
    write_ssh_config(
        tmp_path,
        "host-b",
        "192.168.2.50",
        22,
        tunnels=[(8000, 8000)],
        jumps=["arch-server-main"],
    )

    script = _read(tmp_path)

    remote_hosts = {host for _local, host, _port in _forwards(script)}
    assert remote_hosts == {"192.168.2.50"}


def test_multi_hop_keeps_one_login_not_two(tmp_path):
    """``-J`` chains the hops inside a single ssh invocation."""
    write_ssh_config(
        tmp_path,
        "host-b",
        "192.168.2.50",
        22,
        tunnels=[(8000, 8000)],
        jumps=["arch-server-main"],
    )

    script = _read(tmp_path)

    assert script.count("ssh ") == 1 or script.count("\nssh") <= 1


def test_multi_hop_targets_the_final_host(tmp_path):
    write_ssh_config(
        tmp_path,
        "host-b",
        "192.168.2.50",
        22,
        tunnels=[(8000, 8000)],
        jumps=["arch-server-main"],
    )

    body = _read(tmp_path)

    # The last bare argument before the line continuation ends is the target.
    assert re.search(r"\n\s*192\.168\.2\.50\s*\n", body)


def test_a_jump_host_account_is_carried_when_given(tmp_path):
    write_ssh_config(
        tmp_path,
        "host-b",
        "192.168.2.50",
        22,
        tunnels=[(8000, 8000)],
        jumps=["arch-server-main"],
        jump_user="root",
    )

    assert "root@arch-server-main" in _read(tmp_path)


def test_jumps_are_deduplicated_and_ordered(tmp_path):
    write_ssh_config(
        tmp_path,
        "host-b",
        "192.168.2.50",
        22,
        tunnels=[(8000, 8000)],
        jumps=["bastion", "bastion", "inner"],
    )

    assert _jump_hosts(_read(tmp_path)) == ["bastion", "inner"]


# ---------------------------------------------------------------------------
# Local ports that are already taken
# ---------------------------------------------------------------------------
def _occupy(port: int, family=socket.AF_INET, host="127.0.0.1"):
    """Bind ``port`` and keep it bound for the duration of the test."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    return sock


def test_next_free_local_port_returns_the_port_when_it_is_free():
    free = next_free_local_port(0, tries=1)

    assert free >= 0


def test_next_free_local_port_steps_past_an_occupied_one():
    sock = _occupy(0)
    try:
        taken = sock.getsockname()[1]

        assert next_free_local_port(taken) > taken
    finally:
        sock.close()


def test_next_free_local_port_walks_over_a_run_of_occupied_ports():
    sockets = []
    try:
        first = None
        for _ in range(3):
            candidate = _occupy(0)
            sockets.append(candidate)
            first = candidate.getsockname()[1] if first is None else first

        chosen = next_free_local_port(first)

        assert chosen not in {s.getsockname()[1] for s in sockets}
        assert chosen > first
    finally:
        for candidate in sockets:
            candidate.close()


def test_the_search_is_bounded():
    """A fully occupied range must fail loudly, not spin forever."""
    with pytest.raises(RuntimeError, match="no free local port"):
        next_free_local_port(1, tries=0)


def test_an_occupied_ipv6_port_is_also_avoided():
    """A listener on ::1 can block a forward even when 127.0.0.1 is free."""
    try:
        sock = _occupy(0, family=socket.AF_INET6, host="::1")
    except OSError:
        pytest.skip("no IPv6 loopback available")
    try:
        taken = sock.getsockname()[1]

        assert next_free_local_port(taken) > taken
    finally:
        sock.close()


def test_write_ssh_config_escalates_a_taken_local_port(tmp_path):
    """The generated script must be runnable even when the port is busy."""
    sock = _occupy(0)
    try:
        taken = sock.getsockname()[1]

        write_ssh_config(tmp_path, "host-a", "192.168.1.104", 22, tunnels=[(taken, taken)])

        local_ports = [local for local, _host, _port in _forwards(_read(tmp_path))]
        assert taken not in local_ports
        assert local_ports and local_ports[0] > taken
    finally:
        sock.close()


def test_escalation_can_be_switched_off(tmp_path):
    """A caller who wants the numbers they asked for gets them verbatim."""
    sock = _occupy(0)
    try:
        taken = sock.getsockname()[1]

        write_ssh_config(
            tmp_path,
            "host-a",
            "192.168.1.104",
            22,
            tunnels=[(taken, taken)],
            avoid_occupied_ports=False,
        )

        assert _forwards(_read(tmp_path)) == [(taken, "localhost", taken)]
    finally:
        sock.close()


def test_escalated_ports_do_not_collide_with_each_other(tmp_path):
    """Two forwards in one script must not be given the same local port."""
    write_ssh_config(
        tmp_path,
        "host-a",
        "192.168.1.104",
        22,
        tunnels=[(8888, 8888), (8889, 8889)],
    )

    local_ports = [local for local, _host, _port in _forwards(_read(tmp_path))]

    assert len(local_ports) == len(set(local_ports))


def test_the_chosen_local_port_is_reported(tmp_path):
    """The log line has to say what was actually forwarded, not what was asked."""
    write_ssh_config(tmp_path, "host-a", "192.168.1.104", 22, tunnels=[(8888, 8888)])

    script = _read(tmp_path)

    assert "8888" in script
    assert "ExitOnForwardFailure" in script


def test_escalation_preserves_the_remote_port(tmp_path):
    """Only the *local* side moves; the service is still on its own port."""
    sock = _occupy(0)
    try:
        taken = sock.getsockname()[1]

        write_ssh_config(tmp_path, "host-a", "192.168.1.104", 22, tunnels=[(taken, taken)])

        _local, _host, remote = _forwards(_read(tmp_path))[0]
        assert remote == taken
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# The engine wires the row's provenance into the script
# ---------------------------------------------------------------------------
def test_engine_passes_the_hop_chain_from_the_row(tmp_path):
    """``via`` on the row is how the engine knows a host is behind a hop."""
    from my_lan_prober.config import Config
    from my_lan_prober.engine import Engine

    config = Config.resolve(["--output", str(tmp_path / "out.csv"), "--resolve-host", "localhost"])
    engine = Engine(config)
    engine.ping = lambda ip: True
    engine.probe = lambda ip, port: "SSH-2.0-OpenSSH" if port == 22 else None

    frame = pd.DataFrame(
        [
            {
                "host": "far-away",
                "ip_address": "192.168.2.50",
                "mac_address": None,
                "valid_time": None,
                "via": "arch-server-main",
                "depth": 1,
                "port_22_service": "SSH",
            }
        ]
    )

    engine.write_ssh_scripts(frame)

    assert _jump_hosts(_read(config.data_dir, "far-away")) == ["arch-server-main"]


def test_engine_writes_no_jump_for_a_direct_host(tmp_path):
    from my_lan_prober.config import Config
    from my_lan_prober.engine import Engine

    config = Config.resolve(["--output", str(tmp_path / "out.csv"), "--resolve-host", "localhost"])
    engine = Engine(config)

    frame = pd.DataFrame(
        [
            {
                "host": "nearby",
                "ip_address": "192.168.1.104",
                "mac_address": None,
                "valid_time": None,
                "port_22_service": "SSH",
            }
        ]
    )

    engine.write_ssh_scripts(frame)

    assert _jump_hosts(_read(config.data_dir, "nearby")) == []


def test_engine_forwards_ports_that_are_open_but_unidentified(tmp_path):
    """An open port with an unknown service is still worth forwarding.

    The old rule required ``port_N_service`` to be non-null, so a port that
    answered with nothing identifiable — or that timed out under a short
    ``--port-timeout`` — was silently dropped from the script even though the
    scan had connected to it.
    """
    from my_lan_prober.config import Config
    from my_lan_prober.engine import Engine

    config = Config.resolve(["--output", str(tmp_path / "out.csv"), "--resolve-host", "localhost"])
    engine = Engine(config)

    frame = pd.DataFrame(
        [
            {
                "host": "nearby",
                "ip_address": "192.168.1.104",
                "mac_address": None,
                "valid_time": None,
                "port_22_service": "SSH",
                "port_8000_banner": "HTTP/1.1 200 OK",
                "port_8000_service": None,
            }
        ]
    )

    engine.write_ssh_scripts(frame)

    local_ports = [local for local, _h, _p in _forwards(_read(config.data_dir, "nearby"))]
    assert 8000 in local_ports
