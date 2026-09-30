"""Tests for :mod:`my_lan_prober.config`.

``design.md`` § 9: every knob is ``CLI flag > environment variable > default``.
"""

from __future__ import annotations

import pytest

from my_lan_prober.config import Config, parse_cli_args, resolve_port_timeout


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
def test_defaults_match_the_tested_original(monkeypatch):
    for name in (
        "PORT_TIMEOUT",
        "SCAN_WORKERS",
        "RESOLVE_HOSTS",
        "OUTPUT_CSV",
        "ARP_FETCHER",
        "PW_BROWSER",
    ):
        monkeypatch.delenv(name, raising=False)

    config = Config.resolve([])

    assert config.port_timeout == 0.1
    assert config.resolve_hosts == ["tplogin.cn", "localhost"]
    assert config.fetcher == "tplogin"
    assert config.output == "data/tplogin-arp-enriched.csv"
    assert config.workers >= 1


# ---------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------
def test_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("PORT_TIMEOUT", "2.5")

    config = Config.resolve(["--port-timeout", "0.05"])

    assert config.port_timeout == 0.05


def test_env_overrides_default(monkeypatch):
    monkeypatch.setenv("PORT_TIMEOUT", "2.5")

    assert Config.resolve([]).port_timeout == 2.5


def test_invalid_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("PORT_TIMEOUT", "not-a-number")

    assert Config.resolve([]).port_timeout == 0.1


def test_negative_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("PORT_TIMEOUT", "-3")

    assert Config.resolve([]).port_timeout == 0.1


def test_zero_cli_timeout_is_rejected():
    with pytest.raises(ValueError, match="must be > 0"):
        Config.resolve(["--port-timeout", "0"])


def test_resolve_port_timeout_helper_matches_config():
    assert resolve_port_timeout(0.5) == 0.5
    assert resolve_port_timeout(None) == 0.1


# ---------------------------------------------------------------------------
# Individual knobs
# ---------------------------------------------------------------------------
def test_workers_flag(monkeypatch):
    monkeypatch.delenv("SCAN_WORKERS", raising=False)

    assert Config.resolve(["--workers", "8"]).workers == 8


def test_resolve_host_flag_is_repeatable(monkeypatch):
    monkeypatch.delenv("RESOLVE_HOSTS", raising=False)

    config = Config.resolve(["--resolve-host", "a.local", "--resolve-host", "b.local"])

    assert config.resolve_hosts == ["a.local", "b.local"]


def test_resolve_hosts_env_is_csv(monkeypatch):
    monkeypatch.setenv("RESOLVE_HOSTS", "x.local, y.local")

    assert Config.resolve([]).resolve_hosts == ["x.local", "y.local"]


def test_fetcher_choice_is_validated(monkeypatch):
    monkeypatch.delenv("ARP_FETCHER", raising=False)

    assert Config.resolve(["--fetcher", "unix"]).fetcher == "unix"

    with pytest.raises(SystemExit):
        Config.resolve(["--fetcher", "nonsense"])


def test_output_flag_sets_the_csv_path(monkeypatch):
    monkeypatch.delenv("OUTPUT_CSV", raising=False)

    assert Config.resolve(["--output", "out.csv"]).output == "out.csv"


def test_data_dir_is_derived_from_the_output_path(monkeypatch):
    monkeypatch.delenv("OUTPUT_CSV", raising=False)

    config = Config.resolve(["--output", "custom/leases.csv"])

    assert str(config.data_dir).replace("\\", "/") == "custom"


def test_password_env_is_picked_up(monkeypatch):
    monkeypatch.setenv("TPLOGIN_PASSWORD", "hunter2")

    assert Config.resolve([]).password == "hunter2"


def test_log_level_env_is_picked_up(monkeypatch):
    monkeypatch.setenv("PROBESTACK_LOG_LEVEL", "DEBUG")

    assert Config.resolve([]).log_level == "DEBUG"


def test_port_timeout_is_also_the_connect_timeout(monkeypatch):
    monkeypatch.delenv("PORT_TIMEOUT", raising=False)

    assert Config.resolve(["-t", "0.25"]).port_timeout == 0.25


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
def test_parse_cli_args_returns_a_namespace():
    args = parse_cli_args([])

    assert args.port_timeout is None


def test_parse_cli_args_short_timeout_flag():
    assert parse_cli_args(["-t", "0.3"]).port_timeout == 0.3


def test_xsrf_or_password_never_appears_in_the_repr(monkeypatch):
    """A config object often gets logged; the password must not leak."""
    monkeypatch.setenv("TPLOGIN_PASSWORD", "super-secret")

    assert "super-secret" not in repr(Config.resolve([]))
