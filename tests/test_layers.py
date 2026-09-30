"""Tests for :mod:`my_lan_prober.layers`.

The registry is ``design.md``'s central idea: ~70 protocols described as a
single dict of :class:`LayerSpec` data instead of ~70 hand-written classes.
"""

from __future__ import annotations

import pytest

from my_lan_prober.framing import (
    DatagramFraming,
    DelimiterFraming,
    LengthPrefixFraming,
    StreamFraming,
)
from my_lan_prober.layers import LAYERS, LayerSpec, SessionRegistry


# ---------------------------------------------------------------------------
# LayerSpec
# ---------------------------------------------------------------------------
def test_layer_spec_defaults_are_pass_through():
    spec = LayerSpec(name="Thing")

    assert spec.name == "Thing"
    assert isinstance(spec.framing, StreamFraming)
    assert spec.transform_in is None
    assert spec.transform_out is None
    assert spec.handshake_out is None
    assert spec.override_class is None
    assert spec.allowed_bases is None
    assert spec.ports_hint == ()
    assert spec.requires == ()


def test_layer_spec_is_frozen():
    spec = LayerSpec(name="Thing")

    with pytest.raises(Exception):
        spec.name = "Other"  # type: ignore[misc]


def test_layer_spec_positional_name_is_the_only_required_arg():
    spec = LayerSpec("Custom", DelimiterFraming(b"\n"), ports_hint=(1, 2))

    assert spec.name == "Custom"
    assert isinstance(spec.framing, DelimiterFraming)
    assert spec.ports_hint == (1, 2)


def test_layer_spec_repr_mentions_name():
    assert "TLS" in repr(LayerSpec(name="TLS"))


# ---------------------------------------------------------------------------
# The LAYERS table
# ---------------------------------------------------------------------------
def test_layers_covers_the_root_transports():
    assert isinstance(LAYERS["TCP"].framing, StreamFraming)
    assert isinstance(LAYERS["UDP"].framing, DatagramFraming)


def test_layers_covers_the_protocols_in_the_design_table():
    for name in (
        "TCP",
        "UDP",
        "TLS",
        "SSH",
        "HTTP/1.1",
        "HTTP/2",
        "WebSocket",
        "MQTT",
        "DNS",
        "SMTP",
        "IMAP",
        "POP3",
        "FTP",
        "SMB",
        "RDP",
        "VNC",
        "LDAP",
        "ONC RPC",
        "gRPC",
        "QUIC",
        "mDNS",
    ):
        assert name in LAYERS, f"missing layer {name!r}"


def test_layer_names_match_their_dict_keys():
    for key, spec in LAYERS.items():
        assert key == spec.name


def test_every_layer_has_a_ports_hint_or_is_a_pure_shim():
    """Roots and application protocols advertise ports; pure shims need not."""
    shims = {"HTTP CONNECT", "ICE", "WebRTC", "GSSAPI", "EAP", "WSS", "SFTP", "SCP"}

    for name, spec in LAYERS.items():
        if name in shims:
            continue
        assert spec.ports_hint, f"{name} has no ports_hint"


def test_every_layer_has_a_description():
    for name, spec in LAYERS.items():
        assert spec.description, f"{name} has no description"


def test_tls_uses_length_prefixed_records_with_offset_after_version():
    """TLS record header is type(1) version(2) length(2)."""
    framing = LAYERS["TLS"].framing

    assert isinstance(framing, LengthPrefixFraming)
    assert framing.prefix_bytes == 2
    assert framing.header_bytes == 5
    assert framing.prefix_offset == 3


def test_http_11_uses_request_response_framing():
    from my_lan_prober.framing import RequestResponseFraming

    assert isinstance(LAYERS["HTTP/1.1"].framing, RequestResponseFraming)


def test_ssh_uses_four_byte_length_prefix():
    framing = LAYERS["SSH"].framing

    assert isinstance(framing, LengthPrefixFraming)
    assert framing.prefix_bytes == 4


def test_allowed_bases_only_reference_known_layers():
    for name, spec in LAYERS.items():
        for base in spec.allowed_bases or ():
            assert base in LAYERS, f"{name} allows unknown base {base!r}"


def test_ports_hint_values_are_valid_ports():
    for name, spec in LAYERS.items():
        for port in spec.ports_hint:
            assert 0 < port < 65536, f"{name} has bad port {port}"


# ---------------------------------------------------------------------------
# SessionRegistry
# ---------------------------------------------------------------------------
def test_registry_knows_the_builtin_layers():
    assert SessionRegistry.get("TCP") is LAYERS["TCP"]


def test_registry_raises_keyerror_for_unknown_layer():
    with pytest.raises(KeyError, match="unknown layer"):
        SessionRegistry.get("NoSuchProto")


def test_registry_register_is_idempotent_and_overrides():
    spec = LayerSpec("TestOnly", StreamFraming(), description="test")
    try:
        SessionRegistry.register(spec)
        assert SessionRegistry.get("TestOnly") is spec
        SessionRegistry.register(spec)
        assert SessionRegistry.get("TestOnly") is spec
    finally:
        SessionRegistry._specs.pop("TestOnly", None)


def test_registry_names_lists_registered_layers():
    assert "TCP" in SessionRegistry.names()


def test_registry_all_returns_layer_specs():
    specs = SessionRegistry.all()

    assert specs["TCP"] is LAYERS["TCP"]
