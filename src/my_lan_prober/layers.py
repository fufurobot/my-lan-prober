"""Data-driven layer model — one dict of :class:`LayerSpec` for every protocol.

See ``design.md`` § 1.  Instead of ~70 hand-written session subclasses, each
protocol is a row of data: a framing strategy, optional byte transforms, an
optional handshake payload, and an optional escape-hatch class.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from .framing import (
    DatagramFraming,
    DelimiterFraming,
    FixedSizeFraming,
    Framing,
    LengthPrefixFraming,
    MultiplexFraming,
    RequestResponseFraming,
    StreamFraming,
    VarintLengthFraming,
)

log = logging.getLogger(__name__)

__all__ = ["LayerSpec", "LAYERS", "SessionRegistry"]


@dataclass(frozen=True)
class LayerSpec:
    """Everything a :class:`~my_lan_prober.sessions.TableSession` needs."""

    name: str
    framing: Framing = field(default_factory=StreamFraming)
    #: Byte-level encrypt hook applied on the way out.
    transform_out: Optional[Callable[[bytes], bytes]] = None
    #: Byte-level decrypt hook applied on the way in.
    transform_in: Optional[Callable[[bytes], bytes]] = None
    #: Bytes to send once when the layer opens (``ClientHello``, ``EHLO``, …).
    handshake_out: Any = None
    #: Escape hatch: use a hand-written class instead of ``TableSession``.
    override_class: Optional[type] = None
    #: Documented base layers; the real check is the stack you build.
    allowed_bases: Optional[Tuple[str, ...]] = None
    ports_hint: Tuple[int, ...] = ()
    description: str = ""
    #: Auth shims this layer typically sits above (SASL, GSSAPI, …).
    requires: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# The table.  One line per protocol.
# ---------------------------------------------------------------------------
LAYERS: Dict[str, LayerSpec] = {
    # --- roots -------------------------------------------------------
    "TCP": LayerSpec(
        "TCP", StreamFraming(),
        ports_hint=(22, 80, 443, 25, 587, 3306, 5432, 6379, 8080, 8443),
        description="TCP stream",
    ),
    "UDP": LayerSpec(
        "UDP", DatagramFraming(),
        ports_hint=(53, 123, 161, 5353),
        description="UDP datagrams",
    ),

    # --- security / encryption shims ---------------------------------
    # TLS records are type(1) version(2) length(2): the 2-byte length sits
    # at offset 3, not 0.
    "TLS": LayerSpec(
        "TLS", LengthPrefixFraming(2, header_bytes=5, prefix_offset=3),
        allowed_bases=("TCP",), ports_hint=(443, 465, 636, 853, 993, 995),
        description="TLS / SSL over TCP",
    ),
    "DTLS": LayerSpec(
        "DTLS", DatagramFraming(),
        allowed_bases=("UDP",), ports_hint=(443, 5684),
        description="DTLS over UDP",
    ),
    "SSH": LayerSpec(
        "SSH", LengthPrefixFraming(4, header_bytes=5),
        allowed_bases=("TCP",), ports_hint=(22, 2222, 8022),
        description="SSH transport",
    ),
    "IPsec": LayerSpec(
        "IPsec", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(500, 4500),
        description="IPsec IKE / NAT-T",
    ),
    "WireGuard": LayerSpec(
        "WireGuard", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(51820,),
        description="WireGuard tunnel",
    ),
    "OpenVPN": LayerSpec(
        "OpenVPN", LengthPrefixFraming(2), allowed_bases=("TCP", "UDP"),
        ports_hint=(1194,), description="OpenVPN tunnel",
    ),
    "SRTP": LayerSpec(
        "SRTP", FixedSizeFraming(12), allowed_bases=("RTP", "DTLS"),
        description="Secure RTP",
    ),
    "ZRTP": LayerSpec(
        "ZRTP", StreamFraming(), allowed_bases=("RTP",), description="ZRTP key agreement",
    ),

    # --- multiplex / framing -----------------------------------------
    "QUIC": LayerSpec(
        "QUIC", MultiplexFraming(), allowed_bases=("UDP",), ports_hint=(443, 80),
        description="QUIC transport",
    ),
    "HTTP/1.1": LayerSpec(
        "HTTP/1.1", RequestResponseFraming(), allowed_bases=("TCP", "TLS"),
        ports_hint=(80, 8080, 8000, 8888, 6099, 3080, 30000, 2358, 11434),
        description="HTTP/1.1",
    ),
    "HTTP/2": LayerSpec(
        "HTTP/2", MultiplexFraming(), handshake_out=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        allowed_bases=("TCP", "TLS"), ports_hint=(443, 8443),
        description="HTTP/2 with HPACK",
    ),
    "HTTP/3": LayerSpec(
        "HTTP/3", MultiplexFraming(), allowed_bases=("QUIC",), ports_hint=(443,),
        description="HTTP/3 over QUIC",
    ),
    "WebSocket": LayerSpec(
        "WebSocket", LengthPrefixFraming(2, header_bytes=2),
        allowed_bases=("TCP", "TLS", "HTTP/1.1", "HTTP/2"), ports_hint=(80, 443),
        description="WebSocket upgrade + frames",
    ),

    # --- auth / AAA ---------------------------------------------------
    "SASL": LayerSpec(
        "SASL", StreamFraming(), allowed_bases=("TCP",), ports_hint=(25, 143, 110, 389),
        description="SASL auth exchange",
    ),
    "GSSAPI": LayerSpec(
        "GSSAPI", StreamFraming(), allowed_bases=("SASL", "Kerberos"),
        description="GSSAPI auth shim",
    ),
    "Kerberos": LayerSpec(
        "Kerberos", LengthPrefixFraming(4), allowed_bases=("TCP", "UDP"),
        ports_hint=(88,), description="Kerberos",
    ),
    "RADIUS": LayerSpec(
        "RADIUS", LengthPrefixFraming(2), allowed_bases=("UDP", "TLS"),
        ports_hint=(1812, 1813), description="RADIUS AAA",
    ),
    "EAP": LayerSpec(
        "EAP", LengthPrefixFraming(2), allowed_bases=("RADIUS",), description="EAP over RADIUS",
    ),
    "TACACS+": LayerSpec(
        "TACACS+", LengthPrefixFraming(4), allowed_bases=("TCP",), ports_hint=(49,),
        description="TACACS+",
    ),
    "Diameter": LayerSpec(
        "Diameter", LengthPrefixFraming(3), allowed_bases=("TCP", "TLS"),
        ports_hint=(3868,), description="Diameter AAA",
    ),

    # --- tunnel / proxy ----------------------------------------------
    "SOCKS": LayerSpec(
        "SOCKS", StreamFraming(), allowed_bases=("TCP", "UDP"), ports_hint=(1080,),
        description="SOCKS proxy",
    ),
    "HTTP CONNECT": LayerSpec(
        "HTTP CONNECT", StreamFraming(), allowed_bases=("HTTP/1.1",),
        description="HTTP CONNECT tunnel",
    ),
    "STUN": LayerSpec(
        "STUN", LengthPrefixFraming(2), allowed_bases=("UDP", "TCP"),
        ports_hint=(3478,), description="STUN",
    ),
    "TURN": LayerSpec(
        "TURN", LengthPrefixFraming(2), allowed_bases=("UDP", "TCP", "TLS"),
        ports_hint=(3478, 5349), description="TURN relay",
    ),
    "ICE": LayerSpec(
        "ICE", StreamFraming(), allowed_bases=("STUN", "TURN"), description="ICE negotiation",
    ),
    "L2TP": LayerSpec(
        "L2TP", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(1701,),
        description="L2TP tunnel",
    ),
    "VXLAN": LayerSpec(
        "VXLAN", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(4789,),
        description="VXLAN overlay",
    ),
    "Geneve": LayerSpec(
        "Geneve", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(6081,),
        description="Geneve overlay",
    ),
    "SSTP": LayerSpec(
        "SSTP", LengthPrefixFraming(2), allowed_bases=("TLS",), ports_hint=(443,),
        description="SSTP over TLS",
    ),

    # --- RPC / messaging ---------------------------------------------
    "ONC RPC": LayerSpec(
        "ONC RPC", LengthPrefixFraming(4, header_bytes=4, big_endian=True),
        allowed_bases=("TCP", "UDP"), ports_hint=(111, 2049), description="ONC RPC / portmap",
    ),
    "DCE RPC": LayerSpec(
        "DCE RPC", LengthPrefixFraming(2), allowed_bases=("TCP", "UDP"),
        ports_hint=(135,), description="DCE RPC",
    ),
    "gRPC": LayerSpec(
        "gRPC", LengthPrefixFraming(4), allowed_bases=("HTTP/2", "TLS"),
        ports_hint=(50051,), description="gRPC",
    ),
    "Thrift": LayerSpec(
        "Thrift", LengthPrefixFraming(4), allowed_bases=("TCP", "TLS"),
        ports_hint=(9090,), description="Apache Thrift",
    ),
    "JSON-RPC": LayerSpec(
        "JSON-RPC", RequestResponseFraming(), allowed_bases=("HTTP/1.1",),
        ports_hint=(8545, 8332), description="JSON-RPC",
    ),
    "XML-RPC": LayerSpec(
        "XML-RPC", RequestResponseFraming(), allowed_bases=("HTTP/1.1",),
        ports_hint=(80, 443), description="XML-RPC",
    ),
    "MQTT": LayerSpec(
        "MQTT", VarintLengthFraming(), allowed_bases=("TCP", "TLS", "WebSocket"),
        ports_hint=(1883, 8883), description="MQTT",
    ),
    "AMQP": LayerSpec(
        "AMQP", LengthPrefixFraming(4), allowed_bases=("TCP", "TLS"),
        ports_hint=(5672, 5671), description="AMQP",
    ),
    "STOMP": LayerSpec(
        "STOMP", DelimiterFraming(b"\x00"), allowed_bases=("TCP", "WebSocket"),
        ports_hint=(61613,), description="STOMP",
    ),
    "XMPP": LayerSpec(
        "XMPP", DelimiterFraming(b"</stream:stream>", include_sep=True),
        allowed_bases=("TCP", "TLS"), ports_hint=(5222, 5223), description="XMPP",
    ),
    "IRC": LayerSpec(
        "IRC", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS"),
        ports_hint=(6667, 6697), description="IRC",
    ),
    "Kafka": LayerSpec(
        "Kafka", LengthPrefixFraming(4), allowed_bases=("TCP", "TLS"),
        ports_hint=(9092, 9093), description="Kafka",
    ),

    # --- media / real-time -------------------------------------------
    "RTP": LayerSpec(
        "RTP", FixedSizeFraming(12), allowed_bases=("UDP",), description="RTP",
    ),
    "RTCP": LayerSpec(
        "RTCP", LengthPrefixFraming(2, header_bytes=2), allowed_bases=("UDP",),
        description="RTCP",
    ),
    "RTSP": LayerSpec(
        "RTSP", DelimiterFraming(b"\r\n\r\n"), allowed_bases=("TCP", "UDP"),
        ports_hint=(554, 8554), description="RTSP",
    ),
    "SIP": LayerSpec(
        "SIP", DelimiterFraming(b"\r\n\r\n"), allowed_bases=("UDP", "TCP", "TLS"),
        ports_hint=(5060, 5061), description="SIP",
    ),
    "H.323": LayerSpec(
        "H.323", LengthPrefixFraming(2), allowed_bases=("TCP", "UDP"),
        ports_hint=(1720,), description="H.323",
    ),
    "WebRTC": LayerSpec(
        "WebRTC", StreamFraming(), allowed_bases=("DTLS", "SRTP", "ICE", "SIP", "H.323"),
        description="WebRTC",
    ),

    # --- applications --------------------------------------------------
    "DNS": LayerSpec(
        "DNS", LengthPrefixFraming(2),
        allowed_bases=("UDP", "TCP", "TLS", "HTTP/1.1", "HTTP/2", "QUIC"),
        ports_hint=(53, 853, 5353), description="DNS",
    ),
    "DHCP": LayerSpec(
        "DHCP", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(67, 68),
        description="DHCP",
    ),
    "NTP": LayerSpec(
        "NTP", FixedSizeFraming(48), allowed_bases=("UDP", "TLS"), ports_hint=(123,),
        description="NTP",
    ),
    "SNMP": LayerSpec(
        "SNMP", LengthPrefixFraming(2), allowed_bases=("UDP", "TCP"),
        ports_hint=(161, 162), description="SNMP",
    ),
    "Syslog": LayerSpec(
        "Syslog", DelimiterFraming(b"\n"), allowed_bases=("UDP", "TCP", "TLS"),
        ports_hint=(514, 6514), description="Syslog",
    ),
    "NetFlow": LayerSpec(
        "NetFlow", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(2055,),
        description="NetFlow",
    ),
    "BGP": LayerSpec(
        "BGP", LengthPrefixFraming(2, header_bytes=19), allowed_bases=("TCP",),
        ports_hint=(179,), description="BGP",
    ),
    "RIP": LayerSpec(
        "RIP", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(520,), description="RIP",
    ),
    "LDAP": LayerSpec(
        "LDAP", LengthPrefixFraming(2), allowed_bases=("TCP", "TLS", "SASL", "GSSAPI"),
        ports_hint=(389, 636), description="LDAP",
    ),
    "SMTP": LayerSpec(
        "SMTP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS", "SASL"),
        ports_hint=(25, 465, 587), description="SMTP",
    ),
    "IMAP": LayerSpec(
        "IMAP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS", "SASL"),
        ports_hint=(143, 993), description="IMAP",
    ),
    "POP3": LayerSpec(
        "POP3", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS", "SASL"),
        ports_hint=(110, 995), description="POP3",
    ),
    "FTP": LayerSpec(
        "FTP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS"),
        ports_hint=(21,), description="FTP",
    ),
    "SFTP": LayerSpec(
        "SFTP", LengthPrefixFraming(4), allowed_bases=("SSH",), description="SFTP over SSH",
    ),
    "SCP": LayerSpec(
        "SCP", DelimiterFraming(b"\n"), allowed_bases=("SSH",), description="SCP over SSH",
    ),
    "SMB": LayerSpec(
        "SMB", LengthPrefixFraming(4), allowed_bases=("TCP",), ports_hint=(445, 139),
        description="SMB / CIFS",
    ),
    "NFS": LayerSpec(
        "NFS", LengthPrefixFraming(4), allowed_bases=("ONC RPC", "TCP", "UDP"),
        ports_hint=(2049,), description="NFS",
    ),
    "WebDAV": LayerSpec(
        "WebDAV", RequestResponseFraming(), allowed_bases=("HTTP/1.1", "TLS"),
        ports_hint=(80, 443), description="WebDAV",
    ),
    "WSS": LayerSpec(
        "WSS", LengthPrefixFraming(2, header_bytes=2), allowed_bases=("WebSocket", "TLS"),
        description="WebSocket over TLS",
    ),
    "DB": LayerSpec(
        "DB", LengthPrefixFraming(3), allowed_bases=("TCP", "TLS"),
        ports_hint=(3306, 5432, 6379, 27017, 1433, 1521), description="Generic database wire protocol",
    ),
    "RDP": LayerSpec(
        "RDP", LengthPrefixFraming(2), allowed_bases=("TCP", "TLS"), ports_hint=(3389,),
        description="RDP",
    ),
    "VNC": LayerSpec(
        "VNC", LengthPrefixFraming(4, header_bytes=8), allowed_bases=("TCP", "TLS"),
        ports_hint=(5900, 5901, 5800), description="VNC / RFB",
    ),
    "Telnet": LayerSpec(
        "Telnet", DelimiterFraming(b"\r\n"), allowed_bases=("TCP",), ports_hint=(23,),
        description="Telnet",
    ),
    "WHOIS": LayerSpec(
        "WHOIS", DelimiterFraming(b"\n"), allowed_bases=("TCP",), ports_hint=(43,),
        description="WHOIS",
    ),
    "NNTP": LayerSpec(
        "NNTP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP",), ports_hint=(119, 563),
        description="NNTP",
    ),
    "CoAP": LayerSpec(
        "CoAP", LengthPrefixFraming(2, header_bytes=4), allowed_bases=("UDP", "DTLS"),
        ports_hint=(5683, 5684), description="CoAP",
    ),
    "SSDP": LayerSpec(
        "SSDP", DelimiterFraming(b"\r\n\r\n"), allowed_bases=("UDP",), ports_hint=(1900,),
        description="SSDP",
    ),
    "mDNS": LayerSpec(
        "mDNS", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(5353,),
        description="Multicast DNS",
    ),
    "LLMNR": LayerSpec(
        "LLMNR", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(5355,),
        description="LLMNR",
    ),
    "TFTP": LayerSpec(
        "TFTP", LengthPrefixFraming(2, header_bytes=2), allowed_bases=("UDP",),
        ports_hint=(69,), description="TFTP",
    ),
}


class SessionRegistry:
    """Name → :class:`LayerSpec` lookup used by ``SessionFactory``."""

    _specs: Dict[str, LayerSpec] = dict(LAYERS)

    @classmethod
    def register(cls, spec: LayerSpec) -> None:
        cls._specs[spec.name] = spec

    @classmethod
    def get(cls, name: str) -> LayerSpec:
        try:
            return cls._specs[name]
        except KeyError:
            raise KeyError(f"unknown layer {name!r}") from None

    @classmethod
    def names(cls) -> list:
        return sorted(cls._specs)

    @classmethod
    def all(cls) -> Dict[str, LayerSpec]:
        return dict(cls._specs)
