# Final Design v4 — Data-Driven Layers

Two changes: (6) `TableSession` + `Framing` strategies replace ~70 hand-written classes, and (8) `SocketBannerHandler` takes **both a stack spec and a live session**.

---

## 1. Data-Driven Layer Model

### 1a. The observation

Almost every protocol in the map is one of a handful of **shapes**:

| Shape | Examples | What it does |
|---|---|---|
| **Stream passthrough** | raw TCP, UDP, TLS post-handshake | bytes in = bytes out |
| **Length-prefixed framing** | TLS records, SSH packets, WebSocket, MQTT | 2/4/varint length header |
| **Delimiter framing** | HTTP/1.1, IRC, SMTP, NNTP | `\r\n` or `\r\n\r\n` terminator |
| **Fixed-size records** | RTP, some crypto primitives | N-byte frames |
| **Request/response** | HTTP/1.1 | request → response pairing |
| **Multiplexed streams** | HTTP/2, HTTP/3, QUIC | stream IDs + length headers |
| **Auth wrapper** | SASL, GSSAPI, Kerberos, RADIUS | handshake then passthrough |
| **Tunnel establishment** | SOCKS, HTTP CONNECT, STUN, TURN | negotiate then passthrough |
| **Encryption transform** | TLS, DTLS, WireGuard, SSH transport | byte-level encrypt/decrypt |

Instead of ~70 subclasses, we describe each layer as **data** (`LayerSpec`) + **one of a few strategies** (`Framing`, `Transform`).

### 1b. Framing strategies

```mermaid
classDiagram
    class Framing {
        <<abstract>>
        +frame(buf: bytearray) list~bytes~*   "extract complete messages; mutate buf to drop consumed bytes"
        +encode(payload: bytes) bytes          "add layer headers/prefixes"
        +reset()
    }
    Framing <|-- StreamFraming
    Framing <|-- DatagramFraming
    Framing <|-- LengthPrefixFraming
    Framing <|-- VarintLengthFraming
    Framing <|-- DelimiterFraming
    Framing <|-- FixedSizeFraming
    Framing <|-- RequestResponseFraming
    Framing <|-- MultiplexFraming
```

```python
class Framing(ABC):
    @abstractmethod
    def frame(self, buf: bytearray) -> list[bytes]: ...
    def encode(self, payload: bytes) -> bytes: return payload
    def reset(self): pass


class StreamFraming(Framing):
    """No framing — pass bytes up to max_frame_size as-is."""
    def frame(self, buf):
        if not buf: return []
        out = [bytes(buf)]; buf.clear(); return out


class DatagramFraming(StreamFraming): pass  # UDP: one datagram = one frame


class LengthPrefixFraming(Framing):
    def __init__(self, prefix_bytes, *, big_endian=True, header_bytes=0,
                 max_frame=1 << 24):
        self._pb, self._be, self._hb, self._max = \
            prefix_bytes, big_endian, header_bytes, max_frame

    def frame(self, buf):
        out = []
        while len(buf) >= self._pb:
            n = int.from_bytes(buf[:self._pb],
                               "big" if self._be else "little")
            if n > self._max: raise ValueError(f"oversize frame: {n}")
            total = self._pb + n
            if len(buf) < total: break
            out.append(bytes(buf[self._pb:total]))
            del buf[:total]
        return out

    def encode(self, payload):
        return len(payload).to_bytes(self._pb, "big" if self._be else "little") \
               + payload


class VarintLengthFraming(Framing):
    """MQTT / QUIC / WebSocket-style variable-length integer prefix."""
    # ... 1..4 byte varint encoding


class DelimiterFraming(Framing):
    def __init__(self, sep=b"\r\n", *, include_sep=False):
        self._sep, self._inc = sep, include_sep

    def frame(self, buf):
        out = []
        while True:
            i = buf.find(self._sep)
            if i < 0: break
            end = i + len(self._sep)
            out.append(bytes(buf[:end if self._inc else i]))
            del buf[:end]
        return out

    def encode(self, payload):
        return payload + self._sep


class FixedSizeFraming(Framing):
    def __init__(self, size): self._size = size
    def frame(self, buf):
        out = []
        while len(buf) >= self._size:
            out.append(bytes(buf[:self._size]))
            del buf[:self._size]
        return out


class RequestResponseFraming(Framing):
    """HTTP/1.1: split on \r\n\r\n, then body by Content-Length / chunked."""
    # ... state machine over buf


class MultiplexFraming(Framing):
    """HTTP/2 / HTTP/3 / QUIC: extract frames with stream_id + length."""
    # ... per-stream reassembly buffers
```

Every strategy exposes the same two calls. Layers that need to interleave framing + transform just compose them.

### 1c. LayerSpec — the data table

```python
@dataclass(frozen=True)
class LayerSpec:
    name: str
    framing: Framing = field(default_factory=StreamFraming)
    transform_out: Callable[[bytes], bytes] | None = None
    transform_in:  Callable[[bytes], bytes] | None = None
    handshake_out: bytes | Callable[[], bytes] | None = None
    override_class: type["AsyncSession"] | None = None
    allowed_bases: tuple[str, ...] | None = None      # doc / validation
    ports_hint:    tuple[int, ...] = ()
    description:   str = ""
    requires:      tuple[str, ...] = ()               # auth deps (SASL, GSSAPI, …)
```

| Field | Meaning |
|---|---|
| `framing` | how this layer slices a byte stream into messages |
| `transform_out` / `transform_in` | byte-level encrypt/decrypt (TLS, WireGuard, SRTP, …) |
| `handshake_out` | bytes to send once on open (e.g. ClientHello, `EHLO`) |
| `override_class` | escape hatch — use a hand-written class instead of `TableSession` |
| `allowed_bases` | for documentation and optional runtime validation |
| `ports_hint` | suggested ports |
| `requires` | auth shims this layer typically sits above |

The **dependency edges** from the mermaid map are not stored in the spec — they're enforced at *build time* by the stack you pass to `SessionFactory`. Same protocol can sit over TCP or UDP (e.g. OpenVPN); the stack decides.

### 1d. Registry = one dict

```python
LAYERS: dict[str, LayerSpec] = {
    # --- roots -------------------------------------------------------
    "TCP":   LayerSpec("TCP", StreamFraming(), ports_hint=(80, 443, 22, 25, 587, 3306, 5432, 6379, 8080, 8443), description="TCP stream"),
    "UDP":   LayerSpec("UDP", DatagramFraming(), ports_hint=(53, 123, 161, 5353), description="UDP datagrams"),

    # --- security / encryption shims ---------------------------------
    "TLS":   LayerSpec("TLS", LengthPrefixFraming(2, header_bytes=5),
                       transform_out=tls_encrypt, transform_in=tls_decrypt,
                       allowed_bases=("TCP",), ports_hint=(443, 465, 636, 853, 993, 995),
                       description="TLS / SSL over TCP"),
    "DTLS":  LayerSpec("DTLS", DatagramFraming(),
                       transform_out=dtls_encrypt, transform_in=dtls_decrypt,
                       allowed_bases=("UDP",), description="DTLS over UDP"),
    "SSH":   LayerSpec("SSH", LengthPrefixFraming(4, header_bytes=5),
                       allowed_bases=("TCP",), ports_hint=(22, 2222, 8022),
                       description="SSH transport"),
    "IPsec": LayerSpec("IPsec", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(500, 4500)),
    "WireGuard": LayerSpec("WireGuard", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(51820,)),
    "OpenVPN":   LayerSpec("OpenVPN", LengthPrefixFraming(2),
                           allowed_bases=("TCP", "UDP"), ports_hint=(1194,)),
    "SRTP":  LayerSpec("SRTP", FixedSizeFraming(12), transform_out=srtp_encrypt,
                       transform_in=srtp_decrypt, allowed_bases=("RTP", "DTLS")),
    "ZRTP":  LayerSpec("ZRTP", StreamFraming(), allowed_bases=("RTP",)),

    # --- multiplex / framing -----------------------------------------
    "QUIC":     LayerSpec("QUIC", MultiplexFraming(), allowed_bases=("UDP",), ports_hint=(443, 80),
                          description="QUIC transport"),
    "HTTP/1.1": LayerSpec("HTTP/1.1", RequestResponseFraming(),
                          allowed_bases=("TCP", "TLS"), ports_hint=(80, 8080, 8000, 8888, 6099, 3080, 30000, 2358, 11434),
                          description="HTTP/1.1"),
    "HTTP/2":   LayerSpec("HTTP/2", MultiplexFraming(), handshake_out=H2_PREFACE,
                          allowed_bases=("TCP", "TLS"), ports_hint=(443, 8443),
                          description="HTTP/2 with HPACK"),
    "HTTP/3":   LayerSpec("HTTP/3", MultiplexFraming(), allowed_bases=("QUIC",)),
    "WebSocket": LayerSpec("WebSocket", LengthPrefixFraming(2, header_bytes=2),
                           handshake_out=ws_upgrade, allowed_bases=("TCP", "TLS", "HTTP/1.1", "HTTP/2")),

    # --- auth / AAA ---------------------------------------------------
    "SASL":     LayerSpec("SASL", StreamFraming(), allowed_bases=("TCP",)),
    "GSSAPI":   LayerSpec("GSSAPI", StreamFraming(), allowed_bases=("SASL", "Kerb")),
    "Kerberos": LayerSpec("Kerberos", LengthPrefixFraming(4), allowed_bases=("TCP", "UDP"), ports_hint=(88,)),
    "RADIUS":   LayerSpec("RADIUS", LengthPrefixFraming(2), allowed_bases=("UDP", "TLS"), ports_hint=(1812, 1813)),
    "EAP":      LayerSpec("EAP", LengthPrefixFraming(2), allowed_bases=("RADIUS",)),
    "TACACS+":  LayerSpec("TACACS+", LengthPrefixFraming(4), allowed_bases=("TCP",), ports_hint=(49,)),
    "Diameter": LayerSpec("Diameter", LengthPrefixFraming(3), allowed_bases=("TCP", "TLS"), ports_hint=(3868,)),

    # --- tunnel / proxy ----------------------------------------------
    "SOCKS":        LayerSpec("SOCKS", StreamFraming(), allowed_bases=("TCP", "UDP"), ports_hint=(1080,)),
    "HTTP CONNECT": LayerSpec("HTTP CONNECT", StreamFraming(), allowed_bases=("HTTP/1.1",)),
    "STUN":         LayerSpec("STUN", LengthPrefixFraming(2), allowed_bases=("UDP", "TCP"), ports_hint=(3478,)),
    "TURN":         LayerSpec("TURN", LengthPrefixFraming(2), allowed_bases=("UDP", "TCP", "TLS"), ports_hint=(3478, 5349)),
    "ICE":          LayerSpec("ICE", StreamFraming(), allowed_bases=("STUN", "TURN")),
    "L2TP":         LayerSpec("L2TP", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(1701,)),
    "VXLAN":        LayerSpec("VXLAN", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(4789,)),
    "Geneve":       LayerSpec("Geneve", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(6081,)),
    "SSTP":         LayerSpec("SSTP", LengthPrefixFraming(2), allowed_bases=("TLS",), ports_hint=(443,)),

    # --- RPC / messaging ---------------------------------------------
    "ONC RPC":  LayerSpec("ONC RPC", LengthPrefixFraming(4, header_bytes=4, big_endian=True),
                          allowed_bases=("TCP", "UDP"), ports_hint=(111, 2049)),
    "DCE RPC":  LayerSpec("DCE RPC", LengthPrefixFraming(2), allowed_bases=("TCP", "UDP"), ports_hint=(135,)),
    "gRPC":     LayerSpec("gRPC", LengthPrefixFraming(4), allowed_bases=("HTTP/2", "TLS"), ports_hint=(50051,)),
    "Thrift":   LayerSpec("Thrift", LengthPrefixFraming(4), allowed_bases=("TCP", "TLS"), ports_hint=(9090,)),
    "JSON-RPC": LayerSpec("JSON-RPC", RequestResponseFraming(), allowed_bases=("HTTP/1.1",)),
    "XML-RPC":  LayerSpec("XML-RPC", RequestResponseFraming(), allowed_bases=("HTTP/1.1",)),
    "MQTT":     LayerSpec("MQTT", VarintLengthFraming(), allowed_bases=("TCP", "TLS", "WS"), ports_hint=(1883, 8883)),
    "AMQP":     LayerSpec("AMQP", LengthPrefixFraming(4), allowed_bases=("TCP", "TLS"), ports_hint=(5672, 5671)),
    "STOMP":    LayerSpec("STOMP", DelimiterFraming(b"\x00"), allowed_bases=("TCP", "WS"), ports_hint=(61613,)),
    "XMPP":     LayerSpec("XMPP", DelimiterFraming(b"</stream:stream>", include_sep=True),
                          allowed_bases=("TCP", "TLS"), ports_hint=(5222, 5223)),
    "IRC":      LayerSpec("IRC", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS"), ports_hint=(6667, 6697)),
    "Kafka":    LayerSpec("Kafka", LengthPrefixFraming(4), allowed_bases=("TCP", "TLS"), ports_hint=(9092, 9093)),

    # --- media / real-time -------------------------------------------
    "RTP":     LayerSpec("RTP", FixedSizeFraming(12), allowed_bases=("UDP",)),
    "RTCP":    LayerSpec("RTCP", LengthPrefixFraming(2, header_bytes=2), allowed_bases=("UDP",)),
    "RTSP":    LayerSpec("RTSP", DelimiterFraming(b"\r\n\r\n"), allowed_bases=("TCP", "UDP"), ports_hint=(554, 8554)),
    "SIP":     LayerSpec("SIP", DelimiterFraming(b"\r\n\r\n"), allowed_bases=("UDP", "TCP", "TLS"), ports_hint=(5060, 5061)),
    "H.323":   LayerSpec("H.323", LengthPrefixFraming(2), allowed_bases=("TCP", "UDP"), ports_hint=(1720,)),
    "WebRTC":  LayerSpec("WebRTC", StreamFraming(), allowed_bases=("DTLS", "SRTP", "ICE", "SIP", "H.323")),

    # --- applications --------------------------------------------------
    "DNS":     LayerSpec("DNS", LengthPrefixFraming(2), allowed_bases=("UDP", "TCP", "TLS", "HTTP/1.1", "HTTP/2", "QUIC"),
                         ports_hint=(53, 853, 5353)),
    "DHCP":    LayerSpec("DHCP", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(67, 68)),
    "NTP":     LayerSpec("NTP", FixedSizeFraming(48), allowed_bases=("UDP", "TLS"), ports_hint=(123,)),
    "SNMP":    LayerSpec("SNMP", LengthPrefixFraming(2), allowed_bases=("UDP", "TCP"), ports_hint=(161, 162)),
    "Syslog":  LayerSpec("Syslog", DelimiterFraming(b"\n"), allowed_bases=("UDP", "TCP", "TLS"), ports_hint=(514, 6514)),
    "NetFlow": LayerSpec("NetFlow", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(2055,)),
    "BGP":     LayerSpec("BGP", LengthPrefixFraming(2, header_bytes=19), allowed_bases=("TCP",), ports_hint=(179,)),
    "RIP":     LayerSpec("RIP", DatagramFraming(), allowed_bases=("UDP",), ports_hint=(520,)),
    "LDAP":    LayerSpec("LDAP", LengthPrefixFraming(2), allowed_bases=("TCP", "TLS", "SASL", "GSSAPI"), ports_hint=(389, 636)),
    "SMTP":    LayerSpec("SMTP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS", "SASL"), ports_hint=(25, 465, 587)),
    "IMAP":    LayerSpec("IMAP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS", "SASL"), ports_hint=(143, 993)),
    "POP3":    LayerSpec("POP3", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS", "SASL"), ports_hint=(110, 995)),
    "FTP":     LayerSpec("FTP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP", "TLS"), ports_hint=(21,)),
    "SFTP":    LayerSpec("SFTP", LengthPrefixFraming(4), allowed_bases=("SSH",)),
    "SCP":     LayerSpec("SCP", DelimiterFraming(b"\n"), allowed_bases=("SSH",)),
    "SMB":     LayerSpec("SMB", LengthPrefixFraming(4), allowed_bases=("TCP",), ports_hint=(445, 139)),
    "NFS":     LayerSpec("NFS", LengthPrefixFraming(4), allowed_bases=("ONC RPC", "TCP", "UDP"), ports_hint=(2049,)),
    "WebDAV":  LayerSpec("WebDAV", RequestResponseFraming(), allowed_bases=("HTTP/1.1", "TLS")),
    "WSS":     LayerSpec("WSS", LengthPrefixFraming(2, header_bytes=2), allowed_bases=("WS", "TLS")),
    "DB":      LayerSpec("DB", LengthPrefixFraming(3), allowed_bases=("TCP", "TLS"),
                         ports_hint=(3306, 5432, 6379, 27017, 1433, 1521)),
    "RDP":     LayerSpec("RDP", LengthPrefixFraming(2), allowed_bases=("TCP", "TLS"), ports_hint=(3389,)),
    "VNC":     LayerSpec("VNC", LengthPrefixFraming(4, header_bytes=8), allowed_bases=("TCP", "TLS"), ports_hint=(5900, 5901, 5800)),
    "Telnet":  LayerSpec("Telnet", DelimiterFraming(b"\r\n"), allowed_bases=("TCP",), ports_hint=(23,)),
    "WHOIS":   LayerSpec("WHOIS", DelimiterFraming(b"\n"), allowed_bases=("TCP",), ports_hint=(43,)),
    "NNTP":    LayerSpec("NNTP", DelimiterFraming(b"\r\n"), allowed_bases=("TCP",), ports_hint=(119, 563)),
    "CoAP":    LayerSpec("CoAP", LengthPrefixFraming(2, header_bytes=4), allowed_bases=("UDP", "DTLS"), ports_hint=(5683, 5684)),
    "SSDP":    LayerSpec("SSDP", DelimiterFraming(b"\r\n\r\n"), allowed_bases=("UDP",), ports_hint=(1900,)),
    "mDNS":    LayerSpec("mDNS", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(5353,)),
    "LLMNR":   LayerSpec("LLMNR", LengthPrefixFraming(2), allowed_bases=("UDP",), ports_hint=(5355,)),
    "TFTP":    LayerSpec("TFTP", LengthPrefixFraming(2, header_bytes=2), allowed_bases=("UDP",), ports_hint=(69,)),
}
```

Each entry is exactly one line. **~70 protocols, ~70 lines of data.**

### 1e. `TableSession` — the single concrete class

```python
class TableSession(AsyncSession):
    """A session whose behavior is entirely determined by its LayerSpec."""

    def __init__(self, spec: LayerSpec, *, base, persistor=None,
                 max_frame_size=1024, **root_kwargs):
        super().__init__(base=base, persistor=persistor,
                         max_frame_size=max_frame_size, **root_kwargs)
        self.spec = spec
        self._inbuf = bytearray()
        self._handshake_sent = False

    async def _ensure_open(self):
        if not self._handshake_sent and self.spec.handshake_out is not None:
            hs = (self.spec.handshake_out() if callable(self.spec.handshake_out)
                  else self.spec.handshake_out)
            await self._send_down(hs)
            self._handshake_sent = True

    async def send_async(self, data, recv_debounce_seconds=0.1):
        await self._ensure_open()
        wire = data
        if self.spec.transform_out is not None:
            wire = self.spec.transform_out(wire)
        wire = self.spec.framing.encode(wire)
        await self._send_down(wire)

    async def read_async(self, recv_debounce_seconds=0.1):
        raw = await self._read_up(recv_debounce_seconds)
        if raw is None:
            return None
        self._inbuf.extend(raw)
        frames = self.spec.framing.frame(self._inbuf)
        if not frames:
            return None
        if self.spec.transform_in is not None:
            frames = [self.spec.transform_in(f) for f in frames]
        return frames

    def close(self):
        if self._base is not None:
            self._base.close()
```

Every protocol's behavior flows from `LayerSpec.framing` + `transform_out/in` + `handshake_out`.

### 1f. Escape hatch — `override_class`

Some layers can't be expressed as pure data (they need a library, state machine, or asynchronous negotiation):

| Layer | Why | override_class |
|---|---|---|
| Playwright | browser automation, not byte framing | `PlaywrightBrowserSession` |
| SSH (full) | `asyncssh` handles KEX + channels | `AsyncSSHSession` |
| VNC (full) | `asyncvnc` handles RFB state machine | `AsyncVNCSession` |
| OpenAI | uses `openai.AsyncOpenAI` SDK, not raw HTTP | `AsyncOpenAISession` |
| DNS-over-HTTPS | `httpx` + JSON encoding | `AsyncDoHSession` |
| mDNS | `zeroconf` handles multicast + records | `ZeroconfMDNSSession` |
| `*SocketSession` | raw socket convenience | `AsyncSocketSession` |

So:

```python
LAYERS["SSH"].override_class = AsyncSSHSession
LAYERS["VNC"].override_class = AsyncVNCSession
LAYERS["mDNS"].override_class = ZeroconfMDNSSession
LAYERS["Playwright"].override_class = PlaywrightBrowserSession
```

When `SessionFactory` sees `override_class`, it instantiates that class (passing the spec). The override class **is still a `Session`** and gets `_base`, `_persistor`, `_on_io` the same way.

```python
class AsyncSSHSession(AsyncSession):
    """Escape-hatch: wraps asyncssh; spec is metadata only."""
    spec = LAYERS["SSH"]

    async def send_async(self, data, recv_debounce_seconds=0.1):
        self._conn = self._conn or await asyncssh.connect(self._host, self._port)
        self._writer.write(data); await self._writer.drain()

    async def read_async(self, recv_debounce_seconds=0.1):
        return await asyncio.wait_for(self._reader.read(65536),
                                      timeout=recv_debounce_seconds)
```

**Result:** 8 hand-written classes for the layers that genuinely need code, 1 `TableSession` for the rest, and one big `LAYERS` dict for the metadata.

### 1g. Registry + Factory

```python
class SessionRegistry:
    _specs: dict[str, LayerSpec] = {}

    @classmethod
    def register(cls, spec: LayerSpec): cls._specs[spec.name] = spec

    @classmethod
    def get(cls, name: str) -> LayerSpec:
        if name not in cls._specs:
            raise KeyError(f"unknown layer {name!r}")
        return cls._specs[name]


class SessionFactory:
    @staticmethod
    def build(stack: list[str], *, persistor=None, max_frame_size=1024,
              **root_kwargs) -> AsyncSession:
        if not stack:
            raise ValueError("empty stack")
        root_spec = SessionRegistry.get(stack[0])
        root = SessionFactory._instantiate(root_spec, base=None, **root_kwargs)
        return SessionFactory.upgrade(root, stack[1:],
                                      persistor=persistor,
                                      max_frame_size=max_frame_size)

    @staticmethod
    def upgrade(base: Session, extra: list[str], *,
                persistor=None, max_frame_size=1024) -> AsyncSession:
        top: Session = base
        for i, name in enumerate(extra):
            spec = SessionRegistry.get(name)
            is_top = (i == len(extra) - 1)
            top = SessionFactory._instantiate(
                spec, base=top,
                persistor=persistor if is_top else None,
                max_frame_size=max_frame_size if is_top else None,
            )
        if not extra:                    # upgrade([]) attaches persistor to base
            base._persistor = persistor
            base._max_frame_size = max_frame_size
        return top

    @staticmethod
    def _instantiate(spec: LayerSpec, *, base, **kwargs) -> AsyncSession:
        if spec.override_class is not None:
            return spec.override_class(spec=spec, base=base, **kwargs)
        return TableSession(spec=spec, base=base, **kwargs)
```

---

## 2. `Session` / `AsyncSession` — Same as Before

```mermaid
classDiagram
    class Session {
        <<abstract>>
        #_base: Session|None
        #_persistor: Persistor|None
        #_max_frame_size: int|None
        #_on_io: Callable|None
        +__init__(base=None, persistor=None, max_frame_size=1024)
        +send(data, recv_debounce_seconds=0.1)
        +read(recv_debounce_seconds=0.1)
        +history() DataFrame
        +close()
        #_fire_io(direction, payload)
        +root() Session
    }
    class AsyncSession {
        <<abstract>>
        +send_async(data, recv_debounce_seconds=0.1)*
        +read_async(recv_debounce_seconds=0.1)*
        +send(data, recv_debounce_seconds=0.1)
        +read(recv_debounce_seconds=0.1)
        #_bridge: AsyncBridge
        #_send_down(data)
        #_read_up(debounce)
    }
    Session <|-- AsyncSession
    AsyncSession <|-- TableSession
    AsyncSession <|-- AsyncSocketSession
    AsyncSession <|-- AsyncSSHSession
    AsyncSession <|-- AsyncVNCSession
    AsyncSession <|-- AsyncOpenAISession
    AsyncSession <|-- ZeroconfMDNSSession
    AsyncSession <|-- PlaywrightBrowserSession
    AsyncSession <|-- WifiSession
    AsyncSession <|-- BluetoothSession
```

New addition: `Session.root()` returns the bottom-most session (the one with `base is None`) so `SessionFactory.upgrade` can reuse the live socket.

```python
def root(self) -> "Session":
    s = self
    while s._base is not None:
        s = s._base
    return s
```

---

## 3. `SocketBannerHandler` — Takes Stack **and** Live Session

```mermaid
classDiagram
    class Handler { <<abstract>> +ports +description +handle +ahandle +check_banner }
    class HandlerDispatcher { <<abstract>> +__iadd__ +__isub__ }
    class AsyncHandler
    class ContextfulHandler { #_session: Session }
    class SocketBannerHandler {
        -_stack: list~str~
        -_session: Session
        -_persistor: Persistor|None
        -_children: list~Handler~
        -_glue: bytearray
        +__init__(stack, session, *, persistor=None, children=None)
        +ahandle(target, *args, port=None, **kwargs)
        +_rebind_stack(new_stack)
    }
    class RegexBannerHandler { -_pattern -_name +check_banner }
    class HandlerChain { -_handlers }

    Handler <|-- HandlerDispatcher
    Handler <|-- AsyncHandler
    AsyncHandler <|-- ContextfulHandler
    ContextfulHandler <|-- SocketBannerHandler
    HandlerDispatcher <|-- SocketBannerHandler
    Handler <|-- RegexBannerHandler
    HandlerDispatcher <|-- HandlerChain
```

```python
class SocketBannerHandler(ContextfulHandler, HandlerDispatcher):

    def __init__(self, stack: list[str], session: Session, *,
                 persistor: Persistor | None = None,
                 max_frame_size: int = 1024,
                 children: list[Handler] | None = None):
        super().__init__(session)
        self._stack = list(stack)
        self._persistor = persistor
        self._max_frame_size = max_frame_size
        # attach persistor / hook to the top of the stack
        self._session._persistor = persistor
        self._session._max_frame_size = max_frame_size
        self._session._on_io = self._on_io
        self._children: list[Handler] = []
        self._glue = bytearray()
        for c in children or ():
            self += c

    # --- Handler ---
    def ports(self): return None
    def description(self): return "→".join(self._stack)
    def check_banner(self, banner: bytes) -> bool: return bool(banner)

    # --- Dispatcher ---
    def __iadd__(self, other: Handler):
        other.check_banner(b"")
        self._children.append(other)
        return self

    def __isub__(self, other: Handler):
        self._children.remove(other)
        return self

    # --- Async execution ---
    async def ahandle(self, target, *args, port=None, **kwargs):
        await self._session.send(self._probe_bytes(port))
        banner = bytes(self._glue)
        for child in self._children:
            if child.check_banner(banner):
                deeper = getattr(child, "REQUIRED_STACK", None)
                if deeper and deeper != self._stack:
                    self._rebind_stack(deeper)
                return await child.ahandle(
                    target, *args, port=port, banner=banner, **kwargs)
        return self.handle_banner(banner)

    # --- Stack rebinding — reuses the live socket -------------------
    def _rebind_stack(self, new_stack: list[str]):
        root = self._session.root()           # live TCP/UDP with open fd
        base_len = self._stack.index(
            type(root).spec.name if hasattr(type(root), "spec") else
            self._stack[0]) + 1
        extra = new_stack[base_len:]
        new_top = SessionFactory.upgrade(
            root, extra,
            persistor=self._persistor,
            max_frame_size=self._max_frame_size,
        )
        new_top._on_io = self._on_io
        self._stack = list(new_stack)
        self._session = new_top

    # --- Persistence hook ---
    def _on_io(self, direction: str, payload: bytes):
        if direction != "recv":
            return
        self._glue.extend(payload)
        parsed = self.load_full(bytes(self._glue))
        if parsed is None:
            return
        if self._persistor is not None:
            self._persistor.store_full(parsed)
```

### The two constructor arguments

| Arg | Meaning |
|---|---|
| `stack` | **desired layer stack**, e.g. `["TCP", "TLS", "HTTP/1.1"]` — the handler will build deeper stacks as needed |
| `session` | a **live, raw opened session** to probe with — e.g. an `AsyncSocketSession` wrapping an already-connected socket |

Typical construction:

```python
sock = AsyncSocketSession(sock=await open_connection(host, port))
handler = SocketBannerHandler(
    stack=["TCP"],
    session=sock,
    persistor=JSONLPersistor("scan.jsonl"),
)
handler += RegexBannerHandler(r"^SSH-", name="SSH",
                              stack=["TCP", "SSH"])
handler += RegexBannerHandler(r"^HTTP/", name="HTTP",
                              stack=["TCP", "HTTP/1.1"])
```

When a child declares a deeper stack, the handler upgrades in-place — reusing the live TCP root.

---

## 4. `RegexBannerHandler` — Unchanged

```python
class RegexBannerHandler(Handler):
    def __init__(self, pattern, name, *, stack: list[str] | None = None):
        self._pattern = re.compile(pattern) if isinstance(pattern, str) else pattern
        self._name = name
        self.REQUIRED_STACK = stack

    def ports(self): return None
    def description(self): return f"regex:{self._pattern.pattern} → {self._name}"

    def check_banner(self, banner: bytes) -> bool:
        try:
            return bool(self._pattern.search(banner.decode("utf-8", "ignore")))
        except Exception:
            return False

    def handle(self, target, *args, port=None, banner=b"", **kwargs):
        return ScanResult(port=port, service=self._name, banner=banner)
```

---

## 5. `HandlerChain` — Mixed Sync/Async

```python
class HandlerChain(HandlerDispatcher):
    def __init__(self, handlers):
        self._handlers = _flatten(handlers)

    def ports(self):
        seen, out = set(), []
        for h in self._handlers:
            p = h.ports()
            if p is None: continue
            for x in p:
                if x not in seen: seen.add(x); out.append(x)
        return out or None

    def description(self):
        return " → ".join(h.description() for h in self._handlers)

    def __iadd__(self, other): self._handlers.append(other); return self
    def __isub__(self, other): self._handlers.remove(other); return self

    async def ahandle(self, target, *args, **kwargs):
        for h in self._handlers:
            r = await h.ahandle(target, *args, **kwargs)
            if r is not None: return r
        return None
```

---

## 6. `Persistor` — Unchanged

```mermaid
classDiagram
    class Persistor {
        <<abstract>>
        +history() DataFrame*
        +register(column_name)*
        +store(col, data, previous_id=None) int*
        +store_full(data: dict) int
        +retrieve(id, location=None) dict|None
        +persist(path)*
        +resume(path)*
    }
    Persistor <|-- PicklePersistor
    Persistor <|-- JSONLPersistor
    Persistor <|-- SQLitePersistor
    Persistor <|-- ArrowPlasmaPersistor
```

`store_full` chains `store` calls via `previous_id` and returns the last id. `retrieve(id, location)` checks cache, auto-`resume`s if needed, returns `None` if missing.

---

## 7. ARP Fetchers — Unchanged

```mermaid
classDiagram
    class ARPTableFetcher { <<abstract>> +iptable() DataFrame +__lshift__ +__rshift__ }
    class PlaywrightFetcher { <<abstract>> +run(context,password)* }
    class TPLoginFetcher
    class UnixArpFetcher
    class WindowsArpFetcher
    class OpenWRTFetcher
    class FetcherChain
    ARPTableFetcher <|-- PlaywrightFetcher
    PlaywrightFetcher <|-- TPLoginFetcher
    ARPTableFetcher <|-- UnixArpFetcher
    ARPTableFetcher <|-- WindowsArpFetcher
    ARPTableFetcher <|-- OpenWRTFetcher
    ARPTableFetcher <|-- FetcherChain
```

Fallback: `TPLoginFetcher >> UnixArpFetcher >> OpenWRTFetcher`.

---

## 8. `AsyncBridge` — One Loop Per Process

```mermaid
flowchart LR
    subgraph Main["Worker thread"]
        A["Handler.handle"]
        B["Session.send / read"]
    end
    subgraph BG["AsyncBridge loop thread"]
        L["asyncio loop"]
        C["ahandle / send_async / read_async"]
    end
    A & B -->|run_coroutine_threadsafe| L --> C
    C --> L -->|future.result| A & B
```

---

## 9. Config + Engine

| CLI | ENV | Default |
|---|---|---|
| `-t/--port-timeout` | `PORT_TIMEOUT` | `0.1` |
| `--workers` | `SCAN_WORKERS` | `os.cpu_count()` |
| `--port-strategy` | `PORT_STRATEGY` | `first` |
| `--resolve-host` | `RESOLVE_HOSTS` | `tplogin.cn,localhost` |
| `--output` | `OUTPUT_CSV` | `tplogin-arp-enriched.csv` |
| `--fetcher` | `ARP_FETCHER` | `tplogin` |
| `--unsafe-tplogin-password` | `TPLOGIN_PASSWORD` | prompt |
| `--browser` | `PW_BROWSER` | auto |

```mermaid
flowchart TD
    A[Config] --> B["Root HandlerChain via << / >>"]
    A --> C["FetcherChain via >>"]
    C --> D["iptable() → DataFrame[target, mode, …]"]
    D --> E["ThreadPoolExecutor(max_workers)"]
    E --> F["worker(target)"]
    F --> G["chain.handle(target)"]
    G --> H["SocketBannerHandler builds stack, dispatches, upgrades"]
    H --> I["ScanResults + parsed packets → Persistor"]
    I --> K[Unified table → CSV + ssh.sh]
```

---

## 10. End-to-End Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Eng as Engine
    participant HC as HandlerChain
    participant SBH as SocketBannerHandler
    participant Sess as Session (top)
    participant F as SessionFactory
    participant P as Persistor
    participant AB as AsyncBridge

    Eng->>HC: handle(target)
    HC->>AB: bridge → await ahandle
    HC->>SBH: await ahandle(target, port)
    SBH->>Sess: await send(probe)
    Sess-->>SBH: frames (via _on_io)
    SBH->>SBH: glue → load_full
    SBH->>P: store_full(parsed) → id
    SBH->>SBH: child.check_banner
    SBH->>F: upgrade(root, ["TLS","HTTP/1.1"])
    F-->>SBH: HTTP1Session (top)
    SBH->>Sess: await send(HTTP probe)
    Sess-->>SBH: HTTP response → parsed
    SBH-->>HC: ScanResult
    HC-->>Eng: rows
```

---

## 11. Class Inventory (Final)

| Layer | Class | Abstract | Key members |
|---|---|---|---|
| **Framing** | `Framing` | ✔ | `frame(buf)`, `encode(payload)` |
| | `StreamFraming`, `DatagramFraming`, `LengthPrefixFraming`, `VarintLengthFraming`, `DelimiterFraming`, `FixedSizeFraming`, `RequestResponseFraming`, `MultiplexFraming` | ✘ | 7 concrete strategies |
| **Layer spec** | `LayerSpec` | ✘ | `dataclass(frozen)` — name, framing, transforms, handshake, override, ports, deps |
| | `LAYERS: dict[str, LayerSpec]` | ✘ | ~70 entries, one per protocol |
| **Session** | `Session` | ✔ | `_base`, `_persistor`, `_on_io`, `root`, `_fire_io` |
| | `AsyncSession` | ✔ | `send_async*`, `read_async*`, sync wrappers, `_send_down` / `_read_up` |
| | `TableSession` | ✘ | driven entirely by a `LayerSpec` |
| | Escape-hatch classes (`AsyncSocketSession`, `AsyncSSHSession`, `AsyncVNCSession`, `AsyncOpenAISession`, `ZeroconfMDNSSession`, `PlaywrightBrowserSession`, `WifiSession`, `BluetoothSession`) | ✘ | 8 hand-written classes |
| | `SessionRegistry`, `SessionFactory` | ✘ | dict + `build` / `upgrade` |
| **Handler** | `Handler` | ✔ | `REQUIRED_STACK`, `ports*`, `description*`, `handle*`, `ahandle` (default), `check_banner`, `<<`, `>>` |
| | `HandlerDispatcher` | ✔ | `__iadd__*`, `__isub__*` |
| | `AsyncHandler` | ✔ | `ahandle*` + sync `handle` via bridge |
| | `ContextfulHandler` | ✔ | `_session` — kept for WiFi / BT / non-socket targets |
| | `SocketBannerHandler` | ✘ | `(stack, session, *, persistor, children)`; `_rebind_stack` upgrades over live root |
| | `RegexBannerHandler` | ✘ | regex + optional `REQUIRED_STACK` |
| | `HandlerChain` | ✘ | mixed sync / async; `ports()` union |
| **Persistor** | `Persistor` | ✔ | `history*`, `register*`, `store*`, `store_full`, `retrieve`, `persist*`, `resume*` |
| | `PicklePersistor`, `JSONLPersistor`, `SQLitePersistor`, `ArrowPlasmaPersistor` | ✘ | disk-backed |
| **Bridge** | `AsyncBridge` | ✘ | `run(coro)` |
| **Fetcher** | `ARPTableFetcher` | ✔ | `iptable*`, `<<`, `>>` |
| | `PlaywrightFetcher` | ✔ | `run*`, `_prepare_env`, `_detect_latest_browser` |
| | `TPLoginFetcher`, `UnixArpFetcher`, `WindowsArpFetcher`, `OpenWRTFetcher`, `FetcherChain` | mixed | per-source |
| **App** | `Config`, `Engine` | ✘ | — |

**Count:** ~70 protocols → **1 `TableSession` + ~8 overrides + 1 `LAYERS` dict**. No subclass explosion.

---

## 12. Final Confirmations

1. **`SocketBannerHandler(stack, session, ...)`** — `session` is a pre-opened `Session` (usually `AsyncSocketSession` over a live socket). The handler attaches `_persistor` / `_on_io` / `_max_frame_size` to the top of that session. Confirm.
2. **`_rebind_stack(new_stack)`** — walks to `session.root()` (live socket), then `SessionFactory.upgrade(root, extra)`. Confirm.
3. **`LAYERS` names match the mermaid map** (e.g. `"HTTP/1.1"`, `"ONC RPC"`, `"TACACS+"`). Confirm — I'll use these exact strings.
4. **`override_class` for `asyncssh`/`asyncvnc`/`openai`/`playwright`/`zeroconf`/raw socket** — 8 hand-written classes; everything else is `TableSession` + `LayerSpec`. Confirm.
5. **`Framing` API**: `frame(buf: bytearray) -> list[bytes]` mutates `buf` in place; `encode(payload) -> bytes` adds headers. Confirm.

Say go and I'll write the implementation.