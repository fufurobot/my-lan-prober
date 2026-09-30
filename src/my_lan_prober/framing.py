"""Framing strategies — how each protocol layer slices a byte stream.

Every strategy implements the same two-call contract described in
``design.md`` § 1b:

``frame(buf)``
    Extract every *complete* message from ``buf`` and mutate ``buf`` in
    place, dropping the bytes that were consumed.  Incomplete trailers stay
    buffered for the next ``frame()`` call.

``encode(payload)``
    Add this layer's headers/prefixes to an outgoing payload.

``reset()``
    Drop per-stream state (for strategies that carry any).

A ``Framing`` instance is stateful and belongs to exactly one live stream.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

__all__ = [
    "Framing",
    "StreamFraming",
    "DatagramFraming",
    "LengthPrefixFraming",
    "VarintLengthFraming",
    "DelimiterFraming",
    "FixedSizeFraming",
    "RequestResponseFraming",
    "MultiplexFraming",
]


class Framing(ABC):
    """Extract complete messages from a growing byte buffer."""

    @abstractmethod
    def frame(self, buf: bytearray) -> List[bytes]:
        """Return complete messages found in ``buf``, draining them from it."""
        raise NotImplementedError

    def encode(self, payload: bytes) -> bytes:
        """Add this layer's headers/prefixes. Default: pass through."""
        return payload

    def reset(self) -> None:
        """Drop per-stream state.

        Most strategies are stateless — ``frame()`` keeps any partial message
        in the caller's buffer — so the default is intentionally empty.
        """


class StreamFraming(Framing):
    """No framing — hand the whole buffer up as a single frame."""

    def frame(self, buf: bytearray) -> List[bytes]:
        if not buf:
            return []
        out = [bytes(buf)]
        buf.clear()
        return out


class DatagramFraming(StreamFraming):
    """UDP: one datagram is already one frame."""


class LengthPrefixFraming(Framing):
    """A fixed-width big/little-endian length prefix ahead of each payload.

    ``header_bytes`` is the total size of the layer header, *including* the
    length prefix.  ``prefix_offset`` says where inside that header the
    length field actually sits.

    The offset matters because not every protocol starts with its length.
    A TLS record is ``type(1) version(2) length(2)``, so for TLS you want
    ``LengthPrefixFraming(2, header_bytes=5, prefix_offset=3)``.  (``design.md``
    § 1c writes this as ``LengthPrefixFraming(2, header_bytes=5)``, which
    would read the length from offset 0 — that is ``0x16 0x03`` for a
    handshake record, i.e. 5635 bytes, not the 5-byte header it looks like.)
    """

    def __init__(
        self,
        prefix_bytes: int,
        *,
        big_endian: bool = True,
        header_bytes: int = 0,
        prefix_offset: int = 0,
        max_frame: int = 1 << 24,
    ) -> None:
        if prefix_bytes <= 0:
            raise ValueError("prefix_bytes must be > 0")
        header_bytes = header_bytes or prefix_bytes
        if header_bytes < prefix_bytes:
            raise ValueError("header_bytes must be >= prefix_bytes")
        if prefix_offset < 0 or prefix_offset + prefix_bytes > header_bytes:
            raise ValueError("prefix_offset + prefix_bytes must fit in header_bytes")
        self.prefix_bytes = prefix_bytes
        self.big_endian = big_endian
        self.header_bytes = header_bytes
        self.prefix_offset = prefix_offset
        self.max_frame = max_frame

    def frame(self, buf: bytearray) -> List[bytes]:
        out: List[bytes] = []
        while len(buf) >= self.header_bytes:
            start = self.prefix_offset
            length = int.from_bytes(
                buf[start : start + self.prefix_bytes],
                "big" if self.big_endian else "little",
            )
            if length > self.max_frame:
                raise ValueError(f"oversize frame: {length}")
            total = self.header_bytes + length
            if len(buf) < total:
                break
            out.append(bytes(buf[self.header_bytes : total]))
            del buf[:total]
        return out

    def encode(self, payload: bytes) -> bytes:
        prefix = len(payload).to_bytes(self.prefix_bytes, "big" if self.big_endian else "little")
        header = bytearray(self.header_bytes)
        header[self.prefix_offset : self.prefix_offset + self.prefix_bytes] = prefix
        return bytes(header) + payload


class VarintLengthFraming(Framing):
    """MQTT / QUIC / WebSocket-style variable-length integer prefix.

    Each byte contributes 7 bits of length, the high bit meaning "another
    byte follows". At most :attr:`max_bytes` bytes are consumed.
    """

    def __init__(self, *, max_bytes: int = 4, max_frame: int = 1 << 24) -> None:
        self.max_bytes = max_bytes
        self.max_frame = max_frame

    def _read_varint(self, buf: bytearray) -> tuple[int, int] | None:
        """Return ``(value, prefix_len)`` or ``None`` if incomplete."""
        value = 0
        multiplier = 1
        for i in range(min(len(buf), self.max_bytes)):
            byte = buf[i]
            value += (byte & 0x7F) * multiplier
            if not byte & 0x80:
                return value, i + 1
            multiplier *= 128
        return None

    def frame(self, buf: bytearray) -> List[bytes]:
        out: List[bytes] = []
        while buf:
            parsed = self._read_varint(buf)
            if parsed is None:
                break
            length, prefix_len = parsed
            if length > self.max_frame:
                raise ValueError(f"oversize frame: {length}")
            if len(buf) < prefix_len + length:
                break
            out.append(bytes(buf[prefix_len : prefix_len + length]))
            del buf[: prefix_len + length]
        return out

    def encode(self, payload: bytes) -> bytes:
        length = len(payload)
        prefix = bytearray()
        while True:
            byte = length % 128
            length //= 128
            if length:
                byte |= 0x80
            prefix.append(byte)
            if not length:
                break
        return bytes(prefix) + payload


class DelimiterFraming(Framing):
    """Split on a fixed separator (``\\r\\n``, ``\\x00``, ``</stream>``, …)."""

    def __init__(self, sep: bytes = b"\r\n", *, include_sep: bool = False) -> None:
        if not sep:
            raise ValueError("sep must be non-empty")
        self.sep = sep
        self.include_sep = include_sep

    def frame(self, buf: bytearray) -> List[bytes]:
        out: List[bytes] = []
        while True:
            index = buf.find(self.sep)
            if index < 0:
                break
            end = index + len(self.sep)
            out.append(bytes(buf[: end if self.include_sep else index]))
            del buf[:end]
        return out

    def encode(self, payload: bytes) -> bytes:
        return payload + self.sep


class FixedSizeFraming(Framing):
    """Every record is exactly ``size`` bytes (RTP, NTP, SRTP, …)."""

    def __init__(self, size: int) -> None:
        if size <= 0:
            raise ValueError("size must be > 0")
        self.size = size

    def frame(self, buf: bytearray) -> List[bytes]:
        out: List[bytes] = []
        while len(buf) >= self.size:
            out.append(bytes(buf[: self.size]))
            del buf[: self.size]
        return out


class RequestResponseFraming(Framing):
    """HTTP/1.1: headers up to the blank line, then the body.

    Body length comes from ``Content-Length``. Responses that cannot carry a
    body (``1xx``/``204``/``304``) end at the blank line, as do messages that
    are terminated by connection close.
    """

    _NO_BODY_STATUS = ("204", "304")

    def frame(self, buf: bytearray) -> List[bytes]:
        out: List[bytes] = []
        while True:
            end = buf.find(b"\r\n\r\n")
            if end < 0:
                break
            head_end = end + 4
            head = bytes(buf[:head_end])
            body_len = self._body_length(head)
            if body_len is None:  # no body: message ends at the blank line
                out.append(head)
                del buf[:head_end]
                continue
            if len(buf) < head_end + body_len:
                break
            out.append(bytes(buf[: head_end + body_len]))
            del buf[: head_end + body_len]
        return out

    def _body_length(self, head: bytes) -> int | None:
        """Body length, or ``None`` when the message has no body."""
        if self._is_response(head):
            status = head.split(b"\r\n", 1)[0].split(b" ")[1:2]
            if status and status[0].startswith(b"1"):
                return None
            if status and status[0] in (s.encode() for s in self._NO_BODY_STATUS):
                return None
        for line in head.split(b"\r\n"):
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                try:
                    return int(value.strip())
                except ValueError:
                    return None
        # No Content-Length: a message with no declared length runs until the
        # peer closes, which this framer cannot know — so treat it as complete
        # at the header terminator.
        return None

    @staticmethod
    def _is_response(head: bytes) -> bool:
        return head.startswith(b"HTTP/")

    def encode(self, payload: bytes) -> bytes:
        return payload if payload.endswith(b"\r\n\r\n") else payload + b"\r\n\r\n"


class MultiplexFraming(Framing):
    """HTTP/2-style frames: ``length(3) type(1) flags(1) stream_id(4)``.

    The 3-byte big-endian length counts only the payload that follows the
    9-byte header.
    """

    HEADER = 9

    def __init__(self, *, max_frame: int = 1 << 24) -> None:
        self.max_frame = max_frame

    def frame(self, buf: bytearray) -> List[bytes]:
        out: List[bytes] = []
        while len(buf) >= self.HEADER:
            length = int.from_bytes(buf[:3], "big")
            if length > self.max_frame:
                raise ValueError(f"oversize frame: {length}")
            total = self.HEADER + length
            if len(buf) < total:
                break
            out.append(bytes(buf[:total]))
            del buf[:total]
        return out

    def encode(self, payload: bytes) -> bytes:
        return len(payload).to_bytes(3, "big") + b"\x00\x00" + (0).to_bytes(4, "big") + payload
