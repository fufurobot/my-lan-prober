"""Tests for :mod:`my_lan_prober.framing`.

Contract (from ``design.md`` § 1b):

* ``frame(buf: bytearray) -> list[bytes]`` extracts every *complete* message
  and mutates ``buf`` in place, dropping the consumed bytes.
* ``encode(payload: bytes) -> bytes`` adds this layer's headers/prefixes.
* ``reset()`` drops any per-stream state.
"""

from __future__ import annotations

import pytest

from my_lan_prober.framing import (
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


# ---------------------------------------------------------------------------
# StreamFraming / DatagramFraming
# ---------------------------------------------------------------------------
def test_stream_framing_yields_whole_buffer_and_drains_it():
    framing = StreamFraming()
    buf = bytearray(b"hello")

    assert framing.frame(buf) == [b"hello"]
    assert buf == b""


def test_stream_framing_empty_buffer_yields_nothing():
    framing = StreamFraming()
    buf = bytearray()

    assert framing.frame(buf) == []
    assert buf == b""


def test_stream_framing_encode_is_identity():
    assert StreamFraming().encode(b"payload") == b"payload"


def test_datagram_framing_behaves_like_stream():
    framing = DatagramFraming()
    buf = bytearray(b"datagram")

    assert framing.frame(buf) == [b"datagram"]
    assert buf == b""
    assert framing.encode(b"x") == b"x"


# ---------------------------------------------------------------------------
# LengthPrefixFraming
# ---------------------------------------------------------------------------
def test_length_prefix_framing_extracts_complete_frames():
    framing = LengthPrefixFraming(2)
    buf = bytearray(b"\x00\x03abc\x00\x02de")

    assert framing.frame(buf) == [b"abc", b"de"]
    assert buf == b""


def test_length_prefix_framing_keeps_partial_frame_buffered():
    framing = LengthPrefixFraming(2)
    buf = bytearray(b"\x00\x05abc")

    assert framing.frame(buf) == []
    assert buf == b"\x00\x05abc"

    buf.extend(b"de")
    assert framing.frame(buf) == [b"abcde"]
    assert buf == b""


def test_length_prefix_framing_keeps_incomplete_header_buffered():
    framing = LengthPrefixFraming(2)
    buf = bytearray(b"\x00")

    assert framing.frame(buf) == []
    assert buf == b"\x00"


def test_length_prefix_framing_little_endian():
    framing = LengthPrefixFraming(2, big_endian=False)
    buf = bytearray(b"\x03\x00abc")

    assert framing.frame(buf) == [b"abc"]


def test_length_prefix_framing_header_bytes_offsets_payload_start():
    """TLS record: ``type(1) version(2) length(2)``.

    The length field is at offset 3, not offset 0, so the prefix must be
    given an explicit ``prefix_offset``.  Reading from offset 0 would take
    ``0x16 0x03`` as the length (5635) instead of the real ``0x00 0x05``.
    """
    framing = LengthPrefixFraming(2, header_bytes=5, prefix_offset=3)
    buf = bytearray(b"\x16\x03\x01\x00\x05abcde")

    assert framing.frame(buf) == [b"abcde"]
    assert buf == b""


def test_length_prefix_framing_encode_writes_prefix_at_offset():
    framing = LengthPrefixFraming(2, header_bytes=5, prefix_offset=3)

    assert framing.encode(b"abcde") == b"\x00\x00\x00\x00\x05abcde"


def test_length_prefix_framing_encode_adds_prefix():
    framing = LengthPrefixFraming(2)

    assert framing.encode(b"abc") == b"\x00\x03abc"


def test_length_prefix_framing_rejects_oversize_frame():
    framing = LengthPrefixFraming(2, max_frame=8)
    buf = bytearray(b"\x00\x09" + b"a" * 9)

    with pytest.raises(ValueError, match="oversize frame"):
        framing.frame(buf)


# ---------------------------------------------------------------------------
# VarintLengthFraming (MQTT-style 1..4 byte varint)
# ---------------------------------------------------------------------------
def test_varint_framing_single_byte_length():
    framing = VarintLengthFraming()
    buf = bytearray(b"\x03abc")

    assert framing.frame(buf) == [b"abc"]
    assert buf == b""


def test_varint_framing_two_byte_length():
    """MQTT varint: 128 encodes as ``0x80 0x01``."""
    framing = VarintLengthFraming()
    payload = b"a" * 128
    buf = bytearray(b"\x80\x01" + payload)

    assert framing.frame(buf) == [payload]
    assert buf == b""


def test_varint_framing_waits_for_full_payload():
    framing = VarintLengthFraming()
    buf = bytearray(b"\x80\x01" + b"a" * 10)

    assert framing.frame(buf) == []
    assert buf == b"\x80\x01" + b"a" * 10


def test_varint_framing_encode_round_trips_128():
    framing = VarintLengthFraming()
    encoded = framing.encode(b"a" * 128)

    assert encoded[:2] == b"\x80\x01"
    assert framing.frame(bytearray(encoded)) == [b"a" * 128]


# ---------------------------------------------------------------------------
# DelimiterFraming
# ---------------------------------------------------------------------------
def test_delimiter_framing_splits_on_crlf():
    framing = DelimiterFraming(b"\r\n")
    buf = bytearray(b"220 hi\r\n250 ok\r\n")

    assert framing.frame(buf) == [b"220 hi", b"250 ok"]
    assert buf == b""


def test_delimiter_framing_include_sep_keeps_terminator():
    framing = DelimiterFraming(b"\r\n", include_sep=True)
    buf = bytearray(b"220 hi\r\n")

    assert framing.frame(buf) == [b"220 hi\r\n"]


def test_delimiter_framing_buffers_incomplete_trailer():
    framing = DelimiterFraming(b"\r\n\r\n")
    buf = bytearray(b"GET / HTTP/1.1\r\nHost: x")

    assert framing.frame(buf) == []
    assert buf == b"GET / HTTP/1.1\r\nHost: x"


def test_delimiter_framing_encode_appends_separator():
    assert DelimiterFraming(b"\r\n").encode(b"EHLO") == b"EHLO\r\n"


# ---------------------------------------------------------------------------
# FixedSizeFraming
# ---------------------------------------------------------------------------
def test_fixed_size_framing_extracts_exact_records():
    framing = FixedSizeFraming(4)
    buf = bytearray(b"aaaabbbbcc")

    assert framing.frame(buf) == [b"aaaa", b"bbbb"]
    assert buf == b"cc"


def test_fixed_size_framing_encode_is_identity():
    assert FixedSizeFraming(4).encode(b"abcd") == b"abcd"


# ---------------------------------------------------------------------------
# RequestResponseFraming (HTTP/1.1)
# ---------------------------------------------------------------------------
def test_request_response_framing_with_content_length():
    framing = RequestResponseFraming()
    buf = bytearray(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA")

    assert framing.frame(buf) == [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"]
    assert buf == b"EXTRA"


def test_request_response_framing_waits_for_body():
    framing = RequestResponseFraming()
    buf = bytearray(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel")

    assert framing.frame(buf) == []
    assert buf == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"


def test_request_response_framing_waits_for_header_terminator():
    framing = RequestResponseFraming()
    buf = bytearray(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n")

    assert framing.frame(buf) == []


def test_request_response_framing_empty_body_on_204():
    framing = RequestResponseFraming()
    buf = bytearray(b"HTTP/1.1 204 No Content\r\n\r\n")

    assert framing.frame(buf) == [b"HTTP/1.1 204 No Content\r\n\r\n"]
    assert buf == b""


def test_request_response_framing_encodes_headers_with_blank_line():
    framing = RequestResponseFraming()

    assert framing.encode(b"GET / HTTP/1.1\r\nHost: x") == (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")


def test_request_response_framing_extracts_two_pipelined_responses():
    framing = RequestResponseFraming()
    buf = bytearray(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb"
    )

    assert framing.frame(buf) == [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb",
    ]
    assert buf == b""


# ---------------------------------------------------------------------------
# MultiplexFraming
# ---------------------------------------------------------------------------
def test_multiplex_framing_extracts_stream_id_length_frames():
    """HTTP/2-ish frame: ``length(3) type(1) flags(1) stream_id(4)``."""
    framing = MultiplexFraming()
    frame = b"\x00\x00\x03\x00\x00\x00\x00\x00\x01abc"
    buf = bytearray(frame)

    assert framing.frame(buf) == [frame]
    assert buf == b""


def test_multiplex_framing_waits_for_complete_frame():
    framing = MultiplexFraming()
    buf = bytearray(b"\x00\x00\x03\x00\x00\x00\x00\x00\x01ab")

    assert framing.frame(buf) == []
    assert buf == b"\x00\x00\x03\x00\x00\x00\x00\x00\x01ab"


def test_multiplex_framing_encode_prefixes_header():
    framing = MultiplexFraming()
    encoded = framing.encode(b"abc")

    assert encoded == b"\x00\x00\x03\x00\x00\x00\x00\x00\x00abc"


# ---------------------------------------------------------------------------
# Reset / base class
# ---------------------------------------------------------------------------
def test_reset_is_available_on_every_strategy():
    for framing in (
        StreamFraming(),
        DatagramFraming(),
        LengthPrefixFraming(2),
        VarintLengthFraming(),
        DelimiterFraming(b"\r\n"),
        FixedSizeFraming(4),
        RequestResponseFraming(),
        MultiplexFraming(),
    ):
        framing.reset()


def test_framing_is_abstract():
    with pytest.raises(TypeError):
        Framing()
