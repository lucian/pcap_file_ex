# HTTP/2 Test Frame Data
#
# This file contains raw HTTP/2 frames for unit testing.
# Use with: Code.eval_file("test/fixtures/http2_frames.exs")
#
# Frame format: 9-byte header + payload
#   Length:    3 bytes (24-bit)
#   Type:      1 byte
#   Flags:     1 byte
#   Reserved:  1 bit
#   Stream ID: 31 bits

# Connection preface (client sends first)
connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Helper to build frame header
build_frame = fn length, type, flags, stream_id ->
  <<length::24, type::8, flags::8, 0::1, stream_id::31>>
end

# Frame types
frame_types = %{
  data: 0x00,
  headers: 0x01,
  priority: 0x02,
  rst_stream: 0x03,
  settings: 0x04,
  push_promise: 0x05,
  ping: 0x06,
  goaway: 0x07,
  window_update: 0x08,
  continuation: 0x09
}

# Flags
flags = %{
  end_stream: 0x01,
  end_headers: 0x04,
  padded: 0x08,
  priority: 0x20,
  ack: 0x01
}

# SETTINGS frame (empty, from client)
settings_frame = build_frame.(0, frame_types.settings, 0, 0)

# SETTINGS ACK frame
settings_ack_frame = build_frame.(0, frame_types.settings, flags.ack, 0)

# SETTINGS with HEADER_TABLE_SIZE = 4096
settings_with_table_size =
  build_frame.(6, frame_types.settings, 0, 0) <>
    <<0x00, 0x01, 0x00, 0x00, 0x10, 0x00>>

# Simple HEADERS frame with END_HEADERS and END_STREAM
# Header block: :method GET, :path /, :scheme http, :authority localhost
# Using HPACK static table indices (indexed header field)
simple_request_headers =
  <<0x82, 0x86, 0x84, 0x41, 0x8A, 0x08, 0x9D, 0x5C, 0x0B, 0x81, 0x70, 0xDC, 0x78, 0x0F, 0x03>>

simple_headers_frame =
  build_frame.(
    byte_size(simple_request_headers),
    frame_types.headers,
    Bitwise.bor(flags.end_headers, flags.end_stream),
    1
  ) <> simple_request_headers

# Response HEADERS frame with :status 200
# :status 200 from static table
response_header_block = <<0x88>>

response_headers_frame =
  build_frame.(
    byte_size(response_header_block),
    frame_types.headers,
    flags.end_headers,
    1
  ) <> response_header_block

# DATA frame with body
data_payload = "Hello, HTTP/2!"

data_frame =
  build_frame.(
    byte_size(data_payload),
    frame_types.data,
    flags.end_stream,
    1
  ) <> data_payload

# DATA frame with padding
padded_data_payload = "padded"
pad_length = 4

padded_data_frame =
  build_frame.(
    1 + byte_size(padded_data_payload) + pad_length,
    frame_types.data,
    Bitwise.bor(flags.end_stream, flags.padded),
    1
  ) <> <<pad_length::8>> <> padded_data_payload <> :binary.copy(<<0>>, pad_length)

# WINDOW_UPDATE frame
window_update_frame =
  build_frame.(4, frame_types.window_update, 0, 0) <>
    <<0::1, 65_535::31>>

# RST_STREAM frame with CANCEL error (0x08)
rst_stream_frame =
  build_frame.(4, frame_types.rst_stream, 0, 1) <>
    <<0, 0, 0, 8>>

# GOAWAY frame
# last_stream_id=3, error=NO_ERROR
goaway_frame =
  build_frame.(8, frame_types.goaway, 0, 0) <>
    <<0::1, 3::31, 0, 0, 0, 0>>

# PING frame
ping_frame =
  build_frame.(8, frame_types.ping, 0, 0) <>
    <<1, 2, 3, 4, 5, 6, 7, 8>>

# PING ACK frame
ping_ack_frame =
  build_frame.(8, frame_types.ping, flags.ack, 0) <>
    <<1, 2, 3, 4, 5, 6, 7, 8>>

# CONTINUATION frame (for split headers)
continuation_block = <<0x40, 0x05, "hello", 0x05, "world">>

continuation_frame =
  build_frame.(
    byte_size(continuation_block),
    frame_types.continuation,
    flags.end_headers,
    1
  ) <> continuation_block

# Headers frame without END_HEADERS (expects CONTINUATION)
headers_without_end_headers =
  build_frame.(
    byte_size(simple_request_headers),
    frame_types.headers,
    # No END_HEADERS flag
    flags.end_stream,
    3
  ) <> simple_request_headers

# Trailers (headers with no pseudo-headers)
trailers_block = <<0x40, 0x0B, "grpc-status", 0x01, "0">>

trailers_frame =
  build_frame.(
    byte_size(trailers_block),
    frame_types.headers,
    Bitwise.bor(flags.end_headers, flags.end_stream),
    1
  ) <> trailers_block

# Export all frames
%{
  connection_preface: connection_preface,
  settings_frame: settings_frame,
  settings_ack_frame: settings_ack_frame,
  settings_with_table_size: settings_with_table_size,
  simple_headers_frame: simple_headers_frame,
  response_headers_frame: response_headers_frame,
  data_frame: data_frame,
  padded_data_frame: padded_data_frame,
  window_update_frame: window_update_frame,
  rst_stream_frame: rst_stream_frame,
  goaway_frame: goaway_frame,
  ping_frame: ping_frame,
  ping_ack_frame: ping_ack_frame,
  continuation_frame: continuation_frame,
  headers_without_end_headers: headers_without_end_headers,
  trailers_frame: trailers_frame,
  frame_types: frame_types,
  flags: flags,
  build_frame: build_frame
}
