# HTTP/2 Analysis Guide

Complete guide to analyzing HTTP/2 cleartext (h2c) traffic in PcapFileEx.

## HTTP/2 Overview

PcapFileEx provides HTTP/2 stream reconstruction for cleartext (h2c) traffic:

- **Cleartext only**: No TLS-encrypted HTTP/2 (h2) support
- **Prior-knowledge h2c**: No HTTP/1.1 Upgrade flow support
- **Analysis only**: No playback server implementation

## Quick Start

```elixir
# Analyze PCAP file for HTTP/2 exchanges
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

# Print complete exchanges
Enum.each(complete, fn ex ->
  IO.puts("#{ex.request.method} #{ex.request.path} -> #{ex.response.status}")
end)

# Check incomplete exchanges
Enum.each(incomplete, fn ex ->
  IO.puts("Incomplete: #{PcapFileEx.HTTP2.IncompleteExchange.to_string(ex)}")
end)
```

## Public API

### analyze/2

Analyzes a PCAP file and returns HTTP/2 exchanges:

```elixir
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

# With port filter
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap", port: 8080)

# Disable content decoding (raw binary bodies)
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap", decode_content: false)
```

**Options:**
- `:port` - Filter to specific TCP port (default: nil, all ports)
- `:decode_content` - Auto-decode bodies based on Content-Type (default: true)

Returns:
- `complete` - List of `Exchange.t()` with full request/response pairs
- `incomplete` - List of `IncompleteExchange.t()` for partial exchanges

### analyze_segments/2

Analyzes directional TCP segments directly (skip PCAP parsing):

```elixir
segments = [
  %{flow_key: {client, server}, direction: :a_to_b, data: preface, timestamp: ts1},
  %{flow_key: {client, server}, direction: :a_to_b, data: settings, timestamp: ts2},
  ...
]

{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze_segments(segments)

# With options
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze_segments(segments, decode_content: false)
```

**Options:**
- `:decode_content` - Auto-decode bodies based on Content-Type (default: true)

### http2?/1

Check if binary starts with HTTP/2 connection preface:

```elixir
PcapFileEx.HTTP2.http2?(payload)  # => true/false
```

### connection_preface/0

Returns the HTTP/2 connection preface string (24 bytes):

```elixir
preface = PcapFileEx.HTTP2.connection_preface()
# => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
```

## Exchange Structure

### Complete Exchange

```elixir
%PcapFileEx.HTTP2.Exchange{
  stream_id: 1,
  flow_key: {client_endpoint, server_endpoint},

  request: %PcapFileEx.HTTP2.Request{
    method: "GET",
    path: "/api/users",
    scheme: "http",
    authority: "localhost:8080",
    headers: %PcapFileEx.HTTP2.Headers{
      pseudo: %{":method" => "GET", ":path" => "/api/users", ...},
      regular: %{"content-type" => "application/json", ...}
    },
    body: "",
    decoded_body: nil,  # Auto-decoded based on Content-Type
    trailers: nil
  },

  response: %PcapFileEx.HTTP2.Response{
    status: 200,
    headers: %PcapFileEx.HTTP2.Headers{
      pseudo: %{":status" => "200"},
      regular: %{"content-type" => "application/json", ...}
    },
    body: "{\"users\": [...]}",
    decoded_body: {:json, %{"users" => [...]}},  # Auto-decoded JSON
    trailers: nil
  },

  request_timestamp: ~U[2024-01-01 12:00:00Z],
  response_timestamp: ~U[2024-01-01 12:00:01Z]
}
```

### Incomplete Exchange

```elixir
%PcapFileEx.HTTP2.IncompleteExchange{
  stream_id: 3,
  flow_key: {client_endpoint, server_endpoint},
  request: %PcapFileEx.HTTP2.Request{...},  # May be nil
  response: %PcapFileEx.HTTP2.Response{...},  # May be nil
  reason: :rst_stream | {:rst_stream, error_code} | {:goaway, last_stream_id} | :truncated_no_response
}
```

## Understanding Incomplete Exchanges

Exchanges may be incomplete for several reasons:

### RST_STREAM

Stream was reset by client or server:

```elixir
case ex.reason do
  {:rst_stream, 0x08} -> IO.puts("Stream cancelled (CANCEL)")
  {:rst_stream, 0x07} -> IO.puts("Stream refused (REFUSED_STREAM)")
  {:rst_stream, code} -> IO.puts("RST_STREAM error: #{code}")
end
```

### GOAWAY

Connection was terminated:

```elixir
case ex.reason do
  {:goaway, last_stream_id} ->
    IO.puts("GOAWAY: streams > #{last_stream_id} were terminated")
end
```

### Truncated

Capture ended before exchange completed:

```elixir
case ex.reason do
  :truncated_no_response -> IO.puts("Request sent, no response captured")
  :truncated -> IO.puts("Exchange incomplete (capture ended)")
end
```

## Content Decoding

HTTP/2 exchanges automatically decode request and response bodies based on Content-Type headers.

### Decoded Content Types

| Content-Type | Decoded As | Elixir Type |
|--------------|------------|-------------|
| `application/json` | Parsed JSON | `{:json, map() \| list()}` |
| `application/problem+json` | Parsed JSON | `{:json, map()}` |
| `text/*` | UTF-8 string | `{:text, String.t()}` |
| `multipart/*` | Parsed parts | `{:multipart, [part()]}` |
| (unknown) | Raw binary | `{:binary, binary()}` |

### Accessing Decoded Bodies

```elixir
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap")

Enum.each(complete, fn ex ->
  case ex.response.decoded_body do
    {:json, data} ->
      IO.inspect(data, label: "JSON response")

    {:text, text} ->
      IO.puts("Text response: #{text}")

    {:multipart, parts} ->
      Enum.each(parts, fn part ->
        IO.puts("Part: #{part.content_type}")
        IO.inspect(part.body)
      end)

    {:binary, bin} ->
      IO.puts("Binary response: #{byte_size(bin)} bytes")

    nil ->
      IO.puts("No body")
  end
end)
```

### Multipart Response Handling

Multipart bodies are recursively decoded. Each part has:
- `content_type` - Part's Content-Type header
- `content_id` - Part's Content-Id header (or nil)
- `headers` - All part headers (lowercase keys)
- `body` - Recursively decoded body (tagged tuple)

```elixir
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap")

Enum.each(complete, fn ex ->
  case ex.response.decoded_body do
    {:multipart, parts} ->
      Enum.each(parts, fn part ->
        IO.puts("Part #{part.content_id}: #{part.content_type}")
        case part.body do
          {:json, json} -> IO.inspect(json)
          {:text, text} -> IO.puts(text)
          {:binary, bin} -> IO.puts("Binary: #{byte_size(bin)} bytes")
        end
      end)
    _ -> :skip
  end
end)
```

### Disabling Content Decoding

For raw binary access without decoding overhead:

```elixir
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap", decode_content: false)

ex = hd(complete)
ex.response.body          # Raw binary
ex.response.decoded_body  # nil (not decoded)
```

## Common Patterns

### Pattern 1: Extract All API Calls

```elixir
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap")

api_calls = complete
|> Enum.filter(fn ex ->
  String.starts_with?(ex.request.path, "/api/")
end)
|> Enum.map(fn ex ->
  %{
    method: ex.request.method,
    path: ex.request.path,
    status: ex.response.status,
    request_time: ex.request_timestamp,
    response_time: ex.response_timestamp
  }
end)
```

### Pattern 2: Find Error Responses

```elixir
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap")

errors = Enum.filter(complete, fn ex ->
  ex.response.status >= 400
end)

Enum.each(errors, fn ex ->
  IO.puts("#{ex.request.method} #{ex.request.path} -> #{ex.response.status}")
  IO.puts("Response: #{ex.response.body}")
end)
```

### Pattern 3: Calculate Response Times

```elixir
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap")

response_times = Enum.map(complete, fn ex ->
  duration_ms = DateTime.diff(ex.response_timestamp, ex.request_timestamp, :millisecond)

  %{
    path: ex.request.path,
    method: ex.request.method,
    duration_ms: duration_ms
  }
end)

# Find slow requests
slow = Enum.filter(response_times, & &1.duration_ms > 1000)
```

### Pattern 4: Analyze gRPC Traffic

HTTP/2 is the transport for gRPC. Use trailers to get gRPC status:

```elixir
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap", port: 50051)

grpc_calls = Enum.map(complete, fn ex ->
  grpc_status = ex.response.trailers && ex.response.trailers.regular["grpc-status"]
  grpc_message = ex.response.trailers && ex.response.trailers.regular["grpc-message"]

  %{
    service_method: ex.request.path,  # e.g., "/myservice.MyService/MyMethod"
    grpc_status: grpc_status,
    grpc_message: grpc_message,
    content_type: ex.request.headers.regular["content-type"]
  }
end)
```

### Pattern 5: Group by Stream

```elixir
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

all_exchanges = complete ++ Enum.map(incomplete, & &1)

by_stream = Enum.group_by(all_exchanges, & &1.stream_id)

Enum.each(by_stream, fn {stream_id, exchanges} ->
  IO.puts("Stream #{stream_id}: #{length(exchanges)} exchange(s)")
end)
```

## Mid-Connection Capture

When capture starts after the HTTP/2 connection is established:

### Limitations

1. **Client identification**: Falls back to stream ID semantics (odd = client-initiated)
2. **HPACK dynamic table**: May have missing entries (static table always works)
3. **SETTINGS frames**: Deferred until client is identified

### Best Practices

```elixir
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("mid_connection.pcap")

# Expect more incomplete exchanges in mid-connection captures
IO.puts("Complete: #{length(complete)}, Incomplete: #{length(incomplete)}")

# Some headers may be missing due to HPACK state
Enum.each(complete, fn ex ->
  # Check for missing headers
  if is_nil(ex.request.method) do
    IO.puts("Warning: Stream #{ex.stream_id} missing method (HPACK state issue)")
  end
end)
```

## Filtering by Port

Filter to specific HTTP/2 ports:

```elixir
# Standard h2c port
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap", port: 80)

# Custom port
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap", port: 8080)

# gRPC port
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("capture.pcap", port: 50051)
```

## Testing HTTP/2 Code

### Generating Test Fixtures

Use the provided capture script:

```bash
cd test/fixtures
./capture_http2_traffic.sh
# Generates: http2_sample.pcap, http2_sample.pcapng
```

Requirements:
- Python 3 with `h2` library (`pip install h2`)
- Wireshark's `dumpcap`

### Synthetic Segments for Unit Tests

For unit tests, create synthetic segments instead of using real PCAPs:

```elixir
# Connection preface
@preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Build a frame
defp frame(type, flags, stream_id, payload) do
  type_byte = case type do
    :data -> 0x00
    :headers -> 0x01
    :settings -> 0x04
    # ...
  end

  length = byte_size(payload)
  <<length::24, type_byte::8, flags::8, 0::1, stream_id::31, payload::binary>>
end

# Create segment
defp segment(flow_key, direction, data, timestamp \\ DateTime.utc_now()) do
  %{
    flow_key: flow_key,
    direction: direction,
    data: data,
    timestamp: timestamp
  }
end

# Example test
test "simple GET request" do
  flow_key = {{{127, 0, 0, 1}, 50000}, {{127, 0, 0, 1}, 8080}}

  # Use HPACK indexed representations for headers
  # Index 2 = :method GET, Index 4 = :path /, Index 6 = :scheme http
  request_headers = <<0x82, 0x84, 0x86>>
  response_headers = <<0x88>>  # Index 8 = :status 200

  segments = [
    segment(flow_key, :a_to_b, @preface),
    segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
    segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
    segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
    segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
    segment(flow_key, :b_to_a, frame(:data, 0x01, 1, "Hello"))
  ]

  {:ok, complete, _} = PcapFileEx.HTTP2.analyze_segments(segments)

  assert length(complete) == 1
  [ex] = complete
  assert ex.request.method == "GET"
  assert ex.response.status == 200
end
```

### HPACK Static Table Indices

Common HPACK static table indices for testing:

| Index | Header |
|-------|--------|
| 2 | `:method` GET |
| 3 | `:method` POST |
| 4 | `:path` / |
| 5 | `:path` /index.html |
| 6 | `:scheme` http |
| 7 | `:scheme` https |
| 8 | `:status` 200 |
| 9 | `:status` 204 |
| 10 | `:status` 206 |
| 11 | `:status` 304 |
| 12 | `:status` 400 |
| 13 | `:status` 404 |
| 14 | `:status` 500 |

Use indexed representation: `<<0x80 | index>>` (e.g., `<<0x82>>` for GET)

## Performance Considerations

### Large Captures

For large PCAP files, HTTP/2 analysis processes all TCP flows:

```elixir
# Filter by port to reduce processing
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("huge.pcap", port: 8080)
```

### Memory Usage

Exchanges are accumulated in memory. For very large captures with many exchanges, consider processing incrementally or filtering.

## Common Mistakes

### Mistake 1: Expecting TLS HTTP/2

```elixir
# DON'T: Expect h2 (TLS) to work
{:ok, _, _} = PcapFileEx.HTTP2.analyze("https_traffic.pcap")
# Returns empty - can't decrypt TLS!

# DO: Use cleartext h2c captures
{:ok, complete, _} = PcapFileEx.HTTP2.analyze("h2c_traffic.pcap")
```

### Mistake 2: Ignoring Incomplete Exchanges

```elixir
# DON'T: Only check complete exchanges
{:ok, complete, _incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

# DO: Check both for full picture
{:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")
IO.puts("Complete: #{length(complete)}, Incomplete: #{length(incomplete)}")
```

### Mistake 3: Assuming Headers Exist

```elixir
# DON'T: Assume all headers present (may fail for mid-connection)
ex.request.headers.regular["content-type"]

# DO: Guard against nil
content_type = ex.request.headers && ex.request.headers.regular["content-type"]
```

### Mistake 4: Wrong Frame Flags in Tests

```elixir
# DON'T: Forget END_HEADERS flag (headers incomplete!)
frame(:headers, 0x01, 1, headers)  # Only END_STREAM

# DO: Include END_HEADERS (0x04)
frame(:headers, 0x05, 1, headers)  # END_STREAM (0x01) + END_HEADERS (0x04)
```

## HTTP/2 Error Codes

Reference for RST_STREAM and GOAWAY error codes:

| Code | Name | Description |
|------|------|-------------|
| 0x00 | NO_ERROR | Graceful shutdown |
| 0x01 | PROTOCOL_ERROR | Protocol error detected |
| 0x02 | INTERNAL_ERROR | Implementation error |
| 0x03 | FLOW_CONTROL_ERROR | Flow control limits exceeded |
| 0x04 | SETTINGS_TIMEOUT | Settings not acknowledged |
| 0x05 | STREAM_CLOSED | Frame on closed stream |
| 0x06 | FRAME_SIZE_ERROR | Invalid frame size |
| 0x07 | REFUSED_STREAM | Stream refused before processing |
| 0x08 | CANCEL | Stream cancelled |
| 0x09 | COMPRESSION_ERROR | HPACK compression error |
| 0x0A | CONNECT_ERROR | TCP connection error |
| 0x0B | ENHANCE_YOUR_CALM | Excessive load |
| 0x0C | INADEQUATE_SECURITY | Insufficient security |
| 0x0D | HTTP_1_1_REQUIRED | Use HTTP/1.1 instead |

## Summary: HTTP/2 Best Practices

1. **Use `analyze/2`** for PCAP files, `analyze_segments/2` for pre-parsed segments
2. **Check both complete and incomplete** exchanges for full picture
3. **Filter by port** for large captures with mixed traffic
4. **Use `decoded_body`** for auto-decoded JSON/text/multipart content
5. **Set `decode_content: false`** when you need raw binary bodies
6. **Handle mid-connection captures** gracefully (expect HPACK issues)
7. **Use HPACK static table** indices for test fixtures
8. **Include END_HEADERS flag** (0x04) in test HEADERS frames
9. **Check for nil headers** when processing exchanges
10. **Use trailers** for gRPC status codes
