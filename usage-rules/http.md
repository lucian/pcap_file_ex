# HTTP Decoding Guide

Complete guide to working with HTTP traffic in PcapFileEx.

## HTTP Decoding Overview

PcapFileEx provides two ways to extract HTTP messages:

1. **Single-packet HTTP** - HTTP message in one packet
2. **Reassembled HTTP** - HTTP message fragmented across multiple TCP packets

## Single-Packet HTTP Decoding

### Automatic Decoding

HTTP is automatically decoded when `decode: true` (default):

```elixir
{:ok, packets} = PcapFileEx.read_all("capture.pcap")

# Packets are already decoded
packet = hd(packets)
packet.protocols  # [:ether, :ipv4, :tcp, :http]
packet.decoded    # %{http: %PcapFileEx.HTTP{...}}
```

### Accessing HTTP Data

```elixir
# Method 1: Check decoded map
if :http in packet.protocols do
  http = packet.decoded[:http]
  IO.inspect(http.method)
  IO.inspect(http.path)
  IO.inspect(http.decoded_body)
end

# Method 2: Use helper function
http = PcapFileEx.Packet.decode_http!(packet)
# Raises if packet doesn't contain HTTP
```

### HTTP Structure

```elixir
%PcapFileEx.HTTP{
  # Common fields
  version: "HTTP/1.1",
  headers: %{"Content-Type" => "application/json", ...},
  body: "raw body bytes",
  decoded_body: %{...},  # Auto-decoded (JSON/ETF/form)

  # Request-specific fields
  method: "GET",
  path: "/api/users",
  host: "example.com",

  # Response-specific fields
  status_code: 200,
  status_text: "OK"
}
```

## Automatic Body Decoding

**IMPORTANT**: HTTP bodies are automatically decoded based on Content-Type!

### JSON Decoding

```elixir
# If Content-Type is application/json and Jason is available:
http = PcapFileEx.Packet.decode_http!(packet)

# DON'T: Double-decode
data = Jason.decode!(http.body)  # Already in http.decoded_body!

# DO: Use automatic decoding
IO.inspect(http.decoded_body)  # Already a map! %{"user" => "alice", ...}
```

### Form Data Decoding

```elixir
# Content-Type: application/x-www-form-urlencoded
http = PcapFileEx.Packet.decode_http!(packet)
http.decoded_body  # %{"username" => "alice", "password" => "..."}
```

### ETF Decoding

```elixir
# Content-Type: application/x-erlang-binary
# Decoded with :safe flag (prevents code execution)
http = PcapFileEx.Packet.decode_http!(packet)
http.decoded_body  # Safe ETF decode or nil if invalid
```

### Plain Text

```elixir
# Content-Type: text/plain or text/html
http = PcapFileEx.Packet.decode_http!(packet)
http.decoded_body  # Same as http.body (raw string)
```

### Unknown Content Types

```elixir
# Content-Type: application/octet-stream or unknown
http = PcapFileEx.Packet.decode_http!(packet)
http.decoded_body  # nil
http.body          # Raw bytes
```

## HTTP Filtering

### Finding HTTP Packets

```elixir
# Method 1: Filter module
http_packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_protocol(:http)
|> Enum.to_list()

# Method 2: DisplayFilter
http_packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("http")
|> Enum.to_list()

# Method 3: Manual filtering
http_packets = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p -> :http in p.protocols end)
|> Enum.to_list()
```

### Filtering by HTTP Method

```elixir
# GET requests
get_requests = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].method == "GET"
end)
|> Enum.to_list()

# POST/PUT/DELETE (modifying requests)
modifying_requests = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].method in ["POST", "PUT", "DELETE"]
end)
|> Enum.to_list()

# DisplayFilter syntax
post_requests = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("http.request.method == \"POST\"")
|> Enum.to_list()
```

### Filtering by Path

```elixir
# API endpoints
api_requests = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  String.starts_with?(p.decoded[:http].path || "", "/api/")
end)
|> Enum.to_list()

# Specific path
users_requests = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].path == "/api/users"
end)
|> Enum.to_list()
```

### Filtering by Status Code

```elixir
# Error responses (4xx, 5xx)
errors = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].status_code >= 400
end)
|> Enum.to_list()

# Specific status
not_found = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].status_code == 404
end)
|> Enum.to_list()

# DisplayFilter syntax
server_errors = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("http.response.code >= 500")
|> Enum.to_list()
```

### Filtering by Headers

```elixir
# Requests with specific header
json_requests = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  get_in(p.decoded[:http].headers, ["Content-Type"]) =~ "application/json"
end)
|> Enum.to_list()

# Requests to specific host
host_requests = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].host == "api.example.com"
end)
|> Enum.to_list()
```

## TCP Reassembly for Fragmented HTTP

### When to Use Reassembly

Use `PcapFileEx.TCP.stream_http_messages/2` when:
- HTTP messages span multiple TCP packets
- Large request/response bodies
- Dealing with real-world network traffic

```elixir
# Single-packet HTTP (works for small messages)
http_packets = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p -> :http in p.protocols end)
|> Enum.to_list()

# TCP reassembly (works for all HTTP, including fragmented)
http_messages = PcapFileEx.TCP.stream_http_messages("capture.pcap")
|> Enum.to_list()
```

### Streaming HTTP Messages

```elixir
# All HTTP messages (requests and responses)
PcapFileEx.TCP.stream_http_messages("capture.pcap")
|> Enum.each(fn msg ->
  IO.puts("Direction: #{msg.direction}")  # :request or :response
  IO.inspect(msg.http)
end)

# Only requests
PcapFileEx.TCP.stream_http_messages("capture.pcap", types: [:request])
|> Enum.each(fn msg ->
  IO.puts("#{msg.http.method} #{msg.http.path}")
end)

# Only responses
PcapFileEx.TCP.stream_http_messages("capture.pcap", types: [:response])
|> Enum.each(fn msg ->
  IO.puts("Status: #{msg.http.status_code}")
end)
```

### HTTP Message Structure

```elixir
%{
  direction: :request,  # or :response
  http: %PcapFileEx.HTTP{...},
  packets: [...]  # List of TCP packets that make up this message
}
```

### Filtering Reassembled Messages

```elixir
# POST requests with JSON body
PcapFileEx.TCP.stream_http_messages("capture.pcap", types: [:request])
|> Stream.filter(fn msg ->
  msg.http.method == "POST" and
  is_map(msg.http.decoded_body)
end)
|> Enum.each(fn msg ->
  IO.inspect(msg.http.decoded_body)
end)

# Large responses
PcapFileEx.TCP.stream_http_messages("capture.pcap", types: [:response])
|> Stream.filter(fn msg ->
  byte_size(msg.http.body) > 1_000_000
end)
|> Enum.to_list()
```

## Common HTTP Patterns

### Pattern 1: Extract All API Calls

```elixir
api_calls = PcapFileEx.TCP.stream_http_messages("capture.pcap", types: [:request])
|> Stream.filter(fn msg ->
  String.starts_with?(msg.http.path || "", "/api/")
end)
|> Enum.map(fn msg ->
  %{
    method: msg.http.method,
    path: msg.http.path,
    body: msg.http.decoded_body,
    timestamp: hd(msg.packets).timestamp
  }
end)
```

### Pattern 2: Match Requests with Responses

```elixir
# Group by TCP connection
messages = PcapFileEx.TCP.stream_http_messages("capture.pcap")
|> Enum.group_by(fn msg ->
  packet = hd(msg.packets)
  {packet.src, packet.dst}
end)

# Match pairs (simplified)
Enum.each(messages, fn {_conn, msgs} ->
  requests = Enum.filter(msgs, & &1.direction == :request)
  responses = Enum.filter(msgs, & &1.direction == :response)

  Enum.zip(requests, responses)
  |> Enum.each(fn {req, resp} ->
    IO.puts("#{req.http.method} #{req.http.path} -> #{resp.http.status_code}")
  end)
end)
```

### Pattern 3: Extract JSON API Data

```elixir
PcapFileEx.TCP.stream_http_messages("capture.pcap", types: [:request])
|> Stream.filter(fn msg ->
  msg.http.method == "POST" and
  String.starts_with?(msg.http.path || "", "/api/users") and
  is_map(msg.http.decoded_body)
end)
|> Enum.each(fn msg ->
  user_data = msg.http.decoded_body
  IO.puts("Creating user: #{user_data["username"]}")
end)
```

### Pattern 4: Analyze Response Times

```elixir
# Collect request/response pairs with timestamps
pairs = PcapFileEx.TCP.stream_http_messages("capture.pcap")
|> Enum.chunk_every(2)
|> Enum.filter(fn
  [%{direction: :request}, %{direction: :response}] -> true
  _ -> false
end)
|> Enum.map(fn [req, resp] ->
  req_time = hd(req.packets).timestamp
  resp_time = hd(resp.packets).timestamp
  duration = DateTime.diff(resp_time, req_time, :millisecond)

  %{
    path: req.http.path,
    method: req.http.method,
    status: resp.http.status_code,
    duration_ms: duration
  }
end)

# Find slow requests
slow_requests = Enum.filter(pairs, & &1.duration_ms > 1000)
```

### Pattern 5: Security Analysis

```elixir
# Find authentication attempts
auth_attempts = PcapFileEx.TCP.stream_http_messages("capture.pcap", types: [:request])
|> Stream.filter(fn msg ->
  msg.http.method == "POST" and
  msg.http.path in ["/login", "/api/auth", "/authenticate"]
end)
|> Enum.map(fn msg ->
  %{
    timestamp: hd(msg.packets).timestamp,
    source_ip: hd(msg.packets).src.ip,
    body: msg.http.decoded_body
  }
end)

# Find SQL injection attempts
sqli_attempts = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  String.contains?(p.decoded[:http].path || "", "' OR '1'='1")
end)
|> Enum.to_list()
```

## Security Considerations

### ETF Decoding Safety

```elixir
# ✅ SAFE: Automatic decoding uses :safe flag
http = PcapFileEx.Packet.decode_http!(packet)
http.decoded_body  # Safe ETF decode - no code execution

# ❌ NEVER DO THIS with untrusted data:
:erlang.binary_to_term(http.body)  # Can execute arbitrary code!

# ✅ IF you must manually decode ETF:
:erlang.binary_to_term(http.body, [:safe])
```

### Input Validation

```elixir
# Always validate decoded data from untrusted sources
case http.decoded_body do
  %{"username" => username, "password" => password}
      when is_binary(username) and is_binary(password) ->
    # Valid structure
    :ok

  _ ->
    # Invalid or malicious data
    {:error, :invalid_body}
end
```

### Path Traversal Detection

```elixir
# Detect path traversal attempts
traversal_attempts = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  String.contains?(p.decoded[:http].path || "", "..")
end)
|> Enum.to_list()
```

## Performance Tips for HTTP

### Tip 1: Use PreFilter for HTTP Traffic

```elixir
# ✅ FAST: PreFilter for HTTP ports
{:ok, reader} = PcapFileEx.open("huge.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.any([
    PreFilter.port_dest(80),
    PreFilter.port_dest(443),
    PreFilter.port_dest(8080)
  ])
])
http_packets = PcapFileEx.Stream.from_reader!(reader)
|> Stream.filter(fn p -> :http in p.protocols end)
|> Enum.to_list()
PcapFileEx.Pcap.close(reader)
```

### Tip 2: Disable Decode for Metadata Only

```elixir
# If you only need HTTP metadata (not body decoding)
http_metadata = PcapFileEx.stream!("capture.pcap", decode: false)
|> Stream.filter(fn p ->
  # Manual protocol detection
  byte_size(p.data) > 4 and
  :binary.part(p.data, 0, 4) in ["GET ", "POST", "HTTP"]
end)
|> Enum.map(fn p ->
  %{
    timestamp: p.timestamp,
    size: byte_size(p.data)
  }
end)
```

### Tip 3: Early Termination

```elixir
# Find first HTTP request
first_request = PcapFileEx.TCP.stream_http_messages("huge.pcap", types: [:request])
|> Enum.take(1)
|> hd()

# Find first error response
first_error = PcapFileEx.TCP.stream_http_messages("huge.pcap", types: [:response])
|> Enum.find(fn msg -> msg.http.status_code >= 400 end)
```

## Common Mistakes

### ❌ Mistake 1: Double-Decoding Bodies

```elixir
# DON'T: Manually decode already-decoded body
http = PcapFileEx.Packet.decode_http!(packet)
data = Jason.decode!(http.body)  # Already in http.decoded_body!

# DO: Use automatic decoding
http = PcapFileEx.Packet.decode_http!(packet)
data = http.decoded_body  # Already a map!
```

### ❌ Mistake 2: Assuming Single-Packet HTTP

```elixir
# DON'T: Only check single packets (misses fragmented HTTP)
http_count = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn p -> :http in p.protocols end)
|> Enum.count()  # Undercounts!

# DO: Use TCP reassembly
http_count = PcapFileEx.TCP.stream_http_messages("capture.pcap")
|> Enum.count()  # Accurate count
```

### ❌ Mistake 3: Ignoring nil Values

```elixir
# DON'T: Assume fields exist
path = p.decoded[:http].path
String.starts_with?(path, "/api/")  # Crashes if path is nil!

# DO: Guard against nil
path = p.decoded[:http].path || ""
String.starts_with?(path, "/api/")
```

### ❌ Mistake 4: Missing Content-Type

```elixir
# DON'T: Assume decoded_body exists
data = http.decoded_body["user"]  # Crashes if decoded_body is nil!

# DO: Check first
if is_map(http.decoded_body) do
  data = http.decoded_body["user"]
end
```

## Summary: HTTP Best Practices

1. ✅ Use automatic HTTP decoding (enabled by default)
2. ✅ Check `http.decoded_body` first (auto-decoded JSON/ETF/form)
3. ✅ Use TCP reassembly for fragmented HTTP
4. ✅ Guard against nil values (path, decoded_body)
5. ✅ Use PreFilter for HTTP ports (80, 443, 8080)
6. ✅ Use `:safe` flag for ETF (automatic)
7. ❌ Don't manually decode already-decoded bodies
8. ❌ Don't assume single-packet HTTP
9. ❌ Don't ignore nil values
10. ❌ Don't use unsafe ETF decoding
