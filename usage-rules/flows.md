# Traffic Flows Analysis Guide

## Overview

The `PcapFileEx.Flows` module provides a unified API to analyze PCAP files and identify traffic flows by protocol (HTTP/1, HTTP/2, UDP).

## Quick Start

```elixir
# Analyze a PCAP file
{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng")

# Access flows by protocol
IO.puts("HTTP/1 flows: #{length(result.http1)}")
IO.puts("HTTP/2 flows: #{length(result.http2)}")
IO.puts("UDP flows: #{length(result.udp)}")
```

## Key Concepts

### AnalysisResult

The main result structure containing all flows:

```elixir
%PcapFileEx.Flows.AnalysisResult{
  flows: %{FlowKey.t() => flow_ref()},   # O(1) lookup map
  http1: [HTTP1.Flow.t()],               # Sorted by first exchange timestamp
  http2: [HTTP2.Flow.t()],               # Sorted by first stream timestamp
  udp: [UDP.Flow.t()],                   # Sorted by first datagram timestamp
  timeline: [TimelineEvent.t()],         # Unified timeline
  stats: Stats.t(),                      # Aggregate statistics
  summary: Summary.t()                   # Pre-aggregated traffic for topology
}
```

### FlowKey

Stable identity for O(1) flow lookups:

```elixir
key = PcapFileEx.FlowKey.new(:http2, client_endpoint, server_endpoint)
flow = PcapFileEx.Flows.AnalysisResult.get_flow(result, key)
```

### Flow

Base flow identity with display and authoritative fields:

```elixir
%PcapFileEx.Flow{
  protocol: :http2,
  from: "web-client",           # Display: hostname (no port)
  server: "api-gateway:8080",   # Display: host:port
  client: "web-client:54321",   # Display: host:port
  server_endpoint: %Endpoint{}, # Authoritative
  client_endpoint: %Endpoint{}  # Authoritative
}
```

### TimelineEvent

For unified playback across protocols:

```elixir
Enum.each(result.timeline, fn event ->
  data = PcapFileEx.Flows.AnalysisResult.get_event(result, event)

  case data do
    %HTTP1.Exchange{} -> handle_http1(data)
    %HTTP2.Stream{} -> handle_http2(data)
    %UDP.Datagram{} -> handle_udp(data)
  end
end)
```

## Protocol-Specific Flows

### HTTP/1 Flows

```elixir
Enum.each(result.http1, fn flow ->
  IO.puts("Flow from #{flow.flow.from} to #{flow.flow.server}")

  Enum.each(flow.exchanges, fn exchange ->
    IO.puts("  #{exchange.request.method} #{exchange.request.path}")

    if exchange.complete do
      IO.puts("    -> #{exchange.response.status} (#{exchange.response_delay_ms}ms)")
    end
  end)
end)
```

### HTTP/2 Flows

HTTP/2 uses "streams" to match HTTP/2 spec terminology:

```elixir
Enum.each(result.http2, fn flow ->
  IO.puts("Flow from #{flow.flow.from} to #{flow.flow.server}")

  # Complete streams
  Enum.each(flow.streams, fn stream ->
    ex = stream.exchange
    IO.puts("  #{ex.request.method} #{ex.request.path} -> #{ex.response.status}")
    IO.puts("    Response delay: #{stream.response_delay_ms}ms")
  end)

  # Incomplete streams (RST_STREAM, GOAWAY, truncated)
  Enum.each(flow.incomplete, fn inc ->
    IO.puts("  Incomplete stream #{inc.stream_id}: #{inc.reason}")
  end)
end)
```

### UDP Flows

UDP flows are grouped by server (destination) only:

```elixir
Enum.each(result.udp, fn flow ->
  # UDP flows have from: :any since sources can vary
  IO.puts("UDP to #{flow.flow.server}: #{length(flow.datagrams)} datagrams")

  Enum.each(flow.datagrams, fn dg ->
    IO.puts("  #{dg.from} -> #{dg.to}: #{dg.size} bytes @ +#{dg.relative_offset_ms}ms")
  end)
end)
```

## Playback Timing

### HTTP Response Delay

```elixir
# HTTP/1
exchange.response_delay_ms  # Time from request to response

# HTTP/2
stream.response_delay_ms    # Time from request start to response completion

# Example playback
def playback_http1(exchange) do
  send_request(exchange.request)
  Process.sleep(exchange.response_delay_ms)
  send_response(exchange.response)
end
```

### UDP Relative Offset

```elixir
# First datagram in flow has relative_offset_ms = 0
datagram.relative_offset_ms  # Offset from flow start

# Example playback
def playback_udp(flow) do
  start_time = System.monotonic_time(:millisecond)

  Enum.each(flow.datagrams, fn dg ->
    elapsed = System.monotonic_time(:millisecond) - start_time
    remaining = dg.relative_offset_ms - elapsed
    if remaining > 0, do: Process.sleep(remaining)

    send_udp(dg.to, dg.payload)
  end)
end
```

## Hosts Mapping

Resolve IP addresses to human-readable hostnames:

```elixir
hosts = %{
  "192.168.1.10" => "api-gateway",
  "192.168.1.20" => "metrics-collector",
  "192.168.1.30" => "web-client"
}

{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", hosts_map: hosts)

# Now flows show friendly names
result.http2
|> Enum.map(fn f -> {f.flow.from, f.flow.server} end)
# => [{"web-client", "api-gateway:8080"}, ...]
```

## Traffic Summary

The `summary` field provides pre-aggregated traffic data for network topology visualization:

```elixir
%Summary{
  udp: [%UDPService{}, ...],    # UDP destinations with per-client stats
  http1: [%HTTPService{}, ...], # HTTP/1 servers with per-client stats
  http2: [%HTTPService{}, ...]  # HTTP/2 servers with per-client stats
}
```

### Use Cases

- **Network diagrams** - Show services and connected clients
- **Traffic aggregation** - Total bytes/requests per service
- **Client analysis** - Which clients connect to which services

### Accessing Summary

```elixir
{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", hosts_map: hosts)

# Services sorted by traffic volume (bytes desc)
result.summary.http2
|> Enum.each(fn service ->
  IO.puts("#{service.server_host || service.server}")
  IO.puts("  Total: #{service.total_requests} requests, #{service.total_response_bytes} bytes")
  IO.puts("  Methods: #{inspect(service.methods)}")
  IO.puts("  Status codes: #{inspect(service.status_codes)}")

  Enum.each(service.clients, fn client ->
    IO.puts("  - #{client.client_host || client.client}: #{client.request_count} requests")
  end)
end)

# UDP summary
result.summary.udp
|> Enum.each(fn service ->
  IO.puts("UDP #{service.server_host || service.server}:")
  IO.puts("  Total: #{service.total_packets} packets, #{service.total_bytes} bytes")

  Enum.each(service.clients, fn client ->
    IO.puts("  - #{client.client_host || client.client}: #{client.packet_count} packets")
  end)
end)
```

### Summary Data Structures

#### HTTPService

```elixir
%Summary.HTTPService{
  protocol: :http1 | :http2,
  server: "192.168.1.10:8080",       # IP:port string
  server_host: "api-gateway",        # Hostname (from hosts_map)
  clients: [%HTTPClientStats{}, ...],
  total_requests: 150,
  total_responses: 148,
  total_request_bytes: 45000,
  total_response_bytes: 1200000,
  methods: %{"GET" => 100, "POST" => 50},
  status_codes: %{200 => 140, 404 => 5, 500 => 3},
  first_timestamp: %Timestamp{},
  last_timestamp: %Timestamp{}
}
```

#### HTTPClientStats

```elixir
%Summary.HTTPClientStats{
  client: "10.0.0.5",               # Client IP (no port - ephemeral)
  client_host: "web-client",        # Hostname (from hosts_map)
  connection_count: 3,              # TCP connections
  stream_count: 45,                 # HTTP/2 streams (nil for HTTP/1)
  request_count: 45,
  response_count: 44,
  request_bytes: 12000,
  response_bytes: 350000,
  methods: %{"GET" => 40, "POST" => 5},
  status_codes: %{200 => 42, 404 => 2},
  avg_response_time_ms: 75,
  min_response_time_ms: 12,
  max_response_time_ms: 450,
  first_timestamp: %Timestamp{},
  last_timestamp: %Timestamp{}
}
```

#### UDPService

```elixir
%Summary.UDPService{
  server: "192.168.1.20:5005",      # IP:port string
  server_host: "metrics-collector", # Hostname (from hosts_map)
  clients: [%UDPClientStats{}, ...],
  total_packets: 5000,
  total_bytes: 2500000,
  first_timestamp: %Timestamp{},
  last_timestamp: %Timestamp{}
}
```

#### UDPClientStats

```elixir
%Summary.UDPClientStats{
  client: "10.0.0.5",               # Client IP (no port)
  client_host: "sensor-node",       # Hostname (from hosts_map)
  packet_count: 1200,
  total_bytes: 600000,
  avg_size: 500,
  min_size: 64,
  max_size: 1400,
  first_timestamp: %Timestamp{},
  last_timestamp: %Timestamp{}
}
```

## Protocol Detection

TCP flows are classified by content inspection:

- **HTTP/2**: Connection preface `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`
- **HTTP/1**: Request methods (`GET `, `POST `, etc.) or `HTTP/` response

```elixir
alias PcapFileEx.Flows.ProtocolDetector

ProtocolDetector.detect("GET / HTTP/1.1\r\n")  # => :http1
ProtocolDetector.detect("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")  # => :http2
ProtocolDetector.detect(<<0, 1, 2, 3>>)  # => :unknown
```

## Options

```elixir
PcapFileEx.Flows.analyze("capture.pcapng",
  hosts_map: %{...},      # IP to hostname mapping
  decode_content: true,   # Decode HTTP bodies (default: true)
  tcp_port: 8080,         # Filter TCP to specific port
  udp_port: 5005          # Filter UDP to specific port
)
```

## Common Patterns

### Filter by Client

```elixir
result.http2
|> Enum.filter(fn f -> f.flow.from == "web-client" end)
|> Enum.flat_map(& &1.streams)
```

### Get All Requests

```elixir
all_requests =
  result.http1
  |> Enum.flat_map(& &1.exchanges)
  |> Enum.map(& &1.request)

http2_requests =
  result.http2
  |> Enum.flat_map(& &1.streams)
  |> Enum.map(& &1.exchange.request)
```

### Find Errors

```elixir
# HTTP errors
errors =
  result.http1
  |> Enum.flat_map(& &1.exchanges)
  |> Enum.filter(fn ex -> ex.complete and ex.response.status >= 400 end)

# Incomplete HTTP/2 streams
incomplete =
  result.http2
  |> Enum.flat_map(& &1.incomplete)
```

### Calculate Statistics

```elixir
# Total bytes across all flows
total_bytes =
  result.http1
  |> Enum.map(& &1.stats.byte_count)
  |> Enum.sum()

# Duration of a flow
flow = hd(result.http2)
IO.puts("Duration: #{flow.stats.duration_ms}ms")
```

## Data Structures

### HTTP1.Exchange

```elixir
%HTTP1.Exchange{
  flow_seq: 0,                   # Index within flow's exchange list
  request: %{
    method: "GET",
    path: "/api/users",
    version: "1.1",
    headers: %{"host" => "api.example.com"},
    body: "",
    decoded_body: nil,
    timestamp: %Timestamp{}
  },
  response: %{
    status: 200,
    reason: "OK",
    version: "1.1",
    headers: %{"content-type" => "application/json"},
    body: "{...}",
    decoded_body: {:json, %{...}},
    timestamp: %Timestamp{}
  },
  start_timestamp: %Timestamp{},
  end_timestamp: %Timestamp{},
  response_delay_ms: 150,
  complete: true
}
```

### HTTP2.Stream

```elixir
%HTTP2.Stream{
  flow_seq: 0,                   # Index within flow's stream list
  exchange: %HTTP2.Exchange{},   # Full HTTP/2 exchange
  start_timestamp: %Timestamp{}, # Converted from DateTime
  response_delay_ms: 75          # Exchange duration (see Known Limitations)
}
```

### UDP.Datagram

```elixir
%UDP.Datagram{
  flow_seq: 0,                   # Index within flow's datagram list
  from: %Endpoint{},
  to: %Endpoint{},
  payload: <<...>>,
  timestamp: %Timestamp{},
  relative_offset_ms: 0,         # Offset from flow start
  size: 1024
}
```

## Best Practices

1. **Use `FlowKey` for lookups** - O(1) access instead of iterating

2. **Check `complete` for HTTP** - Incomplete exchanges have `nil` response

3. **Use `streams` for HTTP/2** - Matches HTTP/2 spec terminology

4. **Use timeline for playback** - Maintains chronological order across protocols

5. **Apply hosts_map early** - Makes logs and debugging more readable

6. **Understand `flow_seq` vs `seq_num`** - `flow_seq` is the index within a flow's event list; `seq_num` is only in TimelineEvent for timeline position

## Known Limitations

### HTTP/1 Timestamp Coarseness

HTTP/1 request/response timestamps use the first TCP segment timestamp for each direction. This means:

- Multiple pipelined requests share the same `start_timestamp`
- `response_delay_ms` may not reflect true per-request latency for pipelined traffic

**Workaround**: For precise timing, analyze flows with single request/response exchanges.

### HTTP/2 response_delay_ms

`HTTP2.Stream.response_delay_ms` is the full exchange duration (request start → response complete), not time-to-first-byte (TTFB). For large response bodies, this over-estimates actual response latency.

**Workaround**: For TTFB approximations, consider using the underlying `exchange.start_timestamp` and `exchange.end_timestamp` along with response body size.

### FlowKey Host Independence

FlowKey lookups ignore the `host` field in endpoints. This means you can look up flows using keys built with or without `hosts_map` applied - both will find the same flow.
