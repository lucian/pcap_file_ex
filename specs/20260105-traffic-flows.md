# Traffic Flows API Specification

**Date**: 2026-01-05
**Status**: Draft
**Author**: Claude Code

## Overview

Add a unified API to identify and analyze traffic flows from PCAP files, grouping packets by protocol (HTTP/1, HTTP/2, UDP) and endpoint pairs.

## Motivation

The current `PcapFileEx.HTTP2.analyze/2` handles HTTP/2 streams well, but users with mixed-protocol captures need to:
1. Identify all traffic flows in a single pass
2. Distinguish HTTP/1 from HTTP/2 traffic automatically
3. Capture UDP datagrams alongside HTTP traffic
4. Query flows by logical names (via hosts_map) rather than raw IPs

## API

### Entry Point

```elixir
@spec PcapFileEx.Flows.analyze(Path.t(), keyword()) ::
  {:ok, AnalysisResult.t()} | {:error, term()}

# Options:
#   hosts_map: %{ip_string => hostname_string}
#   decode_content: boolean (default: true)
```

### Data Structures

#### PcapFileEx.Endpoint (existing module)

The existing `PcapFileEx.Endpoint` struct at `lib/pcap_file_ex/endpoint.ex`:

```elixir
# Already defined in the codebase
%PcapFileEx.Endpoint{
  ip: String.t(),              # IPv4 or IPv6 as string
  port: non_neg_integer() | nil,
  host: String.t() | nil       # Resolved hostname from hosts_map
}

# Helpers already available:
Endpoint.new(ip)                            # => %Endpoint{ip: ip, port: nil, host: nil}
Endpoint.new(ip, port)                      # => %Endpoint{ip: ip, port: port, host: nil}
Endpoint.new(ip, port, host)                # => %Endpoint{ip: ip, port: port, host: host}
Endpoint.with_hosts(endpoint, map)          # => Resolves host from hosts_map
Endpoint.to_string(endpoint)                # => "hostname:port" or "ip:port"
Endpoint.from_tuple({ip_tuple, port})       # => Creates from TCP tuple (no host)
Endpoint.from_tuple({ip_tuple, port}, map)  # => Creates from TCP tuple with hosts_map
```

#### Flow Key (for map lookups)

```elixir
defmodule PcapFileEx.FlowKey do
  @moduledoc "Stable identity for flow map lookups"
  alias PcapFileEx.Endpoint

  @type t :: %__MODULE__{
    protocol: :http1 | :http2 | :udp,
    client_endpoint: Endpoint.t() | nil,
    server_endpoint: Endpoint.t()
  }

  @doc "Create a FlowKey for map lookups"
  @spec new(:http1 | :http2 | :udp, Endpoint.t() | nil, Endpoint.t()) :: t()
  def new(protocol, client_endpoint, server_endpoint)
end
```

#### Base Flow Identity

```elixir
defmodule PcapFileEx.Flow do
  alias PcapFileEx.{Endpoint, FlowKey}

  @type t :: %__MODULE__{
    protocol: :http1 | :http2 | :udp,
    # Display fields (non-authoritative, for convenience only)
    from: String.t() | :any,           # client host label (no port) or :any for UDP
    server: String.t(),                # "hostname:port" via Endpoint.to_string/1
    client: String.t() | nil,          # "hostname:port" via Endpoint.to_string/1
    # Authoritative fields (use these for filtering/matching)
    server_endpoint: Endpoint.t(),
    client_endpoint: Endpoint.t() | nil
  }

  @doc "Create a Flow with proper display field derivation"
  @spec new(:http1 | :http2 | :udp, Endpoint.t() | nil, Endpoint.t()) :: t()
  def new(protocol, client_endpoint, server_endpoint)

  @doc "Extract a FlowKey for map lookups (canonical key extraction)"
  @spec key(t()) :: FlowKey.t()
  def key(%__MODULE__{} = flow)
end
```

**Design decisions**:
- **`FlowKey`**: Stable struct for map lookups using only `protocol`, `client_endpoint`, `server_endpoint`
- **`from`**: Host-only display label (no port) for readability; use `client_endpoint` for precise matching
- **`server`/`client`**: Derived via `Endpoint.to_string/1` for display; use `*_endpoint` for matching
- **Constructors**: `Flow.new/3` and `FlowKey.new/3` ensure proper derivation; avoid manual struct creation
- **Key extraction**: Use `Flow.key/1` as the canonical way to extract a `FlowKey` from a `Flow`

#### Analysis Result

```elixir
defmodule PcapFileEx.Flows.AnalysisResult do
  alias PcapFileEx.{Flow, FlowKey}
  alias PcapFileEx.Flows.{HTTP1, HTTP2, UDP, Stats, TimelineEvent}

  @type flow_ref :: %{
    protocol: :http1 | :http2 | :udp,
    index: non_neg_integer()           # Index into the protocol-specific list
  }

  @type t :: %__MODULE__{
    flows: %{FlowKey.t() => flow_ref()},  # O(1) lookup map keyed by FlowKey (stable)
    http1: [HTTP1.Flow.t()],              # HTTP/1.x flows with exchanges (sorted by first exchange timestamp)
    http2: [HTTP2.Flow.t()],              # HTTP/2 flows with streams (sorted by first stream timestamp)
    udp: [UDP.Flow.t()],                  # UDP flows with datagrams (sorted by first datagram timestamp)
    timeline: [TimelineEvent.t()],        # Unified timeline of all events (sorted by timestamp, then seq_num)
    stats: Stats.t()                      # Aggregate statistics
  }

  @doc "Lookup a flow by its key"
  @spec get_flow(t(), FlowKey.t()) :: HTTP1.Flow.t() | HTTP2.Flow.t() | UDP.Flow.t() | nil
  def get_flow(%__MODULE__{} = result, %FlowKey{} = key)

  @doc "Get the actual event data from a timeline event"
  @spec get_event(t(), TimelineEvent.t()) :: HTTP1.Exchange.t() | HTTP2.Stream.t() | UDP.Datagram.t() | nil
  def get_event(%__MODULE__{} = result, %TimelineEvent{} = event)
end
```

**Notes**:
- The `flows` field uses `FlowKey.t()` (not `Flow.t()`) as keys for stable, reproducible lookups
- The `timeline` field provides a unified, ordered view of all events for playback
- Timeline is sorted by `(timestamp, seq_num)` where `seq_num` ensures stable ordering for events with identical timestamps
- `seq_num` on each event equals its index in the timeline list: `timeline[event.seq_num] == event`
- All timestamps use `Timestamp.t()`; HTTP/2 `DateTime.t()` is converted via `Timestamp.from_datetime/1`
- Use `get_event/2` to retrieve full event data from a `TimelineEvent`

#### Stats

```elixir
defmodule PcapFileEx.Flows.Stats do
  alias PcapFileEx.Timestamp

  @type t :: %__MODULE__{
    packet_count: non_neg_integer(),
    byte_count: non_neg_integer(),
    first_timestamp: Timestamp.t() | nil,
    last_timestamp: Timestamp.t() | nil,
    duration_ms: non_neg_integer()        # 0 when timestamps are nil or equal
  }
end
```

**Note**: `duration_ms` is 0 when `first_timestamp` or `last_timestamp` is nil, or when they are equal. It is never nil.

#### Timeline Event (for unified playback)

```elixir
defmodule PcapFileEx.Flows.TimelineEvent do
  @moduledoc "Single event in the unified timeline for playback"
  alias PcapFileEx.{FlowKey, Timestamp}

  @type event_type :: :http1_exchange | :http2_stream | :udp_datagram

  @type t :: %__MODULE__{
    seq_num: non_neg_integer(),        # Timeline index (0-based, matches position in timeline list)
    timestamp: Timestamp.t(),          # Event timestamp (start of exchange/stream/datagram)
    event_type: event_type(),
    flow_key: FlowKey.t(),             # Which flow this belongs to
    flow_index: non_neg_integer(),     # Index within the flow's list (e.g., http2[i].streams[j])
    event_index: non_neg_integer()     # Index within the event list (e.g., j in streams[j])
  }
end
```

**Purpose**: Enables unified playback by providing a single ordered timeline across all protocols.

**`seq_num` semantics**: `seq_num` equals the event's index in the `timeline` list (i.e., `timeline[seq_num] == event`). This ensures stable cross-referencing where `seq_num` always matches timeline position.

#### HTTP/1 Structures

```elixir
defmodule PcapFileEx.Flows.HTTP1.Flow do
  alias PcapFileEx.Flow
  alias PcapFileEx.Flows.{HTTP1, Stats}

  @type t :: %__MODULE__{
    flow: Flow.t(),
    exchanges: [HTTP1.Exchange.t()],
    stats: Stats.t()
  }
end

defmodule PcapFileEx.Flows.HTTP1.Exchange do
  alias PcapFileEx.Timestamp

  @type request :: %{
    method: String.t(),
    path: String.t(),
    version: String.t(),
    headers: %{String.t() => String.t()},
    body: binary(),
    decoded_body: term() | nil,
    timestamp: Timestamp.t()
  }

  @type response :: %{
    status: non_neg_integer(),
    reason: String.t(),
    version: String.t(),
    headers: %{String.t() => String.t()},
    body: binary(),
    decoded_body: term() | nil,
    timestamp: Timestamp.t()
  }

  @type t :: %__MODULE__{
    flow_seq: non_neg_integer(),          # Index within the flow's exchange list (0-based)
    request: request(),
    response: response() | nil,
    start_timestamp: Timestamp.t(),       # When request started
    end_timestamp: Timestamp.t() | nil,   # When response completed
    response_delay_ms: non_neg_integer(), # Delay between request and response completion (for playback)
    complete: boolean()
  }
end

# Note: flow_seq is the index within the flow, not the timeline index.
# Timeline index is only in TimelineEvent.seq_num.
```

#### HTTP/2 Structures

```elixir
defmodule PcapFileEx.Flows.HTTP2.Stream do
  @moduledoc "Wrapper around HTTP2.Exchange with sequence number and playback timing"
  alias PcapFileEx.HTTP2.Exchange
  alias PcapFileEx.Timestamp

  @type t :: %__MODULE__{
    flow_seq: non_neg_integer(),          # Index within the flow's stream list (0-based)
    exchange: Exchange.t(),               # The underlying HTTP2.Exchange (uses DateTime internally)
    start_timestamp: Timestamp.t(),       # Converted from exchange.start_timestamp
    response_delay_ms: non_neg_integer()  # Delay from start to end of exchange (for playback)
  }
end

# Note: flow_seq is the index within the flow, not the timeline index.
# response_delay_ms is computed from end_timestamp (see Known Limitations).

defmodule PcapFileEx.Flows.HTTP2.Flow do
  alias PcapFileEx.Flow
  alias PcapFileEx.HTTP2.IncompleteExchange
  alias PcapFileEx.Flows.{HTTP2, Stats}

  @type t :: %__MODULE__{
    flow: Flow.t(),
    streams: [HTTP2.Stream.t()],            # Complete streams with flow_seq
    incomplete: [IncompleteExchange.t()],   # Incomplete streams (not in timeline)
    stats: Stats.t()
  }
end
```

**Notes**:
- `HTTP2.Stream` wraps the existing `HTTP2.Exchange` to add `flow_seq` for flow-level ordering
- `start_timestamp` is converted from `DateTime.t()` to `Timestamp.t()` via `Timestamp.from_datetime/1` for unified timestamp handling
- Incomplete streams are excluded from the unified timeline

#### UDP Structures

```elixir
defmodule PcapFileEx.Flows.UDP.Flow do
  alias PcapFileEx.Flow
  alias PcapFileEx.Flows.{UDP, Stats}

  @type t :: %__MODULE__{
    flow: Flow.t(),
    datagrams: [UDP.Datagram.t()],
    stats: Stats.t()
  }
end

defmodule PcapFileEx.Flows.UDP.Datagram do
  alias PcapFileEx.{Endpoint, Timestamp}

  @type t :: %__MODULE__{
    flow_seq: non_neg_integer(),          # Index within the flow's datagram list (0-based)
    from: Endpoint.t(),
    to: Endpoint.t(),
    payload: binary(),
    timestamp: Timestamp.t(),
    relative_offset_ms: non_neg_integer(), # Offset from flow start (for playback)
    size: non_neg_integer()
  }
end

# Note: flow_seq is the index within the flow, not the timeline index.
# relative_offset_ms = div(Timestamp.diff(datagram.timestamp, flow.stats.first_timestamp), 1_000_000)
# First datagram in flow has relative_offset_ms = 0
```

## Behavior

### Protocol Detection

Protocols are detected via content inspection:

| Protocol | Detection Method |
|----------|------------------|
| HTTP/2 | First 24 bytes match `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"` (prior-knowledge h2c only) |
| HTTP/1 | Starts with method (`GET `, `POST `, etc.) or `HTTP/` response |
| UDP | IP protocol field = 17 |

**Limitation**: HTTP/2 upgrade flow (`Upgrade: h2c` in HTTP/1.1) is not supported. Only prior-knowledge HTTP/2 connections (where client sends HTTP/2 preface immediately) are detected. This matches the existing `PcapFileEx.HTTP2` module behavior.

### Client/Server Identification

| Protocol | Client Identification |
|----------|----------------------|
| HTTP/1 | First endpoint to send HTTP request |
| HTTP/2 | Connection preface sender, or odd stream ID initiator |
| UDP | N/A - uses `from: :any` pattern |

### UDP Flow Grouping

UDP datagrams are grouped by **destination (server) endpoint only**. All datagrams to the same server IP:port form a single flow regardless of source, matching the pattern:

```elixir
%Flow{from: :any, server: "udp-receiver:5005", protocol: :udp}
```

## Usage Examples

### Basic Analysis

```elixir
{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng")

IO.puts("HTTP/1 flows: #{length(result.http1)}")
IO.puts("HTTP/2 flows: #{length(result.http2)}")
IO.puts("UDP flows: #{length(result.udp)}")
```

### With Hosts Mapping

```elixir
hosts_map = %{
  "192.168.1.10" => "api-gateway",
  "192.168.1.20" => "metrics-collector",
  "192.168.1.30" => "backend-service",
  "192.168.1.40" => "web-client"
}

{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", hosts_map: hosts_map)

# Query HTTP/2 flows from client to backend
client_to_backend = Enum.filter(result.http2, fn f ->
  f.flow.from == "web-client" and f.flow.server == "backend-service:8080"
end)

# Get all streams (HTTP/2 uses "streams" terminology)
streams = Enum.flat_map(client_to_backend, & &1.streams)

# O(1) lookup by FlowKey (stable, reproducible)
key = PcapFileEx.FlowKey.new(:http2, client_endpoint, server_endpoint)
case PcapFileEx.Flows.AnalysisResult.get_flow(result, key) do
  %PcapFileEx.Flows.HTTP2.Flow{} = flow -> flow
  nil -> :not_found
end

# Or extract key from an existing flow
key = PcapFileEx.Flow.key(some_flow)
PcapFileEx.Flows.AnalysisResult.get_flow(result, key)
```

### Playback / Timeline Iteration

```elixir
{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", hosts_map: hosts_map)

# Iterate through unified timeline in capture order
Enum.each(result.timeline, fn event ->
  case PcapFileEx.Flows.AnalysisResult.get_event(result, event) do
    %PcapFileEx.Flows.HTTP1.Exchange{} = ex ->
      IO.puts("[#{event.seq_num}] HTTP/1: #{ex.request.method} #{ex.request.path}")

    %PcapFileEx.Flows.HTTP2.Stream{exchange: ex} ->
      IO.puts("[#{event.seq_num}] HTTP/2: #{ex.request.method} #{ex.request.path}")

    %PcapFileEx.Flows.UDP.Datagram{} = dg ->
      IO.puts("[#{event.seq_num}] UDP: #{dg.size} bytes to #{Endpoint.to_string(dg.to)}")
  end
end)

# Filter timeline by flow
my_flow_key = PcapFileEx.FlowKey.new(:http2, client_endpoint, server_endpoint)
my_events = Enum.filter(result.timeline, fn e -> e.flow_key == my_flow_key end)

# Get events by seq_num range (e.g., replay events 10-20)
replay_events = Enum.filter(result.timeline, fn e -> e.seq_num in 10..20 end)
```

### Filtering by Protocol

```elixir
# All HTTP/1 GET requests
result.http1
|> Enum.flat_map(& &1.exchanges)
|> Enum.filter(fn ex -> ex.request.method == "GET" end)

# UDP datagrams to specific port
result.udp
|> Enum.filter(fn f -> f.flow.server == "metrics-collector:5005" end)
|> Enum.flat_map(& &1.datagrams)
```

## Architecture

### Module Structure

```
lib/pcap_file_ex/
  flow.ex                      # Base Flow struct
  flows.ex                     # Entry point: analyze/2
  flows/
    analysis_result.ex
    stats.ex
    tcp_extractor.ex           # Shared TCP extraction (from HTTP2)
    protocol_detector.ex       # HTTP/1 vs HTTP/2 detection
    http1/
      flow.ex
      exchange.ex
      analyzer.ex
    http2/
      flow.ex                  # Wrapper around existing HTTP2 types
    udp/
      flow.ex
      datagram.ex
      collector.ex
```

### Code Reuse

The implementation extracts shared TCP extraction logic from `PcapFileEx.HTTP2` into `PcapFileEx.Flows.TCPExtractor`. After refactoring:

- `HTTP2.analyze/2` becomes a thin wrapper calling `TCPExtractor` + existing `Analyzer`
- `HTTP1.Analyzer` uses the same `TCPExtractor`
- `Flows.analyze/2` orchestrates all protocol analyzers

## Testing

### Unit Tests
- `TCPExtractor`: Segment parsing, reassembly, deduplication
- `ProtocolDetector`: HTTP/1 vs HTTP/2 vs unknown
- `HTTP1.Analyzer`: Client detection, exchange pairing
- `UDP.Collector`: Datagram collection, flow grouping

### Test Fixture Generation

Create `test/fixtures/capture_mixed_traffic.sh` to generate a PCAP with all three protocols:

**Files:**
```
test/fixtures/
  capture_mixed_traffic.sh      # Combined capture script
  mixed_traffic_sample.pcapng   # Generated fixture (committed to repo)
  mixed_traffic_sample.pcap     # Generated fixture (committed to repo)
```

**Reuses existing infrastructure:**
- HTTP/1: port 8899 (`http_server.py`, `http_client.py`)
- HTTP/2: port 8097 (`h2c_server.py`, `h2c_client.py`)
- UDP: port 8898 (`udp_server.py`, `udp_client.py`)

**Traffic sequence:**
1. Start HTTP/1, HTTP/2, UDP servers
2. Start dumpcap with filter: `(tcp port 8899) or (tcp port 8097) or (udp port 8898)`
3. Generate HTTP/1 requests (5)
4. Generate HTTP/2 requests (3 sets)
5. Generate UDP datagrams (5)
6. Stop capture and servers

### Integration Tests
- End-to-end with `test/fixtures/mixed_traffic_sample.pcapng`
- Verify correct protocol classification
- Verify hosts_map resolution
- Verify stats accuracy

### Property Tests
- Protocol detection always returns valid enum
- Stats are consistent with exchange/datagram counts
- HTTP/1 client is always the request sender

## Backwards Compatibility

- `PcapFileEx.HTTP2.analyze/2` continues to work unchanged
- New `PcapFileEx.Flows` module is additive
- Internal refactoring of TCP extraction is transparent to users

## Known Limitations

### HTTP/1 Timestamp Coarseness

HTTP/1 request/response timestamps are estimated using the first TCP segment timestamp for each direction. This means:

- Multiple pipelined requests in the same flow share the same `start_timestamp`
- The `response_delay_ms` may not reflect true per-request latency for pipelined traffic
- For accurate per-byte timestamps, TCP segment byte offsets would need to be tracked (complex, deferred to future release)

**Impact**: Playback timing is coarse for HTTP/1 flows with multiple exchanges. Sequential ordering within each flow is preserved.

### HTTP/2 response_delay_ms

`HTTP2.Stream.response_delay_ms` is computed from `exchange.end_timestamp`, not the actual response headers timestamp. This means:

- The delay represents full exchange duration (request start → response complete)
- For large response bodies, this over-estimates the time-to-first-byte (TTFB)
- Accurate TTFB would require tracking `response_headers_timestamp` in `HTTP2.StreamState`

**Impact**: Playback may delay response headers longer than actual network latency for large responses.

### flow_seq vs seq_num

- `flow_seq` in protocol structs (HTTP1.Exchange, HTTP2.Stream, UDP.Datagram) is the index within the flow's event list
- `seq_num` in TimelineEvent is the timeline index (position in the unified timeline)
- These are distinct values; do not assume they match

## Future Extensions

- TCP flow analysis (non-HTTP)
- TLS/HTTPS with decryption keys
- QUIC/HTTP/3 support
- Flow filtering options (by port, IP range, time window)
