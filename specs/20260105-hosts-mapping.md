# Hosts Mapping Feature Specification

**Date:** 2026-01-05
**Status:** Draft (v3 - addressing second review)

## Problem Statement

When analyzing PCAP files, IP addresses are displayed as raw strings/tuples:

```elixir
# Current Packet output
%PcapFileEx.Packet{
  src: %PcapFileEx.Endpoint{ip: "172.25.0.4", port: 9091},
  dst: %PcapFileEx.Endpoint{ip: "172.65.251.78", port: 39604}
}

# Current HTTP2.analyze tcp_flow output (uses IP tuples, not strings!)
tcp_flow: {{{172, 65, 251, 78}, 23925}, {{172, 25, 0, 8}, 8081}}
```

Users want to map IPs to human-readable hostnames for easier analysis.

## Proposed Solution

### 1. Extend `PcapFileEx.Endpoint` with Optional Hostname

```elixir
defmodule PcapFileEx.Endpoint do
  defstruct ip: nil, port: nil, host: nil

  @type t :: %__MODULE__{
    ip: String.t(),
    port: non_neg_integer() | nil,
    host: String.t() | nil  # NEW: resolved hostname
  }
end
```

### 2. Canonical IP Format

**Decision:** All IPs in `hosts_map` use **string format** (IPv4: `"a.b.c.d"`, IPv6: `"a:b:c:d:e:f:g:h"`).

Conversion uses `:inet.ntoa/1` **everywhere** for consistency:
- Packet module already uses `format_ip/1` which calls `:inet.ntoa/1`
- HTTP/2 module will use same approach for tuple → string conversion

```elixir
# hosts_map always uses string keys
hosts = %{
  "172.25.0.4" => "api-gateway",
  "172.65.251.78" => "client-service",
  "2001:db8::1" => "ipv6-server"
}
```

### 3. Update `to_string/1` for Endpoint

```elixir
# With hostname and port
Endpoint.to_string(%Endpoint{ip: "172.25.0.4", port: 9091, host: "api-gateway"})
# => "api-gateway:9091"

# With hostname, nil port
Endpoint.to_string(%Endpoint{ip: "172.25.0.4", port: nil, host: "api-gateway"})
# => "api-gateway"

# Without hostname, with port (fallback to IP)
Endpoint.to_string(%Endpoint{ip: "172.25.0.4", port: 9091, host: nil})
# => "172.25.0.4:9091"

# Without hostname, nil port
Endpoint.to_string(%Endpoint{ip: "172.25.0.4", port: nil, host: nil})
# => "172.25.0.4"
```

**Rule:** Use `host` if present, else `ip`. Append `:port` only if port is non-nil.

### 4. HTTP2 Exchange & IncompleteExchange Updates

**BREAKING CHANGE:** Replace `tcp_flow` in **both** `Exchange` and `IncompleteExchange`.

#### When Client/Server Identified

```elixir
%Exchange{
  client: %Endpoint{ip: "172.65.251.78", port: 23925, host: "client-service"},
  server: %Endpoint{ip: "172.25.0.8", port: 8081, host: "backend-db"},
  endpoint_a: nil,  # nil when client/server known
  endpoint_b: nil
}
```

#### When Client/Server Unknown (fallback)

When the analyzer cannot identify client/server (no preface, ambiguous stream semantics):

```elixir
%Exchange{
  client: nil,   # nil when identification fails
  server: nil,
  endpoint_a: %Endpoint{ip: "172.65.251.78", port: 23925, host: "host-a"},  # flow_key order
  endpoint_b: %Endpoint{ip: "172.25.0.8", port: 8081, host: "host-b"}
}

%IncompleteExchange{
  client: nil,
  server: nil,
  endpoint_a: %Endpoint{...},
  endpoint_b: %Endpoint{...}
}
```

**Semantics:**
- `client`/`server`: Set only when HTTP/2 semantics allow identification (preface or stream ID parity)
- `endpoint_a`/`endpoint_b`: Set only when client/server unknown (preserves flow_key order)
- **Exactly one pair is non-nil** - never both

**Helper functions:**
```elixir
def endpoints(%Exchange{client: c, server: s}) when not is_nil(c), do: {c, s}
def endpoints(%Exchange{endpoint_a: a, endpoint_b: b}), do: {a, b}

def client_identified?(%Exchange{client: c}), do: not is_nil(c)
```

## Implementation Plan

### Phase 1: Endpoint Enhancement

**File:** `lib/pcap_file_ex/endpoint.ex`

1. Add `host` field to struct (default `nil`)
2. Add `@type hosts_map :: %{String.t() => String.t()}`
3. Add `new/1`, `new/2`, `new/3` (explicit arities for clarity):
   ```elixir
   @spec new(String.t()) :: t()
   def new(ip) when is_binary(ip), do: %__MODULE__{ip: ip, port: nil}

   @spec new(String.t(), non_neg_integer() | nil) :: t()
   def new(ip, port) when is_binary(ip), do: %__MODULE__{ip: ip, port: port}

   @spec new(String.t(), non_neg_integer() | nil, String.t() | nil) :: t()
   def new(ip, port, host) when is_binary(ip), do: %__MODULE__{ip: ip, port: port, host: host}
   ```
4. Add `with_hosts/2` - apply hosts_map to existing endpoint
5. Add `from_tuple/1` and `from_tuple/2`:
   ```elixir
   @spec from_tuple({tuple(), non_neg_integer()}) :: t()
   def from_tuple(tuple), do: from_tuple(tuple, %{})

   @spec from_tuple({tuple(), non_neg_integer()}, hosts_map()) :: t()
   def from_tuple({ip_tuple, port}, hosts_map) do
     ip = ip_tuple |> :inet.ntoa() |> to_string()
     %__MODULE__{ip: ip, port: port, host: Map.get(hosts_map, ip)}
   end
   ```
6. Update `to_string/1` - prefer hostname, handle nil port

### Phase 2: Packet Integration

**File:** `lib/pcap_file_ex/packet.ex`

1. Add `from_map/2` that accepts `opts` keyword list with `:hosts_map`
2. Keep `from_map/1` for backwards compatibility (calls `from_map(map, [])`)
3. Apply hosts resolution to src/dst endpoints after extraction

### Phase 3: API Entry Points (Complete Coverage)

Add `:hosts_map` option to **ALL** entry points:

**File:** `lib/pcap_file_ex.ex`
- `stream/2` - already has opts
- `stream!/2` - already has opts
- `read_all/2` - already has opts

**File:** `lib/pcap_file_ex/stream.ex`
- `packets/1` → add `packets/2` with opts (keep `/1`)
- `packets!/1` → add `packets!/2` with opts (keep `/1`)
- `from_reader/1` → add `from_reader/2` with opts (keep `/1`)
- `from_reader!/1` → add `from_reader!/2` with opts (keep `/1`)

**File:** `lib/pcap_file_ex/pcap.ex`
- `read_all/1` → add `read_all/2` with opts (keep `/1`)
- `next_packet/1` → add `next_packet/2` with opts (keep `/1`)

**File:** `lib/pcap_file_ex/pcapng.ex`
- `read_all/1` → add `read_all/2` with opts (keep `/1`)
- `next_packet/1` → add `next_packet/2` with opts (keep `/1`)

### Phase 4: HTTP2 Integration

**File:** `lib/pcap_file_ex/http2/exchange.ex`

1. Remove `tcp_flow` field
2. Add fields: `client`, `server`, `endpoint_a`, `endpoint_b` (all `Endpoint.t() | nil`)
3. Add `from_stream/3` with hosts_map
4. Add helper: `endpoints/1`, `client_identified?/1`
5. Keep `from_stream/2` for compat (calls `/3` with empty hosts_map)

**File:** `lib/pcap_file_ex/http2/incomplete_exchange.ex`

1. Same changes as Exchange

**File:** `lib/pcap_file_ex/http2/analyzer.ex`

1. Extract `:hosts_map` from opts
2. In `finalize_connection/2` → `finalize_connection/3`:
   - Check if `conn.client_identified`
   - If identified: set `client`/`server`, leave `endpoint_a`/`endpoint_b` nil
   - If not identified: set `endpoint_a`/`endpoint_b`, leave `client`/`server` nil
   - Use `Endpoint.from_tuple/2` for conversion

**File:** `lib/pcap_file_ex/http2.ex`

1. Add `:hosts_map` option to `analyze/2` (already has opts)
2. Add `:hosts_map` option to `analyze_segments/2` (already has opts)
3. Pass hosts_map to `Analyzer.analyze/2`

## API Changes Summary

| Module | Function | Change |
|--------|----------|--------|
| `Endpoint` | struct | Add `host` field |
| `Endpoint` | `new/1` | Existing (preserved) |
| `Endpoint` | `new/2` | Existing (unchanged) |
| `Endpoint` | `new/3` | NEW: `new(ip, port, host)` |
| `Endpoint` | `with_hosts/2` | NEW function |
| `Endpoint` | `from_tuple/1` | NEW: tuple → Endpoint (no host lookup) |
| `Endpoint` | `from_tuple/2` | NEW: tuple + hosts_map → Endpoint |
| `Endpoint` | `to_string/1` | Prefer host, handle nil port |
| `Packet` | `from_map/2` | NEW arity with opts (keep `/1`) |
| `PcapFileEx` | `stream/2` | Add `:hosts_map` option |
| `PcapFileEx` | `read_all/2` | Add `:hosts_map` option |
| `Stream` | `packets/2` | NEW arity with opts (keep `/1`) |
| `Stream` | `packets!/2` | NEW arity with opts (keep `/1`) |
| `Stream` | `from_reader/2` | NEW arity with opts (keep `/1`) |
| `Stream` | `from_reader!/2` | NEW arity with opts (keep `/1`) |
| `Pcap` | `read_all/2` | NEW arity with opts (keep `/1`) |
| `Pcap` | `next_packet/2` | NEW arity with opts (keep `/1`) |
| `PcapNg` | `read_all/2` | NEW arity with opts (keep `/1`) |
| `PcapNg` | `next_packet/2` | NEW arity with opts (keep `/1`) |
| `HTTP2` | `analyze/2` | Add `:hosts_map` option |
| `HTTP2` | `analyze_segments/2` | Add `:hosts_map` option |
| `Exchange` | struct | **BREAKING**: Replace `tcp_flow` with `client`/`server`/`endpoint_a`/`endpoint_b` |
| `Exchange` | `endpoints/1` | NEW helper |
| `Exchange` | `client_identified?/1` | NEW helper |
| `IncompleteExchange` | struct | **BREAKING**: Same as Exchange |

## Backwards Compatibility

**Non-breaking changes:**
- `host` field defaults to `nil`
- `to_string/1` falls back to IP when no host
- All `/1` function arities preserved
- `from_map/1` remains (calls `/2` with empty opts)

**Breaking changes:**
- `Exchange.tcp_flow` removed → use `Exchange.client`/`Exchange.server` or `endpoint_a`/`endpoint_b`
- `IncompleteExchange.tcp_flow` removed → same pattern

**Migration:**
```elixir
# Before
{{{src_ip}, src_port}, {{dst_ip}, dst_port}} = exchange.tcp_flow

# After (when client/server known)
%Endpoint{ip: client_ip, port: client_port} = exchange.client
%Endpoint{ip: server_ip, port: server_port} = exchange.server

# After (when unknown, using helper)
{endpoint1, endpoint2} = Exchange.endpoints(exchange)
```

## Decisions Made

| Question | Decision |
|----------|----------|
| Support /etc/hosts file format? | **No** - Map only |
| HTTP2 Exchange API | **Replace tcp_flow** with Endpoints (breaking) |
| Display format | **Prefer host over IP**, append `:port` only if non-nil |
| IP format in hosts_map | **String only** - use `:inet.ntoa/1` everywhere |
| Exchange field names | **client/server + endpoint_a/endpoint_b** fallback |
| nil port in to_string | **Omit colon** - return just host or IP |
| Unknown client handling | **Use endpoint_a/endpoint_b** when identification fails |
| from_tuple arities | **Both /1 and /2** - `/1` defaults to empty hosts_map |
| Endpoint.new arities | **Explicit /1, /2, /3** - preserve existing /1 for compat |

## Testing Strategy

1. Unit tests for `Endpoint.with_hosts/2`
2. Unit tests for `Endpoint.from_tuple/1` and `/2` (IPv4, IPv6)
3. Unit tests for `Endpoint.new/2` and `/3`
4. Unit tests for `to_string/1` all combinations
5. Property tests for endpoint invariants
6. Integration tests with hosts_map via all entry points
7. Test `HTTP2.analyze` with hosts_map option
8. Test `HTTP2.analyze_segments` with hosts_map option
9. Test Exchange with identified client/server
10. Test Exchange with unknown client (endpoint_a/endpoint_b fallback)
11. Test IncompleteExchange same patterns
12. Backwards compat tests for all `/1` arities
