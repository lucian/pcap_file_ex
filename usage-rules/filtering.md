# Complete Filtering Guide

PcapFileEx provides three different filtering systems. This guide explains when and how to use each one.

## Filtering Systems Overview

| Filter Type | Where | Performance | Flexibility | Best For |
|-------------|-------|-------------|-------------|----------|
| **PreFilter** | Rust-side (pre-decode) | ⚡⚡⚡ Fastest (10-100x) | Simple criteria | Large files, selective queries |
| **Filter** | Elixir-side (post-decode) | ⚡ Standard | Very flexible | Complex logic, small files |
| **DisplayFilter** | Elixir-side (post-decode) | ⚡ Standard | Wireshark-style | Familiar syntax |

## Decision Tree: Which Filter to Use?

```
Is file > 100MB?
├─ YES: Is query selective (<10% of packets)?
│   ├─ YES: Is criteria simple (IP/port/protocol)?
│   │   ├─ YES: Use PreFilter ⚡⚡⚡
│   │   └─ NO: Use Filter/DisplayFilter ⚡
│   └─ NO: Use Filter/DisplayFilter ⚡
└─ NO: Is syntax important?
    ├─ Wireshark-style preferred: Use DisplayFilter
    ├─ Function-based preferred: Use Filter
    └─ Simple criteria: Use PreFilter (small benefit)
```

## PreFilter (Rust-Side Filtering)

### Overview

- **Location**: Rust native code
- **Timing**: Before packet decode
- **Performance**: 10-100x faster than Elixir filtering
- **Limitation**: Only simple criteria (IP, port, protocol)

### When to Use PreFilter

✅ **Use PreFilter when:**
- File is large (>100MB)
- You need small subset of packets (<10%)
- Criteria are simple (IP, port, protocol)
- Early termination (take/find)

❌ **Don't use PreFilter when:**
- File is small (<10MB) - overhead not worth it
- Need most packets (>50%)
- Need complex application logic
- Need to check decoded payloads

### Available PreFilter Functions

#### Protocol Filtering

```elixir
# Single protocol
PreFilter.protocol("tcp")
PreFilter.protocol("udp")
PreFilter.protocol("icmp")
PreFilter.protocol("http")

# Multiple protocols (OR)
PreFilter.any([
  PreFilter.protocol("tcp"),
  PreFilter.protocol("udp")
])
```

#### Port Filtering

```elixir
# Destination port
PreFilter.port_dest(80)
PreFilter.port_dest(443)

# Source port
PreFilter.port_source(8080)

# Either source or destination
PreFilter.port(443)

# Multiple ports (OR)
PreFilter.any([
  PreFilter.port_dest(80),
  PreFilter.port_dest(443),
  PreFilter.port_dest(8080)
])
```

#### IP Address Filtering

```elixir
# Source IP (exact)
PreFilter.ip_source("192.168.1.1")

# Destination IP (exact)
PreFilter.ip_dest("10.0.0.1")

# Either source or destination
PreFilter.ip("192.168.1.1")

# CIDR range
PreFilter.ip_source_cidr("192.168.0.0/16")
PreFilter.ip_dest_cidr("10.0.0.0/8")
```

#### Combining Filters

```elixir
# AND semantics (all must match)
PreFilter.all([
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(80)
])
# Packet must be TCP AND destination port 80

# OR semantics (any can match)
PreFilter.any([
  PreFilter.port_dest(80),
  PreFilter.port_dest(443)
])
# Packet can have destination port 80 OR 443

# Nested combinations
PreFilter.all([
  PreFilter.protocol("tcp"),
  PreFilter.any([
    PreFilter.port_dest(80),
    PreFilter.port_dest(443),
    PreFilter.port_dest(8080)
  ])
])
# TCP packets to ports 80, 443, or 8080
```

### PreFilter Examples

```elixir
# Example 1: Find HTTPS traffic
{:ok, reader} = PcapFileEx.open("capture.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(443)
])
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.take(100)
PcapFileEx.Pcap.close(reader)

# Example 2: Internal network traffic
{:ok, reader} = PcapFileEx.open("capture.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.ip_source_cidr("10.0.0.0/8")
])
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.to_list()
PcapFileEx.Pcap.close(reader)

# Example 3: Web traffic (HTTP or HTTPS)
{:ok, reader} = PcapFileEx.open("capture.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.any([
    PreFilter.port_dest(80),
    PreFilter.port_dest(443)
  ])
])
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.to_list()
PcapFileEx.Pcap.close(reader)

# Example 4: Clearing filter
{:ok, reader} = PcapFileEx.open("capture.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [PreFilter.protocol("tcp")])
tcp_packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.take(100)

:ok = PcapFileEx.Pcap.clear_filter(reader)  # Back to all packets
all_packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.take(100)
PcapFileEx.Pcap.close(reader)
```

## Filter (Elixir-Side Filtering)

### Overview

- **Location**: Elixir code
- **Timing**: After packet decode
- **Performance**: Standard
- **Flexibility**: Very flexible, full Elixir logic

### Available Filter Functions

#### Protocol Filtering

```elixir
# Filter by single protocol
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_protocol(:tcp)
|> Enum.to_list()

# Filter by multiple protocols
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_protocol([:tcp, :udp])
|> Enum.to_list()
```

#### Size Filtering

```elixir
# Exact size
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_size(1500)
|> Enum.to_list()

# Size range
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_size(100..1500)
|> Enum.to_list()

# Minimum size
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_size(1000..)
|> Enum.to_list()
```

#### Time Range Filtering

```elixir
start_time = ~U[2025-01-01 00:00:00Z]
end_time = ~U[2025-01-02 00:00:00Z]

PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_time_range(start_time, end_time)
|> Enum.to_list()
```

#### Endpoint Filtering

```elixir
# By source endpoint
endpoint = %PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080}
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_source(endpoint)
|> Enum.to_list()

# By destination endpoint
endpoint = %PcapFileEx.Endpoint{ip: "10.0.0.1", port: 80}
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_destination(endpoint)
|> Enum.to_list()

# By either source or destination
endpoint = %PcapFileEx.Endpoint{ip: "192.168.1.1", port: nil}
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_endpoint(endpoint)
|> Enum.to_list()
```

#### Custom Matching

```elixir
# Custom predicate function
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.matching(fn packet ->
  # Any custom logic
  :http in packet.protocols and
  byte_size(packet.data) > 1000 and
  packet.timestamp.hour >= 9 and
  packet.timestamp.hour <= 17
end)
|> Enum.to_list()
```

### Chaining Filters

```elixir
# Combine multiple filters
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_protocol(:tcp)
|> PcapFileEx.Filter.by_size(100..1500)
|> PcapFileEx.Filter.by_time_range(start_time, end_time)
|> PcapFileEx.Filter.matching(fn p ->
  p.dst.port in [80, 443, 8080]
end)
|> Enum.to_list()
```

### Filter Examples

```elixir
# Example 1: Large HTTP packets
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_protocol(:http)
|> PcapFileEx.Filter.by_size(1000..)
|> Enum.to_list()

# Example 2: Traffic to specific server during business hours
server = %PcapFileEx.Endpoint{ip: "10.0.0.1", port: nil}
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_destination(server)
|> PcapFileEx.Filter.matching(fn p ->
  p.timestamp.hour >= 9 and p.timestamp.hour <= 17
end)
|> Enum.to_list()

# Example 3: Complex application logic
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.matching(fn packet ->
  cond do
    :http in packet.protocols ->
      http = packet.decoded[:http]
      http.method == "POST" and String.contains?(http.path || "", "/api/")

    :tcp in packet.protocols ->
      packet.dst.port in [80, 443, 8080]

    true ->
      false
  end
end)
|> Enum.to_list()
```

## DisplayFilter (Wireshark-Style)

### Overview

- **Location**: Elixir code
- **Timing**: After packet decode
- **Syntax**: Wireshark-style expressions
- **Best for**: Users familiar with Wireshark

### Supported Operators

#### Comparison Operators

```
==    Equal
!=    Not equal
>     Greater than
<     Less than
>=    Greater than or equal
<=    Less than or equal
```

#### Logical Operators

```
&&    AND
||    OR
!     NOT
```

#### Field Types

```
String fields:   "value" or 'value'
Numeric fields:  123, 456.78
IP addresses:    192.168.1.1
Boolean:         true, false
```

### Available Fields

#### IP Layer

```
ip.src          Source IP address
ip.dst          Destination IP address
ip.version      IP version (4 or 6)
```

#### TCP Layer

```
tcp.srcport     Source port
tcp.dstport     Destination port
tcp.flags.syn   SYN flag
tcp.flags.ack   ACK flag
tcp.flags.fin   FIN flag
tcp.flags.rst   RST flag
```

#### UDP Layer

```
udp.srcport     Source port
udp.dstport     Destination port
```

#### HTTP Layer

```
http.request.method      HTTP method (GET, POST, etc.)
http.request.uri         Request URI/path
http.request.version     HTTP version
http.response.code       Response status code
http.host                Host header
```

#### Packet Metadata

```
frame.len        Packet length (bytes)
frame.time       Packet timestamp
```

### DisplayFilter Examples

```elixir
# Example 1: Simple inline filter
packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("tcp.dstport == 80")
|> Enum.to_list()

# Example 2: Compiled filter (reuse)
{:ok, filter} = PcapFileEx.DisplayFilter.compile("ip.src == 192.168.1.1 && tcp.dstport == 443")
packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.run(filter)
|> Enum.to_list()

# Example 3: HTTP GET requests
packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("http.request.method == \"GET\"")
|> Enum.to_list()

# Example 4: Complex expression
packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("""
  (ip.src == 192.168.1.1 || ip.dst == 192.168.1.1) &&
  (tcp.dstport == 80 || tcp.dstport == 443) &&
  frame.len > 1000
""")
|> Enum.to_list()

# Example 5: HTTP responses with errors
packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("http.response.code >= 400")
|> Enum.to_list()

# Example 6: SYN packets
packets = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.DisplayFilter.filter("tcp.flags.syn == true && tcp.flags.ack == false")
|> Enum.to_list()
```

## Comparing the Three Approaches

### Same Query, Three Ways

Find all HTTPS traffic from 192.168.1.0/24:

#### Method 1: PreFilter (Fastest for large files)

```elixir
{:ok, reader} = PcapFileEx.open("large.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(443),
  PreFilter.ip_source_cidr("192.168.1.0/24")
])
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.to_list()
PcapFileEx.Pcap.close(reader)
```

#### Method 2: Filter (Most flexible)

```elixir
source_endpoint = %PcapFileEx.Endpoint{ip: "192.168.1.0/24", port: nil}
packets = PcapFileEx.stream!("large.pcap")
|> PcapFileEx.Filter.by_protocol(:tcp)
|> PcapFileEx.Filter.matching(fn p ->
  p.dst.port == 443 and ip_in_cidr?(p.src.ip, "192.168.1.0/24")
end)
|> Enum.to_list()
```

#### Method 3: DisplayFilter (Wireshark syntax)

```elixir
packets = PcapFileEx.stream!("large.pcap")
|> PcapFileEx.DisplayFilter.filter("""
  tcp.dstport == 443 &&
  ip.src >= 192.168.1.0 &&
  ip.src <= 192.168.1.255
""")
|> Enum.to_list()
```

## Advanced Filtering Patterns

### Pattern 1: Two-Stage Filtering

Combine PreFilter (fast) with Elixir Filter (flexible):

```elixir
# Stage 1: PreFilter eliminates ~90% of packets (fast)
{:ok, reader} = PcapFileEx.open("huge.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(80)
])

# Stage 2: Elixir Filter for complex logic (on remaining 10%)
packets = PcapFileEx.Stream.from_reader!(reader)
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].method == "POST" and
  String.contains?(p.decoded[:http].path || "", "/api/users")
end)
|> Enum.to_list()

PcapFileEx.Pcap.close(reader)
```

### Pattern 2: Conditional Filtering

```elixir
# Different filters based on packet type
packets = PcapFileEx.stream!("capture.pcap")
|> Stream.filter(fn packet ->
  cond do
    :http in packet.protocols ->
      http = packet.decoded[:http]
      http.method in ["POST", "PUT", "DELETE"]

    :dns in packet.protocols ->
      # DNS query packets
      true

    :tcp in packet.protocols ->
      packet.dst.port in [22, 3389]  # SSH or RDP

    true ->
      false
  end
end)
|> Enum.to_list()
```

### Pattern 3: Stateful Filtering

```elixir
# Track TCP connections, filter by connection state
connections = %{}

packets = PcapFileEx.stream!("capture.pcap")
|> Enum.reduce([], fn packet, acc ->
  if :tcp in packet.protocols do
    conn_key = {packet.src, packet.dst}

    # Update connection state
    # ... stateful logic ...

    # Filter based on state
    if should_include?(packet, connections[conn_key]) do
      [packet | acc]
    else
      acc
    end
  else
    acc
  end
end)
|> Enum.reverse()
```

### Pattern 4: Sampling

```elixir
# Keep every Nth packet
packets = PcapFileEx.stream!("huge.pcap")
|> Stream.with_index()
|> Stream.filter(fn {_packet, index} -> rem(index, 100) == 0 end)
|> Stream.map(fn {packet, _index} -> packet end)
|> Enum.to_list()

# Random sampling (10%)
packets = PcapFileEx.stream!("huge.pcap")
|> Stream.filter(fn _packet -> :rand.uniform() < 0.1 end)
|> Enum.to_list()
```

## Filter Performance Comparison

### Benchmark: 10GB file, 50M packets, find 100 TCP:443 packets

| Method | Time | Memory | Notes |
|--------|------|--------|-------|
| PreFilter | 1.2s | 50MB | Fastest, Rust-side |
| Filter | 120s | 50MB | 100x slower, Elixir-side |
| DisplayFilter | 125s | 50MB | Similar to Filter |
| Two-stage | 5s | 50MB | PreFilter + complex Elixir logic |

## Common Filtering Mistakes

### ❌ Mistake 1: Wrong Filter Choice for Large Files

```elixir
# DON'T: Use Elixir filter on 10GB file for simple query
PcapFileEx.stream!("10gb.pcap")
|> Stream.filter(fn p -> :tcp in p.protocols and p.dst.port == 443 end)
|> Enum.take(10)  # Takes 2 minutes!

# DO: Use PreFilter
{:ok, r} = PcapFileEx.open("10gb.pcap")
:ok = PcapFileEx.Pcap.set_filter(r, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(443)
])
packets = PcapFileEx.Stream.from_reader(r) |> Enum.take(10)  # Takes 1 second!
PcapFileEx.Pcap.close(r)
```

### ❌ Mistake 2: Forgetting to Close Reader

```elixir
# DON'T: Forget to close
{:ok, r} = PcapFileEx.open("file.pcap")
:ok = PcapFileEx.Pcap.set_filter(r, [...])
packets = PcapFileEx.Stream.from_reader(r) |> Enum.to_list()
# Missing close!

# DO: Always close
{:ok, r} = PcapFileEx.open("file.pcap")
try do
  :ok = PcapFileEx.Pcap.set_filter(r, [...])
  packets = PcapFileEx.Stream.from_reader(r) |> Enum.to_list()
after
  PcapFileEx.Pcap.close(r)
end
```

### ❌ Mistake 3: Using PreFilter for Broad Queries

```elixir
# DON'T: PreFilter that matches most packets (overhead not worth it)
{:ok, r} = PcapFileEx.open("file.pcap")
:ok = PcapFileEx.Pcap.set_filter(r, [
  PreFilter.any([  # Matches 90% of packets!
    PreFilter.protocol("tcp"),
    PreFilter.protocol("udp")
  ])
])

# DO: Use Elixir filter or no filter at all
packets = PcapFileEx.stream!("file.pcap")
|> Stream.filter(fn p -> p.protocol in [:tcp, :udp] end)
|> Enum.to_list()
```

## Summary: Filter Selection Guide

**Use PreFilter when:**
- ✅ File > 100MB
- ✅ Selective query (<10% of packets)
- ✅ Simple criteria (IP/port/protocol)
- ✅ Need maximum performance

**Use Filter when:**
- ✅ Complex application logic
- ✅ Need to check decoded payloads
- ✅ Flexible predicate functions
- ✅ File < 100MB

**Use DisplayFilter when:**
- ✅ Familiar with Wireshark syntax
- ✅ Want readable filter expressions
- ✅ Field-based queries
- ✅ Network engineer background
