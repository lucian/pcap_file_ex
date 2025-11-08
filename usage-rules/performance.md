# Performance Optimization Guide

Complete guide to optimizing PcapFileEx performance for different file sizes and query patterns.

## Decision Matrix: Choosing the Right Approach

| File Size | Query Type | Best Approach | Memory Usage | Speed |
|-----------|-----------|---------------|--------------|-------|
| < 10MB | Read all | `read_all/1` | High (loads all) | Fastest |
| < 10MB | Selective | `read_all/1` + Filter | High | Fast |
| 10-100MB | Read all | `stream/1` | Low (constant) | Fast |
| 10-100MB | Selective | `stream/1` + Filter | Low | Medium |
| 100MB-1GB | Read all | `stream/1` | Low | Medium |
| 100MB-1GB | Selective (<10%) | PreFilter + stream | Low | Fast |
| > 1GB | Read all | `stream/1` | Low | Slow |
| > 1GB | Selective (<10%) | **PreFilter + stream** | Low | **Fast** |
| > 1GB | Selective (>10%) | `stream/1` + Filter | Low | Slow |

## PreFilter Performance

### Benchmark Results

Real-world benchmarks on 10GB PCAP file with 50M packets:

```
Task: Find first 100 packets to port 443

Method 1 - Elixir Filter:
  PcapFileEx.stream("10gb.pcap")
  |> Stream.filter(fn p -> p.dst.port == 443 end)
  |> Enum.take(100)

  Time: ~120 seconds
  Memory: 50MB (constant)

Method 2 - PreFilter:
  {:ok, r} = PcapFileEx.open("10gb.pcap")
  :ok = PcapFileEx.Pcap.set_filter(r, [PreFilter.port_dest(443)])
  packets = PcapFileEx.Stream.from_reader(r) |> Enum.take(100)
  PcapFileEx.Pcap.close(r)

  Time: ~1.2 seconds (100x faster!)
  Memory: 50MB (constant)
```

### When PreFilter Gives Maximum Speedup

✅ **Best speedup scenarios:**
- Large files (>100MB)
- Selective queries (<10% of packets)
- Simple criteria (IP, port, protocol)
- Early termination (take/1, find/1)

❌ **Minimal speedup scenarios:**
- Small files (<10MB) - overhead not worth it
- Reading most packets (>50%)
- Complex application logic needed

## Streaming vs Eager Loading

### Eager Loading (`read_all/1`)

```elixir
{:ok, packets} = PcapFileEx.read_all("capture.pcap")
```

**Pros:**
- Fastest for small files
- Simple API
- Can use Enum functions freely
- Random access to packets

**Cons:**
- Loads entire file into memory
- OOM risk for large files
- Slower startup for large files

**Use when:**
- File < 100MB
- Need random access
- Will process all packets
- Memory is not constrained

### Streaming (`stream/1`)

```elixir
PcapFileEx.stream("capture.pcap")
|> Stream.filter(...)
|> Enum.to_list()
```

**Pros:**
- Constant memory usage
- Works with files larger than RAM
- Can use Stream functions
- Automatic resource cleanup

**Cons:**
- Sequential access only
- Slightly slower per-packet overhead
- Must use Stream-aware functions

**Use when:**
- File > 100MB
- Only need subset of packets
- Memory is constrained
- Processing pipeline works with streams

## Memory Management

### Memory Usage Patterns

```elixir
# HIGH memory - loads all
{:ok, packets} = PcapFileEx.read_all("10gb.pcap")  # 10GB in RAM!

# LOW memory - constant usage
PcapFileEx.stream("10gb.pcap")
|> Enum.each(fn packet -> process(packet) end)  # ~50MB constant

# MEDIUM memory - accumulation
PcapFileEx.stream("10gb.pcap")
|> Enum.to_list()  # Eventually loads all, but gradually

# LOW memory - early termination
PcapFileEx.stream("10gb.pcap")
|> Enum.take(1000)  # Stops after 1000 packets
```

### Resource Cleanup

```elixir
# ✅ AUTOMATIC cleanup (recommended)
PcapFileEx.stream("file.pcap") |> Enum.to_list()

# ✅ MANUAL cleanup (advanced)
{:ok, reader} = PcapFileEx.open("file.pcap")
try do
  packets = PcapFileEx.Stream.from_reader(reader) |> Enum.take(100)
after
  PcapFileEx.Pcap.close(reader)  # Always executes
end

# ❌ LEAK - reader never closed!
{:ok, reader} = PcapFileEx.open("file.pcap")
packets = PcapFileEx.Stream.from_reader(reader) |> Enum.to_list()
# Missing close!
```

## Decode Performance

### When to Disable Decoding

Decoding adds CPU overhead. Disable when you don't need protocol information:

```elixir
# ✅ Disable decode for raw metrics
packet_count = PcapFileEx.stream("large.pcap", decode: false)
|> Enum.count()

total_bytes = PcapFileEx.stream("large.pcap", decode: false)
|> Stream.map(&byte_size(&1.data))
|> Enum.sum()

# Find timestamp range
{first_ts, last_ts} = PcapFileEx.stream("large.pcap", decode: false)
|> Enum.reduce({nil, nil}, fn p, {first, _last} ->
  {first || p.timestamp, p.timestamp}
end)

# ❌ Keep decode enabled when you need protocol info
http_packets = PcapFileEx.stream("large.pcap")  # decode: true (default)
|> Stream.filter(fn p -> :http in p.protocols end)
|> Enum.to_list()
```

### Decode Performance Impact

```
Benchmark: Processing 1M packets

With decode: true (default)
  Time: 45 seconds
  Provides: protocols, decoded payloads, endpoints

With decode: false
  Time: 12 seconds (3.75x faster)
  Provides: timestamp, data (raw bytes)
```

## Statistics Performance

### Eager vs Streaming Statistics

```elixir
# Small files (<100MB) - eager is faster
{:ok, stats} = PcapFileEx.Stats.compute("small.pcap")
# Memory: Loads all packets
# Speed: Fast startup, fast computation

# Large files (>100MB) - streaming is better
{:ok, stats} = PcapFileEx.Stats.compute_streaming("large.pcap")
# Memory: Constant (streaming)
# Speed: Slower per-packet, but works on huge files

# From existing stream
stats = PcapFileEx.stream("file.pcap")
|> PcapFileEx.Filter.by_protocol(:tcp)
|> PcapFileEx.Stats.compute_from_stream()
```

## PreFilter Optimization Techniques

### Combining Filters for Maximum Performance

```elixir
# ✅ GOOD: Specific filters reduce packets early
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),      # Eliminates UDP, ICMP, etc.
  PreFilter.port_dest(443),       # Only port 443
  PreFilter.ip_source_cidr("10.0.0.0/8")  # Only internal IPs
])
# Result: Very few packets pass all filters

# ⚠️ OKAY: Broad filters
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp")  # Still many packets
])

# ❌ INEFFICIENT: Too many matches (use Elixir Filter instead)
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.any([
    PreFilter.protocol("tcp"),
    PreFilter.protocol("udp"),
    PreFilter.protocol("icmp")
  ])
])
# Most packets match! PreFilter overhead not worth it.
```

### OR vs AND Semantics

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
  PreFilter.port_dest(443),
  PreFilter.port_dest(8080)
])
# Packet can have ANY of these destination ports
```

### Clearing Filters

```elixir
# Set filter
:ok = PcapFileEx.Pcap.set_filter(reader, [...])

# Clear filter (back to all packets)
:ok = PcapFileEx.Pcap.clear_filter(reader)
```

## Common Performance Anti-Patterns

### ❌ Anti-Pattern 1: Loading Large Files Eagerly

```elixir
# DON'T: Load 10GB file into memory
{:ok, packets} = PcapFileEx.read_all("huge_10gb.pcap")
tcp_packets = Enum.filter(packets, fn p -> :tcp in p.protocols end)

# DO: Stream instead
tcp_packets = PcapFileEx.stream("huge_10gb.pcap")
|> Stream.filter(fn p -> :tcp in p.protocols end)
|> Enum.to_list()

# BETTER: Use PreFilter if selective
{:ok, reader} = PcapFileEx.open("huge_10gb.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [PreFilter.protocol("tcp")])
tcp_packets = PcapFileEx.Stream.from_reader(reader) |> Enum.to_list()
PcapFileEx.Pcap.close(reader)
```

### ❌ Anti-Pattern 2: Multiple Passes Over Large Files

```elixir
# DON'T: Read file multiple times
tcp_count = PcapFileEx.stream("huge.pcap")
|> Stream.filter(fn p -> :tcp in p.protocols end)
|> Enum.count()

udp_count = PcapFileEx.stream("huge.pcap")  # Re-reads entire file!
|> Stream.filter(fn p -> :udp in p.protocols end)
|> Enum.count()

# DO: Single pass with accumulator
{tcp_count, udp_count} = PcapFileEx.stream("huge.pcap")
|> Enum.reduce({0, 0}, fn packet, {tcp, udp} ->
  cond do
    :tcp in packet.protocols -> {tcp + 1, udp}
    :udp in packet.protocols -> {tcp, udp + 1}
    true -> {tcp, udp}
  end
end)
```

### ❌ Anti-Pattern 3: Unnecessary Decoding

```elixir
# DON'T: Decode when you only need size
sizes = PcapFileEx.stream("large.pcap")  # decode: true (default)
|> Stream.map(&byte_size(&1.data))
|> Enum.to_list()

# DO: Disable decode
sizes = PcapFileEx.stream("large.pcap", decode: false)
|> Stream.map(&byte_size(&1.data))
|> Enum.to_list()
```

### ❌ Anti-Pattern 4: Converting Stream to List Too Early

```elixir
# DON'T: Lose streaming benefits
packets = PcapFileEx.stream("huge.pcap") |> Enum.to_list()  # Loads all!
first_http = Enum.find(packets, fn p -> :http in p.protocols end)

# DO: Keep streaming
first_http = PcapFileEx.stream("huge.pcap")
|> Enum.find(fn p -> :http in p.protocols end)  # Stops at first match
```

## Performance Checklist

Before processing a PCAP file, ask:

1. **How large is the file?**
   - < 100MB → Consider `read_all/1`
   - > 100MB → Use `stream/1`

2. **Do I need all packets?**
   - Yes → Stream or read_all
   - No (<10%) → Use PreFilter

3. **Do I need protocol information?**
   - Yes → Keep `decode: true` (default)
   - No → Use `decode: false`

4. **Is my filter simple?**
   - Yes (IP/port/protocol) → Use PreFilter
   - No (complex logic) → Use Elixir Filter

5. **Will I process packets once or multiple times?**
   - Once → Streaming is fine
   - Multiple times → Consider read_all (if file is small)

6. **Do I need resource cleanup?**
   - Automatic → Use `stream/1`
   - Manual → Use `open/close` with try/after

## Real-World Performance Examples

### Example 1: Finding Specific HTTP Requests

```elixir
# Task: Find first 10 GET requests to /api/* in 5GB file

# ❌ SLOW (150 seconds)
PcapFileEx.stream("5gb.pcap")
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].method == "GET" and
  String.starts_with?(p.decoded[:http].path || "", "/api/")
end)
|> Enum.take(10)

# ✅ FAST (5 seconds)
{:ok, reader} = PcapFileEx.open("5gb.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(80)
])
packets = PcapFileEx.Stream.from_reader(reader)
|> Stream.filter(fn p ->
  :http in p.protocols and
  p.decoded[:http].method == "GET" and
  String.starts_with?(p.decoded[:http].path || "", "/api/")
end)
|> Enum.take(10)
PcapFileEx.Pcap.close(reader)
```

### Example 2: Computing Statistics on Large File

```elixir
# Task: Get protocol breakdown of 20GB file

# ❌ MEMORY ERROR
{:ok, packets} = PcapFileEx.read_all("20gb.pcap")  # OOM!

# ✅ WORKS (constant memory)
{:ok, stats} = PcapFileEx.Stats.compute_streaming("20gb.pcap")
IO.inspect(stats.protocols)
```

### Example 3: Extracting Subset of Packets

```elixir
# Task: Extract all HTTPS traffic from 10GB file to new file

# ❌ SLOW (uses Elixir filtering)
PcapFileEx.stream("10gb.pcap")
|> Stream.filter(fn p -> :tcp in p.protocols and p.dst.port == 443 end)
|> Stream.map(& &1.data)
# ... write to new file ...

# ✅ FAST (uses PreFilter - 50x faster)
{:ok, reader} = PcapFileEx.open("10gb.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(443)
])
PcapFileEx.Stream.from_reader(reader)
|> Stream.map(& &1.data)
# ... write to new file ...
PcapFileEx.Pcap.close(reader)
```

## Summary: Performance Best Practices

1. ✅ Use auto-detection (`PcapFileEx.open/1`)
2. ✅ Use PreFilter for large files + selective queries (10-100x speedup)
3. ✅ Use streaming for files > 100MB
4. ✅ Disable decode when you don't need protocol info (3-4x speedup)
5. ✅ Use streaming statistics for large files
6. ✅ Single-pass processing when possible
7. ✅ Automatic resource cleanup with `stream/1`
8. ❌ Don't load huge files with `read_all/1`
9. ❌ Don't use Elixir filtering on large files for simple criteria
10. ❌ Don't convert streams to lists unnecessarily
