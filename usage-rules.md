# PcapFileEx Usage Rules for LLMs

This guide helps AI coding assistants generate correct, performant PcapFileEx code.

## Critical Decision Trees

### 1. Always Use Auto-Detection

✅ **ALWAYS use these (auto-detect PCAP/PCAPNG):**
- `PcapFileEx.open/1`
- `PcapFileEx.read_all/1`
- `PcapFileEx.stream/1`

❌ **AVOID unless you're CERTAIN of file format:**
- `PcapFileEx.Pcap.open/1` (PCAP only - fails on PCAPNG)
- `PcapFileEx.PcapNg.open/1` (PCAPNG only - fails on PCAP)

**Why:** File extensions lie. A `.pcap` file might be PCAPNG format. Auto-detection prevents "wrong magic number" errors.

### 2. Choose the Right Access Pattern

```elixir
# Small files (<100MB) - load all into memory
{:ok, packets} = PcapFileEx.read_all("small.pcap")

# Large files (>100MB) - stream lazily
PcapFileEx.stream!("large.pcap")
|> Stream.filter(fn p -> :http in p.protocols end)
|> Enum.take(100)

# Need pre-filtering (10-100x faster for selective queries)
{:ok, reader} = PcapFileEx.open("huge.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(80)
])
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.take(10)
PcapFileEx.Pcap.close(reader)
```

### 3. Resource Management

✅ **Automatic (recommended) - no manual cleanup:**
```elixir
PcapFileEx.stream!("file.pcap") |> Enum.to_list()
```

✅ **Manual - MUST close when done:**
```elixir
{:ok, reader} = PcapFileEx.open("file.pcap")
try do
  # Use reader
  packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.to_list()
after
  PcapFileEx.Pcap.close(reader)  # or PcapNg.close(reader)
end
```

### 4. Filtering Strategy Selection

| File Size | Query Type | Use This | Why |
|-----------|-----------|----------|-----|
| >100MB | Simple (IP/port/protocol) | **PreFilter** | 10-100x faster (Rust-side) |
| Any | Complex application logic | Filter/DisplayFilter | Flexible (Elixir-side) |
| Any | Wireshark-style expressions | DisplayFilter | Familiar syntax |

### 5. Writer Format Selection

| Input Format | Output Needed | Use This | Why |
|--------------|---------------|----------|-----|
| Any | Auto-detect | `PcapFileEx.write/3` | Detects from extension (.pcap vs .pcapng) |
| PCAP | PCAP | `PcapFileEx.PcapWriter` | Direct PCAP → PCAP (fastest) |
| PCAPNG | PCAPNG | `PcapFileEx.PcapNgWriter` | Preserves interfaces |
| Any | Specific format | `PcapFileEx.copy/3` with `format:` | Explicit conversion |
| Small (<1000 pkts) | Any | `write!/3` batch | Simplest API |
| Large (>1GB) | Any | Streaming writer | O(1) memory, manual open/write/close |

## Common Mistakes to Avoid

### ❌ Mistake 1: Wrong Format Detection

```elixir
# DON'T: Assume format from extension
{:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
# Fails with "wrong magic number" if file is actually PCAPNG!

# DO: Use auto-detection
{:ok, reader} = PcapFileEx.open("capture.pcap")
```

### ❌ Mistake 2: Forgetting to Close Readers

```elixir
# DON'T: Open without closing (resource leak!)
{:ok, reader} = PcapFileEx.open("file.pcap")
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.to_list()
# Reader never closed!

# DO: Use streaming (auto-closes)
packets = PcapFileEx.stream!("file.pcap") |> Enum.to_list()

# OR: Explicitly close
{:ok, reader} = PcapFileEx.open("file.pcap")
try do
  packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.to_list()
after
  PcapFileEx.Pcap.close(reader)
end
```

### ❌ Mistake 3: Using Slow Filtering on Large Files

```elixir
# DON'T: Filter 10GB file in Elixir (VERY SLOW!)
PcapFileEx.stream!("huge_10gb.pcap")
|> Stream.filter(fn p -> :tcp in p.protocols and p.dst.port == 80 end)
|> Enum.take(10)

# DO: Use PreFilter (10-100x faster - Rust-side filtering)
{:ok, reader} = PcapFileEx.open("huge_10gb.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(80)
])
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.take(10)
PcapFileEx.Pcap.close(reader)
```

### ❌ Mistake 4: Double-Decoding HTTP Bodies

```elixir
# DON'T: Manually decode already-decoded body
http = PcapFileEx.Packet.decode_http!(packet)
data = Jason.decode!(http.body)  # http.decoded_body already has this!

# DO: Use automatic decoding
http = PcapFileEx.Packet.decode_http!(packet)
IO.inspect(http.decoded_body)  # Already parsed JSON/ETF/form data
```

### ❌ Mistake 5: Loading Huge Files Into Memory

```elixir
# DON'T: Load 10GB file into memory
{:ok, packets} = PcapFileEx.read_all("huge_10gb.pcap")
stats = PcapFileEx.Stats.compute_from_packets(packets)

# DO: Stream with constant memory
{:ok, stats} = PcapFileEx.Stats.compute_streaming("huge_10gb.pcap")
```

### ❌ Mistake 6: Accessing PCAPNG Fields on PCAP Files

```elixir
# DON'T: Assume PCAPNG-specific fields exist
packet.interface_id  # nil for PCAP files!
packet.interface     # nil for PCAP files!

# DO: Check format or guard
if packet.interface do
  IO.puts("Interface: #{packet.interface.name}")
end
```

### ❌ Mistake 7: Disabling Decode in Wrong Place

```elixir
# DON'T: Try to disable decoding per-packet
packet = PcapFileEx.Pcap.next_packet(reader, decode: false)  # NO SUCH OPTION!

# DO: Disable at stream/read_all level
packets = PcapFileEx.stream!("file.pcap", decode: false) |> Enum.to_list()
{:ok, packets} = PcapFileEx.read_all("file.pcap", decode: false)
```

### ❌ Mistake 8: Wrong Writer for Format Conversion

```elixir
# DON'T: Use format-specific writer for conversion (complex and error-prone)
{:ok, packets} = PcapFileEx.read_all("input.pcap")
{:ok, header} = PcapFileEx.get_header("input.pcap")
# Then manually create PCAPNG interfaces, assign interface_id, etc... (lots of code!)

# DO: Use copy/3 for format conversion (simple and handles all details)
PcapFileEx.copy("input.pcap", "output.pcapng", format: :pcapng)
```

### ❌ Mistake 9: Loading Huge Files for Filtering

```elixir
# DON'T: Load entire 10GB file into memory to filter (OOM crash!)
{:ok, all_packets} = PcapFileEx.read_all("huge_10gb.pcap")
filtered = Enum.filter(all_packets, fn p -> :http in p.protocols end)
{:ok, header} = PcapFileEx.get_header("huge_10gb.pcap")
PcapFileEx.write!("filtered.pcap", header, filtered)

# DO: Use export_filtered (streaming - constant memory)
PcapFileEx.export_filtered!(
  "huge_10gb.pcap",
  "filtered.pcap",
  fn p -> :http in p.protocols end
)
```

### ❌ Mistake 10: Forgetting interface_id for PCAPNG

```elixir
# DON'T: Write PCAP packets directly to PCAPNG (missing interface_id!)
{:ok, packets} = PcapFileEx.read_all("input.pcap")
# Packets have interface_id == nil, but PCAPNG writer requires it!
PcapFileEx.PcapNgWriter.write_all("output.pcapng", interfaces, packets)  # FAILS!

# DO: Use high-level API that handles conversion automatically
PcapFileEx.copy("input.pcap", "output.pcapng", format: :pcapng)

# OR: Manually assign interface_id if using low-level API
packets_with_interface = Enum.map(packets, &%{&1 | interface_id: 0})
PcapFileEx.PcapNgWriter.write_all("output.pcapng", interfaces, packets_with_interface)
```

## Essential Patterns

### Pattern 1: Basic File Reading

```elixir
# Auto-detect and read all (small files)
{:ok, packets} = PcapFileEx.read_all("capture.pcap")

# Stream for large files
PcapFileEx.stream!("large.pcap")
|> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
|> Enum.take(100)

# Manual control with explicit close
{:ok, reader} = PcapFileEx.open("capture.pcap")
{:ok, header} = PcapFileEx.Pcap.get_header(reader)
{:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
PcapFileEx.Pcap.close(reader)
```

### Pattern 2: Performance Optimization with PreFilter

**Use PreFilter when:**
- File is large (>100MB)
- You need only a small subset of packets
- Filter criteria are simple (IP, port, protocol)

```elixir
# Find first 10 HTTPS packets in 10GB file
{:ok, reader} = PcapFileEx.open("huge.pcap")
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(443)
])
packets = PcapFileEx.Stream.from_reader!(reader) |> Enum.take(10)
PcapFileEx.Pcap.close(reader)

# Multiple criteria with OR
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.any([
    PreFilter.port_dest(80),
    PreFilter.port_dest(443),
    PreFilter.port_dest(8080)
  ])
])

# IP range filtering
:ok = PcapFileEx.Pcap.set_filter(reader, [
  PreFilter.ip_source_cidr("192.168.0.0/16")
])
```

### Pattern 3: Elixir-Side Filtering

**Use Filter when:**
- File is small (<100MB)
- Need complex application logic
- Need to check decoded payloads

```elixir
PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_protocol(:http)
|> PcapFileEx.Filter.by_size(100..1500)
|> PcapFileEx.Filter.by_time_range(start_time, end_time)
|> PcapFileEx.Filter.matching(fn p ->
  # Custom logic
  :http in p.protocols and String.contains?(p.decoded[:http].path || "", "/api/")
end)
|> Enum.to_list()
```

### Pattern 4: DisplayFilter (Wireshark-Style)

```elixir
# Compile once, reuse multiple times
{:ok, filter} = PcapFileEx.DisplayFilter.compile("tcp.dstport == 80 && ip.src == 192.168.1.1")
packets = PcapFileEx.stream!("file.pcap")
|> PcapFileEx.DisplayFilter.run(filter)
|> Enum.to_list()

# Or inline (compiles on each use)
PcapFileEx.stream!("file.pcap")
|> PcapFileEx.DisplayFilter.filter("http.request.method == \"GET\"")
|> Enum.to_list()
```

### Pattern 5: HTTP Decoding

```elixir
# Packets are automatically decoded (decode: true is default)
{:ok, packets} = PcapFileEx.read_all("capture.pcap")
packet = hd(packets)

# Check what protocols were detected
packet.protocols  # [:ether, :ipv4, :tcp, :http]

# Access decoded HTTP
if :http in packet.protocols do
  http = packet.decoded[:http]  # or use decode_http!/1
  IO.inspect(http.method)
  IO.inspect(http.decoded_body)  # Auto-decoded JSON/ETF/form
end

# TCP reassembly for fragmented HTTP
PcapFileEx.TCP.stream_http_messages("capture.pcapng", types: [:request])
|> Enum.each(fn msg ->
  IO.puts("#{msg.http.method} #{msg.http.path}")
  IO.inspect(msg.http.decoded_body)
end)
```

### Pattern 6: Statistics Computation

```elixir
# Small files - eager computation
{:ok, stats} = PcapFileEx.Stats.compute("small.pcap")
IO.puts("Total packets: #{stats.total_packets}")
IO.puts("Total bytes: #{stats.total_bytes}")
IO.inspect(stats.protocols)  # %{tcp: 100, udp: 50, ...}

# Large files - streaming (constant memory)
{:ok, stats} = PcapFileEx.Stats.compute_streaming("huge.pcap")

# With filtering
tcp_stats = PcapFileEx.stream!("capture.pcap")
|> PcapFileEx.Filter.by_protocol(:tcp)
|> PcapFileEx.Stats.compute_from_stream()
```

### Pattern 7: Raw Packet Processing (No Decoding)

**When to disable decoding:**
- Only need packet counts or sizes
- Only need raw bytes
- Maximum performance

```elixir
# Count packets without decoding overhead
packet_count = PcapFileEx.stream!("large.pcap", decode: false)
|> Enum.count()

# Sum packet sizes
total_bytes = PcapFileEx.stream!("large.pcap", decode: false)
|> Stream.map(&byte_size(&1.data))
|> Enum.sum()

# Find largest packet
largest = PcapFileEx.stream!("large.pcap", decode: false)
|> Enum.max_by(&byte_size(&1.data))
```

## Protocol Detection vs Decoding

**Important distinction:**

- `packet.protocols` - List of detected protocols (auto-populated)
- `packet.protocol` - Highest layer protocol detected
- `packet.decoded` - Map of decoded application payloads (auto-populated if decode: true)

```elixir
packet.protocols  # [:ether, :ipv4, :tcp, :http]
packet.protocol   # :http
packet.decoded    # %{http: %PcapFileEx.HTTP{...}}

# Check before accessing
if :http in packet.protocols do
  http = packet.decoded[:http]
  # or use helper
  http = PcapFileEx.Packet.decode_http!(packet)
end
```

### Custom Protocol Decoders

Register custom application-layer protocol decoders using **DecoderRegistry** (v0.5.0+):

```elixir
# Register a custom decoder with context passing (new API)
PcapFileEx.DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, payload ->
    if my_protocol?(layers) do
      # Return context to decoder (thread-safe, efficient)
      {:match, extract_context(layers)}
    else
      false
    end
  end,
  decoder: fn context, payload ->
    # Use context from matcher (no double-decode!)
    {:ok, decode_with_context(payload, context)}
  end,
  fields: [...]
})

# Now packets are automatically decoded
packet = PcapFileEx.Packet.decode_registered(packet)
# => {:ok, {:my_protocol, decoded_data}}
```

**See [Decoder Registry Guide](usage-rules/decoder-registry.md) for complete patterns and migration guide.**

## When to Use Each Module

### PcapFileEx (Main API - Use This!)
- Auto-detects PCAP vs PCAPNG format
- `open/1`, `read_all/1`, `stream/1`
- **Use this unless you have specific reason not to**

### PcapFileEx.Pcap
- PCAP-specific operations
- Only use if you're certain file is PCAP format
- Supports both microsecond and nanosecond precision

### PcapFileEx.PcapNg
- PCAPNG-specific operations
- Only use if you're certain file is PCAPNG format
- Provides interface metadata

### PcapFileEx.Stream
- Lazy streaming with automatic resource cleanup
- `stream/1` for direct file access
- `from_reader/1` for manual reader (must close!)

### PcapFileEx.Filter
- Elixir-side filtering (post-decode)
- Flexible, supports complex logic
- Use for small files or complex queries

### PcapFileEx.PreFilter
- Rust-side filtering (pre-decode)
- **10-100x faster than Filter**
- Use for large files with simple criteria

### PcapFileEx.DisplayFilter
- Wireshark-style filter expressions
- Familiar syntax for network engineers
- Supports field-based queries

### PcapFileEx.Stats
- Statistics computation
- `compute/1` for small files
- `compute_streaming/1` for large files

### PcapFileEx.HTTP
- HTTP message decoding
- Automatic body parsing (JSON/ETF/form)
- Request/response extraction

### PcapFileEx.TCP
- TCP stream reassembly
- `stream_http_messages/2` for fragmented HTTP
- Handles out-of-order packets

### PcapFileEx.HTTP2
- HTTP/2 cleartext (h2c) stream reconstruction
- `analyze/2` for PCAP file analysis with options:
  - `:port` - Filter to specific TCP port
  - `:decode_content` - Auto-decode bodies based on Content-Type (default: true)
- Returns complete and incomplete exchanges with `decoded_body` field
- Automatic body decoding: JSON, text, multipart/*, binary fallback
- Supports mid-connection captures (with limitations)
- **Cleartext only** - no TLS/h2 support
- See [HTTP/2 Guide](usage-rules/http2.md) for content decoding patterns

### PcapFileEx.DecoderRegistry
- Register custom application-layer protocol decoders
- Extend protocol support beyond built-in HTTP
- **Use new context-passing API (v0.5.0+)** for thread-safety and performance
- Matchers return `{:match, context}` instead of booleans
- Decoders receive `(context, payload)` for clean data flow
- See [Decoder Registry Guide](usage-rules/decoder-registry.md) for complete guide

## Security Considerations

### ETF Decoding
When HTTP body contains Erlang Term Format (ETF):
```elixir
# Auto-decoded with :safe flag (prevents code execution)
http = PcapFileEx.Packet.decode_http!(packet)
http.decoded_body  # Safe ETF decode or nil if invalid
```

**NEVER** manually decode ETF from untrusted sources without `:safe` flag!

### Input Validation
Always validate packets from untrusted sources:
```elixir
# Check file validity before processing
case PcapFileEx.Validator.validate_file("untrusted.pcap") do
  {:ok, :pcap} -> # Safe to process
  {:ok, :pcapng} -> # Safe to process
  {:error, reason} -> # Invalid file
end
```

## Performance Guidelines

### File Size Thresholds

- **< 10MB**: Use `read_all/1` (fastest, loads all into memory)
- **10-100MB**: Use `stream/1` (balanced)
- **> 100MB**: Use `stream/1` + PreFilter if selective
- **> 1GB**: Always use streaming + PreFilter

### PreFilter Performance

PreFilter is **10-100x faster** than Elixir-side filtering for simple criteria:

```elixir
# Benchmark: Finding 10 packets in 10GB file
# Elixir Filter: ~120 seconds
# PreFilter: ~1.2 seconds (100x faster!)
```

Use PreFilter when:
- ✅ File > 100MB
- ✅ Need small subset of packets
- ✅ Criteria are simple (IP/port/protocol)

Use Elixir Filter when:
- ✅ File < 100MB
- ✅ Need complex application logic
- ✅ Need to check decoded payloads

## Timestamp Precision (v0.2.0+)

### Understanding Timestamp Fields

Each packet has **two timestamp fields**:

1. **`timestamp`** (DateTime) - Microsecond precision (6 decimal places)
   - Use for: Display, logging, general time queries
   - Backward compatible with existing code

2. **`timestamp_precise`** (Timestamp) - Nanosecond precision (9 decimal places)
   - Use for: Sorting, merging multiple files, precise timing analysis
   - Required for nanosecond-resolution PCAP files (common on Linux)

### Common Use Cases

#### ✅ Merging Packets from Multiple Files

```elixir
# Merge packets from multiple captures in chronological order
# Using PcapFileEx.Merge (v0.3.0+) - memory-efficient streaming merge
files = ["capture1.pcapng", "capture2.pcapng", "capture3.pcapng"]

# Memory-efficient streaming merge (O(N files) memory)
{:ok, stream} = PcapFileEx.Merge.stream(files)
packets = Enum.to_list(stream)

# With source tracking to identify packet origins
{:ok, stream} = PcapFileEx.Merge.stream(files, annotate_source: true)
packets = Enum.take(stream, 100)  # Each item is {packet, metadata}

# Legacy approach (loads all files into memory - not recommended for large files)
all_packets =
  files
  |> Enum.flat_map(fn file ->
    {:ok, packets} = PcapFileEx.read_all(file)
    packets
  end)
  |> Enum.sort_by(& &1.timestamp_precise, PcapFileEx.Timestamp)

# See usage-rules/merging.md for complete merge patterns and best practices
```

#### ✅ Calculating Precise Time Differences

```elixir
{:ok, packets} = PcapFileEx.read_all("capture.pcapng")
[first, second | _] = packets

# Get difference in nanoseconds
diff_ns = PcapFileEx.Timestamp.diff(second.timestamp_precise, first.timestamp_precise)
IO.puts("Time between packets: #{diff_ns} nanoseconds")

# Convert to other units
diff_us = div(diff_ns, 1000)        # microseconds
diff_ms = div(diff_ns, 1_000_000)   # milliseconds
```

#### ✅ Filtering by Precise Time Range

```elixir
# Find packets within a specific nanosecond-precision window
start_ts = PcapFileEx.Timestamp.new(1731065049, 735000000)
end_ts = PcapFileEx.Timestamp.new(1731065049, 736000000)

packets_in_window =
  PcapFileEx.stream!("capture.pcapng")
  |> Stream.filter(fn p ->
    PcapFileEx.Timestamp.compare(p.timestamp_precise, start_ts) != :lt and
    PcapFileEx.Timestamp.compare(p.timestamp_precise, end_ts) != :gt
  end)
  |> Enum.to_list()
```

### When to Use Which Field

| Use Case | Use `timestamp` | Use `timestamp_precise` |
|----------|----------------|------------------------|
| Display to users | ✅ | ❌ |
| Simple time filters | ✅ | ❌ |
| Sorting packets | ❌ | ✅ |
| Merging files | ❌ | ✅ |
| Sub-microsecond timing | ❌ | ✅ |
| Nanosecond analysis | ❌ | ✅ |

### Timestamp API Reference

```elixir
alias PcapFileEx.Timestamp

# Create timestamp
ts = Timestamp.new(secs, nanos)

# Convert to total nanoseconds
total_ns = Timestamp.to_unix_nanos(ts)

# Convert to DateTime (loses nanosecond precision)
dt = Timestamp.to_datetime(ts)

# Compare timestamps
Timestamp.compare(ts1, ts2)  # => :lt | :eq | :gt

# Calculate difference
diff_ns = Timestamp.diff(ts1, ts2)  # => integer (nanoseconds)
```

### ❌ Common Mistake: Using DateTime for Sorting

```elixir
# DON'T: Use DateTime for sorting (loses nanosecond precision!)
packets
|> Enum.sort_by(& &1.timestamp)

# DO: Use Timestamp for accurate sorting
packets
|> Enum.sort_by(& &1.timestamp_precise, PcapFileEx.Timestamp)
```

### Backward Compatibility

Existing code continues to work unchanged:

```elixir
# All of this still works!
packet.timestamp.year        # => 2024
packet.timestamp.month       # => 11
DateTime.compare(packet.timestamp, some_datetime)  # => :lt
```

## Related Documentation

- [Performance Guide](usage-rules/performance.md) - Detailed performance optimization
- [Filtering Guide](usage-rules/filtering.md) - Complete filtering reference
- [HTTP Guide](usage-rules/http.md) - HTTP/1.x decoding patterns
- [HTTP/2 Guide](usage-rules/http2.md) - HTTP/2 cleartext (h2c) analysis
- [Decoder Registry Guide](usage-rules/decoder-registry.md) - Custom protocol decoders with context passing
- [Format Guide](usage-rules/formats.md) - PCAP vs PCAPNG differences
- [Merging Guide](usage-rules/merging.md) - Multi-file chronological merge patterns
- [Writing Guide](usage-rules/writing.md) - Creating and exporting PCAP files
- [Examples](usage-rules/examples.md) - Complete working examples
