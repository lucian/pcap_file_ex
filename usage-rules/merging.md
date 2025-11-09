# Multi-File PCAP Merge Guide

PcapFileEx provides chronological merging of multiple PCAP/PCAPNG files. This guide explains when and how to use the merge functionality effectively.

## Overview

The `PcapFileEx.Merge` module merges packets from multiple capture files into a single chronologically-ordered stream using nanosecond-precision timestamps.

### Key Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Nanosecond precision** | Uses `Timestamp.compare/2` for accurate ordering | Preserves microsecond/nanosecond timestamps |
| **Memory efficient** | O(N files) memory via min-heap | Handles unlimited file sizes |
| **Mixed formats** | PCAP + PCAPNG in same merge | No conversion needed |
| **Interface remapping** | Global interface ID assignment | Prevents PCAPNG interface collisions |
| **Source annotation** | Track packet origins | Debug and provenance tracking |
| **Clock validation** | Detect timestamp drift | Identify clock sync issues |
| **Flexible error handling** | `:halt`, `:skip`, `:collect` modes | Control error behavior |

## Decision Tree: When to Use Merge

```
Need to combine multiple capture files?
├─ YES: Are files from synchronized clocks?
│   ├─ YES: Are files < 100MB each?
│   │   ├─ YES: Use Merge.stream/2 (simple)
│   │   └─ NO: Use Merge.stream/2 with lazy processing
│   └─ NO: Use Merge.validate_clocks/1 first
│       ├─ Drift < 10s: Use merge (with warning)
│       └─ Drift > 10s: Fix clock sync, then merge
└─ NO: Use standard PcapFileEx.stream/1

Need to track packet origins?
├─ YES: Use annotate_source: true option
└─ NO: Use default options

Files might have corrupt packets?
├─ YES: Use on_error: :collect or :skip
└─ NO: Use default on_error: :halt
```

## Basic Usage

### Simple Merge

```elixir
# Merge multiple files chronologically
{:ok, stream} = PcapFileEx.Merge.stream([
  "server1.pcap",
  "server2.pcap",
  "server3.pcap"
])

# Process as normal stream
packets = Enum.to_list(stream)

# Or use bang variant (raises on error)
stream = PcapFileEx.Merge.stream!([
  "server1.pcap",
  "server2.pcap"
])
```

### Count Total Packets

```elixir
# Fast packet count without loading packets
count = PcapFileEx.Merge.count([
  "capture1.pcap",
  "capture2.pcap",
  "capture3.pcap"
])

IO.puts("Total packets: #{count}")
```

### Validate Clock Synchronization

```elixir
files = ["server1.pcap", "server2.pcap", "server3.pcap"]

case PcapFileEx.Merge.validate_clocks(files) do
  {:ok, stats} ->
    IO.puts("Clock drift: #{stats.max_drift_ms}ms - acceptable")
    {:ok, stream} = PcapFileEx.Merge.stream(files)
    # Process stream...

  {:error, :excessive_drift, stats} ->
    IO.puts("WARNING: Clock drift #{stats.max_drift_ms}ms exceeds threshold")
    IO.puts("Files:")
    Enum.each(stats.files, fn file_stats ->
      IO.puts("  #{file_stats.path}: #{file_stats.count} packets")
      IO.puts("    First: #{file_stats.first_timestamp}")
      IO.puts("    Last:  #{file_stats.last_timestamp}")
    end)
    # Decide whether to proceed with merge or fix clock sync
end
```

## Advanced Features

### Source Annotation

Track which file each packet came from:

```elixir
{:ok, stream} = PcapFileEx.Merge.stream(
  ["server1.pcap", "server2.pcap"],
  annotate_source: true
)

# Each item is now {packet, metadata}
stream
|> Enum.take(10)
|> Enum.each(fn {packet, metadata} ->
  IO.puts("Packet from #{metadata.source_file}")
  IO.puts("  File index: #{metadata.file_index}")
  IO.puts("  Packet index: #{metadata.packet_index}")
  IO.puts("  Timestamp: #{packet.timestamp_precise}")

  # PCAPNG files include interface ID info
  if Map.has_key?(metadata, :original_interface_id) do
    IO.puts("  Original interface: #{metadata.original_interface_id}")
    IO.puts("  Remapped interface: #{metadata.remapped_interface_id}")
  end
end)
```

### Error Handling Modes

#### Halt Mode (Default)

```elixir
# Stop on first error - safest behavior
{:ok, stream} = PcapFileEx.Merge.stream(
  files,
  on_error: :halt  # default
)

# Stream will halt if any packet fails to parse
packets = Enum.to_list(stream)
```

#### Skip Mode

```elixir
# Skip corrupt packets, emit skip markers
{:ok, stream} = PcapFileEx.Merge.stream(
  files,
  on_error: :skip
)

stream
|> Enum.each(fn
  %PcapFileEx.Packet{} = packet ->
    # Normal packet
    process_packet(packet)

  {:skipped_packet, %{count: count, last_error: error}} ->
    # Corrupt packet skipped
    Logger.warning("Skipped #{count} packet(s): #{error.reason}")
end)
```

#### Collect Mode

```elixir
# Wrap all items in result tuples
{:ok, stream} = PcapFileEx.Merge.stream(
  files,
  on_error: :collect
)

{packets, errors} = Enum.reduce(stream, {[], []}, fn
  {:ok, packet}, {pkts, errs} ->
    {[packet | pkts], errs}

  {:error, metadata}, {pkts, errs} ->
    {pkts, [metadata | errs]}
end)

IO.puts("Successfully parsed: #{length(packets)} packets")
IO.puts("Errors: #{length(errors)}")

Enum.each(errors, fn error ->
  IO.puts("Error in #{error.source_file} at packet #{error.packet_index}")
  IO.puts("  Reason: #{error.reason}")
end)
```

#### Collect + Annotation (Nested Tuples)

```elixir
# Combine error collection with source tracking
{:ok, stream} = PcapFileEx.Merge.stream(
  files,
  annotate_source: true,
  on_error: :collect
)

# Items are now {:ok, {packet, metadata}} or {:error, metadata}
stream
|> Enum.take(100)
|> Enum.each(fn
  {:ok, {packet, metadata}} ->
    IO.puts("Packet from #{metadata.source_file}: #{byte_size(packet.data)} bytes")

  {:error, metadata} ->
    Logger.error("Failed to parse #{metadata.source_file} packet #{metadata.packet_index}")
end)
```

## PCAPNG Interface Remapping

When merging multiple PCAPNG files, interface IDs are automatically remapped to prevent collisions:

```elixir
# file1.pcapng has interfaces 0, 1
# file2.pcapng has interfaces 0, 1
# Merged stream has global interfaces 0, 1, 2, 3

{:ok, stream} = PcapFileEx.Merge.stream(
  ["file1.pcapng", "file2.pcapng"],
  annotate_source: true
)

stream
|> Enum.take(5)
|> Enum.each(fn {packet, metadata} ->
  # packet.interface_id is the global remapped ID
  # metadata.original_interface_id is the file-local ID
  # metadata.remapped_interface_id == packet.interface_id (always)

  IO.puts("From #{metadata.source_file}")
  IO.puts("  Original interface: #{metadata.original_interface_id}")
  IO.puts("  Global interface: #{metadata.remapped_interface_id}")

  # Invariant always holds: packet.interface_id == packet.interface.id
  if packet.interface do
    IO.puts("  Interface name: #{packet.interface.name}")
  end
end)
```

## Clock Synchronization Best Practices

### Why Clock Sync Matters

Without synchronized clocks, packets will be merged in **wrong order**:

```
Server A clock: 2025-11-09 10:00:00.000 (fast by 5 seconds)
Server B clock: 2025-11-09 09:59:55.000 (accurate)

Actual timeline:
  09:59:55.000 - Server B: HTTP request
  09:59:55.100 - Server A: HTTP response  (but timestamp says 10:00:00.100!)

Merged timeline WITHOUT sync:
  09:59:55.000 - Server B: HTTP request
  10:00:00.100 - Server A: HTTP response   <-- WRONG ORDER! (5 seconds late)

Result: HTTP response appears 5 seconds after request (impossible!)
```

### Recommended: chronyd (NTP)

See README.md section "Clock Synchronization for Multi-File Merge" for:
- Installation instructions (Linux/macOS)
- Configuration examples
- Verification commands
- Troubleshooting drift issues

### Pre-Merge Validation

```elixir
files = ["server1.pcap", "server2.pcap", "server3.pcap"]

case PcapFileEx.Merge.validate_clocks(files) do
  {:ok, %{max_drift_ms: drift}} when drift < 1000 ->
    # < 1 second drift is excellent
    IO.puts("✅ Clocks well synchronized (#{drift}ms drift)")
    {:ok, stream} = PcapFileEx.Merge.stream(files)

  {:ok, %{max_drift_ms: drift}} when drift < 10_000 ->
    # 1-10 seconds drift is acceptable for most use cases
    IO.puts("⚠️  Moderate clock drift (#{drift}ms) - proceed with caution")
    {:ok, stream} = PcapFileEx.Merge.stream(files)

  {:error, :excessive_drift, %{max_drift_ms: drift}} ->
    # > 10 seconds drift is problematic
    IO.puts("❌ Excessive clock drift (#{drift}ms) - fix NTP sync before merging")
    :error
end
```

## Performance Characteristics

### Memory Usage

```elixir
# Merge is memory-efficient: O(N files) not O(M packets)
# Only one packet per file is buffered in memory

# Small files (3 files × 10MB each)
{:ok, stream} = PcapFileEx.Merge.stream([
  "small1.pcap",  # 10MB
  "small2.pcap",  # 10MB
  "small3.pcap"   # 10MB
])
# Memory: ~3 packets buffered (few KB)
# Total: 30MB of files, but only KB of memory used

# Large files (3 files × 1GB each)
{:ok, stream} = PcapFileEx.Merge.stream([
  "large1.pcap",  # 1GB
  "large2.pcap",  # 1GB
  "large3.pcap"   # 1GB
])
# Memory: Still ~3 packets buffered (few KB)
# Total: 3GB of files, but only KB of memory used
```

### Time Complexity

- **Merge algorithm**: O(M log N) where M = total packets, N = number of files
- **Heap operations**: O(log N) per packet (push/pop from min-heap)
- **Timestamp comparison**: O(1) using `Timestamp.compare/2`

### Lazy Evaluation

```elixir
# Stream is lazy - packets only read when consumed
{:ok, stream} = PcapFileEx.Merge.stream([
  "file1.pcap",
  "file2.pcap",
  "file3.pcap"
])

# No packets loaded yet! Files opened but not read.

# Take first 10 packets - only reads enough to produce 10 results
first_10 = Enum.take(stream, 10)

# Find first HTTP packet - stops as soon as found
first_http = Enum.find(stream, fn packet ->
  :http in packet.protocols
end)
```

## Common Patterns

### Distributed Network Capture

```elixir
# Capture from multiple network taps, merge chronologically
firewall_capture = "firewall.pcap"
web_server_capture = "webserver.pcap"
db_server_capture = "database.pcap"

{:ok, stream} = PcapFileEx.Merge.stream(
  [firewall_capture, web_server_capture, db_server_capture],
  annotate_source: true
)

# Trace HTTP request through all systems
stream
|> Stream.filter(fn {packet, _meta} -> :http in packet.protocols end)
|> Stream.take(100)
|> Enum.each(fn {packet, metadata} ->
  location = Path.basename(metadata.source_file, ".pcap")
  IO.puts("[#{location}] HTTP packet at #{packet.timestamp}")
end)
```

### Time-Range Analysis

```elixir
# Merge and filter to specific time window
files = ["capture1.pcap", "capture2.pcap", "capture3.pcap"]

{:ok, stream} = PcapFileEx.Merge.stream(files)

# Find packets in specific 10-second window
start_time = ~U[2025-11-09 10:30:00Z]
end_time = ~U[2025-11-09 10:30:10Z]

packets_in_window =
  stream
  |> Stream.filter(fn packet ->
    DateTime.compare(packet.timestamp, start_time) in [:gt, :eq] and
    DateTime.compare(packet.timestamp, end_time) in [:lt, :eq]
  end)
  |> Enum.to_list()

IO.puts("Found #{length(packets_in_window)} packets in time window")
```

### Multi-Site Correlation

```elixir
# Correlate events across multiple geographic locations
sites = [
  {"us-east", "captures/us-east.pcap"},
  {"us-west", "captures/us-west.pcap"},
  {"eu-west", "captures/eu-west.pcap"},
  {"ap-south", "captures/ap-south.pcap"}
]

file_paths = Enum.map(sites, fn {_site, path} -> path end)

{:ok, stream} = PcapFileEx.Merge.stream(
  file_paths,
  annotate_source: true
)

# Track HTTP requests across sites
stream
|> Stream.filter(fn {packet, _meta} -> :http in packet.protocols end)
|> Enum.each(fn {packet, metadata} ->
  {site, _} = Enum.find(sites, fn {_, path} ->
    path == metadata.source_file
  end)

  IO.puts("[#{site}] #{packet.timestamp} - HTTP #{byte_size(packet.data)} bytes")
end)
```

### Error Recovery

```elixir
# Merge with automatic error recovery
files = ["potentially_corrupt1.pcap", "potentially_corrupt2.pcap"]

{:ok, stream} = PcapFileEx.Merge.stream(
  files,
  annotate_source: true,
  on_error: :skip
)

{success_count, skip_count} = Enum.reduce(stream, {0, 0}, fn
  %PcapFileEx.Packet{}, {success, skip} ->
    {success + 1, skip}

  {:skipped_packet, meta}, {success, skip} ->
    Logger.warning("Skipped #{meta.count} packet(s) in #{meta.last_error.source_file}")
    {success, skip + meta.count}
end)

IO.puts("Successfully parsed: #{success_count}")
IO.puts("Skipped corrupt packets: #{skip_count}")
```

## Troubleshooting

### Problem: Files Not Merging in Expected Order

**Symptom:** Packets appear out of order despite using merge

**Cause:** Clock drift between capture systems

**Solution:**
```elixir
# Validate clocks first
{:error, :excessive_drift, stats} = PcapFileEx.Merge.validate_clocks(files)

IO.puts("Clock drift: #{stats.max_drift_ms}ms")
Enum.each(stats.files, fn file_stats ->
  IO.puts("#{file_stats.path}:")
  IO.puts("  First: #{file_stats.first_timestamp}")
  IO.puts("  Last: #{file_stats.last_timestamp}")
end)

# Fix: Synchronize clocks with chronyd/NTP before capturing
```

### Problem: "file not found" Error

**Symptom:** `{:error, {:file_not_found, path}}`

**Solution:**
```elixir
# Validate files exist before merging
files = ["file1.pcap", "file2.pcap", "file3.pcap"]

existing_files = Enum.filter(files, &File.exists?/1)
missing_files = files -- existing_files

if missing_files != [] do
  IO.puts("Missing files: #{inspect(missing_files)}")
else
  {:ok, stream} = PcapFileEx.Merge.stream(existing_files)
end
```

### Problem: Memory Usage Growing

**Symptom:** Memory increases during merge

**Cause:** Using `Enum.to_list/1` instead of streaming

**Solution:**
```elixir
# ❌ Bad: Loads all packets into memory
{:ok, stream} = PcapFileEx.Merge.stream(files)
all_packets = Enum.to_list(stream)  # Memory grows!

# ✅ Good: Process lazily
{:ok, stream} = PcapFileEx.Merge.stream(files)
stream
|> Stream.filter(fn packet -> :http in packet.protocols end)
|> Stream.take(100)
|> Enum.each(&process_packet/1)  # Constant memory
```

### Problem: Interface IDs Don't Match

**Symptom:** For PCAPNG merges, `packet.interface_id != packet.interface.id`

**This should never happen!** If you see this, it's a bug in PcapFileEx. Please report with:
```elixir
# Include this debugging info in bug report
{:ok, stream} = PcapFileEx.Merge.stream(files, annotate_source: true)

stream
|> Enum.take(10)
|> Enum.each(fn {packet, metadata} ->
  if packet.interface && packet.interface_id != packet.interface.id do
    IO.puts("BUG: Interface ID mismatch!")
    IO.puts("  Source: #{metadata.source_file}")
    IO.puts("  packet.interface_id: #{packet.interface_id}")
    IO.puts("  packet.interface.id: #{packet.interface.id}")
    IO.puts("  Original ID: #{metadata.original_interface_id}")
    IO.puts("  Remapped ID: #{metadata.remapped_interface_id}")
  end
end)
```

## Related Documentation

- [Usage Rules](../usage-rules.md) - Main usage guide with decision trees
- [Performance Guide](performance.md) - Performance optimization strategies
- [Format Guide](formats.md) - PCAP vs PCAPNG differences
- [Examples](examples.md) - Complete working examples
- README.md - Clock synchronization setup instructions
