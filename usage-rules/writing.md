# PCAP/PCAPNG Writing and Export Patterns

Guide for AI assistants on creating, filtering, and converting PCAP files with PcapFileEx.

## Quick Reference: When to Use Each API

| Task | API | Memory | Speed | Complexity |
|------|-----|--------|-------|------------|
| Filter + Export | `export_filtered/4` | Low (streaming) | Fast | Simple |
| Format convert | `copy/3` | Low (streaming) | Fast | Simple |
| Batch write | `write!/3` | High (loads all) | Fastest | Simple |
| Streaming write | `PcapWriter.open/write/close` | Low (O(1)) | Fast | Manual |
| PCAPNG multi-interface | `PcapNgWriter` | Low | Fast | Manual |
| Timestamp shift | `TimestampShift` + `write` | Medium | Fast | Simple |

## Critical Decision Trees

### 1. Format Selection

✅ **ALWAYS auto-detect when possible:**
```elixir
# Auto-detect output format from extension
PcapFileEx.write!("output.pcap", header, packets)    # PCAP
PcapFileEx.write!("output.pcapng", header, packets)  # PCAPNG
```

✅ **Explicit format when converting:**
```elixir
PcapFileEx.copy("input.pcap", "output.pcapng", format: :pcapng)
PcapFileEx.copy("input.pcapng", "output.pcap", format: :pcap)
```

❌ **AVOID format-specific writers unless you need manual control:**
```elixir
# DON'T: Manual writer for simple tasks
{:ok, writer} = PcapFileEx.PcapWriter.open("output.pcap", header)
# ... manual writing code

# DO: Use high-level API
PcapFileEx.write!("output.pcap", header, packets)
```

### 2. Batch vs Streaming

| Scenario | Use | Example |
|----------|-----|---------|
| < 1000 packets | Batch write (`write!/3`) | Small filtered result sets |
| 1000-10000 packets | Either | Check available memory |
| > 10GB file | Streaming (`export_filtered/4`) | Large file filtering |
| Need progress updates | Streaming (manual) | Process while writing |

### 3. Error Handling Strategy

**For export_filtered/4:**
```elixir
# :halt mode (default) - Stop on first error
PcapFileEx.export_filtered(src, dest, filter_fn)

# :skip mode - Skip corrupted packets, continue
PcapFileEx.export_filtered(src, dest, filter_fn, on_error: :skip)

# Custom error handling
case PcapFileEx.export_filtered(src, dest, filter_fn) do
  {:ok, count} -> IO.puts("Exported #{count} packets")
  {:error, reason} -> IO.puts("Export failed: #{reason}")
end
```

## Common Patterns

### Pattern 1: Filter and Export

**Use Case:** Extract subset of packets to new file

```elixir
# HTTP traffic only
PcapFileEx.export_filtered!(
  "full_capture.pcap",
  "http_only.pcap",
  fn packet -> :http in packet.protocols end
)

# Specific IP address
PcapFileEx.export_filtered!(
  "capture.pcap",
  "host_traffic.pcap",
  fn packet ->
    packet.src.ip == "192.168.1.100" or
    packet.dst.ip == "192.168.1.100"
  end
)

# Time range
start_time = ~U[2025-11-09 10:00:00Z]
end_time = ~U[2025-11-09 11:00:00Z]

PcapFileEx.export_filtered!(
  "full_day.pcapng",
  "incident_window.pcapng",
  fn packet ->
    DateTime.compare(packet.timestamp, start_time) != :lt and
    DateTime.compare(packet.timestamp, end_time) != :gt
  end
)

# Packet size filter
PcapFileEx.export_filtered!(
  "capture.pcap",
  "large_packets.pcap",
  fn packet -> byte_size(packet.data) > 1000 end
)

# Complex logic
PcapFileEx.export_filtered!(
  "capture.pcap",
  "suspicious.pcap",
  fn packet ->
    :tcp in packet.protocols and
    packet.dst.port in [22, 23, 3389] and  # SSH, Telnet, RDP
    byte_size(packet.data) > 100
  end
)
```

### Pattern 2: Format Conversion

**Use Case:** Convert between PCAP and PCAPNG formats

```elixir
# PCAP → PCAPNG (preserves all packets, adds interface metadata)
PcapFileEx.copy("legacy.pcap", "modern.pcapng", format: :pcapng)

# PCAPNG → PCAP (loses interface metadata, keeps packets)
PcapFileEx.copy("capture.pcapng", "legacy.pcap", format: :pcap)

# Auto-detect from extension
PcapFileEx.copy("input.pcap", "output.pcapng")  # Detects .pcapng

# Copy without conversion (same format)
PcapFileEx.copy("original.pcap", "backup.pcap")

# Convert and verify
case PcapFileEx.copy("input.pcap", "output.pcapng", format: :pcapng) do
  {:ok, count} ->
    IO.puts("Converted #{count} packets to PCAPNG format")

  {:error, reason} ->
    IO.puts("Conversion failed: #{reason}")
end
```

### Pattern 3: Streaming Large File Writes

**Use Case:** Filter multi-GB file without loading into memory

```elixir
# Manual streaming write for progress updates
{:ok, header} = PcapFileEx.get_header("huge_50gb.pcap")
{:ok, writer} = PcapFileEx.PcapWriter.open("filtered.pcap", header)

count = 0

try do
  PcapFileEx.stream!("huge_50gb.pcap")
  |> Stream.filter(fn packet -> :http in packet.protocols end)
  |> Enum.each(fn packet ->
    :ok = PcapFileEx.PcapWriter.write_packet(writer, packet)
    count = count + 1

    # Progress update every 10000 packets
    if rem(count, 10000) == 0 do
      IO.puts("Processed #{count} packets...")
    end
  end)

  IO.puts("Wrote #{count} packets")
after
  PcapFileEx.PcapWriter.close(writer)
end
```

**Simpler alternative (no progress updates):**
```elixir
# Use export_filtered - handles everything automatically
{:ok, count} = PcapFileEx.export_filtered(
  "huge_50gb.pcap",
  "filtered.pcap",
  fn packet -> :http in packet.protocols end
)

IO.puts("Exported #{count} packets")
```

### Pattern 4: Timestamp Manipulation

**Use Case:** Anonymize timestamps or adjust time zones

```elixir
# Normalize to Unix epoch (t=0)
{:ok, packets} = PcapFileEx.read_all("original.pcap")
normalized = PcapFileEx.TimestampShift.normalize_to_epoch(packets)
{:ok, header} = PcapFileEx.get_header("original.pcap")
PcapFileEx.write!("anonymized.pcap", header, normalized)

# Shift by specific offset (e.g., +1 hour)
one_hour_ns = 3_600_000_000_000  # 1 hour in nanoseconds
shifted = PcapFileEx.TimestampShift.shift_all(packets, one_hour_ns)
PcapFileEx.write!("time_shifted.pcap", header, shifted)

# Shift backward (e.g., -30 minutes)
minus_30_min_ns = -1_800_000_000_000
earlier = PcapFileEx.TimestampShift.shift_all(packets, minus_30_min_ns)
PcapFileEx.write!("earlier.pcap", header, earlier)

# Combined: Normalize then shift
normalized = PcapFileEx.TimestampShift.normalize_to_epoch(packets)
offset = 1_000_000_000_000  # +1000 seconds
final = PcapFileEx.TimestampShift.shift_all(normalized, offset)
PcapFileEx.write!("processed.pcap", header, final)
```

### Pattern 5: Batch Writing Small Datasets

**Use Case:** Create new PCAP from programmatically generated packets

```elixir
# Read, filter, write
{:ok, packets} = PcapFileEx.read_all("input.pcap")
filtered = Enum.filter(packets, fn p -> :tcp in p.protocols end)
{:ok, header} = PcapFileEx.get_header("input.pcap")
PcapFileEx.write!("tcp_only.pcap", header, filtered)

# Create from scratch (requires header)
header = %PcapFileEx.Header{
  version_major: 2,
  version_minor: 4,
  snaplen: 65535,
  datalink: "ethernet",
  ts_resolution: "microsecond",
  endianness: "little"
}

custom_packets = [
  %PcapFileEx.Packet{
    timestamp_precise: PcapFileEx.Timestamp.new(1000, 0),
    orig_len: 100,
    data: <<0x00, 0x01, 0x02, ...>>
  },
  # ... more packets
]

PcapFileEx.write!("custom.pcap", header, custom_packets)
```

### Pattern 6: PCAPNG Multi-Interface Writing

**Use Case:** Create PCAPNG with multiple network interfaces

```elixir
# Define interfaces
interfaces = [
  %PcapFileEx.Interface{
    id: 0,
    linktype: "ethernet",
    snaplen: 65535,
    name: "eth0",
    description: "Primary ethernet",
    timestamp_resolution: :microsecond,
    timestamp_resolution_raw: "microsecond",
    timestamp_offset_secs: 0
  },
  %PcapFileEx.Interface{
    id: 1,
    linktype: "wifi",
    snaplen: 65535,
    name: "wlan0",
    description: "Wireless interface",
    timestamp_resolution: :nanosecond,
    timestamp_resolution_raw: "nanosecond",
    timestamp_offset_secs: 0
  }
]

# Create packets with interface_id assignments
packets = [
  %PcapFileEx.Packet{
    timestamp_precise: PcapFileEx.Timestamp.new(1000, 100),
    orig_len: 100,
    data: <<...>>,
    interface_id: 0,  # eth0
    datalink: "ethernet",
    timestamp_resolution: :microsecond
  },
  %PcapFileEx.Packet{
    timestamp_precise: PcapFileEx.Timestamp.new(1001, 200),
    orig_len: 150,
    data: <<...>>,
    interface_id: 1,  # wlan0
    datalink: "wifi",
    timestamp_resolution: :nanosecond
  }
]

# Write all at once
{:ok, count} = PcapFileEx.PcapNgWriter.write_all(
  "multi_interface.pcapng",
  interfaces,
  packets
)

IO.puts("Wrote #{count} packets across #{length(interfaces)} interfaces")
```

**Manual PCAPNG writer (for streaming):**
```elixir
{:ok, writer} = PcapFileEx.PcapNgWriter.open("output.pcapng")

# Register interfaces
{:ok, 0} = PcapFileEx.PcapNgWriter.write_interface(writer, eth0_interface)
{:ok, 1} = PcapFileEx.PcapNgWriter.write_interface(writer, wlan0_interface)

# Write packets one by one
:ok = PcapFileEx.PcapNgWriter.write_packet(writer, packet1)
:ok = PcapFileEx.PcapNgWriter.write_packet(writer, packet2)

:ok = PcapFileEx.PcapNgWriter.close(writer)
```

### Pattern 7: Combining Read + Filter + Write

**Use Case:** Process packets from multiple sources

```elixir
# Merge filtered results from multiple files
output_file = "combined_http.pcap"
{:ok, header} = PcapFileEx.get_header("capture1.pcap")
{:ok, writer} = PcapFileEx.PcapWriter.open(output_file, header)

try do
  ["capture1.pcap", "capture2.pcap", "capture3.pcap"]
  |> Enum.each(fn file ->
    PcapFileEx.stream!(file)
    |> Stream.filter(fn p -> :http in p.protocols end)
    |> Enum.each(fn packet ->
      :ok = PcapFileEx.PcapWriter.write_packet(writer, packet)
    end)
  end)
after
  PcapFileEx.PcapWriter.close(writer)
end
```

**Simpler (but loads all into memory):**
```elixir
all_http_packets =
  ["capture1.pcap", "capture2.pcap", "capture3.pcap"]
  |> Enum.flat_map(fn file ->
    {:ok, packets} = PcapFileEx.read_all(file)
    Enum.filter(packets, fn p -> :http in p.protocols end)
  end)

{:ok, header} = PcapFileEx.get_header("capture1.pcap")
PcapFileEx.write!("combined_http.pcap", header, all_http_packets)
```

### Pattern 8: Error Recovery

**Use Case:** Handle corrupted packets gracefully

```elixir
# Skip corrupted packets during export
{:ok, count} = PcapFileEx.export_filtered(
  "possibly_corrupt.pcap",
  "cleaned.pcap",
  fn _packet -> true end,  # Accept all valid packets
  on_error: :skip          # Skip corrupted ones
)

IO.puts("Exported #{count} valid packets")

# Halt on first error (default)
case PcapFileEx.export_filtered(src, dest, filter_fn) do
  {:ok, count} ->
    IO.puts("Success: #{count} packets")

  {:error, reason} ->
    IO.puts("Failed: #{reason}")
    # Clean up partial file
    File.rm(dest)
end
```

## Common Mistakes

### ❌ Mistake 1: Wrong Format for Conversion

```elixir
# DON'T: Use format-specific writer for conversion
{:ok, packets} = PcapFileEx.read_all("input.pcap")
# Then create interfaces, assign IDs, etc. (complex!)
PcapFileEx.PcapNgWriter.write_all(...)

# DO: Use copy/3 (handles everything)
PcapFileEx.copy("input.pcap", "output.pcapng", format: :pcapng)
```

### ❌ Mistake 2: Loading Huge Files

```elixir
# DON'T: Load 50GB file into memory
{:ok, all} = PcapFileEx.read_all("huge_50gb.pcap")
filtered = Enum.filter(all, filter_fn)
PcapFileEx.write!("filtered.pcap", header, filtered)

# DO: Use streaming export
PcapFileEx.export_filtered!("huge_50gb.pcap", "filtered.pcap", filter_fn)
```

### ❌ Mistake 3: Forgetting interface_id for PCAPNG

```elixir
# DON'T: Write PCAP packets to PCAPNG without interface_id
{:ok, packets} = PcapFileEx.read_all("input.pcap")
# packets have interface_id == nil!
PcapFileEx.PcapNgWriter.write_all("out.pcapng", interfaces, packets)  # FAILS!

# DO: Use high-level API
PcapFileEx.copy("input.pcap", "out.pcapng", format: :pcapng)

# OR: Manually assign interface_id
packets_with_id = Enum.map(packets, &%{&1 | interface_id: 0})
PcapFileEx.PcapNgWriter.write_all("out.pcapng", interfaces, packets_with_id)
```

### ❌ Mistake 4: Not Closing Writers

```elixir
# DON'T: Forget to close (resource leak!)
{:ok, writer} = PcapFileEx.PcapWriter.open("output.pcap", header)
PcapFileEx.PcapWriter.write_packet(writer, packet)
# Never closed!

# DO: Use try/after
{:ok, writer} = PcapFileEx.PcapWriter.open("output.pcap", header)
try do
  PcapFileEx.PcapWriter.write_packet(writer, packet)
after
  PcapFileEx.PcapWriter.close(writer)
end

# BETTER: Use high-level API (handles cleanup)
PcapFileEx.write!("output.pcap", header, [packet])
```

### ❌ Mistake 5: Incorrect Header Creation

```elixir
# DON'T: Create header without required fields
header = %PcapFileEx.Header{}  # Missing required fields!
PcapFileEx.write!("output.pcap", header, packets)

# DO: Copy from existing file
{:ok, header} = PcapFileEx.get_header("input.pcap")
PcapFileEx.write!("output.pcap", header, packets)

# OR: Create complete header
header = %PcapFileEx.Header{
  version_major: 2,
  version_minor: 4,
  snaplen: 65535,
  datalink: "ethernet",
  ts_resolution: "microsecond",
  endianness: "little"
}
```

## API Reference Summary

### High-Level API (Recommended)

**write/3, write!/3** - Create new PCAP file from packets
```elixir
PcapFileEx.write(path, header, packets)
PcapFileEx.write!(path, header, packets)
```

**copy/3, copy!/3** - Copy with optional format conversion
```elixir
PcapFileEx.copy(src, dest, format: :pcapng)
PcapFileEx.copy!(src, dest)
```

**export_filtered/4, export_filtered!/4** - Filter and export
```elixir
PcapFileEx.export_filtered(src, dest, filter_fn, on_error: :skip)
PcapFileEx.export_filtered!(src, dest, filter_fn)
```

### Low-Level API (Manual Control)

**PcapWriter** - PCAP format writing
```elixir
{:ok, writer} = PcapFileEx.PcapWriter.open(path, header, endianness: "little")
:ok = PcapFileEx.PcapWriter.write_packet(writer, packet)
{:ok, count} = PcapFileEx.PcapWriter.write_all(path, header, packets)
:ok = PcapFileEx.PcapWriter.close(writer)
{:error, reason} = PcapFileEx.PcapWriter.append(path)  # Not supported
```

**PcapNgWriter** - PCAPNG format writing
```elixir
{:ok, writer} = PcapFileEx.PcapNgWriter.open(path, endianness: "little")
{:ok, interface_id} = PcapFileEx.PcapNgWriter.write_interface(writer, interface)
:ok = PcapFileEx.PcapNgWriter.write_packet(writer, packet)
{:ok, count} = PcapFileEx.PcapNgWriter.write_all(path, interfaces, packets, endianness: "little")
:ok = PcapFileEx.PcapNgWriter.close(writer)
{:error, reason} = PcapFileEx.PcapNgWriter.append(path)  # Not implemented in v0.4.0
```

### Utilities

**TimestampShift** - Timestamp manipulation
```elixir
normalized = PcapFileEx.TimestampShift.normalize_to_epoch(packets)
shifted = PcapFileEx.TimestampShift.shift_all(packets, offset_ns)
```

## Performance Guidelines

### Memory Usage

| Operation | Memory | When to Use |
|-----------|--------|-------------|
| `write!/3` | O(N packets) | < 1000 packets |
| `export_filtered/4` | O(1) | Any size, filtering needed |
| `copy/3` | O(1) | Any size, format conversion |
| Manual streaming | O(1) | Need progress updates |

### Speed Comparison

For 10GB file with 10M packets:

| Method | Time | Memory |
|--------|------|--------|
| read_all + filter + write | ~180s | ~8GB |
| export_filtered (streaming) | ~120s | ~10MB |
| copy (no filter) | ~45s | ~10MB |

**Recommendation:** Use `export_filtered/4` for filtering large files, `copy/3` for format conversion.

## Append Mode Limitations (v0.4.0)

### PCAP Append
**Status:** Not supported by upstream `pcap-file` crate

```elixir
{:error, reason} = PcapFileEx.PcapWriter.append("existing.pcap")
# Returns clear error message
```

**Workaround:**
```elixir
# Read existing + new packets, write all
{:ok, existing} = PcapFileEx.read_all("existing.pcap")
all_packets = existing ++ new_packets
{:ok, header} = PcapFileEx.get_header("existing.pcap")
PcapFileEx.write!("existing.pcap", header, all_packets)
```

### PCAPNG Append
**Status:** Not implemented in MVP (v0.4.0)

```elixir
{:error, "Append mode not yet implemented"} =
  PcapFileEx.PcapNgWriter.append("existing.pcapng")
```

**Planned for future release.**

## When to Use Each Module

### PcapFileEx (Main API)
✅ **Use this for 90% of writing tasks**
- Auto-detects format from extension
- Handles resource cleanup
- Simplest API
- `write/3`, `copy/3`, `export_filtered/4`

### PcapFileEx.PcapWriter
✅ **Use when:**
- Need streaming write with progress updates
- Writing very large files (>10GB)
- Need manual control over write operations
- PCAP format only

### PcapFileEx.PcapNgWriter
✅ **Use when:**
- Need multiple interface support
- Creating PCAPNG from scratch
- Need nanosecond timestamp precision
- Need interface-specific metadata

### PcapFileEx.TimestampShift
✅ **Use when:**
- Anonymizing timestamps
- Adjusting time zones
- Normalizing captures to epoch
- Testing time-based logic

## Related Documentation

- [Performance Guide](performance.md) - Optimization strategies
- [Filtering Guide](filtering.md) - Filter patterns and PreFilter
- [Merging Guide](merging.md) - Multi-file chronological merge
- [Format Guide](formats.md) - PCAP vs PCAPNG differences
- [Examples](examples.md) - Complete working examples
