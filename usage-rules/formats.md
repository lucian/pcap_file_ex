# PCAP vs PCAPNG Format Guide

Understanding the differences between PCAP and PCAPNG formats and when to use format-specific APIs.

## Format Overview

| Feature | PCAP | PCAPNG |
|---------|------|---------|
| **File Extension** | .pcap | .pcapng |
| **Timestamp Precision** | Microsecond or Nanosecond | Microsecond or Nanosecond |
| **Multiple Interfaces** | No (single datalink) | Yes (multiple interfaces) |
| **Interface Metadata** | No | Yes (name, description, etc.) |
| **Comments** | No | Yes |
| **Standard** | Older, widely supported | Newer, more features |
| **Default on Linux** | dumpcap uses PCAPNG | Nanosecond precision |
| **Default on macOS** | PCAP | Microsecond precision |

## Auto-Detection (Always Use This!)

### Why Auto-Detection Matters

**File extensions lie!** A `.pcap` file might actually be PCAPNG format.

```elixir
# ✅ ALWAYS: Use auto-detection
{:ok, reader} = PcapFileEx.open("capture.pcap")  # Works for both formats
{:ok, packets} = PcapFileEx.read_all("capture.pcap")
PcapFileEx.stream!("capture.pcap") |> Enum.to_list()

# ❌ AVOID: Assume format from extension
{:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")  # Fails if PCAPNG!
```

### Detecting File Format

```elixir
# Validate and detect format
case PcapFileEx.Validator.validate_file("capture.pcap") do
  {:ok, :pcap} -> IO.puts("PCAP format")
  {:ok, :pcapng} -> IO.puts("PCAPNG format")
  {:error, reason} -> IO.puts("Invalid: #{reason}")
end
```

## PCAP Format

### Characteristics

- Single network interface per file
- Single datalink type (e.g., Ethernet)
- File header + packet records
- Timestamp precision: microsecond or nanosecond

### PCAP-Specific API

```elixir
# Only use if you're CERTAIN file is PCAP
{:ok, reader} = PcapFileEx.Pcap.open("definitely.pcap")
{:ok, header} = PcapFileEx.Pcap.get_header(reader)
{:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
PcapFileEx.Pcap.close(reader)
```

### PCAP Header Structure

```elixir
%PcapFileEx.Header{
  version_major: 2,
  version_minor: 4,
  datalink: :ethernet,  # or :linux_sll, :raw, etc.
  ts_resolution: :microsecond,  # or :nanosecond
  snaplen: 65535,
  endianness: :little  # or :big
}
```

### Magic Numbers

PCAP files start with one of these magic numbers:

- `0xA1B2C3D4` - Microsecond, native byte order
- `0xD4C3B2A1` - Microsecond, swapped byte order
- `0xA1B23C4D` - Nanosecond, native byte order
- `0x4D3CB2A1` - Nanosecond, swapped byte order

## PCAPNG Format

### Characteristics

- Multiple network interfaces per file
- Per-interface metadata (name, description, OS, etc.)
- Supports comments and custom options
- Timestamp precision per interface

### PCAPNG-Specific API

```elixir
# Only use if you're CERTAIN file is PCAPNG
{:ok, reader} = PcapFileEx.PcapNg.open("definitely.pcapng")
{:ok, interfaces} = PcapFileEx.PcapNg.interfaces(reader)
{:ok, packet} = PcapFileEx.PcapNg.next_packet(reader)
PcapFileEx.PcapNg.close(reader)
```

### PCAPNG Interface Structure

```elixir
%PcapFileEx.Interface{
  id: 0,
  link_type: :ethernet,
  snap_len: 65535,
  name: "eth0",
  description: "Ethernet adapter",
  timestamp_resolution: :nanosecond,
  os: "Linux 5.15.0"
}
```

### PCAPNG-Specific Packet Fields

```elixir
# These fields only exist for PCAPNG packets
packet.interface_id         # Integer (which interface)
packet.interface            # %Interface{} struct
packet.timestamp_resolution # :microsecond or :nanosecond
```

## Timestamp Precision

### Understanding Precision

Both formats support microsecond and nanosecond precision:

- **Microsecond**: 1/1,000,000 second (older, more compatible)
- **Nanosecond**: 1/1,000,000,000 second (newer, more precise)

### Platform Differences

```elixir
# Linux dumpcap (default):
# - Format: PCAPNG
# - Precision: Nanosecond

# macOS tcpdump (default):
# - Format: PCAP
# - Precision: Microsecond
```

### Accessing Precision

```elixir
# File-level precision (PCAP only)
{:ok, reader} = PcapFileEx.open("capture.pcap")
{:ok, header} = PcapFileEx.Pcap.get_header(reader)
header.ts_resolution  # :microsecond or :nanosecond

# Packet-level precision (PCAPNG only)
{:ok, packet} = PcapFileEx.PcapNg.next_packet(reader)
packet.timestamp_resolution  # :microsecond or :nanosecond

# Timestamp is always DateTime (precision abstracted)
packet.timestamp  # ~U[2025-01-01 12:00:00.123456Z]
```

## Cross-Platform Compatibility

### Handling Files from Different Platforms

```elixir
# ✅ WORKS: Auto-detection handles both formats
linux_packets = PcapFileEx.stream!("linux_capture.pcapng") |> Enum.to_list()
macos_packets = PcapFileEx.stream!("macos_capture.pcap") |> Enum.to_list()

# Timestamps are normalized to DateTime
linux_packets |> Enum.each(fn p -> IO.inspect(p.timestamp) end)
macos_packets |> Enum.each(fn p -> IO.inspect(p.timestamp) end)
```

### No Timestamp Conversion Needed

```elixir
# ✅ Timestamps are automatically normalized
packet.timestamp  # Always DateTime, regardless of file precision

# No need to convert or adjust for precision
# PcapFileEx handles this internally
```

## When to Use Format-Specific APIs

### Use Auto-Detection (PcapFileEx) When:

✅ **99% of use cases**
- Reading unknown files
- Cross-platform compatibility
- User-provided files
- Mixed file sources

### Use PCAP API (PcapFileEx.Pcap) When:

⚠️ **Rare cases only**
- You created the file yourself with PCAP format
- Performance-critical code (tiny optimization)
- Interoperating with PCAP-only tools

### Use PCAPNG API (PcapFileEx.PcapNg) When:

⚠️ **Rare cases only**
- You need interface metadata
- You created the file with PCAPNG format
- Working exclusively with modern capture tools

## Interface Metadata (PCAPNG Only)

### Accessing Interfaces

```elixir
# PCAPNG files have interface metadata
{:ok, reader} = PcapFileEx.open("capture.pcapng")  # Auto-detect!
{:ok, interfaces} = PcapFileEx.PcapNg.interfaces(reader)

Enum.each(interfaces, fn iface ->
  IO.puts("Interface #{iface.id}: #{iface.name}")
  IO.puts("  Description: #{iface.description}")
  IO.puts("  OS: #{iface.os}")
  IO.puts("  Precision: #{iface.timestamp_resolution}")
end)
```

### Packets Reference Interfaces

```elixir
# Each packet has interface_id and interface
{:ok, packet} = PcapFileEx.PcapNg.next_packet(reader)
packet.interface_id  # 0, 1, 2, etc.
packet.interface     # %Interface{} struct

# PCAP packets don't have these fields
{:ok, pcap_packet} = PcapFileEx.Pcap.next_packet(pcap_reader)
pcap_packet.interface_id  # nil
pcap_packet.interface     # nil
```

### Filtering by Interface

```elixir
# Only packets from specific interface (PCAPNG only)
PcapFileEx.stream!("capture.pcapng")
|> Stream.filter(fn packet ->
  packet.interface_id == 0
end)
|> Enum.to_list()

# Guard against PCAP files
PcapFileEx.stream!("unknown.pcap")
|> Stream.filter(fn packet ->
  packet.interface_id == 0 or is_nil(packet.interface_id)
end)
|> Enum.to_list()
```

## Common Format Mistakes

### ❌ Mistake 1: Assuming Format from Extension

```elixir
# DON'T: Trust file extension
{:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
# Fails with "wrong magic number" if file is actually PCAPNG!

# DO: Use auto-detection
{:ok, reader} = PcapFileEx.open("capture.pcap")
```

### ❌ Mistake 2: Accessing PCAPNG Fields on PCAP Files

```elixir
# DON'T: Assume PCAPNG fields exist
IO.puts(packet.interface.name)  # Crashes if PCAP file! (nil.name)

# DO: Guard against nil
if packet.interface do
  IO.puts("Interface: #{packet.interface.name}")
end
```

### ❌ Mistake 3: Using Wrong Close Function

```elixir
# DON'T: Mismatch open/close
{:ok, reader} = PcapFileEx.Pcap.open("file.pcap")
PcapFileEx.PcapNg.close(reader)  # Wrong!

# DO: Match open/close or use auto-detection
{:ok, reader} = PcapFileEx.open("file.pcap")
# Then use appropriate close based on detection
# Or use streaming (auto-closes)
```

### ❌ Mistake 4: Manual Timestamp Conversion

```elixir
# DON'T: Try to convert timestamps based on precision
if header.ts_resolution == :nanosecond do
  adjusted_timestamp = ...  # Unnecessary!
end

# DO: Use timestamp directly (already normalized)
IO.inspect(packet.timestamp)  # Always DateTime
```

## Format Detection in Practice

### Pattern: Handle Both Formats

```elixir
defmodule CaptureAnalyzer do
  def analyze(file_path) do
    case PcapFileEx.Validator.validate_file(file_path) do
      {:ok, :pcap} ->
        IO.puts("Processing PCAP file...")
        analyze_with_auto_detection(file_path)

      {:ok, :pcapng} ->
        IO.puts("Processing PCAPNG file...")
        analyze_with_interfaces(file_path)

      {:error, reason} ->
        {:error, "Invalid file: #{reason}"}
    end
  end

  defp analyze_with_auto_detection(file) do
    # Works for both formats
    PcapFileEx.stream!(file) |> Enum.count()
  end

  defp analyze_with_interfaces(file) do
    {:ok, reader} = PcapFileEx.open(file)

    # Try to get interfaces (PCAPNG only)
    interfaces = case PcapFileEx.PcapNg.interfaces(reader) do
      {:ok, ifaces} -> ifaces
      _ -> []
    end

    count = PcapFileEx.Stream.from_reader!(reader) |> Enum.count()
    PcapFileEx.Pcap.close(reader)  # Works for both

    {count, length(interfaces)}
  end
end
```

## Summary: Format Best Practices

1. ✅ Always use auto-detection (`PcapFileEx.open/1`)
2. ✅ Use `Validator.validate_file/1` to detect format
3. ✅ Guard against nil when accessing PCAPNG-specific fields
4. ✅ Use `packet.timestamp` directly (already normalized)
5. ✅ Handle both formats in your code
6. ❌ Don't trust file extensions
7. ❌ Don't assume format without detection
8. ❌ Don't manually convert timestamps
9. ❌ Don't access interface fields without nil checks
10. ❌ Don't use format-specific APIs unless necessary
