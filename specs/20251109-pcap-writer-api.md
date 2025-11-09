# PCAP Writer/Trimming API - Feature Specification

**Version:** 1.4.1
**Date:** 2025-11-10
**Author:** Claude Code
**Status:** Implemented (PCAP→PCAPNG Conversion Bug Fixes Applied)

## Table of Contents

1. [Overview](#overview)
2. [Use Cases](#use-cases)
3. [Requirements](#requirements)
4. [Architecture Design](#architecture-design)
5. [API Specification](#api-specification)
6. [Implementation Plan](#implementation-plan)
7. [Testing Strategy](#testing-strategy)
8. [Documentation Plan](#documentation-plan)
9. [Performance Considerations](#performance-considerations)
10. [Security Considerations](#security-considerations)
11. [Open Questions](#open-questions)

---

## Overview

This feature adds comprehensive PCAP/PCAPNG file writing capabilities to PcapFileEx, enabling users to:
- Export filtered packet subsets to new files
- Trim captures by time range, protocol, or custom criteria
- Create regression test fixtures programmatically
- Convert between PCAP and PCAPNG formats
- Append packets to existing captures
- Shift timestamps for anonymization or testing

The writer API mirrors the existing reader architecture, providing both low-level streaming writes and high-level convenience functions.

---

## Use Cases

### UC1: Filter and Export
**User Story:** As a network engineer, I want to extract HTTP traffic from a large capture and share it with colleagues without exposing other protocols.

```elixir
# Read, filter, write in one call
PcapFileEx.export_filtered(
  "full_capture.pcapng",
  "http_only.pcapng",
  fn packet -> :http in packet.protocols end
)
```

### UC2: Regression Testing
**User Story:** As a library developer, I want to programmatically generate minimal test fixtures with known packet sequences.

```elixir
# Create test fixture with synthetic packets
header = %PcapFileEx.Header{
  version_major: 2, version_minor: 4,
  snaplen: 65535, datalink: "ethernet"
}

packets = [
  PcapFileEx.Packet.new(timestamp, 0, 100, http_request_bytes),
  PcapFileEx.Packet.new(timestamp + 1, 0, 200, http_response_bytes)
]

PcapFileEx.write("test/fixtures/http_exchange.pcap", header, packets)
```

### UC3: Time Range Trimming
**User Story:** As a security analyst, I want to extract packets from a specific time window for incident investigation.

```elixir
# Extract 5-minute window
start_time = ~U[2025-11-09 14:30:00Z]
end_time = ~U[2025-11-09 14:35:00Z]

PcapFileEx.export_filtered(
  "full_day_capture.pcapng",
  "incident_window.pcapng",
  fn packet ->
    DateTime.compare(packet.timestamp, start_time) != :lt and
    DateTime.compare(packet.timestamp, end_time) != :gt
  end
)
```

### UC4: Format Conversion
**User Story:** As a network administrator, I want to convert legacy PCAP files to modern PCAPNG format for better tooling support.

```elixir
# Convert PCAP to PCAPNG
PcapFileEx.copy("legacy.pcap", "modern.pcapng", format: :pcapng)
```

### UC5: Timestamp Anonymization
**User Story:** As a researcher, I want to shift all packet timestamps to remove temporal correlation before publishing datasets.

```elixir
# Shift all timestamps to start at epoch
{:ok, packets} = PcapFileEx.read_all("original.pcap")
normalized = PcapFileEx.TimestampShift.normalize_to_epoch(packets)
PcapFileEx.write("anonymized.pcap", header, normalized)
```

### UC6: Streaming Large Filtered Exports
**User Story:** As a DevOps engineer, I want to extract TCP traffic from a 50GB capture without loading the entire file into memory.

```elixir
# Memory-efficient streaming export
{:ok, reader} = PcapFileEx.open("huge_50gb.pcapng")
{:ok, writer} = PcapFileEx.PcapNgWriter.open("tcp_only.pcapng", header)

try do
  PcapFileEx.stream!(reader)
  |> Stream.filter(fn packet -> :tcp in packet.protocols end)
  |> Enum.each(fn packet ->
    :ok = PcapFileEx.PcapNgWriter.write_packet(writer, packet)
  end)
after
  PcapFileEx.PcapNg.close(reader)
  PcapFileEx.PcapNgWriter.close(writer)
end
```

### UC7: Append to Existing Capture
**User Story:** As a monitoring system, I want to append newly captured packets to an existing PCAPNG file.

```elixir
# Append mode - validates header compatibility
{:ok, writer} = PcapFileEx.PcapNgWriter.append("continuous_capture.pcapng")
:ok = PcapFileEx.PcapNgWriter.write_packet(writer, new_packet)
:ok = PcapFileEx.PcapNgWriter.close(writer)
```

---

## Requirements

### Functional Requirements

**FR1: Format Support**
- Support writing both PCAP and PCAPNG formats
- Auto-detect input format when copying
- Allow explicit format selection for conversion

**FR2: Write Modes**
- Create new files (truncate if exists)
- Append to existing files (with validation)
- Validate header compatibility when appending

**FR3: Streaming API**
- Low-level: open/write_packet/close for fine-grained control
- High-level: write_all for batch operations
- Stream integration: pipe streams directly to files

**FR4: Convenience Functions**
- `export_filtered/3` - Read, filter, write in one call
- `copy/2` - Copy entire file (with format conversion)
- Timestamp shift utilities

**FR5: Packet Fidelity**
- Write packets exactly as-is (preserve timestamps, data, metadata)
- Support full nanosecond timestamp precision
- Validate packet constraints (snaplen, orig_len)

**FR6: PCAPNG Complexity**
- Automatic section header writing
- Interface block management
- Interface ID validation
- Support multi-interface captures

### Non-Functional Requirements

**NFR1: Performance**
- Buffered writes (64KB buffer minimum)
- Streaming writes for large datasets (constant memory)
- Minimal allocations in hot path

**NFR2: Resource Safety**
- Explicit close flushes and releases file handles
- Automatic cleanup on GC (Rustler Resource pattern)
- No resource leaks in error cases

**NFR3: Error Handling**
- Consistent `{:ok, result}` | `{:error, reason}` pattern
- Descriptive error messages
- Validation at API boundaries

**NFR4: Backward Compatibility**
- No breaking changes to existing reader API
- Additive changes only
- Follows semver (minor version bump)

**NFR5: Testing**
- Example-based tests for all API functions
- Property-based tests (round-trip, count preservation)
- Comprehensive error case coverage

---

## Architecture Design

### Overview

The writer architecture mirrors the existing reader design:
- **Rust NIF Layer**: High-performance file I/O using upstream `pcap-file` crate
- **Elixir API Layer**: Type-safe, idiomatic API with proper resource management
- **High-Level Helpers**: Convenience functions for common workflows

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Elixir Layer (lib/)                       │
├─────────────────────────────────────────────────────────────┤
│  PcapFileEx (main API)                                       │
│  ├─ write/3, write!/3                                        │
│  ├─ export_filtered/3                                        │
│  └─ copy/2, copy/3                                           │
├─────────────────────────────────────────────────────────────┤
│  PcapFileEx.PcapWriter          PcapFileEx.PcapNgWriter     │
│  ├─ open/2, open/3              ├─ open/2, open/3           │
│  ├─ append/1                    ├─ append/1                 │
│  ├─ write_packet/2              ├─ write_interface/2        │
│  ├─ write_all/3                 ├─ write_packet/2           │
│  └─ close/1                     ├─ write_all/3              │
│                                 └─ close/1                  │
├─────────────────────────────────────────────────────────────┤
│  PcapFileEx.Stream                                           │
│  └─ write/3 (pipe stream to file)                           │
├─────────────────────────────────────────────────────────────┤
│  PcapFileEx.TimestampShift (utility)                         │
│  ├─ shift_all/2                                              │
│  └─ normalize_to_epoch/1                                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Rust NIF Layer (native/pcap_file_ex/src/)       │
├─────────────────────────────────────────────────────────────┤
│  pcap_writer.rs                 pcapng_writer.rs            │
│  ├─ PcapWriterResource          ├─ PcapNgWriterResource     │
│  ├─ pcap_writer_open/2          ├─ pcapng_writer_open/2     │
│  ├─ pcap_writer_append/1        ├─ pcapng_writer_append/1   │
│  ├─ pcap_writer_write/2         ├─ pcapng_writer_write_iface/2│
│  └─ pcap_writer_close/1         ├─ pcapng_writer_write/2    │
│                                 └─ pcapng_writer_close/1    │
├─────────────────────────────────────────────────────────────┤
│  types.rs (reverse conversions)                              │
│  ├─ map_to_pcap_header/1                                     │
│  ├─ map_to_pcap_packet/1                                     │
│  └─ map_to_interface_block/1                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│        Upstream pcap-file Crate (pcap-file/src/)             │
│  ├─ PcapWriter<W: Write>                                     │
│  └─ PcapNgWriter<W: Write>                                   │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

**Write Path (PCAP):**
1. User calls `PcapFileEx.write/3` with path, header, packets
2. Elixir validates inputs, converts structs to maps
3. NIF `pcap_writer_open/2` creates `PcapWriterResource`
4. Rust creates `PcapWriter<BufWriter<File>>`
5. For each packet:
   - Elixir converts `Packet` struct to map
   - NIF converts map to `PcapPacket`
   - Rust writes packet to buffered file
6. NIF `pcap_writer_close/1` flushes buffer, closes file
7. Elixir returns `{:ok, count}` or `{:error, reason}`

**Append Path:**
1. User calls `PcapFileEx.PcapWriter.append/1`
2. NIF opens existing file, parses header
3. Validates header compatibility (version, datalink, snaplen)
4. Seeks to end of file, positions writer
5. Writing proceeds as normal (steps 5-7 above)

---

## API Specification

### Rust NIF Layer

#### `pcap_writer.rs`

```rust
use rustler::{Env, ResourceArc, Error, NifMap};
use pcap_file::pcap::{PcapWriter, PcapHeader};
use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::sync::Mutex;

/// Rustler resource for PCAP writer
pub struct PcapWriterResource {
    writer: Mutex<PcapWriter<BufWriter<File>>>,
}

/// Open a new PCAP file for writing
#[rustler::nif]
pub fn pcap_writer_open(
    path: String,
    header_map: HeaderMap
) -> Result<ResourceArc<PcapWriterResource>, Error> {
    let file = File::create(&path)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create file: {}", e))))?;

    let buf_writer = BufWriter::with_capacity(64 * 1024, file);
    let header = map_to_pcap_header(&header_map)?;
    let writer = PcapWriter::with_header(buf_writer, header)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create writer: {}", e))))?;

    Ok(ResourceArc::new(PcapWriterResource {
        writer: Mutex::new(writer),
    }))
}

/// Open existing PCAP file for appending
#[rustler::nif]
pub fn pcap_writer_append(
    path: String
) -> Result<ResourceArc<PcapWriterResource>, Error> {
    // 1. Open and read existing header
    // 2. Validate file is valid PCAP
    // 3. Open for append
    // 4. Create writer with existing header
    // Implementation details...
}

/// Write a packet to the PCAP file
#[rustler::nif]
pub fn pcap_writer_write_packet(
    resource: ResourceArc<PcapWriterResource>,
    packet_map: PacketMap
) -> Result<(), Error> {
    let mut writer = resource.writer.lock().unwrap();
    let packet = map_to_pcap_packet(&packet_map)?;

    writer.write_packet(&packet)
        .map_err(|e| Error::Term(Box::new(format!("Failed to write packet: {}", e))))?;

    Ok(())
}

/// Close and flush the PCAP writer
#[rustler::nif]
pub fn pcap_writer_close(
    resource: ResourceArc<PcapWriterResource>
) -> Result<(), Error> {
    let mut writer = resource.writer.lock().unwrap();

    writer.flush()
        .map_err(|e| Error::Term(Box::new(format!("Failed to flush: {}", e))))?;

    Ok(())
}
```

#### `pcapng_writer.rs`

```rust
use rustler::{Env, ResourceArc, Error, NifMap};
use pcap_file::pcapng::{PcapNgWriter, Block, InterfaceDescriptionBlock};
use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::sync::Mutex;

/// Rustler resource for PCAPNG writer
pub struct PcapNgWriterResource {
    writer: Mutex<PcapNgWriter<BufWriter<File>>>,
}

/// Open a new PCAPNG file for writing
#[rustler::nif]
pub fn pcapng_writer_open(
    path: String,
    endianness: String  // "big" | "little"
) -> Result<ResourceArc<PcapNgWriterResource>, Error> {
    let file = File::create(&path)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create file: {}", e))))?;

    let buf_writer = BufWriter::with_capacity(64 * 1024, file);
    let endian = parse_endianness(&endianness)?;

    let writer = PcapNgWriter::with_endianness(buf_writer, endian)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create writer: {}", e))))?;

    Ok(ResourceArc::new(PcapNgWriterResource {
        writer: Mutex::new(writer),
    }))
}

/// Write interface descriptor block
#[rustler::nif]
pub fn pcapng_writer_write_interface(
    resource: ResourceArc<PcapNgWriterResource>,
    interface_map: InterfaceMap
) -> Result<u32, Error> {
    let mut writer = resource.writer.lock().unwrap();
    let interface_block = map_to_interface_block(&interface_map)?;

    writer.write_block(&Block::InterfaceDescription(interface_block))
        .map_err(|e| Error::Term(Box::new(format!("Failed to write interface: {}", e))))?;

    // Return assigned interface ID
    Ok(writer.interfaces().len() as u32 - 1)
}

/// Write a packet to the PCAPNG file
#[rustler::nif]
pub fn pcapng_writer_write_packet(
    resource: ResourceArc<PcapNgWriterResource>,
    packet_map: PacketMap
) -> Result<(), Error> {
    let mut writer = resource.writer.lock().unwrap();
    let block = map_to_enhanced_packet_block(&packet_map)?;

    writer.write_block(&Block::EnhancedPacket(block))
        .map_err(|e| Error::Term(Box::new(format!("Failed to write packet: {}", e))))?;

    Ok(())
}

/// Close and flush the PCAPNG writer
#[rustler::nif]
pub fn pcapng_writer_close(
    resource: ResourceArc<PcapNgWriterResource>
) -> Result<(), Error> {
    // Flush handled by Drop implementation
    Ok(())
}

/// Open existing PCAPNG file for appending
///
/// Handles files with trailing blocks (statistics, name resolution, etc.) by:
/// 1. Scanning to find the last Enhanced Packet block
/// 2. Truncating the file at that position (removes trailing metadata)
/// 3. Resuming writes from the last packet position
///
/// This ensures appended packets maintain chronological order and that
/// readers don't encounter unexpected block ordering.
#[rustler::nif]
pub fn pcapng_writer_append(
    path: String
) -> Result<(ResourceArc<PcapNgWriterResource>, SectionMap), Error> {
    // 1. Open and parse existing file
    let file_read = File::open(&path)
        .map_err(|e| Error::Term(Box::new(format!("Failed to open file: {}", e))))?;

    let mut reader = PcapNgReader::new(file_read)
        .map_err(|e| Error::Term(Box::new(format!("Invalid PCAPNG file: {}", e))))?;

    // 2. Scan to find last Enhanced Packet block and collect metadata
    let mut last_packet_pos: u64 = 0;
    let mut section = None;
    let mut interfaces = Vec::new();

    while let Some(block) = reader.next_block()
        .map_err(|e| Error::Term(Box::new(format!("Read error: {}", e))))? {

        match block {
            Block::SectionHeader(s) => section = Some(s),
            Block::InterfaceDescription(i) => interfaces.push(i),
            Block::EnhancedPacket(_) => {
                // Update position to after this block
                last_packet_pos = reader.position();
            }
            // Ignore other blocks (statistics, name resolution, custom, etc.)
            _ => {}
        }
    }

    // Validate we found required metadata
    let section = section
        .ok_or_else(|| Error::Term(Box::new("No section header found in file".to_string())))?;

    if last_packet_pos == 0 {
        return Err(Error::Term(Box::new("No packets found in file - cannot append".to_string())));
    }

    // 3. Open file for writing, seek to last packet, truncate trailing blocks
    let mut file_write = OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|e| Error::Term(Box::new(format!("Failed to open for writing: {}", e))))?;

    file_write.seek(SeekFrom::Start(last_packet_pos))
        .map_err(|e| Error::Term(Box::new(format!("Seek failed: {}", e))))?;

    // Truncate file at current position (removes trailing blocks)
    file_write.set_len(last_packet_pos)
        .map_err(|e| Error::Term(Box::new(format!("Truncate failed: {}", e))))?;

    // 4. Create writer WITHOUT writing new section header (reuse existing)
    let buf_writer = BufWriter::with_capacity(64 * 1024, file_write);

    // NOTE: This requires upstream pcap-file crate support for append mode
    // If not available, we need to:
    // - Manually reconstruct writer state
    // - Track section and interfaces in our resource
    // - Skip section header write on initialization
    let writer = PcapNgWriter::append_to_section(buf_writer, section.clone(), interfaces)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create append writer: {}", e))))?;

    let section_map = section_to_map(&section);

    Ok((
        ResourceArc::new(PcapNgWriterResource {
            writer: Mutex::new(writer),
        }),
        section_map
    ))
}
```

#### `types.rs` (Reverse Conversions)

```rust
use pcap_file::pcap::{PcapHeader, PcapPacket};
use pcap_file::pcapng::InterfaceDescriptionBlock;
use crate::error::NifError;

/// Convert HeaderMap to PcapHeader
pub fn map_to_pcap_header(map: &HeaderMap) -> Result<PcapHeader, NifError> {
    Ok(PcapHeader {
        version_major: map.version_major,
        version_minor: map.version_minor,
        ts_correction: 0,  // Always 0 per PCAP spec
        ts_accuracy: 0,    // Always 0 per PCAP spec
        snaplen: map.snaplen,
        datalink: parse_datalink(&map.datalink)?,
        ts_resolution: parse_ts_resolution(&map.ts_resolution)?,
        endianness: parse_endianness(&map.endianness)?,
    })
}

/// Convert PacketMap to PcapPacket
pub fn map_to_pcap_packet(map: &PacketMap) -> Result<PcapPacket, NifError> {
    let timestamp = map_to_timestamp(&map.timestamp_precise)?;

    Ok(PcapPacket {
        timestamp,
        orig_len: map.orig_len,
        data: map.data.clone().into(),
    })
}

/// Convert InterfaceMap to InterfaceDescriptionBlock
pub fn map_to_interface_block(map: &InterfaceMap) -> Result<InterfaceDescriptionBlock, NifError> {
    // Implementation details...
}
```

### Elixir API Layer

#### `lib/pcap_file_ex/pcap_writer.ex`

```elixir
defmodule PcapFileEx.PcapWriter do
  @moduledoc """
  PCAP file writer for exporting packets to legacy PCAP format.

  Supports both creating new files and appending to existing captures.
  For large datasets, prefer streaming writes over batch operations.

  ## Examples

      # Create new PCAP file
      header = %PcapFileEx.Header{snaplen: 65535, datalink: "ethernet"}
      {:ok, writer} = PcapWriter.open("output.pcap", header)
      :ok = PcapWriter.write_packet(writer, packet1)
      :ok = PcapWriter.write_packet(writer, packet2)
      :ok = PcapWriter.close(writer)

      # Batch write (convenience)
      PcapWriter.write_all("output.pcap", header, packets)

      # Append to existing file
      {:ok, writer} = PcapWriter.append("existing.pcap")
      :ok = PcapWriter.write_packet(writer, new_packet)
      :ok = PcapWriter.close(writer)
  """

  alias PcapFileEx.{Header, Packet, Native}

  @type t :: %__MODULE__{
          reference: reference(),
          path: String.t(),
          header: Header.t()
        }

  @enforce_keys [:reference, :path, :header]
  defstruct [:reference, :path, :header]

  @doc """
  Open a new PCAP file for writing.

  Creates the file (truncates if exists) and writes the global header.

  ## Parameters
  - `path` - File path to create
  - `header` - PCAP global header (snaplen, datalink, timestamp resolution)

  ## Returns
  - `{:ok, writer}` - Writer resource
  - `{:error, reason}` - Failed to create file or write header

  ## Examples

      header = %PcapFileEx.Header{
        version_major: 2,
        version_minor: 4,
        snaplen: 65535,
        datalink: "ethernet",
        ts_resolution: "microsecond",
        endianness: "little"
      }

      {:ok, writer} = PcapWriter.open("capture.pcap", header)
  """
  @spec open(Path.t(), Header.t()) :: {:ok, t()} | {:error, String.t()}
  def open(path, %Header{} = header) do
    header_map = Header.to_map(header)

    case Native.pcap_writer_open(to_string(path), header_map) do
      {:ok, reference} ->
        {:ok, %__MODULE__{
          reference: reference,
          path: to_string(path),
          header: header
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Open a new PCAP file for writing (raises on error).

  See `open/2` for details.
  """
  @spec open!(Path.t(), Header.t()) :: t()
  def open!(path, header) do
    case open(path, header) do
      {:ok, writer} -> writer
      {:error, reason} -> raise "Failed to open PCAP writer: #{reason}"
    end
  end

  @doc """
  Open an existing PCAP file for appending packets.

  Validates the file is a valid PCAP, reads the header, and positions
  the writer at the end. New packets must be compatible with the
  existing header (same datalink, snaplen, timestamp resolution).

  ## Parameters
  - `path` - Existing PCAP file path

  ## Returns
  - `{:ok, writer}` - Writer positioned at end of file
  - `{:error, reason}` - File invalid or incompatible

  ## Examples

      {:ok, writer} = PcapWriter.append("continuous.pcap")
      :ok = PcapWriter.write_packet(writer, new_packet)
      :ok = PcapWriter.close(writer)
  """
  @spec append(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def append(path) do
    case Native.pcap_writer_append(to_string(path)) do
      {:ok, {reference, header_map}} ->
        header = Header.from_map(header_map)
        {:ok, %__MODULE__{
          reference: reference,
          path: to_string(path),
          header: header
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Write a single packet to the PCAP file.

  Packets are written with their original timestamps and data.
  The packet's `orig_len` must be <= writer's `snaplen`.

  ## Parameters
  - `writer` - Open writer resource
  - `packet` - Packet to write

  ## Returns
  - `:ok` - Packet written successfully
  - `{:error, reason}` - Write failed

  ## Examples

      :ok = PcapWriter.write_packet(writer, packet)
  """
  @spec write_packet(t(), Packet.t()) :: :ok | {:error, String.t()}
  def write_packet(%__MODULE__{reference: ref, header: header}, %Packet{} = packet) do
    # Validate packet constraints
    with :ok <- validate_packet(packet, header) do
      packet_map = Packet.to_map(packet)
      Native.pcap_writer_write_packet(ref, packet_map)
    end
  end

  @doc """
  Write multiple packets to a PCAP file (convenience function).

  Opens the file, writes all packets, and closes. For large datasets,
  prefer streaming writes for better memory efficiency.

  ## Parameters
  - `path` - File path to create
  - `header` - PCAP global header
  - `packets` - Enumerable of packets

  ## Returns
  - `{:ok, count}` - Number of packets written
  - `{:error, reason}` - Write failed

  ## Examples

      {:ok, 100} = PcapWriter.write_all("output.pcap", header, packets)
  """
  @spec write_all(Path.t(), Header.t(), Enumerable.t()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def write_all(path, header, packets) do
    with {:ok, writer} <- open(path, header) do
      try do
        count = Enum.reduce_while(packets, 0, fn packet, acc ->
          case write_packet(writer, packet) do
            :ok -> {:cont, acc + 1}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)

        case count do
          {:error, _} = error -> error
          count when is_integer(count) -> {:ok, count}
        end
      after
        close(writer)
      end
    end
  end

  @doc """
  Close the PCAP writer and flush buffered data.

  Always call this when done writing to ensure data is flushed to disk.

  ## Parameters
  - `writer` - Writer to close

  ## Returns
  - `:ok` - Successfully closed
  - `{:error, reason}` - Flush/close failed

  ## Examples

      :ok = PcapWriter.close(writer)
  """
  @spec close(t()) :: :ok | {:error, String.t()}
  def close(%__MODULE__{reference: ref}) do
    Native.pcap_writer_close(ref)
  end

  # Private helpers

  defp validate_packet(%Packet{orig_len: orig_len, data: data}, %Header{snaplen: snaplen}) do
    cond do
      orig_len > snaplen ->
        {:error, "Packet orig_len (#{orig_len}) exceeds snaplen (#{snaplen})"}

      byte_size(data) > snaplen ->
        {:error, "Packet data size (#{byte_size(data)}) exceeds snaplen (#{snaplen})"}

      true ->
        :ok
    end
  end
end
```

#### `lib/pcap_file_ex/pcap_ng_writer.ex`

```elixir
defmodule PcapFileEx.PcapNgWriter do
  @moduledoc """
  PCAPNG file writer for exporting packets to modern PCAPNG format.

  PCAPNG supports multiple interfaces, metadata, and extensibility.
  Writers must register interfaces before writing packets.

  ## Examples

      # Create new PCAPNG with single interface
      {:ok, writer} = PcapNgWriter.open("output.pcapng")

      interface = %PcapFileEx.Interface{
        id: 0,
        linktype: "ethernet",
        snaplen: 65535,
        name: "eth0"
      }
      {:ok, 0} = PcapNgWriter.write_interface(writer, interface)

      :ok = PcapNgWriter.write_packet(writer, packet)
      :ok = PcapNgWriter.close(writer)
  """

  alias PcapFileEx.{Interface, Packet, Native}

  @type t :: %__MODULE__{
          reference: reference(),
          path: String.t(),
          interfaces: [Interface.t()]
        }

  @enforce_keys [:reference, :path]
  defstruct [:reference, :path, interfaces: []]

  @doc """
  Open a new PCAPNG file for writing.

  Creates the file and writes the section header block. Use native
  endianness by default, or specify explicitly.

  ## Options
  - `:endianness` - "little" or "big" (default: system native)

  ## Examples

      {:ok, writer} = PcapNgWriter.open("capture.pcapng")
      {:ok, writer} = PcapNgWriter.open("capture.pcapng", endianness: "little")
  """
  @spec open(Path.t(), keyword()) :: {:ok, t()} | {:error, String.t()}
  def open(path, opts \\ []) do
    endianness = Keyword.get(opts, :endianness, "little")

    case Native.pcapng_writer_open(to_string(path), endianness) do
      {:ok, reference} ->
        {:ok, %__MODULE__{
          reference: reference,
          path: to_string(path)
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Open a new PCAPNG file for writing (raises on error).
  """
  @spec open!(Path.t(), keyword()) :: t()
  def open!(path, opts \\ []) do
    case open(path, opts) do
      {:ok, writer} -> writer
      {:error, reason} -> raise "Failed to open PCAPNG writer: #{reason}"
    end
  end

  @doc """
  Write an interface descriptor block.

  Must be called before writing packets. Returns the assigned interface ID.

  Interface tracking happens in the Rust NIF layer for thread safety and
  validation. The Elixir writer struct does not need to be updated.

  ## Returns
  - `{:ok, interface_id}` - Interface registered
  - `{:error, reason}` - Registration failed

  ## Examples

      interface = %Interface{linktype: "ethernet", snaplen: 65535, name: "eth0"}
      {:ok, 0} = PcapNgWriter.write_interface(writer, interface)
  """
  @spec write_interface(t(), Interface.t()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def write_interface(%__MODULE__{reference: ref}, %Interface{} = interface) do
    interface_map = Interface.to_map(interface)

    # Interface validation and tracking happens in Rust NIF
    Native.pcapng_writer_write_interface(ref, interface_map)
  end

  @doc """
  Write a packet to the PCAPNG file.

  The packet's `interface_id` must reference a previously registered interface.

  ## Examples

      :ok = PcapNgWriter.write_packet(writer, packet)
  """
  @spec write_packet(t(), Packet.t()) :: :ok | {:error, String.t()}
  def write_packet(%__MODULE__{reference: ref}, %Packet{} = packet) do
    packet_map = Packet.to_map(packet)
    Native.pcapng_writer_write_packet(ref, packet_map)
  end

  @doc """
  Write multiple packets to a PCAPNG file (convenience function).

  Registers the provided interfaces before writing packets. Each packet's
  `interface_id` must reference one of the provided interfaces.

  ## Parameters
  - `path` - File path to create
  - `interfaces` - List of interface descriptors to register
  - `packets` - Enumerable of packets (interface_id must be valid)

  ## Returns
  - `{:ok, count}` - Number of packets written
  - `{:error, reason}` - Write failed (interface registration or packet write)

  ## Examples

      # Create PCAPNG with explicit interfaces
      interfaces = [
        %Interface{id: 0, linktype: "ethernet", snaplen: 65535, name: "eth0"}
      ]
      packets = [
        %Packet{interface_id: 0, data: ...}
      ]
      {:ok, 100} = PcapNgWriter.write_all("out.pcapng", interfaces, packets)
  """
  @spec write_all(Path.t(), [Interface.t()], Enumerable.t()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def write_all(path, interfaces, packets) do
    with {:ok, writer} <- open(path) do
      try do
        # Register all interfaces first
        result = Enum.reduce_while(interfaces, :ok, fn iface, _acc ->
          case write_interface(writer, iface) do
            {:ok, _id} -> {:cont, :ok}
            {:error, reason} -> {:halt, {:error, "Failed to register interface: #{reason}"}}
          end
        end)

        case result do
          {:error, _} = error ->
            error

          :ok ->
            # Write packets
            count = Enum.reduce_while(packets, 0, fn packet, acc ->
              case write_packet(writer, packet) do
                :ok -> {:cont, acc + 1}
                {:error, reason} -> {:halt, {:error, reason}}
              end
            end)

            case count do
              {:error, _} = error -> error
              count when is_integer(count) -> {:ok, count}
            end
        end
      after
        close(writer)
      end
    end
  end

  @doc """
  Close the PCAPNG writer and flush buffered data.
  """
  @spec close(t()) :: :ok | {:error, String.t()}
  def close(%__MODULE__{reference: ref}) do
    Native.pcapng_writer_close(ref)
  end
end
```

#### `lib/pcap_file_ex/stream.ex` (additions)

```elixir
defmodule PcapFileEx.Stream do
  # ... existing code ...

  @doc """
  Write a stream of packets to a file.

  Opens a writer, consumes the stream, and closes automatically.
  Format is auto-detected from file extension (.pcap or .pcapng).

  **IMPORTANT:** For PCAPNG output, you must provide the `:interfaces` option
  with a list of interface descriptors. Interface metadata cannot be inferred
  from a streaming source.

  ## Parameters
  - `stream` - Stream of packets to write
  - `path` - Output file path
  - `header` - PCAP header (required for .pcap files)

  ## Options
  - `:format` - Force output format (`:pcap` or `:pcapng`)
  - `:interfaces` - List of Interface structs (required for PCAPNG)

  ## Returns
  - `{:ok, count}` - Number of packets written
  - `{:error, reason}` - Write failed

  ## Examples

      # PCAP output (header required)
      header = %PcapFileEx.Header{snaplen: 65535, datalink: "ethernet"}
      PcapFileEx.stream!("input.pcap")
      |> Stream.filter(fn p -> :http in p.protocols end)
      |> PcapFileEx.Stream.write("output.pcap", header)

      # PCAPNG output (interfaces required)
      interfaces = [
        %PcapFileEx.Interface{id: 0, linktype: "ethernet", snaplen: 65535}
      ]
      PcapFileEx.stream!("input.pcapng")
      |> PcapFileEx.Stream.write("output.pcapng", nil, interfaces: interfaces)
  """
  @spec write(Enumerable.t(), Path.t(), Header.t() | nil, keyword()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def write(stream, path, header_or_nil, opts \\ []) do
    output_format = Keyword.get(opts, :format, detect_format_from_extension(path))
    interfaces = Keyword.get(opts, :interfaces)

    case output_format do
      :pcap when is_nil(header_or_nil) ->
        {:error, "PCAP format requires header parameter"}

      :pcap ->
        PcapFileEx.PcapWriter.write_all(path, header_or_nil, stream)

      :pcapng when is_nil(interfaces) or interfaces == [] ->
        {:error, "PCAPNG format requires :interfaces option with list of interface descriptors. " <>
                 "Extract interfaces from source file using PcapFileEx.PcapNg.interfaces/1"}

      :pcapng ->
        PcapFileEx.PcapNgWriter.write_all(path, interfaces, stream)
    end
  end

  # Helper: Detect format from file extension
  defp detect_format_from_extension(path) do
    case Path.extname(path) do
      ".pcap" -> :pcap
      ".pcapng" -> :pcapng
      _ -> :pcap  # Default to PCAP
    end
  end
end
```

#### `lib/pcap_file_ex.ex` (High-Level API)

```elixir
defmodule PcapFileEx do
  # ... existing code ...

  @doc """
  Write packets to a PCAP file.

  Convenience function for batch writing. For large datasets, prefer
  streaming writes via `PcapWriter` or `Stream.write/3`.

  ## Parameters
  - `path` - Output file path
  - `header` - PCAP global header
  - `packets` - List or stream of packets

  ## Returns
  - `{:ok, count}` - Number of packets written
  - `{:error, reason}` - Write failed

  ## Examples

      header = %PcapFileEx.Header{snaplen: 65535, datalink: "ethernet"}
      {:ok, 100} = PcapFileEx.write("output.pcap", header, packets)
  """
  @spec write(Path.t(), Header.t(), Enumerable.t()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def write(path, header, packets) do
    PcapFileEx.PcapWriter.write_all(path, header, packets)
  end

  @doc """
  Write packets to a file (raises on error).
  """
  @spec write!(Path.t(), Header.t(), Enumerable.t()) :: non_neg_integer()
  def write!(path, header, packets) do
    case write(path, header, packets) do
      {:ok, count} -> count
      {:error, reason} -> raise "Failed to write PCAP: #{reason}"
    end
  end

  @doc """
  Copy a PCAP/PCAPNG file, optionally converting format.

  Uses streaming for memory efficiency - can copy files of any size
  without loading them entirely into memory.

  Automatically detects input format and uses output format based on
  file extension. Use `:format` option to override.

  Handles corrupted packets gracefully based on `:on_error` option.

  ## Options
  - `:format` - Force output format (`:pcap` or `:pcapng`)
  - `:on_error` - How to handle read errors (`:halt` (default) or `:skip`)

  ## Returns
  - `{:ok, count}` - Number of packets written
  - `{:error, reason}` - Read or write failed

  ## Examples

      # Copy as-is (streaming, constant memory)
      {:ok, count} = PcapFileEx.copy("input.pcap", "output.pcap")

      # Convert PCAP to PCAPNG
      {:ok, count} = PcapFileEx.copy("legacy.pcap", "modern.pcapng")

      # Copy with error skipping (useful for partially corrupted files)
      {:ok, count} = PcapFileEx.copy("corrupted.pcap", "fixed.pcap", on_error: :skip)

      # Force format
      {:ok, count} = PcapFileEx.copy("in.pcap", "out.pcapng", format: :pcapng)
  """
  @spec copy(Path.t(), Path.t(), keyword()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def copy(source_path, dest_path, opts \\ []) do
    output_format = Keyword.get(opts, :format, detect_format_from_extension(dest_path))
    on_error = Keyword.get(opts, :on_error, :halt)

    with {:ok, source_format} <- Format.detect(source_path),
         {:ok, header} <- get_header(source_path),
         {:ok, source_stream} <- stream(source_path) do

      # Handle both success and error tuples from safe stream
      packets_stream = source_stream
      |> Stream.flat_map(fn
        {:ok, packet} ->
          [packet]

        {:error, meta} ->
          # Handle read errors based on on_error option
          case on_error do
            :halt ->
              throw({:copy_error, "Read failed at packet #{meta.packet_index}: #{meta.reason}"})

            :skip ->
              require Logger
              Logger.warning("Skipping corrupt packet #{meta.packet_index} during copy: #{meta.reason}")
              []
          end
      end)

      # Write with correct format
      case output_format do
        :pcap ->
          PcapFileEx.PcapWriter.write_all(dest_path, header, packets_stream)

        :pcapng ->
          # Extract interfaces for PCAPNG output
          interfaces = case source_format do
            :pcapng ->
              # Source is PCAPNG - extract interfaces
              case extract_interfaces_from_reader(source_path) do
                {:ok, ifaces} -> ifaces
                {:error, _} -> [create_default_interface_from_header(header)]
              end

            :pcap ->
              # Source is PCAP - create interface from header
              [create_default_interface_from_header(header)]
          end

          PcapFileEx.PcapNgWriter.write_all(dest_path, interfaces, packets_stream)
      end
    catch
      {:copy_error, reason} -> {:error, reason}
    end
  end

  # Private helper: Extract interfaces from PCAPNG file
  defp extract_interfaces_from_reader(path) do
    with {:ok, reader} <- PcapNg.open(path),
         {:ok, interfaces} <- PcapNg.interfaces(reader) do
      PcapNg.close(reader)
      {:ok, interfaces}
    end
  end

  # Private helper: Create default interface for PCAP->PCAPNG conversion
  # Derives interface fields from source PCAP header to preserve datalink and snaplen
  defp create_default_interface_from_header(%Header{} = header) do
    %Interface{
      id: 0,
      linktype: header.datalink,  # Preserve actual datalink (not just "ethernet")
      snaplen: header.snaplen,    # Preserve actual snaplen (not just 65535)
      name: "pcap0",
      description: "Converted from PCAP (#{header.datalink}, snaplen=#{header.snaplen})"
    }
  end

  # Private helper: Detect format from file extension
  defp detect_format_from_extension(path) do
    case Path.extname(path) do
      ".pcapng" -> :pcapng
      _ -> :pcap
    end
  end

  @doc """
  Export filtered packets to a new file.

  Reads source file, applies filter function, and writes matching packets
  to destination. Memory-efficient for large files (streaming).

  Handles corrupted packets gracefully based on `:on_error` option.

  ## Parameters
  - `source_path` - Input PCAP/PCAPNG file
  - `dest_path` - Output file path
  - `filter_fun` - Function `(Packet.t() -> boolean())`
  - `opts` - Options

  ## Options
  - `:format` - Override output format (`:pcap` or `:pcapng`, default: auto-detect from extension)
  - `:on_error` - How to handle read errors (`:halt` (default) or `:skip`)

  ## Returns
  - `{:ok, count}` - Number of packets written
  - `{:error, reason}` - Read or write failed

  ## Examples

      # Extract HTTP traffic
      {:ok, 42} = PcapFileEx.export_filtered(
        "full.pcap",
        "http.pcap",
        fn packet -> :http in packet.protocols end
      )

      # Time range with error skipping
      {:ok, 100} = PcapFileEx.export_filtered(
        "possibly_corrupted.pcapng",
        "window.pcapng",
        fn p ->
          DateTime.compare(p.timestamp, start_time) != :lt and
          DateTime.compare(p.timestamp, end_time) != :gt
        end,
        on_error: :skip
      )

      # Convert format during export
      {:ok, 50} = PcapFileEx.export_filtered(
        "input.pcap",
        "output.pcapng",
        fn p -> :tcp in p.protocols end,
        format: :pcapng
      )
  """
  @spec export_filtered(Path.t(), Path.t(), (Packet.t() -> boolean()), keyword()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def export_filtered(source_path, dest_path, filter_fun, opts \\ [])
      when is_function(filter_fun, 1) do
    output_format = Keyword.get(opts, :format, detect_format_from_extension(dest_path))
    on_error = Keyword.get(opts, :on_error, :halt)

    with {:ok, source_format} <- Format.detect(source_path),
         {:ok, header} <- get_header(source_path),
         {:ok, stream} <- stream(source_path) do

      # Handle both success and error tuples from safe stream
      filtered = stream
      |> Stream.flat_map(fn
        {:ok, packet} ->
          # Apply filter
          if filter_fun.(packet), do: [{:ok, packet}], else: []

        {:error, meta} ->
          # Handle read errors based on on_error option
          case on_error do
            :halt ->
              throw({:export_error, "Read failed at packet #{meta.packet_index}: #{meta.reason}"})

            :skip ->
              require Logger
              Logger.warning("Skipping corrupt packet #{meta.packet_index}: #{meta.reason}")
              []
          end
      end)

      # Extract just packets for writing (errors already handled above)
      packets_only = Stream.map(filtered, fn {:ok, packet} -> packet end)

      # Write with correct format
      case output_format do
        :pcap ->
          PcapFileEx.PcapWriter.write_all(dest_path, header, packets_only)

        :pcapng ->
          # Extract interfaces for PCAPNG output
          interfaces = case source_format do
            :pcapng ->
              case extract_interfaces_from_reader(source_path) do
                {:ok, ifaces} -> ifaces
                {:error, _} -> [create_default_interface_from_header(header)]
              end

            :pcap ->
              [create_default_interface_from_header(header)]
          end

          PcapFileEx.PcapNgWriter.write_all(dest_path, interfaces, packets_only)
      end
    catch
      {:export_error, reason} -> {:error, reason}
    end
  end

  @doc """
  Export filtered packets (raises on error).
  """
  @spec export_filtered!(Path.t(), Path.t(), (Packet.t() -> boolean()), keyword()) :: non_neg_integer()
  def export_filtered!(source_path, dest_path, filter_fun, opts \\ []) do
    case export_filtered(source_path, dest_path, filter_fun, opts) do
      {:ok, count} -> count
      {:error, reason} -> raise "Failed to export filtered packets: #{reason}"
    end
  end
end
```

#### `lib/pcap_file_ex/timestamp_shift.ex` (Utility)

```elixir
defmodule PcapFileEx.TimestampShift do
  @moduledoc """
  Utilities for shifting packet timestamps.

  Useful for anonymizing captures or creating test fixtures.
  """

  alias PcapFileEx.{Packet, Timestamp}

  @doc """
  Shift all packet timestamps by a fixed offset.

  ## Parameters
  - `packets` - Enumerable of packets
  - `offset_nanos` - Nanoseconds to add (negative to subtract)

  ## Returns
  - List of packets with shifted timestamps

  ## Examples

      # Shift forward by 1 hour
      shifted = TimestampShift.shift_all(packets, 3_600_000_000_000)

      # Shift backward by 5 minutes
      shifted = TimestampShift.shift_all(packets, -300_000_000_000)
  """
  @spec shift_all(Enumerable.t(), integer()) :: [Packet.t()]
  def shift_all(packets, offset_nanos) do
    Enum.map(packets, fn packet ->
      new_ts_precise = Timestamp.add(packet.timestamp_precise, offset_nanos)
      new_ts = Timestamp.to_datetime(new_ts_precise)

      %{packet |
        timestamp: new_ts,
        timestamp_precise: new_ts_precise
      }
    end)
  end

  @doc """
  Normalize timestamps so first packet starts at epoch (1970-01-01 00:00:00).

  Preserves relative timing between packets.

  ## Examples

      normalized = TimestampShift.normalize_to_epoch(packets)
      hd(normalized).timestamp
      #=> ~U[1970-01-01 00:00:00.000000Z]
  """
  @spec normalize_to_epoch([Packet.t()]) :: [Packet.t()]
  def normalize_to_epoch([]), do: []
  def normalize_to_epoch([first | _] = packets) do
    first_ts_nanos = Timestamp.to_unix_nanos(first.timestamp_precise)
    shift_all(packets, -first_ts_nanos)
  end
end
```

---

## Implementation Plan

### Phase 1: Rust NIF Layer (2-3 days)

**Tasks:**
1. Create `native/pcap_file_ex/src/pcap_writer.rs`
   - Define `PcapWriterResource` struct
   - Implement NIFs: `pcap_writer_open/2`, `pcap_writer_append/1`, `pcap_writer_write_packet/2`, `pcap_writer_close/1`
   - Add buffering (64KB `BufWriter`)
   - Error handling with `NifError`

2. Create `native/pcap_file_ex/src/pcapng_writer.rs`
   - Define `PcapNgWriterResource` struct
   - Implement NIFs: `pcapng_writer_open/2`, `pcapng_writer_append/1`, `pcapng_writer_write_interface/2`, `pcapng_writer_write_packet/2`, `pcapng_writer_close/1`
   - Interface ID validation

3. Update `native/pcap_file_ex/src/types.rs`
   - Add reverse conversion functions:
     - `map_to_pcap_header/1`
     - `map_to_pcap_packet/1`
     - `map_to_interface_block/1`
     - `map_to_enhanced_packet_block/1`
   - Helper parsers: `parse_datalink/1`, `parse_ts_resolution/1`, `parse_endianness/1`

4. Update `native/pcap_file_ex/src/lib.rs`
   - Register writer resources
   - Export writer NIFs

5. **Testing:**
   - Add Rust unit tests for type conversions
   - Test resource lifecycle (open/write/close)

**Deliverables:**
- Working Rust NIFs for PCAP/PCAPNG writing
- Type conversion layer (Elixir → Rust)
- Basic Rust unit tests

---

### Phase 2: Elixir API Layer (2-3 days)

**Tasks:**
1. Create `lib/pcap_file_ex/pcap_writer.ex`
   - Implement struct and `open/2`, `open!/2`, `append/1`
   - Implement `write_packet/2`, `write_all/3`, `close/1`
   - Add packet validation (snaplen, orig_len)
   - Full module documentation with examples

2. Create `lib/pcap_file_ex/pcap_ng_writer.ex`
   - Implement struct and `open/1`, `open!/1`, `append/1`
   - Implement `write_interface/2`, `write_packet/2`, `write_all/3`, `close/1`
   - Interface tracking and validation
   - Full module documentation

3. Update `lib/pcap_file_ex/stream.ex`
   - Add `write/3` function for streaming writes
   - Format detection from file extension

4. **Testing:**
   - Example-based tests: `test/pcap_file_ex/pcap_writer_test.exs`
   - Example-based tests: `test/pcap_file_ex/pcap_ng_writer_test.exs`
   - Test cases:
     - Write single packet
     - Write multiple packets
     - Append mode
     - Error handling (invalid path, invalid packet)
     - Resource cleanup

**Deliverables:**
- `PcapWriter` and `PcapNgWriter` modules
- Stream integration
- Comprehensive example-based tests

---

### Phase 3: High-Level API (1-2 days)

**Tasks:**
1. Update `lib/pcap_file_ex.ex`
   - Add `write/3`, `write!/3`
   - Add `copy/2`, `copy/3` (with format conversion)
   - Add `export_filtered/3`, `export_filtered!/3`
   - Add private helpers: `get_header/1`, `extract_interfaces/1`

2. Create `lib/pcap_file_ex/timestamp_shift.ex`
   - Implement `shift_all/2`
   - Implement `normalize_to_epoch/1`
   - Full documentation

3. **Testing:**
   - Integration tests: `test/pcap_file_ex_test.exs`
   - Test `export_filtered/3` with various filters
   - Test `copy/2` with format conversion
   - Test `TimestampShift` utilities

**Deliverables:**
- High-level convenience API
- Timestamp shift utilities
- Integration tests

---

### Phase 4: Property Testing & Polish (1-2 days)

**Tasks:**
1. Create `test/property_test/writer_property_test.exs`
   - **Round-trip property**: `read(write(packets)) == packets`
   - **Count preservation**: `length(packets) == write_count`
   - **Header preservation**: Header written equals header read
   - **Timestamp ordering**: Timestamps preserved in order
   - **Interface ID preservation** (PCAPNG)
   - Use existing generators from `test/support/generators.ex`

2. Add writer-specific generators to `test/support/generators.ex`
   - `header_generator/0` (if not exists)
   - `interface_generator/0`

3. Error case testing:
   - Corrupted packets (invalid orig_len)
   - Missing interfaces (PCAPNG)
   - Write after close
   - Append to non-existent file

4. Performance validation:
   - Benchmark write throughput
   - Memory usage for large files

**Deliverables:**
- Property-based test suite
- Error case coverage
- Performance benchmarks

---

### Phase 5: Documentation (1 day)

**Tasks:**
1. **Update README.md**
   - Add "Writer/Export API" section after "Examples"
   - Code examples for all common use cases:
     - Basic writing
     - Filtering and export
     - Format conversion
     - Timestamp shifting
   - Update "Roadmap" (move writer to Completed Features)

2. **Update CHANGELOG.md**
   - Document v0.4.0 features
   - List all new modules and functions
   - Breaking changes (if any)

3. **Update usage-rules.md**
   - Add writer decision tree
   - Common patterns (read → filter → write)
   - Performance guidelines (streaming vs batch)
   - Error handling patterns

4. **Create usage-rules/writing.md**
   - Comprehensive writer guide
   - All API patterns with examples
   - Append mode best practices
   - Format conversion guide
   - Timestamp manipulation
   - Performance optimization
   - Troubleshooting

5. **Update usage-rules/examples.md**
   - Add export/filtering examples
   - Add format conversion examples
   - Add timestamp shifting examples

6. **Update usage-rules/performance.md**
   - Writer performance guidelines
   - Buffering considerations
   - Streaming vs batch comparison

7. **Module documentation (ExDoc)**
   - Ensure all public functions have `@doc`
   - Add `@moduledoc` with overview and examples
   - Add `@spec` for all public functions
   - Cross-reference related modules

**Deliverables:**
- Updated README with writer examples
- Comprehensive usage-rules documentation
- Full ExDoc coverage

---

## Testing Strategy

### Example-Based Tests

**Basic Functionality:**
```elixir
test "write single packet to PCAP file" do
  header = %Header{snaplen: 65535, datalink: "ethernet"}
  packet = %Packet{timestamp: ~U[2025-11-09 10:00:00Z], orig_len: 100, data: <<1,2,3>>}

  assert {:ok, writer} = PcapWriter.open("test.pcap", header)
  assert :ok = PcapWriter.write_packet(writer, packet)
  assert :ok = PcapWriter.close(writer)

  # Verify written file
  assert {:ok, [read_packet]} = PcapFileEx.read_all("test.pcap")
  assert read_packet.data == packet.data
end

test "append to existing PCAP file" do
  # Create initial file
  {:ok, writer1} = PcapWriter.open("test.pcap", header)
  PcapWriter.write_packet(writer1, packet1)
  PcapWriter.close(writer1)

  # Append
  {:ok, writer2} = PcapWriter.append("test.pcap")
  PcapWriter.write_packet(writer2, packet2)
  PcapWriter.close(writer2)

  # Verify both packets
  {:ok, packets} = PcapFileEx.read_all("test.pcap")
  assert length(packets) == 2
end

test "export_filtered extracts HTTP traffic" do
  {:ok, count} = PcapFileEx.export_filtered(
    "test/fixtures/full_capture.pcap",
    "http_only.pcap",
    fn p -> :http in p.protocols end
  )

  assert count > 0

  {:ok, packets} = PcapFileEx.read_all("http_only.pcap")
  assert Enum.all?(packets, fn p -> :http in p.protocols end)
end
```

**Error Cases:**
```elixir
test "write_packet validates snaplen" do
  header = %Header{snaplen: 100}
  packet = %Packet{orig_len: 200, data: binary_of_size(200)}

  {:ok, writer} = PcapWriter.open("test.pcap", header)
  assert {:error, reason} = PcapWriter.write_packet(writer, packet)
  assert reason =~ "snaplen"
end

test "append to non-existent file returns error" do
  assert {:error, reason} = PcapWriter.append("nonexistent.pcap")
  assert reason =~ "not found" or reason =~ "does not exist"
end

test "append validates header compatibility" do
  # Create PCAP with ethernet datalink
  header1 = %Header{datalink: "ethernet"}
  PcapWriter.write_all("test.pcap", header1, [packet1])

  # Try to append with incompatible header (would fail in NIF)
  # This is validated at Rust layer
end
```

### Property-Based Tests

**Round-Trip Property:**
```elixir
property "written packets can be read back identically" do
  check all packets <- packet_list_generator(10..100),
            header <- header_generator() do
    path = "test_#{:rand.uniform(1000000)}.pcap"

    # Write
    {:ok, count} = PcapWriter.write_all(path, header, packets)
    assert count == length(packets)

    # Read
    {:ok, read_packets} = PcapFileEx.read_all(path)

    # Verify
    assert length(read_packets) == length(packets)

    Enum.zip(packets, read_packets)
    |> Enum.each(fn {original, read} ->
      assert read.data == original.data
      assert read.orig_len == original.orig_len
      # Timestamps may have precision differences - compare carefully
      assert Timestamp.compare(read.timestamp_precise, original.timestamp_precise) == :eq
    end)

    File.rm!(path)
  end
end

property "packet count is preserved" do
  check all packets <- packet_list_generator(0..1000),
            header <- header_generator() do
    path = "test_#{:rand.uniform(1000000)}.pcap"

    {:ok, count} = PcapWriter.write_all(path, header, packets)
    assert count == length(packets)

    {:ok, read_packets} = PcapFileEx.read_all(path)
    assert length(read_packets) == length(packets)

    File.rm!(path)
  end
end

property "timestamp ordering is preserved" do
  check all packets <- packet_list_generator(10..100) do
    # Sort packets by timestamp
    sorted_packets = Enum.sort_by(packets, & &1.timestamp_precise, Timestamp)

    path = "test_#{:rand.uniform(1000000)}.pcap"
    header = %Header{snaplen: 65535, datalink: "ethernet"}

    {:ok, _} = PcapWriter.write_all(path, header, sorted_packets)
    {:ok, read_packets} = PcapFileEx.read_all(path)

    # Verify ordering preserved
    read_timestamps = Enum.map(read_packets, & &1.timestamp_precise)
    assert read_timestamps == Enum.sort(read_timestamps, Timestamp)

    File.rm!(path)
  end
end

property "filter does not modify packets" do
  check all packets <- packet_list_generator(10..100),
            header <- header_generator() do
    filter_fun = fn _packet -> true end  # Accept all

    source_path = "source_#{:rand.uniform(1000000)}.pcap"
    dest_path = "dest_#{:rand.uniform(1000000)}.pcap"

    {:ok, _} = PcapWriter.write_all(source_path, header, packets)
    {:ok, count} = PcapFileEx.export_filtered(source_path, dest_path, filter_fun)

    assert count == length(packets)

    {:ok, filtered_packets} = PcapFileEx.read_all(dest_path)
    assert length(filtered_packets) == length(packets)

    File.rm!(source_path)
    File.rm!(dest_path)
  end
end
```

---

## Documentation Plan

### README.md Updates

Add new section after "Examples":

```markdown
## Writer/Export API

### Export Filtered Packets

Extract specific traffic from captures:

```elixir
# Extract HTTP traffic
PcapFileEx.export_filtered!(
  "full_capture.pcap",
  "http_only.pcap",
  fn packet -> :http in packet.protocols end
)

# Time range filtering
start_time = ~U[2025-11-09 10:00:00Z]
end_time = ~U[2025-11-09 11:00:00Z]

PcapFileEx.export_filtered!(
  "full_day.pcapng",
  "one_hour.pcapng",
  fn packet ->
    DateTime.compare(packet.timestamp, start_time) != :lt and
    DateTime.compare(packet.timestamp, end_time) != :gt
  end
)
```

### Write Packets Programmatically

Create test fixtures or synthetic captures:

```elixir
# Create PCAP file
header = %PcapFileEx.Header{
  version_major: 2,
  version_minor: 4,
  snaplen: 65535,
  datalink: "ethernet"
}

packets = [
  %PcapFileEx.Packet{
    timestamp: ~U[2025-11-09 10:00:00Z],
    timestamp_precise: PcapFileEx.Timestamp.from_datetime(~U[2025-11-09 10:00:00Z]),
    orig_len: 100,
    data: http_request_bytes
  }
]

PcapFileEx.write!("test_fixture.pcap", header, packets)
```

### Convert Formats

Convert between PCAP and PCAPNG:

```elixir
# Convert legacy PCAP to modern PCAPNG
PcapFileEx.copy("legacy.pcap", "modern.pcapng")

# Convert PCAPNG to PCAP
PcapFileEx.copy("capture.pcapng", "compatible.pcap")
```

### Streaming Writes

Memory-efficient writes for large filtered datasets:

```elixir
{:ok, reader} = PcapFileEx.open("huge_50gb.pcap")
{:ok, writer} = PcapFileEx.PcapWriter.open("filtered.pcap", header)

try do
  PcapFileEx.stream!(reader)
  |> Stream.filter(fn packet -> :tcp in packet.protocols end)
  |> Enum.each(fn packet ->
    :ok = PcapFileEx.PcapWriter.write_packet(writer, packet)
  end)
after
  PcapFileEx.Pcap.close(reader)
  PcapFileEx.PcapWriter.close(writer)
end
```

### Timestamp Manipulation

Anonymize or normalize timestamps:

```elixir
# Shift all timestamps forward by 1 hour
{:ok, packets} = PcapFileEx.read_all("original.pcap")
shifted = PcapFileEx.TimestampShift.shift_all(packets, 3_600_000_000_000)
PcapFileEx.write!("shifted.pcap", header, shifted)

# Normalize to epoch (first packet at 1970-01-01 00:00:00)
normalized = PcapFileEx.TimestampShift.normalize_to_epoch(packets)
PcapFileEx.write!("normalized.pcap", header, normalized)
```
```

Update Roadmap:

```markdown
## Roadmap

### Completed Features
- [x] PCAP format reading
- [x] PCAPNG format reading
... (existing items)
- [x] **Multi-file timeline merge**
- [x] **PCAP/PCAPNG writer API** - Export filtered packets, format conversion, timestamp manipulation

### Planned Features
- [ ] **Display filter → PreFilter compiler**
- [ ] **Telemetry hooks**
- [ ] **Higher-level protocol decoders** (TLS, HTTP/2)
```

### CHANGELOG.md Entry

```markdown
## [0.4.0] - 2025-11-XX

**MAJOR FEATURE** - PCAP/PCAPNG Writer API

### Added
- **Writer API** - Export and create PCAP/PCAPNG files programmatically
  - New `PcapFileEx.PcapWriter` module for PCAP format
  - New `PcapFileEx.PcapNgWriter` module for PCAPNG format
  - Streaming writes: `open/2`, `write_packet/2`, `close/1`
  - Batch writes: `write_all/3` convenience function
  - Append mode: Add packets to existing captures with validation
  - Memory-efficient: 64KB buffering, constant memory streaming

- **High-Level Convenience API**
  - `PcapFileEx.write/3` - Write packet list to file
  - `PcapFileEx.export_filtered/3` - Read → Filter → Write in one call
  - `PcapFileEx.copy/2` - Copy files with optional format conversion
  - Bang variants: `write!/3`, `export_filtered!/3`

- **Timestamp Utilities**
  - New `PcapFileEx.TimestampShift` module
  - `shift_all/2` - Offset all timestamps by nanoseconds
  - `normalize_to_epoch/1` - Start timestamps at 1970-01-01

- **Format Conversion**
  - Convert PCAP ↔ PCAPNG transparently
  - Automatic format detection from file extension
  - Preserve all metadata (interfaces, timestamps, datalink)

- **Property-Based Tests**
  - Round-trip validation (write then read)
  - Count preservation properties
  - Timestamp ordering validation
  - 30+ new property tests

- **Comprehensive Documentation**
  - New `usage-rules/writing.md` guide
  - Updated README with writer examples
  - Full ExDoc coverage for all writer modules

### Changed
- None (additive changes only)

### Fixed
- None

### Performance
- Buffered writes (64KB buffer) for high throughput
- Streaming writes for large filtered exports (constant memory)
- Benchmarks show X MB/s write throughput

### Documentation
- Complete writer API specification in `specs/20251109-pcap-writer-api.md`
- Usage patterns in `usage-rules/writing.md`
- Examples in README.md
```

---

## Performance Considerations

### Buffering

**Rust Layer:**
- Wrap `File` in `BufWriter::with_capacity(64 * 1024, file)`
- Reduces syscall overhead
- Expected throughput: 100-500 MB/s (depends on disk)

**Benchmarks to Add:**
```bash
mix run bench/pcap_writing.exs
```

Test scenarios:
- Write 10K packets (small)
- Write 1M packets (large)
- Streaming write vs batch
- Memory usage comparison

### Memory Usage

**Streaming Writes (Recommended):**
```elixir
# O(1) memory - only holds current packet
PcapFileEx.stream!("input.pcap")
|> Stream.filter(filter_fun)
|> Enum.each(&PcapWriter.write_packet(writer, &1))
```

**Batch Writes (Convenience):**
```elixir
# O(N) memory - loads all packets
{:ok, packets} = PcapFileEx.read_all("input.pcap")
filtered = Enum.filter(packets, filter_fun)
PcapWriter.write_all("output.pcap", header, filtered)
```

**Guidelines:**
- Files < 100MB: Batch writes OK
- Files > 100MB: Use streaming
- Files > 1GB: Always stream

### Validation Overhead

Packet validation (snaplen, orig_len) happens in Elixir layer:
- Minimal overhead (~1-2% of total time)
- Prevents invalid writes early
- Consider `write_unchecked/2` for trusted input (future optimization)

---

## Security Considerations

### Input Validation

**File Paths:**
- Validate paths before passing to Rust
- Prevent path traversal attacks
- Use `Path.expand/1` to normalize

**Packet Data:**
- Validate `orig_len <= snaplen`
- Validate `byte_size(data) <= snaplen`
- Validate timestamps are non-negative

### Append Mode Validation

**Header Compatibility:**
- Ensure datalink matches
- Ensure snaplen is compatible (new snaplen <= old snaplen)
- Ensure timestamp resolution matches

**File Integrity:**
- Validate existing file is valid PCAP/PCAPNG
- Check magic number before appending
- Detect truncated files

### Resource Limits

**File Size Limits:**
- PCAP: 2GB limit (32-bit packet lengths)
- PCAPNG: No theoretical limit
- Consider adding warnings for files > 10GB

**Packet Count Limits:**
- No hard limits
- Monitor memory usage for batch writes

---

## Open Questions

### Q1: Should we support writing to streams (not just files)?

**Options:**
1. File-only (simpler, covers 95% of use cases)
2. Support any `IO.device()` (more flexible, complex)

**Recommendation:** Start with file-only. Add stream support in future if requested.

---

### Q2: Should `copy/2` preserve exact binary representation?

**Options:**
1. Parse and rewrite (current plan) - may change byte layout
2. Binary copy - preserves exact bytes but can't filter/convert

**Recommendation:** Parse and rewrite. Users wanting binary copy can use `File.cp!/2`.

---

### Q3: Should we validate written files immediately after close?

**Options:**
1. No validation (trust writer, faster)
2. Optional validation (`:validate` option)
3. Always validate (slower, safer)

**Recommendation:** No automatic validation. Users can call `PcapFileEx.Validator.validate/1` manually if needed.

---

### Q4: Should append mode support cross-format appending?

**Example:** Append PCAPNG packets to PCAP file?

**Options:**
1. Same format only (simpler, safer)
2. Allow conversion (complex, error-prone)

**Recommendation:** Same format only. Use `export_filtered/3` for cross-format workflows.

---

### Q5: Should we support writing partial packets (snaplen truncation)?

**Use case:** Write full packet data but with smaller snaplen, auto-truncating.

**Options:**
1. User must truncate data manually (current plan)
2. Auto-truncate if `byte_size(data) > snaplen`

**Recommendation:** User must truncate manually. Makes truncation explicit and intentional.

---

## Timeline Summary

| Phase | Tasks | Duration |
|-------|-------|----------|
| **Phase 1** | Rust NIF Layer | 2-3 days |
| **Phase 2** | Elixir API Layer | 2-3 days |
| **Phase 3** | High-Level API | 1-2 days |
| **Phase 4** | Property Testing | 1-2 days |
| **Phase 5** | Documentation | 1 day |
| **TOTAL** | | **7-11 days** |

---

## Success Criteria

- ✅ Can write PCAP files from packet list
- ✅ Can write PCAPNG files with multiple interfaces
- ✅ Can append to existing files
- ✅ Can export filtered packets in one call
- ✅ Can convert between formats
- ✅ Round-trip property holds (read(write(x)) == x)
- ✅ Memory usage is constant for streaming writes
- ✅ All public functions have documentation and examples
- ✅ Test coverage > 95%
- ✅ No resource leaks under error conditions

---

## Appendix A: Example Use Cases in Detail

### UC1: Security Incident Investigation

**Scenario:** Security team needs to extract suspicious traffic from a 24-hour capture for analysis.

```elixir
# Extract all traffic to/from suspicious IP
suspicious_ip = "192.168.1.100"

PcapFileEx.export_filtered!(
  "full_day_capture.pcapng",
  "suspicious_traffic.pcapng",
  fn packet ->
    (packet.src && packet.src.ip == suspicious_ip) or
    (packet.dst && packet.dst.ip == suspicious_ip)
  end
)

# Result: 500MB file reduced to 2MB for sharing
```

### UC2: Automated Test Fixture Generation

**Scenario:** Create minimal reproducible test case for bug report.

```elixir
# Programmatically create HTTP exchange
defmodule TestFixtures do
  def create_http_exchange do
    header = %Header{snaplen: 65535, datalink: "ethernet"}

    packets = [
      create_packet(0, http_request()),
      create_packet(1, http_response())
    ]

    PcapFileEx.write!("test/fixtures/http_exchange.pcap", header, packets)
  end

  defp create_packet(offset, payload) do
    ts = DateTime.add(~U[2025-01-01 00:00:00Z], offset, :second)

    %Packet{
      timestamp: ts,
      timestamp_precise: Timestamp.from_datetime(ts),
      orig_len: byte_size(payload),
      data: payload
    }
  end
end
```

### UC3: Privacy-Preserving Dataset Publication

**Scenario:** Researcher wants to publish network dataset with anonymized timestamps.

```elixir
# Anonymize timestamps and IP addresses
defmodule DatasetAnonymizer do
  def anonymize(input_path, output_path) do
    {:ok, packets} = PcapFileEx.read_all(input_path)
    {:ok, header} = PcapFileEx.get_header(input_path)

    # Normalize timestamps
    normalized = TimestampShift.normalize_to_epoch(packets)

    # Anonymize IP addresses (external library)
    anonymized = Enum.map(normalized, &anonymize_ips/1)

    PcapFileEx.write!(output_path, header, anonymized)
  end
end
```

---

## Appendix B: Error Messages

**Clear, Actionable Errors:**

```elixir
# Snaplen validation
{:error, "Packet orig_len (1600) exceeds snaplen (1500). Truncate packet data or increase snaplen."}

# Append validation
{:error, "Cannot append: datalink mismatch (file: ethernet, append: wifi). Use export_filtered/3 to convert."}

# Missing interface
{:error, "Packet references interface_id 5, but only 2 interfaces registered. Call write_interface/2 first."}

# File permissions
{:error, "Failed to create file: Permission denied. Check write permissions for /path/to/file.pcap"}
```

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-09 | Initial specification |
| 1.1 | 2025-11-09 | Code review remediation - Fixed 6 critical design flaws |
| 1.2 | 2025-11-09 | Code review round 2 - Fixed 3 additional critical issues |
| 1.3 | 2025-11-09 | Code review round 3 - Fixed undefined function references |
| 1.4 | 2025-11-09 | Post-implementation bug fixes - Resource leaks and error handling |
| 1.4.1 | 2025-11-10 | PCAP→PCAPNG conversion bug fixes - Missing interface_id assignment |

### Version 1.4.1 Changes (PCAP→PCAPNG Conversion Bug Fixes)

**Overview:** After Version 1.4 release, testing revealed that PCAP→PCAPNG format conversion was completely broken in both `copy/3` and `export_filtered/4`. PCAP packets have `interface_id == nil` (PCAP format has no interface concept), but `PcapNgWriter.write_packet/2` requires valid `interface_id` and validates this strictly, causing all PCAP→PCAPNG conversions to fail.

**Critical Bugs Fixed:**

1. **lib/pcap_file_ex.ex:~400 - `copy/3` PCAP→PCAPNG missing interface_id**
   - **Problem:** When copying PCAP to PCAPNG format, PCAP packets have `interface_id == nil`, but PCAPNG writer requires valid interface_id
   - **Impact:** All PCAP→PCAPNG conversions fail with validation error: "interface_id must be a non-negative integer"
   - **Root Cause:** PCAP format has no interface concept, so packets read from PCAP files have nil interface_id. PCAPNG format requires interface tracking, so writer validates interface_id exists.
   - **Fix:** Assign `interface_id: 0` to all packets when converting from PCAP to PCAPNG format
   - **Code Before:**
   ```elixir
   # BROKEN: PCAP packets have interface_id == nil
   write(dest_path, nil, packets_stream, format: :pcapng, interfaces: interfaces)
   ```
   - **Code After:**
   ```elixir
   # Assign interface_id for PCAPNG format (PCAP packets don't have interface_id)
   packets_with_interface =
     if source_format == :pcap do
       packets_stream |> Elixir.Stream.map(&%{&1 | interface_id: 0})
     else
       packets_stream
     end

   write(dest_path, nil, packets_with_interface, format: :pcapng, interfaces: interfaces)
   ```

2. **lib/pcap_file_ex.ex:~502 - `export_filtered/4` PCAP→PCAPNG missing interface_id**
   - **Problem:** Identical to `copy/3` - filtered PCAP packets have nil interface_id but PCAPNG writer requires valid ID
   - **Impact:** All PCAP→PCAPNG filtered exports fail with validation error
   - **Fix:** Same solution as `copy/3` - assign interface_id: 0 when source is PCAP
   - **Code Before:**
   ```elixir
   # BROKEN: PCAP packets have interface_id == nil
   write(dest_path, nil, packets_only, format: :pcapng, interfaces: interfaces)
   ```
   - **Code After:**
   ```elixir
   # Assign interface_id for PCAPNG format (PCAP packets don't have interface_id)
   packets_with_interface =
     if source_format == :pcap do
       packets_only |> Elixir.Stream.map(&%{&1 | interface_id: 0})
     else
       packets_only
     end

   write(dest_path, nil, packets_with_interface, format: :pcapng, interfaces: interfaces)
   ```

**Key Design Insights:**

- **PCAP vs PCAPNG interface model:** PCAP files have a single global datalink type with no interface concept. PCAPNG files support multiple interfaces, each with its own datalink and metadata. When converting PCAP→PCAPNG, we map the single PCAP datalink to interface_id: 0.

- **Lazy evaluation preservation:** The fix uses `Stream.map` to assign interface_id only when needed (source is PCAP), preserving memory efficiency of streaming. PCAPNG→PCAPNG conversions bypass this step since packets already have interface_id.

- **Why interface_id: 0?** PCAPNG interface IDs start at 0. Since PCAP has only one implicit interface, we map it to the first interface (ID 0) in the output PCAPNG file.

**Impact Analysis:**

- **Severity:** Critical - All PCAP→PCAPNG conversions were completely broken
- **Affected Functions:** `copy/3` and `export_filtered/4` when output format is :pcapng and source is PCAP
- **When Discovered:** Post-Version 1.4 testing before public release
- **User Impact:** No users affected (caught before release)

**Files Modified:**

1. `lib/pcap_file_ex.ex` - Fixed both bugs
2. `test/pcap_file_ex/writer_smoke_test.exs` - Added 3 new tests
3. `test/pcap_file_ex/bug_regression_test.exs` - Added regression tests for bugs 9-10
4. `specs/20251109-pcap-writer-api.md` - This documentation

**Testing Additions:**

- Smoke test: `copy/3` PCAP→PCAPNG conversion with packet data verification
- Smoke test: `export_filtered/4` PCAP→PCAPNG conversion with filter validation
- Smoke test: Round-trip PCAP→PCAPNG→PCAP data integrity test
- Regression test: `copy/3` assigns interface_id when converting to PCAPNG
- Regression test: `export_filtered/4` assigns interface_id when converting to PCAPNG
- Regression test: Round-trip conversion preserves packet data

**Test Results:**

All tests pass with the fixes applied. Round-trip conversion (PCAP→PCAPNG→PCAP) preserves:
- Packet data (binary content)
- Original length
- Timestamp information
- Datalink type

---

### Version 1.4 Changes (Post-Implementation Bug Fixes)

**Overview:** After MVP implementation, post-implementation review identified 8 critical bugs related to resource cleanup and error handling. All bugs have been fixed before release.

**Critical Bugs Fixed:**

1. **lib/pcap_file_ex.ex:351 - `copy/3` Format.detect error handling**
   - **Problem:** `Format.detect/1` can return `{:error, reason}` but code assigned result to `source_format` and pattern matched on bare atoms (`:pcap` | `:pcapng`), causing `CaseClauseError` on unreadable files
   - **Impact:** Crashes when copying files with bad permissions, unknown format, or I/O errors
   - **Fix:** Changed to `with {:ok, source_format} <- detect_format_with_validation(source_path)` to properly handle error tuples
   - **Code Before:**
   ```elixir
   try do
     source_format = Format.detect(source_path)  # Can be {:error, ...}!
     with {:ok, header} <- get_header(source_path) do
       case source_format do  # CaseClauseError if error tuple!
         :pcap -> ...
         :pcapng -> ...
       end
     end
   end
   ```
   - **Code After:**
   ```elixir
   try do
     with {:ok, source_format} <- detect_format_with_validation(source_path),
          {:ok, header} <- get_header(source_path) do
       case source_format do  # Now safely always :pcap | :pcapng
         :pcap -> ...
         :pcapng -> ...
       end
     end
   end
   ```

2. **lib/pcap_file_ex.ex:448 - `export_filtered/4` Format.detect error handling**
   - **Problem:** Identical to `copy/3` - `Format.detect/1` error tuple not handled
   - **Impact:** Crashes when exporting from unreadable files
   - **Fix:** Same solution as `copy/3`

3. **lib/pcap_file_ex.ex:536 - `get_header/1` PCAP resource leak**
   - **Problem:** Missing `Pcap.close(reader)` call after extracting header
   - **Impact:** File descriptor leak on every `copy/export_filtered` call - one FD per operation until BEAM GC runs
   - **Fix:** Wrapped in try/after block with `Pcap.close(reader)` in after clause
   - **Code Before:**
   ```elixir
   :pcap ->
     with {:ok, reader} <- Pcap.open(path) do
       {:ok, reader.header}  # No close!
     end
   ```
   - **Code After:**
   ```elixir
   :pcap ->
     with {:ok, reader} <- Pcap.open(path) do
       try do
         {:ok, reader.header}
       after
         Pcap.close(reader)  # Always closes
       end
     end
   ```

4. **lib/pcap_file_ex.ex:542 - `get_header/1` PCAPNG resource leak**
   - **Problem:** Missing `PcapNg.close(reader)` call after building header
   - **Impact:** File descriptor leak on every PCAPNG `copy/export_filtered` call
   - **Fix:** Wrapped in try/after block with `PcapNg.close(reader)` in after clause

5. **lib/pcap_file_ex.ex:540 - `get_header/1` PCAPNG tuple mismatch**
   - **Problem:** `PcapNg.interfaces(reader)` returns `{:ok, [Interface.t()]}` but code called `List.first(interfaces)` directly on tuple
   - **Impact:** Crash when copying PCAPNG files (List.first/1 on `{:ok, list}` tuple)
   - **Fix:** Changed to `with {:ok, interfaces} <- PcapNg.interfaces(reader)` to unwrap tuple
   - **Code Before:**
   ```elixir
   interfaces = PcapNg.interfaces(reader)  # Returns {:ok, list}!
   case List.first(interfaces) do  # List.first on tuple crashes!
     nil -> ...
     first -> ...
   end
   ```
   - **Code After:**
   ```elixir
   with {:ok, interfaces} <- PcapNg.interfaces(reader) do
     case List.first(interfaces) do  # Now safely a list
       nil -> ...
       first -> ...
     end
   end
   ```

6. **lib/pcap_file_ex.ex:582 - `extract_interfaces_from_reader/1` double-wrapping**
   - **Problem:** Returns `{:ok, {:ok, [Interface.t()]}}` instead of `{:ok, [Interface.t()]}` due to not unwrapping `PcapNg.interfaces/1` result
   - **Impact:** Type mismatch when copying PCAPNG files - callers expect `{:ok, list}` not `{:ok, {:ok, list}}`
   - **Fix:** Changed to unwrap result by returning `PcapNg.interfaces(reader)` directly instead of wrapping again
   - **Code Before:**
   ```elixir
   interfaces = PcapNg.interfaces(reader)  # Returns {:ok, list}
   PcapNg.close(reader)
   {:ok, interfaces}  # Returns {:ok, {:ok, list}}!
   ```
   - **Code After:**
   ```elixir
   try do
     PcapNg.interfaces(reader)  # Returns {:ok, list} directly
   after
     PcapNg.close(reader)
   end
   ```

7. **lib/pcap_file_ex/merge/validator.ex:160 - `get_file_datalink_info/1` error silencing**
   - **Problem:** Catch-all `_` clause treated `Format.detect/1` error tuples as `:unknown` format instead of propagating error
   - **Impact:** Silent failure when merging unreadable files - returns inconsistent data instead of failing fast
   - **Fix:** Replaced catch-all with explicit `{:error, reason} -> {:error, ...}` clause that propagates error
   - **Code Before:**
   ```elixir
   case format do
     :pcap -> ...
     :pcapng -> ...
     _ -> %{path: path, format: :unknown, ...}  # Silently treats errors as unknown!
   end
   ```
   - **Code After:**
   ```elixir
   case format do
     :pcap -> ...
     :pcapng -> ...
     {:error, reason} -> {:error, "Cannot detect format: #{reason}"}
   end
   ```
   - **Caller Updated:** Added error handling in `validate_datalinks/1` to check for error tuples before processing

8. **lib/pcap_file_ex/merge/stream_merger.ex:82 - `initialize_merge/1` CaseClauseError**
   - **Problem:** `Format.detect/1` error tuple not handled in case statement, causing `CaseClauseError`
   - **Impact:** Crashes when merging unreadable files
   - **Fix:** Added explicit `{:error, reason}` clause that raises with descriptive message
   - **Code After:**
   ```elixir
   case format do
     :pcap -> ...
     :pcapng -> ...
     {:error, reason} -> raise "Failed to detect format for #{path}: #{reason}"
   end
   ```

**Additional Changes:**

- **New helper function:** Added `detect_format_with_validation/1` in `lib/pcap_file_ex.ex` to convert `Format.detect/1`'s mixed return type (`:pcap | :pcapng | {:error, ...}`) to consistent tagged tuple `{:ok, :pcap | :pcapng} | {:error, ...}` for use in `with` chains

**Impact Analysis:**

- **Severity:** Critical - All bugs would manifest in production use
- **Resource Leaks:** Bugs 3-4 cause file descriptor exhaustion over time
- **Crashes:** Bugs 1-2, 5-6, 8 cause immediate crashes on valid user input (unreadable files, PCAPNG files)
- **Silent Failures:** Bug 7 silently returns incorrect data
- **When Discovered:** Post-implementation testing, before first release
- **Testing:** All bugs have regression tests added to prevent recurrence

**Files Modified:**

1. `lib/pcap_file_ex.ex` - Fixed bugs 1-6
2. `lib/pcap_file_ex/merge/validator.ex` - Fixed bug 7
3. `lib/pcap_file_ex/merge/stream_merger.ex` - Fixed bug 8
4. `specs/20251109-pcap-writer-api.md` - This documentation

**Testing Additions:**

- Regression test for `copy/3` with unreadable file (bug 1)
- Regression test for `export_filtered/4` with unreadable file (bug 2)
- Regression test for PCAPNG file copying (bugs 5-6)
- Resource leak test using `:erlang.system_info(:port_count)` (bugs 3-4)

---

### Version 1.3 Changes (Code Review Round 3)

**Critical Fixes:**

1. **Fixed undefined function calls in `export_filtered/4`** (Lines 1323, 1327)
   - **Problem:** Called non-existent `create_default_interface()` (zero-arity version) after v1.2 renamed it to `create_default_interface_from_header/1`
   - **Impact:** Would cause `UndefinedFunctionError` at runtime and reintroduce hardcoded linktype/snaplen bug
   - **Fix:** Updated both calls to `create_default_interface_from_header(header)` to match `copy/3` implementation
   - **Verified:** `copy/3` already uses correct function (lines 1184, 1189), helper defined at lines 1208-1218

**Consistency:**
- `export_filtered/4` now matches `copy/3` pattern for interface extraction
- All functions now correctly derive interface metadata from source header
- No zero-arity helper version exists anywhere in the spec

---

### Version 1.2 Changes (Code Review Round 2)

**Critical Fixes:**

1. **Fixed `copy/3` safe stream error handling** (Lines 1143-1187)
   - **Problem:** Pattern matched only `{:ok, packet}`, crashed on `{:error, meta}` tuples from safe streams
   - **Fix:** Added `Stream.flat_map` with error handling (`:halt` | `:skip`)
   - **Added:** `:on_error` option to `copy/3` (default: `:halt`)
   - **Impact:** Can now copy partially corrupted files without crashing

2. **Fixed `create_default_interface` hardcoding** (Lines 1198-1208)
   - **Problem:** Hardcoded `linktype: "ethernet"` and `snaplen: 65535`, silently corrupting PCAP→PCAPNG conversions with different datalinks (802.11, loopback, etc.)
   - **Fix:** Renamed to `create_default_interface_from_header/1`, derives `linktype` and `snaplen` from source header
   - **Impact:** PCAP→PCAPNG conversion now preserves actual datalink and snaplen

3. **Removed misleading `:collect` option** (Lines 1234, 1286-1297)
   - **Problem:** Documented `:on_error` with `:collect` option, but implementation just dropped errors like `:skip` without collecting or returning them
   - **Fix:** Removed `:collect` option from documentation and implementation
   - **Simplified:** Only `:halt` (default) and `:skip` are now supported
   - **Impact:** Clear API contract - no misleading options

**Documentation Updates:**

- Updated `copy/3` documentation to include `:on_error` option
- Added example showing error skipping during copy
- Updated `export_filtered/4` to remove `:collect` references
- All examples now reflect simplified error handling

**API Changes:**

- `copy/3`: Added `:on_error` option (`:halt` | `:skip`)
- `export_filtered/4`: Removed `:collect` from `:on_error` option (now `:halt` | `:skip` only)

---

### Version 1.1 Changes (Code Review Feedback)

**Critical Fixes:**

1. **Fixed `copy/3` memory bloat** (Lines 1029-1114)
   - **Problem:** Eagerly called `read_all/1`, loading entire file into memory
   - **Fix:** Implemented streaming copy using `stream/1`
   - **Impact:** Can now copy files of any size with O(1) memory
   - **Added:** Helper functions for interface extraction and default interface creation

2. **Fixed `copy/3` error handling** (Lines 1064-1084)
   - **Problem:** Returned `:ok` unconditionally, masking write failures
   - **Fix:** Proper error propagation with `{:ok, count} | {:error, reason}`
   - **Impact:** Write failures are now properly surfaced to caller

3. **Fixed `export_filtered/3` error handling** (Lines 1116-1227)
   - **Problem:** Assumed all stream elements are `{:ok, packet}`, crashed on errors
   - **Fix:** Proper handling of `{:ok, packet}` and `{:error, meta}` tuples
   - **Added:** `:on_error` option (`:halt` | `:skip` | `:collect`)
   - **Added:** `:format` option support for format conversion during export
   - **Impact:** Gracefully handles corrupted files without data loss

4. **Fixed `PcapNgWriter.write_interface/2` state tracking** (Lines 796-819)
   - **Problem:** Updated local writer struct but didn't propagate changes
   - **Fix:** Interface tracking moved to Rust NIF layer for thread safety
   - **Impact:** Interface validation now works correctly

5. **Fixed `PcapNgWriter.write_all/3` documentation** (Lines 836-897)
   - **Problem:** Docs claimed "automatically registers" but required explicit list
   - **Fix:** Clarified that interfaces must be provided explicitly
   - **Added:** Better error handling for interface registration failures
   - **Impact:** Clear API contract, proper error messages

6. **Fixed `Stream.write/3` PCAPNG implementation** (Lines 909-984)
   - **Problem:** PCAPNG branch was incomplete ("implementation details...")
   - **Fix:** Complete implementation with explicit interface requirement
   - **Added:** Clear error messages explaining interface requirement
   - **Added:** Helper function for format detection
   - **Impact:** PCAPNG streaming writes now fully functional

**Additional Improvements:**

7. **Added PCAPNG append behavior** (Lines 439-519)
   - **Feature:** Detailed implementation for handling files with trailing blocks
   - **Behavior:** Scans for last packet, truncates trailing metadata, resumes writing
   - **Rationale:** Ensures chronological ordering and correct block structure
   - **Trade-off:** Loses trailing statistics blocks (documented and acceptable)

8. **Enhanced error messages throughout**
   - Added context to all error returns
   - Include packet indices in error metadata
   - Provide actionable guidance (e.g., "Extract interfaces using PcapNg.interfaces/1")

**Documentation Updates:**

- All code examples now reflect streaming patterns
- Added `:on_error` option documentation
- Added `:format` option documentation
- Clarified interface requirements for PCAPNG
- Added helper function documentation

**API Changes:**

- `copy/3`: Return type changed from `:ok` to `{:ok, count} | {:error, reason}`
- `export_filtered/4`: Added `:on_error` and `:format` options
- `Stream.write/4`: Added `:interfaces` option (required for PCAPNG)

**Backward Compatibility:**

- All changes are additive except `copy/3` return type
- Existing code will need minor adjustments to handle success tuples
- Error handling is now more robust (breaking change justified by correctness)

---

