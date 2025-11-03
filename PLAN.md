# PcapFileEx - Implementation Plan

## Status: Phase 3 Complete ✅

**Last Updated:** 2025-11-02

### Completed Features
- ✅ Rust NIF infrastructure with Rustler
- ✅ PCAP file reading (open, close, header, packets)
- ✅ PCAPNG file reading (open, close, packets)
- ✅ Automatic format detection (magic number based)
- ✅ Type-safe Elixir structs (Packet, Header)
- ✅ Lazy streaming API for large files (both formats)
- ✅ File validation helpers (format detection, file checks)
- ✅ Statistics functions (count, bytes, time range, distribution)
- ✅ Packet filtering DSL (size, time, content, custom predicates)
- ✅ Comprehensive test suite (65 tests passing)
- ✅ Test traffic generation scripts (generates both formats)
- ✅ Full documentation (README, User Guide, Developer Guide)
- ✅ Packet metadata enrichment (protocol stack, source/destination endpoints, HTTP detection)
- ✅ Custom decoder registry (pluggable application decoders, HTTP default)
- ✅ Packet decode caching (store decoded layers/payload on packet structs)
- ✅ Display filter engine (Wireshark-style expressions with decoder-backed fields)
- ✅ PCAPNG nanosecond timestamp handling and validation
- ✅ Multi-interface metadata exposure (interface list + per-packet association)

### Next Steps
- 🚧 Protocol parsing utilities (Phase 4)
- 🚧 Expand core decoder catalogue (DNS, TLS, etc.)
- 🚧 Provide opt-in payload caching attached to packet streams (lazy vs eager)
- 🚧 Display filter enhancements (regex, value lists, ranges, compiled filter cache)
- 🚧 Additional documentation samples (full dissector walkthrough)

---

## Project Overview

Create `PcapFileEx`, an Elixir library that wraps the Rust `pcap-file` crate to provide PCAP and PCAPNG file parsing capabilities.

## Research Summary

### pcap-file Rust Library (../pcap-file)
- **Version**: 3.0.0-rc1
- **Formats**: Both PCAP (legacy) and PCAPNG (modern)
- **Main APIs**:
  - `PcapReader` - Iterator-based PCAP reading
  - `PcapNgReader` - Iterator-based PCAPNG reading
  - `PcapHeader` - File header with version, snaplen, datalink, etc.
  - `PcapPacket` - Packet with timestamp (Duration), orig_len, data
- **Key Types**:
  - `DataLink` enum - 200+ link layer types
  - `TsResolution` - Microsecond or Nanosecond
  - `Endianness` - Big or Little
  - Various PCAPNG block types (Section, Interface, Enhanced Packet, etc.)
- **Error Handling**: `PcapError` with variants for IncompleteBuffer, IoError, InvalidField, etc.

### Explorer Pattern (Reference Implementation)
- **Structure**: `native/explorer/` directory for Rust code
- **Rustler Init**: Uses `rustler::init!("Elixir.ModuleName")`
- **NIF Pattern**: Elixir stubs that raise `:nif_not_loaded`, replaced at runtime
- **Resources**: Opaque Rust types wrapped as Rustler Resources
- **Error Mapping**: Rust Result → Elixir {:ok, _} / {:error, _}

---

## SPECIFICATION

### Goals
1. ✅ Read PCAP files (legacy format)
2. ✅ Read PCAPNG files (modern format)
3. ✅ Access packet data, timestamps, and metadata
4. ✅ Streaming API for large files
5. ✅ Type-safe Elixir structs

### Features by Phase

**Phase 1 - PCAP Support** ✅ **COMPLETED**
- ✅ Open and parse PCAP files
- ✅ Read file header (version, snaplen, datalink, endianness, ts_resolution)
- ✅ Iterate through packets
- ✅ Access packet timestamp, original length, and raw data
- ✅ Proper resource cleanup
- ✅ High-level streaming API (Elixir Stream protocol)
- ✅ Comprehensive documentation

**Phase 2 - PCAPNG Support** ✅ **COMPLETED**
- ✅ Open and parse PCAPNG files
- ✅ Handle Section Header Block (automatically via pcap-file crate)
- ✅ Handle Interface Description Block (automatically via pcap-file crate)
- ✅ Handle Enhanced Packet Block
- ✅ Stream packets from PCAPNG
- ✅ Tests with PCAPNG files (10 comprehensive tests)
- ✅ Format auto-detection (PCAP vs PCAPNG magic numbers)

**Phase 3 - Enhanced Features** ✅ **COMPLETED**
- ✅ File validation helpers (`PcapFileEx.Validator`)
  - Format detection (PCAP vs PCAPNG)
  - File accessibility checks
  - File size queries
- ✅ Statistics functions (`PcapFileEx.Stats`)
  - Packet count, total bytes
  - Time range and duration
  - Size distribution (min, max, median, percentiles)
  - Comprehensive stats computation
- ✅ Packet filtering DSL (`PcapFileEx.Filter`)
  - Size-based filtering (range, larger/smaller than)
  - Time-based filtering (range, before/after)
  - Content-based filtering (contains, regex)
  - Sampling and limiting
  - Custom predicates
  - Chainable filters

**Phase 4 - Advanced (Optional)** 📋 **FUTURE**
- [ ] Write support (create PCAP/PCAPNG files)
- [ ] Protocol parsing helpers (Ethernet, IP, TCP, UDP)
- [ ] Packet slicing/truncation handling
- [ ] Performance benchmarks
- [ ] Opt-in automatic payload decoding for supported application protocols

---

## ARCHITECTURE

### Actual Directory Structure (Current)
```
pcap_file_ex/
├── lib/
│   ├── pcap_file_ex.ex              # ✅ Main public API with format auto-detection
│   └── pcap_file_ex/
│       ├── native.ex                # ✅ NIF declarations (private)
│       ├── pcap.ex                  # ✅ PCAP reader
│       ├── pcapng.ex                # ✅ PCAPNG reader
│       ├── stream.ex                # ✅ Lazy streaming API (PCAP)
│       ├── packet.ex                # ✅ Packet struct
│       └── header.ex                # ✅ Header struct (PCAP only)
├── native/
│   └── pcap_file_ex/
│       ├── Cargo.toml               # ✅ Rust deps (GitHub pcap-file)
│       └── src/
│           ├── lib.rs               # ✅ Rustler init
│           ├── pcap.rs              # ✅ PCAP NIFs
│           ├── pcapng.rs            # ✅ PCAPNG NIFs
│           └── types.rs             # ✅ Type conversions
├── test/
│   ├── test_helper.exs              # ✅ Test setup
│   ├── pcap_file_ex_test.exs       # ✅ Main API tests
│   └── pcap_file_ex/
│       ├── pcap_test.exs            # ✅ PCAP reader tests (10 tests)
│       └── pcapng_test.exs          # ✅ PCAPNG reader tests (10 tests)
├── test/fixtures/                   # ✅ Test file generation
│   ├── http_server.py               # ✅ Test HTTP server
│   ├── http_client.py               # ✅ Test HTTP client
│   ├── capture_test_traffic.sh      # ✅ Automated capture script (both formats)
│   ├── sample.pcap                  # ✅ Generated PCAP test file
│   ├── sample.pcapng                # ✅ Generated PCAPNG test file
│   └── README.md                    # ✅ Fixture documentation
├── docs/
│   └── userguide.md                 # ✅ Comprehensive user guide
├── PLAN.md                          # ✅ This file
├── CLAUDE.md                        # ✅ Developer guide
└── README.md                        # ✅ Project overview
```

### Key Elixir Modules

#### 1. PcapFileEx (Public API)
High-level convenience functions with automatic format detection:
```elixir
PcapFileEx.open(path)              # ✅ Auto-detect format (PCAP/PCAPNG)
PcapFileEx.read_all(path)          # ✅ Read all packets (list)
PcapFileEx.stream(path)            # ✅ Stream packets lazily
```

#### 2. PcapFileEx.Pcap
```elixir
defmodule PcapFileEx.Pcap do
  @type t :: %__MODULE__{
    reference: reference(),
    header: PcapFileEx.Header.t()
  }
  defstruct [:reference, :header]

  @spec open(Path.t()) :: {:ok, t()} | {:error, String.t()}
  @spec close(t()) :: :ok
  @spec next_packet(t()) :: {:ok, PcapFileEx.Packet.t()} | :eof | {:error, String.t()}
end
```

#### 3. PcapFileEx.PcapNg
```elixir
defmodule PcapFileEx.PcapNg do
  @type t :: %__MODULE__{
    reference: reference(),
    path: String.t()
  }
  defstruct [:reference, :path]

  @spec open(Path.t()) :: {:ok, t()} | {:error, String.t()}
  @spec close(t()) :: :ok
  @spec next_packet(t()) :: {:ok, PcapFileEx.Packet.t()} | :eof | {:error, String.t()}
  @spec interfaces(t()) :: {:ok, [PcapFileEx.Interface.t()]} | {:error, String.t()}
end
```

#### 4. Data Structures
```elixir
defmodule PcapFileEx.Header do
  @type t :: %__MODULE__{
    version_major: non_neg_integer(),
    version_minor: non_neg_integer(),
    snaplen: non_neg_integer(),
    datalink: atom(),
    ts_resolution: :microsecond | :nanosecond,
    endianness: :big | :little
  }
  defstruct [:version_major, :version_minor, :snaplen,
             :datalink, :ts_resolution, :endianness]
end

defmodule PcapFileEx.Packet do
  @type t :: %__MODULE__{
    timestamp: DateTime.t(),
    orig_len: non_neg_integer(),
    data: binary(),
    datalink: String.t() | nil,
    timestamp_resolution: PcapFileEx.Interface.timestamp_resolution() | nil,
    interface_id: non_neg_integer() | nil,
    interface: PcapFileEx.Interface.t() | nil
  }
  defstruct [:timestamp, :orig_len, :data, :datalink, :timestamp_resolution, :interface_id, :interface]
end

defmodule PcapFileEx.Interface do
  @type t :: %__MODULE__{
    id: non_neg_integer(),
    name: String.t() | nil,
    description: String.t() | nil,
    linktype: String.t(),
    snaplen: non_neg_integer(),
    timestamp_resolution: :microsecond | :nanosecond | :unknown,
    timestamp_offset_secs: non_neg_integer()
  }
  defstruct [:id, :name, :description, :linktype, :snaplen, :timestamp_resolution, :timestamp_offset_secs]
end
```

### Rust Implementation Strategy

#### Resource Management
- Use `rustler::Resource` for `PcapReader` and `PcapNgReader`
- Store file handles as opaque Rust resources
- Implement `Drop` trait for automatic cleanup
- Provide explicit `close()` function

#### Memory Strategy
- **Small packets**: Copy data directly to Elixir binary via `OwnedBinary`
- **Streaming**: Iterator-based, one packet at a time
- **No buffering**: Let Elixir control memory via lazy streams

#### Type Conversions (Rust → Elixir)
```
Duration               → DateTime (convert via epoch + nanos)
Vec<u8> / &[u8]        → binary()
u32, u16, i32          → integer()
DataLink enum          → atom (:ethernet, :raw, :ipv4, etc.)
TsResolution enum      → atom (:microsecond, :nanosecond)
Endianness enum        → atom (:big, :little)
Result<T, PcapError>   → {:ok, T} | {:error, String.t()}
```

#### Error Handling
Map `PcapError` variants to descriptive strings:
- `IncompleteBuffer` → "Incomplete data in file"
- `IoError(e)` → Format IO error message
- `InvalidField(msg)` → msg
- etc.

---

## TECHNICAL DECISIONS

### 1. Dependency on pcap-file
**Decision**: Use path dependency to `../pcap-file`

**Cargo.toml**:
```toml
[dependencies]
rustler = "0.37.1"
pcap-file = { path = "../../../../pcap-file" }
thiserror = "1.0"
```

**Rationale**:
- Direct access to local Rust library
- No need to publish to crates.io
- Easy to update/modify

### 2. API Design Philosophy
1. **Streaming first**: Don't load entire file into memory
2. **Resource safety**: Explicit close or use `with`-style helpers
3. **Type safety**: Structs over tuples
4. **Ergonomic**: High-level helpers + low-level control

### 3. Timestamp Handling
**Decision**: Convert Rust `Duration` to Elixir `DateTime`

**Implementation**:
- Parse epoch seconds + nanoseconds from `Duration`
- Use `DateTime.from_unix!/2` with `:nanosecond` precision
- Handle microsecond vs nanosecond resolution

### 4. DataLink Mapping
**Decision**: Map common types to atoms, use `{:unknown, n}` for others

**Examples**:
- `DataLink::ETHERNET` → `:ethernet`
- `DataLink::RAW` → `:raw`
- `DataLink::IEEE802_11` → `:ieee802_11`
- `DataLink::Unknown(123)` → `{:unknown, 123}`

---

## IMPLEMENTATION PROGRESS

### ✅ Phase 1: PCAP Support - **COMPLETED**

#### ✅ Step 1: Initialize Rust NIF Structure
- ✅ Created `native/pcap_file_ex` directory
- ✅ Created `native/pcap_file_ex/Cargo.toml` with GitHub dependency
- ✅ Created `native/pcap_file_ex/src/lib.rs`
- ✅ Configured Rustler in mix.exs
- ✅ Tested basic NIF loading

#### ✅ Step 2: Implement Basic PCAP Support (Rust)
- ✅ Created `src/pcap.rs` with NIFs:
  - ✅ `pcap_open(path)` → `Result<ResourceArc<PcapReaderResource>, Error>`
  - ✅ `pcap_close(reader)` → `Atom`
  - ✅ `pcap_get_header(reader)` → `Result<HeaderMap, Error>`
  - ✅ `pcap_next_packet(reader)` → `Result<Option<PacketMap>, Error>`
- ✅ Created `src/types.rs` with conversions:
  - ✅ `pcap_header_to_map(PcapHeader)` → Elixir map
  - ✅ `pcap_packet_to_map(PcapPacket)` → Elixir map
  - ✅ `datalink_to_string(DataLink)` → String
  - ✅ Timestamp handling (Duration → secs + nanos)
- ✅ Error handling via rustler::Error

#### ✅ Step 3: Implement PCAP Elixir Wrapper
- ✅ Created `lib/pcap_file_ex/native.ex` with NIF stubs
- ✅ Created `lib/pcap_file_ex/header.ex` with struct and conversion
- ✅ Created `lib/pcap_file_ex/packet.ex` with struct and DateTime conversion
- ✅ Created `lib/pcap_file_ex/pcap.ex` with full API
- ✅ Added typespecs to all functions

#### ✅ Step 4: Testing & Validation
- ✅ Created test infrastructure:
  - ✅ Python HTTP server for generating test traffic
  - ✅ Python HTTP client for making requests
  - ✅ Automated capture script using dumpcap
  - ✅ Test fixtures README with documentation
- ✅ Wrote comprehensive tests in `test/pcap_file_ex/pcap_test.exs`:
  - ✅ Test opening valid file
  - ✅ Test reading header
  - ✅ Test iterating packets
  - ✅ Test EOF handling
  - ✅ Test resource cleanup
  - ✅ Test error cases (invalid file, missing file)
  - ✅ Test read_all convenience function
- ✅ **All 10 tests passing**

#### ✅ Step 5: High-Level API & Streaming
- ✅ Implemented `PcapFileEx.open/1` convenience function
- ✅ Implemented `PcapFileEx.stream/1` using Stream.resource
- ✅ Implemented `PcapFileEx.read_all/1` convenience function
- ✅ Created `lib/pcap_file_ex/stream.ex` with lazy streaming
- ✅ Added comprehensive @doc documentation

#### ✅ Step 6: Documentation & Polish
- ✅ Added @moduledoc to all modules
- ✅ Added @doc to all public functions
- ✅ Created comprehensive user guide (`docs/userguide.md`)
- ✅ Updated README.md with examples and architecture
- ✅ Updated CLAUDE.md with developer guide
- ✅ Updated PLAN.md with progress (this file)

### 🚧 Phase 2: PCAPNG Support - **PLANNED**

#### 📋 Step 7: PCAPNG Rust Implementation
- [ ] Create `src/pcapng.rs` with NIFs
- [ ] Implement block reading and parsing
- [ ] Handle different block types
- [ ] Add PCAPNG-specific type conversions

#### 📋 Step 8: PCAPNG Elixir Wrapper
- [ ] Create `lib/pcap_file_ex/pcapng.ex`
- [ ] Define block structs
- [ ] Implement reader API
- [ ] Add tests with PCAPNG files

### 🚧 Phase 3: Enhanced Features - **PLANNED**

#### 📋 Step 9: Statistics & Analysis
- [ ] Add packet counting functions
- [ ] Add byte counting functions
- [ ] Add time range analysis
- [ ] Add basic protocol detection

#### 📋 Step 10: Advanced Features - **FUTURE**
- [ ] Format auto-detection
- [ ] Filtering DSL
- [ ] Write support
- [ ] Protocol parsing helpers
- [ ] Performance benchmarks

---

## Current Implementation Status

### Working Features ✅

All Phase 1 features are fully implemented and tested:

1. **File Operations**
   - Open/close PCAP files
   - Read file headers
   - Iterate through packets
   - Automatic resource cleanup

2. **Data Access**
   - Packet timestamps (as DateTime)
   - Nanosecond timestamp precision preserved when capture provides it
   - Original packet length
   - Raw packet data (binary)
   - Header metadata (version, snaplen, datalink, etc.)
   - PCAPNG interface metadata (id, linktype, resolution, snaplen)

3. **APIs**
   - Low-level: `PcapFileEx.Pcap` module
   - High-level: `PcapFileEx` convenience functions
   - Streaming: `PcapFileEx.stream/1` for large files
   - PCAPNG interface metadata via `PcapFileEx.PcapNg.interfaces/1`

4. **Type Safety**
   - `PcapFileEx.Packet` struct
   - `PcapFileEx.Header` struct
   - Full typespec coverage

5. **Testing**
   - 10 comprehensive tests (all passing)
   - Test traffic generation scripts
   - Error handling tests

### API Usage Examples

#### Basic PCAP Reading
```elixir
# Low-level API
{:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
header = reader.header
IO.inspect(header.datalink)  # "ethernet"

{:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
IO.inspect(packet.timestamp)  # ~U[2025-11-02 12:34:56.123456Z]
IO.inspect(byte_size(packet.data))  # 1514

PcapFileEx.Pcap.close(reader)
```

#### Streaming All Packets
```elixir
# High-level streaming API
PcapFileEx.stream("capture.pcap")
|> Stream.filter(fn packet -> packet.orig_len > 1000 end)
|> Stream.map(fn packet -> parse_ethernet(packet.data) end)
|> Enum.take(10)
```

#### Reading All Packets
```elixir
{:ok, packets} = PcapFileEx.read_all("capture.pcap")
IO.puts("Read #{length(packets)} packets")
```

---

## Testing Strategy

### Test Files
1. **Small PCAP**: 10 packets, generated with dumpcap
2. **Small PCAPNG**: 10 packets, generated with dumpcap
3. **Invalid file**: Random bytes
4. **Empty file**: 0 bytes
5. **Large file**: 10,000+ packets (performance test)
6. **Multi-interface PCAPNG (nanosecond)**: Optional capture validating per-interface metadata

### Test Cases
- ✅ Open valid PCAP file
- ✅ Read header correctly
- ✅ Iterate all packets
- ✅ Handle end-of-file gracefully
- ✅ Error on invalid file
- ✅ Error on missing file
- ✅ Resource cleanup (no leaks)
- ✅ Concurrent readers
- ✅ Stream integration
- ✅ PCAPNG format
- ✅ Mixed block types

### Dumpcap Commands
```bash
# Capture to PCAPNG
/opt/homebrew/bin/dumpcap -i any -w sample.pcapng -c 100

# Capture to PCAP (if supported)
/opt/homebrew/bin/dumpcap -i any -w sample.pcap -c 100 -P

# Multi-interface capture with nanosecond timestamps (script helper)
cd test/fixtures && ./capture_test_traffic.sh --interfaces lo0,en0 --nanosecond

# Or convert with tshark/editcap
```

---

## Future Enhancements

1. **Writing Support**: Create PCAP/PCAPNG files
2. **Packet Parsing**: Parse Ethernet/IP/TCP layers
3. **Filtering DSL**: Query language for packet selection
4. **Statistics**: Protocol distribution, bandwidth analysis
5. **Merging**: Combine multiple capture files
6. **Slicing**: Extract time ranges or packet ranges
7. **Format Conversion**: PCAP ↔ PCAPNG

---

## References

- [pcap-file crate](https://github.com/courvoif/pcap-file)
- [pcap-file docs](https://docs.rs/pcap-file/)
- [Rustler](https://github.com/rusterlium/rustler)
- [Explorer reference](https://github.com/elixir-explorer/explorer)
- [PCAP format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [PCAPNG spec](https://github.com/pcapng/pcapng)
