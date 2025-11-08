# PcapFileEx

High-performance Elixir library for reading and parsing PCAP (Packet Capture) files.

## Features

- ✅ **Fast Binary Parsing** - Rust NIF implementation for high performance
- ✅ **Pre-Filtering** - BPF-style filtering in Rust layer (10-100x speedup for selective queries)
- ✅ **Memory Efficient** - Lazy streaming support for large files
- ✅ **Type Safe** - Elixir structs with proper typespecs
- ✅ **Simple API** - Easy-to-use functions for common tasks
- ✅ **PCAP Support** - Read legacy PCAP format files (microsecond and nanosecond precision)
- ✅ **PCAPNG Support** - Read next-generation PCAPNG format files
- ✅ **Interface Metadata** - Surface interface descriptors and timestamp resolution from PCAPNG captures
- ✅ **Timestamp Precision** - Automatic detection and support for both microsecond and nanosecond timestamp formats
- ✅ **Auto-Detection** - Automatic format detection based on magic numbers
- ✅ **Cross-Platform** - Works with PCAP files from macOS (microsecond) and Linux (nanosecond) without conversion
- ✅ **TCP Reassembly** - Reassemble HTTP messages split across multiple TCP packets
- ✅ **HTTP Body Decoding** - Automatic decoding of JSON, ETF, form data, and text bodies
- ✅ **Statistics** - Compute packet counts, sizes, time ranges, and distributions
- ✅ **Filtering** - Rich DSL for filtering packets by size, time, content
- ✅ **Validation** - File format validation and accessibility checks

## Installation

### From Git (Current)

Add `pcap_file_ex` as a Git dependency in your `mix.exs`:

```elixir
def deps do
  [
    {:pcap_file_ex, git: "https://github.com/lucian/pcap_file_ex.git"}
  ]
end
```

Then fetch dependencies and compile:

```bash
mix deps.get
mix compile
```

**Requirements:**
- Elixir ~> 1.19
- **Rust toolchain** (cargo, rustc) - Required for compiling native extensions
- Erlang/OTP 24+

> **Note:** When using as a Git dependency, the Rust toolchain must be installed on your system. The native code will be compiled automatically during `mix compile`.

### From Hex (Coming Soon)

Once published to Hex, installation will be:

```elixir
def deps do
  [
    {:pcap_file_ex, "~> 0.1.0"}
  ]
end
```

Precompiled binaries will be available for common platforms (Linux, macOS, Windows), eliminating the need for a Rust toolchain.

## AI-Assisted Development

This library includes comprehensive usage rules for LLM-based coding assistants. If you're using AI tools like Claude Code, GitHub Copilot, or Cursor, the library provides detailed guidance to help generate correct, performant code.

**For AI Assistants:** See [`usage-rules.md`](usage-rules.md) for complete API guidance, common patterns, and performance best practices.

**Key guidance includes:**
- Automatic format detection (always use `PcapFileEx.open/1`)
- Filtering strategy selection (PreFilter for large files = 10-100x faster)
- Resource management patterns
- HTTP body auto-decoding
- Performance optimization techniques

To integrate with your AI workflow using the `usage_rules` package:

```elixir
# In your mix.exs
{:usage_rules, "~> 0.1", only: [:dev]}

# Then sync to your project's AI instructions
mix usage_rules.sync CLAUDE.md pcap_file_ex
```

## Development Setup

### Prerequisites

For developing and testing PcapFileEx, you'll need:

- **Elixir** ~> 1.19
- **Rust toolchain** (cargo, rustc) - For compiling native extensions
- **Erlang/OTP** 24+
- **dumpcap** - For generating test fixtures (optional but recommended)
- **Python 3** - For test traffic generation scripts

### Installing dumpcap

dumpcap is used to generate test fixtures. While optional, some tests will be skipped without it.

#### macOS

```bash
brew install wireshark
```

This installs dumpcap with ChmodBPF, allowing packet capture without sudo.

#### Linux (Ubuntu/Debian)

```bash
# Install dumpcap
sudo apt-get install tshark

# Setup non-root packet capture (recommended)
sudo dpkg-reconfigure wireshark-common  # Select "Yes"
sudo usermod -aG wireshark $USER
newgrp wireshark  # Or logout/login to activate group
```

#### Linux (Fedora/RHEL)

```bash
sudo dnf install wireshark-cli
sudo usermod -aG wireshark $USER
newgrp wireshark
```

#### Linux (Arch)

```bash
sudo pacman -S wireshark-cli
sudo usermod -aG wireshark $USER
newgrp wireshark
```

### Running Tests

```bash
# Clone repository
git clone https://github.com/lucian/pcap_file_ex.git
cd pcap_file_ex

# Fetch dependencies
mix deps.get

# Compile (includes Rust NIF)
mix compile

# Run tests (auto-generates fixtures on first run)
mix test
```

**Manual fixture generation:**

```bash
# Generate all fixtures
mix test.fixtures

# Or manually
cd test/fixtures
./capture_test_traffic.sh
```

### Verifying dumpcap Setup

Check if dumpcap has proper permissions:

```bash
dumpcap -D
```

This should list available network interfaces. If you see a permission error, see the Troubleshooting section below.

## Quick Start

### Read all packets

```elixir
# Works with both PCAP and PCAPNG (auto-detected)
{:ok, packets} = PcapFileEx.read_all("capture.pcap")
{:ok, packets} = PcapFileEx.read_all("capture.pcapng")

Enum.each(packets, fn packet ->
  IO.puts("#{packet.timestamp}: #{byte_size(packet.data)} bytes")
end)

# Opt out of automatic decoding when you only need raw payloads
{:ok, raw_packets} = PcapFileEx.read_all("capture.pcapng", decode: false)
```

### Stream packets (recommended for large files)

```elixir
# Works with both formats - automatically detected
PcapFileEx.stream("large_capture.pcap")
|> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
|> Stream.map(fn packet -> parse_packet(packet.data) end)
|> Enum.take(100)

PcapFileEx.stream("large_capture.pcapng")
|> Enum.count()

# Disable automatic decoder attachment for performance-sensitive pipelines
PcapFileEx.stream("large_capture.pcapng", decode: false)
|> Stream.map(&byte_size(&1.data))
|> Enum.sum()
```

### Manual control

```elixir
{:ok, reader} = PcapFileEx.open("capture.pcap")

# Access file header
IO.inspect(reader.header.datalink)      # "ethernet"
IO.inspect(reader.header.snaplen)       # 65535

# Read packets one by one
{:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
IO.inspect(packet.timestamp)
IO.inspect(packet.orig_len)

# Close when done
PcapFileEx.Pcap.close(reader)
```

### Inspect PCAPNG interfaces

```elixir
{:ok, reader} = PcapFileEx.open("capture.pcapng")
{:ok, interfaces} = PcapFileEx.PcapNg.interfaces(reader)
Enum.each(interfaces, fn iface ->
  IO.puts("#{iface.id}: #{iface.name || iface.linktype} (#{iface.timestamp_resolution})")
end)
```

Each packet from a PCAPNG capture also carries `interface_id`, `interface`, and `timestamp_resolution` fields so you can attribute traffic to specific capture interfaces.

## Examples

### Filter by packet size

```elixir
large_packets =
  PcapFileEx.stream("capture.pcap")
  |> Stream.filter(fn packet -> byte_size(packet.data) > 1500 end)
  |> Enum.to_list()
```

### Count packets

```elixir
count =
  PcapFileEx.stream("capture.pcap")
  |> Enum.count()

IO.puts("Total packets: #{count}")
```

### Time range analysis

```elixir
start_time = ~U[2025-11-02 10:00:00Z]
end_time = ~U[2025-11-02 11:00:00Z]

packets_in_range =
  PcapFileEx.stream("capture.pcap")
  |> Stream.filter(fn packet ->
    DateTime.compare(packet.timestamp, start_time) != :lt and
    DateTime.compare(packet.timestamp, end_time) != :gt
  end)
  |> Enum.to_list()
```

### Process in batches

```elixir
PcapFileEx.stream("capture.pcap")
|> Stream.chunk_every(1000)
|> Enum.each(fn batch ->
  # Process 1000 packets at a time
  analyze_batch(batch)
end)
```

### Compute statistics

```elixir
{:ok, stats} = PcapFileEx.Stats.compute("capture.pcap")
IO.puts("Packets: #{stats.packet_count}")
IO.puts("Total bytes: #{stats.total_bytes}")
IO.puts("Duration: #{stats.duration_seconds}s")
IO.puts("Avg packet size: #{stats.avg_packet_size}")

# For large files (>100MB), use streaming (constant memory)
{:ok, stats} = PcapFileEx.Stats.compute_streaming("huge_10gb.pcap")

# Combine with filtering
tcp_stats =
  PcapFileEx.stream("capture.pcap")
  |> Stream.filter(fn p -> :tcp in p.protocols end)
  |> PcapFileEx.Stats.compute_streaming()
```

### Filter packets

```elixir
# Chain multiple filters
PcapFileEx.stream("capture.pcap")
|> PcapFileEx.Filter.by_size(100..1500)
|> PcapFileEx.Filter.larger_than(500)
|> PcapFileEx.Filter.contains("HTTP")
|> Enum.take(10)

# Time-based filtering
start_time = ~U[2025-11-02 10:00:00Z]
end_time = ~U[2025-11-02 11:00:00Z]

PcapFileEx.stream("capture.pcap")
|> PcapFileEx.Filter.by_time_range(start_time, end_time)
|> Enum.to_list()
```

### Pre-filtering (High Performance)

Pre-filtering applies filters in the Rust layer **before** packets are deserialized to Elixir,
providing 10-100x speedup for selective queries on large files.

```elixir
alias PcapFileEx.PreFilter

# Open a reader and set pre-filters
{:ok, reader} = PcapFileEx.Pcap.open("large_capture.pcap")

# Filter for TCP traffic on port 80
filters = [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(80)
]
:ok = PcapFileEx.Pcap.set_filter(reader, filters)

# Stream only matching packets (filtered in Rust!)
packets = PcapFileEx.Stream.from_reader(reader) |> Enum.take(100)

PcapFileEx.Pcap.close(reader)

# Also works with PCAPNG
{:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
:ok = PcapFileEx.PcapNg.set_filter(reader, [
  PreFilter.ip_source_cidr("192.168.1.0/24"),
  PreFilter.size_min(1000)
])
packets = PcapFileEx.Stream.from_reader(reader) |> Enum.to_list()
PcapFileEx.PcapNg.close(reader)

# Available filter types:
# - PreFilter.ip_source("1.2.3.4")
# - PreFilter.ip_dest("1.2.3.4")
# - PreFilter.ip_source_cidr("192.168.0.0/16")
# - PreFilter.ip_dest_cidr("10.0.0.0/8")
# - PreFilter.port_source(8080)
# - PreFilter.port_dest(443)
# - PreFilter.port_source_range(8000, 9000)
# - PreFilter.port_dest_range(80, 443)
# - PreFilter.protocol("tcp") # tcp, udp, icmp, ipv4, ipv6
# - PreFilter.size_min(100)
# - PreFilter.size_max(1500)
# - PreFilter.size_range(100, 1500)
# - PreFilter.timestamp_min(unix_seconds)
# - PreFilter.timestamp_max(unix_seconds)
# - PreFilter.all([filter1, filter2]) # AND
# - PreFilter.any([filter1, filter2]) # OR
# - PreFilter.negate(filter) # NOT
```

**Performance:** Pre-filters skip non-matching packets before creating Elixir terms,
dramatically reducing memory allocation, GC pressure, and CPU usage. Benchmarks show
7-52x speedup depending on filter selectivity.

### Filter by protocol

```elixir
# Pull only HTTP application payloads
http_packets =
  PcapFileEx.stream("capture.pcapng")
  |> PcapFileEx.Filter.by_protocol(:http)
  |> Enum.to_list()

# Transport-level filtering works the same way
tcp_handshakes =
  PcapFileEx.stream("capture.pcapng")
  |> PcapFileEx.Filter.by_protocol(:tcp)
  |> Enum.take(5)

# Decode filtered packets into structured HTTP messages
decoded_http =
PcapFileEx.stream("capture.pcapng")
|> PcapFileEx.Filter.by_protocol(:http)
|> Enum.map(&PcapFileEx.Packet.decode_http!/1)

# Keep packet metadata + decoded payloads
packets_with_decoded =
  PcapFileEx.stream("capture.pcapng")
  |> Enum.map(&PcapFileEx.Packet.attach_decoded/1)

Enum.each(packets_with_decoded, fn packet ->
  IO.inspect(%{
    timestamp: packet.timestamp,
    src: PcapFileEx.Packet.endpoint_to_string(packet.src),
    dst: PcapFileEx.Packet.endpoint_to_string(packet.dst),
    protocol: packet.protocol,
    decoded: packet.decoded
  })
end)

```

### Decode with the pkt library

```elixir
{:ok, packets} = PcapFileEx.read_all("capture.pcapng")
packet = hd(packets)
decoded = PcapFileEx.Packet.pkt_decode!(packet)
IO.inspect(decoded)

# Inspect supported protocol atoms
IO.inspect(PcapFileEx.Packet.known_protocols())

# Try application decoders registered at runtime
case PcapFileEx.Packet.decode_registered(packet) do
  {:ok, {protocol, value}} -> IO.inspect({protocol, value})
  :no_match -> :noop
  {:error, reason} -> IO.warn("decoder failed: #{inspect(reason)}")
end
```

`decode_registered/1` leaves the packet untouched; call `PcapFileEx.DecoderRegistry.unregister/1`
when you want to remove a custom decoder.

### Display filters

```elixir
PcapFileEx.stream("capture.pcapng")
|> PcapFileEx.DisplayFilter.filter("ip.src == 127.0.0.1 && http.request.method == \"GET\"")
|> Enum.to_list()

# Precompile when reusing across streams
{:ok, filter} = PcapFileEx.DisplayFilter.compile("tcp.srcport == 8899")

PcapFileEx.stream("capture.pcapng")
|> PcapFileEx.DisplayFilter.run(filter)
|> Enum.take(5)

# Inspect available fields
PcapFileEx.DisplayFilter.FieldRegistry.fields()
```

### Validate files

```elixir
{:ok, :pcap} = PcapFileEx.Validator.validate("capture.pcap")
true = PcapFileEx.Validator.pcap?("capture.pcap")
{:ok, size} = PcapFileEx.Validator.file_size("capture.pcap")
```

## Timestamp Precision Support

PcapFileEx automatically detects and supports both **microsecond** and **nanosecond** timestamp precision in PCAP files:

### PCAP Magic Numbers

PCAP files identify their format and timestamp precision via magic numbers in the file header:

| Magic Number | Endianness | Timestamp Precision | Default Platform |
|--------------|------------|-------------------|------------------|
| `0xD4C3B2A1` | Little-endian | Microsecond (µs) | macOS dumpcap |
| `0xA1B2C3D4` | Big-endian | Microsecond (µs) | - |
| `0x4D3CB2A1` | Little-endian | Nanosecond (ns) | Linux dumpcap |
| `0xA1B23C4D` | Big-endian | Nanosecond (ns) | - |

### Cross-Platform Compatibility

**All formats are automatically detected and supported** without configuration:

```elixir
# macOS PCAP (microsecond precision)
{:ok, macos_reader} = PcapFileEx.Pcap.open("capture_macos.pcap")
assert macos_reader.header.ts_resolution == "microsecond"

# Linux PCAP (nanosecond precision)
{:ok, linux_reader} = PcapFileEx.Pcap.open("capture_linux.pcap")
assert linux_reader.header.ts_resolution == "nanosecond"

# Both formats read packets identically
{:ok, packets} = PcapFileEx.Pcap.read_all("any_pcap_file.pcap")
```

### No Timestamp Conversion

Timestamps are **preserved in their original precision** - there is no automatic conversion between microsecond and nanosecond formats. This ensures:

- ✅ Data integrity - original capture precision maintained
- ✅ Lossless processing - no rounding or truncation
- ✅ Cross-platform consistency - files from different OSes work identically

### PCAPNG Format

PCAPNG files have their own timestamp resolution metadata and are fully supported on all platforms.

## Data Structures

### Packet

```elixir
%PcapFileEx.Packet{
  timestamp: ~U[2025-11-02 12:34:56.123456Z],  # DateTime
  orig_len: 1514,                               # Original packet length
  data: <<0x00, 0x01, 0x02, ...>>,             # Raw packet data (binary)
  datalink: "ethernet",                         # Link-layer type for the packet
  protocols: [:ether, :ipv4, :tcp, :http],      # Ordered protocol stack
  protocol: :tcp,                               # Highest decoded protocol (:tcp, :udp, ...)
  src: %PcapFileEx.Endpoint{ip: "127.0.0.1", port: 55014},
  dst: %PcapFileEx.Endpoint{ip: "127.0.0.1", port: 8899},
  layers: [:ipv4, :tcp, :http],                 # Protocol layers (cached)
  payload: "GET /hello ...",                    # Payload used during decoding
  decoded: %{http: %PcapFileEx.HTTP{...}}        # Cached decoded payloads
}

Loopback captures are normalized automatically: the 4-byte pseudo-header is removed and `datalink`
is remapped to `"ipv4"`/`"ipv6"` so that protocol decoders operate directly on the payload.
Call `PcapFileEx.Packet.pkt_decode/1` or `pkt_decode!/1` to hand packets to the [`pkt`](https://hex.pm/packages/pkt) library with the correct link type.
Discover supported protocol atoms via `PcapFileEx.Packet.known_protocols/0`. Use
`PcapFileEx.Packet.attach_decoded/1` to stash decoded payloads back on the packet
struct, or call `PcapFileEx.Packet.decode_registered!/1` to fetch them directly.

> Packets are decoded automatically using registered decoders. Pass `decode: false`
> to `PcapFileEx.read_all/2` or `PcapFileEx.stream/2` when you only need raw payloads
> without attaching decoded metadata.

Pattern matching on endpoints is now straightforward:

```elixir
case packet.src do
  %PcapFileEx.Endpoint{ip: "127.0.0.1", port: 8899} -> :ok
  _ -> :other
end
```

### Custom Decoders

You can extend the application-layer protocol support by registering additional decoders:

```elixir
PcapFileEx.DecoderRegistry.register(%{
  protocol: :my_proto,
  matcher: fn layers, payload ->
    Enum.any?(layers, &match?({:udp, _, _, _, _, _}, &1)) and
      MyProto.match?(IO.iodata_to_binary(payload))
  end,
  decoder: fn payload -> {:ok, MyProto.decode(IO.iodata_to_binary(payload))} end,
  fields: [
    %{id: "myproto.value", type: :integer, extractor: fn decoded -> decoded["value"] end},
    %{id: "myproto.sensor", type: :string, extractor: fn decoded -> decoded["sensor"] end}
  ]
})

{:ok, packets} = PcapFileEx.read_all("capture.pcapng")
packet = Enum.find(packets, &(:my_proto in &1.protocols))
{:ok, {:my_proto, decoded}} = PcapFileEx.Packet.decode_registered(packet)

# Persist the decoded payload on the packet struct
packet = PcapFileEx.Packet.attach_decoded(packet)
decoded = packet.decoded[:my_proto]

# Or get the decoded value directly (raises on decoder error)
decoded = PcapFileEx.Packet.decode_registered!(packet)

# Use the fields in display filters
PcapFileEx.stream("capture.pcapng")
|> Enum.map(&PcapFileEx.Packet.attach_decoded/1)
|> PcapFileEx.DisplayFilter.filter("myproto.value >= 25")
|> Enum.to_list()
```

Remove a decoder with `PcapFileEx.DecoderRegistry.unregister/1`. Inspiration for protocol
analysis logic can be taken from Wireshark dissectors (see the
[Lua dissector example](https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html)).

### Reassemble HTTP streams

```elixir
# Lazily reconstruct HTTP requests with payloads that span multiple packets
PcapFileEx.TCP.stream_http_messages("captures/fixture.pcapng", types: [:request])
|> Enum.each(fn message ->
  IO.puts("#{message.http.method} #{message.http.uri} -> #{byte_size(message.http.body)} bytes")

  # Access automatically decoded body
  case message.http.decoded_body do
    map when is_map(map) -> IO.inspect(map, label: "JSON/ETF data")
    text when is_binary(text) -> IO.puts("Text: #{text}")
    nil -> IO.puts("Empty body")
  end
end)

# Responses are available too
PcapFileEx.TCP.stream_http_messages("captures/fixture.pcapng", types: [:response])
|> Enum.take(3)

# Filter by decoded content
PcapFileEx.TCP.stream_http_messages("capture.pcapng")
|> Stream.filter(fn msg ->
  is_map(msg.http.decoded_body) and msg.http.decoded_body["status"] == "error"
end)
|> Enum.to_list()
```

The helper buffers TCP payloads per direction until the full HTTP message is
assembled (based on `Content-Length` when present) and returns
`%PcapFileEx.TCP.HTTPMessage{}` structs with the decoded `%PcapFileEx.HTTP{}` payload.

### HTTP Message with Automatic Body Decoding

```elixir
%PcapFileEx.HTTP{
  type: :response,
  version: "1.0",
  status_code: 200,
  reason_phrase: "OK",
  headers: %{"content-type" => "application/json", "server" => "SimpleHTTP/0.6 Python/3.13.5"},
  body: "{\"message\":\"Hello, World!\"}",
  body_length: 28,
  complete?: true,
  raw: "HTTP/1.0 200 OK...",
  decoded_body: %{"message" => "Hello, World!"}  # Automatically decoded!
}
```

**Automatic Body Decoding**

HTTP bodies are automatically decoded based on content-type and magic bytes:

- **Erlang Term Format (ETF)** - Detected by magic byte `131`, decoded with `:erlang.binary_to_term/1`
- **JSON** - When `Content-Type` contains "json", decoded with Jason (if available)
- **Form data** - `application/x-www-form-urlencoded` decoded to a map
- **Text** - `text/*` content-types returned as-is
- **Binary** - Unknown types returned as raw binary

If decoding fails (e.g., malformed JSON), the raw binary is preserved. The `decoded_body` field is `nil` for empty bodies.

```elixir
# Example: Filter JSON responses by decoded content
"capture.pcapng"
|> PcapFileEx.TCP.stream_http_responses()
|> Stream.filter(fn msg ->
  is_map(msg.http.decoded_body) and
  Map.get(msg.http.decoded_body, "status") == "success"
end)
|> Enum.to_list()

# Example: Inspect Erlang terms from ETF-encoded requests
"capture.pcapng"
|> PcapFileEx.TCP.stream_http_requests()
|> Enum.each(fn msg ->
  case msg.http.decoded_body do
    term when not is_binary(term) ->
      IO.inspect(term, label: "Decoded ETF term")
    _ -> :skip
  end
end)
```

Use `PcapFileEx.Packet.decode_http/1` (or `decode_http!/1`) to obtain this structure directly from TCP payloads.

```

### Header

```elixir
%PcapFileEx.Header{
  version_major: 2,
  version_minor: 4,
  snaplen: 65535,
  datalink: "ethernet",
  ts_resolution: "microsecond",
  endianness: "little"
}
```

## Generating Test Files

Use the included test scripts to generate both PCAP and PCAPNG files with known traffic:

```bash
cd test/fixtures
./capture_test_traffic.sh
```

This generates:
- `sample.pcap` - Legacy PCAP format
- `sample.pcapng` - Next-generation PCAPNG format

Both files contain the same HTTP traffic for consistent testing.

For large benchmark datasets that mix TCP and UDP across multiple interfaces:

```bash
cd test/fixtures
./capture_heavy_traffic.sh --duration 120 --interfaces lo0,en0
```

This produces `large_capture.pcapng` (and optionally `large_capture.pcap`) plus logs detailing the generated HTTP/UDP load.

Or use `dumpcap` directly:

```bash
# PCAPNG format (default)
dumpcap -i any -w capture.pcapng -c 100

# PCAP format (legacy)
dumpcap -i any -w capture.pcap -c 100 -P
```

See [test/fixtures/README.md](test/fixtures/README.md) for more details.

## Benchmarks

Benchee benchmarks quantify parsing throughput (packets per second) and filter performance.

1. Generate a large capture (see `capture_heavy_traffic.sh` above) or provide your own path.
2. Install dependencies: `mix deps.get`
3. Run the benchmarks:

```bash
mix run bench/pcap_parsing.exs
# or specify a custom capture
PCAP_BENCH_FILE=/path/to/capture.pcapng mix run bench/pcap_parsing.exs
```

Benchmarks cover:
- Streaming parse throughput with and without automatic decoder attachment
- UDP-only filtering performance
- HTTP POST filtering using application-level decoding

Benchee reports iterations-per-second (IPS), average/median runtimes, and memory usage for each scenario. Adjust the capture size, duration, or Benchee options inside `bench/pcap_parsing.exs` to explore additional workloads.

## Documentation

- [User Guide](docs/userguide.md) - Comprehensive usage guide with examples
- [Implementation Plan](PLAN.md) - Architecture and implementation details
- [Developer Guide](CLAUDE.md) - Guide for contributors

## Architecture

PcapFileEx is a hybrid Elixir/Rust project:

- **Elixir Layer** (`lib/`) - Public API, structs, and Stream protocol
- **Rust Layer** (`native/pcap_file_ex/`) - Fast binary parsing via NIFs
- **Underlying Parser** - Wraps the [pcap-file](https://github.com/courvoif/pcap-file) Rust crate

This architecture provides:
- **Performance** - Rust handles intensive binary parsing
- **Safety** - Rustler ensures memory safety across the FFI boundary
- **Ergonomics** - Idiomatic Elixir API with proper structs and typespecs

## Performance

Streaming allows processing of arbitrarily large PCAP files with minimal memory usage:

```elixir
# Process a 10GB file with constant memory usage
PcapFileEx.stream("huge_10gb.pcap")
|> Stream.filter(&interesting?/1)
|> Stream.map(&analyze/1)
|> Enum.take(1000)
```

## Roadmap

- [x] PCAP format reading
- [x] PCAPNG format reading
- [x] Automatic format detection
- [x] Lazy streaming API
- [x] Type-safe structs
- [x] Statistics and analysis
- [x] Packet filtering DSL
- [x] File validation
- [x] Comprehensive tests (65 passing)
- [ ] Packet writing capabilities
- [ ] Protocol parsing helpers (Ethernet, IP, TCP, etc.)

## Troubleshooting

### Tests failing: "No such device" error

**Symptoms:**
```
Error: Interface 'lo0' not found
```

**Cause:** Interface name mismatch between platforms.

**Solution:**

On macOS, loopback is `lo0`. On Linux, it's `lo`. The scripts auto-detect this, but if you're specifying interfaces manually:

```bash
# List available interfaces
cd test/fixtures
./capture_test_traffic.sh --list-interfaces

# Use specific interface
./capture_test_traffic.sh --interfaces en0  # macOS ethernet
./capture_test_traffic.sh --interfaces eth0  # Linux ethernet
```

### Tests failing: "Permission denied" error

**Symptoms:**
```
dumpcap: You don't have permission to capture on that device
```

**Cause:** dumpcap requires elevated privileges for packet capture.

#### macOS Solutions

**Option 1: Install via Homebrew (Recommended)**

```bash
brew install wireshark
```

Wireshark includes ChmodBPF, which grants packet capture permissions automatically.

**Option 2: Grant Terminal Permission**

1. Open System Preferences
2. Go to Security & Privacy → Privacy → Input Monitoring
3. Click the lock to make changes
4. Add Terminal.app (or iTerm.app)

**Verify it works:**

```bash
dumpcap -D  # Should list interfaces without error
```

#### Linux Solutions

**Option 1: Wireshark Group (Recommended)**

```bash
# Configure Wireshark for non-root capture
sudo dpkg-reconfigure wireshark-common  # Select "Yes"

# Add your user to the wireshark group
sudo usermod -aG wireshark $USER

# Activate the group (or logout/login)
newgrp wireshark

# Verify it works
dumpcap -D  # Should list interfaces without error
```

**Option 2: Set Capabilities Manually**

```bash
# Give dumpcap specific capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)

# Verify
dumpcap -D
```

**Option 3: Run with sudo (Least Secure)**

```bash
cd test/fixtures
sudo ./capture_test_traffic.sh
```

This works but requires entering your password and running the entire script as root.

### Tests skipped: "Missing dumpcap"

If dumpcap isn't installed, tests that require generated fixtures will be skipped. This is normal.

To fix, install dumpcap (see Development Setup above) and run:

```bash
mix test.fixtures
```

### Fixture generation fails

**Debug steps:**

1. **Check dumpcap is in PATH:**
   ```bash
   which dumpcap
   dumpcap -v
   ```

2. **Check permissions:**
   ```bash
   dumpcap -D  # Should list interfaces
   ```

3. **Try manual generation:**
   ```bash
   cd test/fixtures
   ./capture_test_traffic.sh --list-interfaces
   ./capture_test_traffic.sh
   ```

4. **Check Python is available:**
   ```bash
   python3 --version
   ```

5. **Look at script output:** The capture scripts provide detailed error messages.

### Still Having Issues?

- Check GitHub Issues: https://github.com/lucian/pcap_file_ex/issues
- Read test/fixtures/README.md for detailed fixture documentation
- Most tests will skip gracefully if fixtures are missing - only 4 tests require generated files

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Testing

```bash
# Run all tests
mix test

# Generate test capture file
cd test/fixtures
./capture_test_traffic.sh sample.pcapng
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Credits

- Built with [Rustler](https://github.com/rusterlium/rustler)
- Uses [pcap-file](https://github.com/courvoif/pcap-file) Rust crate
