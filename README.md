# PcapFileEx

High-performance Elixir library for reading and parsing PCAP (Packet Capture) files.

## Features

- ✅ **Fast Binary Parsing** - Rust NIF implementation for high performance
- ✅ **Memory Efficient** - Lazy streaming support for large files
- ✅ **Type Safe** - Elixir structs with proper typespecs
- ✅ **Simple API** - Easy-to-use functions for common tasks
- ✅ **PCAP Support** - Read legacy PCAP format files
- ✅ **PCAPNG Support** - Read next-generation PCAPNG format files
- ✅ **Interface Metadata** - Surface interface descriptors and timestamp resolution from PCAPNG captures
- ✅ **Auto-Detection** - Automatic format detection based on magic numbers
- ✅ **TCP Reassembly** - Reassemble HTTP messages split across multiple TCP packets
- ✅ **HTTP Body Decoding** - Automatic decoding of JSON, ETF, form data, and text bodies
- ✅ **Statistics** - Compute packet counts, sizes, time ranges, and distributions
- ✅ **Filtering** - Rich DSL for filtering packets by size, time, content
- ✅ **Validation** - File format validation and accessibility checks

## Installation

Add `pcap_file_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:pcap_file_ex, "~> 0.1.0"}
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
- Rust toolchain (for building native extensions)
- Erlang/OTP 24+

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
- Inspired by [Explorer](https://github.com/elixir-explorer/explorer)
