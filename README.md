# PcapFileEx

High-performance Elixir library for reading and parsing PCAP (Packet Capture) files.

## Features

- ✅ **Fast Binary Parsing** - Rust NIF implementation for high performance
- ✅ **Memory Efficient** - Lazy streaming support for large files
- ✅ **Type Safe** - Elixir structs with proper typespecs
- ✅ **Simple API** - Easy-to-use functions for common tasks
- ✅ **PCAP Support** - Read legacy PCAP format files
- ✅ **PCAPNG Support** - Read next-generation PCAPNG format files
- ✅ **Auto-Detection** - Automatic format detection based on magic numbers

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

## Data Structures

### Packet

```elixir
%PcapFileEx.Packet{
  timestamp: ~U[2025-11-02 12:34:56.123456Z],  # DateTime
  orig_len: 1514,                               # Original packet length
  data: <<0x00, 0x01, 0x02, ...>>              # Raw packet data (binary)
}
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

Or use `dumpcap` directly:

```bash
# PCAPNG format (default)
dumpcap -i any -w capture.pcapng -c 100

# PCAP format (legacy)
dumpcap -i any -w capture.pcap -c 100 -P
```

See [test/fixtures/README.md](test/fixtures/README.md) for more details.

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
- [x] Comprehensive tests
- [ ] Packet writing capabilities
- [ ] Protocol parsing helpers (Ethernet, IP, TCP, etc.)
- [ ] Filtering DSL

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

