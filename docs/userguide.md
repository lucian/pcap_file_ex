# PcapFileEx User Guide

## Introduction

PcapFileEx is an Elixir library for reading and parsing PCAP (Packet Capture) files. It provides a high-performance Elixir interface to network packet capture files commonly used with tools like Wireshark, tcpdump, and dumpcap.

### Features

- ✅ Read legacy PCAP format files
- ✅ Read PCAPNG (next-generation) format files
- ✅ Automatic format detection
- ✅ Fast binary parsing via Rust NIFs
- ✅ Lazy streaming for memory-efficient processing of large files
- ✅ Type-safe Elixir structs for packets and headers
- ✅ Simple, ergonomic API
- 🚧 Packet writing (planned)

## Installation

Add `pcap_file_ex` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:pcap_file_ex, "~> 0.1.0"}
  ]
end
```

Then run:

```bash
mix deps.get
mix compile
```

**Note:** First compilation will take longer as it builds the Rust NIF components.

### Requirements

- Elixir ~> 1.19
- Rust toolchain (for compilation)
- Erlang/OTP 24+

## Quick Start

### Reading All Packets

The simplest way to read a PCAP or PCAPNG file (format is auto-detected):

```elixir
# Works with both .pcap and .pcapng files
{:ok, packets} = PcapFileEx.read_all("capture.pcap")
# or
{:ok, packets} = PcapFileEx.read_all("capture.pcapng")

Enum.each(packets, fn packet ->
  IO.puts("Time: #{packet.timestamp}")
  IO.puts("Size: #{byte_size(packet.data)} bytes")
  IO.puts("Original length: #{packet.orig_len}")
end)
```

### Streaming Packets (Recommended for Large Files)

For memory efficiency, stream packets lazily:

```elixir
PcapFileEx.stream("large_capture.pcap")
|> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
|> Stream.map(fn packet -> {packet.timestamp, byte_size(packet.data)} end)
|> Enum.take(10)
```

### Manual Reader Control

For fine-grained control over file operations:

```elixir
# Auto-detect format and open
{:ok, reader} = PcapFileEx.open("capture.pcap")

# For PCAP files, you can access header information
if reader.__struct__ == PcapFileEx.Pcap do
  IO.inspect(reader.header.datalink)      # "ethernet"
  IO.inspect(reader.header.snaplen)       # 65535
  IO.inspect(reader.header.ts_resolution) # "microsecond"
end

# Read packets one by one (works for both PCAP and PCAPNG)
case reader.__struct__.next_packet(reader) do
  {:ok, packet} ->
    IO.inspect(packet)
  :eof ->
    IO.puts("End of file")
  {:error, reason} ->
    IO.puts("Error: #{reason}")
end

# Always close when done
reader.__struct__.close(reader)
```

Or use format-specific modules directly:

```elixir
# PCAP
{:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
{:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
PcapFileEx.Pcap.close(reader)

# PCAPNG
{:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
{:ok, packet} = PcapFileEx.PcapNg.next_packet(reader)
PcapFileEx.PcapNg.close(reader)
```

## API Reference

### Main Module: `PcapFileEx`

#### `open(path)`

Opens a PCAP or PCAPNG file for reading with automatic format detection.

- **Parameters:** `path` - String path to PCAP or PCAPNG file
- **Returns:** `{:ok, reader}` (either `Pcap.t()` or `PcapNg.t()`) or `{:error, reason}`
- **Note:** Format is automatically detected by reading the file's magic number

```elixir
{:ok, reader} = PcapFileEx.open("capture.pcap")
{:ok, reader} = PcapFileEx.open("capture.pcapng")
```

#### `read_all(path)`

Reads all packets from a PCAP or PCAPNG file into memory with automatic format detection.

- **Parameters:** `path` - String path to PCAP or PCAPNG file
- **Returns:** `{:ok, [packet]}` or `{:error, reason}`
- **Warning:** Loads entire file into memory. Use `stream/1` for large files.

```elixir
{:ok, packets} = PcapFileEx.read_all("small.pcap")
{:ok, packets} = PcapFileEx.read_all("small.pcapng")
IO.puts("Read #{length(packets)} packets")
```

#### `stream(path)`

Creates a lazy stream of packets from a PCAP or PCAPNG file with automatic format detection.

- **Parameters:** `path` - String path to PCAP or PCAPNG file
- **Returns:** `Enumerable.t()`
- **Note:** File is automatically opened and closed

```elixir
packet_count =
  PcapFileEx.stream("huge.pcap")
  |> Enum.count()

packet_count =
  PcapFileEx.stream("huge.pcapng")
  |> Enum.count()
```

### Reader Modules

PcapFileEx provides format-specific reader modules:

- `PcapFileEx.Pcap` - For legacy PCAP format
- `PcapFileEx.PcapNg` - For PCAPNG (next-generation) format

Both modules share the same API for reading packets.

### PCAP Reader Module: `PcapFileEx.Pcap`

#### `open(path)`

Opens a PCAP file and returns a reader.

```elixir
{:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
```

#### `close(reader)`

Closes an open reader and releases resources.

```elixir
PcapFileEx.Pcap.close(reader)
```

#### `next_packet(reader)`

Reads the next packet from the file.

- **Returns:**
  - `{:ok, packet}` - Successfully read packet
  - `:eof` - End of file reached
  - `{:error, reason}` - Error reading packet

```elixir
case PcapFileEx.Pcap.next_packet(reader) do
  {:ok, packet} -> process_packet(packet)
  :eof -> IO.puts("Done")
  {:error, reason} -> IO.puts("Error: #{reason}")
end
```

#### `read_all(path)`

Convenience function to read all packets.

```elixir
{:ok, packets} = PcapFileEx.Pcap.read_all("capture.pcap")
```

### PCAPNG Reader Module: `PcapFileEx.PcapNg`

#### `open(path)`

Opens a PCAPNG file and returns a reader.

```elixir
{:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
```

#### `close(reader)`

Closes an open PCAPNG reader and releases resources.

```elixir
PcapFileEx.PcapNg.close(reader)
```

#### `next_packet(reader)`

Reads the next packet from the PCAPNG file. Automatically skips non-packet blocks
(like Section Header, Interface Description, etc.)

- **Returns:**
  - `{:ok, packet}` - Successfully read packet
  - `:eof` - End of file reached
  - `{:error, reason}` - Error reading packet

```elixir
case PcapFileEx.PcapNg.next_packet(reader) do
  {:ok, packet} -> process_packet(packet)
  :eof -> IO.puts("Done")
  {:error, reason} -> IO.puts("Error: #{reason}")
end
```

#### `read_all(path)`

Convenience function to read all packets from a PCAPNG file.

```elixir
{:ok, packets} = PcapFileEx.PcapNg.read_all("capture.pcapng")
```

### Data Structures

#### `PcapFileEx.Packet`

Represents a captured network packet.

**Fields:**
- `timestamp` - `DateTime.t()` - When the packet was captured
- `orig_len` - `integer()` - Original packet length on wire
- `data` - `binary()` - Raw packet data (may be truncated)
- `datalink` - `String.t()` - Link layer type (e.g., `"ethernet"`, `"null"`)
- `protocols` - `[atom()]` - Ordered protocol stack decoded for the packet
- `protocol` - `atom()` - Highest decoded protocol (e.g., `:tcp`, `:udp`)
- `src` - `String.t()` - Source endpoint (IP or IP:port when available)
- `dst` - `String.t()` - Destination endpoint (IP or IP:port when available)

```elixir
%PcapFileEx.Packet{
  timestamp: ~U[2025-11-02 12:34:56.123456Z],
  orig_len: 1514,
  data: <<0x00, 0x01, 0x02, ...>>,
  datalink: "ethernet",
  protocols: [:ether, :ipv4, :tcp, :http],
  protocol: :tcp,
  src: "127.0.0.1:55014",
  dst: "127.0.0.1:8899"
}
```

> Loopback captures automatically drop the 4-byte pseudo-header and remap `datalink`
> to `"ipv4"`/`"ipv6"`, so downstream protocol decoders can operate directly on the IP payload.
> `protocols` captures the ordered decode stack (mirroring Wireshark columns) with `protocol`
> set to its final entry. Use `PcapFileEx.Packet.known_protocols/0` to inspect supported atoms.
> `PcapFileEx.Packet.pkt_decode/1` (or `pkt_decode!/1`) forwards packets to the [`pkt`](https://hex.pm/packages/pkt)
> library with the proper link-type atom. Payloads are not decoded automatically—call
> helpers such as `PcapFileEx.Packet.decode_http/1` when you need structured data.

#### `PcapFileEx.HTTP`

Represents a parsed HTTP request or response extracted from a packet payload.

```elixir
%PcapFileEx.HTTP{
  type: :response,
  version: "1.0",
  status_code: 200,
  reason_phrase: "OK",
  headers: %{"content-type" => "text/plain"},
  body: "Hello, World!",
  body_length: 13,
  complete?: true,
  raw: "HTTP/1.0 200 OK..."
}
```

Use `PcapFileEx.Packet.decode_http/1` (or `decode_http!/1`) to obtain this structure directly.

#### `PcapFileEx.Header`

PCAP file header information.

**Fields:**
- `version_major` - `integer()` - Major version (usually 2)
- `version_minor` - `integer()` - Minor version (usually 4)
- `snaplen` - `integer()` - Maximum packet length captured
- `datalink` - `String.t()` - Link layer type (e.g., "ethernet", "raw")
- `ts_resolution` - `String.t()` - Timestamp resolution ("microsecond" or "nanosecond")
- `endianness` - `String.t()` - Byte order ("big" or "little")

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

## Common Use Cases

### Filtering by Size

```elixir
large_packets =
  PcapFileEx.stream("capture.pcap")
  |> Stream.filter(fn packet -> byte_size(packet.data) > 1500 end)
  |> Enum.to_list()
```

### Time Range Analysis

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

### Filtering by Protocol

```elixir
# Extract HTTP application payloads
http_packets =
  PcapFileEx.stream("capture.pcapng")
  |> PcapFileEx.Filter.by_protocol(:http)
  |> Enum.to_list()

# Inspect just the TCP handshake packets
tcp_packets =
  PcapFileEx.stream("capture.pcapng")
  |> PcapFileEx.Filter.by_protocol(:tcp)
  |> Enum.take(10)

# Decode the HTTP packets once they are enumerated
decoded =
  PcapFileEx.stream("capture.pcapng")
  |> PcapFileEx.Filter.by_protocol(:http)
  |> Enum.map(&PcapFileEx.Packet.decode_http!/1)

# Inspect a single HTTP response
response = List.first(decoded)
IO.inspect(response.headers["content-type"])
IO.puts(response.body)

# List known protocol atoms recognised during decoding
IO.inspect(PcapFileEx.Packet.known_protocols())

# Attempt automatic application decoding using registered decoders
case PcapFileEx.Packet.decode_registered(List.first(http_packets)) do
  {:ok, {protocol, value}} -> IO.inspect({protocol, value})
  :no_match -> :noop
  {:error, reason} -> IO.warn("decoder failed: #{inspect(reason)}")
end
```

### Custom Decoders

Register additional protocol decoders at runtime when you need to recognise custom payloads:

```elixir
PcapFileEx.DecoderRegistry.register(%{
  protocol: :my_proto,
  matcher: fn layers, payload ->
    Enum.any?(layers, &match?({:udp, _, _, _, _, _}, &1)) and MyProto.match?(payload)
  end,
  decoder: fn payload -> {:ok, MyProto.decode(payload)} end
})

packet =
  PcapFileEx.stream("capture.pcapng")
  |> Enum.find(&(:my_proto in &1.protocols))

case PcapFileEx.Packet.decode_registered(packet) do
  {:ok, {:my_proto, decoded}} -> IO.inspect(decoded)
  :no_match -> :noop
end

# Remove the decoder when no longer needed
PcapFileEx.DecoderRegistry.unregister(:my_proto)
```

For examples of protocol heuristics see Wireshark's
[Lua dissector tutorial](https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html).

### Packet Statistics

```elixir
{:ok, reader} = PcapFileEx.open("capture.pcap")

stats =
  PcapFileEx.Stream.from_reader(reader)
  |> Enum.reduce(%{count: 0, total_bytes: 0, min_size: nil, max_size: 0}, fn packet, acc ->
    size = byte_size(packet.data)
    %{
      count: acc.count + 1,
      total_bytes: acc.total_bytes + size,
      min_size: if(acc.min_size, do: min(acc.min_size, size), else: size),
      max_size: max(acc.max_size, size)
    }
  end)

PcapFileEx.Pcap.close(reader)

IO.inspect(stats)
# %{count: 1000, total_bytes: 750000, min_size: 60, max_size: 1514}
```

### Processing Packets in Batches

```elixir
PcapFileEx.stream("capture.pcap")
|> Stream.chunk_every(100)
|> Enum.each(fn batch ->
  # Process 100 packets at a time
  process_batch(batch)
end)
```

### Converting Timestamps

```elixir
PcapFileEx.stream("capture.pcap")
|> Stream.map(fn packet ->
  # Convert to Unix timestamp
  unix_ms = DateTime.to_unix(packet.timestamp, :millisecond)
  {unix_ms, packet.data}
end)
|> Enum.take(10)
```

### Finding Specific Packets

```elixir
# Find first packet containing specific bytes
target = <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>

result =
  PcapFileEx.stream("capture.pcap")
  |> Enum.find(fn packet ->
    :binary.match(packet.data, target) != :nomatch
  end)

case result do
  %PcapFileEx.Packet{} = packet ->
    IO.puts("Found at #{packet.timestamp}")
  nil ->
    IO.puts("Not found")
end
```

### Parallel Processing

```elixir
PcapFileEx.stream("capture.pcap")
|> Task.async_stream(fn packet ->
  # Process each packet in parallel
  analyze_packet(packet)
end, max_concurrency: System.schedulers_online())
|> Stream.run()
```

## Error Handling

All functions that can fail return `{:ok, result}` or `{:error, reason}` tuples.

```elixir
case PcapFileEx.open("capture.pcap") do
  {:ok, reader} ->
    # Process file
    result = do_work(reader)
    PcapFileEx.Pcap.close(reader)
    result

  {:error, reason} ->
    Logger.error("Failed to open PCAP: #{reason}")
    {:error, reason}
end
```

For streaming, errors raise exceptions:

```elixir
try do
  PcapFileEx.stream("capture.pcap")
  |> Enum.to_list()
rescue
  e in RuntimeError ->
    Logger.error("Stream error: #{e.message}")
    []
end
```

## Performance Tips

### 1. Use Streaming for Large Files

```elixir
# BAD: Loads entire file into memory
{:ok, packets} = PcapFileEx.read_all("huge_10gb.pcap")

# GOOD: Streams packets on demand
PcapFileEx.stream("huge_10gb.pcap")
|> Stream.filter(...)
|> Enum.take(1000)
```

### 2. Process in Batches

```elixir
PcapFileEx.stream("capture.pcap")
|> Stream.chunk_every(1000)
|> Enum.each(&process_batch/1)
```

### 3. Early Termination

```elixir
# Stop after finding what you need
PcapFileEx.stream("capture.pcap")
|> Enum.find(&matches_criteria?/1)
```

### 4. Avoid Unnecessary Copying

```elixir
# Don't convert packet data unless necessary
packet.data  # Already a binary, no need to transform
```

## Working with Packet Data

Packet data is returned as raw binary. You'll typically need to parse the protocol layers.

### Ethernet Frame Example

```elixir
defmodule EthernetParser do
  def parse(<<
    dst_mac::binary-size(6),
    src_mac::binary-size(6),
    ethertype::16,
    payload::binary
  >>) do
    %{
      dst_mac: format_mac(dst_mac),
      src_mac: format_mac(src_mac),
      ethertype: ethertype,
      payload: payload
    }
  end

  defp format_mac(<<a, b, c, d, e, f>>) do
    [a, b, c, d, e, f]
    |> Enum.map(&String.pad_leading(Integer.to_string(&1, 16), 2, "0"))
    |> Enum.join(":")
  end
end

# Usage
PcapFileEx.stream("capture.pcap")
|> Stream.map(fn packet -> EthernetParser.parse(packet.data) end)
|> Enum.take(5)
```

### IPv4 Header Example

```elixir
defmodule IPv4Parser do
  def parse(<<
    version::4,
    ihl::4,
    _dscp::6,
    _ecn::2,
    total_length::16,
    _id::16,
    _flags::3,
    _fragment_offset::13,
    ttl::8,
    protocol::8,
    _checksum::16,
    src_ip::binary-size(4),
    dst_ip::binary-size(4),
    rest::binary
  >>) do
    %{
      version: version,
      header_length: ihl * 4,
      total_length: total_length,
      ttl: ttl,
      protocol: protocol_name(protocol),
      src_ip: format_ip(src_ip),
      dst_ip: format_ip(dst_ip),
      payload: rest
    }
  end

  defp format_ip(<<a, b, c, d>>), do: "#{a}.#{b}.#{c}.#{d}"

  defp protocol_name(1), do: :icmp
  defp protocol_name(6), do: :tcp
  defp protocol_name(17), do: :udp
  defp protocol_name(n), do: {:unknown, n}
end
```

## Troubleshooting

### Compilation Errors

**Problem:** `error: failed to compile Rust NIF`

**Solution:** Ensure Rust toolchain is installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### File Not Found

**Problem:** `{:error, "No such file or directory"}`

**Solution:** Check file path and permissions:
```bash
ls -l capture.pcap
```

### Invalid PCAP/PCAPNG Format

**Problem:** `{:error, "Invalid field value: PcapHeader: wrong magic number"}` or `{:error, "Unknown file format"}`

**Solution:** File is not a valid PCAP/PCAPNG file. Verify with:
```bash
file capture.pcap
# Should output: capture.pcap: pcap capture file...

file capture.pcapng
# Should output: capture.pcapng: pcapng capture file...
```

**Note:** The library automatically detects the format. If you get an "Unknown file format" error,
the file may be corrupted or a different format entirely.

### Out of Memory

**Problem:** System runs out of memory reading large file

**Solution:** Use streaming instead of `read_all/1`:
```elixir
# Don't load entire file
PcapFileEx.stream("huge.pcap") |> Stream.take(1000) |> Enum.to_list()
```

## Advanced Topics

### Custom Stream Transformations

```elixir
defmodule MyPcapProcessor do
  def process_file(path) do
    PcapFileEx.stream(path)
    |> add_packet_numbers()
    |> filter_by_protocol(:tcp)
    |> extract_payloads()
  end

  defp add_packet_numbers(stream) do
    Stream.with_index(stream, 1)
    |> Stream.map(fn {packet, num} -> Map.put(packet, :number, num) end)
  end

  defp filter_by_protocol(stream, protocol) do
    Stream.filter(stream, &matches_protocol?(&1, protocol))
  end

  defp extract_payloads(stream) do
    Stream.map(stream, fn packet ->
      # Parse and extract payload
      parse_packet(packet.data)
    end)
  end
end
```

### Resource Management with `with`

```elixir
defmodule SafePcapReader do
  def process(path) do
    with {:ok, reader} <- PcapFileEx.open(path),
         result <- process_packets(reader),
         :ok <- PcapFileEx.Pcap.close(reader) do
      {:ok, result}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp process_packets(reader) do
    do_process(reader, [])
  end

  defp do_process(reader, acc) do
    case PcapFileEx.Pcap.next_packet(reader) do
      {:ok, packet} -> do_process(reader, [process(packet) | acc])
      :eof -> Enum.reverse(acc)
      {:error, _} -> Enum.reverse(acc)
    end
  end
end
```

## Generating Test PCAP/PCAPNG Files

For testing, you can generate PCAP and PCAPNG files with known content:

```bash
# Using included test scripts (generates both formats)
cd test/fixtures
./capture_test_traffic.sh

# Using dumpcap manually
# PCAPNG format (default)
dumpcap -i any -w test.pcapng -c 100

# PCAP format (legacy)
dumpcap -i any -w test.pcap -c 100 -P

# Using tcpdump (PCAP format)
sudo tcpdump -i any -w test.pcap -c 100
```

The included test script generates both HTTP and UDP telemetry traffic on localhost
and captures it in PCAP/PCAPNG formats, providing reproducible packet samples for testing.

See `test/fixtures/README.md` for more details.

## Further Reading

- [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [pcap-file Rust Crate](https://github.com/courvoif/pcap-file)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tcpdump & libpcap](https://www.tcpdump.org/)

## Support

- **Issues:** Report bugs at [GitHub Issues](https://github.com/yourusername/pcap_file_ex/issues)
- **Questions:** Open a discussion on GitHub
- **Contributing:** Pull requests welcome!
