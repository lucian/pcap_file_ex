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

# Skip automatic decoder attachment when only raw payloads are needed
{:ok, raw_packets} = PcapFileEx.read_all("small.pcapng", decode: false)
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

payload_bytes =
  PcapFileEx.stream("huge.pcapng", decode: false)
  |> Stream.map(&byte_size(&1.data))
  |> Enum.sum()
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
- `timestamp_resolution` - `atom()` - Resolution atom `:microsecond | :nanosecond | :millisecond | :second | :unknown`
- `interface_id` - `integer() | nil` - Interface index for PCAPNG captures
- `interface` - `%PcapFileEx.Interface{}` - Interface metadata when available
- `protocols` - `[atom()]` - Ordered protocol stack decoded for the packet
- `protocol` - `atom()` - Highest decoded protocol (e.g., `:tcp`, `:udp`)
- `src` - `String.t()` - Source endpoint (IP or IP:port when available)
- `dst` - `String.t()` - Destination endpoint (IP or IP:port when available)
- `layers` - `[term()]` - Raw protocol layer tuples returned by `:pkt`
- `payload` - `binary()` - Payload passed to the last decoded protocol
- `decoded` - `%{optional(atom()) => term()}` - Cached results from application decoders

```elixir
%PcapFileEx.Packet{
  timestamp: ~U[2025-11-02 12:34:56.123456Z],
  orig_len: 1514,
  data: <<0x00, 0x01, 0x02, ...>>,
  datalink: "ethernet",
  timestamp_resolution: :microsecond,
  interface_id: 0,
  interface: %PcapFileEx.Interface{linktype: "ethernet", name: "lo0", snaplen: 262144, timestamp_resolution: :nanosecond, timestamp_offset_secs: 0},
  protocols: [:ether, :ipv4, :tcp, :http],
  protocol: :tcp,
  src: "127.0.0.1:55014",
  dst: "127.0.0.1:8899",
  layers: [:ipv4, :tcp, :http],
  payload: "GET /hello ...",
  decoded: %{http: %PcapFileEx.HTTP{...}}
}
```

> Loopback captures automatically drop the 4-byte pseudo-header and remap `datalink`
> to `"ipv4"`/`"ipv6"`, so downstream protocol decoders can operate directly on the IP payload.
> `protocols` captures the ordered decode stack (mirroring Wireshark columns) with `protocol`
> set to its final entry. Use `PcapFileEx.Packet.known_protocols/0` to inspect supported atoms.
> `PcapFileEx.Packet.pkt_decode/1` (or `pkt_decode!/1`) forwards packets to the [`pkt`](https://hex.pm/packages/pkt)
> library with the proper link-type atom. Registered decoders attach structured payloads
> by default; pass `decode: false` to `PcapFileEx.read_all/2` or `PcapFileEx.stream/2` when
> you want to skip that step. You can still call helpers such as `PcapFileEx.Packet.decode_http/1`,
> `decode_registered!/1`, or `attach_decoded/1` manually whenever you need structured data.

Pattern matching endpoints:

```elixir
case packet.dst do
  %PcapFileEx.Endpoint{ip: "127.0.0.1", port: 8899} -> :target
  _ -> :other
end
```


#### `PcapFileEx.Interface`

Metadata about a capture interface discovered in a PCAPNG file. Populated for packets when the underlying capture exposes Interface Description Blocks.

**Fields:**
- `id` - `integer()` - Interface index
- `name` - `String.t() | nil` - Friendly interface name
- `description` - `String.t() | nil` - Optional description
- `linktype` - `String.t()` - Link-layer type for packets on this interface
- `snaplen` - `integer()` - Capture snapshot length for the interface
- `timestamp_resolution` - `atom()` - Resolution atom `:microsecond | :nanosecond | :millisecond | :second | :unknown`
- `timestamp_offset_secs` - `integer()` - Seconds offset applied to decoded timestamps

`PcapFileEx.PcapNg.interfaces/1` returns this struct for every interface discovered in the capture. Packets also embed the matching interface metadata via the `interface` field when available.

#### `PcapFileEx.HTTP`

Represents a parsed HTTP request or response extracted from a packet payload.

```elixir
%PcapFileEx.HTTP{
  type: :response,
  version: "1.0",
  status_code: 200,
  reason_phrase: "OK",
  headers: %{"content-type" => "application/json"},
  body: "{\"message\":\"Hello, World!\"}",
  body_length: 28,
  complete?: true,
  raw: "HTTP/1.0 200 OK...",
  decoded_body: %{"message" => "Hello, World!"}  # Automatically decoded!
}
```

Use `PcapFileEx.Packet.decode_http/1` (or `decode_http!/1`) to obtain this structure directly.

**Automatic Body Decoding**

The `decoded_body` field is automatically populated based on the Content-Type header and magic bytes:

- **Erlang Term Format (ETF)** - Detected by magic byte `131`, decoded with `:erlang.binary_to_term/1`
- **JSON** - When `Content-Type` contains "json", decoded with Jason (if available)
- **Form data** - `application/x-www-form-urlencoded` decoded to a map
- **Text** - `text/*` content-types returned as-is
- **Binary** - Unknown types returned as raw binary

The decoding is safe and falls back to raw binary if decoding fails. The `decoded_body` field is `nil` for empty bodies.

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

# Keep metadata + decoded payloads together
packets_with_decoded =
  PcapFileEx.stream("capture.pcapng")
  |> Enum.map(&PcapFileEx.Packet.attach_decoded/1)

Enum.each(packets_with_decoded, fn packet ->
  IO.inspect(%{
    ts: packet.timestamp,
    src: PcapFileEx.Packet.endpoint_to_string(packet.src),
    dst: PcapFileEx.Packet.endpoint_to_string(packet.dst),
    protocol: packet.protocol,
    decoded: packet.decoded
  })
end)
```

### Custom Decoders

Register additional protocol decoders at runtime when you need to recognise custom payloads:

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

packet =
  PcapFileEx.stream("capture.pcapng")
  |> Enum.find(&(:my_proto in &1.protocols))

case PcapFileEx.Packet.decode_registered(packet) do
  {:ok, {:my_proto, decoded}} -> IO.inspect(decoded)
  :no_match -> :noop
end

# Persist decoded payload on the packet struct
packet = PcapFileEx.Packet.attach_decoded(packet)
IO.inspect(packet.decoded[:my_proto])

# Remove the decoder when no longer needed
PcapFileEx.DecoderRegistry.unregister(:my_proto)

# Filter using the custom protocol fields
PcapFileEx.stream("capture.pcapng")
|> Enum.map(&PcapFileEx.Packet.attach_decoded/1)
|> PcapFileEx.DisplayFilter.filter("myproto.value >= 20")
|> Enum.to_list()

### Display Filters

```elixir
# Ad-hoc filter
PcapFileEx.stream("capture.pcapng")
|> PcapFileEx.DisplayFilter.filter("ip.dst == 127.0.0.1 && tcp.dstport == 8899")
|> Enum.to_list()

# Compiled filter
{:ok, filter} = PcapFileEx.DisplayFilter.compile("http.request.method == \"GET\"")

PcapFileEx.stream("capture.pcapng")
|> PcapFileEx.DisplayFilter.run(filter)
|> Enum.to_list()

# Inspect available fields
PcapFileEx.DisplayFilter.FieldRegistry.fields()
```
```

For examples of protocol heuristics see Wireshark's
[Lua dissector tutorial](https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html).

### HTTP Body Auto-Decoding

PcapFileEx automatically decodes HTTP message bodies based on Content-Type headers and magic bytes. This eliminates the need for manual decoding and simplifies HTTP traffic analysis.

#### Supported Formats

| Format | Detection Method | Output Type |
|--------|------------------|-------------|
| Erlang Term Format (ETF) | Magic byte `131` | Any Erlang term (map, list, tuple, etc.) |
| JSON | `Content-Type` contains "json" | Map or List |
| Form URL Encoded | `Content-Type: application/x-www-form-urlencoded` | Map |
| Plain Text | `Content-Type: text/*` | String (binary) |
| Unknown/Binary | Default | Raw binary |

#### Basic Usage with TCP Reassembly

```elixir
# Stream HTTP messages - bodies are automatically decoded
"capture.pcap"
|> PcapFileEx.TCP.stream_http_messages(types: :all)
|> Enum.each(fn msg ->
  IO.puts "#{msg.type}: #{msg.http.method || msg.http.status_code}"

  # Access decoded body directly
  case msg.http.decoded_body do
    map when is_map(map) ->
      IO.inspect(map, label: "JSON/Form data")
    term when is_tuple(term) ->
      IO.inspect(term, label: "ETF term")
    text when is_binary(text) ->
      IO.puts("Text: #{text}")
    nil ->
      IO.puts("Empty body")
  end
end)
```

#### Filtering by Decoded Content

```elixir
# Filter JSON responses by decoded field values
error_responses = "capture.pcap"
|> PcapFileEx.TCP.stream_http_responses()
|> Stream.filter(fn msg ->
  is_map(msg.http.decoded_body) and
  msg.http.decoded_body["status"] == "error"
end)
|> Enum.to_list()

# Find specific user IDs in request bodies
user_requests = "capture.pcap"
|> PcapFileEx.TCP.stream_http_requests()
|> Stream.filter(fn msg ->
  match?(%{"user_id" => id} when id > 1000, msg.http.decoded_body)
end)
|> Enum.to_list()
```

#### Working with Erlang Terms

```elixir
# Inspect ETF-encoded messages (common in Elixir/Erlang applications)
"capture.pcap"
|> PcapFileEx.TCP.stream_http_requests()
|> Stream.filter(fn msg ->
  # ETF data is decoded to Erlang terms (not binary)
  not is_binary(msg.http.decoded_body) and not is_nil(msg.http.decoded_body)
end)
|> Enum.each(fn msg ->
  IO.puts "ETF Message:"
  IO.inspect(msg.http.decoded_body, limit: :infinity)
end)
```

#### Pattern Matching on Decoded Data

```elixir
# Pattern match directly on decoded JSON
"capture.pcap"
|> PcapFileEx.TCP.stream_http_messages()
|> Enum.each(fn
  %{http: %{decoded_body: %{"action" => "login", "username" => user}}} ->
    IO.puts "Login attempt: #{user}"

  %{http: %{decoded_body: %{"action" => "logout"}}} ->
    IO.puts "Logout"

  _ ->
    :skip
end)
```

#### Error Handling

All decoding is safe - if decoding fails, the raw binary is preserved:

```elixir
# Invalid JSON or corrupted ETF returns raw binary
msg = %PcapFileEx.HTTP{
  body: "{invalid json",
  headers: %{"content-type" => "application/json"},
  decoded_body: "{invalid json"  # Falls back to raw
}

# You can check if decoding succeeded
case msg.http.decoded_body do
  map when is_map(map) ->
    # Successfully decoded
    IO.inspect(map)
  binary when is_binary(binary) ->
    # Decoding failed or plain text
    IO.puts("Raw body: #{binary}")
end
```

#### Combining with Other Filters

```elixir
# Find large JSON responses with specific status
"capture.pcap"
|> PcapFileEx.TCP.stream_http_responses()
|> Stream.filter(fn msg ->
  msg.http.status_code == 200 and
  msg.http.body_length > 10_000 and
  is_map(msg.http.decoded_body)
end)
|> Enum.each(fn msg ->
  IO.puts "Large JSON response: #{msg.http.body_length} bytes"
  IO.inspect(Map.keys(msg.http.decoded_body), label: "Keys")
end)
```

#### Optional JSON Support

JSON decoding requires the `jason` dependency. If Jason is not available, JSON bodies are returned as raw binary:

```elixir
# Add to mix.exs
def deps do
  [
    {:pcap_file_ex, "~> 0.1.0"},
    {:jason, "~> 1.4"}  # Optional, for JSON decoding
  ]
end
```

Without Jason, the library still works perfectly - JSON just won't be decoded automatically.

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
# Multi-interface + nanosecond timestamps
./capture_test_traffic.sh --interfaces lo0,en0 --nanosecond

# Using dumpcap manually
# PCAPNG format (default)
dumpcap -i any -w test.pcapng -c 100

# PCAP format (legacy)
dumpcap -i any -w test.pcap -c 100 -P

# Using tcpdump (PCAP format)
sudo tcpdump -i any -w test.pcap -c 100
```

The included test script generates both HTTP and UDP telemetry traffic on localhost and captures it in PCAP/PCAPNG formats, providing reproducible packet samples for testing. When run with `--interfaces ... --nanosecond`, it emits an additional `sample_multi_nanosecond.pcapng` fixture alongside the standard `sample.pcapng`/`sample.pcap` pair.

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
