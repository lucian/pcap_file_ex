# Complete Working Examples

Real-world examples demonstrating common PcapFileEx workflows.

## Example 1: Basic File Reading

### Read All Packets (Small Files)

```elixir
# Read entire file into memory
{:ok, packets} = PcapFileEx.read_all("small_capture.pcap")

IO.puts("Total packets: #{length(packets)}")
IO.puts("First packet timestamp: #{hd(packets).timestamp}")
IO.puts("Protocols in first packet: #{inspect(hd(packets).protocols)}")
```

### Stream Large Files

```elixir
# Process large file with constant memory
packet_count = PcapFileEx.stream!("large_capture.pcap")
|> Enum.count()

IO.puts("Total packets: #{packet_count}")
```

### Manual Control with Reader

```elixir
# Open, process, and close manually
{:ok, reader} = PcapFileEx.open("capture.pcap")

try do
  {:ok, header} = PcapFileEx.Pcap.get_header(reader)
  IO.puts("Datalink: #{header.datalink}")
  IO.puts("Timestamp precision: #{header.ts_resolution}")

  {:ok, first_packet} = PcapFileEx.Pcap.next_packet(reader)
  IO.puts("First packet size: #{byte_size(first_packet.data)}")
after
  PcapFileEx.Pcap.close(reader)
end
```

## Example 2: HTTP API Traffic Analysis

### Extract All POST Requests

```elixir
defmodule APIAnalyzer do
  def extract_post_requests(file_path) do
    PcapFileEx.TCP.stream_http_messages(file_path, types: [:request])
    |> Stream.filter(fn msg ->
      msg.http.method == "POST"
    end)
    |> Enum.map(fn msg ->
      %{
        timestamp: hd(msg.packets).timestamp,
        path: msg.http.path,
        source_ip: hd(msg.packets).src.ip,
        body: msg.http.decoded_body
      }
    end)
  end
end

# Usage
posts = APIAnalyzer.extract_post_requests("api_traffic.pcap")
Enum.each(posts, fn post ->
  IO.puts("#{post.timestamp} - POST #{post.path} from #{post.source_ip}")
  IO.inspect(post.body)
end)
```

### Monitor API Errors

```elixir
defmodule APIMonitor do
  def find_errors(file_path) do
    PcapFileEx.TCP.stream_http_messages(file_path)
    |> Enum.reduce(%{}, fn msg, acc ->
      case msg.direction do
        :response ->
          if msg.http.status_code >= 400 do
            path = get_request_path(msg)
            Map.update(acc, path, [msg], fn msgs -> [msg | msgs] end)
          else
            acc
          end
        _ ->
          acc
      end
    end)
  end

  defp get_request_path(response_msg) do
    # In practice, you'd match request/response pairs
    # Simplified for example
    "unknown"
  end
end

# Usage
errors = APIMonitor.find_errors("api_traffic.pcap")
Enum.each(errors, fn {path, messages} ->
  IO.puts("Errors for #{path}: #{length(messages)}")
end)
```

## Example 3: Performance-Optimized Queries

### Find Specific Traffic in Large File

```elixir
defmodule FastQuery do
  def find_https_to_ip(file_path, target_ip) do
    # Use PreFilter for 10-100x speedup
    {:ok, reader} = PcapFileEx.open(file_path)

    try do
      :ok = PcapFileEx.Pcap.set_filter(reader, [
        PreFilter.protocol("tcp"),
        PreFilter.port_dest(443),
        PreFilter.ip_dest(target_ip)
      ])

      packets = PcapFileEx.Stream.from_reader!(reader)
      |> Enum.take(100)

      IO.puts("Found #{length(packets)} HTTPS packets to #{target_ip}")
      packets
    after
      PcapFileEx.Pcap.close(reader)
    end
  end
end

# Usage - finds packets in seconds, not minutes
packets = FastQuery.find_https_to_ip("huge_10gb.pcap", "10.0.0.1")
```

### Streaming Statistics

```elixir
defmodule StreamingAnalyzer do
  def analyze_large_file(file_path) do
    IO.puts("Analyzing #{file_path}...")

    # Constant memory usage regardless of file size
    {:ok, stats} = PcapFileEx.Stats.compute_streaming(file_path)

    IO.puts("\n=== Traffic Summary ===")
    IO.puts("Total packets: #{stats.total_packets}")
    IO.puts("Total bytes: #{stats.total_bytes}")
    IO.puts("Average packet size: #{div(stats.total_bytes, stats.total_packets)} bytes")

    IO.puts("\n=== Protocol Breakdown ===")
    Enum.each(stats.protocols, fn {protocol, count} ->
      percentage = count / stats.total_packets * 100
      IO.puts("#{protocol}: #{count} (#{Float.round(percentage, 2)}%)")
    end)

    IO.puts("\n=== Top Endpoints ===")
    top_sources = stats.endpoints
    |> Enum.sort_by(fn {_endpoint, count} -> count end, :desc)
    |> Enum.take(10)

    Enum.each(top_sources, fn {endpoint, count} ->
      IO.puts("#{endpoint.ip}:#{endpoint.port || "*"} - #{count} packets")
    end)
  end
end

# Usage - works on files larger than RAM
StreamingAnalyzer.analyze_large_file("huge_20gb.pcap")
```

## Example 4: Security Analysis

### Detect SQL Injection Attempts

```elixir
defmodule SecurityScanner do
  @sqli_patterns [
    ~r/('|")\s*(OR|AND)\s*('|")/i,
    ~r/UNION.*SELECT/i,
    ~r/;\s*DROP\s+TABLE/i,
    ~r/--/,
    ~r/\/\*/
  ]

  def scan_for_sqli(file_path) do
    PcapFileEx.TCP.stream_http_messages(file_path, types: [:request])
    |> Stream.filter(&has_sqli_pattern?/1)
    |> Enum.map(fn msg ->
      %{
        timestamp: hd(msg.packets).timestamp,
        source_ip: hd(msg.packets).src.ip,
        method: msg.http.method,
        path: msg.http.path,
        suspicious_content: find_suspicious_parts(msg)
      }
    end)
  end

  defp has_sqli_pattern?(msg) do
    querystring = extract_query(msg.http.path)
    body = msg.http.body || ""

    Enum.any?(@sqli_patterns, fn pattern ->
      Regex.match?(pattern, querystring) or Regex.match?(pattern, body)
    end)
  end

  defp extract_query(path) do
    case String.split(path || "", "?") do
      [_, query] -> query
      _ -> ""
    end
  end

  defp find_suspicious_parts(msg) do
    # Return matched patterns for reporting
    querystring = extract_query(msg.http.path)

    Enum.filter(@sqli_patterns, fn pattern ->
      Regex.match?(pattern, querystring)
    end)
    |> Enum.map(&Regex.source/1)
  end
end

# Usage
attacks = SecurityScanner.scan_for_sqli("web_traffic.pcap")
IO.puts("Found #{length(attacks)} potential SQL injection attempts")
Enum.each(attacks, fn attack ->
  IO.puts("\n#{attack.timestamp}")
  IO.puts("  Source: #{attack.source_ip}")
  IO.puts("  #{attack.method} #{attack.path}")
  IO.puts("  Patterns: #{inspect(attack.suspicious_content)}")
end)
```

### Find Unauthorized Access Attempts

```elixir
defmodule AccessMonitor do
  def find_unauthorized_attempts(file_path) do
    PcapFileEx.TCP.stream_http_messages(file_path)
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.filter(fn
      [%{direction: :request}, %{direction: :response}] = pair ->
        is_auth_failure?(pair)
      _ ->
        false
    end)
    |> Enum.map(fn [req, resp] ->
      %{
        timestamp: hd(req.packets).timestamp,
        source_ip: hd(req.packets).src.ip,
        path: req.http.path,
        status: resp.http.status_code,
        credentials: extract_credentials(req)
      }
    end)
  end

  defp is_auth_failure?([req, resp]) do
    auth_path?(req.http.path) and resp.http.status_code in [401, 403]
  end

  defp auth_path?(path) do
    path in ["/login", "/api/auth", "/authenticate"]
  end

  defp extract_credentials(req) do
    case req.http.decoded_body do
      %{"username" => username} -> %{username: username}
      _ -> %{}
    end
  end
end

# Usage
failures = AccessMonitor.find_unauthorized_attempts("auth_traffic.pcap")
IO.puts("Found #{length(failures)} failed authentication attempts")

# Group by source IP
by_ip = Enum.group_by(failures, & &1.source_ip)
Enum.each(by_ip, fn {ip, attempts} ->
  IO.puts("\n#{ip}: #{length(attempts)} failed attempts")
  if length(attempts) > 5 do
    IO.puts("  ⚠️  WARNING: Potential brute force attack!")
  end
end)
```

## Example 5: Network Debugging

### Track TCP Connections

```elixir
defmodule ConnectionTracker do
  def track_connections(file_path) do
    PcapFileEx.stream!(file_path)
    |> Stream.filter(fn p -> :tcp in p.protocols end)
    |> Enum.reduce(%{}, fn packet, connections ->
      conn_key = connection_key(packet)
      update_connection(connections, conn_key, packet)
    end)
    |> Map.values()
    |> Enum.filter(&connection_complete?/1)
  end

  defp connection_key(packet) do
    {packet.src, packet.dst}
  end

  defp update_connection(connections, key, packet) do
    Map.update(connections, key, %{
      src: packet.src,
      dst: packet.dst,
      start_time: packet.timestamp,
      end_time: packet.timestamp,
      packet_count: 1,
      bytes: byte_size(packet.data),
      syn: has_syn_flag?(packet),
      fin: has_fin_flag?(packet)
    }, fn conn ->
      %{conn |
        end_time: packet.timestamp,
        packet_count: conn.packet_count + 1,
        bytes: conn.bytes + byte_size(packet.data),
        fin: conn.fin or has_fin_flag?(packet)
      }
    end)
  end

  defp has_syn_flag?(packet), do: false  # Simplified
  defp has_fin_flag?(packet), do: false  # Simplified

  defp connection_complete?(conn) do
    conn.syn and conn.fin
  end
end

# Usage
connections = ConnectionTracker.track_connections("network_capture.pcap")
IO.puts("Found #{length(connections)} complete TCP connections")

Enum.each(connections, fn conn ->
  duration = DateTime.diff(conn.end_time, conn.start_time, :second)
  IO.puts("\n#{conn.src.ip}:#{conn.src.port} -> #{conn.dst.ip}:#{conn.dst.port}")
  IO.puts("  Duration: #{duration}s")
  IO.puts("  Packets: #{conn.packet_count}")
  IO.puts("  Bytes: #{conn.bytes}")
end)
```

### Bandwidth Analysis

```elixir
defmodule BandwidthAnalyzer do
  def analyze_by_second(file_path) do
    PcapFileEx.stream!(file_path)
    |> Enum.reduce(%{}, fn packet, acc ->
      # Truncate to second
      second = %{packet.timestamp | microsecond: {0, 6}}
      bytes = byte_size(packet.data)

      Map.update(acc, second, bytes, & &1 + bytes)
    end)
    |> Enum.sort_by(fn {timestamp, _bytes} -> timestamp end)
  end

  def find_peak_usage(file_path) do
    by_second = analyze_by_second(file_path)

    {peak_time, peak_bytes} = Enum.max_by(by_second, fn {_time, bytes} -> bytes end)

    IO.puts("Peak bandwidth:")
    IO.puts("  Time: #{peak_time}")
    IO.puts("  Bytes/second: #{peak_bytes}")
    IO.puts("  Mbps: #{Float.round(peak_bytes * 8 / 1_000_000, 2)}")

    # Show top 10 seconds
    IO.puts("\nTop 10 seconds by bandwidth:")
    by_second
    |> Enum.sort_by(fn {_time, bytes} -> bytes end, :desc)
    |> Enum.take(10)
    |> Enum.each(fn {time, bytes} ->
      mbps = Float.round(bytes * 8 / 1_000_000, 2)
      IO.puts("  #{time} - #{mbps} Mbps")
    end)
  end
end

# Usage
BandwidthAnalyzer.find_peak_usage("network_capture.pcap")
```

## Example 6: Protocol-Specific Analysis

### DNS Query Analysis

```elixir
defmodule DNSAnalyzer do
  def analyze_queries(file_path) do
    PcapFileEx.stream!(file_path)
    |> Stream.filter(fn p -> :dns in p.protocols end)
    |> Enum.reduce(%{queries: [], responses: []}, fn packet, acc ->
      # Simplified - would need actual DNS parsing
      if packet.src.port == 53 do
        %{acc | responses: [packet | acc.responses]}
      else
        %{acc | queries: [packet | acc.queries]}
      end
    end)
  end

  def find_suspicious_domains(file_path) do
    # Look for queries to suspicious TLDs or patterns
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]

    PcapFileEx.stream!(file_path)
    |> Stream.filter(fn p -> :dns in p.protocols end)
    |> Stream.filter(fn _packet ->
      # Would check actual DNS query name
      # Simplified for example
      false
    end)
    |> Enum.to_list()
  end
end
```

### HTTPS/TLS Traffic

```elixir
defmodule TLSAnalyzer do
  def find_tls_connections(file_path) do
    {:ok, reader} = PcapFileEx.open(file_path)

    try do
      # PreFilter for port 443
      :ok = PcapFileEx.Pcap.set_filter(reader, [
        PreFilter.protocol("tcp"),
        PreFilter.port_dest(443)
      ])

      PcapFileEx.Stream.from_reader!(reader)
      |> Enum.group_by(fn packet ->
        {packet.src, packet.dst}
      end)
      |> Map.keys()
      |> length()
    after
      PcapFileEx.Pcap.close(reader)
    end
  end
end

# Usage
tls_conn_count = TLSAnalyzer.find_tls_connections("capture.pcap")
IO.puts("Found #{tls_conn_count} unique TLS connections")
```

## Example 7: Data Export

### Export to CSV

```elixir
defmodule CSVExporter do
  def export_http_to_csv(file_path, output_path) do
    file = File.open!(output_path, [:write])

    # Write header
    IO.write(file, "Timestamp,Source IP,Method,Path,Status,Size\n")

    # Stream and write rows
    PcapFileEx.TCP.stream_http_messages(file_path)
    |> Enum.each(fn msg ->
      row = format_csv_row(msg)
      IO.write(file, row)
    end)

    File.close(file)
    IO.puts("Exported to #{output_path}")
  end

  defp format_csv_row(msg) do
    timestamp = hd(msg.packets).timestamp |> DateTime.to_string()
    source_ip = hd(msg.packets).src.ip
    method = msg.http.method || "N/A"
    path = msg.http.path || "N/A"
    status = msg.http.status_code || "N/A"
    size = byte_size(msg.http.body || "")

    "#{timestamp},#{source_ip},#{method},#{path},#{status},#{size}\n"
  end
end

# Usage
CSVExporter.export_http_to_csv("api_traffic.pcap", "output.csv")
```

### Filter and Save to New PCAP

```elixir
defmodule PcapFilter do
  def filter_and_save(input_path, output_path, filter_fn) do
    # Note: This is conceptual - actual PCAP writing would require
    # a writer implementation (not currently in PcapFileEx)

    filtered_packets = PcapFileEx.stream!(input_path)
    |> Stream.filter(filter_fn)
    |> Enum.to_list()

    IO.puts("Filtered #{length(filtered_packets)} packets")
    # Would write to new PCAP file here
  end
end

# Usage example
PcapFilter.filter_and_save(
  "all_traffic.pcap",
  "http_only.pcap",
  fn packet -> :http in packet.protocols end
)
```

## Example 8: Real-Time Monitoring Pattern

### Process New Packets as They Arrive

```elixir
defmodule RealtimeMonitor do
  def monitor(file_path) do
    # For live capture, you'd use a tail-like pattern
    # This example shows the streaming approach

    PcapFileEx.stream!(file_path)
    |> Stream.each(&process_packet/1)
    |> Stream.run()
  end

  defp process_packet(packet) do
    cond do
      suspicious?(packet) ->
        alert_security_team(packet)

      :http in packet.protocols ->
        log_http_request(packet)

      true ->
        :ok
    end
  end

  defp suspicious?(packet) do
    # Check for suspicious patterns
    byte_size(packet.data) > 10_000 or
    packet.dst.port in [22, 3389]  # SSH, RDP
  end

  defp alert_security_team(packet) do
    IO.puts("⚠️  ALERT: Suspicious packet at #{packet.timestamp}")
    IO.puts("   Source: #{packet.src.ip}:#{packet.src.port}")
    IO.puts("   Dest: #{packet.dst.ip}:#{packet.dst.port}")
    IO.puts("   Size: #{byte_size(packet.data)} bytes")
  end

  defp log_http_request(packet) do
    if http = packet.decoded[:http] do
      IO.puts("HTTP: #{http.method} #{http.path}")
    end
  end
end
```

## Example 9: Custom Protocol Decoder with Context Passing

### Complete Custom Decoder Implementation (v0.5.0+)

This example shows how to register a custom protocol decoder using the **new context-passing API** for optimal performance.

```elixir
defmodule CustomProtocolDecoder do
  @moduledoc """
  Example custom decoder for a binary protocol that uses context-passing
  to avoid double-decoding and maintain thread-safety.

  Protocol format:
  - 4 bytes: Magic number (0x50434150)
  - 2 bytes: Version
  - 2 bytes: Message type
  - 4 bytes: Payload length
  - N bytes: Payload
  """

  alias PcapFileEx.DecoderRegistry

  # Register the decoder at application startup
  def register do
    DecoderRegistry.register(%{
      protocol: :custom_protocol,
      matcher: &match_custom_protocol/2,
      decoder: &decode_custom_protocol/2,
      fields: custom_fields()
    })
  end

  # Matcher: Check if this is our protocol and extract header
  defp match_custom_protocol(layers, payload) do
    # Only match TCP on port 9000
    if tcp_on_port_9000?(layers) and byte_size(payload) >= 12 do
      # Parse header once in matcher
      case parse_header(payload) do
        {:ok, header} ->
          # Return header as context (avoid double-parse!)
          {:match, header}

        :error ->
          false
      end
    else
      false
    end
  end

  # Decoder: Use cached header from matcher
  defp decode_custom_protocol(header, payload) do
    # Skip header bytes we already parsed
    <<_header::binary-size(12), payload_data::binary>> = payload

    # Parse payload based on message type
    case decode_payload(header.message_type, payload_data, header.payload_length) do
      {:ok, decoded_payload} ->
        {:ok, %{
          version: header.version,
          message_type: message_type_name(header.message_type),
          data: decoded_payload
        }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Parse binary header
  defp parse_header(<<0x50, 0x43, 0x41, 0x50, version::16, msg_type::16, length::32, _rest::binary>>) do
    {:ok, %{
      magic: 0x50434150,
      version: version,
      message_type: msg_type,
      payload_length: length
    }}
  end
  defp parse_header(_), do: :error

  # Check if TCP layer is on port 9000
  defp tcp_on_port_9000?(layers) do
    Enum.any?(layers, fn
      {:tcp, _src_port, dst_port, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} ->
        dst_port == 9000
      _ ->
        false
    end)
  end

  # Decode payload based on message type
  defp decode_payload(1, data, expected_length) do
    # Type 1: String message
    if byte_size(data) == expected_length do
      {:ok, %{type: :string, content: data}}
    else
      {:error, :length_mismatch}
    end
  end

  defp decode_payload(2, data, expected_length) do
    # Type 2: JSON message
    if byte_size(data) == expected_length do
      case Jason.decode(data) do
        {:ok, json} -> {:ok, %{type: :json, content: json}}
        {:error, _} -> {:error, :invalid_json}
      end
    else
      {:error, :length_mismatch}
    end
  end

  defp decode_payload(3, <<value::32, rest::binary>>, _length) do
    # Type 3: Integer + data
    {:ok, %{type: :integer_data, value: value, data: rest}}
  end

  defp decode_payload(_unknown, data, _length) do
    {:ok, %{type: :unknown, raw: data}}
  end

  # Human-readable message type names
  defp message_type_name(1), do: :string_message
  defp message_type_name(2), do: :json_message
  defp message_type_name(3), do: :integer_data_message
  defp message_type_name(n), do: {:unknown, n}

  # Field extractors for filtering
  defp custom_fields do
    [
      %{
        id: "custom.version",
        type: :integer,
        extractor: fn decoded -> decoded.version end
      },
      %{
        id: "custom.message_type",
        type: :string,
        extractor: fn decoded -> to_string(decoded.message_type) end
      }
    ]
  end
end
```

### Usage Example

```elixir
# Register decoder at application startup (e.g., in application.ex)
CustomProtocolDecoder.register()

# Now packets are automatically decoded
{:ok, packets} = PcapFileEx.read_all("custom_protocol.pcap")

# Find and decode custom protocol packets
Enum.each(packets, fn packet ->
  case PcapFileEx.Packet.decode_registered(packet) do
    {:ok, {:custom_protocol, decoded}} ->
      IO.puts("Found custom protocol message:")
      IO.puts("  Version: #{decoded.version}")
      IO.puts("  Type: #{decoded.message_type}")
      IO.inspect(decoded.data, label: "  Data")

    :no_match ->
      :ok  # Not our protocol

    {:error, reason} ->
      IO.puts("Decode error: #{inspect(reason)}")
  end
end)

# Stream and filter by custom protocol
PcapFileEx.stream!("custom_protocol.pcap")
|> Stream.filter(fn packet ->
  :custom_protocol in packet.protocols
end)
|> Enum.each(fn packet ->
  {:ok, {:custom_protocol, decoded}} = PcapFileEx.Packet.decode_registered(packet)
  IO.inspect(decoded)
end)
```

### Performance Benefits

```elixir
# OLD API (pre-v0.5.0): Would decode twice
# 1. Matcher parses header to check magic number
# 2. Decoder parses header again (wasteful!)

# NEW API (v0.5.0+): Decode once, cache result
# 1. Matcher parses header and returns as context
# 2. Decoder uses cached header (no re-parse!)

# Result: ~50% faster decoding, thread-safe, cleaner code
```

### Testing the Decoder

```elixir
defmodule CustomProtocolDecoderTest do
  use ExUnit.Case

  setup do
    CustomProtocolDecoder.register()
    :ok
  end

  test "decodes string message" do
    # Build test packet with custom protocol
    magic = <<0x50, 0x43, 0x41, 0x50>>
    version = <<0x00, 0x01>>
    msg_type = <<0x00, 0x01>>  # String message
    payload = "Hello, World!"
    length = <<byte_size(payload)::32>>

    packet_data = magic <> version <> msg_type <> length <> payload

    # Create mock packet (simplified)
    packet = %PcapFileEx.Packet{
      timestamp: DateTime.utc_now(),
      timestamp_precise: PcapFileEx.Timestamp.new(0, 0),
      incl_len: byte_size(packet_data),
      orig_len: byte_size(packet_data),
      data: packet_data,
      protocols: [:ether, :ipv4, :tcp, :custom_protocol],
      decoded: %{}
    }

    # Decode
    {:ok, {:custom_protocol, decoded}} = PcapFileEx.Packet.decode_registered(packet)

    assert decoded.version == 1
    assert decoded.message_type == :string_message
    assert decoded.data.type == :string
    assert decoded.data.content == "Hello, World!"
  end
end
```

### Migration from Old API

```elixir
# OLD API (deprecated, will be removed in v1.0.0)
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, payload ->
    # Returns boolean
    my_protocol?(layers)
  end,
  decoder: fn payload ->
    # Arity-1: Only receives payload
    parse_payload(payload)
  end,
  fields: [...]
})

# NEW API (v0.5.0+)
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, payload ->
    # Returns {:match, context} or false
    if my_protocol?(layers) do
      context = extract_info(layers, payload)
      {:match, context}
    else
      false
    end
  end,
  decoder: fn context, payload ->
    # Arity-2: Receives context from matcher
    parse_payload(payload, context)
  end,
  fields: [...]
})
```

**See the `PcapFileEx.DecoderRegistry` module documentation for complete patterns and best practices.**

## Summary: Key Patterns

1. **Use auto-detection** - `PcapFileEx.open/1`, `read_all/1`, `stream/1`
2. **Use PreFilter for large files** - 10-100x faster for selective queries
3. **Use TCP reassembly for HTTP** - Handles fragmented messages
4. **Stream for memory efficiency** - Process files larger than RAM
5. **Combine filters** - PreFilter (fast) + Elixir Filter (flexible)
6. **Always close readers** - Use try/after or streaming
7. **Check decoded_body first** - Already parsed JSON/ETF/form
8. **Guard against nil** - PCAPNG fields, HTTP fields
9. **Use statistics for summaries** - `compute_streaming/1` for large files
10. **Real-world patterns** - Security scanning, performance analysis, debugging
