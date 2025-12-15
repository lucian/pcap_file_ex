defmodule PcapFileEx.PropertyGenerators do
  @moduledoc """
  StreamData generators for property-based testing of PcapFileEx.

  This module provides generators for all core data types:
  - Timestamps (with boundary cases)
  - Packets (with valid structures)
  - DateTime values
  - Ranges (for filters)
  - Protocols

  All generators produce valid data structures that conform to the
  type specifications and invariants of the library.
  """

  use ExUnitProperties
  import Bitwise

  alias PcapFileEx.{Packet, Timestamp}

  # ============================================================================
  # Timestamp Generators
  # ============================================================================

  @doc """
  Generates random valid timestamps.

  Produces timestamps with:
  - secs: 0..3_000_000_000 (covers 1970 to ~2065)
  - nanos: 0..999_999_999 (valid nanosecond range)
  """
  def timestamp_generator do
    gen all secs <- integer(0..3_000_000_000),
            nanos <- integer(0..999_999_999) do
      Timestamp.new(secs, nanos)
    end
  end

  @doc """
  Generates timestamps at boundary conditions.

  Includes edge cases:
  - Epoch (0, 0)
  - Maximum nanosecond component
  - Year 2038 problem (32-bit signed int max)
  - Far future timestamps
  """
  def timestamp_boundary_generator do
    member_of([
      Timestamp.new(0, 0),
      # Epoch
      Timestamp.new(0, 999_999_999),
      # Almost 1 second
      Timestamp.new(1, 0),
      # First second
      Timestamp.new(2_147_483_647, 0),
      # Year 2038 (32-bit max)
      Timestamp.new(2_147_483_647, 999_999_999),
      # Max 32-bit with max nanos
      Timestamp.new(1_000_000_000, 0),
      # Year ~2001
      Timestamp.new(1_500_000_000, 500_000_000),
      # ~2017 mid-second
      Timestamp.new(3_000_000_000, 0)
      # Far future ~2065
    ])
  end

  @doc """
  Generates timestamps combining regular and boundary cases.

  Weighted 80% regular, 20% boundary cases for better edge case coverage.
  """
  def mixed_timestamp_generator do
    frequency([
      {8, timestamp_generator()},
      {2, timestamp_boundary_generator()}
    ])
  end

  @doc """
  Generates valid DateTime values for conversion testing.

  Range: 0..2_000_000_000 seconds (1970 to ~2033)
  Microsecond precision (DateTime's maximum)
  """
  def datetime_generator do
    gen all secs <- integer(0..2_000_000_000),
            micros <- integer(0..999_999) do
      DateTime.from_unix!(secs, :second)
      |> DateTime.add(micros, :microsecond)
    end
  end

  # ============================================================================
  # Packet Data Generators
  # ============================================================================

  @doc """
  Generates random binary data for packet payloads.

  Size range: 14..9000 bytes (typical Ethernet frame sizes)
  - 14 bytes: Minimum Ethernet frame
  - 1500 bytes: Standard MTU
  - 9000 bytes: Jumbo frames
  """
  def packet_data_generator do
    gen all size <- integer(14..9000) do
      <<rand_bytes::binary-size(size)>> = :crypto.strong_rand_bytes(size)
      rand_bytes
    end
  end

  @doc """
  Generates compact packet data (smaller, faster for most tests).

  Size range: 14..1500 bytes (standard Ethernet frames)
  """
  def compact_packet_data_generator do
    gen all size <- integer(14..1500) do
      <<rand_bytes::binary-size(size)>> = :crypto.strong_rand_bytes(size)
      rand_bytes
    end
  end

  @doc """
  Generates valid datalink type strings.
  """
  def datalink_generator do
    member_of([
      "ethernet",
      "raw",
      "ipv4",
      "ipv6",
      "linux_sll",
      "linux_sll2",
      "null",
      "loop",
      "ppp"
    ])
  end

  @doc """
  Generates raw packet maps as returned by the Rust NIF.

  Ensures invariants:
  - orig_len >= byte_size(data)
  - timestamp_nanos in valid range
  - All required fields present
  """
  def pcap_packet_map_generator do
    gen all timestamp_secs <- integer(0..2_000_000_000),
            timestamp_nanos <- integer(0..999_999_999),
            data <- compact_packet_data_generator(),
            datalink <- datalink_generator(),
            # Generate orig_len offset for truncated captures
            truncation_offset <- integer(0..1000) do
      data_list = :binary.bin_to_list(data)
      data_size = byte_size(data)

      # orig_len can be >= data size (truncated captures)
      # If offset > 0, this is a truncated capture
      orig_len = data_size + truncation_offset

      %{
        timestamp_secs: timestamp_secs,
        timestamp_nanos: timestamp_nanos,
        orig_len: orig_len,
        data: data_list,
        datalink: datalink
      }
    end
  end

  @doc """
  Generates valid Packet structs.
  """
  def packet_generator do
    gen all packet_map <- pcap_packet_map_generator() do
      Packet.from_map(packet_map)
    end
  end

  @doc """
  Generates lists of packets.

  Options:
  - :min_length - Minimum list length (default: 0)
  - :max_length - Maximum list length (default: 100)
  """
  def packet_list_generator(opts \\ []) do
    min_length = Keyword.get(opts, :min_length, 0)
    max_length = Keyword.get(opts, :max_length, 100)

    list_of(packet_generator(), min_length: min_length, max_length: max_length)
  end

  @doc """
  Generates non-empty lists of packets.
  """
  def non_empty_packet_list_generator(opts \\ []) do
    max_length = Keyword.get(opts, :max_length, 100)

    list_of(packet_generator(), min_length: 1, max_length: max_length)
  end

  # ============================================================================
  # Filter-related Generators
  # ============================================================================

  @doc """
  Generates size ranges for packet filtering.

  Returns min..max ranges where min < max
  """
  def size_range_generator do
    gen all min_size <- integer(0..5000),
            max_size <- integer((min_size + 1)..10_000) do
      min_size..max_size
    end
  end

  @doc """
  Generates positive integers for size thresholds.
  """
  def size_threshold_generator do
    integer(1..10_000)
  end

  @doc """
  Generates time ranges for packet filtering.

  Returns {start_dt, end_dt} tuples with end > start
  Duration: 1 second to 1 day
  """
  def time_range_generator do
    gen all start_secs <- integer(1_000_000_000..2_000_000_000),
            duration_secs <- integer(1..86_400) do
      start_dt = DateTime.from_unix!(start_secs, :second)
      end_dt = DateTime.add(start_dt, duration_secs, :second)
      {start_dt, end_dt}
    end
  end

  @doc """
  Generates protocol atoms from known protocols.
  """
  def protocol_generator do
    member_of([
      :ether,
      :ipv4,
      :ipv6,
      :tcp,
      :udp,
      :icmp,
      :http,
      :dns,
      :arp
    ])
  end

  # ============================================================================
  # Endpoint Generators (for decoded packets)
  # ============================================================================

  @doc """
  Generates valid IPv4 address strings.
  """
  def ipv4_string_generator do
    gen all a <- integer(0..255),
            b <- integer(0..255),
            c <- integer(0..255),
            d <- integer(0..255) do
      "#{a}.#{b}.#{c}.#{d}"
    end
  end

  @doc """
  Generates valid port numbers (0..65_535).
  """
  def port_generator do
    integer(0..65_535)
  end

  # ============================================================================
  # HTTP/2 Generators
  # ============================================================================

  @doc """
  Generates valid HTTP/2 frame types.
  """
  def http2_frame_type_generator do
    member_of([
      :data,
      :headers,
      :priority,
      :rst_stream,
      :settings,
      :push_promise,
      :ping,
      :goaway,
      :window_update,
      :continuation
    ])
  end

  @doc """
  Generates HTTP/2 frame type bytes (0x00-0x09).
  """
  def http2_frame_type_byte_generator do
    integer(0x00..0x09)
  end

  @doc """
  Generates valid HTTP/2 stream IDs.
  Stream ID 0 is for connection-level frames.
  Odd stream IDs are client-initiated.
  Even (non-zero) stream IDs are server-initiated (push).
  """
  def http2_stream_id_generator do
    # Most common: client-initiated (odd) and connection-level (0)
    frequency([
      {3, constant(0)},
      {10, gen(all n <- integer(1..1000), do: 2 * n - 1)},
      {2, gen(all n <- integer(1..100), do: 2 * n)}
    ])
  end

  @doc """
  Generates HTTP/2 error codes.
  """
  def http2_error_code_generator do
    member_of([
      # NO_ERROR
      0x00,
      # PROTOCOL_ERROR
      0x01,
      # INTERNAL_ERROR
      0x02,
      # FLOW_CONTROL_ERROR
      0x03,
      # SETTINGS_TIMEOUT
      0x04,
      # STREAM_CLOSED
      0x05,
      # FRAME_SIZE_ERROR
      0x06,
      # REFUSED_STREAM
      0x07,
      # CANCEL
      0x08,
      # COMPRESSION_ERROR
      0x09,
      # CONNECT_ERROR
      0x0A,
      # ENHANCE_YOUR_CALM
      0x0B,
      # INADEQUATE_SECURITY
      0x0C,
      # HTTP_1_1_REQUIRED
      0x0D
    ])
  end

  @doc """
  Generates HTTP/2 frame flags byte based on frame type.
  """
  def http2_frame_flags_generator(frame_type) do
    case frame_type do
      :data ->
        # DATA: END_STREAM (0x01), PADDED (0x08)
        gen all end_stream <- boolean(),
                padded <- boolean() do
          if(end_stream, do: 0x01, else: 0) ||| if padded, do: 0x08, else: 0
        end

      :headers ->
        # HEADERS: END_STREAM (0x01), END_HEADERS (0x04), PADDED (0x08), PRIORITY (0x20)
        gen all end_stream <- boolean(),
                end_headers <- boolean(),
                padded <- boolean(),
                priority <- boolean() do
          if(end_stream, do: 0x01, else: 0) |||
            if(end_headers, do: 0x04, else: 0) |||
            if(padded, do: 0x08, else: 0) |||
            if priority, do: 0x20, else: 0
        end

      :settings ->
        # SETTINGS: ACK (0x01)
        gen(all ack <- boolean(), do: if(ack, do: 0x01, else: 0))

      :ping ->
        # PING: ACK (0x01)
        gen(all ack <- boolean(), do: if(ack, do: 0x01, else: 0))

      :continuation ->
        # CONTINUATION: END_HEADERS (0x04)
        gen(all end_headers <- boolean(), do: if(end_headers, do: 0x04, else: 0))

      _ ->
        # Other frames have no flags
        constant(0)
    end
  end

  @doc """
  Generates HTTP/2 frame payload based on frame type.
  """
  def http2_frame_payload_generator(frame_type) do
    case frame_type do
      :data ->
        binary(min_length: 0, max_length: 1000)

      :headers ->
        # Simplified: just random bytes representing HPACK-encoded headers
        binary(min_length: 1, max_length: 500)

      :priority ->
        # Priority: E (1 bit) + Stream Dependency (31 bits) + Weight (8 bits) = 5 bytes
        gen all exclusive <- boolean(),
                dep <- integer(0..0x7FFFFFFF),
                weight <- integer(0..255) do
          e_bit = if exclusive, do: 1, else: 0
          <<e_bit::1, dep::31, weight::8>>
        end

      :rst_stream ->
        # Error code (32 bits)
        gen(all code <- http2_error_code_generator(), do: <<code::32>>)

      :settings ->
        # Settings: pairs of (16-bit ID, 32-bit value)
        gen all count <- integer(0..6) do
          if count == 0 do
            <<>>
          else
            Enum.map_join(1..count, fn _ ->
              id = Enum.random([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
              value = :rand.uniform(65_536)
              <<id::16, value::32>>
            end)
          end
        end

      :ping ->
        # 8 bytes opaque data
        binary(length: 8)

      :goaway ->
        # Last-Stream-ID (32 bits) + Error Code (32 bits) + optional debug
        gen all last_stream <- integer(0..0x7FFFFFFF),
                error <- http2_error_code_generator(),
                debug <- binary(max_length: 100) do
          <<0::1, last_stream::31, error::32, debug::binary>>
        end

      :window_update ->
        # Window Size Increment (31 bits, must be non-zero)
        gen(all increment <- integer(1..0x7FFFFFFF), do: <<0::1, increment::31>>)

      :continuation ->
        binary(min_length: 1, max_length: 500)

      _ ->
        binary(max_length: 100)
    end
  end

  @doc """
  Generates a complete HTTP/2 frame as binary.
  """
  def http2_frame_binary_generator do
    gen all frame_type_byte <- http2_frame_type_byte_generator(),
            stream_id <- http2_stream_id_generator(),
            frame_type = http2_frame_type_from_byte(frame_type_byte),
            flags <- http2_frame_flags_generator(frame_type),
            payload <- http2_frame_payload_generator(frame_type) do
      length = byte_size(payload)
      <<length::24, frame_type_byte::8, flags::8, 0::1, stream_id::31, payload::binary>>
    end
  end

  @doc """
  Generates HTTP/2 pseudo-headers for requests.
  """
  def http2_request_pseudo_headers_generator do
    gen all method <- member_of(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
            path <- member_of(["/", "/api", "/api/users", "/api/users/1", "/health"]),
            scheme <- member_of(["http", "https"]),
            authority <- member_of(["localhost", "localhost:8080", "example.com"]) do
      %{
        ":method" => method,
        ":path" => path,
        ":scheme" => scheme,
        ":authority" => authority
      }
    end
  end

  @doc """
  Generates HTTP/2 pseudo-headers for responses.
  """
  def http2_response_pseudo_headers_generator do
    gen all status <- member_of(["200", "201", "204", "301", "400", "404", "500"]) do
      %{":status" => status}
    end
  end

  @doc """
  Generates HTTP/2 regular headers.
  """
  def http2_regular_headers_generator do
    gen all count <- integer(0..5) do
      headers = [
        {"content-type", "application/json"},
        {"content-type", "text/plain"},
        {"content-length", "100"},
        {"accept", "application/json"},
        {"cache-control", "no-cache"},
        {"user-agent", "test-client/1.0"},
        {"x-request-id", "abc123"}
      ]

      Enum.take_random(headers, count) |> Map.new()
    end
  end

  # Helper to convert frame type byte to atom
  defp http2_frame_type_from_byte(byte) do
    case byte do
      0x00 -> :data
      0x01 -> :headers
      0x02 -> :priority
      0x03 -> :rst_stream
      0x04 -> :settings
      0x05 -> :push_promise
      0x06 -> :ping
      0x07 -> :goaway
      0x08 -> :window_update
      0x09 -> :continuation
      _ -> :unknown
    end
  end

  # ============================================================================
  # HTTP Content Generators
  # ============================================================================

  @doc """
  Generates valid JSON content.
  """
  def json_content_generator do
    gen all obj <- json_object_generator() do
      Jason.encode!(obj)
    end
  end

  @doc """
  Generates JSON-encodable objects.
  """
  def json_object_generator do
    gen all count <- integer(0..5) do
      Enum.reduce(1..max(count, 1), %{}, fn i, acc ->
        key = "key#{i}"
        value = Enum.random(["string", 42, true, false, nil, [1, 2, 3]])
        Map.put(acc, key, value)
      end)
    end
  end

  @doc """
  Generates valid UTF-8 text content.
  """
  def utf8_text_generator do
    # ASCII printable + common Unicode
    gen all chars <- list_of(utf8_char_generator(), min_length: 0, max_length: 500) do
      chars |> List.to_string()
    end
  end

  defp utf8_char_generator do
    # Mix of ASCII and safe Unicode ranges
    frequency([
      # ASCII printable
      {8, integer(0x20..0x7E)},
      # Latin supplement
      {1, integer(0xC0..0xFF)},
      # Latin extended
      {1, integer(0x100..0x17F)}
    ])
  end

  @doc """
  Generates Content-Type header values for JSON.
  """
  def json_content_type_generator do
    member_of([
      "application/json",
      "application/json; charset=utf-8",
      "application/problem+json",
      "APPLICATION/JSON"
    ])
  end

  @doc """
  Generates Content-Type header values for text.
  """
  def text_content_type_generator do
    member_of([
      "text/plain",
      "text/plain; charset=utf-8",
      "text/html",
      "text/xml",
      "TEXT/PLAIN"
    ])
  end

  @doc """
  Generates Content-Type header values for binary/unknown content.
  """
  def binary_content_type_generator do
    member_of([
      "application/octet-stream",
      "application/vnd.3gpp.ngap",
      "application/x-custom",
      "image/png",
      nil
    ])
  end

  @doc """
  Generates random binary content (non-UTF-8).
  """
  def random_binary_generator do
    gen all size <- integer(0..200) do
      :crypto.strong_rand_bytes(size)
    end
  end

  @doc """
  Generates valid multipart boundary strings.
  """
  def multipart_boundary_generator do
    gen all suffix <- string(:alphanumeric, min_length: 8, max_length: 32) do
      "boundary_" <> suffix
    end
  end

  @doc """
  Generates a simple multipart body with one or more parts.
  """
  def simple_multipart_generator do
    gen all boundary <- multipart_boundary_generator(),
            parts <- list_of(multipart_part_generator(), min_length: 1, max_length: 3) do
      body =
        Enum.map_join(parts, "\r\n", fn {ct, body} ->
          "--#{boundary}\r\nContent-Type: #{ct}\r\n\r\n#{body}"
        end)

      body = body <> "\r\n--#{boundary}--"
      {boundary, body}
    end
  end

  defp multipart_part_generator do
    frequency([
      {3, gen(all json <- json_content_generator(), do: {"application/json", json})},
      {2, gen(all text <- utf8_text_generator(), do: {"text/plain", text})},
      {1, gen(all bin <- random_binary_generator(), do: {"application/octet-stream", bin})}
    ])
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  @doc """
  Generates a value from any generator (useful for testing).
  """
  def generate(generator) do
    Enum.take(generator, 1) |> hd()
  end
end
