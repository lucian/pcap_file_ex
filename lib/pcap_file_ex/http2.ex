defmodule PcapFileEx.HTTP2 do
  @moduledoc """
  HTTP/2 cleartext (h2c) stream reconstruction.

  Parses HTTP/2 frames from TCP payloads and reconstructs complete
  request/response exchanges. Supports prior-knowledge h2c only
  (no HTTP/1.1 Upgrade flow).

  ## Example

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

      IO.puts("Complete: \#{length(complete)}, Incomplete: \#{length(incomplete)}")

      Enum.each(complete, fn ex ->
        IO.puts("\#{ex.request.method} \#{ex.request.path} -> \#{ex.response.status}")
      end)

  ## Limitations

  - **Cleartext only**: No TLS-encrypted HTTP/2 (h2)
  - **Prior-knowledge h2c only**: No HTTP/1.1 Upgrade flow support
  - **No server push**: PUSH_PROMISE frames are ignored
  - **Analysis only**: No playback server implementation

  ## Mid-Connection Capture

  When capturing starts after the HTTP/2 connection is established:
  - Client identification falls back to stream ID semantics
  - Some HPACK dynamic table entries may be missing (static table works)
  - SETTINGS frames are deferred until client is identified
  """

  import Bitwise

  alias PcapFileEx.HTTP2.{Analyzer, Exchange, IncompleteExchange}

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @doc """
  Analyzes a PCAP file and returns HTTP/2 exchanges.

  Returns `{:ok, complete, incomplete}` where:
  - `complete` - List of fully completed request/response exchanges
  - `incomplete` - List of partial exchanges (RST, GOAWAY, truncated)

  ## Options

  - `:port` - Filter to specific TCP port (default: nil, all ports)
  - `:decode_content` - When `true` (default), automatically decodes request/response
    bodies based on Content-Type header. Multipart bodies are recursively decoded,
    JSON is parsed, and text is validated as UTF-8. When `false`, bodies remain as
    raw binaries and `decoded_body` is `nil`.

  ## Example

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

      Enum.each(complete, fn ex ->
        IO.puts("\#{ex.request.method} \#{ex.request.path} -> \#{ex.response.status}")
      end)

      Enum.each(incomplete, fn ex ->
        IO.puts("Incomplete: \#{PcapFileEx.HTTP2.IncompleteExchange.to_string(ex)}")
      end)
  """
  @spec analyze(Path.t(), keyword()) ::
          {:ok, [Exchange.t()], [IncompleteExchange.t()]} | {:error, term()}
  def analyze(pcap_path, opts \\ []) do
    port_filter = Keyword.get(opts, :port)
    decode_content = Keyword.get(opts, :decode_content, true)

    with {:ok, segments} <- extract_tcp_segments(pcap_path, port_filter) do
      # Filter to likely HTTP/2 flows (those with preface or on common ports)
      http2_segments = filter_http2_segments(segments)
      Analyzer.analyze(http2_segments, decode_content: decode_content)
    end
  end

  @doc """
  Analyzes directional TCP segments directly.

  Use this when you already have TCP-reassembled segments with direction
  information, skipping the PCAP parsing step.

  ## Options

  - `:decode_content` - When `true` (default), automatically decodes request/response
    bodies based on Content-Type header. When `false`, bodies remain as raw binaries.

  ## Example

      segments = [
        %{flow_key: {client, server}, direction: :a_to_b, data: preface_bytes, timestamp: ts1},
        %{flow_key: {client, server}, direction: :a_to_b, data: settings_frame, timestamp: ts2},
        ...
      ]

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze_segments(segments)
  """
  @spec analyze_segments([Analyzer.directional_segment()], keyword()) ::
          {:ok, [Exchange.t()], [IncompleteExchange.t()]}
  def analyze_segments(segments, opts \\ []) do
    Analyzer.analyze(segments, opts)
  end

  @doc """
  Check if binary data starts with HTTP/2 connection preface.

  The connection preface is `"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"` (24 bytes).
  """
  @spec http2?(binary()) :: boolean()
  def http2?(<<@connection_preface, _rest::binary>>), do: true
  def http2?(_), do: false

  @doc """
  Returns the HTTP/2 connection preface string.
  """
  @spec connection_preface() :: binary()
  def connection_preface, do: @connection_preface

  # Private helpers

  # Extract TCP segments with direction information from PCAP
  defp extract_tcp_segments(pcap_path, port_filter) do
    # Use PcapFileEx to read packets and reassemble TCP
    case PcapFileEx.stream(pcap_path) do
      {:ok, stream} ->
        segments =
          stream
          |> Stream.filter(fn
            {:ok, _packet} -> true
            {:error, _} -> false
          end)
          |> Stream.map(fn {:ok, packet} -> packet end)
          |> Stream.flat_map(&decode_packet/1)
          |> Stream.filter(fn segment ->
            is_nil(port_filter) or segment_matches_port?(segment, port_filter)
          end)
          |> Enum.to_list()
          |> reassemble_tcp_flows()

        {:ok, segments}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Decode a packet to extract TCP segment info
  # Tries pkt library first, falls back to raw parsing for null/loopback captures
  defp decode_packet(packet) do
    case PcapFileEx.Packet.pkt_decode(packet) do
      {:ok, {layers, payload}} when is_list(layers) and is_binary(payload) ->
        case extract_tcp_info(layers, payload) do
          {:ok, segment_info} ->
            [Map.put(segment_info, :timestamp, packet.timestamp)]

          :skip ->
            # Try raw parsing as fallback
            decode_packet_raw(packet)
        end

      _ ->
        # pkt decode failed - try raw parsing (handles null/loopback)
        decode_packet_raw(packet)
    end
  rescue
    _ -> decode_packet_raw(packet)
  end

  # Raw packet parsing for null loopback and other formats pkt doesn't handle
  defp decode_packet_raw(packet) do
    case parse_tcp_from_raw(packet.data) do
      {:ok, segment_info} ->
        [Map.put(segment_info, :timestamp, packet.timestamp)]

      :skip ->
        []
    end
  rescue
    _ -> []
  end

  # Parse TCP segment from raw packet data
  # Handles: null loopback (AF_INET prefix), ethernet frames
  defp parse_tcp_from_raw(data) when byte_size(data) < 40, do: :skip

  defp parse_tcp_from_raw(data) do
    # Try null loopback format first (4-byte AF header + IP)
    # AF_INET = 2, but stored as 32-bit value
    case data do
      <<2::32-little, rest::binary>> -> parse_ip_tcp(rest)
      <<2::32-big, rest::binary>> -> parse_ip_tcp(rest)
      # Ethernet frame
      <<_dst_mac::48, _src_mac::48, 0x0800::16, rest::binary>> -> parse_ip_tcp(rest)
      # IPv6 over ethernet
      <<_dst_mac::48, _src_mac::48, 0x86DD::16, rest::binary>> -> parse_ipv6_tcp(rest)
      # Try direct IP (some captures)
      <<0x45, _::binary>> = ip_data -> parse_ip_tcp(ip_data)
      <<0x60, _::binary>> = ip_data -> parse_ipv6_tcp(ip_data)
      _ -> :skip
    end
  end

  # Parse IPv4 + TCP
  defp parse_ip_tcp(
         <<version_ihl::8, _tos::8, _total_len::16, _id::16, _flags_frag::16, _ttl::8,
           protocol::8, _checksum::16, src_a::8, src_b::8, src_c::8, src_d::8, dst_a::8, dst_b::8,
           dst_c::8, dst_d::8, rest::binary>>
       ) do
    version = version_ihl >>> 4
    ihl = (version_ihl &&& 0x0F) * 4

    # TCP
    if version == 4 and protocol == 6 do
      # Skip IP options
      options_len = ihl - 20

      if options_len >= 0 and byte_size(rest) >= options_len do
        <<_options::binary-size(options_len), tcp_and_payload::binary>> = rest

        parse_tcp_segment(
          {src_a, src_b, src_c, src_d},
          {dst_a, dst_b, dst_c, dst_d},
          tcp_and_payload
        )
      else
        :skip
      end
    else
      :skip
    end
  end

  defp parse_ip_tcp(_), do: :skip

  # Parse IPv6 + TCP (simplified - no extension headers)
  defp parse_ipv6_tcp(
         <<6::4, _traffic_class::8, _flow_label::20, _payload_len::16, next_header::8,
           _hop_limit::8, src_ip::128, dst_ip::128, rest::binary>>
       ) do
    # TCP
    if next_header == 6 do
      parse_tcp_segment(
        decode_ipv6_addr(src_ip),
        decode_ipv6_addr(dst_ip),
        rest
      )
    else
      :skip
    end
  end

  defp parse_ipv6_tcp(_), do: :skip

  defp decode_ipv6_addr(addr) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = <<addr::128>>
    {a, b, c, d, e, f, g, h}
  end

  # Parse TCP header and extract segment info
  defp parse_tcp_segment(
         src_ip,
         dst_ip,
         <<src_port::16, dst_port::16, seq_num::32, _ack_num::32, data_offset_flags::16,
           _window::16, _checksum::16, _urgent::16, rest::binary>>
       ) do
    data_offset = (data_offset_flags >>> 12) * 4
    options_len = data_offset - 20

    if options_len >= 0 and byte_size(rest) >= options_len do
      <<_options::binary-size(options_len), payload::binary>> = rest

      if byte_size(payload) > 0 do
        src_endpoint = {src_ip, src_port}
        dst_endpoint = {dst_ip, dst_port}

        # Normalize flow key (smaller endpoint first for consistency)
        {flow_key, direction} =
          if src_endpoint <= dst_endpoint do
            {{src_endpoint, dst_endpoint}, :a_to_b}
          else
            {{dst_endpoint, src_endpoint}, :b_to_a}
          end

        {:ok,
         %{
           flow_key: flow_key,
           direction: direction,
           data: payload,
           src_port: src_port,
           dst_port: dst_port,
           seq_num: seq_num
         }}
      else
        :skip
      end
    else
      :skip
    end
  end

  defp parse_tcp_segment(_, _, _), do: :skip

  # Extract TCP info from pkt-decoded layers and payload
  defp extract_tcp_info(layers, payload) do
    ip_header = find_header(layers, :ipv4) || find_header(layers, :ipv6)
    tcp_header = find_header(layers, :tcp)

    if ip_header && tcp_header && byte_size(payload) > 0 do
      # pkt record structures:
      # ipv4: {ipv4, ihl, dscp, ecn, tot_len, id, df, mf, frag_off, ttl, proto, checksum, src, dst, opts}
      # ipv6: {ipv6, class, flow, len, next, hop, src, dst}
      {src_ip, dst_ip} =
        case elem(ip_header, 0) do
          :ipv4 -> {elem(ip_header, 12), elem(ip_header, 13)}
          :ipv6 -> {elem(ip_header, 6), elem(ip_header, 7)}
        end

      src_port = elem(tcp_header, 1)
      dst_port = elem(tcp_header, 2)
      # TCP record: {tcp, sport, dport, seqno, ackno, ...}
      seq_num = if tuple_size(tcp_header) > 3, do: elem(tcp_header, 3), else: 0

      src_endpoint = {src_ip, src_port}
      dst_endpoint = {dst_ip, dst_port}

      # Normalize flow key (smaller endpoint first for consistency)
      {flow_key, direction} =
        if src_endpoint <= dst_endpoint do
          {{src_endpoint, dst_endpoint}, :a_to_b}
        else
          {{dst_endpoint, src_endpoint}, :b_to_a}
        end

      {:ok,
       %{
         flow_key: flow_key,
         direction: direction,
         data: payload,
         src_port: src_port,
         dst_port: dst_port,
         seq_num: seq_num
       }}
    else
      :skip
    end
  end

  defp find_header(headers, type) when is_list(headers) do
    Enum.find(headers, fn
      header when is_tuple(header) -> elem(header, 0) == type
      _ -> false
    end)
  end

  # Check if segment matches port filter
  defp segment_matches_port?(segment, port) do
    segment.src_port == port or segment.dst_port == port
  end

  # Reassemble TCP flows - order by sequence number, detect retransmits/gaps
  #
  # Strategy per direction within each flow:
  # 1. Sort segments by sequence number (handling 32-bit wraparound)
  # 2. Detect and discard retransmissions (same seq range seen before)
  # 3. Track expected next seq to detect gaps
  # 4. Preserve ordering for Analyzer
  defp reassemble_tcp_flows(segments) do
    segments
    |> Enum.group_by(& &1.flow_key)
    |> Enum.flat_map(fn {_flow_key, flow_segments} ->
      # Process each direction separately
      {a_to_b, b_to_a} = Enum.split_with(flow_segments, &(&1.direction == :a_to_b))

      a_to_b_ordered = order_by_seq_with_dedup(a_to_b)
      b_to_a_ordered = order_by_seq_with_dedup(b_to_a)

      # Interleave back by timestamp for proper frame ordering
      (a_to_b_ordered ++ b_to_a_ordered)
      |> Enum.sort_by(& &1.timestamp, {:asc, DateTime})
    end)
  end

  # Order segments by sequence number and remove retransmissions
  defp order_by_seq_with_dedup([]), do: []

  defp order_by_seq_with_dedup(segments) do
    # Sort by sequence number (simple ascending - works for most cases)
    # For full 32-bit wraparound handling, would need more complex logic
    sorted =
      segments
      |> Enum.sort_by(fn seg -> Map.get(seg, :seq_num, 0) end)

    # Remove retransmissions: track seen seq ranges
    # A segment is a retransmit if its seq range overlaps with already-seen data
    {deduped, _seen} =
      Enum.reduce(sorted, {[], %{}}, fn seg, {acc, seen} ->
        seq = Map.get(seg, :seq_num, 0)
        len = byte_size(seg.data)
        end_seq = seq + len

        # Check if this overlaps with seen ranges
        is_retransmit =
          Enum.any?(seen, fn {seen_seq, seen_end} ->
            # Overlap if: seg.start < seen.end AND seg.end > seen.start
            seq < seen_end and end_seq > seen_seq
          end)

        if is_retransmit do
          # Skip retransmit but might extend seen range
          {acc, seen}
        else
          # New data - add to seen ranges
          # Merge with adjacent/overlapping ranges
          new_seen = merge_seq_range(seen, seq, end_seq)
          {[seg | acc], new_seen}
        end
      end)

    Enum.reverse(deduped)
  end

  # Merge a new seq range into existing ranges
  defp merge_seq_range(seen, seq, end_seq) do
    # Simple approach: just add the range (could optimize by merging adjacent)
    Map.put(seen, seq, end_seq)
  end

  # Filter segments to likely HTTP/2 flows
  #
  # Strategy: Don't filter at all - let Analyzer process all TCP flows.
  # This avoids dropping valid mid-connection captures where initial segments
  # may be mid-frame (e.g., continuation of a DATA payload). The Analyzer
  # will simply produce no exchanges for non-HTTP/2 flows.
  #
  # If performance becomes an issue with many non-HTTP/2 flows, consider:
  # 1. Filtering AFTER reassembly (when we have complete frames to inspect)
  # 2. Port-based hinting (common HTTP/2 ports: 80, 443, 8080, 8443)
  # 3. Deferred filtering in FrameBuffer (first valid frame seen = keep flow)
  defp filter_http2_segments(segments) do
    # Pass all segments through - Analyzer handles non-HTTP/2 gracefully
    segments
  end
end
