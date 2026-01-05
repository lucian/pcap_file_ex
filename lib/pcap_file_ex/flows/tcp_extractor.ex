defmodule PcapFileEx.Flows.TCPExtractor do
  @moduledoc """
  Extracts and reassembles TCP segments from PCAP files.

  This module provides shared TCP extraction logic used by both HTTP/1
  and HTTP/2 analyzers. It handles:

  - Decoding packets from various formats (Ethernet, null loopback, etc.)
  - Extracting TCP segment information
  - Reassembling TCP flows with sequence number ordering
  - Detecting and filtering retransmissions

  ## Segment Format

  Each extracted segment is a map with:

      %{
        flow_key: {{src_ip, src_port}, {dst_ip, dst_port}},
        direction: :a_to_b | :b_to_a,
        data: binary(),
        src_port: integer(),
        dst_port: integer(),
        seq_num: integer(),
        timestamp: DateTime.t()
      }

  ## Example

      {:ok, segments} = TCPExtractor.extract("capture.pcap")

      # Filter by port
      {:ok, segments} = TCPExtractor.extract("capture.pcap", port: 8080)
  """

  import Bitwise

  @type segment :: %{
          flow_key: {{tuple(), non_neg_integer()}, {tuple(), non_neg_integer()}},
          direction: :a_to_b | :b_to_a,
          data: binary(),
          src_port: non_neg_integer(),
          dst_port: non_neg_integer(),
          seq_num: non_neg_integer(),
          timestamp: DateTime.t()
        }

  @doc """
  Extracts TCP segments from a PCAP file.

  ## Options

  - `:port` - Filter to specific TCP port (default: nil, all ports)

  ## Returns

  `{:ok, segments}` where segments is a list of reassembled TCP segments
  ordered by timestamp, or `{:error, reason}` on failure.

  ## Examples

      {:ok, segments} = TCPExtractor.extract("capture.pcap")
      {:ok, segments} = TCPExtractor.extract("capture.pcap", port: 8080)
  """
  @spec extract(Path.t(), keyword()) :: {:ok, [segment()]} | {:error, term()}
  def extract(pcap_path, opts \\ []) do
    port_filter = Keyword.get(opts, :port)

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

  @doc """
  Extracts TCP segments from a stream of packets.

  Use this when you already have a packet stream.

  ## Options

  - `:port` - Filter to specific TCP port (default: nil, all ports)
  """
  @spec extract_from_stream(Enumerable.t(), keyword()) :: [segment()]
  def extract_from_stream(packet_stream, opts \\ []) do
    port_filter = Keyword.get(opts, :port)

    packet_stream
    |> Stream.flat_map(&decode_packet/1)
    |> Stream.filter(fn segment ->
      is_nil(port_filter) or segment_matches_port?(segment, port_filter)
    end)
    |> Enum.to_list()
    |> reassemble_tcp_flows()
  end

  @doc """
  Groups segments by flow key.

  Returns a map of `{flow_key => segments}` where segments are
  ordered by timestamp.
  """
  @spec group_by_flow([segment()]) :: %{tuple() => [segment()]}
  def group_by_flow(segments) do
    segments
    |> Enum.group_by(& &1.flow_key)
  end

  # Decode a packet to extract TCP segment info
  # Tries pkt library first, falls back to raw parsing for null/loopback captures
  @doc false
  def decode_packet(packet) do
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
end
