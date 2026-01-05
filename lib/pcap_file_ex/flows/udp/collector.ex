defmodule PcapFileEx.Flows.UDP.Collector do
  @moduledoc """
  Collects UDP datagrams into flows grouped by destination.

  UDP flows are grouped by server (destination) endpoint only,
  using `from: :any` pattern since datagrams may come from any source.

  ## Example

      {:ok, flows} = UDP.Collector.collect(packets)

      Enum.each(flows, fn flow ->
        IO.puts("UDP to \#{flow.flow.server}: \#{length(flow.datagrams)} datagrams")
      end)
  """

  alias PcapFileEx.{Endpoint, Flow, Timestamp}
  alias PcapFileEx.Flows.UDP

  @type packet :: %{
          src_ip: tuple(),
          src_port: non_neg_integer(),
          dst_ip: tuple(),
          dst_port: non_neg_integer(),
          payload: binary(),
          timestamp: DateTime.t()
        }

  @doc """
  Collects UDP packets into flows grouped by destination.

  ## Parameters

  - `packets` - List of UDP packet maps
  - `opts` - Options:
    - `:hosts_map` - Map of IP strings to hostnames

  ## Returns

  `{:ok, flows}` where flows is a list of `UDP.Flow.t()`

  ## Example

      packets = [
        %{src_ip: {10,0,0,1}, src_port: 54321, dst_ip: {10,0,0,2}, dst_port: 5005,
          payload: <<1,2,3>>, timestamp: ~U[2024-01-01 00:00:00Z]},
        ...
      ]

      {:ok, flows} = UDP.Collector.collect(packets, hosts_map: %{"10.0.0.2" => "metrics"})
  """
  @spec collect([packet()], keyword()) :: {:ok, [UDP.Flow.t()]}
  def collect(packets, opts \\ []) do
    hosts_map = Keyword.get(opts, :hosts_map, %{})

    flows =
      packets
      |> Enum.group_by(&{&1.dst_ip, &1.dst_port})
      |> Enum.map(fn {{dst_ip, dst_port}, datagrams} ->
        build_flow(dst_ip, dst_port, datagrams, hosts_map)
      end)
      |> Enum.sort_by(fn flow ->
        case flow.datagrams do
          [] -> nil
          [first | _] -> Timestamp.to_unix_nanos(first.timestamp)
        end
      end)

    {:ok, flows}
  end

  @doc """
  Extracts UDP packets from PCAP file.

  ## Parameters

  - `pcap_path` - Path to PCAP/PCAPNG file
  - `opts` - Options:
    - `:port` - Filter to specific UDP port
    - `:hosts_map` - Map of IP strings to hostnames

  ## Returns

  `{:ok, flows}` where flows is a list of `UDP.Flow.t()`
  """
  @spec extract(Path.t(), keyword()) :: {:ok, [UDP.Flow.t()]} | {:error, term()}
  def extract(pcap_path, opts \\ []) do
    port_filter = Keyword.get(opts, :port)
    hosts_map = Keyword.get(opts, :hosts_map, %{})

    case PcapFileEx.stream(pcap_path) do
      {:ok, stream} ->
        packets =
          stream
          |> Stream.filter(fn
            {:ok, _} -> true
            {:error, _} -> false
          end)
          |> Stream.map(fn {:ok, packet} -> packet end)
          |> Stream.flat_map(&decode_udp_packet/1)
          |> Stream.filter(fn packet ->
            is_nil(port_filter) or packet.dst_port == port_filter or
              packet.src_port == port_filter
          end)
          |> Enum.to_list()

        collect(packets, hosts_map: hosts_map)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Build a UDP flow from datagrams to the same destination
  defp build_flow(dst_ip, dst_port, datagrams, hosts_map) do
    server_endpoint = Endpoint.from_tuple({dst_ip, dst_port}, hosts_map)

    # For UDP flows, we use from: :any since datagrams may come from multiple sources
    flow = Flow.new(:udp, nil, server_endpoint)
    udp_flow = UDP.Flow.new(flow)

    # Add all datagrams
    udp_flow =
      datagrams
      |> Enum.sort_by(& &1.timestamp, DateTime)
      |> Enum.with_index()
      |> Enum.reduce(udp_flow, fn {packet, flow_seq}, acc ->
        from_endpoint = Endpoint.from_tuple({packet.src_ip, packet.src_port}, hosts_map)
        to_endpoint = server_endpoint
        timestamp = Timestamp.from_datetime(packet.timestamp)

        datagram =
          UDP.Datagram.new(flow_seq, from_endpoint, to_endpoint, packet.payload, timestamp)

        UDP.Flow.add_datagram(acc, datagram)
      end)

    UDP.Flow.finalize(udp_flow)
  end

  # Decode UDP packet from raw PCAP packet
  defp decode_udp_packet(packet) do
    case PcapFileEx.Packet.pkt_decode(packet) do
      {:ok, {layers, payload}} when is_list(layers) and is_binary(payload) ->
        extract_udp_info(layers, payload, packet.timestamp)

      _ ->
        decode_udp_packet_raw(packet)
    end
  rescue
    _ -> decode_udp_packet_raw(packet)
  end

  defp decode_udp_packet_raw(packet) do
    case parse_udp_from_raw(packet.data, packet.timestamp) do
      {:ok, info} -> [info]
      :skip -> []
    end
  rescue
    _ -> []
  end

  # Extract UDP info from pkt-decoded layers
  defp extract_udp_info(layers, payload, timestamp) do
    ip_header = find_header(layers, :ipv4) || find_header(layers, :ipv6)
    udp_header = find_header(layers, :udp)

    if ip_header && udp_header do
      {src_ip, dst_ip} =
        case elem(ip_header, 0) do
          :ipv4 -> {elem(ip_header, 12), elem(ip_header, 13)}
          :ipv6 -> {elem(ip_header, 6), elem(ip_header, 7)}
        end

      src_port = elem(udp_header, 1)
      dst_port = elem(udp_header, 2)

      [
        %{
          src_ip: src_ip,
          src_port: src_port,
          dst_ip: dst_ip,
          dst_port: dst_port,
          payload: payload,
          timestamp: timestamp
        }
      ]
    else
      []
    end
  end

  defp find_header(headers, type) when is_list(headers) do
    Enum.find(headers, fn
      header when is_tuple(header) -> elem(header, 0) == type
      _ -> false
    end)
  end

  # Parse UDP from raw packet data
  defp parse_udp_from_raw(data, _timestamp) when byte_size(data) < 28, do: :skip

  defp parse_udp_from_raw(data, timestamp) do
    import Bitwise

    case data do
      # Null loopback
      <<2::32-little, rest::binary>> -> parse_ip_udp(rest, timestamp)
      <<2::32-big, rest::binary>> -> parse_ip_udp(rest, timestamp)
      # Ethernet IPv4
      <<_dst_mac::48, _src_mac::48, 0x0800::16, rest::binary>> -> parse_ip_udp(rest, timestamp)
      # Ethernet IPv6
      <<_dst_mac::48, _src_mac::48, 0x86DD::16, rest::binary>> -> parse_ipv6_udp(rest, timestamp)
      # Direct IPv4
      <<0x45, _::binary>> = ip_data -> parse_ip_udp(ip_data, timestamp)
      # Direct IPv6
      <<0x60, _::binary>> = ip_data -> parse_ipv6_udp(ip_data, timestamp)
      _ -> :skip
    end
  end

  # Parse IPv4 + UDP
  defp parse_ip_udp(
         <<version_ihl::8, _tos::8, _total_len::16, _id::16, _flags_frag::16, _ttl::8,
           protocol::8, _checksum::16, src_a::8, src_b::8, src_c::8, src_d::8, dst_a::8, dst_b::8,
           dst_c::8, dst_d::8, rest::binary>>,
         timestamp
       ) do
    import Bitwise
    version = version_ihl >>> 4
    ihl = (version_ihl &&& 0x0F) * 4

    # UDP protocol = 17
    if version == 4 and protocol == 17 do
      options_len = ihl - 20

      if options_len >= 0 and byte_size(rest) >= options_len do
        <<_options::binary-size(options_len), udp_data::binary>> = rest

        parse_udp_header(
          {src_a, src_b, src_c, src_d},
          {dst_a, dst_b, dst_c, dst_d},
          udp_data,
          timestamp
        )
      else
        :skip
      end
    else
      :skip
    end
  end

  defp parse_ip_udp(_, _), do: :skip

  # Parse IPv6 + UDP
  defp parse_ipv6_udp(
         <<6::4, _traffic_class::8, _flow_label::20, _payload_len::16, next_header::8,
           _hop_limit::8, src_ip::128, dst_ip::128, rest::binary>>,
         timestamp
       ) do
    # UDP protocol = 17
    if next_header == 17 do
      parse_udp_header(decode_ipv6_addr(src_ip), decode_ipv6_addr(dst_ip), rest, timestamp)
    else
      :skip
    end
  end

  defp parse_ipv6_udp(_, _), do: :skip

  defp decode_ipv6_addr(addr) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = <<addr::128>>
    {a, b, c, d, e, f, g, h}
  end

  # Parse UDP header
  defp parse_udp_header(
         src_ip,
         dst_ip,
         <<src_port::16, dst_port::16, _len::16, _checksum::16, payload::binary>>,
         timestamp
       ) do
    {:ok,
     %{
       src_ip: src_ip,
       src_port: src_port,
       dst_ip: dst_ip,
       dst_port: dst_port,
       payload: payload,
       timestamp: timestamp
     }}
  end

  defp parse_udp_header(_, _, _, _), do: :skip
end
