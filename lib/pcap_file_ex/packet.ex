defmodule PcapFileEx.Packet do
  @moduledoc """
  Represents a captured network packet.
  """

  alias PcapFileEx.{DecoderRegistry, Endpoint, HTTP, Interface, Timestamp}

  @loopback_ipv6_families [10, 23, 24, 28, 30]
  @pkt_protocol_map %{
    "ethernet" => :ether,
    "ipv4" => :ipv4,
    "ipv6" => :ipv6,
    "raw" => :raw,
    "linux_sll" => :linux_cooked,
    "linux_sll2" => :linux_cooked_v2,
    "null" => :null,
    "loop" => :null,
    "ppp" => :ppp
  }
  @default_pkt_protocol :ether

  @type t :: %__MODULE__{
          timestamp: DateTime.t(),
          timestamp_precise: Timestamp.t(),
          orig_len: non_neg_integer(),
          data: binary(),
          datalink: String.t() | nil,
          timestamp_resolution: Interface.timestamp_resolution() | nil,
          interface_id: non_neg_integer() | nil,
          interface: Interface.t() | nil,
          protocols: [atom()],
          protocol: atom() | nil,
          src: Endpoint.t() | nil,
          dst: Endpoint.t() | nil,
          layers: [layer()] | nil,
          payload: binary() | nil,
          decoded: %{optional(atom()) => term()}
        }

  @type layer :: tuple() | atom() | map()

  defstruct [
    :timestamp,
    :timestamp_precise,
    :orig_len,
    :data,
    :datalink,
    :timestamp_resolution,
    :interface_id,
    :interface,
    :protocols,
    :protocol,
    :src,
    :dst,
    :layers,
    :payload,
    decoded: %{}
  ]

  @doc """
  Creates a Packet struct from a map returned by the NIF.

  ## Options

    * `:hosts_map` - A map of IP addresses to hostnames for resolving endpoint hosts.
      See `t:PcapFileEx.Endpoint.hosts_map/0` for details.

  ## Examples

      # Without hosts mapping
      packet = Packet.from_map(nif_map)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "server", "10.0.0.1" => "client"}
      packet = Packet.from_map(nif_map, hosts_map: hosts)
      # packet.src.host and packet.dst.host will be resolved if IPs match
  """
  @spec from_map(map()) :: t()
  def from_map(map), do: from_map(map, [])

  @spec from_map(map(), keyword()) :: t()
  def from_map(map, opts) do
    hosts_map = Keyword.get(opts, :hosts_map, %{})

    datalink = Map.get(map, :datalink)
    # Create DateTime timestamp (microsecond precision, for backward compatibility)
    timestamp = DateTime.from_unix!(map.timestamp_secs, :second)
    timestamp = DateTime.add(timestamp, div(map.timestamp_nanos, 1000), :microsecond)
    # Create precise timestamp (full nanosecond precision)
    timestamp_precise = Timestamp.new(map.timestamp_secs, map.timestamp_nanos)
    base_data = :binary.list_to_bin(map.data)
    {data, normalized_datalink} = normalize_loopback(base_data, datalink)
    {protocols, src, dst, layers, payload} = extract_metadata(data, normalized_datalink)
    protocol = List.last(protocols)
    timestamp_resolution = map |> Map.get(:timestamp_resolution) |> resolution_from_value()
    interface_map = map |> Map.get(:interface) |> interface_from_value()
    interface_id = Map.get(map, :interface_id)

    # Apply hosts mapping to endpoints
    src = Endpoint.with_hosts(src, hosts_map)
    dst = Endpoint.with_hosts(dst, hosts_map)

    %__MODULE__{
      timestamp: timestamp,
      timestamp_precise: timestamp_precise,
      orig_len: map.orig_len,
      data: data,
      datalink: normalized_datalink,
      timestamp_resolution: timestamp_resolution,
      interface_id: interface_id,
      interface: interface_map,
      protocols: protocols,
      protocol: protocol,
      src: src,
      dst: dst,
      layers: layers,
      payload: payload,
      decoded: %{}
    }
  end

  defp normalize_loopback(data, datalink) when datalink in ["null", "loop"] do
    case data do
      <<family_bytes::binary-size(4), rest::binary>> ->
        family_le = :binary.decode_unsigned(family_bytes, :little)
        family_be = :binary.decode_unsigned(family_bytes, :big)

        case {family_to_datalink(family_le), family_to_datalink(family_be)} do
          {new_datalink, _} when is_binary(new_datalink) -> {rest, new_datalink}
          {_, new_datalink} when is_binary(new_datalink) -> {rest, new_datalink}
          _ -> {data, datalink}
        end

      _ ->
        {data, datalink}
    end
  end

  defp normalize_loopback(data, datalink), do: {data, datalink}

  defp resolution_from_value(nil), do: nil
  defp resolution_from_value("nanosecond"), do: :nanosecond
  defp resolution_from_value("microsecond"), do: :microsecond
  defp resolution_from_value("millisecond"), do: :millisecond
  defp resolution_from_value("second"), do: :second
  defp resolution_from_value(_), do: :unknown

  defp interface_from_value(nil), do: nil
  defp interface_from_value(map) when is_map(map), do: Interface.from_map(map)
  defp interface_from_value(_), do: nil

  defp family_to_datalink(2), do: "ipv4"
  defp family_to_datalink(family) when family in @loopback_ipv6_families, do: "ipv6"
  defp family_to_datalink(_family), do: nil

  @doc """
  Returns the suggested `:pkt` protocol atom for the packet's link type.
  """
  @spec pkt_protocol(t()) :: atom()
  def pkt_protocol(%__MODULE__{datalink: datalink}) do
    protocol_from_datalink(datalink)
  end

  @doc """
  Formats an endpoint as `"ip:port"` (or just `ip` when the port is absent).
  """
  @spec endpoint_to_string(Endpoint.t() | nil) :: String.t() | nil
  def endpoint_to_string(endpoint), do: Endpoint.to_string(endpoint)

  @doc """
  Convenience wrapper around `:pkt.decode/2` that uses the packet's link type.
  """
  @spec pkt_decode(t()) :: term()
  def pkt_decode(%__MODULE__{} = packet) do
    :pkt.decode(pkt_protocol(packet), packet.data)
  end

  @doc """
  Same as `pkt_decode/1` but returns the decoded value directly or raises on error.
  """
  @spec pkt_decode!(t()) :: term()
  def pkt_decode!(%__MODULE__{} = packet) do
    case pkt_decode(packet) do
      {:ok, decoded} ->
        decoded

      {:error, _partial, reason} ->
        raise RuntimeError, "pkt decode failed: #{inspect(reason)}"
    end
  end

  @doc """
  Extracts the HTTP payload (if any) from the packet.
  """
  @spec http_payload(t()) :: {:ok, binary()} | {:error, atom() | tuple()}
  def http_payload(%__MODULE__{} = packet) do
    extract_payload(packet, :tcp)
  end

  @doc """
  Decodes the HTTP payload into a structured representation.
  """
  @spec decode_http(t()) :: {:ok, HTTP.t()} | {:error, atom() | tuple()}
  def decode_http(%__MODULE__{} = packet) do
    with {:ok, payload} <- http_payload(packet) do
      HTTP.decode(payload)
    end
  end

  @doc """
  Same as `decode_http/1` but raises on error.
  """
  @spec decode_http!(t()) :: HTTP.t()
  def decode_http!(%__MODULE__{} = packet) do
    case decode_http(packet) do
      {:ok, http} -> http
      {:error, reason} -> raise RuntimeError, "http decode failed: #{inspect(reason)}"
    end
  end

  @doc """
  Extracts the UDP payload from the packet.
  """
  @spec udp_payload(t()) :: {:ok, binary()} | {:error, atom() | tuple()}
  def udp_payload(%__MODULE__{} = packet) do
    extract_payload(packet, :udp)
  end

  @doc """
  Attempts to decode the payload using the registered application decoders.

  Returns `{:ok, {protocol, decoded}}` when a decoder matches, `:no_match` when
  none do, or `{:error, reason}` if the decoder raises or returns an error tuple.
  """
  @spec decode_registered(t()) :: {:ok, {atom(), term()}} | :no_match | {:error, term()}
  def decode_registered(%__MODULE__{} = packet) do
    with {:ok, {layers, payload}} <- layers_payload(packet),
         {:ok, {entry, context}} <- find_decoder(layers, payload) do
      case cached_decoded(packet, entry.protocol) do
        {:ok, value} ->
          {:ok, {entry.protocol, value}}

        :miss ->
          case safe_decode(entry, context, payload) do
            {:ok, decoded} -> {:ok, {entry.protocol, decoded}}
            other -> other
          end
      end
    else
      :no_match -> :no_match
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Convenience variant of `decode_registered/1` that returns the decoded value or `nil`.
  Raises on decoder errors.
  """
  @spec decode_registered!(t()) :: term() | nil
  def decode_registered!(%__MODULE__{} = packet) do
    case decode_registered(packet) do
      {:ok, {_, value}} -> value
      :no_match -> nil
      {:error, reason} -> raise RuntimeError, "decoder failed: #{inspect(reason)}"
    end
  end

  @doc """
  Attaches the decoded payload (when available) to the packet's `decoded` map.

  Supports both bare packets and tagged tuples from safe streams.
  """
  @spec attach_decoded(t() | {:ok, t()} | {:error, map()}) :: t() | {:ok, t()} | {:error, map()}
  def attach_decoded({:ok, %__MODULE__{} = packet}) do
    {:ok, attach_decoded(packet)}
  end

  def attach_decoded({:error, _} = error) do
    error
  end

  def attach_decoded(%__MODULE__{} = packet) do
    case decode_registered(packet) do
      {:ok, {protocol, value}} ->
        decoded = Map.put(packet.decoded, protocol, value)
        %__MODULE__{packet | decoded: decoded}

      _ ->
        packet
    end
  end

  defp cached_decoded(%__MODULE__{decoded: decoded}, protocol) do
    case decoded && Map.get(decoded, protocol) do
      nil -> :miss
      value -> {:ok, value}
    end
  end

  defp layers_payload(%__MODULE__{layers: layers, payload: payload})
       when is_list(layers) and is_binary(payload) do
    {:ok, {layers, payload}}
  end

  defp layers_payload(%__MODULE__{} = packet) do
    decode_layers(protocol_from_datalink(packet.datalink), packet.data)
  end

  defp extract_payload(packet, required_protocol) do
    case pkt_decode(packet) do
      {:ok, {layers, payload}} when is_binary(payload) ->
        layers_list = List.wrap(layers)

        if has_protocol?(layers_list, required_protocol) do
          payload_result(payload)
        else
          {:error, {:protocol_not_found, required_protocol}}
        end

      {:error, _partial, reason} ->
        {:error, reason}

      other ->
        {:error, {:unexpected_decode_result, other}}
    end
  end

  defp payload_result(payload) when payload != "", do: {:ok, payload}
  defp payload_result(_payload), do: {:error, :empty_payload}

  defp has_protocol?(layers, protocol) do
    Enum.any?(layers, &layer_protocol?(&1, protocol))
  end

  defp layer_protocol?(layer, protocol) when is_tuple(layer) do
    tuple_size(layer) > 0 and elem(layer, 0) == protocol
  end

  defp layer_protocol?(layer, protocol) when is_map(layer) do
    Map.get(layer, :protocol) == protocol
  end

  defp layer_protocol?(layer, protocol), do: layer == protocol

  defp extract_metadata(data, datalink) do
    case decode_layers(protocol_from_datalink(datalink), data) do
      {:ok, {layers, payload}} ->
        layers_list = layers
        norm_payload = normalize_payload(payload)
        protocols = build_protocol_stack(layers_list, norm_payload)
        {src_ip, dst_ip, src_port, dst_port} = extract_endpoints(layers_list)

        src = build_endpoint(src_ip, src_port)
        dst = build_endpoint(dst_ip, dst_port)

        {protocols, src, dst, layers_list, norm_payload}

      _ ->
        {[], nil, nil, nil, nil}
    end
  end

  defp build_protocol_stack(layers, payload) do
    base =
      layers
      |> Enum.map(&layer_atom/1)
      |> Enum.reject(&is_nil/1)

    applications =
      DecoderRegistry.list()
      |> Enum.reduce([], fn entry, acc ->
        case safe_match?(entry, layers, payload) do
          {:match, _context} -> acc ++ [entry.protocol]
          _ -> acc
        end
      end)

    (base ++ applications)
    |> Enum.uniq()
  end

  defp decode_layers(proto, data) do
    case :pkt.decode(proto, data) do
      {:ok, {layers, payload}} ->
        {:ok, {List.wrap(layers), payload}}

      {:error, _partial, reason} ->
        {:error, reason}
    end
  rescue
    _ -> {:error, :decode_failed}
  end

  defp find_decoder(layers, payload) do
    DecoderRegistry.list()
    |> Enum.find_value(fn entry ->
      case safe_match?(entry, layers, payload) do
        {:match, context} -> {:ok, {entry, context}}
        false -> nil
      end
    end)
    |> case do
      nil -> :no_match
      # {:ok, {entry, context}}
      result -> result
    end
  end

  defp safe_match?(%{matcher: matcher}, layers, payload) do
    case matcher.(layers, normalize_payload(payload)) do
      # New API
      {:match, context} -> {:match, context}
      # Old API (backward compat)
      true -> {:match, nil}
      false -> false
    end
  rescue
    _ -> false
  end

  defp safe_decode(%{decoder: decoder}, context, payload) do
    case decoder.(context, normalize_payload(payload)) do
      {:ok, value} -> {:ok, value}
      {:error, reason} -> {:error, reason}
      value -> {:ok, value}
    end
  rescue
    exception -> {:error, exception}
  end

  defp layer_atom(layer) when is_tuple(layer) and tuple_size(layer) > 0, do: elem(layer, 0)
  defp layer_atom(layer) when is_atom(layer), do: layer
  defp layer_atom(_), do: nil

  defp extract_endpoints(layers) do
    Enum.reduce(layers, {nil, nil, nil, nil}, fn layer, {src_ip, dst_ip, src_port, dst_port} ->
      case layer_atom(layer) do
        :ipv4 ->
          {new_src, new_dst} = ipv4_addresses(layer)
          {new_src || src_ip, new_dst || dst_ip, src_port, dst_port}

        :ipv6 ->
          {new_src, new_dst} = ipv6_addresses(layer)
          {new_src || src_ip, new_dst || dst_ip, src_port, dst_port}

        :tcp ->
          {new_src_port, new_dst_port} = transport_ports(layer)
          {src_ip, dst_ip, new_src_port || src_port, new_dst_port || dst_port}

        :udp ->
          {new_src_port, new_dst_port} = transport_ports(layer)
          {src_ip, dst_ip, new_src_port || src_port, new_dst_port || dst_port}

        _ ->
          {src_ip, dst_ip, src_port, dst_port}
      end
    end)
  end

  defp format_ip({_, _, _, _} = ip), do: ip |> :inet.ntoa() |> to_string()
  defp format_ip({_, _, _, _, _, _, _, _} = ip), do: ip |> :inet.ntoa() |> to_string()
  defp format_ip(_), do: nil

  defp build_endpoint(nil, _port), do: nil
  defp build_endpoint(ip, port), do: Endpoint.new(ip, port)

  defp protocol_from_datalink(datalink) do
    Map.get(@pkt_protocol_map, datalink, @default_pkt_protocol)
  end

  defp ipv4_addresses({:ipv4, _, _, _, _, _, _, _, _, _, _, _, src, dst, _}),
    do: {format_ip(src), format_ip(dst)}

  defp ipv4_addresses(layer), do: tuple_ip_addresses(layer)

  defp ipv6_addresses(layer), do: tuple_ip_addresses(layer)

  defp tuple_ip_addresses(layer) when is_tuple(layer) do
    layer
    |> Tuple.to_list()
    |> Enum.filter(&ip_tuple?/1)
    |> case do
      [src, dst | _] -> {format_ip(src), format_ip(dst)}
      _ -> {nil, nil}
    end
  end

  defp tuple_ip_addresses(_), do: {nil, nil}

  defp transport_ports(layer) when is_tuple(layer) and tuple_size(layer) >= 3 do
    src = elem(layer, 1)
    dst = elem(layer, 2)

    if is_integer(src) and is_integer(dst) do
      {src, dst}
    else
      {nil, nil}
    end
  end

  defp transport_ports(_), do: {nil, nil}

  defp ip_tuple?(value) when is_tuple(value) do
    size = tuple_size(value)

    if size == 4 or size == 8 do
      Enum.all?(Tuple.to_list(value), &is_integer/1)
    else
      false
    end
  end

  defp ip_tuple?(_), do: false

  defp normalize_payload(nil), do: <<>>
  defp normalize_payload(payload) when is_binary(payload), do: payload
  defp normalize_payload(payload), do: IO.iodata_to_binary(payload)

  @doc """
  Converts a Packet struct to a map for passing to NIFs.

  Note: Only includes the core fields needed for writing packets.
  Protocol decoding fields (protocols, src, dst, layers, etc.) are not included
  as they are derived during reading.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = packet) do
    # Ensure data is a binary list (Rust expects Vec<u8>)
    data_list = :binary.bin_to_list(packet.data)

    %{
      timestamp_secs: packet.timestamp_precise.secs,
      timestamp_nanos: packet.timestamp_precise.nanos,
      orig_len: packet.orig_len,
      data: data_list,
      datalink: packet.datalink,
      timestamp_resolution:
        packet.timestamp_resolution && Atom.to_string(packet.timestamp_resolution),
      interface_id: packet.interface_id,
      interface: packet.interface && Interface.to_map(packet.interface)
    }
  end

  @doc """
  Returns the list of protocols that may appear in `packet.protocols`.
  """
  @spec known_protocols() :: [atom()]
  def known_protocols do
    base = @pkt_protocol_map |> Map.values() |> Enum.uniq()
    apps = DecoderRegistry.list() |> Enum.map(& &1.protocol)

    (base ++ apps)
    |> Enum.uniq()
    |> Enum.sort()
  end
end
