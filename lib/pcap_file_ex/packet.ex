defmodule PcapFileEx.Packet do
  @moduledoc """
  Represents a captured network packet.
  """

  alias PcapFileEx.{DecoderRegistry, Endpoint, HTTP}

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
          orig_len: non_neg_integer(),
          data: binary(),
          datalink: String.t() | nil,
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
    :orig_len,
    :data,
    :datalink,
    :protocols,
    :protocol,
    :src,
    :dst,
    :layers,
    :payload,
    :decoded
  ]

  @doc """
  Creates a Packet struct from a map returned by the NIF.
  """
  @spec from_map(map()) :: t()
  def from_map(map) do
    datalink = Map.get(map, :datalink)
    timestamp = DateTime.from_unix!(map.timestamp_secs, :second)
    timestamp = DateTime.add(timestamp, map.timestamp_nanos, :nanosecond)
    base_data = :binary.list_to_bin(map.data)
    {data, normalized_datalink} = normalize_loopback(base_data, datalink)
    {protocols, src, dst, layers, payload} = extract_metadata(data, normalized_datalink)
    protocol = List.last(protocols)

    %__MODULE__{
      timestamp: timestamp,
      orig_len: map.orig_len,
      data: data,
      datalink: normalized_datalink,
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

      {:error, reason} ->
        raise RuntimeError, "pkt decode failed: #{inspect(reason)}"

      other ->
        other
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
         {:ok, entry} <- find_decoder(layers, payload) do
      case cached_decoded(packet, entry.protocol) do
        {:ok, value} ->
          {:ok, {entry.protocol, value}}

        :miss ->
          case safe_decode(entry, payload) do
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
  """
  @spec attach_decoded(t()) :: t()
  def attach_decoded(%__MODULE__{} = packet) do
    case decode_registered(packet) do
      {:ok, {protocol, value}} ->
        decoded = Map.put(packet.decoded || %{}, protocol, value)
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

      {:ok, payload} when is_binary(payload) ->
        payload_result(payload)

      {:error, _} = error ->
        error

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
    with {:ok, {layers, payload}} <- decode_layers(protocol_from_datalink(datalink), data) do
      layers_list = layers
      norm_payload = normalize_payload(payload)
      protocols = build_protocol_stack(layers_list, norm_payload)
      {src_ip, dst_ip, src_port, dst_port} = extract_endpoints(layers_list)

      src = build_endpoint(src_ip, src_port)
      dst = build_endpoint(dst_ip, dst_port)

      {protocols, src, dst, layers_list, norm_payload}
    else
      _ -> {[], nil, nil, nil, nil}
    end
  end

  defp build_protocol_stack(layers, payload) do
    base =
      (layers || [])
      |> Enum.map(&layer_atom/1)
      |> Enum.reject(&is_nil/1)

    applications =
      DecoderRegistry.list()
      |> Enum.reduce([], fn entry, acc ->
        if safe_match?(entry, layers, payload) do
          acc ++ [entry.protocol]
        else
          acc
        end
      end)

    (base ++ applications)
    |> Enum.uniq()
  end

  defp decode_layers(proto, data) do
    try do
      case :pkt.decode(proto, data) do
        {:ok, {layers, payload}} -> {:ok, {List.wrap(layers), payload}}
        {:ok, layers} when is_list(layers) -> {:ok, {layers, ""}}
        {:ok, layer} -> {:ok, {List.wrap(layer), ""}}
        {:error, _} = error -> error
        other -> {:error, {:unexpected_decode, other}}
      end
    rescue
      _ -> {:error, :decode_failed}
    end
  end

  defp find_decoder(layers, payload) do
    DecoderRegistry.list()
    |> Enum.find(&safe_match?(&1, layers, payload))
    |> case do
      nil -> :no_match
      entry -> {:ok, entry}
    end
  end

  defp safe_match?(%{matcher: matcher}, layers, payload) do
    try do
      matcher.(layers || [], normalize_payload(payload))
    rescue
      _ -> false
    end
  end

  defp safe_decode(%{decoder: decoder}, payload) do
    try do
      case decoder.(normalize_payload(payload)) do
        {:ok, value} -> {:ok, value}
        {:error, reason} -> {:error, reason}
        value -> {:ok, value}
      end
    rescue
      exception -> {:error, exception}
    end
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

    cond do
      size == 4 or size == 8 ->
        Enum.all?(Tuple.to_list(value), &is_integer/1)

      true ->
        false
    end
  end

  defp ip_tuple?(_), do: false

  defp normalize_payload(nil), do: <<>>
  defp normalize_payload(payload) when is_binary(payload), do: payload
  defp normalize_payload(payload), do: IO.iodata_to_binary(payload)

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
