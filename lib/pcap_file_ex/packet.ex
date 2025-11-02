defmodule PcapFileEx.Packet do
  @moduledoc """
  Represents a captured network packet.
  """

  alias PcapFileEx.HTTP

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
          datalink: String.t() | nil
        }

  defstruct [:timestamp, :orig_len, :data, :datalink]

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

    %__MODULE__{
      timestamp: timestamp,
      orig_len: map.orig_len,
      data: data,
      datalink: normalized_datalink
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
    Map.get(@pkt_protocol_map, datalink, @default_pkt_protocol)
  end

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
end
