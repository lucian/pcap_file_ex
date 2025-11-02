defmodule PcapFileEx.Filter do
  @moduledoc """
  Packet filtering helpers and DSL for PCAP/PCAPNG files.
  """

  alias PcapFileEx.{HTTP, Packet}

  @doc """
  Filters packets by size range.

  ## Examples

      # Get packets between 100 and 1500 bytes
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.by_size(100..1500)
      |> Enum.to_list()
  """
  @spec by_size(Enumerable.t(), Range.t()) :: Enumerable.t()
  def by_size(stream, range) do
    Stream.filter(stream, fn packet ->
      size = byte_size(packet.data)
      size in range
    end)
  end

  @doc """
  Filters packets larger than a given size.

  ## Examples

      # Get packets larger than 1000 bytes
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.larger_than(1000)
      |> Enum.to_list()
  """
  @spec larger_than(Enumerable.t(), non_neg_integer()) :: Enumerable.t()
  def larger_than(stream, size) do
    Stream.filter(stream, fn packet ->
      byte_size(packet.data) > size
    end)
  end

  @doc """
  Filters packets smaller than a given size.

  ## Examples

      # Get packets smaller than 100 bytes
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.smaller_than(100)
      |> Enum.to_list()
  """
  @spec smaller_than(Enumerable.t(), non_neg_integer()) :: Enumerable.t()
  def smaller_than(stream, size) do
    Stream.filter(stream, fn packet ->
      byte_size(packet.data) < size
    end)
  end

  @doc """
  Filters packets that contain the given protocol layer.

  Supports link-layer (e.g., `:ether`), network-layer (e.g., `:ipv4`),
  transport-layer (e.g., `:tcp`), and application protocols like `:http`.
  """
  @spec by_protocol(Enumerable.t(), atom()) :: Enumerable.t()
  def by_protocol(stream, protocol) when is_atom(protocol) do
    Stream.filter(stream, fn packet -> matches_protocol?(packet, protocol) end)
  end

  @doc """
  Filters packets by time range.

  ## Examples

      start_time = ~U[2025-11-02 10:00:00Z]
      end_time = ~U[2025-11-02 11:00:00Z]

      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.by_time_range(start_time, end_time)
      |> Enum.to_list()
  """
  @spec by_time_range(Enumerable.t(), DateTime.t(), DateTime.t()) :: Enumerable.t()
  def by_time_range(stream, start_time, end_time) do
    Stream.filter(stream, fn packet ->
      DateTime.compare(packet.timestamp, start_time) != :lt and
        DateTime.compare(packet.timestamp, end_time) != :gt
    end)
  end

  @doc """
  Filters packets after a given timestamp.

  ## Examples

      start_time = ~U[2025-11-02 10:00:00Z]

      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.after_time(start_time)
      |> Enum.to_list()
  """
  @spec after_time(Enumerable.t(), DateTime.t()) :: Enumerable.t()
  def after_time(stream, time) do
    Stream.filter(stream, fn packet ->
      DateTime.compare(packet.timestamp, time) != :lt
    end)
  end

  @doc """
  Filters packets before a given timestamp.

  ## Examples

      end_time = ~U[2025-11-02 11:00:00Z]

      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.before_time(end_time)
      |> Enum.to_list()
  """
  @spec before_time(Enumerable.t(), DateTime.t()) :: Enumerable.t()
  def before_time(stream, time) do
    Stream.filter(stream, fn packet ->
      DateTime.compare(packet.timestamp, time) != :gt
    end)
  end

  @doc """
  Filters packets containing specific byte patterns.

  ## Examples

      # Find packets containing HTTP GET
      pattern = "GET "

      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.contains(pattern)
      |> Enum.to_list()
  """
  @spec contains(Enumerable.t(), binary()) :: Enumerable.t()
  def contains(stream, pattern) when is_binary(pattern) do
    Stream.filter(stream, fn packet ->
      :binary.match(packet.data, pattern) != :nomatch
    end)
  end

  @doc """
  Filters packets matching a custom predicate function.

  ## Examples

      # Get packets with even length
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.matching(fn packet ->
        rem(byte_size(packet.data), 2) == 0
      end)
      |> Enum.to_list()
  """
  @spec matching(Enumerable.t(), (Packet.t() -> boolean())) :: Enumerable.t()
  def matching(stream, predicate) when is_function(predicate, 1) do
    Stream.filter(stream, predicate)
  end

  @doc """
  Samples every Nth packet from the stream.

  ## Examples

      # Get every 10th packet
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.sample(10)
      |> Enum.to_list()
  """
  @spec sample(Enumerable.t(), pos_integer()) :: Enumerable.t()
  def sample(stream, n) when is_integer(n) and n > 0 do
    stream
    |> Stream.with_index()
    |> Stream.filter(fn {_packet, index} -> rem(index, n) == 0 end)
    |> Stream.map(fn {packet, _index} -> packet end)
  end

  @doc """
  Limits the stream to the first N packets.

  ## Examples

      # Get first 100 packets
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.limit(100)
      |> Enum.to_list()
  """
  @spec limit(Enumerable.t(), non_neg_integer()) :: Enumerable.t()
  def limit(stream, n) when is_integer(n) and n >= 0 do
    Stream.take(stream, n)
  end

  @doc """
  Skips the first N packets in the stream.

  ## Examples

      # Skip first 50 packets
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.skip(50)
      |> Enum.to_list()
  """
  @spec skip(Enumerable.t(), non_neg_integer()) :: Enumerable.t()
  def skip(stream, n) when is_integer(n) and n >= 0 do
    Stream.drop(stream, n)
  end

  @doc """
  Filters packets with payload matching a regex pattern.

  Note: This converts packet data to string, which may not be appropriate
  for binary protocols.

  ## Examples

      # Find packets containing "HTTP/1.1"
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.matches_regex(~r/HTTP\\/1\\.1/)
      |> Enum.to_list()
  """
  @spec matches_regex(Enumerable.t(), Regex.t()) :: Enumerable.t()
  def matches_regex(stream, regex) do
    Stream.filter(stream, fn packet ->
      # Try to convert to string, ignore if it fails
      case :unicode.characters_to_binary(packet.data) do
        string when is_binary(string) ->
          Regex.match?(regex, string)

        _ ->
          false
      end
    end)
  end

  defp matches_protocol?(packet, protocol) do
    case Packet.pkt_decode(packet) do
      {:ok, {layers, payload}} ->
        protocol_match?(List.wrap(layers), payload, protocol)

      {:ok, layers} when is_list(layers) ->
        protocol_match?(layers, "", protocol)

      {:ok, other} ->
        protocol_match?(List.wrap(other), "", protocol)

      {:error, _} ->
        false
    end
  end

  defp protocol_match?(layers, payload, :http) do
    has_tcp_layer = Enum.any?(layers, &layer_protocol?(&1, :tcp))

    if has_tcp_layer do
      case HTTP.decode(payload) do
        {:ok, _} -> true
        _ -> false
      end
    else
      false
    end
  end

  defp protocol_match?(layers, _payload, protocol) do
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
