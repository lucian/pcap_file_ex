defmodule PcapFileEx.Stats do
  @moduledoc """
  Statistics and analysis functions for PCAP/PCAPNG files.
  """

  alias PcapFileEx.Packet

  @type stats :: %{
          packet_count: non_neg_integer(),
          total_bytes: non_neg_integer(),
          min_packet_size: non_neg_integer() | nil,
          max_packet_size: non_neg_integer(),
          avg_packet_size: float(),
          first_timestamp: DateTime.t() | nil,
          last_timestamp: DateTime.t() | nil,
          duration_seconds: float() | nil
        }

  @doc """
  Computes statistics for a capture file.

  Reads all packets and computes various statistics about the capture.

  **Note:** This function loads all packets into memory. For large files,
  consider using `compute_streaming/1` instead.

  ## Examples

      {:ok, stats} = PcapFileEx.Stats.compute("capture.pcap")
      IO.inspect(stats.packet_count)
      IO.inspect(stats.total_bytes)
  """
  @spec compute(Path.t()) :: {:ok, stats()} | {:error, String.t()}
  def compute(path) when is_binary(path) do
    case PcapFileEx.read_all(path) do
      {:ok, packets} ->
        {:ok, compute_from_packets(packets)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Computes statistics for a capture file using streaming (constant memory).

  Unlike `compute/1`, this function processes packets one at a time without
  loading the entire file into memory. This is ideal for large files (>100MB).

  Accepts either a file path or an existing stream of packets.

  ## Examples

      # From file path
      {:ok, stats} = PcapFileEx.Stats.compute_streaming("huge_10gb.pcap")
      IO.inspect(stats.packet_count)

      # From stream (can be combined with filtering)
      stats =
        PcapFileEx.stream!("capture.pcap")
        |> PcapFileEx.Filter.by_protocol(:tcp)
        |> PcapFileEx.Stats.compute_streaming()

      IO.inspect(stats.total_bytes)
  """
  @spec compute_streaming(Path.t() | Enumerable.t()) :: {:ok, stats()} | stats()
  def compute_streaming(path) when is_binary(path) do
    try do
      stats =
        PcapFileEx.stream!(path)
        |> compute_streaming()

      {:ok, stats}
    rescue
      e in RuntimeError -> {:error, e.message}
    end
  end

  def compute_streaming(stream) do
    stream
    |> Enum.reduce(initial_accumulator(), fn packet, acc ->
      update_accumulator(acc, packet)
    end)
    |> finalize_stats()
  end

  @doc """
  Computes statistics from a list of packets.

  ## Examples

      {:ok, packets} = PcapFileEx.read_all("capture.pcap")
      stats = PcapFileEx.Stats.compute_from_packets(packets)
  """
  @spec compute_from_packets([Packet.t()]) :: stats()
  def compute_from_packets(packets) when is_list(packets) do
    case packets do
      [] ->
        %{
          packet_count: 0,
          total_bytes: 0,
          min_packet_size: nil,
          max_packet_size: 0,
          avg_packet_size: 0.0,
          first_timestamp: nil,
          last_timestamp: nil,
          duration_seconds: nil
        }

      _ ->
        packet_count = length(packets)
        sizes = Enum.map(packets, fn p -> byte_size(p.data) end)
        total_bytes = Enum.sum(sizes)
        min_size = Enum.min(sizes)
        max_size = Enum.max(sizes)
        avg_size = total_bytes / packet_count

        timestamps = Enum.map(packets, & &1.timestamp)
        first_ts = Enum.min(timestamps, DateTime)
        last_ts = Enum.max(timestamps, DateTime)
        duration = DateTime.diff(last_ts, first_ts, :millisecond) / 1000.0

        %{
          packet_count: packet_count,
          total_bytes: total_bytes,
          min_packet_size: min_size,
          max_packet_size: max_size,
          avg_packet_size: avg_size,
          first_timestamp: first_ts,
          last_timestamp: last_ts,
          duration_seconds: duration
        }
    end
  end

  @doc """
  Gets the packet count from a capture file.

  This is optimized to just count packets without storing them in memory.

  ## Examples

      {:ok, count} = PcapFileEx.Stats.packet_count("capture.pcap")
      IO.puts("Total packets: \#{count}")
  """
  @spec packet_count(Path.t()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def packet_count(path) when is_binary(path) do
    try do
      count =
        PcapFileEx.stream!(path)
        |> Enum.count()

      {:ok, count}
    rescue
      e in RuntimeError -> {:error, e.message}
    end
  end

  @doc """
  Gets the total bytes captured in a file.

  ## Examples

      {:ok, bytes} = PcapFileEx.Stats.total_bytes("capture.pcap")
      IO.puts("Total bytes: \#{bytes}")
  """
  @spec total_bytes(Path.t()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def total_bytes(path) when is_binary(path) do
    try do
      bytes =
        PcapFileEx.stream!(path)
        |> Enum.reduce(0, fn packet, acc ->
          acc + byte_size(packet.data)
        end)

      {:ok, bytes}
    rescue
      e in RuntimeError -> {:error, e.message}
    end
  end

  @doc """
  Gets the time range of packets in a capture file.

  Returns the first and last packet timestamps.

  ## Examples

      {:ok, {first, last}} = PcapFileEx.Stats.time_range("capture.pcap")
      IO.puts("Capture from \#{first} to \#{last}")
  """
  @spec time_range(Path.t()) ::
          {:ok, {DateTime.t(), DateTime.t()}} | {:error, String.t()}
  def time_range(path) when is_binary(path) do
    case PcapFileEx.read_all(path) do
      {:ok, []} ->
        {:error, "No packets in file"}

      {:ok, packets} ->
        timestamps = Enum.map(packets, & &1.timestamp)
        first = Enum.min(timestamps, DateTime)
        last = Enum.max(timestamps, DateTime)
        {:ok, {first, last}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Gets the duration of a capture in seconds.

  ## Examples

      {:ok, duration} = PcapFileEx.Stats.duration("capture.pcap")
      IO.puts("Capture duration: \#{duration} seconds")
  """
  @spec duration(Path.t()) :: {:ok, float()} | {:error, String.t()}
  def duration(path) when is_binary(path) do
    case time_range(path) do
      {:ok, {first, last}} ->
        duration = DateTime.diff(last, first, :millisecond) / 1000.0
        {:ok, duration}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Computes packet size distribution statistics.

  Returns a map with percentile information about packet sizes.

  ## Examples

      {:ok, dist} = PcapFileEx.Stats.size_distribution("capture.pcap")
      IO.inspect(dist.median)
      IO.inspect(dist.p95)
  """
  @spec size_distribution(Path.t()) ::
          {:ok,
           %{
             min: non_neg_integer(),
             max: non_neg_integer(),
             median: float(),
             p95: float(),
             p99: float()
           }}
          | {:error, String.t()}
  def size_distribution(path) when is_binary(path) do
    case PcapFileEx.read_all(path) do
      {:ok, []} ->
        {:error, "No packets in file"}

      {:ok, packets} ->
        sizes = Enum.map(packets, fn p -> byte_size(p.data) end) |> Enum.sort()

        {:ok,
         %{
           min: List.first(sizes),
           max: List.last(sizes),
           median: percentile(sizes, 0.50),
           p95: percentile(sizes, 0.95),
           p99: percentile(sizes, 0.99)
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private helper functions

  # Streaming statistics accumulator functions

  defp initial_accumulator do
    %{
      count: 0,
      total_bytes: 0,
      min_size: nil,
      max_size: 0,
      first_timestamp: nil,
      last_timestamp: nil
    }
  end

  defp update_accumulator(acc, packet) do
    size = byte_size(packet.data)

    %{
      count: acc.count + 1,
      total_bytes: acc.total_bytes + size,
      min_size: if(acc.min_size, do: min(acc.min_size, size), else: size),
      max_size: max(acc.max_size, size),
      first_timestamp: acc.first_timestamp || packet.timestamp,
      last_timestamp: packet.timestamp
    }
  end

  defp finalize_stats(%{count: 0} = _acc) do
    %{
      packet_count: 0,
      total_bytes: 0,
      min_packet_size: nil,
      max_packet_size: 0,
      avg_packet_size: 0.0,
      first_timestamp: nil,
      last_timestamp: nil,
      duration_seconds: nil
    }
  end

  defp finalize_stats(acc) do
    duration =
      if acc.first_timestamp && acc.last_timestamp do
        DateTime.diff(acc.last_timestamp, acc.first_timestamp, :millisecond) / 1000.0
      else
        nil
      end

    %{
      packet_count: acc.count,
      total_bytes: acc.total_bytes,
      min_packet_size: acc.min_size,
      max_packet_size: acc.max_size,
      avg_packet_size: acc.total_bytes / acc.count,
      first_timestamp: acc.first_timestamp,
      last_timestamp: acc.last_timestamp,
      duration_seconds: duration
    }
  end

  defp percentile(sorted_list, p) when p >= 0 and p <= 1 do
    len = length(sorted_list)
    index = trunc((len - 1) * p)
    Enum.at(sorted_list, index) * 1.0
  end
end
