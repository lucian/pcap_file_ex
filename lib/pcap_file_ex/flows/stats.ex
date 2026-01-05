defmodule PcapFileEx.Flows.Stats do
  @moduledoc """
  Statistics for a flow or analysis result.

  Tracks packet counts, byte counts, and timing information with
  nanosecond-precision timestamps.

  ## Fields

  - `packet_count` - Total number of packets/events
  - `byte_count` - Total bytes transferred
  - `first_timestamp` - Timestamp of first packet (or `nil` if no packets)
  - `last_timestamp` - Timestamp of last packet (or `nil` if no packets)
  - `duration_ms` - Duration in milliseconds (0 when timestamps are nil or equal)

  ## Examples

      iex> alias PcapFileEx.Flows.Stats
      iex> Stats.new()
      %PcapFileEx.Flows.Stats{
        packet_count: 0,
        byte_count: 0,
        first_timestamp: nil,
        last_timestamp: nil,
        duration_ms: 0
      }
  """

  alias PcapFileEx.Timestamp

  defstruct packet_count: 0,
            byte_count: 0,
            first_timestamp: nil,
            last_timestamp: nil,
            duration_ms: 0

  @type t :: %__MODULE__{
          packet_count: non_neg_integer(),
          byte_count: non_neg_integer(),
          first_timestamp: Timestamp.t() | nil,
          last_timestamp: Timestamp.t() | nil,
          duration_ms: non_neg_integer()
        }

  @doc """
  Creates a new empty Stats struct.

  ## Examples

      iex> PcapFileEx.Flows.Stats.new()
      %PcapFileEx.Flows.Stats{packet_count: 0, byte_count: 0, first_timestamp: nil, last_timestamp: nil, duration_ms: 0}
  """
  @spec new() :: t()
  def new do
    %__MODULE__{}
  end

  @doc """
  Creates a Stats struct from timestamps and counts.

  Automatically computes `duration_ms` from the timestamps.

  ## Parameters

  - `packet_count` - Number of packets
  - `byte_count` - Total bytes
  - `first_timestamp` - First timestamp (or `nil`)
  - `last_timestamp` - Last timestamp (or `nil`)

  ## Examples

      iex> alias PcapFileEx.{Timestamp, Flows.Stats}
      iex> ts1 = Timestamp.new(1000, 0)
      iex> ts2 = Timestamp.new(1001, 500_000_000)
      iex> stats = Stats.from_timestamps(10, 5000, ts1, ts2)
      iex> stats.duration_ms
      1500
  """
  @spec from_timestamps(
          non_neg_integer(),
          non_neg_integer(),
          Timestamp.t() | nil,
          Timestamp.t() | nil
        ) :: t()
  def from_timestamps(packet_count, byte_count, first_timestamp, last_timestamp) do
    duration_ms = compute_duration_ms(first_timestamp, last_timestamp)

    %__MODULE__{
      packet_count: packet_count,
      byte_count: byte_count,
      first_timestamp: first_timestamp,
      last_timestamp: last_timestamp,
      duration_ms: duration_ms
    }
  end

  @doc """
  Merges two Stats structs.

  Combines counts and expands the time range to cover both.

  ## Examples

      iex> alias PcapFileEx.{Timestamp, Flows.Stats}
      iex> ts1 = Timestamp.new(1000, 0)
      iex> ts2 = Timestamp.new(1001, 0)
      iex> ts3 = Timestamp.new(1002, 0)
      iex> stats1 = Stats.from_timestamps(5, 1000, ts1, ts2)
      iex> stats2 = Stats.from_timestamps(3, 500, ts2, ts3)
      iex> merged = Stats.merge(stats1, stats2)
      iex> merged.packet_count
      8
      iex> merged.byte_count
      1500
      iex> merged.duration_ms
      2000
  """
  @spec merge(t(), t()) :: t()
  def merge(%__MODULE__{} = stats1, %__MODULE__{} = stats2) do
    first_ts = earliest_timestamp(stats1.first_timestamp, stats2.first_timestamp)
    last_ts = latest_timestamp(stats1.last_timestamp, stats2.last_timestamp)

    from_timestamps(
      stats1.packet_count + stats2.packet_count,
      stats1.byte_count + stats2.byte_count,
      first_ts,
      last_ts
    )
  end

  @doc """
  Updates stats with a new packet/event.

  ## Parameters

  - `stats` - Current stats
  - `timestamp` - Timestamp of the new event
  - `byte_size` - Size of the new event in bytes

  ## Examples

      iex> alias PcapFileEx.{Timestamp, Flows.Stats}
      iex> stats = Stats.new()
      iex> ts = Timestamp.new(1000, 0)
      iex> stats = Stats.add_event(stats, ts, 100)
      iex> stats.packet_count
      1
      iex> stats.byte_count
      100
  """
  @spec add_event(t(), Timestamp.t(), non_neg_integer()) :: t()
  def add_event(%__MODULE__{} = stats, timestamp, byte_size) do
    first_ts = earliest_timestamp(stats.first_timestamp, timestamp)
    last_ts = latest_timestamp(stats.last_timestamp, timestamp)

    from_timestamps(
      stats.packet_count + 1,
      stats.byte_count + byte_size,
      first_ts,
      last_ts
    )
  end

  # Compute duration in milliseconds from two timestamps
  defp compute_duration_ms(nil, _), do: 0
  defp compute_duration_ms(_, nil), do: 0

  defp compute_duration_ms(%Timestamp{} = first, %Timestamp{} = last) do
    diff_nanos = Timestamp.diff(last, first)
    # Ensure non-negative (in case timestamps are in wrong order)
    max(0, div(diff_nanos, 1_000_000))
  end

  # Get the earliest of two timestamps
  defp earliest_timestamp(nil, ts), do: ts
  defp earliest_timestamp(ts, nil), do: ts

  defp earliest_timestamp(%Timestamp{} = ts1, %Timestamp{} = ts2) do
    case Timestamp.compare(ts1, ts2) do
      :lt -> ts1
      _ -> ts2
    end
  end

  # Get the latest of two timestamps
  defp latest_timestamp(nil, ts), do: ts
  defp latest_timestamp(ts, nil), do: ts

  defp latest_timestamp(%Timestamp{} = ts1, %Timestamp{} = ts2) do
    case Timestamp.compare(ts1, ts2) do
      :gt -> ts1
      _ -> ts2
    end
  end
end
