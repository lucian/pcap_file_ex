defmodule PcapFileEx.Timestamp do
  @moduledoc """
  High-precision timestamp supporting nanosecond resolution.

  Unlike Elixir's `DateTime` (limited to microsecond precision), this struct
  preserves full nanosecond precision from PCAP files. This is essential for
  accurate chronological sorting and merging of packets from multiple capture files.

  ## Structure

  A timestamp consists of two components:
  - `secs`: Unix timestamp in seconds since the epoch (January 1, 1970)
  - `nanos`: Nanoseconds component (0-999,999,999)

  ## Examples

      # Create a timestamp
      iex> PcapFileEx.Timestamp.new(1731065049, 735188123)
      %PcapFileEx.Timestamp{secs: 1731065049, nanos: 735188123}

      # Convert to total nanoseconds
      iex> ts = PcapFileEx.Timestamp.new(1731065049, 735188123)
      iex> PcapFileEx.Timestamp.to_unix_nanos(ts)
      1731065049735188123

      # Convert to DateTime (loses nanosecond precision)
      iex> ts = PcapFileEx.Timestamp.new(1731065049, 735188123)
      iex> PcapFileEx.Timestamp.to_datetime(ts)
      ~U[2024-11-08 11:24:09.735188Z]

      # Compare timestamps
      iex> ts1 = PcapFileEx.Timestamp.new(100, 500)
      iex> ts2 = PcapFileEx.Timestamp.new(100, 600)
      iex> PcapFileEx.Timestamp.compare(ts1, ts2)
      :lt

      # Sort packets by precise timestamp
      # packets
      # |> Enum.sort_by(& &1.timestamp_precise, PcapFileEx.Timestamp)

  ## Precision Note

  When converting to `DateTime` using `to_datetime/1`, the nanosecond precision
  is truncated to microseconds due to DateTime's limitations. The original
  nanosecond precision is preserved in the Timestamp struct itself.
  """

  defstruct [:secs, :nanos]

  @type t :: %__MODULE__{
          secs: non_neg_integer(),
          nanos: 0..999_999_999
        }

  @doc """
  Creates a new timestamp from seconds and nanoseconds.

  ## Parameters

  - `secs` - Unix timestamp in seconds since epoch
  - `nanos` - Nanoseconds component (0-999,999,999)

  ## Examples

      iex> PcapFileEx.Timestamp.new(1731065049, 735188123)
      %PcapFileEx.Timestamp{secs: 1731065049, nanos: 735188123}

      iex> PcapFileEx.Timestamp.new(0, 0)
      %PcapFileEx.Timestamp{secs: 0, nanos: 0}

  """
  @spec new(non_neg_integer(), 0..999_999_999) :: t()
  def new(secs, nanos)
      when is_integer(secs) and secs >= 0 and nanos >= 0 and nanos <= 999_999_999 do
    %__MODULE__{secs: secs, nanos: nanos}
  end

  @doc """
  Converts a timestamp to total nanoseconds since Unix epoch.

  This is useful for precise time calculations and comparisons.

  ## Examples

      iex> ts = PcapFileEx.Timestamp.new(1731065049, 735188123)
      iex> PcapFileEx.Timestamp.to_unix_nanos(ts)
      1731065049735188123

      iex> ts = PcapFileEx.Timestamp.new(0, 999999999)
      iex> PcapFileEx.Timestamp.to_unix_nanos(ts)
      999999999

  """
  @spec to_unix_nanos(t()) :: non_neg_integer()
  def to_unix_nanos(%__MODULE__{secs: secs, nanos: nanos}) do
    secs * 1_000_000_000 + nanos
  end

  @doc """
  Converts a timestamp to an Elixir DateTime.

  **Warning**: This conversion loses nanosecond precision! DateTime only supports
  microsecond precision (6 decimal places), so the last 3 digits of nanosecond
  precision are truncated.

  ## Examples

      iex> ts = PcapFileEx.Timestamp.new(1731065049, 735188123)
      iex> PcapFileEx.Timestamp.to_datetime(ts)
      ~U[2024-11-08 11:24:09.735188Z]
      # Note: 735188123 nanos becomes 735188 micros (lost 123 nanos)

  """
  @spec to_datetime(t()) :: DateTime.t()
  def to_datetime(%__MODULE__{secs: secs, nanos: nanos}) do
    # Convert nanoseconds to microseconds (loses last 3 digits)
    micros = div(nanos, 1000)

    DateTime.from_unix!(secs, :second)
    |> DateTime.add(micros, :microsecond)
  end

  @doc """
  Creates a timestamp from an Elixir DateTime.

  The resulting timestamp will have microsecond precision, with the nanosecond
  component being the microsecond value multiplied by 1000.

  ## Parameters

  - `datetime` - The DateTime to convert
  - `resolution` - Optional resolution (`:microsecond` or `:nanosecond`). Defaults to `:microsecond`.

  ## Examples

      iex> dt = ~U[2024-11-08 11:24:09.735188Z]
      iex> PcapFileEx.Timestamp.from_datetime(dt)
      %PcapFileEx.Timestamp{secs: 1731065049, nanos: 735188000}

      iex> dt = ~U[2024-11-08 11:24:09.735188Z]
      iex> PcapFileEx.Timestamp.from_datetime(dt, :nanosecond)
      %PcapFileEx.Timestamp{secs: 1731065049, nanos: 735188000}

  """
  @spec from_datetime(DateTime.t(), :microsecond | :nanosecond) :: t()
  def from_datetime(%DateTime{} = dt, resolution \\ :microsecond) do
    secs = DateTime.to_unix(dt, :second)
    {micros, _precision} = dt.microsecond

    nanos =
      case resolution do
        :microsecond -> micros * 1000
        :nanosecond -> micros * 1000
      end

    new(secs, nanos)
  end

  @doc """
  Compares two timestamps.

  Returns:
  - `:lt` if the first timestamp is earlier than the second
  - `:eq` if the timestamps are equal
  - `:gt` if the first timestamp is later than the second

  ## Examples

      iex> ts1 = PcapFileEx.Timestamp.new(100, 500)
      iex> ts2 = PcapFileEx.Timestamp.new(100, 600)
      iex> PcapFileEx.Timestamp.compare(ts1, ts2)
      :lt

      iex> ts1 = PcapFileEx.Timestamp.new(200, 500)
      iex> ts2 = PcapFileEx.Timestamp.new(100, 600)
      iex> PcapFileEx.Timestamp.compare(ts1, ts2)
      :gt

      iex> ts1 = PcapFileEx.Timestamp.new(100, 500)
      iex> ts2 = PcapFileEx.Timestamp.new(100, 500)
      iex> PcapFileEx.Timestamp.compare(ts1, ts2)
      :eq

  """
  @spec compare(t(), t()) :: :lt | :eq | :gt
  def compare(%__MODULE__{secs: s1, nanos: n1}, %__MODULE__{secs: s2, nanos: n2}) do
    cond do
      s1 < s2 -> :lt
      s1 > s2 -> :gt
      n1 < n2 -> :lt
      n1 > n2 -> :gt
      true -> :eq
    end
  end

  @doc """
  Calculates the difference between two timestamps in nanoseconds.

  Returns a positive number if `ts1` is later than `ts2`, negative if earlier.

  ## Examples

      iex> ts1 = PcapFileEx.Timestamp.new(100, 500)
      iex> ts2 = PcapFileEx.Timestamp.new(100, 600)
      iex> PcapFileEx.Timestamp.diff(ts1, ts2)
      -100

      iex> ts1 = PcapFileEx.Timestamp.new(101, 0)
      iex> ts2 = PcapFileEx.Timestamp.new(100, 0)
      iex> PcapFileEx.Timestamp.diff(ts1, ts2)
      1000000000

  """
  @spec diff(t(), t()) :: integer()
  def diff(%__MODULE__{} = ts1, %__MODULE__{} = ts2) do
    to_unix_nanos(ts1) - to_unix_nanos(ts2)
  end

  # Protocol implementations

  defimpl String.Chars do
    def to_string(%PcapFileEx.Timestamp{} = ts) do
      dt = PcapFileEx.Timestamp.to_datetime(ts)
      # Add nanosecond component for full precision display
      subsec_nanos = rem(ts.nanos, 1000)

      if subsec_nanos == 0 do
        DateTime.to_string(dt)
      else
        # Show the additional nanosecond precision that DateTime can't represent
        micros_str =
          dt.microsecond |> elem(0) |> Integer.to_string() |> String.pad_leading(6, "0")

        nanos_str = subsec_nanos |> Integer.to_string() |> String.pad_leading(3, "0")
        date_part = DateTime.to_iso8601(dt) |> String.replace(~r/\.\d{6}Z$/, "")
        "#{date_part}.#{micros_str}#{nanos_str}Z"
      end
    end
  end

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%PcapFileEx.Timestamp{secs: secs, nanos: nanos}, _opts) do
      concat([
        "#PcapFileEx.Timestamp<",
        to_string(PcapFileEx.Timestamp.new(secs, nanos)),
        ">"
      ])
    end
  end
end
