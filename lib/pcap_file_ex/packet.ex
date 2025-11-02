defmodule PcapFileEx.Packet do
  @moduledoc """
  Represents a captured network packet.
  """

  @type t :: %__MODULE__{
          timestamp: DateTime.t(),
          orig_len: non_neg_integer(),
          data: binary()
        }

  defstruct [:timestamp, :orig_len, :data]

  @doc """
  Creates a Packet struct from a map returned by the NIF.
  """
  @spec from_map(map()) :: t()
  def from_map(map) do
    timestamp = DateTime.from_unix!(map.timestamp_secs, :second)
    timestamp = DateTime.add(timestamp, map.timestamp_nanos, :nanosecond)

    %__MODULE__{
      timestamp: timestamp,
      orig_len: map.orig_len,
      data: :binary.list_to_bin(map.data)
    }
  end
end
