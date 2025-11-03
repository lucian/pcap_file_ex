defmodule PcapFileEx.Interface do
  @moduledoc """
  Metadata describing an interface present in a PCAPNG capture.
  """

  @type timestamp_resolution :: :microsecond | :nanosecond | :millisecond | :second | :unknown

  @type t :: %__MODULE__{
          id: non_neg_integer(),
          name: String.t() | nil,
          description: String.t() | nil,
          linktype: String.t(),
          snaplen: non_neg_integer(),
          timestamp_resolution: timestamp_resolution(),
          timestamp_resolution_raw: String.t(),
          timestamp_offset_secs: non_neg_integer()
        }

  defstruct [
    :id,
    :name,
    :description,
    :linktype,
    :snaplen,
    :timestamp_resolution,
    :timestamp_resolution_raw,
    :timestamp_offset_secs
  ]

  @doc false
  @spec from_map(map()) :: t()
  def from_map(map) when is_map(map) do
    raw_resolution = Map.get(map, :timestamp_resolution, "unknown")

    %__MODULE__{
      id: Map.fetch!(map, :id),
      name: Map.get(map, :name),
      description: Map.get(map, :description),
      linktype: Map.fetch!(map, :linktype),
      snaplen: Map.fetch!(map, :snaplen),
      timestamp_resolution: resolution_from_string(raw_resolution),
      timestamp_resolution_raw: raw_resolution,
      timestamp_offset_secs: Map.get(map, :timestamp_offset_secs, 0)
    }
  end

  defp resolution_from_string("nanosecond"), do: :nanosecond
  defp resolution_from_string("microsecond"), do: :microsecond
  defp resolution_from_string("millisecond"), do: :millisecond
  defp resolution_from_string("second"), do: :second
  defp resolution_from_string(_), do: :unknown
end
