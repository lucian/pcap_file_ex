defmodule PcapFileEx.Header do
  @moduledoc """
  Represents a PCAP file header.
  """

  @type datalink :: String.t()
  @type ts_resolution :: String.t()
  @type endianness :: String.t()

  @type t :: %__MODULE__{
          version_major: non_neg_integer(),
          version_minor: non_neg_integer(),
          snaplen: non_neg_integer(),
          datalink: datalink(),
          ts_resolution: ts_resolution(),
          endianness: endianness()
        }

  defstruct [
    :version_major,
    :version_minor,
    :snaplen,
    :datalink,
    :ts_resolution,
    :endianness
  ]

  @doc """
  Creates a Header struct from a map returned by the NIF.
  """
  @spec from_map(map()) :: t()
  def from_map(map) do
    %__MODULE__{
      version_major: map.version_major,
      version_minor: map.version_minor,
      snaplen: map.snaplen,
      datalink: map.datalink,
      ts_resolution: map.ts_resolution,
      endianness: map.endianness
    }
  end
end
