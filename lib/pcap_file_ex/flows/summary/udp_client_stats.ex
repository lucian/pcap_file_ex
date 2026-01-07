defmodule PcapFileEx.Flows.Summary.UDPClientStats do
  @moduledoc """
  Per-client UDP traffic statistics.

  Represents traffic from a single client IP to a UDP service.
  """

  defstruct [
    :client,
    :client_host,
    :packet_count,
    :total_bytes,
    :avg_size,
    :min_size,
    :max_size,
    :first_timestamp,
    :last_timestamp
  ]

  @type t :: %__MODULE__{
          client: String.t(),
          client_host: String.t() | nil,
          packet_count: non_neg_integer(),
          total_bytes: non_neg_integer(),
          avg_size: non_neg_integer() | nil,
          min_size: non_neg_integer(),
          max_size: non_neg_integer(),
          first_timestamp: PcapFileEx.Timestamp.t() | nil,
          last_timestamp: PcapFileEx.Timestamp.t() | nil
        }
end
