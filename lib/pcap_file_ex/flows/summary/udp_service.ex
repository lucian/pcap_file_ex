defmodule PcapFileEx.Flows.Summary.UDPService do
  @moduledoc """
  Aggregated UDP service summary.

  Represents traffic to a single UDP destination (IP:port), with per-client statistics.
  """

  alias PcapFileEx.Flows.Summary.UDPClientStats

  defstruct [
    :server,
    :server_host,
    :clients,
    :total_packets,
    :total_bytes,
    :first_timestamp,
    :last_timestamp
  ]

  @type t :: %__MODULE__{
          server: String.t(),
          server_host: String.t() | nil,
          clients: [UDPClientStats.t()],
          total_packets: non_neg_integer(),
          total_bytes: non_neg_integer(),
          first_timestamp: PcapFileEx.Timestamp.t() | nil,
          last_timestamp: PcapFileEx.Timestamp.t() | nil
        }
end
