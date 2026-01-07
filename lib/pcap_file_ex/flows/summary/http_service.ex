defmodule PcapFileEx.Flows.Summary.HTTPService do
  @moduledoc """
  Aggregated HTTP service summary.

  Represents traffic to a single HTTP server (IP:port), with per-client statistics.
  Used for both HTTP/1 and HTTP/2 protocols.
  """

  alias PcapFileEx.Flows.Summary.HTTPClientStats

  defstruct [
    :protocol,
    :server,
    :server_host,
    :clients,
    :total_requests,
    :total_responses,
    :total_request_bytes,
    :total_response_bytes,
    :methods,
    :status_codes,
    :first_timestamp,
    :last_timestamp
  ]

  @type t :: %__MODULE__{
          protocol: :http1 | :http2,
          server: String.t(),
          server_host: String.t() | nil,
          clients: [HTTPClientStats.t()],
          total_requests: non_neg_integer(),
          total_responses: non_neg_integer(),
          total_request_bytes: non_neg_integer(),
          total_response_bytes: non_neg_integer(),
          methods: %{String.t() => non_neg_integer()},
          status_codes: %{integer() => non_neg_integer()},
          first_timestamp: PcapFileEx.Timestamp.t() | nil,
          last_timestamp: PcapFileEx.Timestamp.t() | nil
        }
end
