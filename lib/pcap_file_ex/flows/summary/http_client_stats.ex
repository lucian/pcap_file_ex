defmodule PcapFileEx.Flows.Summary.HTTPClientStats do
  @moduledoc """
  Per-client HTTP traffic statistics.

  Represents traffic from a single client IP to an HTTP service.
  Used for both HTTP/1 and HTTP/2 protocols.
  """

  defstruct [
    :client,
    :client_host,
    :connection_count,
    :stream_count,
    :request_count,
    :response_count,
    :request_bytes,
    :response_bytes,
    :methods,
    :status_codes,
    :avg_response_time_ms,
    :min_response_time_ms,
    :max_response_time_ms,
    :first_timestamp,
    :last_timestamp
  ]

  @type t :: %__MODULE__{
          client: String.t(),
          client_host: String.t() | nil,
          connection_count: non_neg_integer(),
          stream_count: non_neg_integer() | nil,
          request_count: non_neg_integer(),
          response_count: non_neg_integer(),
          request_bytes: non_neg_integer(),
          response_bytes: non_neg_integer(),
          methods: %{String.t() => non_neg_integer()},
          status_codes: %{integer() => non_neg_integer()},
          avg_response_time_ms: number() | nil,
          min_response_time_ms: number() | nil,
          max_response_time_ms: number() | nil,
          first_timestamp: PcapFileEx.Timestamp.t() | nil,
          last_timestamp: PcapFileEx.Timestamp.t() | nil
        }
end
