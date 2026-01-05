defmodule PcapFileEx.HTTP2.IncompleteExchange do
  @moduledoc """
  Represents a partial HTTP/2 exchange that couldn't complete.

  The reason field indicates why the exchange is incomplete:

  ## Protocol-level termination
  - `{:rst_stream, error_code}` - Stream was reset by peer
  - `{:goaway, last_stream_id}` - Connection was shut down

  ## PCAP truncation (capture ended mid-stream)
  - `:truncated_no_response` - Request sent, no response headers seen
  - `:truncated_incomplete_response` - Response headers seen, no END_STREAM
  - `:truncated_incomplete_headers` - Mid-CONTINUATION, waiting for END_HEADERS

  ## TCP-level issues
  - `:tcp_fin_without_end_stream` - TCP closed before HTTP/2 END_STREAM

  ## Decode errors
  - `{:hpack_error, term()}` - HPACK decompression failed
  - `{:frame_error, term()}` - Malformed frame (bad padding, etc.)

  ## Endpoint Semantics

  Exactly one pair of endpoint fields will be set:
  - When client/server roles are identified: `client` and `server` are set, `endpoint_a` and `endpoint_b` are nil
  - When identification fails: `endpoint_a` and `endpoint_b` are set, `client` and `server` are nil

  Use `client_identified?/1` to check which pair is set, and `endpoints/1` to get
  the pair of endpoints regardless of which fields are populated.
  """

  alias PcapFileEx.Endpoint
  alias PcapFileEx.HTTP2.{Exchange, StreamState}

  @typedoc "Tuple of {ip_tuple, port} for backwards compatibility"
  @type legacy_endpoint :: {tuple(), non_neg_integer()}

  # Protocol-level termination
  @type reason ::
          {:rst_stream, error_code :: non_neg_integer()}
          | {:goaway, last_stream_id :: non_neg_integer()}
          # PCAP truncation (capture ended mid-stream)
          | :truncated_no_response
          | :truncated_incomplete_response
          | :truncated_incomplete_headers
          # TCP-level issues
          | :tcp_fin_without_end_stream
          # Decode errors
          | {:hpack_error, term()}
          | {:frame_error, term()}

  @type t :: %__MODULE__{
          stream_id: non_neg_integer(),
          client: Endpoint.t() | nil,
          server: Endpoint.t() | nil,
          endpoint_a: Endpoint.t() | nil,
          endpoint_b: Endpoint.t() | nil,
          request: Exchange.request() | nil,
          response: Exchange.response() | nil,
          reason: reason(),
          timestamp: DateTime.t()
        }

  defstruct [
    :stream_id,
    :client,
    :server,
    :endpoint_a,
    :endpoint_b,
    :request,
    :response,
    :reason,
    :timestamp
  ]

  @doc """
  Build an incomplete exchange from a stream state.

  Determines the reason from the stream's termination_reason or infers
  from the stream's state.

  ## Parameters

  - `stream` - The stream state
  - `tcp_flow` - Tuple of {{ip_tuple, port}, {ip_tuple, port}} (legacy format)
  - `opts` - Options:
    - `:hosts_map` - Map of IP strings to hostnames
    - `:client_identified` - Whether client/server roles were identified (default: true)
  """
  @spec from_stream(StreamState.t(), {legacy_endpoint(), legacy_endpoint()}) :: t()
  def from_stream(stream, tcp_flow), do: from_stream(stream, tcp_flow, [])

  @spec from_stream(StreamState.t(), {legacy_endpoint(), legacy_endpoint()}, keyword()) :: t()
  def from_stream(%StreamState{} = stream, {endpoint_a, endpoint_b}, opts) do
    reason = determine_reason(stream)
    hosts_map = Keyword.get(opts, :hosts_map, %{})
    client_identified = Keyword.get(opts, :client_identified, true)

    {client, server, ep_a, ep_b} =
      if client_identified do
        {Endpoint.from_tuple(endpoint_a, hosts_map), Endpoint.from_tuple(endpoint_b, hosts_map),
         nil, nil}
      else
        {nil, nil, Endpoint.from_tuple(endpoint_a, hosts_map),
         Endpoint.from_tuple(endpoint_b, hosts_map)}
      end

    %__MODULE__{
      stream_id: stream.stream_id,
      client: client,
      server: server,
      endpoint_a: ep_a,
      endpoint_b: ep_b,
      request: Exchange.build_request(stream),
      response: Exchange.build_response(stream),
      reason: reason,
      timestamp: stream.completed_at || stream.created_at
    }
  end

  @doc """
  Returns the pair of endpoints, regardless of whether client/server was identified.

  When client/server identified, returns `{client, server}`.
  When not identified, returns `{endpoint_a, endpoint_b}`.

  ## Examples

      {client, server} = IncompleteExchange.endpoints(exchange)
  """
  @spec endpoints(t()) :: {Endpoint.t(), Endpoint.t()}
  def endpoints(%__MODULE__{client: client, server: server}) when not is_nil(client) do
    {client, server}
  end

  def endpoints(%__MODULE__{endpoint_a: a, endpoint_b: b}) do
    {a, b}
  end

  @doc """
  Returns true if client/server roles were identified for this exchange.

  ## Examples

      if IncompleteExchange.client_identified?(exchange) do
        IO.puts("Client: \#{exchange.client}")
      else
        IO.puts("Endpoints: \#{exchange.endpoint_a} <-> \#{exchange.endpoint_b}")
      end
  """
  @spec client_identified?(t()) :: boolean()
  def client_identified?(%__MODULE__{client: client}), do: not is_nil(client)

  @doc """
  Get a human-readable description of the incompletion reason.
  """
  @spec reason_string(reason()) :: String.t()
  def reason_string({:rst_stream, code}), do: "RST_STREAM (error code: #{code})"
  def reason_string({:goaway, last_id}), do: "GOAWAY (last stream: #{last_id})"
  def reason_string(:truncated_no_response), do: "Capture ended before response"
  def reason_string(:truncated_incomplete_response), do: "Capture ended before response completed"
  def reason_string(:truncated_incomplete_headers), do: "Capture ended mid-header block"
  def reason_string(:tcp_fin_without_end_stream), do: "TCP closed without HTTP/2 END_STREAM"
  def reason_string({:hpack_error, err}), do: "HPACK decode error: #{inspect(err)}"
  def reason_string({:frame_error, err}), do: "Frame error: #{inspect(err)}"

  @doc """
  Get a friendly string representation of the incomplete exchange.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = exchange) do
    req_part =
      if exchange.request do
        "#{exchange.request.method} #{exchange.request.path}"
      else
        "no request"
      end

    resp_part =
      if exchange.response do
        "-> #{exchange.response.status}"
      else
        "-> no response"
      end

    "#{req_part} #{resp_part} (#{reason_string(exchange.reason)})"
  end

  # Private helpers

  defp determine_reason(%StreamState{termination_reason: reason}) when reason != nil do
    reason
  end

  defp determine_reason(%StreamState{} = stream) do
    cond do
      stream.awaiting_continuation ->
        :truncated_incomplete_headers

      stream.request_headers != nil and stream.response_headers == nil ->
        :truncated_no_response

      not stream.request_complete or not stream.response_complete ->
        :truncated_incomplete_response

      true ->
        # Shouldn't happen for incomplete exchanges
        :truncated_incomplete_response
    end
  end
end
