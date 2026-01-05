defmodule PcapFileEx.HTTP2.Exchange do
  @moduledoc """
  Represents a complete HTTP/2 request/response exchange.

  An exchange is complete when both the request and response have received
  their END_STREAM flag, indicating no more data will be sent.

  ## Structure

  - `stream_id` - HTTP/2 stream identifier
  - `client` - Client endpoint (set when client/server identified via HTTP/2 preface or stream semantics)
  - `server` - Server endpoint (set when client/server identified)
  - `endpoint_a` - First endpoint (set when client/server cannot be identified, uses flow_key order)
  - `endpoint_b` - Second endpoint (set when client/server cannot be identified)
  - `request` - Request data including headers, body, and method
  - `response` - Response data including headers, body, and status
  - `start_timestamp` - When first frame of this stream was seen
  - `end_timestamp` - When final END_STREAM frame was received

  ## Endpoint Semantics

  Exactly one pair of endpoint fields will be set:
  - When client/server roles are identified: `client` and `server` are set, `endpoint_a` and `endpoint_b` are nil
  - When identification fails: `endpoint_a` and `endpoint_b` are set, `client` and `server` are nil

  Use `client_identified?/1` to check which pair is set, and `endpoints/1` to get
  the pair of endpoints regardless of which fields are populated.
  """

  alias PcapFileEx.Endpoint
  alias PcapFileEx.HTTP.Content
  alias PcapFileEx.HTTP2.{Headers, StreamState}

  @type request :: %{
          headers: Headers.t(),
          trailers: Headers.t() | nil,
          body: binary(),
          decoded_body: Content.decoded() | nil,
          method: String.t(),
          path: String.t(),
          authority: String.t() | nil
        }

  @type response :: %{
          headers: Headers.t(),
          trailers: Headers.t() | nil,
          body: binary(),
          decoded_body: Content.decoded() | nil,
          status: integer(),
          informational: [Headers.t()]
        }

  @type t :: %__MODULE__{
          stream_id: non_neg_integer(),
          client: Endpoint.t() | nil,
          server: Endpoint.t() | nil,
          endpoint_a: Endpoint.t() | nil,
          endpoint_b: Endpoint.t() | nil,
          request: request(),
          response: response(),
          start_timestamp: DateTime.t(),
          end_timestamp: DateTime.t()
        }

  defstruct [
    :stream_id,
    :client,
    :server,
    :endpoint_a,
    :endpoint_b,
    :request,
    :response,
    :start_timestamp,
    :end_timestamp
  ]

  @typedoc "Tuple of {ip_tuple, port} for backwards compatibility"
  @type legacy_endpoint :: {tuple(), non_neg_integer()}

  @doc """
  Build a complete exchange from a finished stream state.

  Returns nil if the stream is not complete.

  ## Parameters

  - `stream` - The completed stream state
  - `tcp_flow` - Tuple of {{ip_tuple, port}, {ip_tuple, port}} (legacy format)
  - `opts` - Options:
    - `:hosts_map` - Map of IP strings to hostnames
    - `:client_identified` - Whether client/server roles were identified (default: true)
  """
  @spec from_stream(StreamState.t(), {legacy_endpoint(), legacy_endpoint()}) :: t() | nil
  def from_stream(stream, tcp_flow), do: from_stream(stream, tcp_flow, [])

  @spec from_stream(StreamState.t(), {legacy_endpoint(), legacy_endpoint()}, keyword()) ::
          t() | nil
  def from_stream(%StreamState{} = stream, {endpoint_a, endpoint_b}, opts) do
    if StreamState.complete?(stream) do
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
        request: build_request(stream),
        response: build_response(stream),
        start_timestamp: stream.created_at,
        end_timestamp: stream.completed_at
      }
    else
      nil
    end
  end

  @doc """
  Returns the pair of endpoints, regardless of whether client/server was identified.

  When client/server identified, returns `{client, server}`.
  When not identified, returns `{endpoint_a, endpoint_b}`.

  ## Examples

      {client, server} = Exchange.endpoints(exchange)
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

      if Exchange.client_identified?(exchange) do
        IO.puts("Client: \#{exchange.client}")
      else
        IO.puts("Endpoints: \#{exchange.endpoint_a} <-> \#{exchange.endpoint_b}")
      end
  """
  @spec client_identified?(t()) :: boolean()
  def client_identified?(%__MODULE__{client: client}), do: not is_nil(client)

  @doc """
  Build just the request portion from a stream state.

  Returns nil if no request headers are present.
  """
  @spec build_request(StreamState.t()) :: request() | nil
  def build_request(%StreamState{request_headers: nil}), do: nil

  def build_request(%StreamState{} = stream) do
    headers = stream.request_headers

    %{
      headers: headers,
      trailers: stream.request_trailers,
      body: StreamState.request_body_binary(stream),
      decoded_body: nil,
      method: Headers.method(headers) || "UNKNOWN",
      path: Headers.path(headers) || "/",
      authority: Headers.authority(headers)
    }
  end

  @doc """
  Build just the response portion from a stream state.

  Returns nil if no response headers are present.
  """
  @spec build_response(StreamState.t()) :: response() | nil
  def build_response(%StreamState{response_headers: nil}), do: nil

  def build_response(%StreamState{} = stream) do
    headers = stream.response_headers

    %{
      headers: headers,
      trailers: stream.response_trailers,
      body: StreamState.response_body_binary(stream),
      decoded_body: nil,
      status: Headers.status(headers) || 0,
      informational: stream.informational_responses
    }
  end

  @doc """
  Get a friendly string representation of the exchange.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = exchange) do
    "#{exchange.request.method} #{exchange.request.path} -> #{exchange.response.status}"
  end
end
