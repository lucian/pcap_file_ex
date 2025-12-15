defmodule PcapFileEx.HTTP2.Exchange do
  @moduledoc """
  Represents a complete HTTP/2 request/response exchange.

  An exchange is complete when both the request and response have received
  their END_STREAM flag, indicating no more data will be sent.

  ## Structure

  - `stream_id` - HTTP/2 stream identifier
  - `tcp_flow` - Tuple of {client_endpoint, server_endpoint}
  - `request` - Request data including headers, body, and method
  - `response` - Response data including headers, body, and status
  - `start_timestamp` - When first frame of this stream was seen
  - `end_timestamp` - When final END_STREAM frame was received
  """

  alias PcapFileEx.HTTP.Content
  alias PcapFileEx.HTTP2.{Headers, StreamState}

  @type endpoint :: {tuple(), non_neg_integer()}

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
          tcp_flow: {endpoint(), endpoint()},
          request: request(),
          response: response(),
          start_timestamp: DateTime.t(),
          end_timestamp: DateTime.t()
        }

  defstruct [:stream_id, :tcp_flow, :request, :response, :start_timestamp, :end_timestamp]

  @doc """
  Build a complete exchange from a finished stream state.

  Returns nil if the stream is not complete.
  """
  @spec from_stream(StreamState.t(), {endpoint(), endpoint()}) :: t() | nil
  def from_stream(%StreamState{} = stream, tcp_flow) do
    if StreamState.complete?(stream) do
      %__MODULE__{
        stream_id: stream.stream_id,
        tcp_flow: tcp_flow,
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
