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
  """

  alias PcapFileEx.HTTP2.{Exchange, StreamState}

  @type endpoint :: {tuple(), non_neg_integer()}

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
          tcp_flow: {endpoint(), endpoint()},
          request: Exchange.request() | nil,
          response: Exchange.response() | nil,
          reason: reason(),
          timestamp: DateTime.t()
        }

  defstruct [:stream_id, :tcp_flow, :request, :response, :reason, :timestamp]

  @doc """
  Build an incomplete exchange from a stream state.

  Determines the reason from the stream's termination_reason or infers
  from the stream's state.
  """
  @spec from_stream(StreamState.t(), {endpoint(), endpoint()}) :: t()
  def from_stream(%StreamState{} = stream, tcp_flow) do
    reason = determine_reason(stream)

    %__MODULE__{
      stream_id: stream.stream_id,
      tcp_flow: tcp_flow,
      request: Exchange.build_request(stream),
      response: Exchange.build_response(stream),
      reason: reason,
      timestamp: stream.completed_at || stream.created_at
    }
  end

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
