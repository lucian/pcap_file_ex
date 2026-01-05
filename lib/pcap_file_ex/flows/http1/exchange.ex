defmodule PcapFileEx.Flows.HTTP1.Exchange do
  @moduledoc """
  An HTTP/1.x request/response exchange.

  Represents a complete or partial HTTP/1.x transaction within a flow,
  including request, response, timing information, and playback metadata.

  ## Fields

  - `flow_seq` - Index within the flow's exchange list (0-based)
  - `request` - The HTTP request
  - `response` - The HTTP response (or `nil` if incomplete)
  - `start_timestamp` - When the request started
  - `end_timestamp` - When the response completed (or `nil`)
  - `response_delay_ms` - Delay between request and response (for playback)
  - `complete` - Whether both request and response are present

  ## Playback Timing

  `response_delay_ms` indicates how long to wait after receiving a request
  before sending the response during playback:

  - 0 if no response
  - Computed as: `div(Timestamp.diff(response.timestamp, request.timestamp), 1_000_000)`

  ## Examples

      # Check if exchange is complete
      if exchange.complete do
        IO.puts("\#{exchange.request.method} \#{exchange.request.path} -> \#{exchange.response.status}")
      end

      # Access timing for playback
      Process.sleep(exchange.response_delay_ms)
      send_response(exchange.response)
  """

  alias PcapFileEx.Timestamp

  @enforce_keys [:flow_seq, :request, :start_timestamp]
  defstruct [
    :flow_seq,
    :request,
    :response,
    :start_timestamp,
    :end_timestamp,
    response_delay_ms: 0,
    complete: false
  ]

  @type request :: %{
          method: String.t(),
          path: String.t(),
          version: String.t(),
          headers: %{String.t() => String.t()},
          body: binary(),
          decoded_body: term() | nil,
          timestamp: Timestamp.t()
        }

  @type response :: %{
          status: non_neg_integer(),
          reason: String.t(),
          version: String.t(),
          headers: %{String.t() => String.t()},
          body: binary(),
          decoded_body: term() | nil,
          timestamp: Timestamp.t()
        }

  @type t :: %__MODULE__{
          flow_seq: non_neg_integer(),
          request: request(),
          response: response() | nil,
          start_timestamp: Timestamp.t(),
          end_timestamp: Timestamp.t() | nil,
          response_delay_ms: non_neg_integer(),
          complete: boolean()
        }

  @doc """
  Creates a new exchange with a request.

  The exchange is incomplete until a response is added.

  ## Parameters

  - `flow_seq` - Index within the flow's exchange list
  - `request` - The HTTP request map

  ## Examples

      request = %{
        method: "GET",
        path: "/api/users",
        version: "1.1",
        headers: %{"host" => "api.example.com"},
        body: "",
        decoded_body: nil,
        timestamp: timestamp
      }
      exchange = Exchange.new(0, request)
  """
  @spec new(non_neg_integer(), request()) :: t()
  def new(flow_seq, request) do
    %__MODULE__{
      flow_seq: flow_seq,
      request: request,
      start_timestamp: request.timestamp,
      response: nil,
      end_timestamp: nil,
      response_delay_ms: 0,
      complete: false
    }
  end

  @doc """
  Adds a response to an exchange.

  Marks the exchange as complete and computes `response_delay_ms`.

  ## Parameters

  - `exchange` - The exchange to update
  - `response` - The HTTP response map

  ## Examples

      response = %{
        status: 200,
        reason: "OK",
        version: "1.1",
        headers: %{"content-type" => "application/json"},
        body: "{}",
        decoded_body: %{},
        timestamp: response_timestamp
      }
      exchange = Exchange.add_response(exchange, response)
  """
  @spec add_response(t(), response()) :: t()
  def add_response(%__MODULE__{} = exchange, response) do
    delay_ms = compute_response_delay(exchange.start_timestamp, response.timestamp)

    %{
      exchange
      | response: response,
        end_timestamp: response.timestamp,
        response_delay_ms: delay_ms,
        complete: true
    }
  end

  # Compute response delay in milliseconds
  defp compute_response_delay(%Timestamp{} = request_ts, %Timestamp{} = response_ts) do
    diff_nanos = Timestamp.diff(response_ts, request_ts)
    max(0, div(diff_nanos, 1_000_000))
  end
end
