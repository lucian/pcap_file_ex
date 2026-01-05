defmodule PcapFileEx.Flows.HTTP2.Stream do
  @moduledoc """
  Wrapper around HTTP2.Exchange with sequence number and playback timing.

  Wraps the existing `PcapFileEx.HTTP2.Exchange` to add timeline ordering
  and playback timing metadata.

  ## Fields

  - `flow_seq` - Index within the flow's stream list (0-based)
  - `exchange` - The underlying `HTTP2.Exchange` (uses DateTime internally)
  - `start_timestamp` - Converted from exchange.start_timestamp to `Timestamp.t()`
  - `response_delay_ms` - Delay between request headers and response headers (for playback)

  ## Timestamp Conversion

  The existing `HTTP2.Exchange` uses `DateTime.t()` internally. This wrapper
  converts timestamps to `Timestamp.t()` via `Timestamp.from_datetime/1` for
  consistent nanosecond-precision handling across the Flows API.

  ## Playback Timing

  `response_delay_ms` is the full exchange duration in milliseconds:

  - Computed from `exchange.start_timestamp` to `exchange.end_timestamp`
  - 0 if either timestamp is not available

  **Note**: This is the total exchange duration (request start → response complete),
  not time-to-first-byte (TTFB). For large response bodies, this over-estimates
  actual response latency. See Known Limitations in the Flows documentation.

  ## Examples

      # Access the underlying exchange
      stream.exchange.request.method
      stream.exchange.response.status

      # Use for playback
      Process.sleep(stream.response_delay_ms)
      send_response(stream.exchange.response)
  """

  alias PcapFileEx.HTTP2.Exchange
  alias PcapFileEx.Timestamp

  @enforce_keys [:flow_seq, :exchange, :start_timestamp]
  defstruct [:flow_seq, :exchange, :start_timestamp, response_delay_ms: 0]

  @type t :: %__MODULE__{
          flow_seq: non_neg_integer(),
          exchange: Exchange.t(),
          start_timestamp: Timestamp.t(),
          response_delay_ms: non_neg_integer()
        }

  @doc """
  Creates a new Stream wrapper from an HTTP2.Exchange.

  Converts the DateTime timestamps to Timestamp and computes response_delay_ms.

  ## Parameters

  - `flow_seq` - Index within the flow's stream list
  - `exchange` - The HTTP2.Exchange to wrap

  ## Examples

      stream = Stream.from_exchange(0, exchange)
      stream.start_timestamp  # => %Timestamp{}
      stream.response_delay_ms  # => 150 (ms)
  """
  @spec from_exchange(non_neg_integer(), Exchange.t()) :: t()
  def from_exchange(flow_seq, %Exchange{} = exchange) do
    start_ts = convert_datetime(exchange.start_timestamp)
    response_delay = compute_response_delay(exchange)

    %__MODULE__{
      flow_seq: flow_seq,
      exchange: exchange,
      start_timestamp: start_ts,
      response_delay_ms: response_delay
    }
  end

  # Convert DateTime to Timestamp (nil-safe)
  defp convert_datetime(nil), do: nil
  defp convert_datetime(%DateTime{} = dt), do: Timestamp.from_datetime(dt)

  # Compute exchange duration in milliseconds from start to end timestamp
  defp compute_response_delay(%Exchange{} = exchange) do
    start_dt = exchange.start_timestamp
    end_dt = exchange.end_timestamp

    case {start_dt, end_dt} do
      {nil, _} -> 0
      {_, nil} -> 0
      {%DateTime{} = s, %DateTime{} = e} -> compute_delay_ms(s, e)
    end
  end

  defp compute_delay_ms(%DateTime{} = start_dt, %DateTime{} = end_dt) do
    # Convert to Unix microseconds and compute difference
    start_us = DateTime.to_unix(start_dt, :microsecond)
    end_us = DateTime.to_unix(end_dt, :microsecond)
    max(0, div(end_us - start_us, 1000))
  end
end
