defmodule PcapFileEx.Flows.UDP.Datagram do
  @moduledoc """
  A UDP datagram within a flow.

  Represents a single UDP packet with source/destination endpoints,
  payload, timing information, and playback metadata.

  ## Fields

  - `flow_seq` - Index within the flow's datagram list (0-based)
  - `from` - Source endpoint
  - `to` - Destination endpoint
  - `payload` - UDP payload binary
  - `decoded_payload` - Custom decoder result, or `nil` if no decoder matched
  - `timestamp` - Datagram timestamp (nanosecond precision)
  - `relative_offset_ms` - Offset from flow start (for playback)
  - `size` - Payload size in bytes

  ## Custom Decoding

  When custom decoders are registered via `PcapFileEx.Flows.analyze/2`, the
  `decoded_payload` field contains the result:

  - `{:custom, term}` - Custom decoder succeeded
  - `{:decode_error, reason}` - Custom decoder failed
  - `nil` - No decoder matched or no decoders registered

  ## Playback Timing

  `relative_offset_ms` indicates when to send this datagram relative to
  the flow start time:

  - First datagram in flow has `relative_offset_ms = 0`
  - Computed as: `div(Timestamp.diff(datagram.timestamp, flow.stats.first_timestamp), 1_000_000)`

  ## Examples

      # Stream datagrams with proper timing
      start_time = System.monotonic_time(:millisecond)

      Enum.each(flow.datagrams, fn dg ->
        # Wait until the relative offset
        elapsed = System.monotonic_time(:millisecond) - start_time
        remaining = dg.relative_offset_ms - elapsed
        if remaining > 0, do: Process.sleep(remaining)

        send_udp(dg.to, dg.payload)
      end)
  """

  alias PcapFileEx.{Endpoint, Timestamp}

  @enforce_keys [:flow_seq, :from, :to, :payload, :timestamp, :size]
  defstruct [
    :flow_seq,
    :from,
    :to,
    :payload,
    :decoded_payload,
    :timestamp,
    :size,
    relative_offset_ms: 0
  ]

  @type t :: %__MODULE__{
          flow_seq: non_neg_integer(),
          from: Endpoint.t(),
          to: Endpoint.t(),
          payload: binary(),
          decoded_payload: {:custom, term()} | {:decode_error, term()} | nil,
          timestamp: Timestamp.t(),
          relative_offset_ms: non_neg_integer(),
          size: non_neg_integer()
        }

  @doc """
  Creates a new UDP datagram.

  ## Parameters

  - `flow_seq` - Index within the flow's datagram list
  - `from` - Source endpoint
  - `to` - Destination endpoint
  - `payload` - UDP payload binary
  - `timestamp` - Datagram timestamp

  ## Examples

      alias PcapFileEx.{Endpoint, Timestamp}
      alias PcapFileEx.Flows.UDP.Datagram

      from = Endpoint.new("10.0.0.1", 54321)
      to = Endpoint.new("10.0.0.2", 5005)
      ts = Timestamp.new(1000, 0)
      payload = <<1, 2, 3, 4>>

      dg = Datagram.new(0, from, to, payload, ts)
      dg.size  # => 4
  """
  @spec new(non_neg_integer(), Endpoint.t(), Endpoint.t(), binary(), Timestamp.t()) :: t()
  def new(flow_seq, from, to, payload, timestamp) do
    %__MODULE__{
      flow_seq: flow_seq,
      from: from,
      to: to,
      payload: payload,
      decoded_payload: nil,
      timestamp: timestamp,
      size: byte_size(payload),
      relative_offset_ms: 0
    }
  end

  @doc """
  Sets the relative offset for playback timing.

  ## Parameters

  - `datagram` - The datagram to update
  - `flow_start` - The flow's first timestamp

  ## Examples

      dg = Datagram.with_relative_offset(dg, flow.stats.first_timestamp)
      dg.relative_offset_ms  # => 150
  """
  @spec with_relative_offset(t(), Timestamp.t()) :: t()
  def with_relative_offset(%__MODULE__{} = datagram, %Timestamp{} = flow_start) do
    offset_ms = compute_offset_ms(datagram.timestamp, flow_start)
    %{datagram | relative_offset_ms: offset_ms}
  end

  defp compute_offset_ms(%Timestamp{} = dg_ts, %Timestamp{} = flow_start) do
    diff_nanos = Timestamp.diff(dg_ts, flow_start)
    max(0, div(diff_nanos, 1_000_000))
  end
end
