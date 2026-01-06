defmodule PcapFileEx.Flows.UDP.Datagram do
  @moduledoc """
  A UDP datagram within a flow.

  Represents a single UDP packet with source/destination endpoints,
  payload, timing information, and playback metadata.

  ## Fields

  - `flow_seq` - Index within the flow's datagram list (0-based)
  - `from` - Source endpoint
  - `to` - Destination endpoint
  - `payload` - UDP payload (raw binary or decoded tagged tuple)
  - `payload_binary` - Original binary when `keep_binary: true` and decoder was invoked
  - `timestamp` - Datagram timestamp (nanosecond precision)
  - `relative_offset_ms` - Offset from flow start (for playback)
  - `size` - Payload size in bytes

  ## Payload States

  The `payload` field can be:

  - **Raw binary** - No decoders configured, or decoder returned `:skip`
  - `{:custom, term}` - Custom decoder succeeded
  - `{:decode_error, reason}` - Custom decoder failed

  ## Binary Preservation

  When `keep_binary: true` is passed to `PcapFileEx.Flows.analyze/2` and a
  custom decoder was invoked (success or error), `payload_binary` contains
  the original binary for playback scenarios.

  **Important:** `payload_binary` is only set when a decoder was *invoked*.
  If no decoder matched or decoder returned `:skip`, `payload` remains raw
  binary and `payload_binary` is `nil`.

  ## Playback Timing

  `relative_offset_ms` indicates when to send this datagram relative to
  the flow start time:

  - First datagram in flow has `relative_offset_ms = 0`
  - Computed as: `div(Timestamp.diff(datagram.timestamp, flow.stats.first_timestamp), 1_000_000)`

  ## Examples

      # Pattern match on payload
      case datagram.payload do
        {:custom, decoded} ->
          handle_decoded(decoded)
          # For playback: datagram.payload_binary (if keep_binary: true)

        {:decode_error, reason} ->
          Logger.warning("Decode failed: \#{inspect(reason)}")
          # Recovery: datagram.payload_binary (if keep_binary: true)

        raw when is_binary(raw) ->
          handle_raw(raw)
          # Note: payload_binary is nil in this case
      end

      # Stream datagrams with proper timing
      start_time = System.monotonic_time(:millisecond)

      Enum.each(flow.datagrams, fn dg ->
        # Wait until the relative offset
        elapsed = System.monotonic_time(:millisecond) - start_time
        remaining = dg.relative_offset_ms - elapsed
        if remaining > 0, do: Process.sleep(remaining)

        # Get raw binary for sending
        raw = case dg.payload do
          binary when is_binary(binary) -> binary
          _decoded -> dg.payload_binary
        end
        send_udp(dg.to, raw)
      end)
  """

  alias PcapFileEx.{Endpoint, Timestamp}

  @enforce_keys [:flow_seq, :from, :to, :payload, :timestamp, :size]
  defstruct [
    :flow_seq,
    :from,
    :to,
    :payload,
    :payload_binary,
    :timestamp,
    :size,
    relative_offset_ms: 0
  ]

  @typedoc "Decoded payload from custom decoder"
  @type decoded :: {:custom, term()} | {:decode_error, term()}

  @type t :: %__MODULE__{
          flow_seq: non_neg_integer(),
          from: Endpoint.t(),
          to: Endpoint.t(),
          payload: decoded() | binary(),
          payload_binary: binary() | nil,
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
      payload_binary: nil,
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
