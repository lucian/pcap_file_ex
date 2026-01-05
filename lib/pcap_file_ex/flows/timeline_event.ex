defmodule PcapFileEx.Flows.TimelineEvent do
  @moduledoc """
  A single event in the unified timeline for playback.

  `TimelineEvent` provides a unified view of all events across protocols,
  enabling playback in chronological order. Each event references the
  actual data via indices into the protocol-specific lists.

  ## Fields

  - `seq_num` - Timeline index (0-based, matches position in timeline list)
  - `timestamp` - Event timestamp (nanosecond precision)
  - `event_type` - Type of event (`:http1_exchange`, `:http2_stream`, `:udp_datagram`)
  - `flow_key` - Which flow this event belongs to
  - `flow_index` - Index within the protocol list (e.g., `http2[flow_index]`)
  - `event_index` - Index within the events list (e.g., `streams[event_index]`)

  ## seq_num Semantics

  The `seq_num` equals the event's index in the `timeline` list:

      timeline[event.seq_num] == event

  This ensures stable cross-referencing where `seq_num` always matches
  the timeline position.

  ## Retrieving Event Data

  Use `AnalysisResult.get_event/2` to retrieve the actual event data:

      event = Enum.at(result.timeline, 5)
      data = AnalysisResult.get_event(result, event)

  ## Examples

      # Timeline is sorted by (timestamp, seq_num)
      result.timeline
      |> Enum.each(fn event ->
        case AnalysisResult.get_event(result, event) do
          %HTTP1.Exchange{} = ex -> handle_http1(ex)
          %HTTP2.Stream{} = stream -> handle_http2(stream)
          %UDP.Datagram{} = dg -> handle_udp(dg)
        end
      end)
  """

  alias PcapFileEx.{FlowKey, Timestamp}

  @enforce_keys [:seq_num, :timestamp, :event_type, :flow_key, :flow_index, :event_index]
  defstruct [:seq_num, :timestamp, :event_type, :flow_key, :flow_index, :event_index]

  @type event_type :: :http1_exchange | :http2_stream | :udp_datagram

  @type t :: %__MODULE__{
          seq_num: non_neg_integer(),
          timestamp: Timestamp.t(),
          event_type: event_type(),
          flow_key: FlowKey.t(),
          flow_index: non_neg_integer(),
          event_index: non_neg_integer()
        }

  @doc """
  Creates a new TimelineEvent.

  ## Parameters

  - `seq_num` - Timeline index (position in timeline list)
  - `timestamp` - Event timestamp
  - `event_type` - Type of event
  - `flow_key` - FlowKey identifying the flow
  - `flow_index` - Index in the protocol list
  - `event_index` - Index in the events list

  ## Examples

      iex> alias PcapFileEx.{FlowKey, Endpoint, Timestamp, Flows.TimelineEvent}
      iex> server = Endpoint.new("10.0.0.1", 8080)
      iex> key = FlowKey.new(:udp, nil, server)
      iex> ts = Timestamp.new(1000, 0)
      iex> event = TimelineEvent.new(0, ts, :udp_datagram, key, 0, 0)
      iex> event.seq_num
      0
      iex> event.event_type
      :udp_datagram
  """
  @spec new(
          non_neg_integer(),
          Timestamp.t(),
          event_type(),
          FlowKey.t(),
          non_neg_integer(),
          non_neg_integer()
        ) :: t()
  def new(seq_num, timestamp, event_type, flow_key, flow_index, event_index)
      when event_type in [:http1_exchange, :http2_stream, :udp_datagram] do
    %__MODULE__{
      seq_num: seq_num,
      timestamp: timestamp,
      event_type: event_type,
      flow_key: flow_key,
      flow_index: flow_index,
      event_index: event_index
    }
  end
end
