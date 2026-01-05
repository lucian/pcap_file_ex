defmodule PcapFileEx.Flows.AnalysisResult do
  @moduledoc """
  Result of analyzing a PCAP file for traffic flows.

  Contains protocol-specific flow lists, a unified timeline for playback,
  and a lookup map for O(1) flow access by key.

  ## Fields

  - `flows` - Map of `FlowKey.t() => flow_ref()` for O(1) lookups
  - `http1` - List of HTTP/1 flows (sorted by first exchange timestamp)
  - `http2` - List of HTTP/2 flows (sorted by first stream timestamp)
  - `udp` - List of UDP flows (sorted by first datagram timestamp)
  - `timeline` - Unified timeline of all events (sorted by timestamp, then deterministically by flow and event)
  - `stats` - Aggregate statistics across all flows

  ## Flow Lookup

  Use `get_flow/2` for O(1) access to flows by key:

      key = FlowKey.new(:http2, client_endpoint, server_endpoint)
      flow = AnalysisResult.get_flow(result, key)

  Or extract a key from an existing flow:

      key = Flow.key(some_flow)
      flow = AnalysisResult.get_flow(result, key)

  ## Timeline Access

  Use `get_event/2` to retrieve actual event data from a timeline event:

      Enum.each(result.timeline, fn event ->
        case AnalysisResult.get_event(result, event) do
          %HTTP1.Exchange{} = ex -> handle_http1(ex)
          %HTTP2.Stream{} = stream -> handle_http2(stream)
          %UDP.Datagram{} = dg -> handle_udp(dg)
        end
      end)

  ## Examples

      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng")

      # Access by protocol
      IO.puts("HTTP/1 flows: \#{length(result.http1)}")
      IO.puts("HTTP/2 flows: \#{length(result.http2)}")
      IO.puts("UDP flows: \#{length(result.udp)}")

      # Query specific flows
      result.http2
      |> Enum.filter(fn f -> f.flow.from == "web-client" end)

      # Playback in timeline order
      Enum.each(result.timeline, fn event ->
        data = AnalysisResult.get_event(result, event)
        playback(data)
      end)
  """

  alias PcapFileEx.FlowKey
  alias PcapFileEx.Flows.{HTTP1, HTTP2, Stats, TimelineEvent, UDP}

  defstruct flows: %{},
            http1: [],
            http2: [],
            udp: [],
            timeline: [],
            stats: %Stats{}

  @type flow_ref :: %{
          protocol: :http1 | :http2 | :udp,
          index: non_neg_integer()
        }

  @type t :: %__MODULE__{
          flows: %{FlowKey.t() => flow_ref()},
          http1: [HTTP1.Flow.t()],
          http2: [HTTP2.Flow.t()],
          udp: [UDP.Flow.t()],
          timeline: [TimelineEvent.t()],
          stats: Stats.t()
        }

  @doc """
  Creates a new empty AnalysisResult.
  """
  @spec new() :: t()
  def new do
    %__MODULE__{}
  end

  @doc """
  Looks up a flow by its FlowKey.

  Returns the flow struct or `nil` if not found.

  ## Parameters

  - `result` - The AnalysisResult
  - `key` - The FlowKey to look up

  ## Examples

      key = FlowKey.new(:http2, client_endpoint, server_endpoint)
      case AnalysisResult.get_flow(result, key) do
        %HTTP2.Flow{} = flow -> handle_flow(flow)
        nil -> :not_found
      end
  """
  @spec get_flow(t(), FlowKey.t()) :: HTTP1.Flow.t() | HTTP2.Flow.t() | UDP.Flow.t() | nil
  def get_flow(%__MODULE__{} = result, %FlowKey{} = key) do
    # Normalize key to match how keys are stored in the map
    normalized_key = FlowKey.normalize(key)

    case Map.get(result.flows, normalized_key) do
      nil ->
        nil

      %{protocol: :http1, index: index} ->
        Enum.at(result.http1, index)

      %{protocol: :http2, index: index} ->
        Enum.at(result.http2, index)

      %{protocol: :udp, index: index} ->
        Enum.at(result.udp, index)
    end
  end

  @doc """
  Retrieves the actual event data from a TimelineEvent.

  Returns the event struct (Exchange, Stream, or Datagram) or `nil` if not found.

  ## Parameters

  - `result` - The AnalysisResult
  - `event` - The TimelineEvent

  ## Examples

      event = Enum.at(result.timeline, 5)
      case AnalysisResult.get_event(result, event) do
        %HTTP1.Exchange{} = ex ->
          IO.puts("\#{ex.request.method} \#{ex.request.path}")

        %HTTP2.Stream{exchange: ex} ->
          IO.puts("\#{ex.request.method} \#{ex.request.path}")

        %UDP.Datagram{} = dg ->
          IO.puts("UDP: \#{dg.size} bytes")
      end
  """
  @spec get_event(t(), TimelineEvent.t()) ::
          HTTP1.Exchange.t() | HTTP2.Stream.t() | UDP.Datagram.t() | nil
  def get_event(%__MODULE__{} = result, %TimelineEvent{} = event) do
    case event.event_type do
      :http1_exchange ->
        flow = Enum.at(result.http1, event.flow_index)
        flow && Enum.at(flow.exchanges, event.event_index)

      :http2_stream ->
        flow = Enum.at(result.http2, event.flow_index)
        flow && Enum.at(flow.streams, event.event_index)

      :udp_datagram ->
        flow = Enum.at(result.udp, event.flow_index)
        flow && Enum.at(flow.datagrams, event.event_index)
    end
  end

  @doc """
  Builds an AnalysisResult from protocol-specific flow lists.

  Constructs the flows map, timeline, and aggregate stats.

  ## Parameters

  - `http1_flows` - List of HTTP/1 flows
  - `http2_flows` - List of HTTP/2 flows
  - `udp_flows` - List of UDP flows
  """
  @spec build([HTTP1.Flow.t()], [HTTP2.Flow.t()], [UDP.Flow.t()]) :: t()
  def build(http1_flows, http2_flows, udp_flows) do
    # Build flows lookup map
    flows_map =
      build_flows_map(http1_flows, :http1) ++
        build_flows_map(http2_flows, :http2) ++
        build_flows_map(udp_flows, :udp)

    flows = Map.new(flows_map)

    # Build timeline
    timeline = build_timeline(http1_flows, http2_flows, udp_flows)

    # Compute aggregate stats
    stats = compute_aggregate_stats(http1_flows, http2_flows, udp_flows)

    %__MODULE__{
      flows: flows,
      http1: http1_flows,
      http2: http2_flows,
      udp: udp_flows,
      timeline: timeline,
      stats: stats
    }
  end

  # Build flows map entries for a protocol
  # Keys are normalized (host stripped) for consistent matching
  defp build_flows_map(flows, protocol) do
    flows
    |> Enum.with_index()
    |> Enum.map(fn {flow, index} ->
      key = flow.flow |> PcapFileEx.Flow.key() |> FlowKey.normalize()
      {key, %{protocol: protocol, index: index}}
    end)
  end

  # Build unified timeline from all flows
  defp build_timeline(http1_flows, http2_flows, udp_flows) do
    # Collect all events with their timestamps and metadata
    http1_events = collect_http1_events(http1_flows)
    http2_events = collect_http2_events(http2_flows)
    udp_events = collect_udp_events(udp_flows)

    all_events = http1_events ++ http2_events ++ udp_events

    # Sort by (timestamp, normalized_key, event_type, event_index) for stable deterministic ordering
    sorted_events =
      all_events
      |> Enum.sort_by(fn {ts, event_type, flow_key, _flow_idx, event_idx} ->
        {
          PcapFileEx.Timestamp.to_unix_nanos(ts),
          FlowKey.normalize(flow_key),
          event_type,
          event_idx
        }
      end)

    # Assign seq_num and create TimelineEvent structs
    sorted_events
    |> Enum.with_index()
    |> Enum.map(fn {{ts, event_type, flow_key, flow_idx, event_idx}, seq_num} ->
      TimelineEvent.new(seq_num, ts, event_type, flow_key, flow_idx, event_idx)
    end)
  end

  defp collect_http1_events(flows) do
    flows
    |> Enum.with_index()
    |> Enum.flat_map(fn {flow, flow_idx} ->
      flow_key = PcapFileEx.Flow.key(flow.flow)

      flow.exchanges
      |> Enum.with_index()
      |> Enum.map(fn {ex, event_idx} ->
        {ex.start_timestamp, :http1_exchange, flow_key, flow_idx, event_idx}
      end)
    end)
  end

  defp collect_http2_events(flows) do
    flows
    |> Enum.with_index()
    |> Enum.flat_map(fn {flow, flow_idx} ->
      flow_key = PcapFileEx.Flow.key(flow.flow)

      flow.streams
      |> Enum.with_index()
      |> Enum.map(fn {stream, event_idx} ->
        {stream.start_timestamp, :http2_stream, flow_key, flow_idx, event_idx}
      end)
    end)
  end

  defp collect_udp_events(flows) do
    flows
    |> Enum.with_index()
    |> Enum.flat_map(fn {flow, flow_idx} ->
      flow_key = PcapFileEx.Flow.key(flow.flow)

      flow.datagrams
      |> Enum.with_index()
      |> Enum.map(fn {dg, event_idx} ->
        {dg.timestamp, :udp_datagram, flow_key, flow_idx, event_idx}
      end)
    end)
  end

  # Compute aggregate stats from all flows
  defp compute_aggregate_stats(http1_flows, http2_flows, udp_flows) do
    all_stats =
      Enum.map(http1_flows, & &1.stats) ++
        Enum.map(http2_flows, & &1.stats) ++
        Enum.map(udp_flows, & &1.stats)

    Enum.reduce(all_stats, Stats.new(), &Stats.merge(&2, &1))
  end
end
