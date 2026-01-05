defmodule PcapFileEx.Flows.HTTP2.Flow do
  @moduledoc """
  An HTTP/2 flow containing streams (request/response exchanges).

  Groups HTTP/2 streams that share the same client-server connection.
  Uses "streams" terminology to match the HTTP/2 specification.

  ## Fields

  - `flow` - The base `Flow` identity (protocol, endpoints, display fields)
  - `streams` - List of `HTTP2.Stream` structs (complete streams with flow_seq)
  - `incomplete` - List of `IncompleteExchange` structs (not in timeline)
  - `stats` - Aggregate statistics for this flow

  ## Complete vs Incomplete

  - `streams` contains exchanges that have both request and response
  - `incomplete` contains exchanges that were cut off (RST_STREAM, GOAWAY, truncated)
  - Only complete streams are included in the unified timeline

  ## Examples

      # Query flows from a specific client
      result.http2
      |> Enum.filter(fn f -> f.flow.from == "web-client" end)
      |> Enum.flat_map(& &1.streams)

      # Get all POST requests
      result.http2
      |> Enum.flat_map(& &1.streams)
      |> Enum.filter(fn s -> s.exchange.request.method == "POST" end)

      # Check for incomplete streams
      result.http2
      |> Enum.flat_map(& &1.incomplete)
      |> Enum.each(fn incomplete ->
        IO.puts("Incomplete stream \#{incomplete.stream_id}: \#{incomplete.reason}")
      end)
  """

  alias PcapFileEx.Flow
  alias PcapFileEx.Flows.{HTTP2, Stats}
  alias PcapFileEx.HTTP2.IncompleteExchange
  alias PcapFileEx.Timestamp

  @enforce_keys [:flow]
  defstruct [:flow, streams: [], incomplete: [], stats: %Stats{}]

  @type t :: %__MODULE__{
          flow: Flow.t(),
          streams: [HTTP2.Stream.t()],
          incomplete: [IncompleteExchange.t()],
          stats: Stats.t()
        }

  @doc """
  Creates a new HTTP/2 flow.

  ## Parameters

  - `flow` - The base Flow identity

  ## Examples

      alias PcapFileEx.{Flow, Endpoint}
      alias PcapFileEx.Flows.HTTP2

      client = Endpoint.new("10.0.0.1", 54321)
      server = Endpoint.new("10.0.0.2", 8080)
      flow = Flow.new(:http2, client, server)
      http2_flow = HTTP2.Flow.new(flow)
  """
  @spec new(Flow.t()) :: t()
  def new(%Flow{protocol: :http2} = flow) do
    %__MODULE__{
      flow: flow,
      streams: [],
      incomplete: [],
      stats: Stats.new()
    }
  end

  @doc """
  Adds a stream to the flow.

  ## Parameters

  - `http2_flow` - The HTTP/2 flow
  - `stream` - The stream to add
  """
  @spec add_stream(t(), HTTP2.Stream.t()) :: t()
  def add_stream(%__MODULE__{} = http2_flow, %HTTP2.Stream{} = stream) do
    %{http2_flow | streams: http2_flow.streams ++ [stream]}
  end

  @doc """
  Adds an incomplete exchange to the flow.

  ## Parameters

  - `http2_flow` - The HTTP/2 flow
  - `incomplete` - The incomplete exchange to add
  """
  @spec add_incomplete(t(), IncompleteExchange.t()) :: t()
  def add_incomplete(%__MODULE__{} = http2_flow, %IncompleteExchange{} = incomplete) do
    %{http2_flow | incomplete: http2_flow.incomplete ++ [incomplete]}
  end

  @doc """
  Finalizes the flow by computing stats from all streams.

  Called after all streams have been added.
  """
  @spec finalize(t()) :: t()
  def finalize(%__MODULE__{} = http2_flow) do
    # Compute stats from streams
    stats =
      Enum.reduce(http2_flow.streams, Stats.new(), fn stream, acc ->
        # Calculate byte size from exchange
        byte_size =
          byte_size(stream.exchange.request.body || <<>>) +
            byte_size(stream.exchange.response.body || <<>>)

        Stats.add_event(acc, stream.start_timestamp, byte_size)
      end)

    # Get first and last timestamps
    first_ts =
      case http2_flow.streams do
        [] -> nil
        [first | _] -> first.start_timestamp
      end

    last_ts =
      case http2_flow.streams do
        [] ->
          nil

        streams ->
          last_stream = List.last(streams)

          # Use end_timestamp if available
          case last_stream.exchange.end_timestamp do
            nil -> last_stream.start_timestamp
            %DateTime{} = dt -> Timestamp.from_datetime(dt)
          end
      end

    final_stats = Stats.from_timestamps(stats.packet_count, stats.byte_count, first_ts, last_ts)

    %{http2_flow | stats: final_stats}
  end
end
