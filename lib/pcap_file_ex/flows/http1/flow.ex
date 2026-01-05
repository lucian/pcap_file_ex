defmodule PcapFileEx.Flows.HTTP1.Flow do
  @moduledoc """
  An HTTP/1.x flow containing request/response exchanges.

  Groups HTTP/1.x exchanges that share the same client-server connection.

  ## Fields

  - `flow` - The base `Flow` identity (protocol, endpoints, display fields)
  - `exchanges` - List of `HTTP1.Exchange` structs
  - `stats` - Aggregate statistics for this flow

  ## Examples

      # Query flows from a specific client
      result.http1
      |> Enum.filter(fn f -> f.flow.from == "web-client" end)
      |> Enum.flat_map(& &1.exchanges)

      # Get all GET requests
      result.http1
      |> Enum.flat_map(& &1.exchanges)
      |> Enum.filter(fn ex -> ex.request.method == "GET" end)
  """

  alias PcapFileEx.Flow
  alias PcapFileEx.Flows.{HTTP1, Stats}

  @enforce_keys [:flow]
  defstruct [:flow, exchanges: [], stats: %Stats{}]

  @type t :: %__MODULE__{
          flow: Flow.t(),
          exchanges: [HTTP1.Exchange.t()],
          stats: Stats.t()
        }

  @doc """
  Creates a new HTTP/1 flow.

  ## Parameters

  - `flow` - The base Flow identity

  ## Examples

      alias PcapFileEx.{Flow, Endpoint}
      alias PcapFileEx.Flows.HTTP1

      client = Endpoint.new("10.0.0.1", 54321)
      server = Endpoint.new("10.0.0.2", 80)
      flow = Flow.new(:http1, client, server)
      http1_flow = HTTP1.Flow.new(flow)
  """
  @spec new(Flow.t()) :: t()
  def new(%Flow{protocol: :http1} = flow) do
    %__MODULE__{
      flow: flow,
      exchanges: [],
      stats: Stats.new()
    }
  end

  @doc """
  Adds an exchange to the flow and updates stats.

  ## Parameters

  - `http1_flow` - The HTTP/1 flow
  - `exchange` - The exchange to add

  ## Examples

      http1_flow = HTTP1.Flow.add_exchange(http1_flow, exchange)
  """
  @spec add_exchange(t(), HTTP1.Exchange.t()) :: t()
  def add_exchange(%__MODULE__{} = http1_flow, %HTTP1.Exchange{} = exchange) do
    # Calculate byte size (request + response bodies)
    byte_size =
      byte_size(exchange.request.body) +
        if exchange.response, do: byte_size(exchange.response.body), else: 0

    updated_stats = Stats.add_event(http1_flow.stats, exchange.start_timestamp, byte_size)

    %{http1_flow | exchanges: http1_flow.exchanges ++ [exchange], stats: updated_stats}
  end

  @doc """
  Finalizes the flow by setting the stats from all exchanges.

  Called after all exchanges have been added to compute final stats.
  """
  @spec finalize(t()) :: t()
  def finalize(%__MODULE__{} = http1_flow) do
    # Recompute stats from all exchanges
    stats =
      Enum.reduce(http1_flow.exchanges, Stats.new(), fn exchange, acc ->
        byte_size =
          byte_size(exchange.request.body) +
            if exchange.response, do: byte_size(exchange.response.body), else: 0

        # Use end_timestamp if available, otherwise start_timestamp
        timestamp = exchange.end_timestamp || exchange.start_timestamp
        Stats.add_event(acc, timestamp, byte_size)
      end)

    # Recalculate with proper first/last timestamps
    first_ts =
      case http1_flow.exchanges do
        [] -> nil
        [first | _] -> first.start_timestamp
      end

    last_ts =
      case http1_flow.exchanges do
        [] -> nil
        exchanges -> List.last(exchanges).end_timestamp || List.last(exchanges).start_timestamp
      end

    final_stats = Stats.from_timestamps(stats.packet_count, stats.byte_count, first_ts, last_ts)

    %{http1_flow | stats: final_stats}
  end
end
