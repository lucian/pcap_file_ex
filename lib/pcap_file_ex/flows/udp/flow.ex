defmodule PcapFileEx.Flows.UDP.Flow do
  @moduledoc """
  A UDP flow containing datagrams.

  Groups UDP datagrams by destination (server) endpoint. Unlike HTTP flows,
  UDP flows use `from: :any` because datagrams are grouped by server only,
  regardless of source.

  ## Fields

  - `flow` - The base `Flow` identity (protocol, endpoints, display fields)
  - `datagrams` - List of `UDP.Datagram` structs
  - `stats` - Aggregate statistics for this flow

  ## UDP Grouping

  UDP datagrams are grouped by destination (server) IP:port only.
  All datagrams to the same server form a single flow:

      %Flow{
        protocol: :udp,
        from: :any,                          # Datagrams may come from any source
        server: "metrics-collector:5005",
        client: nil,
        client_endpoint: nil
      }

  ## Examples

      # Get all datagrams to a specific server
      result.udp
      |> Enum.filter(fn f -> f.flow.server == "metrics-collector:5005" end)
      |> Enum.flat_map(& &1.datagrams)

      # Calculate total bytes to each UDP server
      result.udp
      |> Enum.map(fn f -> {f.flow.server, f.stats.byte_count} end)
  """

  alias PcapFileEx.Flow
  alias PcapFileEx.Flows.{Stats, UDP}

  @enforce_keys [:flow]
  defstruct [:flow, datagrams: [], stats: %Stats{}]

  @type t :: %__MODULE__{
          flow: Flow.t(),
          datagrams: [UDP.Datagram.t()],
          stats: Stats.t()
        }

  @doc """
  Creates a new UDP flow.

  ## Parameters

  - `flow` - The base Flow identity (should have `protocol: :udp`)

  ## Examples

      alias PcapFileEx.{Flow, Endpoint}
      alias PcapFileEx.Flows.UDP

      server = Endpoint.new("10.0.0.2", 5005, "metrics-collector")
      flow = Flow.new(:udp, nil, server)
      udp_flow = UDP.Flow.new(flow)
  """
  @spec new(Flow.t()) :: t()
  def new(%Flow{protocol: :udp} = flow) do
    %__MODULE__{
      flow: flow,
      datagrams: [],
      stats: Stats.new()
    }
  end

  @doc """
  Adds a datagram to the flow.

  ## Parameters

  - `udp_flow` - The UDP flow
  - `datagram` - The datagram to add
  """
  @spec add_datagram(t(), UDP.Datagram.t()) :: t()
  def add_datagram(%__MODULE__{} = udp_flow, %UDP.Datagram{} = datagram) do
    updated_stats = Stats.add_event(udp_flow.stats, datagram.timestamp, datagram.size)
    %{udp_flow | datagrams: udp_flow.datagrams ++ [datagram], stats: updated_stats}
  end

  @doc """
  Finalizes the flow by computing relative offsets for all datagrams.

  Called after all datagrams have been added.
  """
  @spec finalize(t()) :: t()
  def finalize(%__MODULE__{} = udp_flow) do
    case udp_flow.stats.first_timestamp do
      nil ->
        udp_flow

      flow_start ->
        # Update all datagrams with relative offsets
        updated_datagrams =
          Enum.map(udp_flow.datagrams, fn dg ->
            UDP.Datagram.with_relative_offset(dg, flow_start)
          end)

        %{udp_flow | datagrams: updated_datagrams}
    end
  end
end
