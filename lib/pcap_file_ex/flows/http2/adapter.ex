defmodule PcapFileEx.Flows.HTTP2.Adapter do
  @moduledoc """
  Adapter that converts PcapFileEx.HTTP2 analyzer output to Flows API format.

  Bridges the existing `PcapFileEx.HTTP2.analyze/2` output to the new
  `PcapFileEx.Flows.HTTP2.Flow` structure.

  ## Example

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")
      {:ok, flows} = HTTP2.Adapter.from_exchanges(complete, incomplete, hosts_map: hosts)
  """

  alias PcapFileEx.{Endpoint, Flow, Timestamp}
  alias PcapFileEx.Flows.HTTP2
  alias PcapFileEx.HTTP2.{Exchange, IncompleteExchange}

  @doc """
  Converts HTTP2.Exchange list to Flows.HTTP2.Flow list.

  Groups exchanges by client-server pair into flows.

  ## Parameters

  - `complete` - List of complete HTTP2.Exchange structs
  - `incomplete` - List of IncompleteExchange structs
  - `opts` - Options:
    - `:hosts_map` - Map of IP strings to hostnames

  ## Returns

  `{:ok, flows}` where flows is a list of `HTTP2.Flow.t()`
  """
  @spec from_exchanges([Exchange.t()], [IncompleteExchange.t()], keyword()) ::
          {:ok, [HTTP2.Flow.t()]}
  def from_exchanges(complete, incomplete, opts \\ []) do
    hosts_map = Keyword.get(opts, :hosts_map, %{})

    # Group complete exchanges by client-server pair
    grouped_complete =
      complete
      |> Enum.group_by(&exchange_flow_key/1)

    # Group incomplete exchanges by client-server pair
    grouped_incomplete =
      incomplete
      |> Enum.group_by(&incomplete_flow_key/1)

    # Get all unique flow keys
    all_keys =
      MapSet.union(
        MapSet.new(Map.keys(grouped_complete)),
        MapSet.new(Map.keys(grouped_incomplete))
      )

    # Build flows for each key
    flows =
      all_keys
      |> Enum.map(fn key ->
        complete_exchanges = Map.get(grouped_complete, key, [])
        incomplete_exchanges = Map.get(grouped_incomplete, key, [])
        build_flow(key, complete_exchanges, incomplete_exchanges, hosts_map)
      end)
      |> Enum.sort_by(fn flow ->
        case flow.streams do
          [] -> nil
          [first | _] -> Timestamp.to_unix_nanos(first.start_timestamp)
        end
      end)

    {:ok, flows}
  end

  # Extract flow key from complete exchange
  defp exchange_flow_key(%Exchange{} = ex) do
    {client, server} = Exchange.endpoints(ex)
    {endpoint_to_key(client), endpoint_to_key(server)}
  end

  # Extract flow key from incomplete exchange
  defp incomplete_flow_key(%IncompleteExchange{} = ex) do
    # IncompleteExchange has client/server or endpoint_a/endpoint_b
    if ex.client do
      {endpoint_to_key(ex.client), endpoint_to_key(ex.server)}
    else
      {endpoint_to_key(ex.endpoint_a), endpoint_to_key(ex.endpoint_b)}
    end
  end

  defp endpoint_to_key(%Endpoint{} = ep), do: {ep.ip, ep.port}
  defp endpoint_to_key(nil), do: {nil, nil}

  # Build a flow from grouped exchanges
  defp build_flow({client_key, server_key}, complete_exchanges, incomplete_exchanges, hosts_map) do
    # Create endpoints
    # Note: client_key/server_key contain {ip_string, port} since endpoint_to_key
    # extracts from Endpoint structs where ip is already a string
    client_endpoint =
      case client_key do
        {nil, nil} -> nil
        {ip, port} -> Endpoint.new(ip, port, Map.get(hosts_map, ip))
      end

    server_endpoint =
      case server_key do
        {nil, nil} -> nil
        {ip, port} -> Endpoint.new(ip, port, Map.get(hosts_map, ip))
      end

    # Create base flow
    flow = Flow.new(:http2, client_endpoint, server_endpoint)
    http2_flow = HTTP2.Flow.new(flow)

    # Sort complete exchanges by timestamp
    sorted_complete =
      complete_exchanges
      |> Enum.sort_by(fn ex ->
        case ex.start_timestamp do
          %DateTime{} = dt -> DateTime.to_unix(dt, :nanosecond)
          _ -> 0
        end
      end)

    # Add complete exchanges as streams with flow_seq
    http2_flow =
      sorted_complete
      |> Enum.with_index()
      |> Enum.reduce(http2_flow, fn {ex, flow_seq}, acc ->
        stream = HTTP2.Stream.from_exchange(flow_seq, ex)
        HTTP2.Flow.add_stream(acc, stream)
      end)

    # Add incomplete exchanges
    http2_flow =
      Enum.reduce(incomplete_exchanges, http2_flow, fn inc, acc ->
        HTTP2.Flow.add_incomplete(acc, inc)
      end)

    HTTP2.Flow.finalize(http2_flow)
  end
end
