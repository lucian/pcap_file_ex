defmodule PcapFileEx.Flows.Summary do
  @moduledoc """
  Aggregated traffic summary for network topology analysis.

  Provides a network-administrator view of captured traffic, grouping flows by:
  - UDP: destination service (IP:port) with per-client statistics
  - HTTP/1: server service (IP:port) with per-client request/response metrics
  - HTTP/2: server service (IP:port) with per-client stream statistics

  This summary is used by the Diagram API for clean topology rendering.
  """

  alias PcapFileEx.Endpoint
  alias PcapFileEx.Flows.Summary.{HTTPClientStats, HTTPService, UDPClientStats, UDPService}

  defstruct [
    :udp,
    :http1,
    :http2
  ]

  @type t :: %__MODULE__{
          udp: [UDPService.t()],
          http1: [HTTPService.t()],
          http2: [HTTPService.t()]
        }

  @doc """
  Builds a traffic summary from analyzed flows.

  ## Parameters

  - `http1_flows` - List of HTTP1.Flow structs
  - `http2_flows` - List of HTTP2.Flow structs
  - `udp_flows` - List of UDP.Flow structs
  - `hosts_map` - Optional map of IP -> hostname for display

  ## Returns

  A `Summary` struct with aggregated traffic data per protocol.
  """
  @spec build(list(), list(), list(), map()) :: t()
  def build(http1_flows, http2_flows, udp_flows, hosts_map \\ %{}) do
    %__MODULE__{
      udp: summarize_udp(udp_flows, hosts_map),
      http1: summarize_http(http1_flows, :http1, hosts_map),
      http2: summarize_http2(http2_flows, hosts_map)
    }
  end

  # UDP Summary: group by destination service, aggregate per-client stats
  defp summarize_udp(flows, hosts_map) do
    flows
    |> Enum.flat_map(fn flow ->
      server_ep = flow.flow.server_endpoint
      server_str = Endpoint.to_string(server_ep)
      server_host = get_host(server_ep, hosts_map)

      # Group datagrams by source client IP (no port)
      flow.datagrams
      |> Enum.group_by(fn dg -> Endpoint.to_client_string(dg.from) end)
      |> Enum.map(fn {client_str, datagrams} ->
        client_host = get_client_host(List.first(datagrams).from, hosts_map)
        {server_str, server_host, client_str, client_host, datagrams}
      end)
    end)
    |> Enum.group_by(fn {server_str, _server_host, _client, _client_host, _dgs} -> server_str end)
    |> Enum.map(fn {server_str, groups} ->
      build_udp_service(server_str, groups)
    end)
    |> Enum.sort_by(& &1.total_bytes, :desc)
  end

  defp build_udp_service(server_str, groups) do
    # Extract server host from first group
    {_, server_host, _, _, _} = List.first(groups)

    # Build client stats
    clients =
      groups
      |> Enum.group_by(fn {_, _, client, _, _} -> client end)
      |> Enum.map(fn {client_str, client_groups} ->
        all_datagrams = Enum.flat_map(client_groups, fn {_, _, _, _, dgs} -> dgs end)
        {_, _, _, client_host, _} = List.first(client_groups)
        build_udp_client_stats(client_str, client_host, all_datagrams)
      end)
      |> Enum.sort_by(& &1.total_bytes, :desc)

    # Aggregate totals
    total_packets = Enum.sum(Enum.map(clients, & &1.packet_count))
    total_bytes = Enum.sum(Enum.map(clients, & &1.total_bytes))

    timestamps = Enum.flat_map(clients, fn c -> [c.first_timestamp, c.last_timestamp] end)
    first_ts = timestamps |> Enum.reject(&is_nil/1) |> Enum.min_by(&ts_to_nanos/1, fn -> nil end)
    last_ts = timestamps |> Enum.reject(&is_nil/1) |> Enum.max_by(&ts_to_nanos/1, fn -> nil end)

    %UDPService{
      server: server_str,
      server_host: server_host,
      clients: clients,
      total_packets: total_packets,
      total_bytes: total_bytes,
      first_timestamp: first_ts,
      last_timestamp: last_ts
    }
  end

  defp build_udp_client_stats(client_str, client_host, datagrams) do
    sizes = Enum.map(datagrams, & &1.size)
    timestamps = Enum.map(datagrams, & &1.timestamp)

    %UDPClientStats{
      client: client_str,
      client_host: client_host,
      packet_count: length(datagrams),
      total_bytes: Enum.sum(sizes),
      avg_size: safe_avg(sizes),
      min_size: Enum.min(sizes, fn -> 0 end),
      max_size: Enum.max(sizes, fn -> 0 end),
      first_timestamp: Enum.min_by(timestamps, &ts_to_nanos/1, fn -> nil end),
      last_timestamp: Enum.max_by(timestamps, &ts_to_nanos/1, fn -> nil end)
    }
  end

  # HTTP/1 Summary: group by server, aggregate per-client exchange stats
  defp summarize_http(flows, protocol, hosts_map) do
    flows
    |> Enum.map(fn flow ->
      server_ep = flow.flow.server_endpoint
      client_ep = flow.flow.client_endpoint
      server_str = Endpoint.to_string(server_ep)
      server_host = get_host(server_ep, hosts_map)
      client_str = Endpoint.to_client_string(client_ep)
      client_host = get_client_host(client_ep, hosts_map)

      {server_str, server_host, client_str, client_host, flow}
    end)
    |> Enum.group_by(fn {server_str, _server_host, _client, _client_host, _flow} ->
      server_str
    end)
    |> Enum.map(fn {server_str, groups} ->
      build_http_service(server_str, groups, protocol)
    end)
    |> Enum.sort_by(&(&1.total_request_bytes + &1.total_response_bytes), :desc)
  end

  defp build_http_service(server_str, groups, protocol) do
    {_, server_host, _, _, _} = List.first(groups)

    # Build client stats - group by client IP
    clients =
      groups
      |> Enum.group_by(fn {_, _, client, _, _} -> client end)
      |> Enum.map(fn {client_str, client_groups} ->
        flows = Enum.map(client_groups, fn {_, _, _, _, flow} -> flow end)
        {_, _, _, client_host, _} = List.first(client_groups)
        build_http1_client_stats(client_str, client_host, flows)
      end)
      |> Enum.sort_by(&(&1.request_bytes + &1.response_bytes), :desc)

    # Aggregate service-level stats
    total_requests = Enum.sum(Enum.map(clients, & &1.request_count))
    total_responses = Enum.sum(Enum.map(clients, & &1.response_count))
    total_req_bytes = Enum.sum(Enum.map(clients, & &1.request_bytes))
    total_res_bytes = Enum.sum(Enum.map(clients, & &1.response_bytes))

    methods = merge_maps(Enum.map(clients, & &1.methods))
    status_codes = merge_maps(Enum.map(clients, & &1.status_codes))

    timestamps = Enum.flat_map(clients, fn c -> [c.first_timestamp, c.last_timestamp] end)
    first_ts = timestamps |> Enum.reject(&is_nil/1) |> Enum.min_by(&ts_to_nanos/1, fn -> nil end)
    last_ts = timestamps |> Enum.reject(&is_nil/1) |> Enum.max_by(&ts_to_nanos/1, fn -> nil end)

    %HTTPService{
      protocol: protocol,
      server: server_str,
      server_host: server_host,
      clients: clients,
      total_requests: total_requests,
      total_responses: total_responses,
      total_request_bytes: total_req_bytes,
      total_response_bytes: total_res_bytes,
      methods: methods,
      status_codes: status_codes,
      first_timestamp: first_ts,
      last_timestamp: last_ts
    }
  end

  defp build_http1_client_stats(client_str, client_host, flows) do
    exchanges = Enum.flat_map(flows, & &1.exchanges)

    request_count = length(exchanges)
    response_count = Enum.count(exchanges, & &1.response)

    request_bytes =
      exchanges
      |> Enum.map(fn ex -> byte_size(ex.request.body || <<>>) end)
      |> Enum.sum()

    response_bytes =
      exchanges
      |> Enum.filter(& &1.response)
      |> Enum.map(fn ex -> byte_size(ex.response.body || <<>>) end)
      |> Enum.sum()

    methods =
      exchanges
      |> Enum.map(& &1.request.method)
      |> Enum.frequencies()

    status_codes =
      exchanges
      |> Enum.filter(& &1.response)
      |> Enum.map(& &1.response.status)
      |> Enum.frequencies()

    response_times =
      exchanges
      |> Enum.filter(& &1.response_delay_ms)
      |> Enum.map(& &1.response_delay_ms)

    timestamps =
      exchanges
      |> Enum.flat_map(fn ex ->
        [ex.start_timestamp, ex.end_timestamp]
      end)
      |> Enum.reject(&is_nil/1)

    %HTTPClientStats{
      client: client_str,
      client_host: client_host,
      connection_count: length(flows),
      stream_count: nil,
      request_count: request_count,
      response_count: response_count,
      request_bytes: request_bytes,
      response_bytes: response_bytes,
      methods: methods,
      status_codes: status_codes,
      avg_response_time_ms: safe_avg(response_times),
      min_response_time_ms: Enum.min(response_times, fn -> nil end),
      max_response_time_ms: Enum.max(response_times, fn -> nil end),
      first_timestamp: Enum.min_by(timestamps, &ts_to_nanos/1, fn -> nil end),
      last_timestamp: Enum.max_by(timestamps, &ts_to_nanos/1, fn -> nil end)
    }
  end

  # HTTP/2 Summary: group by server, aggregate per-client stream stats
  defp summarize_http2(flows, hosts_map) do
    flows
    |> Enum.map(fn flow ->
      server_ep = flow.flow.server_endpoint
      client_ep = flow.flow.client_endpoint
      server_str = Endpoint.to_string(server_ep)
      server_host = get_host(server_ep, hosts_map)
      client_str = Endpoint.to_client_string(client_ep)
      client_host = get_client_host(client_ep, hosts_map)

      {server_str, server_host, client_str, client_host, flow}
    end)
    |> Enum.group_by(fn {server_str, _server_host, _client, _client_host, _flow} ->
      server_str
    end)
    |> Enum.map(fn {server_str, groups} ->
      build_http2_service(server_str, groups)
    end)
    |> Enum.sort_by(&(&1.total_request_bytes + &1.total_response_bytes), :desc)
  end

  defp build_http2_service(server_str, groups) do
    {_, server_host, _, _, _} = List.first(groups)

    # Build client stats - group by client IP
    clients =
      groups
      |> Enum.group_by(fn {_, _, client, _, _} -> client end)
      |> Enum.map(fn {client_str, client_groups} ->
        flows = Enum.map(client_groups, fn {_, _, _, _, flow} -> flow end)
        {_, _, _, client_host, _} = List.first(client_groups)
        build_http2_client_stats(client_str, client_host, flows)
      end)
      |> Enum.sort_by(&(&1.request_bytes + &1.response_bytes), :desc)

    # Aggregate service-level stats
    total_requests = Enum.sum(Enum.map(clients, & &1.request_count))
    total_responses = Enum.sum(Enum.map(clients, & &1.response_count))
    total_req_bytes = Enum.sum(Enum.map(clients, & &1.request_bytes))
    total_res_bytes = Enum.sum(Enum.map(clients, & &1.response_bytes))

    methods = merge_maps(Enum.map(clients, & &1.methods))
    status_codes = merge_maps(Enum.map(clients, & &1.status_codes))

    timestamps = Enum.flat_map(clients, fn c -> [c.first_timestamp, c.last_timestamp] end)
    first_ts = timestamps |> Enum.reject(&is_nil/1) |> Enum.min_by(&ts_to_nanos/1, fn -> nil end)
    last_ts = timestamps |> Enum.reject(&is_nil/1) |> Enum.max_by(&ts_to_nanos/1, fn -> nil end)

    %HTTPService{
      protocol: :http2,
      server: server_str,
      server_host: server_host,
      clients: clients,
      total_requests: total_requests,
      total_responses: total_responses,
      total_request_bytes: total_req_bytes,
      total_response_bytes: total_res_bytes,
      methods: methods,
      status_codes: status_codes,
      first_timestamp: first_ts,
      last_timestamp: last_ts
    }
  end

  defp build_http2_client_stats(client_str, client_host, flows) do
    streams = Enum.flat_map(flows, & &1.streams)

    stream_count = length(streams)
    request_count = stream_count
    response_count = Enum.count(streams, &(&1.exchange.response != nil))

    request_bytes =
      streams
      |> Enum.map(fn s -> byte_size(s.exchange.request.body || <<>>) end)
      |> Enum.sum()

    response_bytes =
      streams
      |> Enum.filter(&(&1.exchange.response != nil))
      |> Enum.map(fn s -> byte_size(s.exchange.response.body || <<>>) end)
      |> Enum.sum()

    methods =
      streams
      |> Enum.map(& &1.exchange.request.method)
      |> Enum.frequencies()

    status_codes =
      streams
      |> Enum.filter(&(&1.exchange.response != nil))
      |> Enum.map(& &1.exchange.response.status)
      |> Enum.frequencies()

    response_times =
      streams
      |> Enum.filter(& &1.response_delay_ms)
      |> Enum.map(& &1.response_delay_ms)

    timestamps =
      streams
      |> Enum.map(& &1.start_timestamp)
      |> Enum.reject(&is_nil/1)

    %HTTPClientStats{
      client: client_str,
      client_host: client_host,
      connection_count: length(flows),
      stream_count: stream_count,
      request_count: request_count,
      response_count: response_count,
      request_bytes: request_bytes,
      response_bytes: response_bytes,
      methods: methods,
      status_codes: status_codes,
      avg_response_time_ms: safe_avg(response_times),
      min_response_time_ms: Enum.min(response_times, fn -> nil end),
      max_response_time_ms: Enum.max(response_times, fn -> nil end),
      first_timestamp: Enum.min_by(timestamps, &ts_to_nanos/1, fn -> nil end),
      last_timestamp: Enum.max_by(timestamps, &ts_to_nanos/1, fn -> nil end)
    }
  end

  # Helper functions

  defp get_host(%Endpoint{host: host}, _hosts_map) when not is_nil(host), do: host
  defp get_host(%Endpoint{ip: ip}, hosts_map), do: Map.get(hosts_map, ip)
  defp get_host(_, _), do: nil

  defp get_client_host(%Endpoint{host: host}, _hosts_map) when not is_nil(host), do: host
  defp get_client_host(%Endpoint{ip: ip}, hosts_map), do: Map.get(hosts_map, ip)
  defp get_client_host(_, _), do: nil

  defp ts_to_nanos(nil), do: 0
  defp ts_to_nanos(ts), do: PcapFileEx.Timestamp.to_unix_nanos(ts)

  defp safe_avg([]), do: nil
  defp safe_avg(list), do: round(Enum.sum(list) / length(list))

  defp merge_maps(maps) do
    Enum.reduce(maps, %{}, fn map, acc ->
      Map.merge(acc, map, fn _k, v1, v2 -> v1 + v2 end)
    end)
  end
end
