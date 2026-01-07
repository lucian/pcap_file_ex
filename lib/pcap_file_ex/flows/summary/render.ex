defmodule PcapFileEx.Flows.Summary.Render do
  @moduledoc """
  Render Summary data as markdown tables and Mermaid flowcharts.

  ## Markdown Tables

      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng")
      markdown = PcapFileEx.Flows.Summary.Render.to_markdown(result.summary)
      IO.puts(markdown)

  ## Mermaid Flowcharts

      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng")
      mermaid = PcapFileEx.Flows.Summary.Render.to_mermaid(result.summary)
      IO.puts(mermaid)

  """

  alias PcapFileEx.Flows.Summary
  alias PcapFileEx.Flows.Summary.{HTTPService, UDPService}

  @doc """
  Renders the summary as markdown tables.

  ## Options

  - `:title` - Add section titles (default: true)
  - `:humanize_bytes` - Format bytes as KB/MB (default: false)
  - `:protocol` - Filter to :http1, :http2, :udp, or :all (default: :all)

  ## Example

      iex> render = PcapFileEx.Flows.Summary.Render.to_markdown(summary)
      iex> IO.puts(render)
      ## HTTP Traffic
      | Protocol | Server | Client | Requests | Responses | Req Bytes | Res Bytes | Avg RT (ms) |
      ...
  """
  @spec to_markdown(Summary.t(), keyword()) :: String.t()
  def to_markdown(%Summary{} = summary, opts \\ []) do
    show_title = Keyword.get(opts, :title, true)
    protocol_filter = Keyword.get(opts, :protocol, :all)

    sections = []

    # HTTP section (combined http1 + http2)
    http_services = filter_http_services(summary, protocol_filter)

    sections =
      if http_services != [] do
        sections ++ [http_table(http_services, show_title, opts)]
      else
        sections
      end

    # UDP section
    sections =
      if protocol_filter in [:all, :udp] and summary.udp != [] do
        sections ++ [udp_table(summary.udp, show_title, opts)]
      else
        sections
      end

    Enum.join(sections, "\n\n")
  end

  @doc """
  Renders the summary as a Mermaid flowchart.

  ## Options

  - `:direction` - :lr (left-right, default) or :tb (top-bottom)
  - `:group_by` - :protocol (default) or :none

  ## Example

      iex> mermaid = PcapFileEx.Flows.Summary.Render.to_mermaid(summary)
      iex> IO.puts(mermaid)
      flowchart LR
        subgraph Clients
          c0[web-client]
        end
        ...
  """
  @spec to_mermaid(Summary.t(), keyword()) :: String.t()
  def to_mermaid(%Summary{} = summary, opts \\ []) do
    direction = Keyword.get(opts, :direction, :lr)
    group_by = Keyword.get(opts, :group_by, :protocol)

    # Collect all unique clients and services
    {clients, services, connections} = extract_topology(summary)

    if clients == [] and services == [] do
      "flowchart #{direction_str(direction)}\n  %% Empty summary"
    else
      lines =
        [
          "flowchart #{direction_str(direction)}",
          client_subgraph(clients),
          service_subgraphs(services, group_by),
          connection_lines(connections)
        ]
        |> List.flatten()
        |> Enum.reject(&is_nil/1)

      Enum.join(lines, "\n")
    end
  end

  # --- HTTP Table ---

  defp filter_http_services(summary, :all), do: summary.http1 ++ summary.http2
  defp filter_http_services(summary, :http1), do: summary.http1
  defp filter_http_services(summary, :http2), do: summary.http2
  defp filter_http_services(_summary, :udp), do: []

  defp http_table(services, show_title, opts) do
    humanize = Keyword.get(opts, :humanize_bytes, false)

    title =
      if show_title do
        "## HTTP Traffic\n\n"
      else
        ""
      end

    header =
      "| Protocol | Server | Client | Requests | Responses | Req Bytes | Res Bytes | Avg RT (ms) |"

    separator =
      "|----------|--------|--------|----------|-----------|-----------|-----------|-------------|"

    rows =
      services
      |> Enum.flat_map(fn service ->
        Enum.map(service.clients, fn client ->
          format_http_row(service, client, humanize)
        end)
      end)

    title <> Enum.join([header, separator | rows], "\n")
  end

  defp format_http_row(%HTTPService{} = service, client, humanize) do
    server = format_server(service.server_host, service.server)
    client_name = client.client_host || client.client
    req_bytes = format_bytes(client.request_bytes, humanize)
    res_bytes = format_bytes(client.response_bytes, humanize)
    avg_rt = format_number(client.avg_response_time_ms)

    "| #{service.protocol} | #{server} | #{client_name} | #{client.request_count} | #{client.response_count} | #{req_bytes} | #{res_bytes} | #{avg_rt} |"
  end

  # --- UDP Table ---

  defp udp_table(services, show_title, opts) do
    humanize = Keyword.get(opts, :humanize_bytes, false)

    title =
      if show_title do
        "## UDP Traffic\n\n"
      else
        ""
      end

    header = "| Server | Client | Packets | Total Bytes | Avg Size | Min | Max |"
    separator = "|--------|--------|---------|-------------|----------|-----|-----|"

    rows =
      services
      |> Enum.flat_map(fn service ->
        Enum.map(service.clients, fn client ->
          format_udp_row(service, client, humanize)
        end)
      end)

    title <> Enum.join([header, separator | rows], "\n")
  end

  defp format_udp_row(%UDPService{} = service, client, humanize) do
    server = format_server(service.server_host, service.server)
    client_name = client.client_host || client.client
    total_bytes = format_bytes(client.total_bytes, humanize)
    avg_size = format_number(client.avg_size)
    min_size = format_number(client.min_size)
    max_size = format_number(client.max_size)

    "| #{server} | #{client_name} | #{client.packet_count} | #{total_bytes} | #{avg_size} | #{min_size} | #{max_size} |"
  end

  # --- Mermaid Flowchart ---

  defp direction_str(:lr), do: "LR"
  defp direction_str(:tb), do: "TB"
  defp direction_str(:rl), do: "RL"
  defp direction_str(:bt), do: "BT"

  defp extract_topology(summary) do
    # Collect clients, services, and connections
    {http_clients, http_services, http_conns} = extract_http_topology(summary.http1, :http1)

    {http2_clients, http2_services, http2_conns} =
      extract_http_topology(summary.http2, :http2)

    {udp_clients, udp_services, udp_conns} = extract_udp_topology(summary.udp)

    # Merge and deduplicate clients by name
    all_clients =
      (http_clients ++ http2_clients ++ udp_clients)
      |> Enum.uniq_by(fn {name, _id} -> name end)

    all_services = http_services ++ http2_services ++ udp_services
    all_connections = http_conns ++ http2_conns ++ udp_conns

    {all_clients, all_services, all_connections}
  end

  defp extract_http_topology(services, protocol) do
    services
    |> Enum.with_index()
    |> Enum.reduce({[], [], []}, fn {service, idx}, {clients, servers, conns} ->
      server_name = format_server(service.server_host, service.server)
      server_id = "s#{protocol}_#{idx}"

      new_server = {server_name, server_id, protocol}

      {new_clients, new_conns} =
        service.clients
        |> Enum.map(fn client ->
          client_name = client.client_host || client.client
          client_id = sanitize_id("c_#{client_name}")
          label = "#{client.request_count} req"
          {{client_name, client_id}, {client_id, server_id, label}}
        end)
        |> Enum.unzip()

      {clients ++ new_clients, [new_server | servers], conns ++ new_conns}
    end)
  end

  defp extract_udp_topology(services) do
    services
    |> Enum.with_index()
    |> Enum.reduce({[], [], []}, fn {service, idx}, {clients, servers, conns} ->
      server_name = format_server(service.server_host, service.server)
      server_id = "sudp_#{idx}"

      new_server = {server_name, server_id, :udp}

      {new_clients, new_conns} =
        service.clients
        |> Enum.map(fn client ->
          client_name = client.client_host || client.client
          client_id = sanitize_id("c_#{client_name}")
          label = "#{client.packet_count} pkts"
          {{client_name, client_id}, {client_id, server_id, label}}
        end)
        |> Enum.unzip()

      {clients ++ new_clients, [new_server | servers], conns ++ new_conns}
    end)
  end

  defp client_subgraph([]), do: nil

  defp client_subgraph(clients) do
    nodes =
      clients
      |> Enum.map(fn {name, id} -> "    #{id}[#{escape_mermaid(name)}]" end)

    ["  subgraph Clients", nodes, "  end"]
    |> List.flatten()
  end

  defp service_subgraphs([], _group_by), do: nil

  defp service_subgraphs(services, :protocol) do
    services
    |> Enum.group_by(fn {_name, _id, protocol} -> protocol end)
    |> Enum.map(fn {protocol, group} ->
      subgraph_name = protocol_label(protocol)

      nodes =
        Enum.map(group, fn {name, id, _proto} ->
          "    #{id}[#{escape_mermaid(name)}]"
        end)

      ["  subgraph #{subgraph_name}", nodes, "  end"]
      |> List.flatten()
    end)
    |> List.flatten()
  end

  defp service_subgraphs(services, :none) do
    services
    |> Enum.map(fn {name, id, _proto} ->
      "  #{id}[#{escape_mermaid(name)}]"
    end)
  end

  defp protocol_label(:http1), do: "HTTP/1"
  defp protocol_label(:http2), do: "HTTP/2"
  defp protocol_label(:udp), do: "UDP"

  defp connection_lines([]), do: nil

  defp connection_lines(connections) do
    connections
    |> Enum.uniq()
    |> Enum.map(fn {from_id, to_id, label} ->
      "  #{from_id} -->|#{label}| #{to_id}"
    end)
  end

  defp sanitize_id(str) do
    str
    |> String.replace(~r/[^a-zA-Z0-9_]/, "_")
    |> String.replace(~r/_+/, "_")
    |> String.trim_trailing("_")
  end

  defp escape_mermaid(str) do
    # Escape special characters for Mermaid node labels
    str
    |> String.replace("\"", "'")
    |> String.replace("[", "(")
    |> String.replace("]", ")")
  end

  # --- Formatting Helpers ---

  defp format_server(nil, server), do: server

  defp format_server(host, server) do
    # server is "IP:port", extract port and append to hostname
    case String.split(server, ":") do
      [_ip, port] -> "#{host}:#{port}"
      _ -> host
    end
  end

  defp format_bytes(nil, _humanize), do: "-"
  defp format_bytes(bytes, false), do: format_number(bytes)

  defp format_bytes(bytes, true) when bytes >= 1_000_000_000 do
    "#{Float.round(bytes / 1_000_000_000, 1)} GB"
  end

  defp format_bytes(bytes, true) when bytes >= 1_000_000 do
    "#{Float.round(bytes / 1_000_000, 1)} MB"
  end

  defp format_bytes(bytes, true) when bytes >= 1_000 do
    "#{Float.round(bytes / 1_000, 1)} KB"
  end

  defp format_bytes(bytes, true), do: "#{bytes} B"

  defp format_number(nil), do: "-"
  defp format_number(num) when is_float(num), do: Integer.to_string(round(num))
  defp format_number(num), do: Integer.to_string(num)
end
