defmodule PcapFileEx.Flows do
  @moduledoc """
  Unified traffic flow analysis API.

  Analyzes PCAP files to identify and group traffic by protocol (HTTP/1, HTTP/2, UDP).
  Returns a structured `AnalysisResult` with protocol-specific flow containers,
  a unified timeline for playback, and O(1) flow lookups.

  ## Example

      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng")

      # Access flows by protocol
      IO.puts("HTTP/1 flows: \#{length(result.http1)}")
      IO.puts("HTTP/2 flows: \#{length(result.http2)}")
      IO.puts("UDP flows: \#{length(result.udp)}")

      # Query specific flows
      result.http2
      |> Enum.filter(fn f -> f.flow.from == "web-client" end)
      |> Enum.flat_map(& &1.streams)

      # Playback in timeline order
      Enum.each(result.timeline, fn event ->
        data = PcapFileEx.Flows.AnalysisResult.get_event(result, event)
        playback(data)
      end)

  ## Protocol Detection

  TCP flows are classified by content inspection:
  - **HTTP/2**: Connection preface `"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"`
  - **HTTP/1**: Request methods (`GET `, `POST `, etc.) or `HTTP/` response

  UDP packets are collected separately and grouped by destination server.

  ## Hosts Mapping

  Use the `:hosts_map` option to resolve IP addresses to hostnames:

      hosts = %{
        "192.168.1.10" => "api-gateway",
        "192.168.1.20" => "metrics-collector"
      }
      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", hosts_map: hosts)

      # Now flows show friendly names
      result.http2
      |> Enum.map(fn f -> {f.flow.from, f.flow.server} end)
      # => [{"web-client", "api-gateway:8080"}, ...]
  """

  alias PcapFileEx.Flows.{
    AnalysisResult,
    HTTP1,
    HTTP2,
    ProtocolDetector,
    TCPExtractor,
    UDP
  }

  @doc """
  Analyzes a PCAP file and returns traffic flows grouped by protocol.

  ## Parameters

  - `pcap_path` - Path to PCAP/PCAPNG file
  - `opts` - Options:
    - `:hosts_map` - Map of IP address strings to hostname strings
    - `:decode_content` - Whether to decode HTTP bodies (default: true)
    - `:decoders` - List of custom decoder specs (see `PcapFileEx.Flows.Decoder`)
    - `:tcp_port` - Filter TCP traffic to specific port
    - `:udp_port` - Filter UDP traffic to specific port

  ## Returns

  `{:ok, result}` where result is an `AnalysisResult` struct containing:
  - `http1` - List of HTTP/1 flows
  - `http2` - List of HTTP/2 flows
  - `udp` - List of UDP flows
  - `flows` - Map for O(1) flow lookup by FlowKey
  - `timeline` - Unified event timeline for playback
  - `stats` - Aggregate statistics

  ## Examples

      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng")

      # With hosts mapping
      hosts = %{"10.0.0.1" => "client", "10.0.0.2" => "server"}
      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", hosts_map: hosts)

      # Filter to specific ports
      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", tcp_port: 8080)

      # With custom decoders
      decoder = %{protocol: :udp, match: %{port: 5005}, decoder: &MyDecoder.decode/1}
      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng", decoders: [decoder])
  """
  @spec analyze(Path.t(), keyword()) :: {:ok, AnalysisResult.t()} | {:error, term()}
  def analyze(pcap_path, opts \\ []) do
    hosts_map = Keyword.get(opts, :hosts_map, %{})
    decode_content = Keyword.get(opts, :decode_content, true)
    decoders = Keyword.get(opts, :decoders, [])
    tcp_port = Keyword.get(opts, :tcp_port)
    udp_port = Keyword.get(opts, :udp_port)

    # Extract TCP segments
    with {:ok, tcp_segments} <- TCPExtractor.extract(pcap_path, port: tcp_port) do
      # Classify TCP flows by protocol
      {http1_segments, http2_segments} = classify_tcp_flows(tcp_segments)

      # Analyze HTTP/1 flows
      {:ok, http1_flows} =
        HTTP1.Analyzer.analyze(http1_segments,
          decode_content: decode_content,
          hosts_map: hosts_map,
          decoders: decoders
        )

      # Analyze HTTP/2 flows using existing analyzer, then convert
      {:ok, http2_flows} =
        analyze_http2_flows(http2_segments, decode_content, hosts_map, decoders)

      # Collect UDP flows
      {:ok, udp_flows} =
        UDP.Collector.extract(pcap_path, port: udp_port, hosts_map: hosts_map, decoders: decoders)

      # Build combined result
      result = AnalysisResult.build(http1_flows, http2_flows, udp_flows)

      {:ok, result}
    end
  end

  @doc """
  Analyzes pre-extracted TCP segments.

  Use this when you already have TCP-reassembled segments, skipping the PCAP parsing step.

  ## Parameters

  - `tcp_segments` - List of TCP segments from `TCPExtractor`
  - `udp_packets` - List of UDP packets (optional, default: [])
  - `opts` - Same options as `analyze/2`

  ## Returns

  `{:ok, result}` with `AnalysisResult`
  """
  @spec analyze_segments([TCPExtractor.segment()], [map()], keyword()) ::
          {:ok, AnalysisResult.t()}
  def analyze_segments(tcp_segments, udp_packets \\ [], opts \\ []) do
    hosts_map = Keyword.get(opts, :hosts_map, %{})
    decode_content = Keyword.get(opts, :decode_content, true)
    decoders = Keyword.get(opts, :decoders, [])

    # Classify TCP flows
    {http1_segments, http2_segments} = classify_tcp_flows(tcp_segments)

    # Analyze HTTP/1
    {:ok, http1_flows} =
      HTTP1.Analyzer.analyze(http1_segments,
        decode_content: decode_content,
        hosts_map: hosts_map,
        decoders: decoders
      )

    # Analyze HTTP/2
    {:ok, http2_flows} = analyze_http2_flows(http2_segments, decode_content, hosts_map, decoders)

    # Collect UDP
    {:ok, udp_flows} =
      UDP.Collector.collect(udp_packets, hosts_map: hosts_map, decoders: decoders)

    # Build result
    result = AnalysisResult.build(http1_flows, http2_flows, udp_flows)

    {:ok, result}
  end

  # Classify TCP segments into HTTP/1 and HTTP/2 based on content inspection
  defp classify_tcp_flows(segments) do
    # Group by flow
    by_flow = TCPExtractor.group_by_flow(segments)

    # Classify each flow
    {http1_flows, http2_flows} =
      Enum.reduce(by_flow, {[], []}, fn {_flow_key, flow_segments}, {h1, h2} ->
        protocol = detect_flow_protocol(flow_segments)

        case protocol do
          :http2 -> {h1, flow_segments ++ h2}
          :http1 -> {flow_segments ++ h1, h2}
          :unknown -> {h1, h2}
        end
      end)

    {http1_flows, http2_flows}
  end

  # Detect protocol from first segment with data
  defp detect_flow_protocol(segments) do
    # Sort by timestamp and find first segment with meaningful data
    sorted = Enum.sort_by(segments, & &1.timestamp, DateTime)

    first_data =
      sorted
      |> Enum.map(& &1.data)
      |> Enum.find(&(byte_size(&1) >= 4))

    case first_data do
      nil -> :unknown
      data -> ProtocolDetector.detect(data)
    end
  end

  # Analyze HTTP/2 flows using existing PcapFileEx.HTTP2 analyzer
  defp analyze_http2_flows(segments, decode_content, hosts_map, decoders) do
    if segments == [] do
      {:ok, []}
    else
      # Use the HTTP2 analyzer directly on segments
      {:ok, complete, incomplete} =
        PcapFileEx.HTTP2.analyze_segments(segments,
          decode_content: decode_content,
          hosts_map: hosts_map,
          decoders: decoders
        )

      # Convert to Flows format
      HTTP2.Adapter.from_exchanges(complete, incomplete, hosts_map: hosts_map)
    end
  end
end
