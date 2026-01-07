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
    - `:keep_binary` - When `true`, preserve original binary in `payload_binary`/`body_binary`
      when custom decoders are invoked (default: `false`). **Warning:** This doubles
      memory usage for decoded content.
    - `:unwrap_custom` - When `true` (default), custom decoder results are returned directly
      without the `{:custom, ...}` wrapper tuple. Set to `false` to get wrapped results
      like `{:custom, decoded_value}`.
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

      # With binary preservation for playback
      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng",
        decoders: [decoder],
        keep_binary: true
      )
  """
  @spec analyze(Path.t(), keyword()) :: {:ok, AnalysisResult.t()} | {:error, term()}
  def analyze(pcap_path, opts \\ []) do
    hosts_map = Keyword.get(opts, :hosts_map, %{})
    decode_content = Keyword.get(opts, :decode_content, true)
    decoders = Keyword.get(opts, :decoders, [])
    keep_binary = Keyword.get(opts, :keep_binary, false)
    unwrap_custom = Keyword.get(opts, :unwrap_custom, true)
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
          decoders: decoders,
          keep_binary: keep_binary
        )

      # Analyze HTTP/2 flows using existing analyzer, then convert
      {:ok, http2_flows} =
        analyze_http2_flows(http2_segments, decode_content, hosts_map, decoders, keep_binary)

      # Collect UDP flows
      {:ok, udp_flows} =
        UDP.Collector.extract(pcap_path,
          port: udp_port,
          hosts_map: hosts_map,
          decoders: decoders,
          keep_binary: keep_binary
        )

      # Build combined result with traffic summary
      result = AnalysisResult.build(http1_flows, http2_flows, udp_flows, hosts_map: hosts_map)

      # Unwrap {:custom, value} tuples when unwrap_custom: true (default)
      result = if unwrap_custom, do: unwrap_custom_values(result), else: result

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
    keep_binary = Keyword.get(opts, :keep_binary, false)
    unwrap_custom = Keyword.get(opts, :unwrap_custom, true)

    # Classify TCP flows
    {http1_segments, http2_segments} = classify_tcp_flows(tcp_segments)

    # Analyze HTTP/1
    {:ok, http1_flows} =
      HTTP1.Analyzer.analyze(http1_segments,
        decode_content: decode_content,
        hosts_map: hosts_map,
        decoders: decoders,
        keep_binary: keep_binary
      )

    # Analyze HTTP/2
    {:ok, http2_flows} =
      analyze_http2_flows(http2_segments, decode_content, hosts_map, decoders, keep_binary)

    # Collect UDP
    {:ok, udp_flows} =
      UDP.Collector.collect(udp_packets,
        hosts_map: hosts_map,
        decoders: decoders,
        keep_binary: keep_binary
      )

    # Build result with traffic summary
    result = AnalysisResult.build(http1_flows, http2_flows, udp_flows, hosts_map: hosts_map)

    # Unwrap {:custom, value} tuples when unwrap_custom: true (default)
    result = if unwrap_custom, do: unwrap_custom_values(result), else: result

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

  # Unwrap {:custom, value} tuples to just value throughout the result
  # Leaves {:decode_error, reason} unchanged
  defp unwrap_custom_values(result) do
    %{
      result
      | http1: Enum.map(result.http1, &unwrap_http1_flow/1),
        http2: Enum.map(result.http2, &unwrap_http2_flow/1),
        udp: Enum.map(result.udp, &unwrap_udp_flow/1)
    }
  end

  defp unwrap_http1_flow(flow) do
    %{flow | exchanges: Enum.map(flow.exchanges, &unwrap_http1_exchange/1)}
  end

  defp unwrap_http1_exchange(exchange) do
    %{
      exchange
      | request: unwrap_decoded_body(exchange.request),
        response: unwrap_decoded_body(exchange.response)
    }
  end

  defp unwrap_http2_flow(flow) do
    %{
      flow
      | streams: Enum.map(flow.streams, &unwrap_http2_stream/1),
        incomplete: Enum.map(flow.incomplete, &unwrap_http2_incomplete/1)
    }
  end

  defp unwrap_http2_stream(stream) do
    %{stream | exchange: unwrap_http2_exchange(stream.exchange)}
  end

  defp unwrap_http2_exchange(exchange) do
    %{
      exchange
      | request: unwrap_decoded_body(exchange.request),
        response: unwrap_decoded_body(exchange.response)
    }
  end

  defp unwrap_http2_incomplete(incomplete) do
    request = if incomplete.request, do: unwrap_decoded_body(incomplete.request), else: nil
    response = if incomplete.response, do: unwrap_decoded_body(incomplete.response), else: nil
    %{incomplete | request: request, response: response}
  end

  defp unwrap_udp_flow(flow) do
    %{flow | datagrams: Enum.map(flow.datagrams, &unwrap_udp_datagram/1)}
  end

  defp unwrap_udp_datagram(datagram) do
    %{datagram | payload: unwrap_custom(datagram.payload)}
  end

  # Unwrap decoded_body in request/response maps
  defp unwrap_decoded_body(nil), do: nil

  defp unwrap_decoded_body(req_or_resp) when is_map(req_or_resp) do
    case Map.get(req_or_resp, :decoded_body) do
      nil -> req_or_resp
      decoded_body -> %{req_or_resp | decoded_body: unwrap_decoded(decoded_body)}
    end
  end

  # Unwrap decoded content - handles nested multipart structures
  defp unwrap_decoded({:custom, value}), do: value
  defp unwrap_decoded({:decode_error, _} = error), do: error
  defp unwrap_decoded({:multipart, parts}), do: {:multipart, Enum.map(parts, &unwrap_part/1)}
  defp unwrap_decoded(other), do: other

  defp unwrap_part(part) when is_map(part) do
    %{part | body: unwrap_decoded(part.body)}
  end

  # Unwrap custom tuple for UDP payloads
  defp unwrap_custom({:custom, value}), do: value
  defp unwrap_custom(other), do: other

  # Analyze HTTP/2 flows using existing PcapFileEx.HTTP2 analyzer
  defp analyze_http2_flows(segments, decode_content, hosts_map, decoders, keep_binary) do
    if segments == [] do
      {:ok, []}
    else
      # Use the HTTP2 analyzer directly on segments
      {:ok, complete, incomplete} =
        PcapFileEx.HTTP2.analyze_segments(segments,
          decode_content: decode_content,
          hosts_map: hosts_map,
          decoders: decoders,
          keep_binary: keep_binary
        )

      # Convert to Flows format
      HTTP2.Adapter.from_exchanges(complete, incomplete, hosts_map: hosts_map)
    end
  end
end
