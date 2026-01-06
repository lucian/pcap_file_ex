defmodule PcapFileEx.HTTP2 do
  @moduledoc """
  HTTP/2 cleartext (h2c) stream reconstruction.

  Parses HTTP/2 frames from TCP payloads and reconstructs complete
  request/response exchanges. Supports prior-knowledge h2c only
  (no HTTP/1.1 Upgrade flow).

  ## Example

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

      IO.puts("Complete: \#{length(complete)}, Incomplete: \#{length(incomplete)}")

      Enum.each(complete, fn ex ->
        IO.puts("\#{ex.request.method} \#{ex.request.path} -> \#{ex.response.status}")
      end)

  ## Limitations

  - **Cleartext only**: No TLS-encrypted HTTP/2 (h2)
  - **Prior-knowledge h2c only**: No HTTP/1.1 Upgrade flow support
  - **No server push**: PUSH_PROMISE frames are ignored
  - **Analysis only**: No playback server implementation

  ## Mid-Connection Capture

  When capturing starts after the HTTP/2 connection is established:
  - Client identification falls back to stream ID semantics
  - Some HPACK dynamic table entries may be missing (static table works)
  - SETTINGS frames are deferred until client is identified
  """

  alias PcapFileEx.Flows.TCPExtractor
  alias PcapFileEx.HTTP2.{Analyzer, Exchange, IncompleteExchange}

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @doc """
  Analyzes a PCAP file and returns HTTP/2 exchanges.

  Returns `{:ok, complete, incomplete}` where:
  - `complete` - List of fully completed request/response exchanges
  - `incomplete` - List of partial exchanges (RST, GOAWAY, truncated)

  ## Options

  - `:port` - Filter to specific TCP port (default: nil, all ports)
  - `:decode_content` - When `true` (default), automatically decodes request/response
    bodies based on Content-Type header. Multipart bodies are recursively decoded,
    JSON is parsed, and text is validated as UTF-8. When `false`, bodies remain as
    raw binaries and `decoded_body` is `nil`.
  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution.
  - `:decoders` - List of custom decoder specs (see `PcapFileEx.Flows.Decoder`)
  - `:keep_binary` - When `true`, preserve original binary in multipart parts'
    `body_binary` field when custom decoders are invoked (default: `false`)

  ## Example

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

      Enum.each(complete, fn ex ->
        IO.puts("\#{ex.request.method} \#{ex.request.path} -> \#{ex.response.status}")
      end)

      Enum.each(incomplete, fn ex ->
        IO.puts("Incomplete: \#{PcapFileEx.HTTP2.IncompleteExchange.to_string(ex)}")
      end)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "client", "10.0.0.1" => "server"}
      {:ok, complete, _incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap", hosts_map: hosts)
      %{client: client, server: server} = hd(complete)
      IO.puts("Request from \#{client} to \#{server}")
  """
  @spec analyze(Path.t(), keyword()) ::
          {:ok, [Exchange.t()], [IncompleteExchange.t()]} | {:error, term()}
  def analyze(pcap_path, opts \\ []) do
    port_filter = Keyword.get(opts, :port)
    decode_content = Keyword.get(opts, :decode_content, true)
    hosts_map = Keyword.get(opts, :hosts_map, %{})
    decoders = Keyword.get(opts, :decoders, [])
    keep_binary = Keyword.get(opts, :keep_binary, false)

    with {:ok, segments} <- TCPExtractor.extract(pcap_path, port: port_filter) do
      # Filter to likely HTTP/2 flows (those with preface or on common ports)
      http2_segments = filter_http2_segments(segments)

      Analyzer.analyze(http2_segments,
        decode_content: decode_content,
        hosts_map: hosts_map,
        decoders: decoders,
        keep_binary: keep_binary
      )
    end
  end

  @doc """
  Analyzes directional TCP segments directly.

  Use this when you already have TCP-reassembled segments with direction
  information, skipping the PCAP parsing step.

  ## Options

  - `:decode_content` - When `true` (default), automatically decodes request/response
    bodies based on Content-Type header. When `false`, bodies remain as raw binaries.
  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution.

  ## Example

      segments = [
        %{flow_key: {client, server}, direction: :a_to_b, data: preface_bytes, timestamp: ts1},
        %{flow_key: {client, server}, direction: :a_to_b, data: settings_frame, timestamp: ts2},
        ...
      ]

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze_segments(segments)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "client"}
      {:ok, complete, _incomplete} = PcapFileEx.HTTP2.analyze_segments(segments, hosts_map: hosts)
  """
  @spec analyze_segments([Analyzer.directional_segment()], keyword()) ::
          {:ok, [Exchange.t()], [IncompleteExchange.t()]}
  def analyze_segments(segments, opts \\ []) do
    Analyzer.analyze(segments, opts)
  end

  @doc """
  Check if binary data starts with HTTP/2 connection preface.

  The connection preface is `"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"` (24 bytes).
  """
  @spec http2?(binary()) :: boolean()
  def http2?(<<@connection_preface, _rest::binary>>), do: true
  def http2?(_), do: false

  @doc """
  Returns the HTTP/2 connection preface string.
  """
  @spec connection_preface() :: binary()
  def connection_preface, do: @connection_preface

  # Private helpers

  # Filter segments to likely HTTP/2 flows
  #
  # Strategy: Don't filter at all - let Analyzer process all TCP flows.
  # This avoids dropping valid mid-connection captures where initial segments
  # may be mid-frame (e.g., continuation of a DATA payload). The Analyzer
  # will simply produce no exchanges for non-HTTP/2 flows.
  #
  # If performance becomes an issue with many non-HTTP/2 flows, consider:
  # 1. Filtering AFTER reassembly (when we have complete frames to inspect)
  # 2. Port-based hinting (common HTTP/2 ports: 80, 443, 8080, 8443)
  # 3. Deferred filtering in FrameBuffer (first valid frame seen = keep flow)
  defp filter_http2_segments(segments) do
    # Pass all segments through - Analyzer handles non-HTTP/2 gracefully
    segments
  end
end
