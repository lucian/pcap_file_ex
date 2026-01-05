defmodule PcapFileEx.Flows.ProtocolDetector do
  @moduledoc """
  Detects HTTP protocol version from TCP flow data.

  Inspects the initial bytes of a TCP flow to determine whether it's
  HTTP/2 (h2c prior-knowledge), HTTP/1.x, or unknown.

  ## Detection Strategy

  1. **HTTP/2**: Match the connection preface `"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"`
  2. **HTTP/1**: Match request methods (`GET `, `POST `, etc.) or response (`HTTP/`)
  3. **Unknown**: Any other content

  ## Example

      data = "GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
      :http1 = ProtocolDetector.detect(data)

      data = "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" <> settings_frame
      :http2 = ProtocolDetector.detect(data)

      data = <<0x16, 0x03, 0x01, ...>>  # TLS handshake
      :unknown = ProtocolDetector.detect(data)
  """

  @http2_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @http2_preface_size byte_size(@http2_preface)

  # HTTP/1.x request methods (must be followed by space)
  @http1_methods ~w(GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT)

  @type protocol :: :http1 | :http2 | :unknown

  @doc """
  Detects the HTTP protocol version from flow data.

  Examines the beginning of the data to identify the protocol.

  ## Parameters

  - `data` - Binary data from the start of a TCP flow

  ## Returns

  - `:http2` - HTTP/2 connection preface detected
  - `:http1` - HTTP/1.x request or response detected
  - `:unknown` - Neither HTTP/1 nor HTTP/2 detected

  ## Examples

      iex> PcapFileEx.Flows.ProtocolDetector.detect("GET / HTTP/1.1\\r\\n")
      :http1

      iex> PcapFileEx.Flows.ProtocolDetector.detect("HTTP/1.1 200 OK\\r\\n")
      :http1

      iex> PcapFileEx.Flows.ProtocolDetector.detect("PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n")
      :http2

      iex> PcapFileEx.Flows.ProtocolDetector.detect(<<0, 1, 2, 3>>)
      :unknown
  """
  @spec detect(binary()) :: protocol()
  def detect(data) when is_binary(data) do
    cond do
      http2?(data) -> :http2
      http1?(data) -> :http1
      true -> :unknown
    end
  end

  @doc """
  Checks if data starts with HTTP/2 connection preface.

  ## Examples

      iex> PcapFileEx.Flows.ProtocolDetector.http2?("PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n")
      true

      iex> PcapFileEx.Flows.ProtocolDetector.http2?("GET / HTTP/1.1")
      false
  """
  @spec http2?(binary()) :: boolean()
  def http2?(<<@http2_preface, _rest::binary>>), do: true
  def http2?(_), do: false

  @doc """
  Checks if data looks like HTTP/1.x request or response.

  ## Examples

      iex> PcapFileEx.Flows.ProtocolDetector.http1?("GET / HTTP/1.1\\r\\n")
      true

      iex> PcapFileEx.Flows.ProtocolDetector.http1?("HTTP/1.1 200 OK\\r\\n")
      true

      iex> PcapFileEx.Flows.ProtocolDetector.http1?("PRI * HTTP/2.0")
      false
  """
  @spec http1?(binary()) :: boolean()
  def http1?(data) when is_binary(data) do
    http1_request?(data) or http1_response?(data)
  end

  @doc """
  Returns the HTTP/2 connection preface.
  """
  @spec http2_preface() :: binary()
  def http2_preface, do: @http2_preface

  @doc """
  Returns the size of the HTTP/2 connection preface in bytes.
  """
  @spec http2_preface_size() :: non_neg_integer()
  def http2_preface_size, do: @http2_preface_size

  # Check for HTTP/1.x request (METHOD SP Request-URI SP HTTP-Version)
  defp http1_request?(data) do
    Enum.any?(@http1_methods, fn method ->
      prefix = method <> " "
      String.starts_with?(data, prefix)
    end)
  end

  # Check for HTTP/1.x response (HTTP-Version SP Status-Code SP Reason-Phrase)
  defp http1_response?(<<"HTTP/", _rest::binary>>), do: true
  defp http1_response?(_), do: false
end
