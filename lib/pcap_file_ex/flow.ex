defmodule PcapFileEx.Flow do
  @moduledoc """
  Represents a network traffic flow identity.

  A `Flow` identifies a logical connection between endpoints, with both
  authoritative fields (endpoints) for matching and display fields
  (from, server, client strings) for convenience.

  ## Fields

  ### Authoritative Fields (use for matching/filtering)

  - `protocol` - The protocol type (`:http1`, `:http2`, or `:udp`)
  - `server_endpoint` - The server endpoint (`Endpoint.t()`)
  - `client_endpoint` - The client endpoint (`Endpoint.t()` or `nil` for UDP)

  ### Display Fields (for convenience only)

  - `from` - Client host label without port, or `:any` for UDP flows
  - `server` - Server as "hostname:port" string (via `Endpoint.to_string/1`)
  - `client` - Client as "hostname:port" string, or `nil` for UDP flows

  ## Creating Flows

  Always use `Flow.new/3` to create flows - this ensures display fields
  are properly derived from endpoints:

      alias PcapFileEx.{Flow, Endpoint}

      client = Endpoint.new("192.168.1.10", 54321, "web-client")
      server = Endpoint.new("192.168.1.20", 8080, "api-gateway")

      flow = Flow.new(:http2, client, server)
      # => %Flow{
      #      protocol: :http2,
      #      from: "web-client",
      #      server: "api-gateway:8080",
      #      client: "web-client:54321",
      #      server_endpoint: %Endpoint{...},
      #      client_endpoint: %Endpoint{...}
      #    }

  ## Extracting FlowKey

  Use `Flow.key/1` to extract a `FlowKey` for map lookups:

      key = Flow.key(flow)
      # Use key for AnalysisResult.get_flow/2

  ## UDP Flows

  UDP flows use `from: :any` because datagrams are grouped by server only:

      server = Endpoint.new("192.168.1.20", 5005, "metrics-collector")
      flow = Flow.new(:udp, nil, server)
      # => %Flow{protocol: :udp, from: :any, client: nil, ...}
  """

  alias PcapFileEx.{Endpoint, FlowKey}

  @enforce_keys [:protocol, :server_endpoint]
  defstruct [
    :protocol,
    :from,
    :server,
    :client,
    :server_endpoint,
    :client_endpoint
  ]

  @type protocol :: :http1 | :http2 | :udp

  @type t :: %__MODULE__{
          protocol: protocol(),
          from: String.t() | :any,
          server: String.t(),
          client: String.t() | nil,
          server_endpoint: Endpoint.t(),
          client_endpoint: Endpoint.t() | nil
        }

  @doc """
  Creates a new Flow with proper display field derivation.

  ## Parameters

  - `protocol` - The protocol type (`:http1`, `:http2`, or `:udp`)
  - `client_endpoint` - The client endpoint, or `nil` for UDP flows
  - `server_endpoint` - The server endpoint (required)

  ## Examples

      iex> alias PcapFileEx.{Flow, Endpoint}
      iex> client = Endpoint.new("10.0.0.1", 12345, "client-host")
      iex> server = Endpoint.new("10.0.0.2", 80, "api-server")
      iex> flow = Flow.new(:http1, client, server)
      iex> flow.protocol
      :http1
      iex> flow.from
      "client-host"
      iex> flow.server
      "api-server:80"
      iex> flow.client
      "client-host:12345"

      # UDP flow with nil client
      iex> alias PcapFileEx.{Flow, Endpoint}
      iex> server = Endpoint.new("10.0.0.2", 5005)
      iex> flow = Flow.new(:udp, nil, server)
      iex> flow.from
      :any
      iex> flow.client
      nil
  """
  @spec new(protocol(), Endpoint.t() | nil, Endpoint.t()) :: t()
  def new(protocol, client_endpoint, server_endpoint)
      when protocol in [:http1, :http2, :udp] do
    %__MODULE__{
      protocol: protocol,
      from: derive_from(protocol, client_endpoint),
      server: Endpoint.to_string(server_endpoint),
      client: derive_client(client_endpoint),
      server_endpoint: server_endpoint,
      client_endpoint: client_endpoint
    }
  end

  @doc """
  Extracts a FlowKey for map lookups.

  This is the canonical way to get a `FlowKey` from a `Flow`.

  ## Examples

      iex> alias PcapFileEx.{Flow, FlowKey, Endpoint}
      iex> client = Endpoint.new("10.0.0.1", 12345)
      iex> server = Endpoint.new("10.0.0.2", 80)
      iex> flow = Flow.new(:http1, client, server)
      iex> key = Flow.key(flow)
      iex> key.protocol
      :http1
      iex> key.server_endpoint.port
      80
  """
  @spec key(t()) :: FlowKey.t()
  def key(%__MODULE__{} = flow) do
    FlowKey.new(flow.protocol, flow.client_endpoint, flow.server_endpoint)
  end

  # Derive the `from` display field
  # For UDP, always :any (grouped by server only)
  # For HTTP/1 and HTTP/2, use client host (without port) or IP
  defp derive_from(:udp, _client_endpoint), do: :any

  defp derive_from(_protocol, nil), do: nil

  defp derive_from(_protocol, %Endpoint{host: host}) when is_binary(host), do: host

  defp derive_from(_protocol, %Endpoint{ip: ip}), do: ip

  # Derive the `client` display field (full "host:port" or "ip:port")
  defp derive_client(nil), do: nil
  defp derive_client(%Endpoint{} = endpoint), do: Endpoint.to_string(endpoint)
end
