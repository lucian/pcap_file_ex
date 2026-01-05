defmodule PcapFileEx.FlowKey do
  @moduledoc """
  Stable identity for flow map lookups.

  `FlowKey` contains only the fields necessary for identifying a unique flow:
  protocol type and endpoint information. It is used as a map key in
  `AnalysisResult.flows` for O(1) lookups.

  ## Why FlowKey?

  Using the full `Flow` struct as a map key would be fragile because `Flow`
  contains display fields (like `from`, `server`, `client`) that are derived
  and could vary. `FlowKey` contains only the authoritative fields needed
  for equality comparison.

  ## Examples

      iex> alias PcapFileEx.{FlowKey, Endpoint}
      iex> client = Endpoint.new("192.168.1.10", 54321)
      iex> server = Endpoint.new("192.168.1.20", 8080)
      iex> FlowKey.new(:http2, client, server)
      %PcapFileEx.FlowKey{
        protocol: :http2,
        client_endpoint: %PcapFileEx.Endpoint{ip: "192.168.1.10", port: 54321, host: nil},
        server_endpoint: %PcapFileEx.Endpoint{ip: "192.168.1.20", port: 8080, host: nil}
      }

      # UDP flows have nil client_endpoint
      iex> FlowKey.new(:udp, nil, server)
      %PcapFileEx.FlowKey{
        protocol: :udp,
        client_endpoint: nil,
        server_endpoint: %PcapFileEx.Endpoint{ip: "192.168.1.20", port: 8080, host: nil}
      }
  """

  alias PcapFileEx.Endpoint

  @enforce_keys [:protocol, :server_endpoint]
  defstruct [:protocol, :client_endpoint, :server_endpoint]

  @type protocol :: :http1 | :http2 | :udp

  @type t :: %__MODULE__{
          protocol: protocol(),
          client_endpoint: Endpoint.t() | nil,
          server_endpoint: Endpoint.t()
        }

  @doc """
  Creates a new FlowKey for map lookups.

  ## Parameters

  - `protocol` - The protocol type (`:http1`, `:http2`, or `:udp`)
  - `client_endpoint` - The client endpoint, or `nil` for UDP flows
  - `server_endpoint` - The server endpoint (required)

  ## Examples

      iex> alias PcapFileEx.{FlowKey, Endpoint}
      iex> client = Endpoint.new("10.0.0.1", 12345)
      iex> server = Endpoint.new("10.0.0.2", 80)
      iex> key = FlowKey.new(:http1, client, server)
      iex> key.protocol
      :http1

      iex> alias PcapFileEx.{FlowKey, Endpoint}
      iex> server = Endpoint.new("10.0.0.2", 5005)
      iex> key = FlowKey.new(:udp, nil, server)
      iex> key.client_endpoint
      nil
  """
  @spec new(protocol(), Endpoint.t() | nil, Endpoint.t()) :: t()
  def new(protocol, client_endpoint, server_endpoint)
      when protocol in [:http1, :http2, :udp] do
    %__MODULE__{
      protocol: protocol,
      client_endpoint: client_endpoint,
      server_endpoint: server_endpoint
    }
  end

  @doc """
  Compares two FlowKeys for equality.

  Two FlowKeys are equal if they have the same protocol and endpoints.
  The `host` field in endpoints is ignored for comparison purposes
  since it's derived from hosts_map and may vary.

  ## Examples

      iex> alias PcapFileEx.{FlowKey, Endpoint}
      iex> client = Endpoint.new("10.0.0.1", 12345)
      iex> server = Endpoint.new("10.0.0.2", 80)
      iex> key1 = FlowKey.new(:http1, client, server)
      iex> key2 = FlowKey.new(:http1, client, server)
      iex> FlowKey.equal?(key1, key2)
      true
  """
  @spec equal?(t(), t()) :: boolean()
  def equal?(%__MODULE__{} = key1, %__MODULE__{} = key2) do
    key1.protocol == key2.protocol and
      endpoints_equal?(key1.client_endpoint, key2.client_endpoint) and
      endpoints_equal?(key1.server_endpoint, key2.server_endpoint)
  end

  @doc """
  Normalizes a FlowKey for use as a map key.

  Strips the `host` field from endpoints to ensure consistent key matching
  regardless of whether hosts_map was applied. This allows callers to pass
  either host-resolved or raw keys to `AnalysisResult.get_flow/2`.

  ## Examples

      iex> alias PcapFileEx.{FlowKey, Endpoint}
      iex> client = Endpoint.new("10.0.0.1", 12345, "client-host")
      iex> server = Endpoint.new("10.0.0.2", 80, "server-host")
      iex> key = FlowKey.new(:http1, client, server)
      iex> normalized = FlowKey.normalize(key)
      iex> normalized.client_endpoint.host
      nil
      iex> normalized.server_endpoint.host
      nil
  """
  @spec normalize(t()) :: t()
  def normalize(%__MODULE__{} = key) do
    %__MODULE__{
      protocol: key.protocol,
      client_endpoint: strip_host(key.client_endpoint),
      server_endpoint: strip_host(key.server_endpoint)
    }
  end

  defp endpoints_equal?(nil, nil), do: true
  defp endpoints_equal?(nil, _), do: false
  defp endpoints_equal?(_, nil), do: false

  defp endpoints_equal?(%Endpoint{ip: ip1, port: port1}, %Endpoint{ip: ip2, port: port2}) do
    ip1 == ip2 and port1 == port2
  end

  defp strip_host(nil), do: nil
  defp strip_host(%Endpoint{} = ep), do: %{ep | host: nil}
end
