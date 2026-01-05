defmodule PcapFileEx.Endpoint do
  @moduledoc """
  Represents a network endpoint (IP + optional port + optional hostname).

  `ip` is stored as a string (IPv4 or IPv6), `port` is either an integer or `nil`,
  and `host` is an optional hostname string resolved via hosts mapping.

  ## Hosts Mapping

  The `host` field allows mapping IP addresses to human-readable hostnames:

      hosts = %{
        "172.25.0.4" => "api-gateway",
        "172.65.251.78" => "client-service"
      }

      endpoint = Endpoint.new("172.25.0.4", 9091)
      endpoint = Endpoint.with_hosts(endpoint, hosts)
      # => %Endpoint{ip: "172.25.0.4", port: 9091, host: "api-gateway"}

      Endpoint.to_string(endpoint)
      # => "api-gateway:9091"

  ## Creating from IP Tuples

  For HTTP/2 analysis and other cases where IPs are represented as tuples:

      Endpoint.from_tuple({{172, 25, 0, 4}, 9091})
      # => %Endpoint{ip: "172.25.0.4", port: 9091, host: nil}

      Endpoint.from_tuple({{172, 25, 0, 4}, 9091}, hosts)
      # => %Endpoint{ip: "172.25.0.4", port: 9091, host: "api-gateway"}
  """

  @enforce_keys [:ip]
  defstruct ip: nil, port: nil, host: nil

  @type t :: %__MODULE__{
          ip: String.t(),
          port: non_neg_integer() | nil,
          host: String.t() | nil
        }

  @typedoc "Map of IP address strings to hostname strings"
  @type hosts_map :: %{String.t() => String.t()}

  @doc """
  Builds a new endpoint with just an IP address.

  ## Examples

      iex> PcapFileEx.Endpoint.new("192.168.1.1")
      %PcapFileEx.Endpoint{ip: "192.168.1.1", port: nil, host: nil}
  """
  @spec new(String.t()) :: t()
  def new(ip) when is_binary(ip) do
    %__MODULE__{ip: ip, port: nil}
  end

  @doc """
  Builds a new endpoint with IP and port.

  ## Examples

      iex> PcapFileEx.Endpoint.new("192.168.1.1", 8080)
      %PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080, host: nil}

      iex> PcapFileEx.Endpoint.new("192.168.1.1", nil)
      %PcapFileEx.Endpoint{ip: "192.168.1.1", port: nil, host: nil}
  """
  @spec new(String.t(), non_neg_integer() | nil) :: t()
  def new(ip, port) when is_binary(ip) do
    %__MODULE__{ip: ip, port: port}
  end

  @doc """
  Builds a new endpoint with IP, port, and hostname.

  ## Examples

      iex> PcapFileEx.Endpoint.new("192.168.1.1", 8080, "api-server")
      %PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080, host: "api-server"}
  """
  @spec new(String.t(), non_neg_integer() | nil, String.t() | nil) :: t()
  def new(ip, port, host) when is_binary(ip) do
    %__MODULE__{ip: ip, port: port, host: host}
  end

  @doc """
  Applies a hosts mapping to an endpoint, setting the `host` field if the IP matches.

  Returns `nil` if the input endpoint is `nil`.

  ## Examples

      iex> hosts = %{"192.168.1.1" => "api-server"}
      iex> endpoint = PcapFileEx.Endpoint.new("192.168.1.1", 8080)
      iex> PcapFileEx.Endpoint.with_hosts(endpoint, hosts)
      %PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080, host: "api-server"}

      iex> hosts = %{"192.168.1.1" => "api-server"}
      iex> endpoint = PcapFileEx.Endpoint.new("10.0.0.1", 8080)
      iex> PcapFileEx.Endpoint.with_hosts(endpoint, hosts)
      %PcapFileEx.Endpoint{ip: "10.0.0.1", port: 8080, host: nil}

      iex> PcapFileEx.Endpoint.with_hosts(nil, %{})
      nil
  """
  @spec with_hosts(t() | nil, hosts_map()) :: t() | nil
  def with_hosts(nil, _hosts_map), do: nil

  def with_hosts(%__MODULE__{ip: ip} = endpoint, hosts_map) do
    %{endpoint | host: Map.get(hosts_map, ip)}
  end

  @doc """
  Creates an endpoint from an IP tuple and port, without hostname resolution.

  ## Examples

      iex> PcapFileEx.Endpoint.from_tuple({{192, 168, 1, 1}, 8080})
      %PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080, host: nil}

      iex> PcapFileEx.Endpoint.from_tuple({{0, 0, 0, 0, 0, 0, 0, 1}, 443})
      %PcapFileEx.Endpoint{ip: "::1", port: 443, host: nil}
  """
  @spec from_tuple({tuple(), non_neg_integer()}) :: t()
  def from_tuple(tuple), do: from_tuple(tuple, %{})

  @doc """
  Creates an endpoint from an IP tuple and port, with optional hostname resolution.

  Uses `:inet.ntoa/1` for consistent IP string formatting across the codebase.

  ## Examples

      iex> hosts = %{"192.168.1.1" => "api-server"}
      iex> PcapFileEx.Endpoint.from_tuple({{192, 168, 1, 1}, 8080}, hosts)
      %PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080, host: "api-server"}

      iex> hosts = %{"::1" => "localhost"}
      iex> PcapFileEx.Endpoint.from_tuple({{0, 0, 0, 0, 0, 0, 0, 1}, 443}, hosts)
      %PcapFileEx.Endpoint{ip: "::1", port: 443, host: "localhost"}
  """
  @spec from_tuple({tuple(), non_neg_integer()}, hosts_map()) :: t()
  def from_tuple({ip_tuple, port}, hosts_map) do
    ip = ip_tuple |> :inet.ntoa() |> List.to_string()
    %__MODULE__{ip: ip, port: port, host: Map.get(hosts_map, ip)}
  end

  @doc """
  Formats the endpoint as a string.

  - Uses `host` if present, otherwise falls back to `ip`
  - Appends `:port` only if port is non-nil

  ## Examples

      iex> PcapFileEx.Endpoint.to_string(%PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080, host: "api-server"})
      "api-server:8080"

      iex> PcapFileEx.Endpoint.to_string(%PcapFileEx.Endpoint{ip: "192.168.1.1", port: nil, host: "api-server"})
      "api-server"

      iex> PcapFileEx.Endpoint.to_string(%PcapFileEx.Endpoint{ip: "192.168.1.1", port: 8080, host: nil})
      "192.168.1.1:8080"

      iex> PcapFileEx.Endpoint.to_string(%PcapFileEx.Endpoint{ip: "192.168.1.1", port: nil, host: nil})
      "192.168.1.1"

      iex> PcapFileEx.Endpoint.to_string(nil)
      nil
  """
  @spec to_string(t() | nil) :: String.t() | nil
  def to_string(nil), do: nil

  def to_string(%__MODULE__{ip: ip, port: nil, host: nil}), do: ip
  def to_string(%__MODULE__{ip: _ip, port: nil, host: host}), do: host
  def to_string(%__MODULE__{ip: ip, port: port, host: nil}), do: "#{ip}:#{port}"
  def to_string(%__MODULE__{ip: _ip, port: port, host: host}), do: "#{host}:#{port}"

  defimpl String.Chars do
    def to_string(endpoint), do: PcapFileEx.Endpoint.to_string(endpoint)
  end
end
