defmodule PcapFileEx.Endpoint do
  @moduledoc """
  Represents a network endpoint (IP + optional port).

  `ip` is stored as a string (IPv4 or IPv6) and `port` is either an integer or `nil`.
  """

  @enforce_keys [:ip]
  defstruct ip: nil, port: nil

  @type t :: %__MODULE__{
          ip: String.t(),
          port: non_neg_integer() | nil
        }

  @doc """
  Builds a new endpoint ensuring the IP is a string.
  """
  @spec new(String.t(), non_neg_integer() | nil) :: t()
  def new(ip, port \\ nil) when is_binary(ip) do
    %__MODULE__{ip: ip, port: port}
  end

  @doc """
  Formats the endpoint as `"ip:port"` when a port is present, otherwise just the IP.
  """
  @spec to_string(t() | nil) :: String.t() | nil
  def to_string(nil), do: nil
  def to_string(%__MODULE__{ip: ip, port: nil}), do: ip
  def to_string(%__MODULE__{ip: ip, port: port}), do: "#{ip}:#{port}"

  defimpl String.Chars do
    def to_string(endpoint), do: PcapFileEx.Endpoint.to_string(endpoint)
  end
end
