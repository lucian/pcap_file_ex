defmodule PcapFileEx.HTTP2.Headers do
  @moduledoc """
  HTTP/2 headers container with pseudo-header and regular header separation.

  HTTP/2 defines pseudo-headers that start with `:` and carry request/response
  metadata. Regular headers follow standard HTTP semantics.

  ## Pseudo-Headers

  Request pseudo-headers:
  - `:method` - HTTP method (GET, POST, etc.)
  - `:scheme` - URI scheme (http, https)
  - `:authority` - Host and optional port
  - `:path` - Request path

  Response pseudo-headers:
  - `:status` - Response status code

  ## Header Types

  - **Request headers**: Contains `:method` pseudo-header
  - **Response headers**: Contains `:status` pseudo-header
  - **Trailers**: No pseudo-headers present (sent after body)
  """

  @type t :: %__MODULE__{
          pseudo: %{optional(String.t()) => String.t()},
          regular: %{optional(String.t()) => String.t() | [String.t()]}
        }

  defstruct pseudo: %{}, regular: %{}

  @doc """
  Create Headers from a list of {name, value} tuples.

  Separates pseudo-headers (starting with `:`) from regular headers.
  Handles duplicate headers by converting to a list.
  """
  @spec from_list([{binary(), binary()}]) :: t()
  def from_list(header_list) when is_list(header_list) do
    {pseudo, regular} =
      Enum.reduce(header_list, {%{}, %{}}, fn {name, value}, {pseudo_acc, regular_acc} ->
        if String.starts_with?(name, ":") do
          {Map.put(pseudo_acc, name, value), regular_acc}
        else
          regular_acc = add_header(regular_acc, name, value)
          {pseudo_acc, regular_acc}
        end
      end)

    %__MODULE__{pseudo: pseudo, regular: regular}
  end

  @doc """
  Get the HTTP method from request headers.
  """
  @spec method(t()) :: String.t() | nil
  def method(%__MODULE__{pseudo: pseudo}), do: Map.get(pseudo, ":method")

  @doc """
  Get the request path from request headers.
  """
  @spec path(t()) :: String.t() | nil
  def path(%__MODULE__{pseudo: pseudo}), do: Map.get(pseudo, ":path")

  @doc """
  Get the scheme from request headers.
  """
  @spec scheme(t()) :: String.t() | nil
  def scheme(%__MODULE__{pseudo: pseudo}), do: Map.get(pseudo, ":scheme")

  @doc """
  Get the authority from request headers.
  """
  @spec authority(t()) :: String.t() | nil
  def authority(%__MODULE__{pseudo: pseudo}), do: Map.get(pseudo, ":authority")

  @doc """
  Get the status code from response headers.

  Returns the status as an integer, or nil if not present.
  """
  @spec status(t()) :: integer() | nil
  def status(%__MODULE__{pseudo: pseudo}) do
    case Map.get(pseudo, ":status") do
      nil -> nil
      status_str -> String.to_integer(status_str)
    end
  end

  @doc """
  Get the raw status string from response headers.
  """
  @spec status_string(t()) :: String.t() | nil
  def status_string(%__MODULE__{pseudo: pseudo}), do: Map.get(pseudo, ":status")

  @doc """
  Check if these are request headers (contains `:method`).
  """
  @spec request?(t()) :: boolean()
  def request?(%__MODULE__{pseudo: pseudo}), do: Map.has_key?(pseudo, ":method")

  @doc """
  Check if these are response headers (contains `:status`).
  """
  @spec response?(t()) :: boolean()
  def response?(%__MODULE__{pseudo: pseudo}), do: Map.has_key?(pseudo, ":status")

  @doc """
  Check if these are trailer headers (no pseudo-headers present).

  Trailers are headers sent after the body data in a request or response.
  They cannot contain pseudo-headers.
  """
  @spec trailers?(t()) :: boolean()
  def trailers?(%__MODULE__{pseudo: pseudo}), do: map_size(pseudo) == 0

  @doc """
  Check if this is an informational response (1xx status).
  """
  @spec informational?(t()) :: boolean()
  def informational?(%__MODULE__{} = headers) do
    case status(headers) do
      nil -> false
      status when status >= 100 and status < 200 -> true
      _ -> false
    end
  end

  @doc """
  Check if headers contain a specific pseudo-header.
  """
  @spec has_pseudo?(t(), String.t()) :: boolean()
  def has_pseudo?(%__MODULE__{pseudo: pseudo}, name) do
    Map.has_key?(pseudo, name)
  end

  @doc """
  Get a regular header value.

  Returns nil if header not present, or the value (String or list of Strings).
  """
  @spec get(t(), String.t()) :: String.t() | [String.t()] | nil
  def get(%__MODULE__{regular: regular}, name) do
    Map.get(regular, String.downcase(name))
  end

  @doc """
  Get a regular header value as a single string.

  If the header has multiple values, joins them with ", ".
  """
  @spec get_string(t(), String.t()) :: String.t() | nil
  def get_string(%__MODULE__{} = headers, name) do
    case get(headers, name) do
      nil -> nil
      values when is_list(values) -> Enum.join(values, ", ")
      value -> value
    end
  end

  @doc """
  Get all regular headers as a list of {name, value} tuples.

  Multi-value headers are expanded to multiple tuples.
  """
  @spec to_list(t()) :: [{String.t(), String.t()}]
  def to_list(%__MODULE__{regular: regular}) do
    Enum.flat_map(regular, fn
      {name, values} when is_list(values) ->
        Enum.map(values, fn value -> {name, value} end)

      {name, value} ->
        [{name, value}]
    end)
  end

  @doc """
  Get all headers (pseudo and regular) as a list.

  Pseudo-headers come first, followed by regular headers.
  """
  @spec all_to_list(t()) :: [{String.t(), String.t()}]
  def all_to_list(%__MODULE__{pseudo: pseudo} = headers) do
    pseudo_list = Enum.map(pseudo, fn {k, v} -> {k, v} end)
    regular_list = to_list(headers)
    pseudo_list ++ regular_list
  end

  # Private helpers

  defp add_header(headers, name, value) do
    # Normalize header name to lowercase (HTTP/2 requires lowercase anyway)
    name = String.downcase(name)

    case Map.get(headers, name) do
      nil ->
        Map.put(headers, name, value)

      existing when is_list(existing) ->
        Map.put(headers, name, existing ++ [value])

      existing ->
        Map.put(headers, name, [existing, value])
    end
  end
end
