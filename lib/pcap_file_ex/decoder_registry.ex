defmodule PcapFileEx.DecoderRegistry do
  @moduledoc """
  Registry of application-layer payload decoders.

  Each decoder entry supplies:

    * `:protocol` — atom identifying the protocol (e.g., `:http`)
    * `:matcher` — `fn layers, payload -> boolean end` returning true when the decoder applies
    * `:decoder` — `fn payload -> {:ok, term} | {:error, term}` returning structured data

  Matchers receive the list of protocol layers returned by `:pkt.decode/2` and the raw payload
  binary from the previous layer.  Decoders should return `{:ok, value}` on success; any other
  return is wrapped in `{:ok, value}` automatically.
  """

  alias PcapFileEx.HTTP

  @type field_descriptor :: %{
          id: String.t(),
          type: :string | :integer | :list_integer,
          extractor: (term() -> term())
        }

  @type entry :: %{
          protocol: atom(),
          matcher: (list(), binary() -> boolean()),
          decoder: (binary() -> {:ok, term()} | {:error, term()} | term()),
          fields: [field_descriptor()]
        }

  @key {:pcap_file_ex, :decoders}
  @doc """
  Lists the registered decoder entries in registration order.
  """
  @spec list() :: [entry()]
  def list do
    ensure_initialized()
    :persistent_term.get(@key)
  end

  @doc """
  Registers a new decoder entry.

  If a decoder for `entry.protocol` already exists it is replaced.
  """
  @spec register(entry()) :: :ok
  def register(%{protocol: protocol, matcher: matcher, decoder: decoder} = entry)
      when is_atom(protocol) and is_function(matcher, 2) and is_function(decoder, 1) do
    ensure_initialized()

    entry = normalize_fields(entry)

    entries =
      list()
      |> Enum.reject(&(&1.protocol == protocol))
      |> Kernel.++([entry])

    :persistent_term.put(@key, entries)
    :ok
  end

  @doc """
  Unregisters a decoder by protocol atom. No-op if not present.
  """
  @spec unregister(atom()) :: :ok
  def unregister(protocol) when is_atom(protocol) do
    ensure_initialized()

    entries =
      list()
      |> Enum.reject(&(&1.protocol == protocol))
      |> maybe_restore_default(protocol)

    :persistent_term.put(@key, entries)
    :ok
  end

  defp ensure_initialized do
    case :persistent_term.get(@key, :undefined) do
      :undefined -> :persistent_term.put(@key, default_decoders())
      _ -> :ok
    end
  end

  defp maybe_restore_default(entries, protocol) do
    case Enum.find(default_decoders(), &(&1.protocol == protocol)) do
      nil -> entries
      default -> entries ++ [default]
    end
  end

  defp default_decoders do
    [
      normalize_fields(%{
        protocol: :http,
        matcher: fn layers, payload ->
          Enum.any?(layers, fn
            {:tcp, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} -> true
            :tcp -> true
            %{protocol: :tcp} -> true
            _ -> false
          end) and match?({:ok, _}, HTTP.decode(payload))
        end,
        decoder: &HTTP.decode/1,
        fields: default_http_fields()
      })
    ]
  end

  defp normalize_fields(entry) do
    Map.update(entry, :fields, [], fn
      nil -> []
      fields -> fields
    end)
  end

  defp default_http_fields do
    [
      %{id: "http.request.method", type: :string, extractor: &http_request(&1, :method)},
      %{id: "http.uri", type: :string, extractor: &http_request(&1, :uri)},
      %{id: "http.response.code", type: :integer, extractor: &http_response(&1, :status_code)},
      %{id: "http.response.reason", type: :string, extractor: &http_response(&1, :reason_phrase)},
      %{id: "http.header.server", type: :string, extractor: &http_header(&1, "server")}
    ]
  end

  defp http_request(%{type: :request} = http, field), do: Map.get(http, field)
  defp http_request(_http, _field), do: nil

  defp http_response(%{type: :response} = http, field), do: Map.get(http, field)
  defp http_response(_http, _field), do: nil

  defp http_header(%{headers: headers}, name) when is_map(headers), do: Map.get(headers, name)
  defp http_header(_http, _name), do: nil
end
