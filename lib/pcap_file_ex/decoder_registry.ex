defmodule PcapFileEx.DecoderRegistry do
  @moduledoc """
  Registry of application-layer payload decoders.

  ## New API (v0.5.0+)

  Matchers can now return context to decoders for clean data flow:

      DecoderRegistry.register(%{
        protocol: :my_protocol,
        matcher: fn layers, payload ->
          if my_protocol?(layers) do
            {:match, extract_context(layers)}  # Return context
          else
            false
          end
        end,
        decoder: fn context, payload ->  # Receive context
          decode(payload, context)
        end,
        fields: [...]
      })

  Benefits:
  - ✅ No `Process.put` workarounds (thread-safe, no race conditions)
  - ✅ More efficient (decode once in matcher, use cached result in decoder)
  - ✅ Pure data flow (easier to test)

  ## Legacy API (deprecated, will be removed in v1.0.0)

  The old API is still supported for backward compatibility:

      DecoderRegistry.register(%{
        protocol: :my_protocol,
        matcher: fn layers, payload -> my_protocol?(layers) end,  # Returns boolean
        decoder: fn payload -> decode(payload) end,  # Arity-1
        fields: [...]
      })

  **Note:** Deprecation warnings will be emitted when using the old API.

  ## Decoder Entry Format

  Each decoder entry supplies:

    * `:protocol` — atom identifying the protocol (e.g., `:http`)
    * `:matcher` — function returning `false | {:match, context}` when the decoder applies
    * `:decoder` — function accepting `(context, payload)` and returning structured data
    * `:fields` — optional list of field descriptors for extraction

  Matchers receive the list of protocol layers returned by `:pkt.decode/2` and the raw payload
  binary from the previous layer. Decoders receive the context from the matcher (or `nil` for
  old API) and the payload. Decoders should return `{:ok, value}` on success; any other
  return is wrapped in `{:ok, value}` automatically.
  """

  alias PcapFileEx.HTTP

  @type field_descriptor :: %{
          id: String.t(),
          type: :string | :integer | :list_integer,
          extractor: (term() -> term())
        }

  # New API types (v0.5.0+)
  @type match_result :: false | {:match, context :: term()}
  @type matcher_fun :: (list(), binary() -> match_result())
  @type decoder_fun :: (term(), binary() -> {:ok, term()} | {:error, term()} | term())

  @type entry :: %{
          protocol: atom(),
          matcher: matcher_fun(),
          decoder: decoder_fun(),
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

  Supports both new API (arity-2 decoder) and legacy API (arity-1 decoder).
  """
  @spec register(entry()) :: :ok
  def register(%{protocol: protocol, matcher: matcher, decoder: decoder} = entry)
      when is_atom(protocol) and is_function(matcher, 2) and
             (is_function(decoder, 1) or is_function(decoder, 2)) do
    ensure_initialized()

    # Emit deprecation warning for old API
    if is_function(decoder, 1) do
      IO.warn("""
      Decoder registry old API (arity-1 decoder) is deprecated and will be removed in v1.0.0.
      Please update your decoder to accept context as first argument:

        decoder: fn context, payload -> ... end

      See migration guide: https://hexdocs.pm/pcap_file_ex/changelog.html#v0-5-0-2025-11-19
      """)
    end

    entry =
      entry
      |> normalize_fields()
      |> normalize_entry()

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
          if Enum.any?(layers, fn
               {:tcp, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} -> true
               :tcp -> true
               %{protocol: :tcp} -> true
               _ -> false
             end) do
            case HTTP.decode(payload) do
              # Cache decoded result as context (optimization: decode once, not twice)
              {:ok, decoded} -> {:match, decoded}
              _ -> false
            end
          else
            false
          end
        end,
        # Use cached result from matcher
        decoder: fn decoded, _payload -> {:ok, decoded} end,
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

  # Backward compatibility: Normalize old API to new API
  defp normalize_entry(%{matcher: matcher, decoder: decoder} = entry) do
    decoder_arity = :erlang.fun_info(decoder)[:arity]

    case decoder_arity do
      # Old API: matcher returns boolean, decoder arity-1
      1 ->
        %{entry | matcher: wrap_old_matcher(matcher), decoder: wrap_old_decoder(decoder)}

      # New API: matcher returns {:match, context}, decoder arity-2
      2 ->
        entry
    end
  end

  # Wrap old-style matcher (boolean) to new-style ({:match, context} | false)
  defp wrap_old_matcher(matcher) do
    fn layers, payload ->
      case matcher.(layers, payload) do
        # Old API: convert true to {:match, nil}
        true -> {:match, nil}
        false -> false
        # Already new format (backward compatible matchers)
        other -> other
      end
    end
  end

  # Wrap old-style decoder (arity-1) to new-style (arity-2)
  defp wrap_old_decoder(decoder) do
    fn _context, payload ->
      # Old API: ignore context, call with payload only
      decoder.(payload)
    end
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
