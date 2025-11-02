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

  @type entry :: %{
          protocol: atom(),
          matcher: (list(), binary() -> boolean()),
          decoder: (binary() -> {:ok, term()} | {:error, term()} | term())
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

    :persistent_term.put(@key, entries)
    :ok
  end

  defp ensure_initialized do
    case :persistent_term.get(@key, :undefined) do
      :undefined -> :persistent_term.put(@key, default_decoders())
      _ -> :ok
    end
  end

  defp default_decoders do
    [
      %{
        protocol: :http,
        matcher: fn layers, payload ->
          has_tcp_layer?(layers) and match?({:ok, _}, HTTP.decode(payload))
        end,
        decoder: &HTTP.decode/1
      }
    ]
  end

  defp has_tcp_layer?(layers) do
    Enum.any?(layers, fn
      {:tcp, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} -> true
      :tcp -> true
      %{protocol: :tcp} -> true
      _ -> false
    end)
  end
end
