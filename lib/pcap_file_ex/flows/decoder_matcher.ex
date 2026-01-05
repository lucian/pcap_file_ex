defmodule PcapFileEx.Flows.DecoderMatcher do
  @moduledoc """
  Matcher and invoker for custom flow decoders.

  Evaluates decoder specifications against match context and invokes
  matching decoders in order. Handles :skip fall-through and terminal errors.
  """

  alias PcapFileEx.Flows.Decoder

  require Logger

  @typedoc """
  Result of decoder evaluation.

  - `{:ok, term}` - Decoder succeeded, to be wrapped as `{:custom, term}`
  - `{:error, term}` - Decoder failed (terminal), to be stored as `{:decode_error, term}`
  - `:skip` - No decoder matched or all returned :skip
  """
  @type eval_result :: {:ok, term()} | {:error, term()} | :skip

  @doc """
  Find and invoke matching decoders for the given context and payload.

  Evaluates decoders in order. If a decoder returns `:skip`, continues to
  the next matching decoder. If a decoder returns `{:error, reason}`, stops
  immediately (terminal). Returns `:skip` if no decoder matches or all skip.

  ## Parameters

  - `decoders` - List of decoder specifications
  - `ctx` - Match context with protocol, direction, and other metadata
  - `payload` - Binary payload to decode

  ## Returns

  - `{:ok, decoded}` - A decoder succeeded
  - `{:error, reason}` - A decoder failed (terminal)
  - `:skip` - No decoder matched or all returned :skip
  """
  @spec find_and_invoke([Decoder.decoder_spec()], Decoder.match_context(), binary()) ::
          eval_result()
  def find_and_invoke(decoders, ctx, payload) when is_list(decoders) and is_binary(payload) do
    case Map.get(ctx, :protocol) do
      nil ->
        :skip

      protocol ->
        decoders
        |> Enum.filter(fn spec -> spec.protocol == protocol end)
        |> evaluate_candidates(ctx, payload)
    end
  end

  defp evaluate_candidates([], _ctx, _payload), do: :skip

  defp evaluate_candidates([spec | rest], ctx, payload) do
    if matches?(spec.match, ctx) do
      case invoke_decoder(spec.decoder, ctx, payload) do
        {:ok, _} = success -> success
        {:error, _} = error -> error
        :skip -> evaluate_candidates(rest, ctx, payload)
      end
    else
      evaluate_candidates(rest, ctx, payload)
    end
  end

  @doc """
  Check if a matcher matches the given context.

  ## Map Matchers

  All specified criteria must match:
  - `:scope` - Exact match
  - `:port` - Integer, Range, or list of integers
  - `:content_type` - String (exact), Regex, or list of strings
  - `:content_id` - String (exact) or Regex
  - `:method` - String or list of strings
  - `:path` - String (exact) or Regex

  ## Function Matchers

  Function receives the full context and returns boolean.
  Exceptions are caught and treated as no match.
  """
  @spec matches?(Decoder.matcher(), Decoder.match_context()) :: boolean()
  def matches?(matcher, ctx) when is_function(matcher, 1) do
    matcher.(ctx) == true
  rescue
    e ->
      Logger.warning("Matcher function raised: #{Exception.message(e)}")
      false
  end

  def matches?(matcher, ctx) when is_map(matcher) do
    Enum.all?(matcher, fn {key, expected} ->
      # Skip :protocol in matcher - it's handled at decoder_spec level
      if key == :protocol do
        true
      else
        actual = Map.get(ctx, key)
        match_value?(key, expected, actual)
      end
    end)
  end

  defp match_value?(_key, expected, actual) when expected == actual, do: true

  defp match_value?(:port, expected, actual) when is_integer(actual) do
    cond do
      is_integer(expected) -> expected == actual
      is_struct(expected, Range) -> actual in expected
      is_list(expected) -> actual in expected
      true -> false
    end
  end

  defp match_value?(:content_type, expected, actual) when is_binary(actual) do
    cond do
      is_binary(expected) -> String.downcase(expected) == String.downcase(actual)
      is_struct(expected, Regex) -> Regex.match?(expected, actual)
      is_list(expected) -> Enum.any?(expected, &(String.downcase(&1) == String.downcase(actual)))
      true -> false
    end
  end

  defp match_value?(:content_id, expected, actual) when is_binary(actual) do
    cond do
      is_binary(expected) -> expected == actual
      is_struct(expected, Regex) -> Regex.match?(expected, actual)
      true -> false
    end
  end

  defp match_value?(:method, expected, actual) when is_binary(actual) do
    cond do
      is_binary(expected) -> String.upcase(expected) == String.upcase(actual)
      is_list(expected) -> Enum.any?(expected, &(String.upcase(&1) == String.upcase(actual)))
      true -> false
    end
  end

  defp match_value?(:path, expected, actual) when is_binary(actual) do
    cond do
      is_binary(expected) -> expected == actual
      is_struct(expected, Regex) -> Regex.match?(expected, actual)
      true -> false
    end
  end

  defp match_value?(:scope, expected, actual) when is_atom(expected) and is_atom(actual) do
    expected == actual
  end

  defp match_value?(_key, _expected, _actual), do: false

  @doc """
  Invoke a decoder with the given context and payload.

  Handles:
  - Arity-1 functions: `decoder.(payload)`, wraps result
  - Arity-2 functions: `decoder.(ctx, payload)`, expects decode_result()
  - Modules: `module.decode(ctx, payload)`, expects decode_result()

  Exceptions are caught and returned as `{:error, %{exception: e, stacktrace: st}}`.
  """
  @spec invoke_decoder(Decoder.decoder_fn() | module(), Decoder.match_context(), binary()) ::
          Decoder.decode_result()
  def invoke_decoder(decoder, ctx, payload) do
    do_invoke(decoder, ctx, payload)
  rescue
    e ->
      stacktrace = __STACKTRACE__

      Logger.warning(
        "Decoder raised: #{Exception.message(e)}\n#{Exception.format_stacktrace(stacktrace)}"
      )

      {:error, %{exception: e, stacktrace: stacktrace}}
  end

  defp do_invoke(decoder, _ctx, payload) when is_function(decoder, 1) do
    case decoder.(payload) do
      {:error, reason} -> {:error, reason}
      other -> {:ok, other}
    end
  end

  defp do_invoke(decoder, ctx, payload) when is_function(decoder, 2) do
    decoder.(ctx, payload)
  end

  defp do_invoke(module, ctx, payload) when is_atom(module) do
    module.decode(ctx, payload)
  end

  @doc """
  Process the result from find_and_invoke into the final stored value.

  ## Returns

  - `{:custom, term}` - Decoder succeeded
  - `{:decode_error, reason}` - Decoder failed
  - `:binary_fallback` - No decoder matched (caller should use `{:binary, payload}` or `nil`)
  """
  @spec process_result(eval_result()) ::
          {:custom, term()} | {:decode_error, term()} | :binary_fallback
  def process_result({:ok, decoded}), do: {:custom, decoded}
  def process_result({:error, reason}), do: {:decode_error, reason}
  def process_result(:skip), do: :binary_fallback
end
