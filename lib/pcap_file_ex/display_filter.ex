defmodule PcapFileEx.DisplayFilter do
  @moduledoc """
  Wireshark-style display filters for `PcapFileEx`.

  Supports boolean expressions with comparison operators over packet metadata and decoded payloads.

      PcapFileEx.stream("sample.pcapng")
      |> PcapFileEx.DisplayFilter.filter("ip.src == 127.0.0.1 && tcp.srcport == 8899")
      |> Enum.to_list()

  Supports standard fields like `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`, `udp.srcport`, `udp.dstport`, and others.
  """

  alias __MODULE__.FieldRegistry
  alias PcapFileEx.Packet

  @type compiled_filter :: (Packet.t() -> boolean())

  @doc """
  Compiles a display filter expression into a function that accepts a `%Packet{}`.
  """
  @spec compile(String.t()) :: {:ok, compiled_filter()} | {:error, String.t()}
  def compile(expression) when is_binary(expression) do
    with {:ok, tokens} <- tokenize(expression),
         {:ok, ast, []} <- parse_expression(tokens) do
      fun = fn packet ->
        packet = Packet.attach_decoded(packet)
        evaluate(ast, packet)
      end

      {:ok, fun}
    else
      {:error, reason} -> {:error, reason}
      {:ok, _ast, rest} -> {:error, "Unexpected tokens: #{inspect(rest)}"}
    end
  end

  @doc """
  Applies a compiled filter function to a stream/list of packets.
  """
  @spec run(Enumerable.t(), compiled_filter()) :: Enumerable.t()
  def run(enumerable, fun) when is_function(fun, 1) do
    Stream.filter(enumerable, fun)
  end

  @doc """
  Applies a display filter expression inline in a pipeline.

  Raises `ArgumentError` if the expression is invalid.
  """
  @spec filter(Enumerable.t(), String.t()) :: Enumerable.t()
  def filter(enumerable, expression) when is_binary(expression) do
    case compile(expression) do
      {:ok, fun} -> run(enumerable, fun)
      {:error, reason} -> raise ArgumentError, "invalid display filter (#{reason})"
    end
  end

  ## Parser -----------------------------------------------------------------

  defp tokenize(str) when is_binary(str) do
    do_tokenize(String.trim_leading(str), [])
  end

  defp do_tokenize("", acc), do: {:ok, Enum.reverse(acc)}

  defp do_tokenize(str, acc) do
    str = String.trim_leading(str)

    cond do
      str == "" ->
        {:ok, Enum.reverse(acc)}

      String.starts_with?(str, "&&") ->
        do_tokenize(binary_part(str, 2, byte_size(str) - 2), [:and | acc])

      String.starts_with?(str, "||") ->
        do_tokenize(binary_part(str, 2, byte_size(str) - 2), [:or | acc])

      String.starts_with?(str, "!") ->
        do_tokenize(binary_part(str, 1, byte_size(str) - 1), [:not | acc])

      String.starts_with?(str, "(") ->
        do_tokenize(binary_part(str, 1, byte_size(str) - 1), [:"(" | acc])

      String.starts_with?(str, ")") ->
        do_tokenize(binary_part(str, 1, byte_size(str) - 1), [:")" | acc])

      String.starts_with?(str, "contains") && next_non_identifier?(str, 8) ->
        do_tokenize(binary_part(str, 8, byte_size(str) - 8), [{:op, :contains} | acc])

      String.starts_with?(str, "==") ->
        do_tokenize(binary_part(str, 2, byte_size(str) - 2), [{:op, :eq} | acc])

      String.starts_with?(str, "!=") ->
        do_tokenize(binary_part(str, 2, byte_size(str) - 2), [{:op, :neq} | acc])

      String.starts_with?(str, ">=") ->
        do_tokenize(binary_part(str, 2, byte_size(str) - 2), [{:op, :gte} | acc])

      String.starts_with?(str, "<=") ->
        do_tokenize(binary_part(str, 2, byte_size(str) - 2), [{:op, :lte} | acc])

      String.starts_with?(str, ">") ->
        do_tokenize(binary_part(str, 1, byte_size(str) - 1), [{:op, :gt} | acc])

      String.starts_with?(str, "<") ->
        do_tokenize(binary_part(str, 1, byte_size(str) - 1), [{:op, :lt} | acc])

      String.starts_with?(str, "\"") ->
        case consume_string(str) do
          {:ok, value, rest} ->
            do_tokenize(rest, [{:string, value} | acc])

          {:error, reason} ->
            {:error, reason}
        end

      ip_literal?(str) ->
        {value, rest} = consume_regex(str, ~r/^\d+\.\d+\.\d+\.\d+/)
        do_tokenize(rest, [{:string, value} | acc])

      number_literal?(str) ->
        {value, rest} = consume_regex(str, ~r/^\d+/)
        do_tokenize(rest, [{:number, String.to_integer(value)} | acc])

      field_literal?(str) ->
        {value, rest} = consume_regex(str, ~r/^[A-Za-z_][A-Za-z0-9_.]*/)
        do_tokenize(rest, [{:field, value} | acc])

      true ->
        {:error, "unexpected token near: #{inspect(String.slice(str, 0, 10))}"}
    end
  end

  defp next_non_identifier?(str, offset) do
    case String.slice(str, offset, 1) do
      <<char>> when char in [?0..?9, ?A..?Z, ?a..?z, ?_, ?.] -> false
      _ -> true
    end
  end

  defp consume_string(<<"\"", rest::binary>>), do: consume_string(rest, [])

  defp consume_string(<<"\"", rest::binary>>, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp consume_string(<<"\\\"", rest::binary>>, acc), do: consume_string(rest, ["\"" | acc])
  defp consume_string(<<"\\\\", rest::binary>>, acc), do: consume_string(rest, ["\\" | acc])
  defp consume_string(<<"\\n", rest::binary>>, acc), do: consume_string(rest, ["\n" | acc])
  defp consume_string(<<"\\t", rest::binary>>, acc), do: consume_string(rest, ["\t" | acc])
  defp consume_string(<<"\\r", rest::binary>>, acc), do: consume_string(rest, ["\r" | acc])

  defp consume_string(<<char::utf8, rest::binary>>, acc),
    do: consume_string(rest, [<<char::utf8>> | acc])

  defp consume_string(_, _), do: {:error, "unterminated string literal"}

  defp consume_regex(str, regex) do
    [match] = Regex.run(regex, str)
    length = byte_size(match)
    rest = binary_part(str, length, byte_size(str) - length)
    {match, rest}
  end

  defp ip_literal?(str), do: Regex.match?(~r/^\d+\.\d+\.\d+\.\d+/, str)
  defp number_literal?(str), do: Regex.match?(~r/^\d+/, str)
  defp field_literal?(str), do: Regex.match?(~r/^[A-Za-z_][A-Za-z0-9_.]*/, str)

  ## Recursive-descent parser

  defp parse_expression(tokens), do: parse_or(tokens)

  defp parse_or(tokens) do
    with {:ok, left, rest} <- parse_and(tokens) do
      parse_or_rest(left, rest)
    end
  end

  defp parse_or_rest(left, [:or | rest]) do
    with {:ok, right, rest2} <- parse_and(rest) do
      parse_or_rest({:or, left, right}, rest2)
    end
  end

  defp parse_or_rest(left, rest), do: {:ok, left, rest}

  defp parse_and(tokens) do
    with {:ok, left, rest} <- parse_not(tokens) do
      parse_and_rest(left, rest)
    end
  end

  defp parse_and_rest(left, [:and | rest]) do
    with {:ok, right, rest2} <- parse_not(rest) do
      parse_and_rest({:and, left, right}, rest2)
    end
  end

  defp parse_and_rest(left, rest), do: {:ok, left, rest}

  defp parse_not([:not | rest]) do
    with {:ok, expr, rest2} <- parse_not(rest) do
      {:ok, {:not, expr}, rest2}
    end
  end

  defp parse_not(tokens), do: parse_factor(tokens)

  defp parse_factor([:"(" | rest]) do
    with {:ok, expr, rest2} <- parse_expression(rest) do
      case rest2 do
        [:")" | rest3] -> {:ok, expr, rest3}
        _ -> {:error, "missing closing parenthesis"}
      end
    end
  end

  defp parse_factor(tokens), do: parse_comparison(tokens)

  defp parse_comparison([{:field, field}, {:op, op} | rest]) do
    case rest do
      [{type, value} | rest2] when type in [:string, :number] ->
        {:ok, {:cmp, field, op, {type, value}}, rest2}

      _ ->
        {:error, "expected literal after operator"}
    end
  end

  defp parse_comparison([{:field, _} | _]), do: {:error, "expected comparison operator"}
  defp parse_comparison(tokens), do: {:error, "expected field comparison, got #{inspect(tokens)}"}

  ## Evaluation ----------------------------------------------------------------

  defp evaluate({:and, left, right}, packet) do
    evaluate(left, packet) && evaluate(right, packet)
  end

  defp evaluate({:or, left, right}, packet) do
    evaluate(left, packet) || evaluate(right, packet)
  end

  defp evaluate({:not, expr}, packet) do
    !evaluate(expr, packet)
  end

  defp evaluate({:cmp, field, op, literal}, packet) do
    case FieldRegistry.fetch(field) do
      {:ok, %{type: type, accessor: accessor}} ->
        value = accessor.(packet)
        compare(type, value, op, literal)

      :error ->
        false
    end
  end

  defp compare(_type, nil, _op, _literal), do: false

  defp compare(:string, actual, :contains, {:string, expected}) when is_binary(actual) do
    String.contains?(actual, expected)
  end

  defp compare(:string, actual, :contains, {:number, expected}) when is_binary(actual) do
    String.contains?(actual, Integer.to_string(expected))
  end

  defp compare(:string, actual, op, literal) do
    actual = to_string(actual)
    expected = literal_to_string(literal)

    case op do
      :eq -> actual == expected
      :neq -> actual != expected
      :contains -> String.contains?(actual, expected)
      _ -> false
    end
  end

  defp compare(:integer, actual, op, literal) do
    case literal_to_integer(literal) do
      {:ok, expected} ->
        case op do
          :eq -> actual == expected
          :neq -> actual != expected
          :gt -> actual > expected
          :lt -> actual < expected
          :gte -> actual >= expected
          :lte -> actual <= expected
          _ -> false
        end

      _ ->
        false
    end
  end

  defp compare(:list_integer, actual, op, literal) when is_list(actual) do
    case literal_to_integer(literal) do
      {:ok, expected} ->
        case op do
          :eq -> Enum.any?(actual, &(&1 == expected))
          :neq -> Enum.any?(actual, &(&1 != expected))
          _ -> false
        end

      _ ->
        false
    end
  end

  defp compare(_type, _actual, _op, _literal), do: false

  defp literal_to_string({:string, value}), do: value
  defp literal_to_string({:number, value}), do: Integer.to_string(value)

  defp literal_to_integer({:number, value}), do: {:ok, value}

  defp literal_to_integer({:string, value}) do
    case Integer.parse(value) do
      {int, ""} -> {:ok, int}
      _ -> :error
    end
  end

  ## Field registry ------------------------------------------------------------

  defmodule FieldRegistry do
    @moduledoc false
    alias PcapFileEx.{DecoderRegistry, Endpoint, Packet}

    defp base_fields do
      %{
        "ip.src" => %{
          type: :string,
          accessor: fn
            %{src: %Endpoint{ip: ip}} -> ip
            _ -> nil
          end
        },
        "ip.dst" => %{
          type: :string,
          accessor: fn
            %{dst: %Endpoint{ip: ip}} -> ip
            _ -> nil
          end
        },
        "tcp.srcport" => %{
          type: :integer,
          accessor: fn
            %{src: %Endpoint{port: port}, protocols: protocols} when is_integer(port) ->
              if :tcp in protocols, do: port, else: nil

            _ ->
              nil
          end
        },
        "tcp.dstport" => %{
          type: :integer,
          accessor: fn
            %{dst: %Endpoint{port: port}, protocols: protocols} when is_integer(port) ->
              if :tcp in protocols, do: port, else: nil

            _ ->
              nil
          end
        },
        "udp.srcport" => %{
          type: :integer,
          accessor: fn
            %{src: %Endpoint{port: port}, protocols: protocols} when is_integer(port) ->
              if :udp in protocols, do: port, else: nil

            _ ->
              nil
          end
        },
        "udp.dstport" => %{
          type: :integer,
          accessor: fn
            %{dst: %Endpoint{port: port}, protocols: protocols} when is_integer(port) ->
              if :udp in protocols, do: port, else: nil

            _ ->
              nil
          end
        }
      }
    end

    @spec fetch(String.t()) :: {:ok, map()} | :error
    def fetch(field), do: Map.fetch(fields_map(), field)

    @spec fields() :: [String.t()]
    def fields, do: fields_map() |> Map.keys()

    defp fields_map do
      Map.merge(base_fields(), dynamic_fields())
    end

    defp dynamic_fields do
      DecoderRegistry.list()
      |> Enum.reduce(%{}, fn entry, acc ->
        Enum.reduce(entry.fields, acc, fn field_desc, inner_acc ->
          Map.put(inner_acc, field_desc.id, %{
            type: field_desc.type,
            accessor: dynamic_accessor(entry.protocol, field_desc.extractor)
          })
        end)
      end)
    end

    defp dynamic_accessor(protocol, extractor) do
      fn packet ->
        decoded = Packet.attach_decoded(packet).decoded

        with %{} = map <- decoded,
             value when not is_nil(value) <- Map.get(map, protocol) do
          safe_extract(extractor, value)
        else
          _ -> nil
        end
      end
    end

    defp safe_extract(extractor, decoded) do
      extractor.(decoded)
    rescue
      _ -> nil
    end
  end
end
