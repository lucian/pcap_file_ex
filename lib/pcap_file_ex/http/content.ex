defmodule PcapFileEx.HTTP.Content do
  @moduledoc """
  Generic HTTP body content decoder based on Content-Type.

  Recursively decodes multipart bodies, JSON, and text.
  Unknown types remain as binary. Supports custom decoders for binary content.

  ## Design Principles

  1. **Content-Type driven** - Decode strategy based on Content-Type header
  2. **Recursive** - Multipart parts are decoded based on their own Content-Type
  3. **Safe fallback** - Unknown types remain as binary (no crashes)
  4. **Custom decoders** - Binary content can be decoded by user-provided decoders

  ## Custom Decoder Pipeline

  Custom decoders are invoked only when built-in decoding yields `{:binary, payload}`:
  1. Built-in JSON decoder (`application/json`)
  2. Built-in text decoder (`text/*`)
  3. Built-in multipart parser (`multipart/*`)
  4. **Custom decoders** (if provided in opts)
  5. Binary fallback

  ## Examples

      iex> PcapFileEx.HTTP.Content.decode("application/json", ~s({"key":"value"}))
      {:json, %{"key" => "value"}}

      iex> PcapFileEx.HTTP.Content.decode("text/plain", "hello")
      {:text, "hello"}

      iex> PcapFileEx.HTTP.Content.decode("application/octet-stream", <<1, 2, 3>>)
      {:binary, <<1, 2, 3>>}

  """

  alias PcapFileEx.Flows.DecoderMatcher

  @type decoded ::
          {:json, map() | list()}
          | {:text, String.t()}
          | {:multipart, [part()]}
          | {:binary, binary()}
          | {:custom, term()}
          | {:decode_error, term()}

  @type part :: %{
          content_type: String.t(),
          content_id: String.t() | nil,
          headers: %{String.t() => String.t()},
          body: decoded()
        }

  @type raw_part :: %{
          headers: %{String.t() => String.t()},
          body: binary()
        }

  @doc """
  Decode HTTP body based on Content-Type header.

  Returns a tagged tuple indicating the decoded content type:
  - `{:json, data}` - Parsed JSON map or list
  - `{:text, string}` - Valid UTF-8 text
  - `{:multipart, parts}` - List of decoded parts
  - `{:binary, data}` - Raw binary (unknown type or decode failure)
  - `{:custom, data}` - Custom decoder result
  - `{:decode_error, reason}` - Custom decoder error

  ## Options

  - `:decoders` - List of custom decoder specs (see `PcapFileEx.Flows.Decoder`)
  - `:context` - Base context for decoder matching (protocol, direction, headers, etc.)

  ## Examples

      iex> Content.decode("application/json", ~s({"a":1}))
      {:json, %{"a" => 1}}

      iex> Content.decode("text/plain", "hello")
      {:text, "hello"}

      iex> Content.decode(nil, <<1, 2, 3>>)
      {:binary, <<1, 2, 3>>}

  """
  @spec decode(String.t() | nil, binary(), keyword()) :: decoded()
  def decode(content_type, body, opts \\ [])

  def decode(nil, body, opts), do: try_custom_or_binary(nil, body, opts)
  def decode("", body, opts), do: try_custom_or_binary("", body, opts)

  def decode(content_type, body, opts) when is_binary(content_type) and is_binary(body) do
    base_type = normalize_content_type(content_type)

    cond do
      String.starts_with?(base_type, "multipart/") ->
        decode_multipart(content_type, body, opts)

      base_type in ["application/json", "application/problem+json"] ->
        # JSON parse failure yields {:binary, body} which is eligible for custom decoders
        case decode_json(body) do
          {:binary, _} = binary_result ->
            try_custom_or_binary(content_type, body, opts, binary_result)

          other ->
            other
        end

      String.starts_with?(base_type, "text/") ->
        # Text decode failure yields {:binary, body} which is eligible for custom decoders
        case decode_text(body, extract_charset(content_type)) do
          {:binary, _} = binary_result ->
            try_custom_or_binary(content_type, body, opts, binary_result)

          other ->
            other
        end

      true ->
        try_custom_or_binary(content_type, body, opts)
    end
  end

  @doc """
  Extract boundary parameter from multipart Content-Type.

  ## Examples

      iex> Content.extract_boundary("multipart/related; boundary=abc123")
      {:ok, "abc123"}

      iex> Content.extract_boundary(~s(multipart/related; boundary="abc 123"))
      {:ok, "abc 123"}

      iex> Content.extract_boundary("application/json")
      {:error, :no_boundary}

  """
  @spec extract_boundary(String.t()) :: {:ok, String.t()} | {:error, :no_boundary}
  def extract_boundary(content_type) do
    # Try quoted boundary first (can contain spaces)
    case Regex.run(~r/boundary="([^"]+)"/, content_type) do
      [_, boundary] ->
        {:ok, boundary}

      nil ->
        # Try unquoted boundary (no spaces allowed)
        case Regex.run(~r/boundary=([^\s;]+)/, content_type) do
          [_, boundary] -> {:ok, boundary}
          nil -> {:error, :no_boundary}
        end
    end
  end

  @doc """
  Parse MIME multipart body into raw parts.

  Uses binary pattern matching to preserve exact bytes in part bodies.
  Does not decode part bodies - use `decode/2` for that.

  ## Examples

      iex> body = "--abc\\r\\nContent-Type: text/plain\\r\\n\\r\\nhello\\r\\n--abc--"
      iex> Content.parse_parts(body, "abc")
      {:ok, [%{headers: %{"content-type" => "text/plain"}, body: "hello"}]}

  """
  @spec parse_parts(binary(), String.t()) :: {:ok, [raw_part()]} | {:error, term()}
  def parse_parts(body, boundary) do
    delimiter = "\r\n--" <> boundary
    first_delimiter = "--" <> boundary
    terminator_suffix = "--"

    case skip_to_first_delimiter(body, first_delimiter) do
      {:ok, rest} ->
        parts = parse_parts_loop(rest, delimiter, terminator_suffix, [])
        {:ok, parts}

      :not_found ->
        {:error, :no_delimiter_found}
    end
  end

  # --- Private Functions ---

  # Try custom decoders for binary content, fall back to {:binary, payload}
  defp try_custom_or_binary(content_type, body, opts, fallback \\ nil) do
    decoders = Keyword.get(opts, :decoders, [])
    base_ctx = Keyword.get(opts, :context, %{})

    if decoders == [] do
      fallback || {:binary, body}
    else
      # Build context for matching - only set scope to :body if not already set
      ctx =
        base_ctx
        |> Map.put_new(:scope, :body)
        |> Map.put(:content_type, content_type && normalize_content_type(content_type))

      case DecoderMatcher.find_and_invoke(decoders, ctx, body) do
        {:ok, decoded} -> {:custom, decoded}
        {:error, reason} -> {:decode_error, reason}
        :skip -> fallback || {:binary, body}
      end
    end
  end

  defp normalize_content_type(content_type) do
    content_type
    |> String.split(";")
    |> hd()
    |> String.trim()
    |> String.downcase()
  end

  defp extract_charset(content_type) do
    case Regex.run(~r/charset="?([^";\s]+)"?/i, content_type) do
      [_, charset] -> String.downcase(charset)
      nil -> nil
    end
  end

  defp decode_json(body) do
    case Jason.decode(body) do
      {:ok, data} -> {:json, data}
      {:error, _} -> {:binary, body}
    end
  end

  defp decode_text(body, charset) do
    charset = charset || "utf-8"

    cond do
      charset in ["utf-8", "utf8"] ->
        if String.valid?(body) do
          {:text, body}
        else
          {:binary, body}
        end

      charset in ["iso-8859-1", "latin1", "latin-1"] ->
        case :unicode.characters_to_binary(body, :latin1) do
          converted when is_binary(converted) -> {:text, converted}
          _ -> {:binary, body}
        end

      true ->
        # Unknown charset - return as binary
        {:binary, body}
    end
  end

  defp decode_multipart(content_type, body, opts) do
    with {:ok, boundary} <- extract_boundary(content_type),
         {:ok, parts} <- parse_parts(body, boundary) do
      base_ctx = Keyword.get(opts, :context, %{})

      decoded_parts =
        Enum.map(parts, fn part ->
          part_ct = Map.get(part.headers, "content-type", "application/octet-stream")
          content_id = Map.get(part.headers, "content-id")

          # Build part-specific context for custom decoders
          # Override headers with part's own headers (not parent request/response headers)
          part_ctx =
            base_ctx
            |> Map.put(:scope, :multipart_part)
            |> Map.put(:content_type, normalize_content_type(part_ct))
            |> Map.put(:content_id, content_id)
            |> Map.put(:headers, part.headers)

          part_opts = Keyword.put(opts, :context, part_ctx)
          decoded_body = decode(part_ct, part.body, part_opts)

          %{
            content_type: part_ct,
            content_id: content_id,
            headers: part.headers,
            body: decoded_body
          }
        end)

      {:multipart, decoded_parts}
    else
      # Multipart parse failure yields {:binary, body} which is eligible for custom decoders
      {:error, _} -> try_custom_or_binary(content_type, body, opts)
    end
  end

  defp skip_to_first_delimiter(body, first_delimiter) do
    case :binary.match(body, first_delimiter) do
      {pos, len} ->
        # Skip past the delimiter
        rest = :binary.part(body, pos + len, byte_size(body) - pos - len)
        {:ok, rest}

      :nomatch ->
        :not_found
    end
  end

  defp parse_parts_loop(body, delimiter, terminator_suffix, acc) do
    # Skip CRLF after delimiter
    body = skip_crlf(body)

    # Check if we're at the terminator
    if String.starts_with?(body, terminator_suffix) or body == "" do
      Enum.reverse(acc)
    else
      case :binary.split(body, delimiter) do
        [part_data, rest] ->
          part = parse_single_part(part_data)
          parse_parts_loop(rest, delimiter, terminator_suffix, [part | acc])

        [remaining] ->
          # No more delimiters - check for terminator
          terminator = terminator_suffix

          case :binary.split(remaining, terminator) do
            [part_data, _epilogue] ->
              part_data = strip_trailing_crlf(part_data)
              part = parse_single_part(part_data)
              Enum.reverse([part | acc])

            [_no_terminator] ->
              # Malformed - return what we have
              Enum.reverse(acc)
          end
      end
    end
  end

  defp skip_crlf(<<"\r\n", rest::binary>>), do: rest
  defp skip_crlf(<<"\n", rest::binary>>), do: rest
  defp skip_crlf(body), do: body

  defp strip_trailing_crlf(data) do
    size = byte_size(data)

    cond do
      size >= 2 and :binary.part(data, size - 2, 2) == "\r\n" ->
        :binary.part(data, 0, size - 2)

      size >= 1 and :binary.part(data, size - 1, 1) == "\n" ->
        :binary.part(data, 0, size - 1)

      true ->
        data
    end
  end

  defp parse_single_part(data) do
    case :binary.split(data, "\r\n\r\n") do
      [headers_raw, part_body] ->
        headers = parse_part_headers(headers_raw)
        %{headers: headers, body: part_body}

      [headers_only] ->
        # Try with just \n\n (tolerant parsing)
        case :binary.split(headers_only, "\n\n") do
          [headers_raw, part_body] ->
            headers = parse_part_headers(headers_raw)
            %{headers: headers, body: part_body}

          [_] ->
            # No body separator found
            headers = parse_part_headers(headers_only)
            %{headers: headers, body: <<>>}
        end
    end
  end

  defp parse_part_headers(raw) do
    # Handle line continuations (folded headers per RFC 2822)
    unfolded =
      raw
      |> :binary.replace("\r\n ", " ", [:global])
      |> :binary.replace("\r\n\t", " ", [:global])
      |> :binary.replace("\n ", " ", [:global])
      |> :binary.replace("\n\t", " ", [:global])

    # Split into lines and parse each header
    unfolded
    |> :binary.split("\r\n", [:global])
    |> Enum.flat_map(fn line ->
      # Also split on just \n for tolerant parsing
      :binary.split(line, "\n", [:global])
    end)
    |> Enum.reduce(%{}, fn line, headers ->
      case :binary.match(line, ":") do
        {pos, _len} ->
          # Split at first colon only - value may contain additional colons
          name = :binary.part(line, 0, pos) |> String.trim() |> String.downcase()
          value = :binary.part(line, pos + 1, byte_size(line) - pos - 1) |> String.trim()
          Map.put(headers, name, value)

        :nomatch ->
          # Malformed header line (no colon) - skip
          headers
      end
    end)
  end
end
