defmodule PcapFileEx.HTTP do
  @moduledoc """
  Minimal HTTP decoder for payloads extracted from TCP segments.

  Designed to work with payloads returned by `:pkt.decode/2`. It parses the
  request/response line, headers, and any body bytes present within the same
  packet.
  """

  @enforce_keys [:type, :version, :headers, :body, :body_length, :complete?, :raw]
  defstruct type: nil,
            method: nil,
            uri: nil,
            version: nil,
            status_code: nil,
            reason_phrase: nil,
            headers: %{},
            body: "",
            body_length: nil,
            complete?: true,
            raw: "",
            decoded_body: nil

  @type t :: %__MODULE__{
          type: :request | :response,
          method: String.t() | nil,
          uri: String.t() | nil,
          version: String.t(),
          status_code: non_neg_integer() | nil,
          reason_phrase: String.t() | nil,
          headers: %{optional(String.t()) => String.t()},
          body: binary(),
          body_length: non_neg_integer() | nil,
          complete?: boolean(),
          raw: binary(),
          decoded_body: term()
        }

  @doc """
  Decodes an HTTP payload.

  Returns `{:ok, %__MODULE__{}}` on success or `{:error, reason}`.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, atom()}
  def decode(payload) when is_binary(payload) and payload != "" do
    with {:ok, header_part, body} <- split_headers_body(payload),
         {:ok, start_line, header_lines} <- extract_start_line(header_part),
         {:ok, message} <- build_message(start_line, header_lines, body, payload) do
      {:ok, message}
    else
      {:error, _} = error -> error
    end
  end

  def decode(_payload), do: {:error, :not_http}

  @doc """
  Same as `decode/1` but raises on failure.
  """
  @spec decode!(binary()) :: t()
  def decode!(payload) do
    case decode(payload) do
      {:ok, message} -> message
      {:error, reason} -> raise RuntimeError, "http decode failed: #{inspect(reason)}"
    end
  end

  defp split_headers_body(payload) do
    case :binary.match(payload, "\r\n\r\n") do
      {header_len, _} ->
        header_part = binary_part(payload, 0, header_len)
        body = binary_part(payload, header_len + 4, byte_size(payload) - header_len - 4)
        {:ok, header_part, body}

      :nomatch ->
        {:error, :incomplete}
    end
  end

  defp extract_start_line(header_part) do
    lines = String.split(header_part, "\r\n", trim: true)

    case lines do
      [] -> {:error, :invalid_start_line}
      [start_line | rest] -> {:ok, start_line, rest}
    end
  end

  defp build_message(start_line, header_lines, body, raw) do
    case parse_start_line(start_line) do
      {:request, method, uri, version} ->
        headers = parse_headers(header_lines)

        {:ok,
         %__MODULE__{
           type: :request,
           method: method,
           uri: uri,
           version: version,
           headers: headers,
           body: body,
           body_length: parse_content_length(headers),
           complete?: body_complete?(headers, body),
           raw: raw,
           decoded_body: decode_body(body, headers)
         }}

      {:response, version, status_code, reason} ->
        headers = parse_headers(header_lines)

        {:ok,
         %__MODULE__{
           type: :response,
           version: version,
           status_code: status_code,
           reason_phrase: reason,
           headers: headers,
           body: body,
           body_length: parse_content_length(headers),
           complete?: body_complete?(headers, body),
           raw: raw,
           decoded_body: decode_body(body, headers)
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_start_line("HTTP/" <> rest) do
    case String.split(rest, " ", parts: 3) do
      [version, status, reason] ->
        with {:ok, status_code} <- parse_status(status) do
          {:response, version, status_code, String.trim(reason)}
        else
          _ -> {:error, :invalid_status}
        end

      [version, status] ->
        with {:ok, status_code} <- parse_status(status) do
          {:response, version, status_code, ""}
        else
          _ -> {:error, :invalid_status}
        end

      _ ->
        {:error, :invalid_start_line}
    end
  end

  defp parse_start_line(line) do
    case String.split(line, " ", parts: 3) do
      [method, uri, "HTTP/" <> version] ->
        {:request, method, uri, version}

      _ ->
        {:error, :invalid_start_line}
    end
  end

  defp parse_status(status) do
    status
    |> String.trim()
    |> Integer.parse()
    |> case do
      {code, ""} -> {:ok, code}
      _ -> :error
    end
  end

  defp parse_headers(lines) do
    {headers, _last_key} =
      Enum.reduce(lines, {%{}, nil}, fn line, {acc, last_key} ->
        cond do
          line == "" ->
            {acc, last_key}

          continuation_line?(line) and last_key ->
            updated =
              Map.update!(acc, last_key, fn value ->
                value <> " " <> String.trim(line)
              end)

            {updated, last_key}

          true ->
            case String.split(line, ":", parts: 2) do
              [name, value] ->
                key = name |> String.trim() |> String.downcase()
                val = String.trim(value)
                {Map.put(acc, key, val), key}

              _ ->
                {acc, last_key}
            end
        end
      end)

    headers
  end

  defp continuation_line?(<<char, _::binary>>) when char in [?\s, ?\t], do: true
  defp continuation_line?(_), do: false

  defp parse_content_length(headers) do
    headers
    |> Map.get("content-length")
    |> case do
      nil ->
        nil

      value ->
        case Integer.parse(value) do
          {len, _} -> len
          :error -> nil
        end
    end
  end

  defp body_complete?(headers, body) do
    case parse_content_length(headers) do
      nil -> true
      expected when is_integer(expected) -> byte_size(body) >= expected
    end
  end

  # Automatically decodes HTTP body based on content-type header and magic bytes.
  #
  # Supports:
  # - Erlang Term Format (ETF) - starts with byte 131 (checked first)
  # - JSON - content-type contains "json"
  # - Form data - application/x-www-form-urlencoded
  # - Text - content-type starts with "text/"
  # - Raw binary for everything else
  #
  # Returns the decoded body or nil if empty.
  @spec decode_body(binary(), map()) :: term()
  defp decode_body(body, _headers) when body == "", do: nil

  defp decode_body(body, headers) do
    content_type = Map.get(headers, "content-type", "")

    cond do
      # Check for ETF format first (magic byte 131), regardless of content-type
      is_etf?(body) ->
        decode_etf(body)

      String.contains?(content_type, "json") ->
        decode_json(body)

      String.starts_with?(content_type, "text/") ->
        body

      String.starts_with?(content_type, "application/x-www-form-urlencoded") ->
        decode_form_urlencoded(body)

      true ->
        # Return raw binary for unknown types
        body
    end
  end

  defp is_etf?(<<131, _rest::binary>>), do: true
  defp is_etf?(_), do: false

  defp decode_etf(body) do
    # Use :safe flag to prevent code execution from malicious PCAP files
    # This prevents arbitrary code injection via specially crafted ETF payloads
    :erlang.binary_to_term(body, [:safe])
  rescue
    _ -> body
  end

  defp decode_json(body) do
    if Code.ensure_loaded?(Jason) do
      case Jason.decode(body) do
        {:ok, decoded} -> decoded
        {:error, _} -> body
      end
    else
      # Jason not available, return raw body
      body
    end
  rescue
    _ -> body
  end

  defp decode_form_urlencoded(body) do
    URI.decode_query(body)
  rescue
    _ -> body
  end
end
