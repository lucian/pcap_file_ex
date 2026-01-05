defmodule PcapFileEx.Flows.HTTP1.Analyzer do
  @moduledoc """
  HTTP/1.x request/response analyzer.

  Parses TCP segments to reconstruct HTTP/1.x exchanges.

  ## Features

  - Automatic client/server detection (first to send request)
  - Request/response pairing
  - Chunked transfer encoding support
  - Content-Length body reassembly
  - Body decoding via `PcapFileEx.HTTP.Content`

  ## Example

      {:ok, flows} = HTTP1.Analyzer.analyze(tcp_segments)

      Enum.each(flows, fn flow ->
        IO.puts("Flow: \#{flow.flow.from} -> \#{flow.flow.server}")
        Enum.each(flow.exchanges, fn ex ->
          IO.puts("  \#{ex.request.method} \#{ex.request.path} -> \#{ex.response.status}")
        end)
      end)
  """

  alias PcapFileEx.{Endpoint, Flow, Timestamp}
  alias PcapFileEx.Flows.HTTP1
  alias PcapFileEx.HTTP.Content

  @type segment :: %{
          flow_key: {{tuple(), non_neg_integer()}, {tuple(), non_neg_integer()}},
          direction: :a_to_b | :b_to_a,
          data: binary(),
          timestamp: DateTime.t()
        }

  @http_methods ~w(GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT)

  @doc """
  Analyzes TCP segments to extract HTTP/1.x flows.

  ## Parameters

  - `segments` - List of TCP segments from `TCPExtractor`
  - `opts` - Options:
    - `:decode_content` - Whether to decode bodies (default: true)
    - `:hosts_map` - Map of IP strings to hostnames
    - `:decoders` - List of custom decoder specs (see `PcapFileEx.Flows.Decoder`)

  ## Returns

  `{:ok, flows}` where flows is a list of `HTTP1.Flow.t()`
  """
  @spec analyze([segment()], keyword()) :: {:ok, [HTTP1.Flow.t()]}
  def analyze(segments, opts \\ []) do
    decode_content = Keyword.get(opts, :decode_content, true)
    hosts_map = Keyword.get(opts, :hosts_map, %{})
    decoders = Keyword.get(opts, :decoders, [])

    flows =
      segments
      |> Enum.group_by(& &1.flow_key)
      |> Enum.flat_map(fn {flow_key, flow_segments} ->
        analyze_flow(flow_key, flow_segments, decode_content, hosts_map, decoders)
      end)
      |> Enum.sort_by(fn flow ->
        case flow.exchanges do
          [] -> nil
          [first | _] -> Timestamp.to_unix_nanos(first.start_timestamp)
        end
      end)

    {:ok, flows}
  end

  # Analyze a single TCP flow for HTTP/1.x exchanges
  defp analyze_flow(flow_key, segments, decode_content, hosts_map, decoders) do
    # Sort segments by timestamp
    sorted = Enum.sort_by(segments, & &1.timestamp, DateTime)

    # Separate by direction
    {a_to_b, b_to_a} = Enum.split_with(sorted, &(&1.direction == :a_to_b))

    # Concatenate data per direction
    a_data = Enum.map_join(a_to_b, & &1.data)
    b_data = Enum.map_join(b_to_a, & &1.data)

    # Determine client direction - whoever sends HTTP request first
    a_first_ts = first_timestamp(a_to_b)
    b_first_ts = first_timestamp(b_to_a)
    a_has_request = has_http_request?(a_data)
    b_has_request = has_http_request?(b_data)

    {client_dir, client_data, server_data, client_segments, server_segments} =
      cond do
        # A sends request first
        a_has_request and (not b_has_request or timestamp_before?(a_first_ts, b_first_ts)) ->
          {:a_to_b, a_data, b_data, a_to_b, b_to_a}

        # B sends request first
        b_has_request ->
          {:b_to_a, b_data, a_data, b_to_a, a_to_b}

        # Neither has request - skip this flow
        true ->
          {nil, "", "", [], []}
      end

    if client_dir == nil do
      []
    else
      {client_endpoint, server_endpoint} = determine_endpoints(flow_key, client_dir, hosts_map)

      # Parse requests and responses
      requests = parse_requests(client_data, client_segments, decode_content, decoders)

      responses =
        parse_responses(server_data, server_segments, decode_content, decoders, requests)

      # Pair requests with responses
      exchanges = pair_exchanges(requests, responses)

      if exchanges == [] do
        []
      else
        flow = Flow.new(:http1, client_endpoint, server_endpoint)
        http1_flow = HTTP1.Flow.new(flow)

        http1_flow =
          Enum.reduce(exchanges, http1_flow, fn ex, acc ->
            HTTP1.Flow.add_exchange(acc, ex)
          end)

        [HTTP1.Flow.finalize(http1_flow)]
      end
    end
  end

  defp first_timestamp([]), do: nil
  defp first_timestamp([first | _]), do: first.timestamp

  defp timestamp_before?(nil, _), do: false
  defp timestamp_before?(_, nil), do: true
  defp timestamp_before?(ts1, ts2), do: DateTime.compare(ts1, ts2) == :lt

  defp has_http_request?(data) when byte_size(data) < 4, do: false

  defp has_http_request?(data) do
    Enum.any?(@http_methods, fn method ->
      prefix = method <> " "
      String.starts_with?(data, prefix)
    end)
  end

  defp determine_endpoints({{ep_a_ip, ep_a_port}, {ep_b_ip, ep_b_port}}, client_dir, hosts_map) do
    case client_dir do
      :a_to_b ->
        {Endpoint.from_tuple({ep_a_ip, ep_a_port}, hosts_map),
         Endpoint.from_tuple({ep_b_ip, ep_b_port}, hosts_map)}

      :b_to_a ->
        {Endpoint.from_tuple({ep_b_ip, ep_b_port}, hosts_map),
         Endpoint.from_tuple({ep_a_ip, ep_a_port}, hosts_map)}
    end
  end

  # Parse HTTP/1.x requests from data
  defp parse_requests(data, segments, decode_content, decoders) do
    parse_messages(data, segments, :request, decode_content, decoders, nil, [])
  end

  # Parse HTTP/1.x responses from data (needs requests for context pairing)
  defp parse_responses(data, segments, decode_content, decoders, requests) do
    parse_messages(data, segments, :response, decode_content, decoders, requests, [])
  end

  defp parse_messages("", _segments, _type, _decode, _decoders, _requests, acc),
    do: Enum.reverse(acc)

  defp parse_messages(data, _segments, _type, _decode_content, _decoders, _requests, acc)
       when byte_size(data) < 10 do
    # Not enough data for a message
    Enum.reverse(acc)
  end

  defp parse_messages(data, segments, type, decode_content, decoders, requests, acc) do
    case type do
      :request -> parse_request_message(data, segments, decode_content, decoders, acc)
      :response -> parse_response_message(data, segments, decode_content, decoders, requests, acc)
    end
  end

  defp parse_request_message(data, segments, decode_content, decoders, acc) do
    case parse_request_line(data) do
      {:ok, method, path, version, rest} ->
        case parse_headers(rest) do
          {:ok, headers, body_start} ->
            {body, remaining, _body_size} = extract_body(body_start, headers)
            timestamp = estimate_timestamp(data, segments, byte_size(data) - byte_size(remaining))

            decoded_body =
              if decode_content do
                content_type = Map.get(headers, "content-type")
                # Build context for custom decoders
                ctx = %{
                  protocol: :http1,
                  direction: :request,
                  scope: :body,
                  headers: headers,
                  method: method,
                  path: path
                }

                decode_body(content_type, body, decoders, ctx)
              else
                nil
              end

            request = %{
              method: method,
              path: path,
              version: version,
              headers: headers,
              body: body,
              decoded_body: decoded_body,
              timestamp: timestamp
            }

            parse_messages(remaining, segments, :request, decode_content, decoders, nil, [
              request | acc
            ])

          :incomplete ->
            Enum.reverse(acc)
        end

      :not_found ->
        Enum.reverse(acc)
    end
  end

  defp parse_response_message(data, segments, decode_content, decoders, requests, acc) do
    case parse_status_line(data) do
      {:ok, version, status, reason, rest} ->
        case parse_headers(rest) do
          {:ok, headers, body_start} ->
            {body, remaining, _body_size} = extract_body(body_start, headers)
            timestamp = estimate_timestamp(data, segments, byte_size(data) - byte_size(remaining))

            decoded_body =
              if decode_content do
                content_type = Map.get(headers, "content-type")
                # Get corresponding request for context (if available)
                response_index = length(acc)
                request = if requests, do: Enum.at(requests, response_index)
                # Build context for custom decoders
                ctx = %{
                  protocol: :http1,
                  direction: :response,
                  scope: :body,
                  headers: headers,
                  status: status,
                  method: request && request.method,
                  path: request && request.path
                }

                decode_body(content_type, body, decoders, ctx)
              else
                nil
              end

            response = %{
              status: status,
              reason: reason,
              version: version,
              headers: headers,
              body: body,
              decoded_body: decoded_body,
              timestamp: timestamp
            }

            parse_messages(remaining, segments, :response, decode_content, decoders, requests, [
              response | acc
            ])

          :incomplete ->
            Enum.reverse(acc)
        end

      :not_found ->
        Enum.reverse(acc)
    end
  end

  # Parse "METHOD path HTTP/x.y\r\n"
  defp parse_request_line(data) do
    case :binary.match(data, "\r\n") do
      {pos, _} ->
        line = :binary.part(data, 0, pos)
        rest = :binary.part(data, pos + 2, byte_size(data) - pos - 2)

        case String.split(line, " ", parts: 3) do
          [method, path, "HTTP/" <> version] when method in @http_methods ->
            {:ok, method, path, version, rest}

          _ ->
            :not_found
        end

      :nomatch ->
        :not_found
    end
  end

  # Parse "HTTP/x.y status reason\r\n"
  defp parse_status_line(data) do
    case :binary.match(data, "\r\n") do
      {pos, _} ->
        line = :binary.part(data, 0, pos)
        rest = :binary.part(data, pos + 2, byte_size(data) - pos - 2)

        case parse_status_line_parts(line) do
          {:ok, version, status, reason} ->
            {:ok, version, status, reason, rest}

          :error ->
            :not_found
        end

      :nomatch ->
        :not_found
    end
  end

  defp parse_status_line_parts(
         <<"HTTP/", version::binary-size(3), " ", status::binary-size(3), " ", reason::binary>>
       ) do
    case Integer.parse(status) do
      {status_int, ""} -> {:ok, version, status_int, reason}
      _ -> :error
    end
  end

  defp parse_status_line_parts(<<"HTTP/", version::binary-size(3), " ", status::binary-size(3)>>) do
    case Integer.parse(status) do
      {status_int, ""} -> {:ok, version, status_int, ""}
      _ -> :error
    end
  end

  defp parse_status_line_parts(_), do: :error

  # Parse headers until empty line
  defp parse_headers(data) do
    case :binary.match(data, "\r\n\r\n") do
      {pos, _} ->
        headers_raw = :binary.part(data, 0, pos)
        body_start = :binary.part(data, pos + 4, byte_size(data) - pos - 4)
        headers = parse_header_lines(headers_raw)
        {:ok, headers, body_start}

      :nomatch ->
        :incomplete
    end
  end

  defp parse_header_lines(raw) do
    raw
    |> String.split("\r\n")
    |> Enum.reduce(%{}, fn line, acc ->
      case String.split(line, ":", parts: 2) do
        [name, value] ->
          Map.put(acc, String.downcase(String.trim(name)), String.trim(value))

        _ ->
          acc
      end
    end)
  end

  # Extract body based on Content-Length or chunked encoding
  defp extract_body(data, headers) do
    cond do
      Map.get(headers, "transfer-encoding") == "chunked" ->
        extract_chunked_body(data)

      content_length = Map.get(headers, "content-length") ->
        case Integer.parse(content_length) do
          {len, _} when len > 0 and byte_size(data) >= len ->
            body = :binary.part(data, 0, len)
            remaining = :binary.part(data, len, byte_size(data) - len)
            {body, remaining, len}

          {len, _} when len > 0 ->
            # Not enough data - return what we have
            {data, "", byte_size(data)}

          _ ->
            {"", data, 0}
        end

      true ->
        # No body indication - assume no body for requests
        {"", data, 0}
    end
  end

  # Parse chunked transfer encoding
  defp extract_chunked_body(data) do
    extract_chunks(data, [])
  end

  defp extract_chunks(data, acc) do
    case :binary.match(data, "\r\n") do
      {pos, _} ->
        size_hex = :binary.part(data, 0, pos)
        rest = :binary.part(data, pos + 2, byte_size(data) - pos - 2)

        case parse_chunk_size(size_hex) do
          {:ok, 0} ->
            # End of chunks - skip optional trailers
            body = IO.iodata_to_binary(Enum.reverse(acc))
            remaining = skip_trailers(rest)
            {body, remaining, byte_size(body)}

          {:ok, size} when byte_size(rest) >= size + 2 ->
            chunk = :binary.part(rest, 0, size)
            # Skip chunk data + CRLF
            after_chunk = :binary.part(rest, size + 2, byte_size(rest) - size - 2)
            extract_chunks(after_chunk, [chunk | acc])

          {:ok, _size} ->
            # Incomplete chunk
            body = IO.iodata_to_binary(Enum.reverse(acc))
            {body, "", byte_size(body)}

          :error ->
            body = IO.iodata_to_binary(Enum.reverse(acc))
            {body, data, byte_size(body)}
        end

      :nomatch ->
        body = IO.iodata_to_binary(Enum.reverse(acc))
        {body, data, byte_size(body)}
    end
  end

  defp parse_chunk_size(hex) do
    # Strip chunk extensions (;...)
    hex =
      case :binary.match(hex, ";") do
        {pos, _} -> :binary.part(hex, 0, pos)
        :nomatch -> hex
      end

    hex = String.trim(hex)

    case Integer.parse(hex, 16) do
      {size, ""} -> {:ok, size}
      _ -> :error
    end
  end

  defp skip_trailers(data) do
    case :binary.match(data, "\r\n\r\n") do
      {pos, _} -> :binary.part(data, pos + 4, byte_size(data) - pos - 4)
      :nomatch -> data
    end
  end

  # Estimate timestamp for a message based on byte position
  defp estimate_timestamp(_data, [], _byte_offset), do: Timestamp.new(0, 0)

  defp estimate_timestamp(_data, [first | _], _byte_offset) do
    Timestamp.from_datetime(first.timestamp)
  end

  defp decode_body(nil, body, _decoders, _ctx), do: {:binary, body}

  defp decode_body(content_type, body, decoders, ctx) do
    opts = [decoders: decoders, context: ctx]
    Content.decode(content_type, body, opts)
  end

  # Pair requests with responses (1:1 in HTTP/1.x pipelining order)
  defp pair_exchanges(requests, responses) do
    pair_exchanges(requests, responses, 0, [])
  end

  defp pair_exchanges([], _responses, _seq, acc), do: Enum.reverse(acc)

  defp pair_exchanges([request | rest_requests], responses, flow_seq, acc) do
    exchange = HTTP1.Exchange.new(flow_seq, request)

    {exchange, remaining_responses} =
      case responses do
        [response | rest] ->
          {HTTP1.Exchange.add_response(exchange, response), rest}

        [] ->
          {exchange, []}
      end

    pair_exchanges(rest_requests, remaining_responses, flow_seq + 1, [exchange | acc])
  end
end
