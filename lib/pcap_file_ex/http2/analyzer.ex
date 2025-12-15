defmodule PcapFileEx.HTTP2.Analyzer do
  @moduledoc """
  HTTP/2 stream reconstruction from TCP segments.

  This module implements the core analysis algorithm that:
  1. Buffers TCP segments per direction
  2. Detects client via connection preface or stream semantics
  3. Parses HTTP/2 frames from buffers
  4. Tracks stream state and decodes headers via HPACK
  5. Builds complete and incomplete exchanges

  ## Usage

  The analyzer processes directional TCP segments and produces exchanges:

      segments = [...] # DirectionalSegments from TCP reassembly
      {:ok, complete, incomplete} = Analyzer.analyze(segments)

  ## Mid-Connection Capture Support

  When the connection preface is not captured:
  - Client identification falls back to stream ID semantics
  - SETTINGS frames are deferred until client is identified
  - Some HPACK dynamic table entries may be missing
  """

  alias PcapFileEx.HTTP2.{
    Connection,
    Exchange,
    Frame,
    FrameBuffer,
    Headers,
    IncompleteExchange,
    StreamState
  }

  alias PcapFileEx.HTTP.Content

  @type endpoint :: {tuple(), non_neg_integer()}
  @type direction :: :a_to_b | :b_to_a

  @type directional_segment :: %{
          flow_key: {endpoint(), endpoint()},
          direction: direction(),
          data: binary(),
          timestamp: DateTime.t()
        }

  @type option :: {:decode_content, boolean()}

  @doc """
  Analyze directional TCP segments and extract HTTP/2 exchanges.

  Returns `{:ok, complete_exchanges, incomplete_exchanges}`.

  ## Options

    * `:decode_content` - When `true` (default), automatically decodes request
      and response bodies based on their Content-Type header. Multipart bodies
      are recursively decoded, JSON is parsed, and text is validated as UTF-8.
      When `false`, bodies are left as raw binaries and `decoded_body` is `nil`.
  """
  @spec analyze([directional_segment()], [option()]) ::
          {:ok, [Exchange.t()], [IncompleteExchange.t()]}
  def analyze(segments, opts \\ []) when is_list(segments) do
    decode_content = Keyword.get(opts, :decode_content, true)

    # Process all segments, building connection state
    connections =
      Enum.reduce(segments, %{}, fn segment, connections ->
        process_segment(segment, connections)
      end)

    # Finalize streams and build exchange lists
    {complete, incomplete} =
      connections
      |> Map.values()
      |> Enum.flat_map(&finalize_connection(&1, decode_content))
      |> Enum.split_with(fn
        %Exchange{} -> true
        %IncompleteExchange{} -> false
      end)

    {:ok, complete, incomplete}
  end

  # Process a single TCP segment
  defp process_segment(segment, connections) do
    flow_key = segment.flow_key
    direction = segment.direction

    conn = Map.get(connections, flow_key) || Connection.new(flow_key)

    # Append data to correct directional buffer
    buffer = Connection.select_buffer(conn, direction)
    buffer = FrameBuffer.append(buffer, segment.data, segment.timestamp)

    # Check for preface if client not yet identified
    {conn, buffer} = maybe_check_preface(conn, buffer, direction)

    # Parse all complete frames from buffer
    {conn, buffer} = extract_frames(conn, buffer, direction)

    # Store updated buffer back
    conn = Connection.store_buffer(conn, direction, buffer)

    Map.put(connections, flow_key, conn)
  end

  # Check for connection preface if not yet identified
  defp maybe_check_preface(%Connection{client_identified: true} = conn, buffer, _direction) do
    {conn, buffer}
  end

  defp maybe_check_preface(conn, buffer, direction) do
    case FrameBuffer.check_preface(buffer) do
      {:preface_found, new_buffer} ->
        new_conn = Connection.identify_client_from_preface(conn, direction)
        {new_conn, new_buffer}

      {:no_preface, new_buffer} ->
        {conn, new_buffer}

      {:need_more_data, buffer} ->
        {conn, buffer}
    end
  end

  # Extract all complete frames from buffer
  defp extract_frames(conn, buffer, direction) do
    case FrameBuffer.next_frame(buffer) do
      {:ok, frame, frame_timestamp, new_buffer} ->
        conn = process_frame(conn, frame, direction, frame_timestamp)
        extract_frames(conn, new_buffer, direction)

      {:need_more, buffer} ->
        {conn, buffer}
    end
  end

  # Process a single frame
  defp process_frame(conn, frame, direction, timestamp) do
    # Determine if frame is from client
    is_from_client = determine_frame_direction(conn, frame, direction)

    if Frame.control_frame?(frame) do
      process_control_frame(conn, frame, is_from_client, direction)
    else
      process_stream_frame(conn, frame, direction, is_from_client, timestamp)
    end
  end

  # Determine frame direction (is_from_client)
  defp determine_frame_direction(conn, frame, direction) do
    case Connection.from_client?(conn, direction) do
      is_client when is_boolean(is_client) ->
        is_client

      nil ->
        # Mid-connection capture - infer from stream semantics
        infer_direction(conn, frame, direction)
    end
  end

  # Infer direction from stream semantics for mid-connection captures
  defp infer_direction(conn, frame, direction) do
    # For stream 0 (control frames), check history
    if frame.stream_id == 0 do
      case Map.get(conn.direction_history, direction) do
        :client -> true
        :server -> false
        nil -> nil
      end
    else
      # For non-zero streams, use stream ID parity
      # Odd stream IDs are client-initiated
      is_client_initiated = rem(frame.stream_id, 2) == 1

      case frame.type do
        :headers ->
          stream = Map.get(conn.streams, frame.stream_id)

          if is_client_initiated and (stream == nil or stream.request_headers == nil) do
            # First HEADERS on client-initiated stream = request = from client
            true
          else
            # Response headers from server
            false
          end

        :data ->
          stream = Map.get(conn.streams, frame.stream_id)

          cond do
            stream == nil -> is_client_initiated
            stream.response_headers == nil -> true
            stream.request_complete -> false
            true -> Map.get(conn.direction_history, direction) == :client
          end

        _ ->
          is_client_initiated
      end
    end
  end

  # Process control frames (stream 0)
  defp process_control_frame(conn, frame, is_from_client, direction) do
    case frame.type do
      :settings ->
        if frame.flags.ack do
          # ACK - no action needed
          conn
        else
          if is_from_client == nil do
            # Defer settings until client identified
            Connection.defer_settings(conn, direction, frame)
          else
            process_settings(conn, frame, is_from_client)
          end
        end

      :goaway ->
        process_goaway(conn, frame)

      _ ->
        # PING, WINDOW_UPDATE - ignore for analysis
        conn
    end
  end

  # Process SETTINGS frame
  defp process_settings(conn, frame, is_from_client) do
    parse_settings(frame.payload)
    |> Enum.reduce(conn, fn {id, value}, %Connection{} = acc ->
      case id do
        0x1 ->
          # HEADER_TABLE_SIZE
          Connection.resize_decode_table(acc, is_from_client, value)

        _ ->
          acc
      end
    end)
  end

  defp parse_settings(<<>>), do: []

  defp parse_settings(<<id::16, value::32, rest::binary>>),
    do: [{id, value} | parse_settings(rest)]

  defp parse_settings(_), do: []

  # Process GOAWAY frame
  # RFC 7540 Section 6.8: Last-Stream-ID has reserved high bit that must be masked
  defp process_goaway(conn, frame) do
    <<_reserved::1, last_stream_id::31, _error_code::32, _debug::binary>> = frame.payload
    conn = Connection.set_goaway(conn, last_stream_id)

    # Mark affected streams as terminated
    conn.streams
    |> Enum.filter(fn {stream_id, _} -> stream_id > last_stream_id end)
    |> Enum.reduce(conn, fn {_stream_id, stream}, %Connection{} = acc ->
      updated_stream = StreamState.terminate(stream, {:goaway, last_stream_id})
      Connection.update_stream(acc, updated_stream)
    end)
  end

  # Process stream frames (non-zero stream_id)
  # Returns updated connection with stream and HPACK table changes
  defp process_stream_frame(conn, frame, direction, is_from_client, timestamp) do
    # Maybe infer client direction for mid-connection captures
    conn =
      if not conn.client_identified and is_from_client == true do
        # We've determined this direction is client via stream semantics
        # The direction parameter tells us which direction sent this frame
        Connection.identify_client_from_stream(conn, direction)
      else
        conn
      end

    # Get or create stream state
    {stream, conn} = Connection.get_or_create_stream(conn, frame.stream_id, timestamp)

    # Handle frame by type - all return {stream, conn} to propagate HPACK updates
    {stream, conn} =
      case frame.type do
        :headers ->
          process_headers_frame(conn, stream, frame, is_from_client, timestamp)

        :continuation ->
          process_continuation_frame(conn, stream, frame, is_from_client, timestamp)

        :data ->
          stream = process_data_frame(stream, frame, is_from_client, timestamp)
          {stream, conn}

        :rst_stream ->
          stream = process_rst_stream(stream, frame)
          {stream, conn}

        _ ->
          {stream, conn}
      end

    Connection.update_stream(conn, stream)
  end

  # Process HEADERS frame - returns {stream, conn}
  defp process_headers_frame(conn, stream, frame, is_from_client, timestamp) do
    case Frame.extract_header_block(frame) do
      {:ok, header_block} ->
        end_stream = Frame.end_stream?(frame)

        if Frame.end_headers?(frame) do
          # Complete header block - decode immediately
          decode_and_apply_headers(
            conn,
            stream,
            header_block,
            is_from_client,
            end_stream,
            timestamp
          )
        else
          # Incomplete - start CONTINUATION buffering
          stream =
            StreamState.start_continuation(stream, header_block, end_stream, is_from_client)

          {stream, conn}
        end

      {:error, reason} ->
        stream = StreamState.set_error(stream, {:frame_error, reason})
        {stream, conn}
    end
  end

  # Process CONTINUATION frame - returns {stream, conn}
  defp process_continuation_frame(conn, stream, frame, _is_from_client, timestamp) do
    if stream.awaiting_continuation do
      stream = StreamState.append_continuation(stream, frame.payload)

      if Frame.end_headers?(frame) do
        # Complete the continuation and decode the accumulated header block
        {header_block, end_stream, pending_is_from_client, stream} =
          StreamState.complete_continuation(stream)

        # Now decode the complete header block with proper HPACK state
        decode_and_apply_headers(
          conn,
          stream,
          header_block,
          pending_is_from_client,
          end_stream,
          timestamp
        )
      else
        {stream, conn}
      end
    else
      stream = StreamState.set_error(stream, {:unexpected_continuation, frame.stream_id})
      {stream, conn}
    end
  end

  # Process DATA frame - returns stream only (no HPACK changes)
  defp process_data_frame(stream, frame, is_from_client, timestamp) do
    case Frame.extract_data(frame) do
      {:ok, data} ->
        end_stream = Frame.end_stream?(frame)

        if is_from_client do
          StreamState.append_request_data(stream, data, end_stream, timestamp)
        else
          StreamState.append_response_data(stream, data, end_stream, timestamp)
        end

      {:error, reason} ->
        StreamState.set_error(stream, {:frame_error, reason})
    end
  end

  # Process RST_STREAM frame - returns stream only
  defp process_rst_stream(stream, frame) do
    <<error_code::32>> = frame.payload
    StreamState.terminate(stream, {:rst_stream, error_code})
  end

  # Decode headers and apply to stream - returns {stream, conn} with updated HPACK table
  defp decode_and_apply_headers(conn, stream, header_block, is_from_client, end_stream, timestamp) do
    case Connection.decode_headers(conn, is_from_client, header_block) do
      {:ok, header_list, updated_conn} ->
        headers = Headers.from_list(header_list)
        stream = apply_headers(stream, headers, is_from_client, end_stream, timestamp)
        {stream, updated_conn}

      {:error, reason} ->
        stream =
          stream
          |> StreamState.set_error({:hpack_error, reason})
          |> StreamState.terminate({:hpack_error, reason})

        {stream, conn}
    end
  end

  # Apply decoded headers to stream state
  defp apply_headers(stream, headers, is_from_client, end_stream, timestamp) do
    cond do
      Headers.request?(headers) ->
        StreamState.set_request_headers(stream, headers, end_stream, timestamp)

      Headers.response?(headers) ->
        StreamState.set_response_headers(stream, headers, end_stream, timestamp)

      Headers.trailers?(headers) ->
        if is_from_client do
          StreamState.set_request_trailers(stream, headers, timestamp)
        else
          StreamState.set_response_trailers(stream, headers, timestamp)
        end

      true ->
        stream
    end
  end

  # Finalize a connection - mark truncated streams and build exchanges
  defp finalize_connection(%Connection{} = conn, decode_content) do
    tcp_flow = {conn.client || elem(conn.flow_key, 0), conn.server || elem(conn.flow_key, 1)}

    conn.streams
    |> Map.values()
    |> Enum.map(fn stream ->
      stream = finalize_stream(stream)

      if StreamState.complete?(stream) and not stream.terminated do
        exchange = Exchange.from_stream(stream, tcp_flow)
        if decode_content, do: decode_exchange_content(exchange), else: exchange
      else
        IncompleteExchange.from_stream(stream, tcp_flow)
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  # Decode request and response bodies based on Content-Type
  defp decode_exchange_content(%Exchange{} = exchange) do
    request = decode_body(exchange.request)
    response = decode_body(exchange.response)
    %{exchange | request: request, response: response}
  end

  defp decode_body(%{headers: headers, body: body} = data) do
    content_type = Headers.get(headers, "content-type")
    decoded = Content.decode(content_type, body)
    %{data | decoded_body: decoded}
  end

  # Finalize a stream - set termination reason for truncated streams
  defp finalize_stream(%StreamState{terminated: true} = stream), do: stream

  defp finalize_stream(%StreamState{} = stream) do
    cond do
      stream.awaiting_continuation ->
        StreamState.terminate(stream, :truncated_incomplete_headers)

      stream.request_headers != nil and stream.response_headers == nil ->
        StreamState.terminate(stream, :truncated_no_response)

      not stream.request_complete or not stream.response_complete ->
        StreamState.terminate(stream, :truncated_incomplete_response)

      true ->
        stream
    end
  end
end
