defmodule PcapFileEx.TCP do
  @moduledoc """
  TCP stream helpers built on top of `PcapFileEx.stream/2`.

  The module currently focuses on lightweight HTTP message reassembly by
  concatenating TCP payloads within each direction of a flow until an entire
  HTTP message (headers + optional body) has been collected. It operates on the
  packet order present in the capture and does **not** attempt full TCP
  retransmission or out-of-order handling – it is intended for clean captures
  (e.g. loopback traffic, lab fixtures).
  """

  require Logger

  alias PcapFileEx.{Endpoint, HTTP, Packet}

  @typedoc """
  Directional TCP flow, as observed in the capture.
  """
  @type flow_key :: {Endpoint.t(), Endpoint.t()}

  defmodule HTTPMessage do
    @moduledoc """
    Represents a reassembled HTTP request or response reconstructed from one or
    more TCP packets.
    """

    @enforce_keys [:flow, :src, :dst, :raw, :http, :packets, :start_timestamp, :end_timestamp]
    defstruct [:flow, :src, :dst, :raw, :http, :packets, :start_timestamp, :end_timestamp, :type]

    @type t :: %__MODULE__{
            flow: PcapFileEx.TCP.flow_key(),
            src: Endpoint.t(),
            dst: Endpoint.t(),
            raw: binary(),
            http: HTTP.t(),
            packets: [Packet.t()],
            start_timestamp: DateTime.t(),
            end_timestamp: DateTime.t(),
            type: :request | :response | atom()
          }
  end

  @doc """
  Returns a stream of reassembled HTTP messages (requests and/or responses)
  produced from the given capture or packet enumerable.

  ## Options

    * `:types` - list of HTTP types to emit (`[:request]`, `[:response]`,
      or both). Defaults to `[:request]`.
    * `:max_buffer_bytes` - maximum buffered payload per flow direction
      before the state is discarded. Defaults to `4_000_000` (4 MB).
    * `:filter` - predicate function `fn %HTTPMessage{} -> boolean` used to
      filter emitted messages.
    * `:packet_filter` - predicate `fn %Packet{} -> boolean` to pre-filter
      packets before they reach the reassembler (defaults to accepting any TCP
      packet with payload).

  The function yields a lazy stream; consumers can compose additional filters or
  transformations on top.
  """
  @spec stream_http_messages(Enumerable.t() | Path.t(), keyword()) :: Enumerable.t()
  def stream_http_messages(source, opts \\ []) do
    opts = parse_options(opts)

    source
    |> packet_stream()
    |> Stream.transform(%{}, fn packet, state ->
      process_packet(packet, state, opts)
    end)
    |> maybe_filter_messages(opts)
  end

  @doc """
  Convenience wrapper returning only HTTP requests.
  """
  @spec stream_http_requests(Enumerable.t() | Path.t(), keyword()) :: Enumerable.t()
  def stream_http_requests(source, opts \\ []) do
    opts =
      Keyword.update(opts, :types, [:request], fn types -> ensure_list(types) ++ [:request] end)

    stream_http_messages(source, opts)
  end

  @doc """
  Convenience wrapper returning only HTTP responses.
  """
  @spec stream_http_responses(Enumerable.t() | Path.t(), keyword()) :: Enumerable.t()
  def stream_http_responses(source, opts \\ []) do
    opts =
      Keyword.update(opts, :types, [:response], fn types -> ensure_list(types) ++ [:response] end)

    stream_http_messages(source, opts)
  end

  # -- internal ----------------------------------------------------------------

  defmodule DirectionState do
    @moduledoc false

    defstruct buffer: <<>>, fragments: :queue.new(), src: nil, dst: nil

    @type t :: %__MODULE__{
            buffer: binary(),
            fragments: :queue.queue(),
            src: Endpoint.t() | nil,
            dst: Endpoint.t() | nil
          }

    @spec empty?(t()) :: boolean()
    def empty?(%__MODULE__{buffer: <<>>, fragments: fragments}) do
      :queue.is_empty(fragments)
    end

    def empty?(_), do: false
  end

  @typep options :: %{
           max_buffer_bytes: pos_integer(),
           types: :all | MapSet.t(),
           filter: (HTTPMessage.t() -> boolean()) | nil,
           packet_filter: (Packet.t() -> boolean())
         }

  @spec packet_stream(Enumerable.t() | Path.t()) :: Enumerable.t()
  defp packet_stream(path) when is_binary(path) do
    PcapFileEx.stream(path, decode: false)
  end

  defp packet_stream(enum), do: enum

  @spec process_packet(Packet.t(), map(), options()) :: {[HTTPMessage.t()], map()}
  defp process_packet(%Packet{} = packet, state, opts) do
    cond do
      not tcp_packet?(packet) ->
        {[], state}

      is_function(opts.packet_filter) and not opts.packet_filter.(packet) ->
        {[], state}

      not endpoints_with_ports?(packet) ->
        {[], state}

      true ->
        payload = packet.payload || <<>>

        if payload == <<>> do
          {[], state}
        else
          key = flow_key(packet)

          direction_state =
            state
            |> Map.get(key, %DirectionState{src: packet.src, dst: packet.dst})

          {messages, updated_state} =
            add_payload(direction_state, packet, payload, opts)

          state =
            if DirectionState.empty?(updated_state) do
              Map.delete(state, key)
            else
              Map.put(state, key, updated_state)
            end

          {messages, state}
        end
    end
  end

  defp tcp_packet?(%Packet{protocols: protocols}) when is_list(protocols) do
    Enum.any?(protocols, &(&1 == :tcp))
  end

  defp tcp_packet?(_), do: false

  @dialyzer {:nowarn_function, add_payload: 4}
  @spec add_payload(DirectionState.t(), Packet.t(), binary(), options()) ::
          {[HTTPMessage.t()], DirectionState.t()}
  defp add_payload(%DirectionState{} = state, packet, payload, opts) do
    fragments = :queue.in({packet, payload}, state.fragments)
    buffer = state.buffer <> payload

    if byte_size(buffer) > opts.max_buffer_bytes do
      Logger.warning(
        "tcp.reassembly buffer exceeded max size for flow #{flow_label(state.src, state.dst)} " <>
          "(#{byte_size(buffer)} bytes > #{opts.max_buffer_bytes}); dropping buffered data"
      )

      {[], %DirectionState{src: state.src, dst: state.dst}}
    else
      extract_http_messages(buffer, fragments, state.src, state.dst, opts, [])
    end
  end

  defp extract_http_messages(buffer, fragments, src, dst, opts, acc) do
    case next_http_frame(buffer) do
      {:ok, message_len} ->
        <<message_binary::binary-size(message_len), remaining::binary>> = buffer
        {consumed, remaining_fragments} = consume_fragments(fragments, message_len)

        case HTTP.decode(message_binary) do
          {:ok, http} ->
            message = build_message(src, dst, consumed, message_binary, http)

            extract_http_messages(
              remaining,
              remaining_fragments,
              src,
              dst,
              opts,
              [message | acc]
            )

          {:error, reason} ->
            Logger.warning(
              "tcp.reassembly failed to decode HTTP message for #{flow_label(src, dst)}: #{inspect(reason)}"
            )

            {Enum.reverse(acc), %DirectionState{src: src, dst: dst}}
        end

      :need_more ->
        {Enum.reverse(acc),
         %DirectionState{buffer: buffer, fragments: fragments, src: src, dst: dst}}

      {:error, reason} ->
        Logger.warning(
          "tcp.reassembly encountered malformed HTTP data for #{flow_label(src, dst)}: #{reason}; clearing buffer"
        )

        {Enum.reverse(acc), %DirectionState{src: src, dst: dst}}
    end
  end

  defp build_message(src, dst, consumed, raw, http) do
    packets = consumed |> Enum.map(& &1.packet) |> Enum.uniq()

    %HTTPMessage{
      flow: {src, dst},
      src: src,
      dst: dst,
      raw: raw,
      http: http,
      packets: packets,
      start_timestamp: consumed |> hd() |> Map.fetch!(:packet) |> Map.fetch!(:timestamp),
      end_timestamp: consumed |> List.last() |> Map.fetch!(:packet) |> Map.fetch!(:timestamp),
      type: http.type
    }
  end

  defp next_http_frame(buffer) when byte_size(buffer) == 0, do: :need_more

  defp next_http_frame(buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      :nomatch ->
        :need_more

      {header_end, 4} ->
        headers_bin = :binary.part(buffer, 0, header_end)
        header_lines = headers_bin |> to_header_lines()

        content_length =
          header_lines
          |> Enum.reduce_while(nil, fn line, acc ->
            case String.split(line, ":", parts: 2) do
              [name, value] ->
                if String.downcase(String.trim(name)) == "content-length" do
                  case Integer.parse(String.trim(value)) do
                    {len, _} -> {:halt, len}
                    :error -> {:halt, :invalid}
                  end
                else
                  {:cont, acc}
                end

              _ ->
                {:cont, acc}
            end
          end)

        body_offset = header_end + 4

        case content_length do
          :invalid ->
            {:error, "invalid content-length header"}

          nil ->
            {:ok, body_offset}

          len when is_integer(len) and len >= 0 ->
            if byte_size(buffer) >= body_offset + len do
              {:ok, body_offset + len}
            else
              :need_more
            end
        end
    end
  end

  defp to_header_lines(binary) do
    binary
    |> :binary.copy()
    |> String.split("\r\n", trim: true)
  end

  defp consume_fragments(queue, bytes_to_consume) do
    do_consume(queue, bytes_to_consume, [])
  end

  defp do_consume(queue, 0, acc), do: {Enum.reverse(acc), queue}

  defp do_consume(queue, bytes_left, acc) do
    case :queue.out(queue) do
      {:empty, _} ->
        {Enum.reverse(acc), queue}

      {{:value, {packet, chunk}}, rest} ->
        chunk_size = byte_size(chunk)

        cond do
          chunk_size < bytes_left ->
            do_consume(rest, bytes_left - chunk_size, [%{packet: packet, data: chunk} | acc])

          chunk_size == bytes_left ->
            do_consume(rest, 0, [%{packet: packet, data: chunk} | acc])

          chunk_size > bytes_left ->
            <<needed::binary-size(bytes_left), leftover::binary>> = chunk
            rest = :queue.in_r({packet, leftover}, rest)
            do_consume(rest, 0, [%{packet: packet, data: needed} | acc])
        end
    end
  end

  defp maybe_filter_messages(stream, %{types: :all, filter: nil}), do: stream

  defp maybe_filter_messages(stream, %{types: types, filter: filter_fun}) do
    Stream.filter(stream, fn message ->
      cond do
        message.http == nil ->
          false

        not allow_type?(types, message.type) ->
          false

        is_function(filter_fun) ->
          filter_fun.(message)

        true ->
          true
      end
    end)
  end

  defp allow_type?(:all, _type), do: true
  defp allow_type?(%MapSet{} = set, type), do: MapSet.member?(set, type)

  defp parse_options(opts) do
    %{
      max_buffer_bytes: Keyword.get(opts, :max_buffer_bytes, 4_000_000),
      types: opts |> Keyword.get(:types, [:request]) |> normalize_types(),
      filter: Keyword.get(opts, :filter),
      packet_filter: Keyword.get(opts, :packet_filter)
    }
  end

  defp normalize_types(:all), do: :all

  defp normalize_types(types) do
    types
    |> ensure_list()
    |> Enum.map(&normalize_type_atom/1)
    |> MapSet.new()
  end

  defp normalize_type_atom(type) when type in [:request, :response], do: type
  defp normalize_type_atom(other), do: other

  defp ensure_list(value) when is_list(value), do: value
  defp ensure_list(value), do: [value]

  defp flow_key(%Packet{src: %Endpoint{} = src, dst: %Endpoint{} = dst}) do
    {src, dst}
  end

  defp flow_key(packet) do
    raise ArgumentError,
          "Cannot determine endpoints for packet; expected endpoints with ports, got: #{inspect(packet)}"
  end

  defp flow_label(nil, nil), do: "unknown"

  defp flow_label(%Endpoint{} = src, %Endpoint{} = dst) do
    "#{Endpoint.to_string(src)} -> #{Endpoint.to_string(dst)}"
  end

  defp endpoints_with_ports?(%Packet{src: %Endpoint{port: port1}, dst: %Endpoint{port: port2}})
       when is_integer(port1) and is_integer(port2),
       do: true

  defp endpoints_with_ports?(_), do: false
end
