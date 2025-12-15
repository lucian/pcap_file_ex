defmodule PcapFileEx.HTTP2.Connection do
  @moduledoc """
  State for an HTTP/2 connection.

  Maintains dual frame buffers (one per direction) and dual HPACK tables.
  Direction is tracked from TCP reassembly, not inferred per-frame.

  ## Direction Tracking

  TCP flows have two directions: A→B and B→A. Before client identification,
  these are tracked as `:a_to_b` and `:b_to_a`. After the client is identified
  (via connection preface or stream semantics), these map to client/server.

  ## HPACK Tables

  Each HTTP/2 connection has two independent HPACK decode contexts:
  - `server_decode_table`: Decodes headers sent by client (requests)
  - `client_decode_table`: Decodes headers sent by server (responses)

  ## Mid-Connection Capture Support

  When capturing mid-connection (no preface seen):
  1. Direction is inferred from stream ID semantics (odd = client-initiated)
  2. SETTINGS frames are deferred until direction is determined
  3. Some HPACK dynamic table entries may be missing
  """

  alias PcapFileEx.HTTP2.{Frame, FrameBuffer, StreamState}

  @type endpoint :: {tuple(), non_neg_integer()}
  @type direction :: :a_to_b | :b_to_a

  @type t :: %__MODULE__{
          # Flow identification
          flow_key: {endpoint(), endpoint()},

          # Endpoints (identified after preface or stream semantics)
          client: endpoint() | nil,
          server: endpoint() | nil,
          client_identified: boolean(),
          identified_via: :preface | :stream_semantics | nil,

          # Direction tracking for mid-connection captures
          direction_history: %{direction() => :client | :server},
          deferred_settings: [{direction(), Frame.t()}],

          # Streams
          streams: %{non_neg_integer() => StreamState.t()},

          # HPACK decode tables (separate per direction)
          # server_decode_table: decodes client→server headers (requests)
          # client_decode_table: decodes server→client headers (responses)
          server_decode_table: HPAX.Table.t(),
          client_decode_table: HPAX.Table.t(),

          # Dual frame buffers (one per direction)
          a_to_b_buffer: FrameBuffer.t(),
          b_to_a_buffer: FrameBuffer.t(),

          # Settings (optional, for validation)
          client_max_header_list_size: non_neg_integer() | nil,
          server_max_header_list_size: non_neg_integer() | nil,

          # Connection state
          goaway_received: boolean(),
          last_good_stream_id: non_neg_integer() | nil
        }

  @default_header_table_size 4096

  defstruct [
    :flow_key,
    client: nil,
    server: nil,
    client_identified: false,
    identified_via: nil,
    direction_history: %{},
    deferred_settings: [],
    streams: %{},
    server_decode_table: nil,
    client_decode_table: nil,
    a_to_b_buffer: nil,
    b_to_a_buffer: nil,
    client_max_header_list_size: nil,
    server_max_header_list_size: nil,
    goaway_received: false,
    last_good_stream_id: nil
  ]

  @doc """
  Create a new connection state for a TCP flow.

  The flow_key should be normalized (e.g., endpoints sorted consistently).
  """
  @spec new({endpoint(), endpoint()}) :: t()
  def new(flow_key) do
    %__MODULE__{
      flow_key: flow_key,
      server_decode_table: HPAX.new(@default_header_table_size),
      client_decode_table: HPAX.new(@default_header_table_size),
      a_to_b_buffer: FrameBuffer.new(),
      b_to_a_buffer: FrameBuffer.new()
    }
  end

  @doc """
  Select frame buffer based on segment direction.
  """
  @spec select_buffer(t(), direction()) :: FrameBuffer.t()
  def select_buffer(%__MODULE__{a_to_b_buffer: buffer}, :a_to_b), do: buffer
  def select_buffer(%__MODULE__{b_to_a_buffer: buffer}, :b_to_a), do: buffer

  @doc """
  Store updated buffer back into connection.
  """
  @spec store_buffer(t(), direction(), FrameBuffer.t()) :: t()
  def store_buffer(%__MODULE__{} = conn, :a_to_b, buffer) do
    %__MODULE__{conn | a_to_b_buffer: buffer}
  end

  def store_buffer(%__MODULE__{} = conn, :b_to_a, buffer) do
    %__MODULE__{conn | b_to_a_buffer: buffer}
  end

  @doc """
  Check if direction maps to client after identification.

  Returns:
  - `true` - Direction is from client
  - `false` - Direction is from server
  - `nil` - Direction unknown (client not yet identified)
  """
  @spec from_client?(t(), direction()) :: boolean() | nil
  def from_client?(
        %__MODULE__{client_identified: false, direction_history: history},
        direction
      ) do
    case Map.get(history, direction) do
      :client -> true
      :server -> false
      nil -> nil
    end
  end

  def from_client?(%__MODULE__{client_identified: true} = conn, direction) do
    direction == direction_for_endpoint(conn, conn.client)
  end

  @doc """
  Get the segment direction for a given endpoint.
  """
  @spec direction_for_endpoint(t(), endpoint()) :: direction()
  def direction_for_endpoint(%__MODULE__{flow_key: {endpoint_a, _endpoint_b}}, endpoint) do
    if endpoint == endpoint_a, do: :a_to_b, else: :b_to_a
  end

  @doc """
  Get the endpoint for a given direction and role.
  """
  @spec endpoint_for_direction(t(), direction(), :sender | :receiver) :: endpoint()
  def endpoint_for_direction(%__MODULE__{flow_key: {endpoint_a, _endpoint_b}}, :a_to_b, :sender) do
    endpoint_a
  end

  def endpoint_for_direction(%__MODULE__{flow_key: {_endpoint_a, endpoint_b}}, :a_to_b, :receiver) do
    endpoint_b
  end

  def endpoint_for_direction(%__MODULE__{flow_key: {_endpoint_a, endpoint_b}}, :b_to_a, :sender) do
    endpoint_b
  end

  def endpoint_for_direction(%__MODULE__{flow_key: {endpoint_a, _endpoint_b}}, :b_to_a, :receiver) do
    endpoint_a
  end

  @doc """
  Get the opposite direction.
  """
  @spec opposite_direction(direction()) :: direction()
  def opposite_direction(:a_to_b), do: :b_to_a
  def opposite_direction(:b_to_a), do: :a_to_b

  @doc """
  Set client identification from preface detection.
  """
  @spec identify_client_from_preface(t(), direction()) :: t()
  def identify_client_from_preface(%__MODULE__{} = conn, client_direction) do
    %__MODULE__{
      conn
      | client: endpoint_for_direction(conn, client_direction, :sender),
        server: endpoint_for_direction(conn, client_direction, :receiver),
        client_identified: true,
        identified_via: :preface,
        direction_history:
          Map.merge(conn.direction_history, %{
            client_direction => :client,
            opposite_direction(client_direction) => :server
          })
    }
  end

  @doc """
  Set client identification from stream semantics (mid-connection capture).
  """
  @spec identify_client_from_stream(t(), direction()) :: t()
  def identify_client_from_stream(%__MODULE__{client_identified: true} = conn, _direction) do
    # Already identified, just update history
    conn
  end

  def identify_client_from_stream(%__MODULE__{} = conn, client_direction) do
    conn = %__MODULE__{
      conn
      | client: endpoint_for_direction(conn, client_direction, :sender),
        server: endpoint_for_direction(conn, client_direction, :receiver),
        client_identified: true,
        identified_via: :stream_semantics,
        direction_history:
          Map.merge(conn.direction_history, %{
            client_direction => :client,
            opposite_direction(client_direction) => :server
          })
    }

    # Replay deferred settings now that we know directions
    replay_deferred_settings(conn)
  end

  @doc """
  Add a SETTINGS frame to deferred list (for mid-connection captures).
  """
  @spec defer_settings(t(), direction(), Frame.t()) :: t()
  def defer_settings(%__MODULE__{deferred_settings: deferred} = conn, direction, frame) do
    %__MODULE__{conn | deferred_settings: deferred ++ [{direction, frame}]}
  end

  @doc """
  Decode headers using correct table based on sender direction.

  Returns {:ok, headers_list, updated_conn} or {:error, reason}.
  """
  @spec decode_headers(t(), boolean(), binary()) ::
          {:ok, [{binary(), binary()}], t()} | {:error, term()}
  def decode_headers(%__MODULE__{} = conn, is_from_client, header_block) do
    # Select the decode table based on who sent the headers
    # Client sends → we decode with server_decode_table
    # Server sends → we decode with client_decode_table
    {table, table_key} =
      if is_from_client do
        {conn.server_decode_table, :server_decode_table}
      else
        {conn.client_decode_table, :client_decode_table}
      end

    case HPAX.decode(header_block, table) do
      {:ok, headers, new_table} ->
        updated_conn = Map.put(conn, table_key, new_table)
        {:ok, headers, updated_conn}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Resize HPACK decode table based on SETTINGS frame.

  When an endpoint sends SETTINGS with HEADER_TABLE_SIZE:
  - If from client: resize client_decode_table (for server→client headers)
  - If from server: resize server_decode_table (for client→server headers)
  """
  @spec resize_decode_table(t(), boolean(), non_neg_integer()) :: t()
  def resize_decode_table(%__MODULE__{} = conn, is_from_client, max_size) do
    if is_from_client do
      %__MODULE__{conn | client_decode_table: HPAX.resize(conn.client_decode_table, max_size)}
    else
      %__MODULE__{conn | server_decode_table: HPAX.resize(conn.server_decode_table, max_size)}
    end
  end

  @doc """
  Get or create stream state for a stream ID.
  """
  @spec get_or_create_stream(t(), non_neg_integer(), DateTime.t()) :: {StreamState.t(), t()}
  def get_or_create_stream(%__MODULE__{streams: streams} = conn, stream_id, timestamp) do
    case Map.get(streams, stream_id) do
      nil ->
        stream = StreamState.new(stream_id, timestamp)
        {stream, %__MODULE__{conn | streams: Map.put(streams, stream_id, stream)}}

      stream ->
        {stream, conn}
    end
  end

  @doc """
  Update a stream in the connection.
  """
  @spec update_stream(t(), StreamState.t()) :: t()
  def update_stream(%__MODULE__{streams: streams} = conn, %StreamState{stream_id: id} = stream) do
    %__MODULE__{conn | streams: Map.put(streams, id, stream)}
  end

  @doc """
  Mark connection as having received GOAWAY.
  """
  @spec set_goaway(t(), non_neg_integer()) :: t()
  def set_goaway(%__MODULE__{} = conn, last_stream_id) do
    %__MODULE__{
      conn
      | goaway_received: true,
        last_good_stream_id: last_stream_id
    }
  end

  # Private helpers

  defp replay_deferred_settings(%__MODULE__{deferred_settings: []} = conn), do: conn

  defp replay_deferred_settings(%__MODULE__{deferred_settings: deferred} = conn) do
    %__MODULE__{} =
      conn =
      Enum.reduce(deferred, conn, fn {direction, frame}, %__MODULE__{} = acc ->
        is_from_client = Map.get(acc.direction_history, direction) == :client
        process_settings_frame(acc, frame, is_from_client)
      end)

    %__MODULE__{conn | deferred_settings: []}
  end

  defp process_settings_frame(%__MODULE__{} = conn, %Frame{payload: payload}, is_from_client) do
    # Parse settings payload (6 bytes per setting: 2-byte id + 4-byte value)
    parse_settings(payload)
    |> Enum.reduce(conn, fn {id, value}, %__MODULE__{} = acc ->
      case id do
        0x1 ->
          # HEADER_TABLE_SIZE
          resize_decode_table(acc, is_from_client, value)

        0x6 ->
          # MAX_HEADER_LIST_SIZE
          if is_from_client do
            %__MODULE__{acc | client_max_header_list_size: value}
          else
            %__MODULE__{acc | server_max_header_list_size: value}
          end

        _ ->
          # Other settings not critical for passive analysis
          acc
      end
    end)
  end

  defp parse_settings(<<>>), do: []

  defp parse_settings(<<id::16, value::32, rest::binary>>) do
    [{id, value} | parse_settings(rest)]
  end

  defp parse_settings(_), do: []
end
