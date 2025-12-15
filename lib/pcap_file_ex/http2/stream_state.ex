defmodule PcapFileEx.HTTP2.StreamState do
  @moduledoc """
  Per-stream state for HTTP/2 stream reconstruction.

  Tracks request and response data including headers, body, and trailers.
  Handles CONTINUATION frame buffering for split header blocks.

  ## Stream Lifecycle

  1. Created when first frame for stream ID is seen
  2. Receives HEADERS (possibly with CONTINUATION frames)
  3. May receive DATA frames
  4. May receive trailing HEADERS (trailers)
  5. Completes when both request and response have END_STREAM
  6. May be terminated early by RST_STREAM/GOAWAY

  ## CONTINUATION Handling

  When a HEADERS frame has END_HEADERS=false, subsequent CONTINUATION
  frames are buffered until END_HEADERS=true. During this time:
  - `awaiting_continuation` is true
  - `pending_header_block` accumulates the header block fragments
  - `pending_end_stream` tracks if the initial HEADERS had END_STREAM
  - `pending_direction` tracks who sent the initial HEADERS

  ## Timestamps

  - `created_at`: When first frame for this stream was seen
  - `completed_at`: When BOTH request_complete AND response_complete became true
  """

  alias PcapFileEx.HTTP2.Headers

  # Protocol-level termination
  @type termination_reason ::
          {:rst_stream, non_neg_integer()}
          | {:goaway, non_neg_integer()}
          # PCAP truncation
          | :truncated_no_response
          | :truncated_incomplete_response
          | :truncated_incomplete_headers
          # TCP-level issues
          | :tcp_fin_without_end_stream
          # Decode errors
          | {:hpack_error, term()}
          | {:frame_error, term()}

  @type t :: %__MODULE__{
          stream_id: non_neg_integer(),

          # Request
          request_headers: Headers.t() | nil,
          request_trailers: Headers.t() | nil,
          request_body: iodata(),
          request_complete: boolean(),

          # Response
          response_headers: Headers.t() | nil,
          response_trailers: Headers.t() | nil,
          response_body: iodata(),
          response_complete: boolean(),
          informational_responses: [Headers.t()],

          # State
          terminated: boolean(),
          termination_reason: termination_reason() | nil,
          error: term() | nil,

          # CONTINUATION handling
          awaiting_continuation: boolean(),
          pending_header_block: binary(),
          pending_end_stream: boolean(),
          pending_direction: boolean() | nil,

          # Timestamps
          created_at: DateTime.t(),
          completed_at: DateTime.t() | nil
        }

  defstruct [
    :stream_id,
    :created_at,
    request_headers: nil,
    request_trailers: nil,
    request_body: [],
    request_complete: false,
    response_headers: nil,
    response_trailers: nil,
    response_body: [],
    response_complete: false,
    informational_responses: [],
    terminated: false,
    termination_reason: nil,
    error: nil,
    awaiting_continuation: false,
    pending_header_block: <<>>,
    pending_end_stream: false,
    pending_direction: nil,
    completed_at: nil
  ]

  @doc """
  Create a new stream state.
  """
  @spec new(non_neg_integer(), DateTime.t()) :: t()
  def new(stream_id, timestamp) do
    %__MODULE__{
      stream_id: stream_id,
      created_at: timestamp
    }
  end

  @doc """
  Start buffering a header block that spans multiple frames.

  Called when HEADERS frame has END_HEADERS=false.
  """
  @spec start_continuation(t(), binary(), boolean(), boolean()) :: t()
  def start_continuation(%__MODULE__{} = stream, header_block, end_stream, is_from_client) do
    %__MODULE__{
      stream
      | awaiting_continuation: true,
        pending_header_block: header_block,
        pending_end_stream: end_stream,
        pending_direction: is_from_client
    }
  end

  @doc """
  Append a CONTINUATION frame's payload to the pending header block.
  """
  @spec append_continuation(t(), binary()) :: t()
  def append_continuation(%__MODULE__{pending_header_block: pending} = stream, payload) do
    %__MODULE__{stream | pending_header_block: pending <> payload}
  end

  @doc """
  Complete the header block and clear continuation state.

  Returns the complete header block and updated stream.
  """
  @spec complete_continuation(t()) :: {binary(), boolean(), boolean() | nil, t()}
  def complete_continuation(%__MODULE__{} = stream) do
    header_block = stream.pending_header_block
    end_stream = stream.pending_end_stream
    is_from_client = stream.pending_direction

    updated = %__MODULE__{
      stream
      | awaiting_continuation: false,
        pending_header_block: <<>>,
        pending_end_stream: false,
        pending_direction: nil
    }

    {header_block, end_stream, is_from_client, updated}
  end

  @doc """
  Set request headers (from initial HEADERS frame with :method).
  """
  @spec set_request_headers(t(), Headers.t(), boolean(), DateTime.t()) :: t()
  def set_request_headers(%__MODULE__{} = stream, headers, end_stream, timestamp) do
    stream = %__MODULE__{stream | request_headers: headers}

    if end_stream do
      mark_request_complete(stream, timestamp)
    else
      stream
    end
  end

  @doc """
  Set response headers (from HEADERS frame with :status).

  Handles both informational (1xx) and final responses.
  """
  @spec set_response_headers(t(), Headers.t(), boolean(), DateTime.t()) :: t()
  def set_response_headers(%__MODULE__{} = stream, headers, end_stream, timestamp) do
    if Headers.informational?(headers) do
      # 1xx responses are stored separately, don't mark complete
      %__MODULE__{
        stream
        | informational_responses: stream.informational_responses ++ [headers]
      }
    else
      stream = %__MODULE__{stream | response_headers: headers}

      if end_stream do
        mark_response_complete(stream, timestamp)
      else
        stream
      end
    end
  end

  @doc """
  Set request trailers (HEADERS with no pseudo-headers, from client).
  """
  @spec set_request_trailers(t(), Headers.t(), DateTime.t()) :: t()
  def set_request_trailers(%__MODULE__{} = stream, headers, timestamp) do
    stream = %__MODULE__{stream | request_trailers: headers}
    mark_request_complete(stream, timestamp)
  end

  @doc """
  Set response trailers (HEADERS with no pseudo-headers, from server).
  """
  @spec set_response_trailers(t(), Headers.t(), DateTime.t()) :: t()
  def set_response_trailers(%__MODULE__{} = stream, headers, timestamp) do
    stream = %__MODULE__{stream | response_trailers: headers}
    mark_response_complete(stream, timestamp)
  end

  @doc """
  Append data to request body.
  """
  @spec append_request_data(t(), binary(), boolean(), DateTime.t()) :: t()
  def append_request_data(%__MODULE__{request_body: body} = stream, data, end_stream, timestamp) do
    stream = %__MODULE__{stream | request_body: body ++ [data]}

    if end_stream do
      mark_request_complete(stream, timestamp)
    else
      stream
    end
  end

  @doc """
  Append data to response body.
  """
  @spec append_response_data(t(), binary(), boolean(), DateTime.t()) :: t()
  def append_response_data(%__MODULE__{response_body: body} = stream, data, end_stream, timestamp) do
    stream = %__MODULE__{stream | response_body: body ++ [data]}

    if end_stream do
      mark_response_complete(stream, timestamp)
    else
      stream
    end
  end

  @doc """
  Mark stream as terminated with a reason.
  """
  @spec terminate(t(), termination_reason()) :: t()
  def terminate(%__MODULE__{} = stream, reason) do
    %__MODULE__{
      stream
      | terminated: true,
        termination_reason: reason
    }
  end

  @doc """
  Record an error on the stream.
  """
  @spec set_error(t(), term()) :: t()
  def set_error(%__MODULE__{} = stream, error) do
    %__MODULE__{stream | error: error}
  end

  @doc """
  Check if stream is complete (both request and response finished).
  """
  @spec complete?(t()) :: boolean()
  def complete?(%__MODULE__{request_complete: req, response_complete: resp}) do
    req and resp
  end

  @doc """
  Get the complete request body as a binary.
  """
  @spec request_body_binary(t()) :: binary()
  def request_body_binary(%__MODULE__{request_body: body}) do
    IO.iodata_to_binary(body)
  end

  @doc """
  Get the complete response body as a binary.
  """
  @spec response_body_binary(t()) :: binary()
  def response_body_binary(%__MODULE__{response_body: body}) do
    IO.iodata_to_binary(body)
  end

  # Private helpers

  defp mark_request_complete(%__MODULE__{} = stream, timestamp) do
    stream = %__MODULE__{stream | request_complete: true}
    maybe_set_completed_at(stream, timestamp)
  end

  defp mark_response_complete(%__MODULE__{} = stream, timestamp) do
    stream = %__MODULE__{stream | response_complete: true}
    maybe_set_completed_at(stream, timestamp)
  end

  defp maybe_set_completed_at(%__MODULE__{completed_at: nil} = stream, timestamp) do
    if stream.request_complete and stream.response_complete do
      %__MODULE__{stream | completed_at: timestamp}
    else
      stream
    end
  end

  defp maybe_set_completed_at(stream, _timestamp), do: stream
end
