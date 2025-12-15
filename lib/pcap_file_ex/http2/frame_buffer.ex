defmodule PcapFileEx.HTTP2.FrameBuffer do
  @moduledoc """
  Accumulates TCP payload bytes and extracts complete HTTP/2 frames.
  Handles cross-packet frame reassembly and connection preface detection.

  IMPORTANT: This module owns ALL preface detection logic. The analyzer
  should not duplicate preface checks - just call check_preface/1.

  ## Timestamp Tracking

  Each appended chunk carries a timestamp. When a frame is extracted,
  the timestamp returned is the time when the FIRST byte of that frame
  was received (not when the frame became complete). This provides
  accurate timing even for frames spanning multiple TCP segments.

  ## Buffer Mutation Invariants

  The buffer can ONLY be mutated through these three operations:

  1. `append/3` - Adds bytes to end, records timestamp at new offset
  2. `check_preface/1` - May strip 24 bytes from start (shifts timestamp_index)
  3. `next_frame/1` - Removes frame bytes from start (shifts timestamp_index)

  All operations that remove bytes from the buffer start MUST call
  `shift_timestamp_index/2` to maintain alignment between `buffer` and
  `timestamp_index`. Direct manipulation of the buffer binary or
  timestamp_index outside these functions is NOT allowed.

  Error paths that encounter malformed data should either:
  - Return the buffer unchanged (let caller decide how to proceed)
  - Skip a known number of bytes using the same shift mechanism

  There is no "drop arbitrary bytes" operation - the buffer is consumed
  strictly from the front via check_preface and next_frame.
  """

  alias PcapFileEx.HTTP2.Frame

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @preface_length 24
  @frame_header_size 9

  @type preface_result :: :preface_found | :no_preface | :need_more_data

  @type t :: %__MODULE__{
          buffer: binary(),
          timestamp_index: [{non_neg_integer(), DateTime.t()}],
          preface_checked: boolean(),
          preface_found: boolean()
        }

  defstruct buffer: <<>>, timestamp_index: [], preface_checked: false, preface_found: false

  @doc """
  Create a new empty frame buffer.
  """
  @spec new() :: t()
  def new do
    %__MODULE__{}
  end

  @doc """
  Append data to the buffer with a timestamp.

  The timestamp is recorded at the current buffer offset, allowing
  accurate timing for frames that span multiple TCP segments.
  """
  @spec append(t(), binary(), DateTime.t()) :: t()
  def append(%__MODULE__{buffer: buffer, timestamp_index: index} = fb, data, timestamp) do
    start_offset = byte_size(buffer)

    %__MODULE__{
      fb
      | buffer: buffer <> data,
        timestamp_index: index ++ [{start_offset, timestamp}]
    }
  end

  @doc """
  Check for connection preface at start of buffer.

  Returns:
  - `{:preface_found, updated_buffer}` - Preface detected and stripped
  - `{:no_preface, buffer}` - Buffer doesn't start with preface (mid-connection or not HTTP/2)
  - `{:need_more_data, buffer}` - Buffer has < 24 bytes, can't determine yet

  This function is idempotent - once preface is checked, subsequent calls
  return the cached result.

  INVARIANT: check_preface is only called to check offset 0.
  The preface is always exactly 24 bytes ("PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n").
  We only strip when buffer has ≥24 bytes AND first 24 bytes match preface exactly.
  """
  @spec check_preface(t()) :: {preface_result(), t()}
  def check_preface(%__MODULE__{preface_checked: true, preface_found: true} = fb) do
    {:preface_found, fb}
  end

  def check_preface(%__MODULE__{preface_checked: true, preface_found: false} = fb) do
    {:no_preface, fb}
  end

  def check_preface(%__MODULE__{buffer: buffer} = fb) when byte_size(buffer) < @preface_length do
    {:need_more_data, fb}
  end

  def check_preface(%__MODULE__{buffer: buffer, timestamp_index: index} = fb) do
    <<first_24::binary-size(@preface_length), remaining::binary>> = buffer

    if first_24 == @connection_preface do
      # Strip exactly 24 bytes from buffer and shift index by exactly 24
      updated_index = shift_timestamp_index(index, @preface_length)

      updated_fb = %__MODULE__{
        fb
        | buffer: remaining,
          timestamp_index: updated_index,
          preface_checked: true,
          preface_found: true
      }

      {:preface_found, updated_fb}
    else
      # Not HTTP/2 or mid-connection capture (preface already passed)
      updated_fb = %__MODULE__{fb | preface_checked: true, preface_found: false}
      {:no_preface, updated_fb}
    end
  end

  @doc """
  Check if buffer contains a complete frame (9-byte header + payload).
  """
  @spec has_complete_frame?(t()) :: boolean()
  def has_complete_frame?(%__MODULE__{buffer: buffer})
      when byte_size(buffer) < @frame_header_size do
    false
  end

  def has_complete_frame?(%__MODULE__{buffer: buffer}) do
    <<length::24, _rest::binary>> = buffer
    byte_size(buffer) >= @frame_header_size + length
  end

  @doc """
  Parse and return next complete frame from buffer.

  Returns:
  - `{:ok, frame, timestamp, updated_buffer}` - Successfully parsed frame with timestamp
  - `{:need_more, buffer}` - Incomplete frame, need more data
  - `{:error, reason, buffer}` - Malformed frame

  The timestamp is the time when the FIRST byte of the frame was received,
  looked up from the timestamp_index.
  """
  @spec next_frame(t()) ::
          {:ok, Frame.t(), DateTime.t(), t()}
          | {:need_more, t()}
  def next_frame(%__MODULE__{buffer: buffer} = fb) when byte_size(buffer) < @frame_header_size do
    {:need_more, fb}
  end

  def next_frame(%__MODULE__{buffer: buffer, timestamp_index: index} = fb) do
    # Parse frame header to get length
    <<length::24, _rest::binary>> = buffer
    frame_size = @frame_header_size + length

    if byte_size(buffer) < frame_size do
      {:need_more, fb}
    else
      # Get timestamp for first byte of frame (offset 0 in current buffer)
      frame_timestamp = timestamp_at(index, 0)

      # Extract frame bytes
      <<frame_bytes::binary-size(frame_size), remaining::binary>> = buffer

      # Parse frame - we've already validated the size, so this should succeed
      {:ok, frame, <<>>} = Frame.parse(frame_bytes)

      # Shift timestamp_index to account for removed bytes
      updated_index = shift_timestamp_index(index, frame_size)

      updated_fb = %__MODULE__{
        fb
        | buffer: remaining,
          timestamp_index: updated_index
      }

      {:ok, frame, frame_timestamp, updated_fb}
    end
  end

  @doc """
  Get timestamp for a byte offset (finds latest timestamp entry <= offset).
  """
  @spec timestamp_at([{non_neg_integer(), DateTime.t()}], non_neg_integer()) :: DateTime.t() | nil
  def timestamp_at([], _offset), do: nil

  def timestamp_at(index, offset) do
    # Find the latest entry where start_offset <= offset
    # (the chunk that contains this byte)
    index
    |> Enum.take_while(fn {start_offset, _ts} -> start_offset <= offset end)
    |> List.last()
    |> case do
      nil -> nil
      {_offset, timestamp} -> timestamp
    end
  end

  @doc """
  Shift timestamp_index after consuming bytes from buffer start.

  Subtracts bytes_consumed from all offsets. Removes entries with negative
  offsets (their data was consumed), but preserves the last valid timestamp
  for offset 0 continuity.
  """
  @spec shift_timestamp_index([{non_neg_integer(), DateTime.t()}], non_neg_integer()) ::
          [{non_neg_integer(), DateTime.t()}]
  def shift_timestamp_index(index, bytes_consumed) do
    {shifted, last_valid_timestamp} =
      Enum.reduce(index, {[], nil}, fn {offset, timestamp}, {acc, last_ts} ->
        new_offset = offset - bytes_consumed

        if new_offset < 0 do
          # This chunk's start is now before buffer start
          # Keep track of it in case it's the timestamp for offset 0
          {acc, timestamp}
        else
          {acc ++ [{new_offset, timestamp}], last_ts}
        end
      end)

    # If offset 0 has no entry but we have a prior timestamp, add it
    case shifted do
      [] when last_valid_timestamp != nil ->
        [{0, last_valid_timestamp}]

      [{first_offset, _} | _] when first_offset > 0 and last_valid_timestamp != nil ->
        [{0, last_valid_timestamp} | shifted]

      _ ->
        shifted
    end
  end

  @doc """
  Get the current buffer size in bytes.
  """
  @spec buffer_size(t()) :: non_neg_integer()
  def buffer_size(%__MODULE__{buffer: buffer}), do: byte_size(buffer)
end
