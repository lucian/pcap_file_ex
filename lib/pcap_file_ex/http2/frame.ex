defmodule PcapFileEx.HTTP2.Frame do
  @moduledoc """
  HTTP/2 frame parsing.

  Parses the 9-byte frame header and payload according to RFC 7540.

  ## Frame Header Structure

      +-----------------------------------------------+
      |                 Length (24)                   |
      +---------------+---------------+---------------+
      |   Type (8)    |   Flags (8)   |
      +-+-------------+---------------+---------------+
      |R|                 Stream ID (31)              |
      +=+=============================================================+
      |                   Payload (0...)              |
      +---------------------------------------------------------------+

  ## Frame Types

  | Type          | Code |
  |---------------|------|
  | DATA          | 0x00 |
  | HEADERS       | 0x01 |
  | PRIORITY      | 0x02 |
  | RST_STREAM    | 0x03 |
  | SETTINGS      | 0x04 |
  | PUSH_PROMISE  | 0x05 |
  | PING          | 0x06 |
  | GOAWAY        | 0x07 |
  | WINDOW_UPDATE | 0x08 |
  | CONTINUATION  | 0x09 |
  """

  @type frame_type ::
          :data
          | :headers
          | :priority
          | :rst_stream
          | :settings
          | :push_promise
          | :ping
          | :goaway
          | :window_update
          | :continuation
          | :unknown

  @type flags :: %{
          end_stream: boolean(),
          end_headers: boolean(),
          padded: boolean(),
          priority: boolean(),
          ack: boolean()
        }

  @type t :: %__MODULE__{
          length: non_neg_integer(),
          type: frame_type(),
          type_byte: non_neg_integer(),
          flags: flags(),
          flags_byte: non_neg_integer(),
          stream_id: non_neg_integer(),
          payload: binary(),
          raw: binary()
        }

  defstruct [:length, :type, :type_byte, :flags, :flags_byte, :stream_id, :payload, :raw]

  # Frame type codes
  @data 0x00
  @headers 0x01
  @priority 0x02
  @rst_stream 0x03
  @settings 0x04
  @push_promise 0x05
  @ping 0x06
  @goaway 0x07
  @window_update 0x08
  @continuation 0x09

  # Flag bits
  @flag_end_stream 0x01
  @flag_ack 0x01
  @flag_end_headers 0x04
  @flag_padded 0x08
  @flag_priority 0x20

  # Frame header size
  @header_size 9

  @doc """
  Parse an HTTP/2 frame from binary data.

  Returns:
  - `{:ok, frame, rest}` - Successfully parsed frame with remaining bytes
  - `{:need_more, bytes_needed}` - Incomplete frame, need more data
  - `{:error, reason}` - Malformed frame
  """
  @spec parse(binary()) ::
          {:ok, t(), binary()} | {:need_more, non_neg_integer()} | {:error, atom()}
  def parse(data) when byte_size(data) < @header_size do
    {:need_more, @header_size - byte_size(data)}
  end

  def parse(
        <<length::24, type_byte::8, flags_byte::8, _reserved::1, stream_id::31, rest::binary>>
      ) do
    if byte_size(rest) < length do
      {:need_more, length - byte_size(rest)}
    else
      <<payload::binary-size(length), remaining::binary>> = rest

      frame = %__MODULE__{
        length: length,
        type: decode_type(type_byte),
        type_byte: type_byte,
        flags: decode_flags(type_byte, flags_byte),
        flags_byte: flags_byte,
        stream_id: stream_id,
        payload: payload,
        raw: <<length::24, type_byte::8, flags_byte::8, 0::1, stream_id::31, payload::binary>>
      }

      {:ok, frame, remaining}
    end
  end

  @doc """
  Extract header block from HEADERS or PUSH_PROMISE frame, handling padding and priority.

  Returns:
  - `{:ok, header_block}` - Successfully extracted header block
  - `{:error, reason}` - Invalid frame structure
  """
  @spec extract_header_block(t()) :: {:ok, binary()} | {:error, atom()}
  def extract_header_block(%__MODULE__{payload: payload, flags: flags}) do
    with {:ok, offset, pad_length} <- handle_padding(payload, flags.padded),
         {:ok, offset} <- handle_priority(payload, offset, flags.priority, pad_length) do
      # Calculate header block length
      header_block_length = byte_size(payload) - offset - pad_length

      if header_block_length < 0 do
        {:error, :invalid_frame_structure}
      else
        header_block = binary_part(payload, offset, header_block_length)
        {:ok, header_block}
      end
    end
  end

  @doc """
  Extract data from DATA frame, handling padding.

  Returns:
  - `{:ok, data}` - Successfully extracted data
  - `{:error, reason}` - Invalid frame structure
  """
  @spec extract_data(t()) :: {:ok, binary()} | {:error, atom()}
  def extract_data(%__MODULE__{payload: payload, flags: flags}) do
    with {:ok, offset, pad_length} <- handle_padding(payload, flags.padded) do
      data_length = byte_size(payload) - offset - pad_length

      if data_length < 0 do
        {:error, :invalid_frame_structure}
      else
        data = binary_part(payload, offset, data_length)
        {:ok, data}
      end
    end
  end

  @doc """
  Check if frame has END_STREAM flag set.
  """
  @spec end_stream?(t()) :: boolean()
  def end_stream?(%__MODULE__{flags: %{end_stream: end_stream}}), do: end_stream

  @doc """
  Check if frame has END_HEADERS flag set.
  """
  @spec end_headers?(t()) :: boolean()
  def end_headers?(%__MODULE__{flags: %{end_headers: end_headers}}), do: end_headers

  @doc """
  Check if frame is on stream 0 (connection-level control frame).
  """
  @spec control_frame?(t()) :: boolean()
  def control_frame?(%__MODULE__{stream_id: 0}), do: true
  def control_frame?(_), do: false

  # Private helpers

  defp decode_type(@data), do: :data
  defp decode_type(@headers), do: :headers
  defp decode_type(@priority), do: :priority
  defp decode_type(@rst_stream), do: :rst_stream
  defp decode_type(@settings), do: :settings
  defp decode_type(@push_promise), do: :push_promise
  defp decode_type(@ping), do: :ping
  defp decode_type(@goaway), do: :goaway
  defp decode_type(@window_update), do: :window_update
  defp decode_type(@continuation), do: :continuation
  defp decode_type(_), do: :unknown

  defp decode_flags(type_byte, flags_byte) do
    %{
      end_stream: has_flag?(flags_byte, @flag_end_stream) and type_byte in [@data, @headers],
      end_headers:
        has_flag?(flags_byte, @flag_end_headers) and
          type_byte in [@headers, @push_promise, @continuation],
      padded:
        has_flag?(flags_byte, @flag_padded) and type_byte in [@data, @headers, @push_promise],
      priority: has_flag?(flags_byte, @flag_priority) and type_byte == @headers,
      ack: has_flag?(flags_byte, @flag_ack) and type_byte in [@settings, @ping]
    }
  end

  defp has_flag?(flags_byte, flag), do: Bitwise.band(flags_byte, flag) != 0

  defp handle_padding(payload, true) do
    if byte_size(payload) < 1 do
      {:error, :invalid_padding_no_length}
    else
      <<pad_length::8, _rest::binary>> = payload

      if pad_length > byte_size(payload) - 1 do
        {:error, :invalid_padding_exceeds_payload}
      else
        {:ok, 1, pad_length}
      end
    end
  end

  defp handle_padding(_payload, false), do: {:ok, 0, 0}

  defp handle_priority(payload, offset, true, pad_length) do
    # Priority field is 5 bytes: E(1 bit) + Stream Dependency(31 bits) + Weight(8 bits)
    remaining = byte_size(payload) - offset - pad_length

    if remaining < 5 do
      {:error, :invalid_priority_truncated}
    else
      {:ok, offset + 5}
    end
  end

  defp handle_priority(_payload, offset, false, _pad_length), do: {:ok, offset}
end
