defmodule PcapFileEx.HTTP2.FrameTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.HTTP2.Frame

  describe "parse/1" do
    test "parses a valid DATA frame" do
      # DATA frame: length=5, type=0x00, flags=0x00, stream_id=1, payload="hello"
      frame_bytes = <<0, 0, 5, 0x00, 0x00, 0::1, 1::31, "hello">>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.length == 5
      assert frame.type == :data
      assert frame.type_byte == 0x00
      assert frame.stream_id == 1
      assert frame.payload == "hello"
      assert frame.flags.end_stream == false
      assert frame.flags.padded == false
    end

    test "parses a DATA frame with END_STREAM flag" do
      # DATA frame with END_STREAM (0x01)
      frame_bytes = <<0, 0, 5, 0x00, 0x01, 0::1, 1::31, "hello">>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :data
      assert frame.flags.end_stream == true
    end

    test "parses a HEADERS frame" do
      # HEADERS frame: length=10, type=0x01, flags=0x04 (END_HEADERS), stream_id=1
      header_block = <<0x82, 0x86, 0x84, 0x41, 0x8A, 0x08, 0x9D, 0x5C, 0x0B, 0x81>>
      frame_bytes = <<0, 0, 10, 0x01, 0x04, 0::1, 1::31, header_block::binary>>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :headers
      assert frame.flags.end_headers == true
      assert frame.flags.end_stream == false
      assert frame.flags.priority == false
      assert frame.flags.padded == false
    end

    test "parses a HEADERS frame with END_STREAM and END_HEADERS" do
      frame_bytes = <<0, 0, 5, 0x01, 0x05, 0::1, 1::31, "block">>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :headers
      assert frame.flags.end_stream == true
      assert frame.flags.end_headers == true
    end

    test "parses a SETTINGS frame" do
      # SETTINGS frame on stream 0
      # HEADER_TABLE_SIZE (0x01) = 4096 (0x1000)
      settings_payload = <<0x00, 0x01, 0x00, 0x00, 0x10, 0x00>>
      frame_bytes = <<0, 0, 6, 0x04, 0x00, 0::1, 0::31, settings_payload::binary>>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :settings
      assert frame.stream_id == 0
      assert frame.flags.ack == false
    end

    test "parses a SETTINGS ACK frame" do
      # Empty SETTINGS with ACK flag
      frame_bytes = <<0, 0, 0, 0x04, 0x01, 0::1, 0::31>>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :settings
      assert frame.flags.ack == true
    end

    test "parses a RST_STREAM frame" do
      # RST_STREAM with error code CANCEL (0x08)
      frame_bytes = <<0, 0, 4, 0x03, 0x00, 0::1, 1::31, 0, 0, 0, 8>>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :rst_stream
      assert frame.stream_id == 1
      assert frame.payload == <<0, 0, 0, 8>>
    end

    test "parses a GOAWAY frame" do
      # GOAWAY: last_stream_id=3, error_code=0 (NO_ERROR)
      frame_bytes = <<0, 0, 8, 0x07, 0x00, 0::1, 0::31, 0::1, 3::31, 0, 0, 0, 0>>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :goaway
      assert frame.stream_id == 0
    end

    test "parses a CONTINUATION frame" do
      frame_bytes = <<0, 0, 5, 0x09, 0x04, 0::1, 1::31, "block">>

      assert {:ok, frame, <<>>} = Frame.parse(frame_bytes)
      assert frame.type == :continuation
      assert frame.flags.end_headers == true
    end

    test "returns need_more when data is incomplete" do
      # Only header, no payload
      incomplete = <<0, 0, 10, 0x00, 0x00, 0::1, 1::31>>

      assert {:need_more, 10} = Frame.parse(incomplete)
    end

    test "returns need_more when header is incomplete" do
      assert {:need_more, 4} = Frame.parse(<<0, 0, 0, 0, 0>>)
    end

    test "returns remaining bytes after frame" do
      frame_bytes = <<0, 0, 5, 0x00, 0x00, 0::1, 1::31, "hello", "extra">>

      assert {:ok, frame, rest} = Frame.parse(frame_bytes)
      assert frame.payload == "hello"
      assert rest == "extra"
    end
  end

  describe "extract_header_block/1" do
    test "extracts header block from simple HEADERS frame" do
      frame = %Frame{
        payload: "header_block_data",
        flags: %{padded: false, priority: false, end_stream: false, end_headers: true, ack: false}
      }

      assert {:ok, "header_block_data"} = Frame.extract_header_block(frame)
    end

    test "extracts header block with padding" do
      # 2 bytes padding, header block, 2 padding bytes
      payload = <<2, "header", 0, 0>>

      frame = %Frame{
        payload: payload,
        flags: %{padded: true, priority: false, end_stream: false, end_headers: true, ack: false}
      }

      assert {:ok, "header"} = Frame.extract_header_block(frame)
    end

    test "extracts header block with priority" do
      # 5 bytes priority (E + stream dep + weight), then header block
      priority_bytes = <<0::1, 0::31, 15>>
      payload = priority_bytes <> "header"

      frame = %Frame{
        payload: payload,
        flags: %{padded: false, priority: true, end_stream: false, end_headers: true, ack: false}
      }

      assert {:ok, "header"} = Frame.extract_header_block(frame)
    end

    test "extracts header block with both padding and priority" do
      # pad_length + priority (5 bytes) + header + padding
      payload = <<3, 0::1, 0::31, 15, "hdr", 0, 0, 0>>

      frame = %Frame{
        payload: payload,
        flags: %{padded: true, priority: true, end_stream: false, end_headers: true, ack: false}
      }

      assert {:ok, "hdr"} = Frame.extract_header_block(frame)
    end

    test "returns error for invalid padding" do
      # Padding length exceeds payload
      payload = <<100, "short">>

      frame = %Frame{
        payload: payload,
        flags: %{padded: true, priority: false, end_stream: false, end_headers: true, ack: false}
      }

      assert {:error, :invalid_padding_exceeds_payload} = Frame.extract_header_block(frame)
    end
  end

  describe "extract_data/1" do
    test "extracts data from simple DATA frame" do
      frame = %Frame{
        payload: "response body",
        flags: %{
          padded: false,
          priority: false,
          end_stream: false,
          end_headers: false,
          ack: false
        }
      }

      assert {:ok, "response body"} = Frame.extract_data(frame)
    end

    test "extracts data with padding" do
      payload = <<4, "data", 0, 0, 0, 0>>

      frame = %Frame{
        payload: payload,
        flags: %{padded: true, priority: false, end_stream: false, end_headers: false, ack: false}
      }

      assert {:ok, "data"} = Frame.extract_data(frame)
    end
  end

  describe "helper functions" do
    test "end_stream?/1 returns flag value" do
      frame_with = %Frame{
        flags: %{end_stream: true, end_headers: false, padded: false, priority: false, ack: false}
      }

      frame_without = %Frame{
        flags: %{
          end_stream: false,
          end_headers: false,
          padded: false,
          priority: false,
          ack: false
        }
      }

      assert Frame.end_stream?(frame_with) == true
      assert Frame.end_stream?(frame_without) == false
    end

    test "end_headers?/1 returns flag value" do
      frame_with = %Frame{
        flags: %{end_stream: false, end_headers: true, padded: false, priority: false, ack: false}
      }

      frame_without = %Frame{
        flags: %{
          end_stream: false,
          end_headers: false,
          padded: false,
          priority: false,
          ack: false
        }
      }

      assert Frame.end_headers?(frame_with) == true
      assert Frame.end_headers?(frame_without) == false
    end

    test "control_frame?/1 checks stream_id == 0" do
      control = %Frame{stream_id: 0}
      stream = %Frame{stream_id: 1}

      assert Frame.control_frame?(control) == true
      assert Frame.control_frame?(stream) == false
    end
  end
end
