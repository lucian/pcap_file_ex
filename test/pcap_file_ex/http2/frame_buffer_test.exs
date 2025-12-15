defmodule PcapFileEx.HTTP2.FrameBufferTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.HTTP2.FrameBuffer

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  describe "new/0" do
    test "creates empty buffer" do
      buffer = FrameBuffer.new()

      assert buffer.buffer == <<>>
      assert buffer.timestamp_index == []
      assert buffer.preface_checked == false
      assert buffer.preface_found == false
    end
  end

  describe "append/3" do
    test "appends data to buffer" do
      ts = DateTime.utc_now()
      buffer = FrameBuffer.new() |> FrameBuffer.append("hello", ts)

      assert buffer.buffer == "hello"
      assert buffer.timestamp_index == [{0, ts}]
    end

    test "appends multiple chunks with timestamps" do
      ts1 = ~U[2024-01-01 12:00:00Z]
      ts2 = ~U[2024-01-01 12:00:01Z]

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append("hello", ts1)
        |> FrameBuffer.append("world", ts2)

      assert buffer.buffer == "helloworld"
      assert buffer.timestamp_index == [{0, ts1}, {5, ts2}]
    end
  end

  describe "check_preface/1" do
    test "detects connection preface" do
      ts = DateTime.utc_now()

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append(@connection_preface <> "more_data", ts)

      assert {:preface_found, new_buffer} = FrameBuffer.check_preface(buffer)
      assert new_buffer.preface_checked == true
      assert new_buffer.preface_found == true
      assert new_buffer.buffer == "more_data"
    end

    test "returns no_preface when buffer doesn't start with preface" do
      ts = DateTime.utc_now()

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append("not a preface at all!!", ts)

      # Need at least 24 bytes to check
      buffer = FrameBuffer.append(buffer, "!!", ts)

      assert {:no_preface, new_buffer} = FrameBuffer.check_preface(buffer)
      assert new_buffer.preface_checked == true
      assert new_buffer.preface_found == false
      # Buffer unchanged (except flags)
      assert new_buffer.buffer == "not a preface at all!!!!"
    end

    test "returns need_more_data when buffer too small" do
      ts = DateTime.utc_now()

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append("short", ts)

      assert {:need_more_data, ^buffer} = FrameBuffer.check_preface(buffer)
      assert buffer.preface_checked == false
    end

    test "is idempotent after first check" do
      ts = DateTime.utc_now()

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append(@connection_preface, ts)

      {:preface_found, buffer} = FrameBuffer.check_preface(buffer)
      assert {:preface_found, ^buffer} = FrameBuffer.check_preface(buffer)
    end

    test "handles preface split across chunks" do
      ts1 = ~U[2024-01-01 12:00:00Z]
      ts2 = ~U[2024-01-01 12:00:01Z]

      # Split preface at byte 12
      <<first_half::binary-size(12), second_half::binary>> = @connection_preface

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append(first_half, ts1)

      assert {:need_more_data, buffer} = FrameBuffer.check_preface(buffer)

      buffer = FrameBuffer.append(buffer, second_half <> "data", ts2)

      assert {:preface_found, new_buffer} = FrameBuffer.check_preface(buffer)
      assert new_buffer.buffer == "data"
    end
  end

  describe "has_complete_frame?/1" do
    test "returns false for empty buffer" do
      buffer = FrameBuffer.new()
      assert FrameBuffer.has_complete_frame?(buffer) == false
    end

    test "returns false when less than header size" do
      ts = DateTime.utc_now()
      buffer = FrameBuffer.new() |> FrameBuffer.append(<<0, 0, 5, 0, 0>>, ts)
      assert FrameBuffer.has_complete_frame?(buffer) == false
    end

    test "returns false when payload incomplete" do
      ts = DateTime.utc_now()
      # Frame header says length=10, but only 5 bytes of payload
      buffer =
        FrameBuffer.new() |> FrameBuffer.append(<<0, 0, 10, 0, 0, 0::1, 1::31, "short">>, ts)

      assert FrameBuffer.has_complete_frame?(buffer) == false
    end

    test "returns true when frame is complete" do
      ts = DateTime.utc_now()
      # Complete frame: length=5
      buffer =
        FrameBuffer.new() |> FrameBuffer.append(<<0, 0, 5, 0, 0, 0::1, 1::31, "hello">>, ts)

      assert FrameBuffer.has_complete_frame?(buffer) == true
    end
  end

  describe "next_frame/1" do
    test "extracts complete frame" do
      ts = ~U[2024-01-01 12:00:00Z]
      frame_bytes = <<0, 0, 5, 0x00, 0x00, 0::1, 1::31, "hello">>

      buffer = FrameBuffer.new() |> FrameBuffer.append(frame_bytes, ts)

      assert {:ok, frame, frame_ts, new_buffer} = FrameBuffer.next_frame(buffer)
      assert frame.type == :data
      assert frame.payload == "hello"
      assert frame_ts == ts
      assert new_buffer.buffer == <<>>
    end

    test "returns need_more for incomplete frame" do
      ts = DateTime.utc_now()
      buffer = FrameBuffer.new() |> FrameBuffer.append(<<0, 0, 10, 0, 0>>, ts)

      assert {:need_more, ^buffer} = FrameBuffer.next_frame(buffer)
    end

    test "preserves remaining data after frame" do
      ts = DateTime.utc_now()
      frame_bytes = <<0, 0, 5, 0x00, 0x00, 0::1, 1::31, "hello", "extra">>

      buffer = FrameBuffer.new() |> FrameBuffer.append(frame_bytes, ts)

      assert {:ok, _frame, _ts, new_buffer} = FrameBuffer.next_frame(buffer)
      assert new_buffer.buffer == "extra"
    end

    test "tracks timestamp correctly for frames spanning chunks" do
      ts1 = ~U[2024-01-01 12:00:00Z]
      ts2 = ~U[2024-01-01 12:00:01Z]

      # Frame header in first chunk
      header = <<0, 0, 10, 0x00, 0x00, 0::1, 1::31>>
      # Payload split across chunks
      payload_part1 = "hello"
      payload_part2 = "world"

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append(header <> payload_part1, ts1)
        |> FrameBuffer.append(payload_part2, ts2)

      assert {:ok, frame, frame_ts, _new_buffer} = FrameBuffer.next_frame(buffer)
      # Timestamp should be from first byte (ts1)
      assert frame_ts == ts1
      assert frame.payload == "helloworld"
    end
  end

  describe "timestamp_at/2" do
    test "returns timestamp for exact offset" do
      ts1 = ~U[2024-01-01 12:00:00Z]
      ts2 = ~U[2024-01-01 12:00:01Z]

      index = [{0, ts1}, {10, ts2}]

      assert FrameBuffer.timestamp_at(index, 0) == ts1
      assert FrameBuffer.timestamp_at(index, 10) == ts2
    end

    test "returns timestamp for offset within chunk" do
      ts1 = ~U[2024-01-01 12:00:00Z]
      ts2 = ~U[2024-01-01 12:00:01Z]

      index = [{0, ts1}, {10, ts2}]

      assert FrameBuffer.timestamp_at(index, 5) == ts1
      assert FrameBuffer.timestamp_at(index, 15) == ts2
    end

    test "returns nil for empty index" do
      assert FrameBuffer.timestamp_at([], 0) == nil
    end
  end

  describe "shift_timestamp_index/2" do
    test "shifts all offsets by consumed bytes" do
      ts1 = ~U[2024-01-01 12:00:00Z]
      ts2 = ~U[2024-01-01 12:00:01Z]

      index = [{0, ts1}, {10, ts2}]
      shifted = FrameBuffer.shift_timestamp_index(index, 5)

      # First entry should be at offset 0 with ts1 (was covering bytes 0-9)
      # Second entry should be at offset 5 (was 10, minus 5)
      assert [{0, ^ts1}, {5, ^ts2}] = shifted
    end

    test "removes entries that fall before buffer start" do
      ts1 = ~U[2024-01-01 12:00:00Z]
      ts2 = ~U[2024-01-01 12:00:01Z]

      index = [{0, ts1}, {10, ts2}]
      shifted = FrameBuffer.shift_timestamp_index(index, 15)

      # First chunk completely consumed, second chunk now starts at 0
      # But we need to keep continuity for offset 0
      assert [{0, ^ts2}] = shifted
    end

    test "preserves timestamp for offset 0 continuity" do
      ts1 = ~U[2024-01-01 12:00:00Z]

      index = [{0, ts1}]
      shifted = FrameBuffer.shift_timestamp_index(index, 5)

      # Even though chunk started at 0, it still covers the new offset 0
      assert [{0, ^ts1}] = shifted
    end
  end

  describe "buffer_size/1" do
    test "returns size of buffer" do
      ts = DateTime.utc_now()

      buffer =
        FrameBuffer.new()
        |> FrameBuffer.append("hello", ts)
        |> FrameBuffer.append("world", ts)

      assert FrameBuffer.buffer_size(buffer) == 10
    end

    test "returns 0 for empty buffer" do
      buffer = FrameBuffer.new()
      assert FrameBuffer.buffer_size(buffer) == 0
    end
  end
end
