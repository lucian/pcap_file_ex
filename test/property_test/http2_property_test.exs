defmodule PcapFileEx.HTTP2PropertyTest do
  @moduledoc """
  Property-based tests for HTTP/2 frame parsing and headers handling.

  Tests invariants such as:
  - Frame parsing never crashes on valid frame structure
  - Headers module correctly separates pseudo-headers
  - Frame buffer handles arbitrary data without crashing
  - Round-trip properties for headers
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.HTTP2.{Frame, FrameBuffer, Headers}
  alias PcapFileEx.PropertyGenerators

  @moduletag :property

  # Number of iterations for property tests
  @max_runs if System.get_env("CI"), do: 1000, else: 100

  describe "Frame parsing properties" do
    property "parse never crashes on well-formed frame binary" do
      check all frame_binary <- PropertyGenerators.http2_frame_binary_generator(),
                max_runs: @max_runs do
        # Should either succeed or return need_more, never crash
        result = Frame.parse(frame_binary)

        assert match?({:ok, %Frame{}, _rest}, result) or
                 match?({:need_more, _}, result)
      end
    end

    property "parse returns consistent length for valid frames" do
      check all frame_binary <- PropertyGenerators.http2_frame_binary_generator(),
                max_runs: @max_runs do
        case Frame.parse(frame_binary) do
          {:ok, frame, rest} ->
            # Length in header should match actual payload size
            assert frame.length == byte_size(frame.payload)
            # Rest should be whatever was after the frame
            assert byte_size(rest) == byte_size(frame_binary) - 9 - frame.length

          {:need_more, _} ->
            :ok
        end
      end
    end

    property "parse handles incomplete frames gracefully" do
      check all frame_binary <- PropertyGenerators.http2_frame_binary_generator(),
                cut_at <- integer(0..(byte_size(frame_binary) - 1)),
                max_runs: @max_runs do
        incomplete = binary_part(frame_binary, 0, cut_at)

        # Should return need_more for incomplete data
        result = Frame.parse(incomplete)

        # If cut includes complete frame, parsing succeeds
        assert match?({:need_more, _}, result) or
                 match?({:ok, %Frame{}, _}, result)
      end
    end

    property "frame type byte maps to correct atom" do
      check all type_byte <- integer(0x00..0x09),
                max_runs: @max_runs do
        # Build minimal frame
        frame_binary = <<0::24, type_byte::8, 0::8, 0::32>>

        {:ok, frame, _} = Frame.parse(frame_binary)

        expected_type =
          case type_byte do
            0x00 -> :data
            0x01 -> :headers
            0x02 -> :priority
            0x03 -> :rst_stream
            0x04 -> :settings
            0x05 -> :push_promise
            0x06 -> :ping
            0x07 -> :goaway
            0x08 -> :window_update
            0x09 -> :continuation
          end

        assert frame.type == expected_type
        assert frame.type_byte == type_byte
      end
    end

    property "stream_id preserved correctly" do
      check all stream_id <- integer(0..0x7FFFFFFF),
                max_runs: @max_runs do
        # Build frame with specific stream ID
        frame_binary = <<0::24, 0::8, 0::8, 0::1, stream_id::31>>

        {:ok, frame, _} = Frame.parse(frame_binary)

        assert frame.stream_id == stream_id
      end
    end
  end

  describe "Headers properties" do
    property "from_list separates pseudo-headers correctly" do
      check all pseudo <- PropertyGenerators.http2_request_pseudo_headers_generator(),
                regular <- PropertyGenerators.http2_regular_headers_generator(),
                max_runs: @max_runs do
        # Convert maps to list
        pseudo_list = Enum.map(pseudo, fn {k, v} -> {k, v} end)
        regular_list = Enum.map(regular, fn {k, v} -> {k, v} end)
        combined = pseudo_list ++ regular_list

        headers = Headers.from_list(combined)

        # All pseudo-headers should be in pseudo map
        for {k, v} <- pseudo_list do
          assert headers.pseudo[k] == v
        end

        # All regular headers should be in regular map (lowercased)
        for {k, v} <- regular_list do
          assert headers.regular[String.downcase(k)] == v
        end
      end
    end

    property "request? true only when :method present" do
      check all pseudo <- PropertyGenerators.http2_request_pseudo_headers_generator(),
                max_runs: @max_runs do
        headers = Headers.from_list(Enum.map(pseudo, fn {k, v} -> {k, v} end))

        assert Headers.request?(headers) == Map.has_key?(pseudo, ":method")
      end
    end

    property "response? true only when :status present" do
      check all pseudo <- PropertyGenerators.http2_response_pseudo_headers_generator(),
                max_runs: @max_runs do
        headers = Headers.from_list(Enum.map(pseudo, fn {k, v} -> {k, v} end))

        assert Headers.response?(headers) == Map.has_key?(pseudo, ":status")
      end
    end

    property "trailers? true when no pseudo-headers" do
      check all regular <- PropertyGenerators.http2_regular_headers_generator(),
                max_runs: @max_runs do
        headers = Headers.from_list(Enum.map(regular, fn {k, v} -> {k, v} end))

        # Trailers have no pseudo-headers
        assert Headers.trailers?(headers) == (map_size(headers.pseudo) == 0)
      end
    end

    property "header name lookup is case-insensitive" do
      check all name <- string(:alphanumeric, min_length: 1, max_length: 20),
                value <- string(:alphanumeric, min_length: 1, max_length: 50),
                max_runs: @max_runs do
        headers = Headers.from_list([{name, value}])

        # Should find with original case
        assert Headers.get(headers, name) == value
        # Should find with lowercase
        assert Headers.get(headers, String.downcase(name)) == value
        # Should find with uppercase
        assert Headers.get(headers, String.upcase(name)) == value
      end
    end

    property "status/1 parses integer correctly" do
      check all status_code <- integer(100..599),
                max_runs: @max_runs do
        headers = Headers.from_list([{":status", Integer.to_string(status_code)}])

        assert Headers.status(headers) == status_code
      end
    end
  end

  describe "FrameBuffer properties" do
    property "append never loses data" do
      check all chunks <-
                  list_of(binary(min_length: 1, max_length: 100), min_length: 1, max_length: 10),
                max_runs: @max_runs do
        ts = DateTime.utc_now()

        buffer =
          Enum.reduce(chunks, FrameBuffer.new(), fn chunk, buf ->
            FrameBuffer.append(buf, chunk, ts)
          end)

        expected_data = Enum.join(chunks)
        assert buffer.buffer == expected_data
        assert FrameBuffer.buffer_size(buffer) == byte_size(expected_data)
      end
    end

    property "check_preface detects connection preface" do
      check all suffix <- binary(max_length: 100),
                max_runs: @max_runs do
        preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        ts = DateTime.utc_now()

        buffer =
          FrameBuffer.new()
          |> FrameBuffer.append(preface <> suffix, ts)

        case FrameBuffer.check_preface(buffer) do
          {:preface_found, new_buffer} ->
            assert new_buffer.preface_found == true
            assert new_buffer.buffer == suffix

          {:need_more_data, _} ->
            # Only if suffix makes total < 24 bytes (impossible here)
            flunk("Should have found preface")

          {:no_preface, _} ->
            flunk("Should have found preface")
        end
      end
    end

    property "check_preface returns no_preface for non-preface data" do
      check all data <- binary(min_length: 24, max_length: 100),
                # Ensure it doesn't accidentally match
                not String.starts_with?(data, "PRI * HTTP"),
                max_runs: @max_runs do
        ts = DateTime.utc_now()

        buffer =
          FrameBuffer.new()
          |> FrameBuffer.append(data, ts)

        case FrameBuffer.check_preface(buffer) do
          {:no_preface, new_buffer} ->
            assert new_buffer.preface_checked == true
            assert new_buffer.preface_found == false

          {:preface_found, _} ->
            flunk("Should not find preface in random data")

          {:need_more_data, _} ->
            flunk("Should have enough data")
        end
      end
    end

    property "timestamp tracking is monotonic" do
      check all count <- integer(1..10),
                max_runs: @max_runs do
        base_ts = ~U[2024-01-01 00:00:00Z]

        {buffer, _} =
          Enum.reduce(1..count, {FrameBuffer.new(), base_ts}, fn i, {buf, ts} ->
            next_ts = DateTime.add(ts, i, :second)
            new_buf = FrameBuffer.append(buf, "chunk#{i}", next_ts)
            {new_buf, next_ts}
          end)

        # Each entry in timestamp_index should have increasing timestamps
        timestamps = Enum.map(buffer.timestamp_index, fn {_offset, ts} -> ts end)

        assert timestamps == Enum.sort(timestamps, {:asc, DateTime})
      end
    end

    property "next_frame extracts complete frames correctly" do
      check all frame_binary <- PropertyGenerators.http2_frame_binary_generator(),
                max_runs: @max_runs do
        ts = DateTime.utc_now()

        buffer =
          FrameBuffer.new()
          |> FrameBuffer.append(frame_binary, ts)

        case FrameBuffer.next_frame(buffer) do
          {:ok, frame, frame_ts, new_buffer} ->
            assert frame_ts == ts
            # Frame should be valid
            assert %Frame{} = frame
            # Remaining buffer should be empty (single frame)
            assert new_buffer.buffer == <<>>

          {:need_more, _} ->
            # Frame was incomplete
            :ok
        end
      end
    end
  end

  describe "Frame flag parsing properties" do
    property "DATA frame END_STREAM flag parsed correctly" do
      check all has_end_stream <- boolean(),
                max_runs: @max_runs do
        flags = if has_end_stream, do: 0x01, else: 0x00
        frame_binary = <<5::24, 0x00::8, flags::8, 0::1, 1::31, "hello">>

        {:ok, frame, _} = Frame.parse(frame_binary)

        assert frame.flags.end_stream == has_end_stream
      end
    end

    property "HEADERS frame flags parsed correctly" do
      check all end_stream <- boolean(),
                end_headers <- boolean(),
                padded <- boolean(),
                priority <- boolean(),
                max_runs: @max_runs do
        import Bitwise

        flags =
          if(end_stream, do: 0x01, else: 0) |||
            if(end_headers, do: 0x04, else: 0) |||
            if(padded, do: 0x08, else: 0) |||
            if priority, do: 0x20, else: 0

        # Build payload that satisfies padding/priority requirements
        payload =
          cond do
            padded and priority ->
              # pad_length (1) + priority (5) + header + padding
              <<2, 0::1, 0::31, 15, "hdr", 0, 0>>

            padded ->
              # pad_length (1) + header + padding
              <<2, "hdr", 0, 0>>

            priority ->
              # priority (5) + header
              <<0::1, 0::31, 15, "hdr">>

            true ->
              "hdr"
          end

        frame_binary = <<byte_size(payload)::24, 0x01::8, flags::8, 0::1, 1::31, payload::binary>>

        {:ok, frame, _} = Frame.parse(frame_binary)

        assert frame.flags.end_stream == end_stream
        assert frame.flags.end_headers == end_headers
        assert frame.flags.padded == padded
        assert frame.flags.priority == priority
      end
    end

    property "SETTINGS frame ACK flag parsed correctly" do
      check all has_ack <- boolean(),
                max_runs: @max_runs do
        flags = if has_ack, do: 0x01, else: 0x00
        frame_binary = <<0::24, 0x04::8, flags::8, 0::32>>

        {:ok, frame, _} = Frame.parse(frame_binary)

        assert frame.flags.ack == has_ack
      end
    end
  end

  describe "Extract data/headers properties" do
    property "extract_data removes padding correctly" do
      check all data <- binary(min_length: 1, max_length: 100),
                pad_length <- integer(0..10),
                max_runs: @max_runs do
        # Build padded DATA frame
        padding = :binary.copy(<<0>>, pad_length)

        frame = %Frame{
          payload: <<pad_length::8, data::binary, padding::binary>>,
          flags: %{
            padded: true,
            end_stream: false,
            end_headers: false,
            priority: false,
            ack: false
          }
        }

        assert {:ok, extracted} = Frame.extract_data(frame)
        assert extracted == data
      end
    end

    property "extract_data returns original for unpadded frames" do
      check all data <- binary(max_length: 100),
                max_runs: @max_runs do
        frame = %Frame{
          payload: data,
          flags: %{
            padded: false,
            end_stream: false,
            end_headers: false,
            priority: false,
            ack: false
          }
        }

        assert {:ok, extracted} = Frame.extract_data(frame)
        assert extracted == data
      end
    end

    property "extract_header_block handles priority field" do
      check all header_block <- binary(min_length: 1, max_length: 100),
                exclusive <- boolean(),
                dep <- integer(0..0x7FFFFFFF),
                weight <- integer(0..255),
                max_runs: @max_runs do
        # Build priority prefix
        e_bit = if exclusive, do: 1, else: 0
        priority_bytes = <<e_bit::1, dep::31, weight::8>>

        frame = %Frame{
          payload: priority_bytes <> header_block,
          flags: %{
            padded: false,
            priority: true,
            end_stream: false,
            end_headers: true,
            ack: false
          }
        }

        assert {:ok, extracted} = Frame.extract_header_block(frame)
        assert extracted == header_block
      end
    end
  end
end
