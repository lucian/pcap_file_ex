defmodule PcapFileEx.StreamPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.{Filter, Timestamp}
  import PcapFileEx.PropertyGenerators

  # Note: These tests focus on Stream behaviors using in-memory packet lists
  # since we're avoiding file I/O in property tests per user requirements.
  # File-based streaming is tested in the existing example-based tests.

  describe "Stream operations on packet lists" do
    property "converting to stream and back preserves all packets" do
      check all packets <- packet_list_generator() do
        stream_result =
          packets
          |> Stream.map(& &1)
          |> Enum.to_list()

        assert stream_result == packets
      end
    end

    property "stream filtering preserves order" do
      check all packets <- packet_list_generator(min_length: 5, max_length: 50),
                threshold <- size_threshold_generator() do
        filtered_stream =
          packets
          |> Stream.filter(fn p -> byte_size(p.data) > threshold end)
          |> Enum.to_list()

        filtered_eager = Enum.filter(packets, fn p -> byte_size(p.data) > threshold end)

        assert filtered_stream == filtered_eager
      end
    end

    property "stream take is lazy and produces correct count" do
      check all packets <- packet_list_generator(min_length: 10, max_length: 100),
                n <- integer(0..20) do
        taken =
          packets
          |> Stream.take(n)
          |> Enum.to_list()

        assert length(taken) == min(n, length(packets))
        assert taken == Enum.take(packets, n)
      end
    end

    property "stream drop removes first N packets" do
      check all packets <- packet_list_generator(min_length: 5, max_length: 50),
                n <- integer(0..10) do
        dropped_stream =
          packets
          |> Stream.drop(n)
          |> Enum.to_list()

        dropped_eager = Enum.drop(packets, n)

        assert dropped_stream == dropped_eager
      end
    end
  end

  describe "Filter operations on streams" do
    property "Filter.by_size on stream equals filter on list" do
      check all packets <- packet_list_generator(),
                range <- size_range_generator() do
        stream_result =
          packets
          |> Stream.map(& &1)
          |> Filter.by_size(range)
          |> Enum.to_list()

        list_result =
          packets
          |> Filter.by_size(range)
          |> Enum.to_list()

        assert stream_result == list_result
      end
    end

    property "Filter.larger_than on stream equals filter on list" do
      check all packets <- packet_list_generator(),
                threshold <- size_threshold_generator() do
        stream_result =
          packets
          |> Stream.map(& &1)
          |> Filter.larger_than(threshold)
          |> Enum.to_list()

        list_result =
          packets
          |> Filter.larger_than(threshold)
          |> Enum.to_list()

        assert stream_result == list_result
      end
    end

    property "chaining filters on stream produces correct results" do
      check all packets <- packet_list_generator(),
                threshold1 <- integer(100..1000),
                threshold2 <- integer(1001..5000) do
        stream_result =
          packets
          |> Stream.map(& &1)
          |> Filter.larger_than(threshold1)
          |> Filter.smaller_than(threshold2)
          |> Enum.to_list()

        # All packets should be in the range (threshold1, threshold2)
        Enum.all?(stream_result, fn packet ->
          size = byte_size(packet.data)
          assert size > threshold1 and size < threshold2
        end)
      end
    end
  end

  describe "Stream transformations" do
    property "mapping over stream preserves count" do
      check all packets <- packet_list_generator() do
        mapped =
          packets
          |> Stream.map(fn p -> %{p | decoded: %{test: true}} end)
          |> Enum.to_list()

        assert length(mapped) == length(packets)
      end
    end

    property "sorting stream by timestamp produces ordered result" do
      check all packets <- packet_list_generator(min_length: 2, max_length: 50) do
        sorted =
          packets
          |> Stream.map(& &1)
          |> Enum.sort_by(& &1.timestamp_precise, Timestamp)

        # Verify ordering
        sorted
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.each(fn [p1, p2] ->
          cmp = Timestamp.compare(p1.timestamp_precise, p2.timestamp_precise)
          assert cmp in [:lt, :eq]
        end)
      end
    end

    property "stream concat combines packet lists" do
      check all packets1 <- packet_list_generator(max_length: 30),
                packets2 <- packet_list_generator(max_length: 30) do
        concatenated =
          [packets1, packets2]
          |> Stream.concat()
          |> Enum.to_list()

        assert length(concatenated) == length(packets1) + length(packets2)
        assert concatenated == packets1 ++ packets2
      end
    end
  end

  describe "Stream counting and aggregation" do
    property "Enum.count on stream matches list length" do
      check all packets <- packet_list_generator() do
        stream_count =
          packets
          |> Stream.map(& &1)
          |> Enum.count()

        assert stream_count == length(packets)
      end
    end

    property "counting filtered stream matches filtered list" do
      check all packets <- packet_list_generator(),
                threshold <- size_threshold_generator() do
        stream_count =
          packets
          |> Stream.filter(fn p -> byte_size(p.data) > threshold end)
          |> Enum.count()

        list_count =
          packets
          |> Enum.filter(fn p -> byte_size(p.data) > threshold end)
          |> length()

        assert stream_count == list_count
      end
    end

    property "summing packet sizes via stream equals eager sum" do
      check all packets <- packet_list_generator() do
        stream_sum =
          packets
          |> Stream.map(fn p -> byte_size(p.data) end)
          |> Enum.sum()

        eager_sum =
          packets
          |> Enum.map(fn p -> byte_size(p.data) end)
          |> Enum.sum()

        assert stream_sum == eager_sum
      end
    end
  end

  describe "Stream limit and pagination" do
    property "limit and skip together provide pagination" do
      check all packets <- packet_list_generator(min_length: 20, max_length: 100),
                page_size <- integer(5..15),
                page_num <- integer(0..3) do
        skip_count = page_num * page_size

        page =
          packets
          |> Stream.drop(skip_count)
          |> Stream.take(page_size)
          |> Enum.to_list()

        expected =
          packets
          |> Enum.drop(skip_count)
          |> Enum.take(page_size)

        assert page == expected
      end
    end

    property "chunk_every on stream maintains all packets" do
      check all packets <- packet_list_generator(min_length: 10, max_length: 50),
                chunk_size <- integer(2..10) do
        chunked =
          packets
          |> Stream.chunk_every(chunk_size)
          |> Enum.to_list()

        flattened = List.flatten(chunked)

        assert flattened == packets
      end
    end
  end
end
