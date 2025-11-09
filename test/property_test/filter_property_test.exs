defmodule PcapFileEx.FilterPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.Filter
  import PcapFileEx.PropertyGenerators

  describe "Filter.by_size/2" do
    property "filtering never increases packet count" do
      check all packets <- packet_list_generator(),
                range <- size_range_generator() do
        filtered = packets |> Filter.by_size(range) |> Enum.to_list()

        assert length(filtered) <= length(packets)
      end
    end

    property "all filtered packets are within size range" do
      check all packets <- packet_list_generator(),
                range <- size_range_generator() do
        filtered = packets |> Filter.by_size(range) |> Enum.to_list()

        Enum.all?(filtered, fn packet ->
          size = byte_size(packet.data)

          assert size in range,
                 "packet size #{size} should be in range #{inspect(range)}"
        end)
      end
    end

    property "by_size is idempotent" do
      check all packets <- packet_list_generator(),
                range <- size_range_generator() do
        filtered_once = packets |> Filter.by_size(range) |> Enum.to_list()
        filtered_twice = filtered_once |> Filter.by_size(range) |> Enum.to_list()

        assert filtered_once == filtered_twice
      end
    end
  end

  describe "Filter.larger_than/2" do
    property "all filtered packets are larger than threshold" do
      check all packets <- packet_list_generator(),
                threshold <- size_threshold_generator() do
        filtered = packets |> Filter.larger_than(threshold) |> Enum.to_list()

        Enum.all?(filtered, fn packet ->
          size = byte_size(packet.data)

          assert size > threshold,
                 "packet size #{size} should be > #{threshold}"
        end)
      end
    end

    property "larger_than never increases count" do
      check all packets <- packet_list_generator(),
                threshold <- size_threshold_generator() do
        filtered = packets |> Filter.larger_than(threshold) |> Enum.to_list()

        assert length(filtered) <= length(packets)
      end
    end

    property "higher threshold means fewer or equal packets" do
      check all packets <- packet_list_generator(),
                threshold1 <- integer(100..1000),
                threshold2 <- integer(1001..5000) do
        # threshold2 > threshold1, so should filter out more
        filtered1 = packets |> Filter.larger_than(threshold1) |> Enum.to_list()
        filtered2 = packets |> Filter.larger_than(threshold2) |> Enum.to_list()

        assert length(filtered2) <= length(filtered1)
      end
    end
  end

  describe "Filter.smaller_than/2" do
    property "all filtered packets are smaller than threshold" do
      check all packets <- packet_list_generator(),
                threshold <- size_threshold_generator() do
        filtered = packets |> Filter.smaller_than(threshold) |> Enum.to_list()

        Enum.all?(filtered, fn packet ->
          size = byte_size(packet.data)

          assert size < threshold,
                 "packet size #{size} should be < #{threshold}"
        end)
      end
    end

    property "smaller_than never increases count" do
      check all packets <- packet_list_generator(),
                threshold <- size_threshold_generator() do
        filtered = packets |> Filter.smaller_than(threshold) |> Enum.to_list()

        assert length(filtered) <= length(packets)
      end
    end
  end

  describe "Filter.by_time_range/3" do
    property "all filtered packets are within time range" do
      check all packets <- packet_list_generator(),
                {start_time, end_time} <- time_range_generator() do
        filtered = packets |> Filter.by_time_range(start_time, end_time) |> Enum.to_list()

        Enum.all?(filtered, fn packet ->
          cmp_start = DateTime.compare(packet.timestamp, start_time)
          cmp_end = DateTime.compare(packet.timestamp, end_time)

          assert cmp_start != :lt, "timestamp should be >= start_time"
          assert cmp_end != :gt, "timestamp should be <= end_time"
        end)
      end
    end

    property "by_time_range never increases count" do
      check all packets <- packet_list_generator(),
                {start_time, end_time} <- time_range_generator() do
        filtered = packets |> Filter.by_time_range(start_time, end_time) |> Enum.to_list()

        assert length(filtered) <= length(packets)
      end
    end
  end

  describe "Filter.after_time/2" do
    property "all filtered packets are after or at time" do
      check all packets <- packet_list_generator(),
                time <- datetime_generator() do
        filtered = packets |> Filter.after_time(time) |> Enum.to_list()

        Enum.all?(filtered, fn packet ->
          cmp = DateTime.compare(packet.timestamp, time)
          assert cmp != :lt, "timestamp should be >= time"
        end)
      end
    end
  end

  describe "Filter.before_time/2" do
    property "all filtered packets are before or at time" do
      check all packets <- packet_list_generator(),
                time <- datetime_generator() do
        filtered = packets |> Filter.before_time(time) |> Enum.to_list()

        Enum.all?(filtered, fn packet ->
          cmp = DateTime.compare(packet.timestamp, time)
          assert cmp != :gt, "timestamp should be <= time"
        end)
      end
    end
  end

  describe "Filter.limit/2" do
    property "limit returns at most N packets" do
      check all packets <- packet_list_generator(),
                n <- integer(0..200) do
        limited = packets |> Filter.limit(n) |> Enum.to_list()

        assert length(limited) <= n
        assert length(limited) <= length(packets)
      end
    end

    property "limit preserves order" do
      check all packets <- packet_list_generator(min_length: 5, max_length: 50),
                n <- integer(1..10) do
        limited = packets |> Filter.limit(n) |> Enum.to_list()

        # Limited packets should be the first N packets
        expected = Enum.take(packets, n)
        assert limited == expected
      end
    end

    property "limit 0 returns empty list" do
      check all packets <- packet_list_generator() do
        limited = packets |> Filter.limit(0) |> Enum.to_list()

        assert limited == []
      end
    end
  end

  describe "Filter.skip/2" do
    property "skip removes first N packets" do
      check all packets <- packet_list_generator(min_length: 5, max_length: 50),
                n <- integer(0..10) do
        skipped = packets |> Filter.skip(n) |> Enum.to_list()

        expected = Enum.drop(packets, n)
        assert skipped == expected
      end
    end

    property "skip + limit equals slicing" do
      check all packets <- packet_list_generator(min_length: 10, max_length: 50),
                skip_n <- integer(0..10),
                limit_n <- integer(1..20) do
        result =
          packets
          |> Filter.skip(skip_n)
          |> Filter.limit(limit_n)
          |> Enum.to_list()

        expected =
          packets
          |> Enum.drop(skip_n)
          |> Enum.take(limit_n)

        assert result == expected
      end
    end
  end

  describe "Filter.sample/2" do
    property "sample returns every Nth packet" do
      check all packets <- packet_list_generator(min_length: 10, max_length: 100),
                n <- integer(1..10) do
        sampled = packets |> Filter.sample(n) |> Enum.to_list()

        # Should have roughly length(packets) / n items
        expected_count = div(length(packets), n) + if rem(length(packets), n) > 0, do: 1, else: 0
        assert length(sampled) == expected_count or length(sampled) == expected_count - 1
      end
    end

    property "sample never increases count" do
      check all packets <- packet_list_generator(),
                n <- integer(1..20) do
        sampled = packets |> Filter.sample(n) |> Enum.to_list()

        assert length(sampled) <= length(packets)
      end
    end

    property "sample with n=1 returns all packets" do
      check all packets <- packet_list_generator() do
        sampled = packets |> Filter.sample(1) |> Enum.to_list()

        assert sampled == packets
      end
    end
  end

  describe "Filter.contains/2" do
    property "contains never increases count" do
      check all packets <- packet_list_generator(),
                pattern <- binary(min_length: 1, max_length: 10) do
        filtered = packets |> Filter.contains(pattern) |> Enum.to_list()

        assert length(filtered) <= length(packets)
      end
    end

    property "all filtered packets contain the pattern" do
      check all packets <- packet_list_generator(),
                pattern <- binary(min_length: 1, max_length: 10) do
        filtered = packets |> Filter.contains(pattern) |> Enum.to_list()

        Enum.all?(filtered, fn packet ->
          assert :binary.match(packet.data, pattern) != :nomatch,
                 "packet should contain pattern"
        end)
      end
    end
  end

  describe "Filter composition" do
    property "filter order doesn't affect final count when combining by_size filters" do
      check all packets <- packet_list_generator(),
                range1 <- size_range_generator(),
                range2 <- size_range_generator() do
        # Filter by range1 then range2
        result1 =
          packets
          |> Filter.by_size(range1)
          |> Filter.by_size(range2)
          |> Enum.to_list()

        # Filter by range2 then range1
        result2 =
          packets
          |> Filter.by_size(range2)
          |> Filter.by_size(range1)
          |> Enum.to_list()

        # Both should have the same count (order doesn't matter for set operations)
        assert length(result1) == length(result2)
      end
    end

    property "multiple filters reduce count monotonically" do
      check all packets <- packet_list_generator(),
                threshold1 <- size_threshold_generator(),
                threshold2 <- size_threshold_generator() do
        # Each filter should reduce or maintain the count
        filtered1 = packets |> Filter.larger_than(threshold1) |> Enum.to_list()
        filtered2 = filtered1 |> Filter.larger_than(threshold2) |> Enum.to_list()

        assert length(packets) >= length(filtered1)
        assert length(filtered1) >= length(filtered2)
      end
    end
  end
end
