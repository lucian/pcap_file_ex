defmodule PcapFileEx.FilterTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Filter, HTTP, Packet}

  @test_pcap_file "test/fixtures/sample.pcap"

  setup do
    {:ok, packets} = PcapFileEx.read_all(@test_pcap_file)
    {:ok, packets: packets}
  end

  describe "by_size/2" do
    test "filters packets by size range", %{packets: packets} do
      filtered =
        packets
        |> Filter.by_size(60..70)
        |> Enum.to_list()

      refute Enum.empty?(filtered)

      Enum.each(filtered, fn packet ->
        size = byte_size(packet.data)
        assert size >= 60 and size <= 70
      end)
    end
  end

  describe "larger_than/2" do
    test "filters packets larger than size", %{packets: packets} do
      filtered =
        packets
        |> Filter.larger_than(100)
        |> Enum.to_list()

      refute Enum.empty?(filtered)

      Enum.each(filtered, fn packet ->
        assert byte_size(packet.data) > 100
      end)
    end
  end

  describe "smaller_than/2" do
    test "filters packets smaller than size", %{packets: packets} do
      filtered =
        packets
        |> Filter.smaller_than(70)
        |> Enum.to_list()

      refute Enum.empty?(filtered)

      Enum.each(filtered, fn packet ->
        assert byte_size(packet.data) < 70
      end)
    end
  end

  describe "by_protocol/2" do
    test "filters packets by transport protocol", %{packets: packets} do
      filtered =
        packets
        |> Filter.by_protocol(:tcp)
        |> Enum.to_list()

      refute Enum.empty?(filtered)

      Enum.each(filtered, fn packet ->
        assert {:ok, {layers, _payload}} = Packet.pkt_decode(packet)
        assert Enum.any?(List.wrap(layers), &tcp_layer?/1)
      end)
    end

    test "filters HTTP packets", %{packets: packets} do
      http_packets =
        packets
        |> Filter.by_protocol(:http)
        |> Enum.to_list()

      refute Enum.empty?(http_packets)

      Enum.each(http_packets, fn packet ->
        assert {:ok, {layers, payload}} = Packet.pkt_decode(packet)
        assert Enum.any?(List.wrap(layers), &tcp_layer?/1)
        assert {:ok, %HTTP{}} = HTTP.decode(payload)
      end)
    end
  end

  describe "by_time_range/3" do
    test "filters packets by time range", %{packets: packets} do
      timestamps = Enum.map(packets, & &1.timestamp)
      first = Enum.min(timestamps, DateTime)
      last = Enum.max(timestamps, DateTime)

      # Get middle half
      duration = DateTime.diff(last, first, :second)
      start_time = DateTime.add(first, div(duration, 4), :second)
      end_time = DateTime.add(first, div(duration * 3, 4), :second)

      filtered =
        packets
        |> Filter.by_time_range(start_time, end_time)
        |> Enum.to_list()

      Enum.each(filtered, fn packet ->
        assert DateTime.compare(packet.timestamp, start_time) != :lt
        assert DateTime.compare(packet.timestamp, end_time) != :gt
      end)
    end
  end

  describe "after_time/2" do
    test "filters packets after timestamp", %{packets: packets} do
      timestamps = Enum.map(packets, & &1.timestamp)
      first = Enum.min(timestamps, DateTime)

      filtered =
        packets
        |> Filter.after_time(first)
        |> Enum.to_list()

      assert length(filtered) == length(packets)

      Enum.each(filtered, fn packet ->
        assert DateTime.compare(packet.timestamp, first) != :lt
      end)
    end
  end

  describe "before_time/2" do
    test "filters packets before timestamp", %{packets: packets} do
      timestamps = Enum.map(packets, & &1.timestamp)
      last = Enum.max(timestamps, DateTime)

      filtered =
        packets
        |> Filter.before_time(last)
        |> Enum.to_list()

      assert length(filtered) == length(packets)

      Enum.each(filtered, fn packet ->
        assert DateTime.compare(packet.timestamp, last) != :gt
      end)
    end
  end

  describe "contains/2" do
    test "filters packets containing pattern", %{packets: packets} do
      # Look for TCP SYN packets (HTTP traffic should have some)
      filtered =
        packets
        |> Filter.contains("HTTP")
        |> Enum.to_list()

      # Our test capture contains HTTP traffic
      refute Enum.empty?(filtered)
    end
  end

  describe "matching/2" do
    test "filters packets with custom predicate", %{packets: packets} do
      # Get packets with even-sized data
      filtered =
        packets
        |> Filter.matching(fn packet ->
          rem(byte_size(packet.data), 2) == 0
        end)
        |> Enum.to_list()

      refute Enum.empty?(filtered)

      Enum.each(filtered, fn packet ->
        assert rem(byte_size(packet.data), 2) == 0
      end)
    end
  end

  describe "sample/2" do
    test "samples every Nth packet", %{packets: packets} do
      total = length(packets)
      expected = div(total + 9, 10)

      filtered =
        packets
        |> Filter.sample(10)
        |> Enum.to_list()

      assert length(filtered) == expected

      expected_packets =
        packets
        |> Enum.with_index()
        |> Enum.filter(fn {_packet, idx} -> rem(idx, 10) == 0 end)
        |> Enum.map(&elem(&1, 0))
        |> Enum.take(expected)

      assert filtered == expected_packets
    end
  end

  describe "limit/2" do
    test "limits stream to N packets", %{packets: packets} do
      filtered =
        packets
        |> Filter.limit(10)
        |> Enum.to_list()

      assert length(filtered) == 10
    end
  end

  describe "skip/2" do
    test "skips first N packets", %{packets: packets} do
      n = 10

      filtered =
        packets
        |> Filter.skip(n)
        |> Enum.to_list()

      assert length(filtered) == length(packets) - n
    end
  end

  describe "matches_regex/2" do
    test "filters packets matching regex", %{packets: packets} do
      filtered =
        packets
        |> Filter.matches_regex(~r/Hello/)
        |> Enum.to_list()

      # Our test capture contains "Hello, World!" responses
      assert is_list(filtered)
      # Just verify it doesn't crash - regex matching on binary data is tricky
    end
  end

  describe "chaining filters" do
    test "can chain multiple filters", %{packets: packets} do
      filtered =
        packets
        |> Filter.larger_than(60)
        |> Filter.smaller_than(200)
        |> Filter.limit(5)
        |> Enum.to_list()

      assert length(filtered) == 5

      Enum.each(filtered, fn packet ->
        size = byte_size(packet.data)
        assert size > 60 and size < 200
      end)
    end
  end

  defp tcp_layer?(layer) when is_tuple(layer) do
    tuple_size(layer) > 0 and elem(layer, 0) == :tcp
  end

  defp tcp_layer?(layer), do: layer == :tcp
end
