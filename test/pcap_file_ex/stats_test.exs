defmodule PcapFileEx.StatsTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.Stats

  @test_pcap_file "test/fixtures/sample.pcap"
  @test_pcapng_file "test/fixtures/sample.pcapng"

  setup_all do
    {:ok, pcap_packets} = PcapFileEx.read_all(@test_pcap_file)
    {:ok, pcapng_packets} = PcapFileEx.read_all(@test_pcapng_file)

    %{
      pcap_packets: pcap_packets,
      pcapng_packets: pcapng_packets,
      pcap_count: length(pcap_packets),
      pcapng_count: length(pcapng_packets)
    }
  end

  describe "compute/1" do
    test "computes statistics for PCAP file", %{pcap_count: expected_count} do
      assert {:ok, stats} = Stats.compute(@test_pcap_file)

      assert stats.packet_count == expected_count
      assert stats.total_bytes > 0
      assert stats.min_packet_size > 0
      assert stats.max_packet_size > stats.min_packet_size
      assert stats.avg_packet_size > 0
      assert %DateTime{} = stats.first_timestamp
      assert %DateTime{} = stats.last_timestamp
      assert stats.duration_seconds >= 0
    end

    test "computes statistics for PCAPNG file", %{pcapng_count: expected_count} do
      assert {:ok, stats} = Stats.compute(@test_pcapng_file)

      assert stats.packet_count == expected_count
      assert stats.total_bytes > 0
      assert is_float(stats.avg_packet_size)
    end

    test "returns error for non-existent file" do
      assert {:error, _reason} = Stats.compute("nonexistent.pcap")
    end
  end

  describe "compute_from_packets/1" do
    test "computes statistics from packet list", %{
      pcap_packets: packets,
      pcap_count: expected_count
    } do
      stats = Stats.compute_from_packets(packets)

      assert stats.packet_count == expected_count
      assert stats.total_bytes > 0
    end

    test "handles empty packet list" do
      stats = Stats.compute_from_packets([])

      assert stats.packet_count == 0
      assert stats.total_bytes == 0
      assert stats.min_packet_size == nil
      assert stats.first_timestamp == nil
    end
  end

  describe "packet_count/1" do
    test "counts packets in PCAP file", %{pcap_count: expected_count} do
      assert {:ok, count} = Stats.packet_count(@test_pcap_file)
      assert count == expected_count
    end

    test "counts packets in PCAPNG file", %{pcapng_count: expected_count} do
      assert {:ok, count} = Stats.packet_count(@test_pcapng_file)
      assert count == expected_count
    end
  end

  describe "total_bytes/1" do
    test "sums total bytes in PCAP file" do
      assert {:ok, bytes} = Stats.total_bytes(@test_pcap_file)
      assert is_integer(bytes)
      assert bytes > 0
    end

    test "sums total bytes in PCAPNG file" do
      assert {:ok, bytes} = Stats.total_bytes(@test_pcapng_file)
      assert is_integer(bytes)
      assert bytes > 0
    end
  end

  describe "time_range/1" do
    test "gets time range from PCAP file" do
      assert {:ok, {first, last}} = Stats.time_range(@test_pcap_file)
      assert %DateTime{} = first
      assert %DateTime{} = last
      assert DateTime.compare(last, first) in [:gt, :eq]
    end

    test "gets time range from PCAPNG file" do
      assert {:ok, {first, last}} = Stats.time_range(@test_pcapng_file)
      assert %DateTime{} = first
      assert %DateTime{} = last
    end
  end

  describe "duration/1" do
    test "computes duration for PCAP file" do
      assert {:ok, duration} = Stats.duration(@test_pcap_file)
      assert is_float(duration)
      assert duration >= 0
    end

    test "computes duration for PCAPNG file" do
      assert {:ok, duration} = Stats.duration(@test_pcapng_file)
      assert is_float(duration)
      assert duration >= 0
    end
  end

  describe "size_distribution/1" do
    test "computes size distribution for PCAP file" do
      assert {:ok, dist} = Stats.size_distribution(@test_pcap_file)

      assert dist.min > 0
      assert dist.max >= dist.min
      assert dist.median > 0
      assert dist.p95 > 0
      assert dist.p99 > 0
    end

    test "computes size distribution for PCAPNG file" do
      assert {:ok, dist} = Stats.size_distribution(@test_pcapng_file)

      assert dist.min > 0
      assert is_float(dist.median)
    end
  end

  describe "compute_streaming/1" do
    test "computes same statistics as compute/1 for PCAP file", %{pcap_count: expected_count} do
      # Compute using both methods
      assert {:ok, regular_stats} = Stats.compute(@test_pcap_file)
      assert {:ok, streaming_stats} = Stats.compute_streaming(@test_pcap_file)

      # Should produce identical results
      assert streaming_stats.packet_count == regular_stats.packet_count
      assert streaming_stats.packet_count == expected_count
      assert streaming_stats.total_bytes == regular_stats.total_bytes
      assert streaming_stats.min_packet_size == regular_stats.min_packet_size
      assert streaming_stats.max_packet_size == regular_stats.max_packet_size
      assert streaming_stats.avg_packet_size == regular_stats.avg_packet_size
      assert streaming_stats.first_timestamp == regular_stats.first_timestamp
      assert streaming_stats.last_timestamp == regular_stats.last_timestamp
      assert streaming_stats.duration_seconds == regular_stats.duration_seconds
    end

    test "computes same statistics as compute/1 for PCAPNG file", %{pcapng_count: expected_count} do
      assert {:ok, regular_stats} = Stats.compute(@test_pcapng_file)
      assert {:ok, streaming_stats} = Stats.compute_streaming(@test_pcapng_file)

      assert streaming_stats.packet_count == regular_stats.packet_count
      assert streaming_stats.packet_count == expected_count
      assert streaming_stats.total_bytes == regular_stats.total_bytes
      assert_in_delta streaming_stats.avg_packet_size, regular_stats.avg_packet_size, 0.01
    end

    test "works with stream input (not just path)" do
      # Create stream and compute stats
      stats =
        PcapFileEx.stream!(@test_pcap_file)
        |> Stats.compute_streaming()

      assert stats.packet_count > 0
      assert stats.total_bytes > 0
      assert is_float(stats.avg_packet_size)
    end

    test "works with filtered stream", %{pcap_count: total_count} do
      # Get all TCP packets
      all_tcp_count =
        PcapFileEx.stream!(@test_pcap_file)
        |> Enum.filter(fn packet -> :tcp in packet.protocols end)
        |> length()

      # Compute stats only for TCP packets
      tcp_stats =
        PcapFileEx.stream!(@test_pcap_file)
        |> Stream.filter(fn packet -> :tcp in packet.protocols end)
        |> Stats.compute_streaming()

      # Should only count TCP packets
      assert tcp_stats.packet_count == all_tcp_count
      assert tcp_stats.packet_count <= total_count
      assert tcp_stats.total_bytes > 0
    end

    test "handles empty stream" do
      empty_stream = Stream.filter([1, 2, 3], fn _ -> false end)
      stats = Stats.compute_streaming(empty_stream)

      assert stats.packet_count == 0
      assert stats.total_bytes == 0
      assert stats.min_packet_size == nil
      assert stats.max_packet_size == 0
      assert stats.avg_packet_size == 0.0
      assert stats.first_timestamp == nil
      assert stats.last_timestamp == nil
      assert stats.duration_seconds == nil
    end

    test "constant memory usage (spot check with take)" do
      # This test verifies streaming works by taking only first N packets
      # If it loaded all into memory, this would be slow for large files
      stats =
        PcapFileEx.stream!(@test_pcap_file)
        |> Stream.take(5)
        |> Stats.compute_streaming()

      assert stats.packet_count == 5
      assert stats.total_bytes > 0
    end

    test "can be chained with other stream operations" do
      # Complex streaming pipeline
      stats =
        PcapFileEx.stream!(@test_pcap_file)
        |> Stream.filter(fn packet -> byte_size(packet.data) > 50 end)
        |> Stream.take(10)
        |> Stats.compute_streaming()

      assert stats.packet_count <= 10
      assert stats.min_packet_size > 50
    end

    test "returns error for non-existent file" do
      assert {:error, _reason} = Stats.compute_streaming("nonexistent.pcap")
    end
  end
end
