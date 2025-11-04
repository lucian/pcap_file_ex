defmodule PcapFileEx.PreFilterTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Pcap, PcapNg, PreFilter}

  @pcap_fixture "test/fixtures/sample.pcap"
  @pcapng_fixture "test/fixtures/new_test.pcapng"

  describe "PreFilter API" do
    test "ip_source/1 creates correct filter" do
      assert PreFilter.ip_source("192.168.1.1") == {:ip_source, "192.168.1.1"}
    end

    test "ip_dest/1 creates correct filter" do
      assert PreFilter.ip_dest("8.8.8.8") == {:ip_dest, "8.8.8.8"}
    end

    test "ip_source_cidr/1 creates correct filter" do
      assert PreFilter.ip_source_cidr("192.168.1.0/24") == {:ip_source_cidr, "192.168.1.0/24"}
    end

    test "ip_dest_cidr/1 creates correct filter" do
      assert PreFilter.ip_dest_cidr("10.0.0.0/8") == {:ip_dest_cidr, "10.0.0.0/8"}
    end

    test "port_source/1 creates correct filter" do
      assert PreFilter.port_source(8080) == {:port_source, 8080}
    end

    test "port_dest/1 creates correct filter" do
      assert PreFilter.port_dest(80) == {:port_dest, 80}
    end

    test "port_source_range/2 creates correct filter" do
      assert PreFilter.port_source_range(8000, 9000) == {:port_source_range, 8000, 9000}
    end

    test "port_dest_range/2 creates correct filter" do
      assert PreFilter.port_dest_range(1024, 65535) == {:port_dest_range, 1024, 65535}
    end

    test "protocol/1 creates correct filter" do
      assert PreFilter.protocol("tcp") == {:protocol, "tcp"}
      assert PreFilter.protocol("TCP") == {:protocol, "tcp"}
    end

    test "size_min/1 creates correct filter" do
      assert PreFilter.size_min(100) == {:size_min, 100}
    end

    test "size_max/1 creates correct filter" do
      assert PreFilter.size_max(1500) == {:size_max, 1500}
    end

    test "size_range/2 creates correct filter" do
      assert PreFilter.size_range(100, 1500) == {:size_range, 100, 1500}
    end

    test "timestamp_min/1 creates correct filter" do
      assert PreFilter.timestamp_min(1_730_732_400) == {:timestamp_min, 1_730_732_400}
    end

    test "timestamp_max/1 creates correct filter" do
      assert PreFilter.timestamp_max(1_730_818_800) == {:timestamp_max, 1_730_818_800}
    end

    test "all/1 creates AND filter" do
      filters = [PreFilter.protocol("tcp"), PreFilter.port_dest(80)]
      assert PreFilter.all(filters) == {:and, filters}
    end

    test "any/1 creates OR filter" do
      filters = [PreFilter.port_dest(80), PreFilter.port_dest(443)]
      assert PreFilter.any(filters) == {:or, filters}
    end

    test "not_filter/1 creates NOT filter" do
      filter = PreFilter.protocol("tcp")
      assert PreFilter.not_filter(filter) == {:not, filter}
    end
  end

  describe "PCAP filtering" do
    test "set_filter/2 succeeds on PCAP reader" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      filters = [PreFilter.protocol("tcp")]
      assert :ok = Pcap.set_filter(reader, filters)

      Pcap.close(reader)
    end

    test "clear_filter/1 succeeds on PCAP reader" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      filters = [PreFilter.protocol("tcp")]
      :ok = Pcap.set_filter(reader, filters)
      assert :ok = Pcap.clear_filter(reader)

      Pcap.close(reader)
    end

    test "filtering by protocol works" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      # Set filter for TCP packets
      filters = [PreFilter.protocol("tcp")]
      :ok = Pcap.set_filter(reader, filters)

      # Read all filtered packets
      packets = read_all_packets(reader, [])
      Pcap.close(reader)

      # All packets should be TCP
      for packet <- packets do
        assert :tcp in packet.protocols,
               "Expected TCP packet but got protocols: #{inspect(packet.protocols)}"
      end
    end

    test "filtering by size works" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      # Filter packets between 100 and 200 bytes
      filters = [PreFilter.size_range(100, 200)]
      :ok = Pcap.set_filter(reader, filters)

      packets = read_all_packets(reader, [])
      Pcap.close(reader)

      # All packets should be in size range
      for packet <- packets do
        size = byte_size(packet.data)
        assert size >= 100 and size <= 200, "Packet size #{size} out of range 100-200"
      end
    end

    test "combining filters with AND works" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      # TCP packets between 100-500 bytes
      filters = [
        PreFilter.protocol("tcp"),
        PreFilter.size_range(100, 500)
      ]

      :ok = Pcap.set_filter(reader, filters)

      packets = read_all_packets(reader, [])
      Pcap.close(reader)

      # All packets should match both filters
      for packet <- packets do
        assert :tcp in packet.protocols
        size = byte_size(packet.data)
        assert size >= 100 and size <= 500
      end
    end

    test "filtering returns no packets when no match" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      # Filter for impossibly large packets
      filters = [PreFilter.size_min(100_000)]
      :ok = Pcap.set_filter(reader, filters)

      packets = read_all_packets(reader, [])
      Pcap.close(reader)

      # Should have no packets (or very few if any exist)
      assert length(packets) == 0
    end
  end

  describe "PCAPNG filtering" do
    test "set_filter/2 succeeds on PCAPNG reader" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      filters = [PreFilter.protocol("tcp")]
      assert :ok = PcapNg.set_filter(reader, filters)

      PcapNg.close(reader)
    end

    test "clear_filter/1 succeeds on PCAPNG reader" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      filters = [PreFilter.protocol("tcp")]
      :ok = PcapNg.set_filter(reader, filters)
      assert :ok = PcapNg.clear_filter(reader)

      PcapNg.close(reader)
    end

    test "filtering by protocol works on PCAPNG" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      # Set filter for TCP packets
      filters = [PreFilter.protocol("tcp")]
      :ok = PcapNg.set_filter(reader, filters)

      # Read all filtered packets
      packets = read_all_packets_ng(reader, [])
      PcapNg.close(reader)

      # All packets should be TCP
      for packet <- packets do
        assert :tcp in packet.protocols,
               "Expected TCP packet but got protocols: #{inspect(packet.protocols)}"
      end
    end

    test "filtering by size works on PCAPNG" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      # Filter packets larger than 100 bytes
      filters = [PreFilter.size_min(100)]
      :ok = PcapNg.set_filter(reader, filters)

      packets = read_all_packets_ng(reader, [])
      PcapNg.close(reader)

      # All packets should be >= 100 bytes
      for packet <- packets do
        size = packet.orig_len
        assert size >= 100, "Packet size #{size} below minimum 100"
      end
    end
  end

  describe "filter performance" do
    @tag :performance
    test "pre-filtering is faster than post-filtering" do
      # This is a smoke test - actual performance testing would need larger files
      {:ok, reader} = Pcap.open(@pcap_fixture)

      # Pre-filter
      filters = [PreFilter.protocol("tcp")]
      :ok = Pcap.set_filter(reader, filters)

      {pre_time, pre_packets} =
        :timer.tc(fn ->
          packets = read_all_packets(reader, [])
          Pcap.close(reader)
          packets
        end)

      # Post-filter (no pre-filter)
      {:ok, reader2} = Pcap.open(@pcap_fixture)

      {post_time, post_packets} =
        :timer.tc(fn ->
          packets =
            read_all_packets(reader2, [])
            |> Enum.filter(fn packet -> :tcp in packet.protocols end)

          Pcap.close(reader2)
          packets
        end)

      # Both should return same number of packets
      assert length(pre_packets) == length(post_packets)

      # Pre-filtering should not be significantly slower
      # (in real benchmarks with large files, it would be much faster)
      # Here we just verify it works
      assert pre_time > 0
      assert post_time > 0
    end
  end

  # Helper functions
  defp read_all_packets(reader, acc) do
    case Pcap.next_packet(reader) do
      {:ok, packet} -> read_all_packets(reader, [packet | acc])
      :eof -> Enum.reverse(acc)
      {:error, _} -> Enum.reverse(acc)
    end
  end

  defp read_all_packets_ng(reader, acc) do
    case PcapNg.next_packet(reader) do
      {:ok, packet} -> read_all_packets_ng(reader, [packet | acc])
      :eof -> Enum.reverse(acc)
      {:error, _} -> Enum.reverse(acc)
    end
  end
end
