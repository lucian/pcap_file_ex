defmodule PcapFileEx.PcapNgTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Endpoint, Packet, PcapNg}

  @test_pcapng_file "test/fixtures/sample.pcapng"
  @multi_interface_pcapng "test/fixtures/sample_multi_nanosecond.pcapng"

  describe "open/1" do
    test "opens a valid PCAPNG file" do
      if File.exists?(@test_pcapng_file) do
        assert {:ok, reader} = PcapNg.open(@test_pcapng_file)
        assert %PcapNg{} = reader
        assert reader.path == @test_pcapng_file
        PcapNg.close(reader)
      else
        IO.puts("\nSkipping test - no test file at #{@test_pcapng_file}")
        IO.puts("Generate one with: cd test/fixtures && ./capture_test_traffic.sh")
      end
    end

    test "returns error for non-existent file" do
      assert {:error, _reason} = PcapNg.open("non_existent.pcapng")
    end

    test "returns error for invalid PCAPNG file" do
      invalid_file = "test/fixtures/invalid.pcapng"
      File.write!(invalid_file, "not a pcapng file")

      assert {:error, _reason} = PcapNg.open(invalid_file)

      File.rm!(invalid_file)
    end
  end

  describe "next_packet/1" do
    test "reads packets from PCAPNG file" do
      if File.exists?(@test_pcapng_file) do
        {:ok, reader} = PcapNg.open(@test_pcapng_file)

        # Read first packet
        assert {:ok, packet} = PcapNg.next_packet(reader)
        assert %Packet{} = packet
        assert %DateTime{} = packet.timestamp
        assert is_integer(packet.orig_len)
        assert is_binary(packet.data)
        assert byte_size(packet.data) > 0
        assert packet.protocol in [nil, :tcp, :udp, :icmp, :icmp6, :http]
        assert is_list(packet.protocols)
        if packet.protocol, do: assert(List.last(packet.protocols) == packet.protocol)

        if packet.src do
          assert %Endpoint{ip: ip} = packet.src
          assert is_binary(ip)
        end

        if packet.dst do
          assert %Endpoint{ip: ip} = packet.dst
          assert is_binary(ip)
        end

        assert packet.timestamp_resolution in [nil, :microsecond, :nanosecond, :unknown]

        if packet.interface do
          assert packet.interface_id == packet.interface.id
        end

        assert {:ok, decoded} = Packet.pkt_decode(packet)
        assert decoded == Packet.pkt_decode!(packet)

        PcapNg.close(reader)
      end
    end

    test "returns :eof when no more packets" do
      if File.exists?(@test_pcapng_file) do
        {:ok, reader} = PcapNg.open(@test_pcapng_file)

        # Read all packets until EOF
        result =
          Stream.repeatedly(fn -> PcapNg.next_packet(reader) end)
          |> Enum.take_while(fn
            {:ok, _} -> true
            :eof -> false
            {:error, _} -> false
          end)

        refute Enum.empty?(result)

        # Next read should be EOF
        assert :eof = PcapNg.next_packet(reader)

        PcapNg.close(reader)
      end
    end
  end

  describe "read_all/1" do
    test "reads all packets at once" do
      if File.exists?(@test_pcapng_file) do
        assert {:ok, packets} = PcapNg.read_all(@test_pcapng_file)
        assert is_list(packets)
        refute Enum.empty?(packets)

        # Verify all packets are valid
        Enum.each(packets, fn packet ->
          assert %Packet{} = packet
          assert %DateTime{} = packet.timestamp
          assert is_integer(packet.orig_len)
          assert is_binary(packet.data)
          assert packet.protocol in [nil, :tcp, :udp, :icmp, :icmp6, :http]
          assert is_list(packet.protocols)
          if packet.protocol, do: assert(List.last(packet.protocols) == packet.protocol)

          if packet.src do
            assert %Endpoint{} = packet.src
          end

          if packet.dst do
            assert %Endpoint{} = packet.dst
          end

          assert {:ok, decoded} = Packet.pkt_decode(packet)
          assert decoded == Packet.pkt_decode!(packet)
        end)
      end
    end

    test "reads HTTP traffic correctly" do
      if File.exists?(@test_pcapng_file) do
        assert {:ok, packets} = PcapNg.read_all(@test_pcapng_file)

        # The test capture should contain HTTP traffic
        # (5 requests to /hello + 5 to /json = 10 total requests + responses)
        # Each request/response generates multiple packets (TCP handshake, data, etc.)
        assert length(packets) > 10

        # All packets should have valid timestamps
        Enum.each(packets, fn packet ->
          assert packet.timestamp.year >= 2024
          assert packet.timestamp.month in 1..12
          if packet.src, do: assert(String.length(Packet.endpoint_to_string(packet.src)) > 0)
          if packet.dst, do: assert(String.length(Packet.endpoint_to_string(packet.dst)) > 0)
        end)
      end
    end
  end

  describe "close/1" do
    test "closes reader successfully" do
      if File.exists?(@test_pcapng_file) do
        {:ok, reader} = PcapNg.open(@test_pcapng_file)
        assert :ok = PcapNg.close(reader)
      end
    end
  end

  describe "packet data integrity" do
    test "packets have reasonable sizes" do
      if File.exists?(@test_pcapng_file) do
        {:ok, packets} = PcapNg.read_all(@test_pcapng_file)

        Enum.each(packets, fn packet ->
          # Ethernet frames are typically 64-1518 bytes
          # But with jumbo frames, could be larger
          assert packet.orig_len > 0
          assert packet.orig_len < 65_536
          assert byte_size(packet.data) > 0
        end)
      end
    end

    test "timestamps are in chronological order" do
      if File.exists?(@test_pcapng_file) do
        {:ok, packets} = PcapNg.read_all(@test_pcapng_file)

        # Check that timestamps are generally increasing
        # (allowing for some reordering in network captures)
        timestamps = Enum.map(packets, & &1.timestamp)
        first_timestamp = List.first(timestamps)
        last_timestamp = List.last(timestamps)

        assert DateTime.compare(last_timestamp, first_timestamp) in [:gt, :eq]
      end
    end
  end

  describe "interfaces/1" do
    test "returns interface metadata for multi-interface captures" do
      if File.exists?(@multi_interface_pcapng) do
        {:ok, reader} = PcapNg.open(@multi_interface_pcapng)
        assert {:ok, packet} = PcapNg.next_packet(reader)

        assert is_integer(packet.interface_id)
        assert packet.interface
        assert packet.timestamp_resolution in [:microsecond, :nanosecond, :unknown]

        assert {:ok, interfaces} = PcapNg.interfaces(reader)
        assert length(interfaces) >= 2
        assert Enum.any?(interfaces, &(&1.id == packet.interface_id))

        matching = Enum.find(interfaces, &(&1.id == packet.interface_id))
        refute is_nil(matching)
        assert matching.linktype == packet.interface.linktype

        PcapNg.close(reader)
      else
        IO.puts("\nSkipping multi-interface test - no test file at #{@multi_interface_pcapng}")

        IO.puts(
          "Generate one with: cd test/fixtures && ./capture_test_traffic.sh --interfaces lo0,en0 --nanosecond"
        )
      end
    end
  end
end
