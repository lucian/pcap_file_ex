defmodule PcapFileEx.PcapTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Endpoint, Header, Packet, Pcap}

  @test_pcap_file "test/fixtures/sample.pcap"

  describe "open/1" do
    test "opens a valid PCAP file" do
      assert {:ok, reader} = Pcap.open(@test_pcap_file)
      assert %Pcap{} = reader
      assert %Header{} = reader.header
      assert reader.path == @test_pcap_file
      Pcap.close(reader)
    end

    test "returns error for non-existent file" do
      assert {:error, _reason} = Pcap.open("non_existent.pcap")
    end

    test "returns error for invalid PCAP file" do
      invalid_file = "test/fixtures/invalid.pcap"
      File.write!(invalid_file, "not a pcap file")

      assert {:error, _reason} = Pcap.open(invalid_file)

      File.rm!(invalid_file)
    end
  end

  describe "header" do
    test "reads PCAP header correctly" do
      {:ok, reader} = Pcap.open(@test_pcap_file)
      header = reader.header

      assert is_integer(header.version_major)
      assert is_integer(header.version_minor)
      assert is_integer(header.snaplen)
      assert is_binary(header.datalink)
      assert header.ts_resolution in ["microsecond", "nanosecond"]
      assert header.endianness in ["big", "little"]

      Pcap.close(reader)
    end
  end

  describe "next_packet/1" do
    test "reads packets from PCAP file" do
      {:ok, reader} = Pcap.open(@test_pcap_file)

      # Read first packet
      assert {:ok, packet} = Pcap.next_packet(reader)
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

      Pcap.close(reader)
    end

    test "returns :eof when no more packets" do
      {:ok, reader} = Pcap.open(@test_pcap_file)

      # Read all packets until EOF
      result =
        Stream.repeatedly(fn -> Pcap.next_packet(reader) end)
        |> Enum.take_while(fn
          {:ok, _} -> true
          :eof -> false
          {:error, _} -> false
        end)

      refute Enum.empty?(result)

      # Next read should be EOF
      assert :eof = Pcap.next_packet(reader)

      Pcap.close(reader)
    end
  end

  describe "read_all/1" do
    test "reads all packets at once" do
      assert {:ok, packets} = Pcap.read_all(@test_pcap_file)
      assert is_list(packets)
      refute Enum.empty?(packets)

      # Verify all packets are valid
      Enum.each(packets, fn packet ->
        assert %Packet{} = packet
        assert %DateTime{} = packet.timestamp
        assert is_integer(packet.orig_len)
        assert is_binary(packet.data)
        assert is_list(packet.protocols)
        if packet.protocol, do: assert(List.last(packet.protocols) == packet.protocol)

        if packet.src do
          assert %Endpoint{} = packet.src
        end

        if packet.dst do
          assert %Endpoint{} = packet.dst
        end
      end)
    end

    test "reads HTTP traffic correctly" do
      assert {:ok, packets} = Pcap.read_all(@test_pcap_file)

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

  describe "close/1" do
    test "closes reader successfully" do
      {:ok, reader} = Pcap.open(@test_pcap_file)
      assert :ok = Pcap.close(reader)
    end
  end

  describe "packet data integrity" do
    test "packets have reasonable sizes" do
      {:ok, packets} = Pcap.read_all(@test_pcap_file)

      Enum.each(packets, fn packet ->
        # Ethernet frames are typically 64-1518 bytes
        # But with jumbo frames, could be larger
        assert packet.orig_len > 0
        assert packet.orig_len < 65_536
        assert byte_size(packet.data) > 0
      end)
    end

    test "timestamps are in chronological order" do
      {:ok, packets} = Pcap.read_all(@test_pcap_file)

      # Check that timestamps are generally increasing
      # (allowing for some reordering in network captures)
      timestamps = Enum.map(packets, & &1.timestamp)
      first_timestamp = List.first(timestamps)
      last_timestamp = List.last(timestamps)

      assert DateTime.compare(last_timestamp, first_timestamp) in [:gt, :eq]
    end
  end
end
