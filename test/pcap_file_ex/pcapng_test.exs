defmodule PcapFileEx.PcapNgTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{PcapNg, Packet}

  @test_pcapng_file "test/fixtures/sample.pcapng"

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

        assert length(result) > 0

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
        assert length(packets) > 0

        # Verify all packets are valid
        Enum.each(packets, fn packet ->
          assert %Packet{} = packet
          assert %DateTime{} = packet.timestamp
          assert is_integer(packet.orig_len)
          assert is_binary(packet.data)
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
          assert packet.orig_len < 65536
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
end
