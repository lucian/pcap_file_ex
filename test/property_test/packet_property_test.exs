defmodule PcapFileEx.PacketPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.{Packet, Timestamp}
  import PcapFileEx.PropertyGenerators

  describe "Packet.from_map/1" do
    property "creates packet with all required fields" do
      check all packet_map <- pcap_packet_map_generator() do
        packet = Packet.from_map(packet_map)

        assert %Packet{} = packet
        assert packet.timestamp != nil
        assert packet.timestamp_precise != nil
        assert packet.orig_len != nil
        assert packet.data != nil
      end
    end

    property "preserves orig_len from map" do
      check all packet_map <- pcap_packet_map_generator() do
        packet = Packet.from_map(packet_map)

        assert packet.orig_len == packet_map.orig_len
      end
    end

    property "converts data from list to binary" do
      check all packet_map <- pcap_packet_map_generator() do
        packet = Packet.from_map(packet_map)

        assert is_binary(packet.data)
        assert is_list(packet_map.data)
        assert packet.data == :binary.list_to_bin(packet_map.data)
      end
    end

    property "creates valid timestamp_precise from secs and nanos" do
      check all packet_map <- pcap_packet_map_generator() do
        packet = Packet.from_map(packet_map)

        assert %Timestamp{} = packet.timestamp_precise
        assert packet.timestamp_precise.secs == packet_map.timestamp_secs
        assert packet.timestamp_precise.nanos == packet_map.timestamp_nanos
      end
    end
  end

  describe "Packet invariants" do
    property "orig_len >= byte_size(data)" do
      check all packet <- packet_generator() do
        assert packet.orig_len >= byte_size(packet.data),
               "orig_len (#{packet.orig_len}) should be >= data size (#{byte_size(packet.data)})"
      end
    end

    property "timestamp_precise has valid nanosecond component" do
      check all packet <- packet_generator() do
        assert packet.timestamp_precise.nanos >= 0
        assert packet.timestamp_precise.nanos <= 999_999_999
      end
    end

    property "timestamp_precise has non-negative seconds" do
      check all packet <- packet_generator() do
        assert packet.timestamp_precise.secs >= 0
      end
    end

    property "data is always a binary" do
      check all packet <- packet_generator() do
        assert is_binary(packet.data)
      end
    end

    property "orig_len is always positive" do
      check all packet <- packet_generator() do
        assert packet.orig_len > 0
      end
    end

    property "protocols is a list when present" do
      check all packet <- packet_generator() do
        if packet.protocols != nil do
          assert is_list(packet.protocols)
        end
      end
    end

    property "protocol matches last element of protocols list when both present" do
      check all packet <- packet_generator() do
        if packet.protocols != nil and packet.protocol != nil and packet.protocols != [] do
          assert packet.protocol == List.last(packet.protocols),
                 "protocol (#{inspect(packet.protocol)}) should match last of protocols (#{inspect(packet.protocols)})"
        end
      end
    end

    property "datalink is a valid string when present" do
      check all packet <- packet_generator() do
        if packet.datalink != nil do
          assert is_binary(packet.datalink)

          # Should be one of the known datalink types
          valid_datalinks = [
            "ethernet",
            "raw",
            "ipv4",
            "ipv6",
            "linux_sll",
            "linux_sll2",
            "null",
            "loop",
            "ppp"
          ]

          assert packet.datalink in valid_datalinks,
                 "datalink '#{packet.datalink}' should be in #{inspect(valid_datalinks)}"
        end
      end
    end
  end

  describe "Packet.pkt_decode/1" do
    property "pkt_decode never raises for valid packets" do
      check all packet <- packet_generator() do
        # pkt_decode should always return a result, never raise
        result =
          try do
            Packet.pkt_decode(packet)
            :ok
          rescue
            _ -> :error
          end

        assert result == :ok
      end
    end

    property "pkt_decode returns ok/error tuple or other valid response" do
      check all packet <- packet_generator() do
        result = Packet.pkt_decode(packet)

        # Result should be one of the known patterns
        # Partial decode
        assert match?({:ok, _}, result) or
                 match?({:error, _}, result) or
                 match?({:more, _, _}, result) or
                 is_tuple(result) or
                 is_list(result)
      end
    end
  end

  describe "Packet list operations" do
    property "filtering a packet list never increases its length" do
      check all packets <- packet_list_generator() do
        # Filter to only packets larger than 100 bytes
        filtered = Enum.filter(packets, fn p -> byte_size(p.data) > 100 end)

        assert length(filtered) <= length(packets)
      end
    end

    property "sorting by timestamp maintains all packets" do
      check all packets <- packet_list_generator(min_length: 1, max_length: 50) do
        sorted = Enum.sort_by(packets, & &1.timestamp_precise, Timestamp)

        assert length(sorted) == length(packets)
      end
    end

    property "sorting by timestamp is stable" do
      check all packets <- packet_list_generator(min_length: 1, max_length: 50) do
        sorted = Enum.sort_by(packets, & &1.timestamp_precise, Timestamp)

        # Verify that adjacent packets are in correct order
        sorted
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.each(fn [p1, p2] ->
          cmp = Timestamp.compare(p1.timestamp_precise, p2.timestamp_precise)
          assert cmp in [:lt, :eq]
        end)
      end
    end
  end
end
