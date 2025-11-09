defmodule PcapFileEx.DecodingPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.Packet
  import PcapFileEx.PropertyGenerators

  describe "Packet.pkt_decode/1 robustness" do
    property "pkt_decode never raises for valid packets" do
      check all packet <- packet_generator() do
        result =
          try do
            Packet.pkt_decode(packet)
            :ok
          rescue
            _ -> :error
          end

        assert result == :ok, "pkt_decode should not raise for valid packets"
      end
    end

    property "pkt_decode returns consistent result type" do
      check all packet <- packet_generator() do
        result = Packet.pkt_decode(packet)

        # Result should be one of the known valid patterns from :pkt library
        valid_result =
          match?({:ok, _}, result) or
            match?({:error, _}, result) or
            match?({:more, _, _}, result) or
            is_tuple(result) or
            is_list(result)

        assert valid_result, "pkt_decode should return a valid result type"
      end
    end

    property "pkt_decode on same packet produces same result" do
      check all packet <- packet_generator() do
        result1 = Packet.pkt_decode(packet)
        result2 = Packet.pkt_decode(packet)

        assert result1 == result2, "pkt_decode should be deterministic"
      end
    end
  end

  describe "Packet.pkt_protocol/1" do
    property "pkt_protocol always returns an atom" do
      check all packet <- packet_generator() do
        protocol = Packet.pkt_protocol(packet)

        assert is_atom(protocol),
               "pkt_protocol should return an atom, got: #{inspect(protocol)}"
      end
    end

    property "pkt_protocol is based on datalink" do
      check all packet <- packet_generator() do
        protocol = Packet.pkt_protocol(packet)

        # Protocol should be one of the known protocol atoms
        known_protocols = [
          :ether,
          :ipv4,
          :ipv6,
          :raw,
          :linux_cooked,
          :linux_cooked_v2,
          :null,
          :ppp
        ]

        assert protocol in known_protocols,
               "protocol #{inspect(protocol)} should be in known list"
      end
    end
  end

  describe "Packet endpoint extraction" do
    property "endpoint IPs have valid format when present" do
      check all packet <- packet_generator() do
        if packet.src do
          # IPv4 or IPv6 format
          assert packet.src.ip =~ ~r/^\d+\.\d+\.\d+\.\d+$/ or
                   packet.src.ip =~ ~r/^[0-9a-f:]+$/i,
                 "src IP should be valid IPv4 or IPv6 format"
        end

        if packet.dst do
          assert packet.dst.ip =~ ~r/^\d+\.\d+\.\d+\.\d+$/ or
                   packet.dst.ip =~ ~r/^[0-9a-f:]+$/i,
                 "dst IP should be valid IPv4 or IPv6 format"
        end
      end
    end

    property "endpoint ports are in valid range when present" do
      check all packet <- packet_generator() do
        if packet.src && packet.src.port do
          assert packet.src.port >= 0 and packet.src.port <= 65535,
                 "src port should be in valid range 0..65535"
        end

        if packet.dst && packet.dst.port do
          assert packet.dst.port >= 0 and packet.dst.port <= 65535,
                 "dst port should be in valid range 0..65535"
        end
      end
    end

    property "endpoints are nil or valid structs" do
      check all packet <- packet_generator() do
        assert packet.src == nil or is_struct(packet.src),
               "src endpoint should be nil or a struct"

        assert packet.dst == nil or is_struct(packet.dst),
               "dst endpoint should be nil or a struct"
      end
    end
  end

  describe "Packet.decode_registered/1" do
    property "decode_registered never raises" do
      check all packet <- packet_generator() do
        result =
          try do
            Packet.decode_registered(packet)
            :ok
          rescue
            _ -> :error
          end

        assert result == :ok, "decode_registered should not raise"
      end
    end

    property "decode_registered returns valid result pattern" do
      check all packet <- packet_generator() do
        result = Packet.decode_registered(packet)

        # Should return one of the documented patterns
        valid_result =
          case result do
            {:ok, {protocol, _decoded}} when is_atom(protocol) -> true
            :no_match -> true
            {:error, _reason} -> true
            _ -> false
          end

        assert valid_result,
               "decode_registered should return {:ok, {protocol, decoded}}, :no_match, or {:error, reason}"
      end
    end
  end

  describe "Packet.attach_decoded/1" do
    property "attach_decoded never raises" do
      check all packet <- packet_generator() do
        result =
          try do
            Packet.attach_decoded(packet)
            :ok
          rescue
            _ -> :error
          end

        assert result == :ok, "attach_decoded should not raise"
      end
    end

    property "attach_decoded returns a Packet struct" do
      check all packet <- packet_generator() do
        result = Packet.attach_decoded(packet)

        assert %Packet{} = result, "attach_decoded should return a Packet struct"
      end
    end

    property "attach_decoded preserves original packet data" do
      check all packet <- packet_generator() do
        result = Packet.attach_decoded(packet)

        # Core fields should be unchanged
        assert result.data == packet.data
        assert result.orig_len == packet.orig_len
        assert result.timestamp == packet.timestamp
        assert result.timestamp_precise == packet.timestamp_precise
      end
    end

    property "attach_decoded decoded field is a map" do
      check all packet <- packet_generator() do
        result = Packet.attach_decoded(packet)

        assert is_map(result.decoded), "decoded field should be a map"
      end
    end
  end

  describe "Protocol list consistency" do
    property "protocols list contains only atoms when present" do
      check all packet <- packet_generator() do
        if packet.protocols && packet.protocols != [] do
          Enum.all?(packet.protocols, fn proto ->
            assert is_atom(proto), "all protocols should be atoms, got: #{inspect(proto)}"
          end)
        end
      end
    end

    property "layers list structure is valid when present" do
      check all packet <- packet_generator() do
        if packet.layers do
          assert is_list(packet.layers), "layers should be a list"

          # Each layer should be a tuple, atom, or map
          Enum.all?(packet.layers, fn layer ->
            assert is_tuple(layer) or is_atom(layer) or is_map(layer),
                   "layer should be tuple, atom, or map, got: #{inspect(layer)}"
          end)
        end
      end
    end

    property "payload is binary or nil" do
      check all packet <- packet_generator() do
        if packet.payload != nil do
          assert is_binary(packet.payload), "payload should be binary when present"
        end
      end
    end
  end

  describe "Packet.known_protocols/0" do
    property "known_protocols returns list of atoms" do
      protocols = Packet.known_protocols()

      assert is_list(protocols)
      assert length(protocols) > 0

      Enum.all?(protocols, fn proto ->
        assert is_atom(proto), "all known protocols should be atoms"
      end)
    end

    property "known_protocols list is sorted" do
      protocols = Packet.known_protocols()
      sorted = Enum.sort(protocols)

      assert protocols == sorted, "known_protocols should return a sorted list"
    end

    property "known_protocols is stable across calls" do
      result1 = Packet.known_protocols()
      result2 = Packet.known_protocols()

      assert result1 == result2, "known_protocols should return the same result"
    end
  end
end
