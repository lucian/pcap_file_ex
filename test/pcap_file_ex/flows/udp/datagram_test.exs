defmodule PcapFileEx.Flows.UDP.DatagramTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Endpoint, Timestamp}
  alias PcapFileEx.Flows.UDP.{Collector, Datagram}

  describe "Datagram struct" do
    test "new/5 creates datagram with raw binary payload" do
      from = Endpoint.new("10.0.0.1", 54_321)
      to = Endpoint.new("10.0.0.2", 5005)
      ts = Timestamp.new(1000, 0)
      payload = <<1, 2, 3, 4>>

      dg = Datagram.new(0, from, to, payload, ts)

      assert is_binary(dg.payload)
      assert dg.payload == <<1, 2, 3, 4>>
      assert dg.payload_binary == nil
      assert dg.size == 4
    end
  end

  describe "payload states with custom decoders" do
    test "no decoders - payload stays raw binary, no payload_binary" do
      packets = [
        %{
          src_ip: {10, 0, 0, 1},
          src_port: 54_321,
          dst_ip: {10, 0, 0, 2},
          dst_port: 5005,
          payload: <<1, 2, 3, 4>>,
          timestamp: ~U[2024-01-01 00:00:00Z]
        }
      ]

      {:ok, flows} = Collector.collect(packets, decoders: [])

      assert [flow] = flows
      assert [dg] = flow.datagrams

      assert is_binary(dg.payload)
      assert dg.payload == <<1, 2, 3, 4>>
      assert dg.payload_binary == nil
    end

    test "decoder matched, keep_binary: false - payload is {:custom, _}, no payload_binary" do
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn payload -> {:decoded, payload} end
      }

      packets = [
        %{
          src_ip: {10, 0, 0, 1},
          src_port: 54_321,
          dst_ip: {10, 0, 0, 2},
          dst_port: 5005,
          payload: <<1, 2, 3, 4>>,
          timestamp: ~U[2024-01-01 00:00:00Z]
        }
      ]

      {:ok, flows} = Collector.collect(packets, decoders: [decoder], keep_binary: false)

      assert [flow] = flows
      assert [dg] = flow.datagrams

      assert {:custom, {:decoded, <<1, 2, 3, 4>>}} = dg.payload
      assert dg.payload_binary == nil
    end

    test "decoder matched, keep_binary: true - payload is {:custom, _}, payload_binary is raw" do
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn payload -> {:decoded, payload} end
      }

      packets = [
        %{
          src_ip: {10, 0, 0, 1},
          src_port: 54_321,
          dst_ip: {10, 0, 0, 2},
          dst_port: 5005,
          payload: <<1, 2, 3, 4>>,
          timestamp: ~U[2024-01-01 00:00:00Z]
        }
      ]

      {:ok, flows} = Collector.collect(packets, decoders: [decoder], keep_binary: true)

      assert [flow] = flows
      assert [dg] = flow.datagrams

      assert {:custom, {:decoded, <<1, 2, 3, 4>>}} = dg.payload
      assert dg.payload_binary == <<1, 2, 3, 4>>
    end

    test "decoder returns :skip - payload stays raw binary, no payload_binary" do
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _ctx, _payload -> :skip end
      }

      packets = [
        %{
          src_ip: {10, 0, 0, 1},
          src_port: 54_321,
          dst_ip: {10, 0, 0, 2},
          dst_port: 5005,
          payload: <<1, 2, 3, 4>>,
          timestamp: ~U[2024-01-01 00:00:00Z]
        }
      ]

      {:ok, flows} = Collector.collect(packets, decoders: [decoder], keep_binary: true)

      assert [flow] = flows
      assert [dg] = flow.datagrams

      # :skip is semantically equivalent to "no decoder"
      assert is_binary(dg.payload)
      assert dg.payload == <<1, 2, 3, 4>>
      assert dg.payload_binary == nil
    end

    test "decoder error, keep_binary: true - payload is {:decode_error, _}, payload_binary is raw" do
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _payload -> {:error, :parse_failed} end
      }

      packets = [
        %{
          src_ip: {10, 0, 0, 1},
          src_port: 54_321,
          dst_ip: {10, 0, 0, 2},
          dst_port: 5005,
          payload: <<1, 2, 3, 4>>,
          timestamp: ~U[2024-01-01 00:00:00Z]
        }
      ]

      {:ok, flows} = Collector.collect(packets, decoders: [decoder], keep_binary: true)

      assert [flow] = flows
      assert [dg] = flow.datagrams

      assert {:decode_error, :parse_failed} = dg.payload
      assert dg.payload_binary == <<1, 2, 3, 4>>
    end

    test "decoder does not match (wrong port) - payload stays raw binary" do
      decoder = %{
        protocol: :udp,
        match: %{port: 9999},
        decoder: fn payload -> {:decoded, payload} end
      }

      packets = [
        %{
          src_ip: {10, 0, 0, 1},
          src_port: 54_321,
          dst_ip: {10, 0, 0, 2},
          dst_port: 5005,
          payload: <<1, 2, 3, 4>>,
          timestamp: ~U[2024-01-01 00:00:00Z]
        }
      ]

      {:ok, flows} = Collector.collect(packets, decoders: [decoder], keep_binary: true)

      assert [flow] = flows
      assert [dg] = flow.datagrams

      # Decoder didn't match - payload is raw binary
      assert is_binary(dg.payload)
      assert dg.payload == <<1, 2, 3, 4>>
      assert dg.payload_binary == nil
    end
  end

  describe "pattern matching on payload" do
    test "can pattern match on all payload states" do
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn payload -> {:decoded, payload} end
      }

      packets = [
        %{
          src_ip: {10, 0, 0, 1},
          src_port: 54_321,
          dst_ip: {10, 0, 0, 2},
          dst_port: 5005,
          payload: <<1, 2, 3, 4>>,
          timestamp: ~U[2024-01-01 00:00:00Z]
        }
      ]

      {:ok, flows} = Collector.collect(packets, decoders: [decoder], keep_binary: true)

      [flow] = flows
      [dg] = flow.datagrams

      # Pattern match like in documentation
      result =
        case dg.payload do
          {:custom, data} ->
            {:decoded, data}

          {:decode_error, reason} ->
            {:error, reason}

          raw when is_binary(raw) ->
            {:raw, raw}
        end

      assert {:decoded, {:decoded, <<1, 2, 3, 4>>}} = result
    end
  end
end
