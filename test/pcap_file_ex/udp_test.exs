defmodule PcapFileEx.UDPTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Filter, Packet}

  @request_payload ~s({"sensor":"sensor-1","value":25.5,"seq":1})
  @response_payload ~s({"ack":"sensor-1","received":25.5,"ts":1730575588.123,"status":"ok"})

  test "decodes UDP telemetry request payload" do
    packet = build_packet(@request_payload)

    assert {:ok, payload} = Packet.udp_payload(packet)
    assert payload == @request_payload

    telemetry = decode_payload(payload)
    assert telemetry["sensor"] == "sensor-1"
    assert telemetry["value"] == 25.5
    assert telemetry["seq"] == 1
    assert :no_match = Packet.decode_registered(packet)
  end

  test "decodes UDP telemetry response payload" do
    packet = build_packet(@response_payload)

    {:ok, payload} = Packet.udp_payload(packet)
    telemetry = decode_payload(payload)
    assert telemetry["ack"] == "sensor-1"
    assert telemetry["received"] == 25.5
    assert telemetry["status"] == "ok"
    assert telemetry["ts"] == 1_730_575_588.123
    assert :no_match = Packet.decode_registered(packet)
  end

  test "filter recognizes UDP packets" do
    packet = build_packet(@request_payload)

    filtered =
      [packet]
      |> Filter.by_protocol(:udp)
      |> Enum.to_list()

    assert [^packet] = filtered
  end

  test "udp_payload returns error for empty data" do
    packet = build_packet("")
    assert {:error, :empty_payload} = Packet.udp_payload(packet)
  end

  defp build_packet(payload) do
    data = ipv4_udp_packet(payload)

    %Packet{
      timestamp: DateTime.utc_now(),
      orig_len: byte_size(data),
      data: data,
      datalink: "ipv4"
    }
  end

  defp ipv4_udp_packet(payload, opts \\ []) do
    src_ip = Keyword.get(opts, :src_ip, {127, 0, 0, 1})
    dst_ip = Keyword.get(opts, :dst_ip, {127, 0, 0, 1})
    src_port = Keyword.get(opts, :src_port, 40_000)
    dst_port = Keyword.get(opts, :dst_port, 8898)

    payload_bin = payload
    udp_len = 8 + byte_size(payload_bin)
    total_len = 20 + udp_len

    <<
      0x45,
      0x00,
      total_len::16,
      0x12,
      0x34,
      0x00,
      0x00,
      64,
      17,
      0x00,
      0x00,
      ip_tuple_to_binary(src_ip)::binary-size(4),
      ip_tuple_to_binary(dst_ip)::binary-size(4),
      src_port::16,
      dst_port::16,
      udp_len::16,
      0x00,
      0x00,
      payload_bin::binary
    >>
  end

  defp ip_tuple_to_binary({a, b, c, d}) do
    <<a, b, c, d>>
  end

  defp decode_payload(payload) do
    Jason.decode!(payload)
  end
end
