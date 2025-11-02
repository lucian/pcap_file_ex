defmodule PcapFileEx.DecoderRegistryTest do
  use ExUnit.Case, async: false

  alias PcapFileEx.{DecoderRegistry, Packet}

  @payload ~s({"sensor":"alpha","value":21.5})

  setup do
    DecoderRegistry.unregister(:custom_json)

    on_exit(fn ->
      DecoderRegistry.unregister(:custom_json)
    end)

    :ok
  end

  test "registers custom decoder and augments protocol stack" do
    DecoderRegistry.register(%{
      protocol: :custom_json,
      matcher: fn _layers, payload ->
        String.contains?(IO.iodata_to_binary(payload), "sensor")
      end,
      decoder: fn payload ->
        {:ok, Jason.decode!(IO.iodata_to_binary(payload))}
      end
    })

    packet = build_udp_packet(@payload)

    assert :custom_json in packet.protocols
    assert {:ok, {:custom_json, decoded}} = Packet.decode_registered(packet)
    assert decoded["sensor"] == "alpha"
  end

  defp build_udp_packet(payload) do
    data = ipv4_udp_packet(payload)

    map = %{
      timestamp_secs: DateTime.to_unix(DateTime.utc_now()),
      timestamp_nanos: 0,
      orig_len: byte_size(data),
      data: :binary.bin_to_list(data),
      datalink: "ipv4"
    }

    Packet.from_map(map)
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
end
