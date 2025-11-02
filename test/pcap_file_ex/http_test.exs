defmodule PcapFileEx.HTTPTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.Packet

  @pcapng "test/fixtures/sample.pcapng"

  setup do
    if File.exists?(@pcapng) do
      {:ok, packets} = PcapFileEx.read_all(@pcapng)
      {:ok, packets: packets}
    else
      :skip
    end
  end

  test "decodes HTTP request payload", %{packets: packets} do
    packet =
      packets
      |> Enum.find(fn packet ->
        case Packet.pkt_decode(packet) do
          {:ok, {_, payload}} -> String.starts_with?(payload, "GET ")
          _ -> false
        end
      end)

    assert packet
    assert {:ok, http} = Packet.decode_http(packet)
    assert packet.protocol == :http
    assert :http in packet.protocols
    assert List.last(packet.protocols) == :http
    assert {:ok, {:http, decoded_http}} = Packet.decode_registered(packet)
    assert decoded_http == http

    assert http.type == :request
    assert http.method == "GET"
    assert http.uri == "/hello"
    assert http.version == "1.1"
    assert http.headers["host"] == "127.0.0.1:8899"
    assert http.complete?
  end

  test "decodes HTTP response payload", %{packets: packets} do
    packet =
      packets
      |> Enum.find(fn packet ->
        case Packet.pkt_decode(packet) do
          {:ok, {_, payload}} -> String.starts_with?(payload, "HTTP/")
          _ -> false
        end
      end)

    assert packet
    assert {:ok, http} = Packet.decode_http(packet)
    assert packet.protocol == :http
    assert :http in packet.protocols
    assert List.last(packet.protocols) == :http
    assert {:ok, {:http, decoded_http}} = Packet.decode_registered(packet)
    assert decoded_http == http

    assert http.type == :response
    assert http.status_code == 200
    assert http.reason_phrase == "OK"
    assert http.headers["server"] =~ "SimpleHTTP"
    assert http.headers["content-type"] == "text/plain"
    assert http.complete?
  end

  test "returns error for non-HTTP payload", %{packets: [first | _]} do
    assert {:error, :empty_payload} = Packet.decode_http(first)
  end

  test "known protocols include http" do
    assert :http in Packet.known_protocols()
  end
end
