defmodule PcapFileEx.DisplayFilterTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{DisplayFilter, Packet}

  @pcapng "test/fixtures/sample.pcapng"

  test "filters by HTTP request method" do
    ensure_fixture(@pcapng)

    packets =
      PcapFileEx.stream(@pcapng)
      |> Enum.map(&Packet.attach_decoded/1)

    filtered =
      packets
      |> DisplayFilter.filter("http.request.method == \"GET\"")
      |> Enum.to_list()

    assert filtered != []

    Enum.each(filtered, fn packet ->
      http = packet.decoded[:http]
      assert http
      assert http.type == :request
      assert http.method == "GET"
    end)
  end

  test "filters by tcp and ip fields" do
    ensure_fixture(@pcapng)

    [packet | _] =
      PcapFileEx.stream(@pcapng)
      |> Enum.map(&Packet.attach_decoded/1)
      |> DisplayFilter.filter("tcp.srcport > 0 && ip.src == 127.0.0.1")
      |> Enum.to_list()

    assert packet.src.ip == "127.0.0.1"
    assert packet.src.port > 0
  end

  defp ensure_fixture(path) do
    unless File.exists?(path) do
      flunk("fixture not available: #{path}")
    end
  end
end
