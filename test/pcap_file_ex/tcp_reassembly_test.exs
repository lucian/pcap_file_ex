defmodule PcapFileEx.TCPReassemblyTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Endpoint, Packet, TCP}

  describe "stream_http_messages/2" do
    test "reassembles HTTP requests split across multiple packets" do
      request =
        build_http_sequence(
          "GET /hello HTTP/1.1\r\nHost: example\r\nContent-Length: 4\r\n\r\n",
          "PING",
          4000,
          80
        )

      messages =
        request
        |> TCP.stream_http_messages(types: :all)
        |> Enum.to_list()

      assert [%TCP.HTTPMessage{} = message] = messages
      assert message.http.type == :request
      assert message.http.method == "GET"
      assert message.http.complete?
      assert message.http.body == "PING"
      assert length(message.packets) == 2
    end

    test "supports filtering responses" do
      request = build_http_sequence("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "", 5000, 443)

      response =
        build_http_sequence(
          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
          "PONG!",
          443,
          5000
        )

      messages =
        (request ++ response)
        |> TCP.stream_http_messages(types: [:response])
        |> Enum.to_list()

      assert [%TCP.HTTPMessage{} = message] = messages
      assert message.http.type == :response
      assert message.http.status_code == 200
      assert message.http.body == "PONG!"

      assert message.flow ==
               {Endpoint.new("127.0.0.1", 443), Endpoint.new("127.0.0.1", 5000)}
    end
  end

  defp build_http_sequence(headers, body, src_port, dst_port) do
    now = DateTime.utc_now()

    [
      packet(headers, src_port, dst_port, now),
      packet(body, src_port, dst_port, DateTime.add(now, 1, :millisecond))
    ]
  end

  defp packet(payload, src_port, dst_port, timestamp) do
    %Packet{
      timestamp: timestamp,
      orig_len: byte_size(payload),
      data: payload,
      datalink: "ipv4",
      protocols: [:tcp],
      protocol: :tcp,
      src: Endpoint.new("127.0.0.1", src_port),
      dst: Endpoint.new("127.0.0.1", dst_port),
      payload: payload,
      decoded: %{}
    }
  end
end
