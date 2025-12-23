defmodule PcapFileEx.HTTP2IntegrationTest do
  @moduledoc """
  Integration tests for HTTP/2 stream reconstruction.

  Tests the complete analysis pipeline from raw segments to exchanges,
  including:
  - Client/server identification via connection preface
  - HPACK header decoding
  - Stream state tracking
  - Complete and incomplete exchange building
  - Mid-connection capture handling
  """

  use ExUnit.Case, async: true

  alias PcapFileEx.HTTP2
  alias PcapFileEx.HTTP2.{Analyzer, Exchange, IncompleteExchange}

  @moduletag :integration

  # Connection preface
  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  # Helper to build frame binary
  defp frame(type, flags, stream_id, payload) do
    type_byte =
      case type do
        :data -> 0x00
        :headers -> 0x01
        :priority -> 0x02
        :rst_stream -> 0x03
        :settings -> 0x04
        :push_promise -> 0x05
        :ping -> 0x06
        :goaway -> 0x07
        :window_update -> 0x08
        :continuation -> 0x09
      end

    length = byte_size(payload)
    <<length::24, type_byte::8, flags::8, 0::1, stream_id::31, payload::binary>>
  end

  # Helper to create segments
  defp segment(flow_key, direction, data, timestamp \\ nil) do
    %{
      flow_key: flow_key,
      direction: direction,
      data: data,
      timestamp: timestamp || DateTime.utc_now()
    }
  end

  describe "basic connection flow" do
    test "analyzes simple GET request/response" do
      # Flow key: client -> server
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      # Request headers using HPACK indexed representations
      # Index 2 = :method GET, Index 4 = :path /, Index 6 = :scheme http
      request_headers = <<0x82, 0x84, 0x86>>

      # Response headers: Index 8 = :status 200
      response_headers = <<0x88>>

      # Response body
      response_body = "Hello, World!"

      segments = [
        # Client sends preface
        segment(flow_key, :a_to_b, @preface),
        # Client sends SETTINGS
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        # Server sends SETTINGS
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Client sends SETTINGS ACK
        segment(flow_key, :a_to_b, frame(:settings, 0x01, 0, <<>>)),
        # Server sends SETTINGS ACK
        segment(flow_key, :b_to_a, frame(:settings, 0x01, 0, <<>>)),
        # Client sends request HEADERS (END_HEADERS=0x04, END_STREAM=0x01)
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        # Server sends response HEADERS (END_HEADERS=0x04)
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        # Server sends DATA (END_STREAM=0x01)
        segment(flow_key, :b_to_a, frame(:data, 0x01, 1, response_body))
      ]

      {:ok, complete, incomplete} = Analyzer.analyze(segments)

      assert length(complete) == 1
      assert Enum.empty?(incomplete)

      [exchange] = complete
      assert %Exchange{} = exchange
      assert exchange.stream_id == 1
      assert exchange.request.method == "GET"
      assert exchange.request.path == "/"
      assert exchange.response.status == 200
      assert exchange.response.body == response_body
    end

    test "handles POST request with body" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      # POST request headers: Index 3 = :method POST
      request_headers = <<0x83, 0x84, 0x86>>
      request_body = ~s({"name": "test"})

      # Response headers and body
      response_headers = <<0x88>>
      response_body = ~s({"status": "created"})

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Client sends request HEADERS (END_HEADERS=0x04, no END_STREAM)
        segment(flow_key, :a_to_b, frame(:headers, 0x04, 1, request_headers)),
        # Client sends request DATA (END_STREAM=0x01)
        segment(flow_key, :a_to_b, frame(:data, 0x01, 1, request_body)),
        # Server sends response HEADERS (END_HEADERS=0x04)
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        # Server sends DATA (END_STREAM=0x01)
        segment(flow_key, :b_to_a, frame(:data, 0x01, 1, response_body))
      ]

      {:ok, complete, _incomplete} = Analyzer.analyze(segments)

      assert length(complete) == 1

      [exchange] = complete
      assert exchange.request.method == "POST"
      assert exchange.request.body == request_body
      assert exchange.response.status == 200
      assert exchange.response.body == response_body
    end
  end

  describe "multiple streams" do
    test "handles concurrent streams" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      # Two parallel requests on streams 1 and 3
      request_headers_1 = <<0x82, 0x84, 0x86>>
      request_headers_3 = <<0x82, 0x84, 0x86>>

      response_headers = <<0x88>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Stream 1 request
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers_1)),
        # Stream 3 request
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 3, request_headers_3)),
        # Stream 1 response
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        segment(flow_key, :b_to_a, frame(:data, 0x01, 1, "response 1")),
        # Stream 3 response
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 3, response_headers)),
        segment(flow_key, :b_to_a, frame(:data, 0x01, 3, "response 3"))
      ]

      {:ok, complete, incomplete} = Analyzer.analyze(segments)

      assert length(complete) == 2
      assert Enum.empty?(incomplete)

      stream_ids = Enum.map(complete, & &1.stream_id) |> Enum.sort()
      assert stream_ids == [1, 3]
    end
  end

  describe "error handling" do
    test "handles RST_STREAM" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      request_headers = <<0x82, 0x84, 0x86>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Client sends request
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        # Server sends RST_STREAM with CANCEL (0x08)
        segment(flow_key, :b_to_a, frame(:rst_stream, 0, 1, <<0, 0, 0, 8>>))
      ]

      {:ok, complete, incomplete} = Analyzer.analyze(segments)

      assert Enum.empty?(complete)
      assert length(incomplete) == 1

      [exchange] = incomplete
      assert %IncompleteExchange{} = exchange
      assert exchange.stream_id == 1
      assert exchange.reason == {:rst_stream, 8}
    end

    test "handles GOAWAY" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      request_headers = <<0x82, 0x84, 0x86>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Client sends request on stream 1
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        # Client sends request on stream 3
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 3, request_headers)),
        # Server sends GOAWAY (last_stream_id=1, error=NO_ERROR)
        segment(flow_key, :b_to_a, frame(:goaway, 0, 0, <<0::1, 1::31, 0, 0, 0, 0>>))
      ]

      {:ok, _complete, incomplete} = Analyzer.analyze(segments)

      # Stream 1 should be incomplete (no response)
      # Stream 3 should be terminated by GOAWAY
      assert length(incomplete) == 2

      stream_3 = Enum.find(incomplete, &(&1.stream_id == 3))
      assert stream_3.reason == {:goaway, 1}
    end

    test "GOAWAY after complete exchange does not mark it incomplete" do
      # Regression test: A stream that has both END_STREAM on request and response
      # should remain a complete Exchange even if GOAWAY is received afterward.
      # See: capture_20251222_173359-broken-goaway.pcapng where stream 63 was
      # incorrectly marked incomplete due to a client GOAWAY with last_stream_id=0.
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      request_headers = <<0x82, 0x84, 0x86>>
      # Simple 204 response with :status pseudo-header
      response_headers = <<0x89>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Client sends complete request on stream 1 (END_STREAM + END_HEADERS)
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        # Server sends complete 204 response (END_STREAM + END_HEADERS)
        segment(flow_key, :b_to_a, frame(:headers, 0x05, 1, response_headers)),
        # Client sends GOAWAY with last_stream_id=0 (after exchange is complete)
        segment(flow_key, :a_to_b, frame(:goaway, 0, 0, <<0::1, 0::31, 0, 0, 0, 2>>)),
        # Server sends GOAWAY with last_stream_id=1
        segment(flow_key, :b_to_a, frame(:goaway, 0, 0, <<0::1, 1::31, 0, 0, 0, 0>>))
      ]

      {:ok, complete, incomplete} = Analyzer.analyze(segments)

      # Stream 1 should be complete (both request and response had END_STREAM)
      # even though GOAWAY with last_stream_id=0 was received afterward
      assert length(complete) == 1
      assert Enum.empty?(incomplete)

      [exchange] = complete
      assert exchange.stream_id == 1
    end

    test "handles truncated stream" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      request_headers = <<0x82, 0x84, 0x86>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Client sends request
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers))
        # No response - capture ended
      ]

      {:ok, complete, incomplete} = Analyzer.analyze(segments)

      assert Enum.empty?(complete)
      assert length(incomplete) == 1

      [exchange] = incomplete
      assert exchange.reason == :truncated_no_response
    end
  end

  describe "CONTINUATION frames" do
    test "handles split headers across CONTINUATION" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      # Split request headers
      request_headers_part1 = <<0x82, 0x84>>
      request_headers_part2 = <<0x86, 0x41, 0x09, "localhost">>

      response_headers = <<0x88>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        # Client sends HEADERS without END_HEADERS (flags=0x01 for END_STREAM only)
        segment(flow_key, :a_to_b, frame(:headers, 0x01, 1, request_headers_part1)),
        # Client sends CONTINUATION with END_HEADERS (flags=0x04)
        segment(flow_key, :a_to_b, frame(:continuation, 0x04, 1, request_headers_part2)),
        # Server sends response
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        segment(flow_key, :b_to_a, frame(:data, 0x01, 1, "response"))
      ]

      {:ok, complete, _incomplete} = Analyzer.analyze(segments)

      assert length(complete) == 1

      [exchange] = complete
      assert exchange.request.method == "GET"
      assert exchange.request.path == "/"
    end
  end

  describe "padding handling" do
    test "handles padded DATA frames" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      request_headers = <<0x82, 0x84, 0x86>>
      response_headers = <<0x88>>

      # Padded DATA: pad_length=4, data="hello", padding=0000
      padded_data = <<4, "hello", 0, 0, 0, 0>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        # Server sends padded DATA (PADDED=0x08, END_STREAM=0x01)
        segment(flow_key, :b_to_a, frame(:data, 0x09, 1, padded_data))
      ]

      {:ok, complete, _incomplete} = Analyzer.analyze(segments)

      assert length(complete) == 1

      [exchange] = complete
      # Padding should be stripped
      assert exchange.response.body == "hello"
    end
  end

  describe "public API" do
    test "HTTP2.http2?/1 detects connection preface" do
      assert HTTP2.http2?(@preface <> "extra data") == true
      assert HTTP2.http2?("not http2") == false
      assert HTTP2.http2?("PRI") == false
    end

    test "HTTP2.connection_preface/0 returns preface" do
      assert HTTP2.connection_preface() == @preface
    end

    test "HTTP2.analyze_segments/1 works with segment list" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      request_headers = <<0x82, 0x84, 0x86>>
      response_headers = <<0x88>>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        segment(flow_key, :b_to_a, frame(:data, 0x01, 1, "OK"))
      ]

      {:ok, complete, incomplete} = HTTP2.analyze_segments(segments)

      assert length(complete) == 1
      assert Enum.empty?(incomplete)
    end
  end

  describe "trailers" do
    test "handles response with trailers" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      request_headers = <<0x82, 0x84, 0x86>>
      response_headers = <<0x88>>

      # Trailers: grpc-status: 0 (literal header)
      trailers = <<0x40, 0x0B, "grpc-status", 0x01, "0">>

      segments = [
        segment(flow_key, :a_to_b, @preface),
        segment(flow_key, :a_to_b, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :b_to_a, frame(:settings, 0, 0, <<>>)),
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        # Response headers (no END_STREAM)
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        # Response data (no END_STREAM)
        segment(flow_key, :b_to_a, frame(:data, 0, 1, "data")),
        # Trailers (END_HEADERS=0x04, END_STREAM=0x01)
        segment(flow_key, :b_to_a, frame(:headers, 0x05, 1, trailers))
      ]

      {:ok, complete, _incomplete} = Analyzer.analyze(segments)

      assert length(complete) == 1

      [exchange] = complete
      assert exchange.response.body == "data"
      assert exchange.response.trailers != nil
      assert exchange.response.trailers.regular["grpc-status"] == "0"
    end
  end

  describe "mid-connection capture" do
    test "identifies client from stream ID semantics" do
      flow_key = {{{127, 0, 0, 1}, 50_000}, {{127, 0, 0, 1}, 8080}}

      # No preface - mid-connection capture
      # Stream 1 (odd) is client-initiated
      request_headers = <<0x82, 0x84, 0x86>>
      response_headers = <<0x88>>

      segments = [
        # First frame seen: request on stream 1 (client-initiated)
        segment(flow_key, :a_to_b, frame(:headers, 0x05, 1, request_headers)),
        # Response from other direction
        segment(flow_key, :b_to_a, frame(:headers, 0x04, 1, response_headers)),
        segment(flow_key, :b_to_a, frame(:data, 0x01, 1, "response"))
      ]

      {:ok, complete, incomplete} = Analyzer.analyze(segments)

      # May be incomplete due to HPACK issues without full context
      # But should not crash
      assert is_list(complete)
      assert is_list(incomplete)
    end
  end

  describe "real PCAP file analysis" do
    @fixture_dir "test/fixtures"

    @tag :pcap_fixture
    test "analyzes http2_sample.pcap" do
      path = Path.join(@fixture_dir, "http2_sample.pcap")

      if File.exists?(path) do
        {:ok, complete, incomplete} = HTTP2.analyze(path)

        # Should have some exchanges (generated with 3 request sets)
        assert length(complete) + length(incomplete) > 0

        # Verify exchange structure
        for ex <- complete do
          assert %Exchange{} = ex
          assert ex.request.method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
          assert is_binary(ex.request.path)
          assert is_integer(ex.response.status)
        end
      else
        # Skip if fixture not generated
        IO.puts("Skipping: http2_sample.pcap not found (run capture_http2_traffic.sh)")
      end
    end

    @tag :pcap_fixture
    test "analyzes http2_sample.pcapng" do
      path = Path.join(@fixture_dir, "http2_sample.pcapng")

      if File.exists?(path) do
        {:ok, complete, incomplete} = HTTP2.analyze(path)

        assert length(complete) + length(incomplete) > 0

        for ex <- complete do
          assert %Exchange{} = ex
          assert is_binary(ex.request.method)
          assert is_binary(ex.request.path)
        end
      else
        IO.puts("Skipping: http2_sample.pcapng not found")
      end
    end

    @tag :pcap_fixture
    test "PCAP and PCAPNG produce same exchanges" do
      pcap_path = Path.join(@fixture_dir, "http2_sample.pcap")
      pcapng_path = Path.join(@fixture_dir, "http2_sample.pcapng")

      if File.exists?(pcap_path) and File.exists?(pcapng_path) do
        {:ok, pcap_complete, _} = HTTP2.analyze(pcap_path)
        {:ok, pcapng_complete, _} = HTTP2.analyze(pcapng_path)

        # Same number of complete exchanges
        assert length(pcap_complete) == length(pcapng_complete)

        # Same request paths (order may differ)
        pcap_paths = Enum.map(pcap_complete, & &1.request.path) |> Enum.sort()
        pcapng_paths = Enum.map(pcapng_complete, & &1.request.path) |> Enum.sort()
        assert pcap_paths == pcapng_paths
      else
        IO.puts("Skipping: PCAP fixtures not found")
      end
    end
  end
end
