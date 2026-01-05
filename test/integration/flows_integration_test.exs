defmodule PcapFileEx.Flows.IntegrationTest do
  use ExUnit.Case, async: false

  alias PcapFileEx.Flows
  alias PcapFileEx.Flows.{AnalysisResult, HTTP1, HTTP2, UDP}

  @fixture_path "test/fixtures/mixed_traffic_sample.pcapng"

  # Loopback IP -> friendly hostname mapping
  @hosts_map %{
    "127.0.0.1" => "localhost"
  }

  setup_all do
    unless File.exists?(@fixture_path) do
      IO.puts("\nGenerating fixture: #{@fixture_path}")
      IO.puts("This requires dumpcap and Python with h2 library...")

      case System.cmd("bash", ["capture_mixed_traffic.sh"],
             cd: "test/fixtures",
             stderr_to_stdout: true
           ) do
        {output, 0} ->
          IO.puts("Fixture generated successfully")
          IO.puts(output)

        {output, code} ->
          IO.puts("Warning: Fixture generation failed (exit code #{code})")
          IO.puts(output)
          IO.puts("Some tests may be skipped")
      end
    end

    :ok
  end

  describe "analyze/2" do
    @tag :integration
    test "analyzes mixed traffic PCAP with all three protocols" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      assert result.http1 != [], "Expected at least 1 HTTP/1 flow"
      assert result.http2 != [], "Expected at least 1 HTTP/2 flow"
      assert result.udp != [], "Expected at least 1 UDP flow"

      # Verify protocol classification
      assert Enum.all?(result.http1, fn f -> f.flow.protocol == :http1 end)
      assert Enum.all?(result.http2, fn f -> f.flow.protocol == :http2 end)
      assert Enum.all?(result.udp, fn f -> f.flow.protocol == :udp end)
    end

    @tag :integration
    test "hosts_map resolves IP addresses to hostnames" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path, hosts_map: @hosts_map)

      # Verify flows use resolved hostname
      Enum.each(result.http1, fn flow ->
        assert flow.flow.server =~ "localhost",
               "HTTP/1 server should contain 'localhost', got: #{flow.flow.server}"
      end)

      Enum.each(result.http2, fn flow ->
        assert flow.flow.server =~ "localhost",
               "HTTP/2 server should contain 'localhost', got: #{flow.flow.server}"
      end)

      Enum.each(result.udp, fn flow ->
        assert flow.flow.server =~ "localhost",
               "UDP server should contain 'localhost', got: #{flow.flow.server}"
      end)
    end

    @tag :integration
    test "timeline contains events from all protocols" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      types = Enum.map(result.timeline, & &1.event_type) |> Enum.uniq()

      assert :http1_exchange in types, "Timeline should contain HTTP/1 exchanges"
      assert :http2_stream in types, "Timeline should contain HTTP/2 streams"
      assert :udp_datagram in types, "Timeline should contain UDP datagrams"
    end

    @tag :integration
    test "timeline is sorted chronologically" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      timestamps =
        result.timeline
        |> Enum.map(& &1.timestamp)
        |> Enum.map(&PcapFileEx.Timestamp.to_unix_nanos/1)

      sorted = Enum.sort(timestamps)
      assert timestamps == sorted, "Timeline should be sorted by timestamp"
    end

    @tag :integration
    test "get_event returns correct data types" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      Enum.each(result.timeline, fn event ->
        data = AnalysisResult.get_event(result, event)
        assert data != nil, "get_event should return data for event #{inspect(event)}"

        case event.event_type do
          :http1_exchange ->
            assert %HTTP1.Exchange{} = data

          :http2_stream ->
            assert %HTTP2.Stream{} = data

          :udp_datagram ->
            assert %UDP.Datagram{} = data
        end
      end)
    end

    @tag :integration
    test "flow lookup via FlowKey works" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path, hosts_map: @hosts_map)

      # Test HTTP/2 flow lookup
      if result.http2 != [] do
        [first_http2 | _] = result.http2
        key = PcapFileEx.Flow.key(first_http2.flow)

        found = AnalysisResult.get_flow(result, key)
        assert found == first_http2, "FlowKey lookup should return the same flow"
      end

      # Test HTTP/1 flow lookup
      if result.http1 != [] do
        [first_http1 | _] = result.http1
        key = PcapFileEx.Flow.key(first_http1.flow)

        found = AnalysisResult.get_flow(result, key)
        assert found == first_http1, "FlowKey lookup should return the same flow"
      end

      # Test UDP flow lookup
      if result.udp != [] do
        [first_udp | _] = result.udp
        key = PcapFileEx.Flow.key(first_udp.flow)

        found = AnalysisResult.get_flow(result, key)
        assert found == first_udp, "FlowKey lookup should return the same flow"
      end
    end

    @tag :integration
    test "stats are computed for each flow" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      all_flows = result.http1 ++ result.http2 ++ result.udp

      Enum.each(all_flows, fn flow ->
        assert flow.stats.packet_count >= 0,
               "packet_count should be non-negative"

        assert flow.stats.byte_count >= 0,
               "byte_count should be non-negative"

        assert flow.stats.duration_ms >= 0,
               "duration_ms should be non-negative"
      end)
    end

    @tag :integration
    test "HTTP/1 exchanges have request and response data" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      Enum.each(result.http1, fn flow ->
        Enum.each(flow.exchanges, fn exchange ->
          assert exchange.request != nil, "Exchange should have request"
          assert exchange.request.method != nil, "Request should have method"
          assert exchange.request.path != nil, "Request should have path"

          if exchange.complete do
            assert exchange.response != nil, "Complete exchange should have response"
            assert exchange.response.status != nil, "Response should have status"
          end
        end)
      end)
    end

    @tag :integration
    test "HTTP/2 streams wrap exchanges correctly" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      Enum.each(result.http2, fn flow ->
        Enum.each(flow.streams, fn stream ->
          assert stream.exchange != nil, "Stream should wrap an exchange"
          assert stream.flow_seq != nil, "Stream should have flow_seq"
          assert stream.start_timestamp != nil, "Stream should have start_timestamp"

          ex = stream.exchange
          assert ex.request != nil, "Exchange should have request"
          assert ex.request.method != nil, "Request should have method"
        end)
      end)
    end

    @tag :integration
    test "UDP datagrams have source and destination" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      Enum.each(result.udp, fn flow ->
        # UDP flows have from: :any pattern
        assert flow.flow.from == :any, "UDP flow should have from: :any"

        Enum.each(flow.datagrams, fn datagram ->
          assert datagram.from != nil, "Datagram should have from endpoint"
          assert datagram.to != nil, "Datagram should have to endpoint"
          assert datagram.payload != nil, "Datagram should have payload"
          assert datagram.size >= 0, "Datagram size should be non-negative"
          assert datagram.relative_offset_ms >= 0, "relative_offset_ms should be non-negative"
        end)
      end)
    end

    @tag :integration
    test "aggregate stats cover all flows" do
      skip_unless_fixture_exists()

      {:ok, result} = Flows.analyze(@fixture_path)

      # Aggregate stats should exist
      assert result.stats != nil
      assert result.stats.packet_count >= 0
      assert result.stats.byte_count >= 0
    end
  end

  # Helper to skip tests if fixture doesn't exist
  defp skip_unless_fixture_exists do
    unless File.exists?(@fixture_path) do
      flunk("""
      Fixture file not found: #{@fixture_path}

      To generate the fixture, run:
        cd test/fixtures && ./capture_mixed_traffic.sh

      Requirements:
        - dumpcap (from Wireshark)
        - Python 3 with h2 library (pip install h2)
      """)
    end
  end
end
