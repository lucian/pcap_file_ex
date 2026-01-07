defmodule PcapFileEx.Flows.SummaryTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.Endpoint
  alias PcapFileEx.Flow
  alias PcapFileEx.Flows.{HTTP1, HTTP2, Summary, UDP}
  alias PcapFileEx.Flows.Summary.{HTTPClientStats, HTTPService, UDPClientStats, UDPService}
  alias PcapFileEx.Timestamp

  describe "build/4" do
    test "returns empty summary for empty flows" do
      summary = Summary.build([], [], [])

      assert summary.http1 == []
      assert summary.http2 == []
      assert summary.udp == []
    end

    test "aggregates UDP flows by destination" do
      ts1 = Timestamp.new(1, 0)
      ts2 = Timestamp.new(2, 0)

      client1 = Endpoint.new("10.0.0.1", 50_000)
      client2 = Endpoint.new("10.0.0.2", 50_001)
      server = Endpoint.new("192.168.1.1", 5005)

      udp_flow = %UDP.Flow{
        flow: %Flow{
          client_endpoint: nil,
          server_endpoint: server,
          protocol: :udp,
          from: :any,
          server: "192.168.1.1:5005"
        },
        datagrams: [
          UDP.Datagram.new(0, client1, server, String.duplicate("x", 100), ts1),
          UDP.Datagram.new(1, client1, server, String.duplicate("x", 150), ts2),
          UDP.Datagram.new(2, client2, server, String.duplicate("x", 200), ts1)
        ],
        stats: %PcapFileEx.Flows.Stats{}
      }

      summary = Summary.build([], [], [udp_flow])

      assert length(summary.udp) == 1
      [service] = summary.udp

      assert service.server == "192.168.1.1:5005"
      assert service.total_packets == 3
      assert service.total_bytes == 450

      # Should have 2 clients
      assert length(service.clients) == 2

      # Find client1's stats (sorted by bytes desc, so client2 first with 200, then client1 with 250)
      client1_stats = Enum.find(service.clients, &(&1.client == "10.0.0.1"))
      assert client1_stats.packet_count == 2
      assert client1_stats.total_bytes == 250
    end

    test "aggregates HTTP/1 flows by server" do
      ts = Timestamp.new(1, 0)

      client1 = Endpoint.new("10.0.0.1", 50_000)
      client2 = Endpoint.new("10.0.0.2", 50_001)
      server = Endpoint.new("192.168.1.1", 8080)

      http1_flow1 = %HTTP1.Flow{
        flow: %Flow{
          client_endpoint: client1,
          server_endpoint: server,
          protocol: :http1,
          from: "10.0.0.1:50_000",
          server: "192.168.1.1:8080"
        },
        exchanges: [
          %HTTP1.Exchange{
            flow_seq: 0,
            request: %{method: "GET", path: "/api/users", headers: [], body: <<>>},
            response: %{status: 200, headers: [], body: "response"},
            start_timestamp: ts,
            end_timestamp: ts,
            response_delay_ms: 5
          },
          %HTTP1.Exchange{
            flow_seq: 1,
            request: %{method: "POST", path: "/api/users", headers: [], body: "body"},
            response: %{status: 201, headers: [], body: "created"},
            start_timestamp: ts,
            end_timestamp: ts,
            response_delay_ms: 10
          }
        ],
        stats: %PcapFileEx.Flows.Stats{}
      }

      http1_flow2 = %HTTP1.Flow{
        flow: %Flow{
          client_endpoint: client2,
          server_endpoint: server,
          protocol: :http1,
          from: "10.0.0.2:50_001",
          server: "192.168.1.1:8080"
        },
        exchanges: [
          %HTTP1.Exchange{
            flow_seq: 0,
            request: %{method: "GET", path: "/api/items", headers: [], body: <<>>},
            response: %{status: 200, headers: [], body: "items"},
            start_timestamp: ts,
            end_timestamp: ts,
            response_delay_ms: 3
          }
        ],
        stats: %PcapFileEx.Flows.Stats{}
      }

      summary = Summary.build([http1_flow1, http1_flow2], [], [])

      assert length(summary.http1) == 1
      [service] = summary.http1

      assert service.server == "192.168.1.1:8080"
      assert service.protocol == :http1
      assert service.total_requests == 3
      assert service.total_responses == 3

      # Should have 2 clients
      assert length(service.clients) == 2

      # Check methods aggregation
      assert service.methods == %{"GET" => 2, "POST" => 1}
      assert service.status_codes == %{200 => 2, 201 => 1}
    end

    test "aggregates HTTP/2 flows by server" do
      ts = Timestamp.new(1, 0)

      client = Endpoint.new("10.0.0.1", 50_000)
      server = Endpoint.new("192.168.1.1", 443)

      http2_flow = %HTTP2.Flow{
        flow: %Flow{
          client_endpoint: client,
          server_endpoint: server,
          protocol: :http2,
          from: "10.0.0.1:50_000",
          server: "192.168.1.1:443"
        },
        streams: [
          %HTTP2.Stream{
            flow_seq: 0,
            exchange: %{
              request: %{method: "GET", path: "/api/data", headers: [], body: <<>>},
              response: %{status: 200, headers: [], body: "data"},
              start_timestamp: nil,
              end_timestamp: nil
            },
            start_timestamp: ts,
            response_delay_ms: 2
          },
          %HTTP2.Stream{
            flow_seq: 1,
            exchange: %{
              request: %{method: "POST", path: "/api/data", headers: [], body: "payload"},
              response: %{status: 204, headers: [], body: <<>>},
              start_timestamp: nil,
              end_timestamp: nil
            },
            start_timestamp: ts,
            response_delay_ms: 5
          }
        ],
        stats: %PcapFileEx.Flows.Stats{}
      }

      summary = Summary.build([], [http2_flow], [])

      assert length(summary.http2) == 1
      [service] = summary.http2

      assert service.server == "192.168.1.1:443"
      assert service.protocol == :http2
      assert service.total_requests == 2
      assert service.total_responses == 2

      # Should have 1 client
      assert length(service.clients) == 1
      [client_stats] = service.clients

      assert client_stats.client == "10.0.0.1"
      assert client_stats.stream_count == 2
      assert client_stats.connection_count == 1
    end

    test "applies hosts_map for server hostnames" do
      ts = Timestamp.new(1, 0)

      client = Endpoint.new("10.0.0.1", 50_000)
      server = Endpoint.new("192.168.1.1", 8080)

      http1_flow = %HTTP1.Flow{
        flow: %Flow{
          client_endpoint: client,
          server_endpoint: server,
          protocol: :http1,
          from: "10.0.0.1:50_000",
          server: "192.168.1.1:8080"
        },
        exchanges: [
          %HTTP1.Exchange{
            flow_seq: 0,
            request: %{method: "GET", path: "/", headers: [], body: <<>>},
            response: %{status: 200, headers: [], body: "ok"},
            start_timestamp: ts,
            end_timestamp: ts,
            response_delay_ms: 1
          }
        ],
        stats: %PcapFileEx.Flows.Stats{}
      }

      hosts_map = %{
        "192.168.1.1" => "api-server",
        "10.0.0.1" => "my-client"
      }

      summary = Summary.build([http1_flow], [], [], hosts_map)

      [service] = summary.http1
      assert service.server_host == "api-server"

      [client_stats] = service.clients
      assert client_stats.client_host == "my-client"
    end

    test "services are sorted by total bytes descending" do
      ts = Timestamp.new(1, 0)

      # Small service
      small_server = Endpoint.new("192.168.1.1", 8080)
      small_client = Endpoint.new("10.0.0.1", 50_000)

      small_flow = %HTTP1.Flow{
        flow: %Flow{
          client_endpoint: small_client,
          server_endpoint: small_server,
          protocol: :http1,
          from: "10.0.0.1:50_000",
          server: "192.168.1.1:8080"
        },
        exchanges: [
          %HTTP1.Exchange{
            flow_seq: 0,
            request: %{method: "GET", path: "/", headers: [], body: <<>>},
            response: %{status: 200, headers: [], body: "x"},
            start_timestamp: ts,
            end_timestamp: ts,
            response_delay_ms: 1
          }
        ],
        stats: %PcapFileEx.Flows.Stats{}
      }

      # Large service
      large_server = Endpoint.new("192.168.1.2", 8080)
      large_client = Endpoint.new("10.0.0.2", 50_000)

      large_flow = %HTTP1.Flow{
        flow: %Flow{
          client_endpoint: large_client,
          server_endpoint: large_server,
          protocol: :http1,
          from: "10.0.0.2:50_000",
          server: "192.168.1.2:8080"
        },
        exchanges: [
          %HTTP1.Exchange{
            flow_seq: 0,
            request: %{
              method: "POST",
              path: "/upload",
              headers: [],
              body: String.duplicate("x", 1000)
            },
            response: %{status: 200, headers: [], body: String.duplicate("y", 5000)},
            start_timestamp: ts,
            end_timestamp: ts,
            response_delay_ms: 100
          }
        ],
        stats: %PcapFileEx.Flows.Stats{}
      }

      summary = Summary.build([small_flow, large_flow], [], [])

      assert length(summary.http1) == 2
      [first, second] = summary.http1

      # Large service should come first
      assert first.server == "192.168.1.2:8080"
      assert second.server == "192.168.1.1:8080"
    end
  end

  describe "struct types" do
    test "UDPService has expected fields" do
      service = %UDPService{
        server: "192.168.1.1:5005",
        server_host: "metrics",
        clients: [],
        total_packets: 10,
        total_bytes: 1000,
        first_timestamp: nil,
        last_timestamp: nil
      }

      assert service.server == "192.168.1.1:5005"
      assert service.server_host == "metrics"
    end

    test "UDPClientStats has expected fields" do
      stats = %UDPClientStats{
        client: "10.0.0.1",
        client_host: "sensor",
        packet_count: 5,
        total_bytes: 500,
        avg_size: 100,
        min_size: 50,
        max_size: 150,
        first_timestamp: nil,
        last_timestamp: nil
      }

      assert stats.client == "10.0.0.1"
      assert stats.avg_size == 100
    end

    test "HTTPService has expected fields" do
      service = %HTTPService{
        protocol: :http2,
        server: "192.168.1.1:443",
        server_host: "api-gw",
        clients: [],
        total_requests: 100,
        total_responses: 95,
        total_request_bytes: 10_000,
        total_response_bytes: 50_000,
        methods: %{"GET" => 50, "POST" => 50},
        status_codes: %{200 => 90, 500 => 5},
        first_timestamp: nil,
        last_timestamp: nil
      }

      assert service.protocol == :http2
      assert service.methods["POST"] == 50
    end

    test "HTTPClientStats has expected fields" do
      stats = %HTTPClientStats{
        client: "10.0.0.1",
        client_host: "client-app",
        connection_count: 3,
        stream_count: 10,
        request_count: 10,
        response_count: 9,
        request_bytes: 1000,
        response_bytes: 5000,
        methods: %{"GET" => 10},
        status_codes: %{200 => 9},
        avg_response_time_ms: 50,
        min_response_time_ms: 10,
        max_response_time_ms: 200,
        first_timestamp: nil,
        last_timestamp: nil
      }

      assert stats.stream_count == 10
      assert stats.avg_response_time_ms == 50
    end
  end
end
