defmodule PcapFileEx.Flows.Summary.RenderTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.Flows.Summary
  alias PcapFileEx.Flows.Summary.{HTTPClientStats, HTTPService, UDPClientStats, UDPService}
  alias PcapFileEx.Flows.Summary.Render

  describe "to_markdown/2" do
    test "returns empty string for empty summary" do
      summary = %Summary{http1: [], http2: [], udp: []}
      assert Render.to_markdown(summary) == ""
    end

    test "renders HTTP traffic table" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "192.168.1.10:8080",
            server_host: "api-gateway",
            clients: [
              %HTTPClientStats{
                client: "10.0.0.1",
                client_host: "web-client",
                connection_count: 1,
                stream_count: 45,
                request_count: 45,
                response_count: 44,
                request_bytes: 12_000,
                response_bytes: 350_000,
                methods: %{"GET" => 40, "POST" => 5},
                status_codes: %{200 => 42, 404 => 2},
                avg_response_time_ms: 75,
                min_response_time_ms: 12,
                max_response_time_ms: 450,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 45,
            total_responses: 44,
            total_request_bytes: 12_000,
            total_response_bytes: 350_000,
            methods: %{"GET" => 40, "POST" => 5},
            status_codes: %{200 => 42, 404 => 2},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      markdown = Render.to_markdown(summary)

      assert markdown =~ "## HTTP Traffic"
      assert markdown =~ "| Protocol | Server | Client |"

      assert markdown =~
               "| http2 | api-gateway:8080 | web-client | 45 | 44 | 12000 | 350000 | 75 |"
    end

    test "renders UDP traffic table" do
      summary = %Summary{
        http1: [],
        http2: [],
        udp: [
          %UDPService{
            server: "192.168.1.20:5005",
            server_host: "metrics",
            clients: [
              %UDPClientStats{
                client: "10.0.0.5",
                client_host: "sensor-1",
                packet_count: 1200,
                total_bytes: 600_000,
                avg_size: 500,
                min_size: 64,
                max_size: 1400,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_packets: 1200,
            total_bytes: 600_000,
            first_timestamp: nil,
            last_timestamp: nil
          }
        ]
      }

      markdown = Render.to_markdown(summary)

      assert markdown =~ "## UDP Traffic"
      assert markdown =~ "| Server | Client | Packets |"
      assert markdown =~ "| metrics:5005 | sensor-1 | 1200 | 600000 | 500 | 64 | 1400 |"
    end

    test "renders both HTTP and UDP tables" do
      summary = %Summary{
        http1: [
          %HTTPService{
            protocol: :http1,
            server: "legacy:80",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "10.0.0.2",
                client_host: nil,
                connection_count: 1,
                stream_count: nil,
                request_count: 10,
                response_count: 10,
                request_bytes: 500,
                response_bytes: 5000,
                methods: %{"GET" => 10},
                status_codes: %{200 => 10},
                avg_response_time_ms: 200,
                min_response_time_ms: 100,
                max_response_time_ms: 300,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 10,
            total_responses: 10,
            total_request_bytes: 500,
            total_response_bytes: 5000,
            methods: %{"GET" => 10},
            status_codes: %{200 => 10},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        http2: [],
        udp: [
          %UDPService{
            server: "metrics:5005",
            server_host: nil,
            clients: [
              %UDPClientStats{
                client: "10.0.0.5",
                client_host: nil,
                packet_count: 100,
                total_bytes: 50_000,
                avg_size: 500,
                min_size: 64,
                max_size: 1400,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_packets: 100,
            total_bytes: 50_000,
            first_timestamp: nil,
            last_timestamp: nil
          }
        ]
      }

      markdown = Render.to_markdown(summary)

      assert markdown =~ "## HTTP Traffic"
      assert markdown =~ "## UDP Traffic"
      assert markdown =~ "| http1 | legacy:80 | 10.0.0.2 |"
      assert markdown =~ "| metrics:5005 | 10.0.0.5 |"
    end

    test "humanizes bytes when option is set" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "client",
                client_host: nil,
                connection_count: 1,
                stream_count: 10,
                request_count: 10,
                response_count: 10,
                request_bytes: 1_500_000,
                response_bytes: 2_500_000_000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: 50,
                min_response_time_ms: 10,
                max_response_time_ms: 100,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 10,
            total_responses: 10,
            total_request_bytes: 1_500_000,
            total_response_bytes: 2_500_000_000,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      markdown = Render.to_markdown(summary, humanize_bytes: true)

      assert markdown =~ "1.5 MB"
      assert markdown =~ "2.5 GB"
    end

    test "filters by protocol" do
      summary = %Summary{
        http1: [
          %HTTPService{
            protocol: :http1,
            server: "legacy:80",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "c1",
                client_host: nil,
                connection_count: 1,
                stream_count: nil,
                request_count: 5,
                response_count: 5,
                request_bytes: 100,
                response_bytes: 500,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 5,
            total_responses: 5,
            total_request_bytes: 100,
            total_response_bytes: 500,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "c2",
                client_host: nil,
                connection_count: 1,
                stream_count: 10,
                request_count: 10,
                response_count: 10,
                request_bytes: 200,
                response_bytes: 1000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 10,
            total_responses: 10,
            total_request_bytes: 200,
            total_response_bytes: 1000,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      # Filter to http1 only
      markdown = Render.to_markdown(summary, protocol: :http1)
      assert markdown =~ "legacy:80"
      refute markdown =~ "api:8080"

      # Filter to http2 only
      markdown = Render.to_markdown(summary, protocol: :http2)
      refute markdown =~ "legacy:80"
      assert markdown =~ "api:8080"
    end

    test "hides titles when option is false" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "c",
                client_host: nil,
                connection_count: 1,
                stream_count: 1,
                request_count: 1,
                response_count: 1,
                request_bytes: 0,
                response_bytes: 0,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 1,
            total_responses: 1,
            total_request_bytes: 0,
            total_response_bytes: 0,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      markdown = Render.to_markdown(summary, title: false)
      refute markdown =~ "## HTTP Traffic"
      assert markdown =~ "| Protocol |"
    end
  end

  describe "to_mermaid/2" do
    test "returns empty flowchart for empty summary" do
      summary = %Summary{http1: [], http2: [], udp: []}
      mermaid = Render.to_mermaid(summary)

      assert mermaid =~ "flowchart LR"
      assert mermaid =~ "%% Empty summary"
    end

    test "renders HTTP/2 flowchart with unified host nodes (default)" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "192.168.1.10:8080",
            server_host: "api-gateway",
            clients: [
              %HTTPClientStats{
                client: "10.0.0.1",
                client_host: "web-client",
                connection_count: 1,
                stream_count: 45,
                request_count: 45,
                response_count: 44,
                request_bytes: 12_000,
                response_bytes: 350_000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: 75,
                min_response_time_ms: 12,
                max_response_time_ms: 450,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 45,
            total_responses: 44,
            total_request_bytes: 12_000,
            total_response_bytes: 350_000,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary)

      assert mermaid =~ "flowchart LR"
      # Default is unified host nodes (no subgraphs)
      refute mermaid =~ "subgraph"
      # Unified node IDs (no c_ or s_ prefix)
      assert mermaid =~ "web_client[web-client]"
      assert mermaid =~ "api_gateway[api-gateway]"
      # Edge has protocol:port and stats
      assert mermaid =~ "web_client -->|\"HTTP/2 :8080 (45 req)\"| api_gateway"
    end

    test "renders UDP flowchart with unified host nodes (default)" do
      summary = %Summary{
        http1: [],
        http2: [],
        udp: [
          %UDPService{
            server: "metrics:5005",
            server_host: nil,
            clients: [
              %UDPClientStats{
                client: "10.0.0.5",
                client_host: "sensor-1",
                packet_count: 1200,
                total_bytes: 600_000,
                avg_size: 500,
                min_size: 64,
                max_size: 1400,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_packets: 1200,
            total_bytes: 600_000,
            first_timestamp: nil,
            last_timestamp: nil
          }
        ]
      }

      mermaid = Render.to_mermaid(summary)

      assert mermaid =~ "flowchart LR"
      # Default is unified host nodes (no subgraphs)
      refute mermaid =~ "subgraph"
      # Unified node IDs
      assert mermaid =~ "sensor_1[sensor-1]"
      assert mermaid =~ "metrics[metrics]"
      # Edge has protocol:port and stats
      assert mermaid =~ "sensor_1 -->|\"UDP :5005 (1200 pkts)\"| metrics"
    end

    test "supports top-bottom direction" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "c",
                client_host: nil,
                connection_count: 1,
                stream_count: 1,
                request_count: 1,
                response_count: 1,
                request_bytes: 0,
                response_bytes: 0,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 1,
            total_responses: 1,
            total_request_bytes: 0,
            total_response_bytes: 0,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary, direction: :tb)
      assert mermaid =~ "flowchart TB"
    end

    test "deduplicates clients connected to multiple services (style: :service)" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api1:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "shared-client",
                client_host: nil,
                connection_count: 1,
                stream_count: 5,
                request_count: 5,
                response_count: 5,
                request_bytes: 100,
                response_bytes: 500,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 5,
            total_responses: 5,
            total_request_bytes: 100,
            total_response_bytes: 500,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          },
          %HTTPService{
            protocol: :http2,
            server: "api2:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "shared-client",
                client_host: nil,
                connection_count: 1,
                stream_count: 3,
                request_count: 3,
                response_count: 3,
                request_bytes: 50,
                response_bytes: 200,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 3,
            total_responses: 3,
            total_request_bytes: 50,
            total_response_bytes: 200,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary, style: :service)

      # Client should only appear once in Clients subgraph
      client_matches = Regex.scan(~r/c_shared_client\[shared-client\]/, mermaid)
      assert length(client_matches) == 1

      # But should have connections to both servers
      assert mermaid =~ "c_shared_client -->|\"5 req\"| shttp2_0"
      assert mermaid =~ "c_shared_client -->|\"3 req\"| shttp2_1"
    end

    test "handles special characters in hostnames" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api.example.com:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "client-with-dashes",
                client_host: nil,
                connection_count: 1,
                stream_count: 1,
                request_count: 1,
                response_count: 1,
                request_bytes: 0,
                response_bytes: 0,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 1,
            total_responses: 1,
            total_request_bytes: 0,
            total_response_bytes: 0,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary)

      # IDs should be sanitized (no dots, dashes converted to underscores)
      # Unified node IDs (no c_ or s_ prefix)
      assert mermaid =~ "client_with_dashes"
      # Labels should preserve readable names
      assert mermaid =~ "[client-with-dashes]"
      assert mermaid =~ "[api.example.com]"
    end

    test "supports :none grouping (no subgraphs for services) with style: :service" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "c",
                client_host: nil,
                connection_count: 1,
                stream_count: 1,
                request_count: 1,
                response_count: 1,
                request_bytes: 0,
                response_bytes: 0,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 1,
            total_responses: 1,
            total_request_bytes: 0,
            total_response_bytes: 0,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary, style: :service, group_by: :none)

      # Should have client subgraph but not HTTP/2 subgraph
      assert mermaid =~ "subgraph Clients"
      refute mermaid =~ "subgraph HTTP/2"
      assert mermaid =~ "shttp2_0[api:8080]"
    end
  end

  describe "to_mermaid/2 with style: :host (default)" do
    test "renders unified host nodes with protocol:port on edges" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "192.168.1.10:8080",
            server_host: "api-gateway",
            clients: [
              %HTTPClientStats{
                client: "10.0.0.1",
                client_host: "web-client",
                connection_count: 1,
                stream_count: 45,
                request_count: 45,
                response_count: 44,
                request_bytes: 12_000,
                response_bytes: 350_000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: 75,
                min_response_time_ms: 12,
                max_response_time_ms: 450,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 45,
            total_responses: 44,
            total_request_bytes: 12_000,
            total_response_bytes: 350_000,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary, style: :host)

      assert mermaid =~ "flowchart LR"
      # Unified nodes - no subgraphs
      refute mermaid =~ "subgraph"
      # Unified node IDs (no c_ or s_ prefix)
      assert mermaid =~ "web_client[web-client]"
      assert mermaid =~ "api_gateway[api-gateway]"
      # Edge should have protocol:port and stats
      assert mermaid =~ "web_client -->|\"HTTP/2 :8080 (45 req)\"| api_gateway"
    end

    test "deduplicates hosts with multiple services on same host" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "192.168.1.10:8080",
            server_host: "api-gateway",
            clients: [
              %HTTPClientStats{
                client: "10.0.0.1",
                client_host: "web-client",
                connection_count: 1,
                stream_count: 45,
                request_count: 45,
                response_count: 44,
                request_bytes: 12_000,
                response_bytes: 350_000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: 75,
                min_response_time_ms: 12,
                max_response_time_ms: 450,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 45,
            total_responses: 44,
            total_request_bytes: 12_000,
            total_response_bytes: 350_000,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: [
          %UDPService{
            server: "192.168.1.10:5005",
            server_host: "api-gateway",
            clients: [
              %UDPClientStats{
                client: "10.0.0.1",
                client_host: "web-client",
                packet_count: 100,
                total_bytes: 50_000,
                avg_size: 500,
                min_size: 64,
                max_size: 1400,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_packets: 100,
            total_bytes: 50_000,
            first_timestamp: nil,
            last_timestamp: nil
          }
        ]
      }

      mermaid = Render.to_mermaid(summary, style: :host)

      # Host node should appear only once (unified node ID)
      host_matches = Regex.scan(~r/api_gateway\[api-gateway\]/, mermaid)
      assert length(host_matches) == 1

      # Should have two separate edges with different protocol:port
      assert mermaid =~ "web_client -->|\"HTTP/2 :8080 (45 req)\"| api_gateway"
      assert mermaid =~ "web_client -->|\"UDP :5005 (100 pkts)\"| api_gateway"
    end

    test "handles multiple clients to same host" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "192.168.1.10:8080",
            server_host: "api-gateway",
            clients: [
              %HTTPClientStats{
                client: "10.0.0.1",
                client_host: "web-client",
                connection_count: 1,
                stream_count: 45,
                request_count: 45,
                response_count: 44,
                request_bytes: 12_000,
                response_bytes: 350_000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: 75,
                min_response_time_ms: 12,
                max_response_time_ms: 450,
                first_timestamp: nil,
                last_timestamp: nil
              },
              %HTTPClientStats{
                client: "10.0.0.2",
                client_host: "mobile-app",
                connection_count: 1,
                stream_count: 30,
                request_count: 30,
                response_count: 30,
                request_bytes: 8_000,
                response_bytes: 200_000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: 120,
                min_response_time_ms: 20,
                max_response_time_ms: 500,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 75,
            total_responses: 74,
            total_request_bytes: 20_000,
            total_response_bytes: 550_000,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary, style: :host)

      # Both clients should have edges to the same host (unified node IDs)
      assert mermaid =~ "web_client -->|\"HTTP/2 :8080 (45 req)\"| api_gateway"
      assert mermaid =~ "mobile_app -->|\"HTTP/2 :8080 (30 req)\"| api_gateway"
    end

    test "supports direction option with style: :host" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "api:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "c",
                client_host: nil,
                connection_count: 1,
                stream_count: 1,
                request_count: 1,
                response_count: 1,
                request_bytes: 0,
                response_bytes: 0,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: nil,
                min_response_time_ms: nil,
                max_response_time_ms: nil,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 1,
            total_responses: 1,
            total_request_bytes: 0,
            total_response_bytes: 0,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary, style: :host, direction: :tb)
      assert mermaid =~ "flowchart TB"
    end

    test "returns empty flowchart for empty summary with style: :host" do
      summary = %Summary{http1: [], http2: [], udp: []}
      mermaid = Render.to_mermaid(summary, style: :host)

      assert mermaid =~ "flowchart LR"
      assert mermaid =~ "%% Empty summary"
    end

    test "uses IP when no server_host is set" do
      summary = %Summary{
        http1: [],
        http2: [
          %HTTPService{
            protocol: :http2,
            server: "192.168.1.10:8080",
            server_host: nil,
            clients: [
              %HTTPClientStats{
                client: "10.0.0.1",
                client_host: nil,
                connection_count: 1,
                stream_count: 10,
                request_count: 10,
                response_count: 10,
                request_bytes: 1000,
                response_bytes: 5000,
                methods: %{},
                status_codes: %{},
                avg_response_time_ms: 50,
                min_response_time_ms: 10,
                max_response_time_ms: 100,
                first_timestamp: nil,
                last_timestamp: nil
              }
            ],
            total_requests: 10,
            total_responses: 10,
            total_request_bytes: 1000,
            total_response_bytes: 5000,
            methods: %{},
            status_codes: %{},
            first_timestamp: nil,
            last_timestamp: nil
          }
        ],
        udp: []
      }

      mermaid = Render.to_mermaid(summary, style: :host)

      # Should use IP as host name
      assert mermaid =~ "[192.168.1.10]"
      assert mermaid =~ "HTTP/2 :8080 (10 req)"
    end
  end
end
