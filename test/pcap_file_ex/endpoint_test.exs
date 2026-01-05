defmodule PcapFileEx.EndpointTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.Endpoint

  describe "new/1" do
    test "creates endpoint with IP only" do
      endpoint = Endpoint.new("192.168.1.1")
      assert endpoint.ip == "192.168.1.1"
      assert endpoint.port == nil
      assert endpoint.host == nil
    end
  end

  describe "new/2" do
    test "creates endpoint with IP and port" do
      endpoint = Endpoint.new("192.168.1.1", 8080)
      assert endpoint.ip == "192.168.1.1"
      assert endpoint.port == 8080
      assert endpoint.host == nil
    end

    test "creates endpoint with nil port" do
      endpoint = Endpoint.new("192.168.1.1", nil)
      assert endpoint.ip == "192.168.1.1"
      assert endpoint.port == nil
      assert endpoint.host == nil
    end
  end

  describe "new/3" do
    test "creates endpoint with IP, port, and host" do
      endpoint = Endpoint.new("192.168.1.1", 8080, "api-server")
      assert endpoint.ip == "192.168.1.1"
      assert endpoint.port == 8080
      assert endpoint.host == "api-server"
    end

    test "creates endpoint with nil host" do
      endpoint = Endpoint.new("192.168.1.1", 8080, nil)
      assert endpoint.ip == "192.168.1.1"
      assert endpoint.port == 8080
      assert endpoint.host == nil
    end
  end

  describe "with_hosts/2" do
    test "applies hosts mapping when IP matches" do
      hosts = %{"192.168.1.1" => "api-server"}
      endpoint = Endpoint.new("192.168.1.1", 8080)
      result = Endpoint.with_hosts(endpoint, hosts)
      assert result.host == "api-server"
      assert result.ip == "192.168.1.1"
      assert result.port == 8080
    end

    test "leaves host nil when IP not in map" do
      hosts = %{"192.168.1.1" => "api-server"}
      endpoint = Endpoint.new("10.0.0.1", 8080)
      result = Endpoint.with_hosts(endpoint, hosts)
      assert result.host == nil
    end

    test "returns nil when endpoint is nil" do
      hosts = %{"192.168.1.1" => "api-server"}
      result = Endpoint.with_hosts(nil, hosts)
      assert result == nil
    end

    test "overwrites existing host" do
      hosts = %{"192.168.1.1" => "new-server"}
      endpoint = Endpoint.new("192.168.1.1", 8080, "old-server")
      result = Endpoint.with_hosts(endpoint, hosts)
      assert result.host == "new-server"
    end
  end

  describe "from_tuple/1" do
    test "creates endpoint from IPv4 tuple" do
      endpoint = Endpoint.from_tuple({{192, 168, 1, 1}, 8080})
      assert endpoint.ip == "192.168.1.1"
      assert endpoint.port == 8080
      assert endpoint.host == nil
    end

    test "creates endpoint from IPv6 tuple" do
      endpoint = Endpoint.from_tuple({{0, 0, 0, 0, 0, 0, 0, 1}, 443})
      assert endpoint.ip == "::1"
      assert endpoint.port == 443
      assert endpoint.host == nil
    end

    test "creates endpoint from full IPv6 tuple" do
      endpoint = Endpoint.from_tuple({{8193, 3512, 0, 0, 0, 0, 0, 1}, 80})
      assert endpoint.ip == "2001:db8::1"
      assert endpoint.port == 80
    end
  end

  describe "from_tuple/2" do
    test "creates endpoint with hosts mapping for IPv4" do
      hosts = %{"192.168.1.1" => "api-server"}
      endpoint = Endpoint.from_tuple({{192, 168, 1, 1}, 8080}, hosts)
      assert endpoint.ip == "192.168.1.1"
      assert endpoint.port == 8080
      assert endpoint.host == "api-server"
    end

    test "creates endpoint with hosts mapping for IPv6" do
      hosts = %{"::1" => "localhost"}
      endpoint = Endpoint.from_tuple({{0, 0, 0, 0, 0, 0, 0, 1}, 443}, hosts)
      assert endpoint.ip == "::1"
      assert endpoint.port == 443
      assert endpoint.host == "localhost"
    end

    test "leaves host nil when IP not in map" do
      hosts = %{"10.0.0.1" => "other-server"}
      endpoint = Endpoint.from_tuple({{192, 168, 1, 1}, 8080}, hosts)
      assert endpoint.host == nil
    end
  end

  describe "to_string/1" do
    test "returns nil for nil endpoint" do
      assert Endpoint.to_string(nil) == nil
    end

    test "returns IP only when no port and no host" do
      endpoint = Endpoint.new("192.168.1.1")
      assert Endpoint.to_string(endpoint) == "192.168.1.1"
    end

    test "returns host when host is set and no port" do
      endpoint = Endpoint.new("192.168.1.1", nil, "api-server")
      assert Endpoint.to_string(endpoint) == "api-server"
    end

    test "returns IP:port when port is set and no host" do
      endpoint = Endpoint.new("192.168.1.1", 8080)
      assert Endpoint.to_string(endpoint) == "192.168.1.1:8080"
    end

    test "returns host:port when both host and port are set" do
      endpoint = Endpoint.new("192.168.1.1", 8080, "api-server")
      assert Endpoint.to_string(endpoint) == "api-server:8080"
    end
  end

  describe "String.Chars protocol" do
    test "implements to_string/1" do
      endpoint = Endpoint.new("192.168.1.1", 8080, "api-server")
      assert "#{endpoint}" == "api-server:8080"
    end
  end
end
