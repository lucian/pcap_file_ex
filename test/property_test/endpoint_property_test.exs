defmodule PcapFileEx.EndpointPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.Endpoint

  # Generators

  defp ipv4_tuple_generator do
    gen all(
          a <- StreamData.integer(0..255),
          b <- StreamData.integer(0..255),
          c <- StreamData.integer(0..255),
          d <- StreamData.integer(0..255)
        ) do
      {a, b, c, d}
    end
  end

  defp ipv6_tuple_generator do
    gen all(parts <- StreamData.list_of(StreamData.integer(0..65_535), length: 8)) do
      List.to_tuple(parts)
    end
  end

  defp port_generator do
    StreamData.integer(0..65_535)
  end

  defp ip_string_generator do
    gen all(
          a <- StreamData.integer(0..255),
          b <- StreamData.integer(0..255),
          c <- StreamData.integer(0..255),
          d <- StreamData.integer(0..255)
        ) do
      "#{a}.#{b}.#{c}.#{d}"
    end
  end

  defp hostname_generator do
    gen all(name <- StreamData.string(:alphanumeric, min_length: 1, max_length: 20)) do
      name
    end
  end

  defp hosts_map_generator do
    gen all(
          pairs <-
            StreamData.list_of(
              StreamData.tuple({ip_string_generator(), hostname_generator()}),
              max_length: 5
            )
        ) do
      Map.new(pairs)
    end
  end

  # Properties

  describe "new/1" do
    property "always creates endpoint with given IP" do
      check all(ip <- ip_string_generator()) do
        endpoint = Endpoint.new(ip)
        assert endpoint.ip == ip
        assert endpoint.port == nil
        assert endpoint.host == nil
      end
    end
  end

  describe "new/2" do
    property "always creates endpoint with given IP and port" do
      check all(
              ip <- ip_string_generator(),
              port <- port_generator()
            ) do
        endpoint = Endpoint.new(ip, port)
        assert endpoint.ip == ip
        assert endpoint.port == port
        assert endpoint.host == nil
      end
    end
  end

  describe "new/3" do
    property "always creates endpoint with all fields" do
      check all(
              ip <- ip_string_generator(),
              port <- port_generator(),
              host <- hostname_generator()
            ) do
        endpoint = Endpoint.new(ip, port, host)
        assert endpoint.ip == ip
        assert endpoint.port == port
        assert endpoint.host == host
      end
    end
  end

  describe "from_tuple/1" do
    property "IPv4 tuples produce valid IP strings" do
      check all(
              ip_tuple <- ipv4_tuple_generator(),
              port <- port_generator()
            ) do
        endpoint = Endpoint.from_tuple({ip_tuple, port})
        # IP should be a valid string
        assert is_binary(endpoint.ip)
        assert endpoint.port == port
        # Should be parseable back to tuple via :inet.parse_address
        {:ok, _parsed} = :inet.parse_address(to_charlist(endpoint.ip))
      end
    end

    property "IPv6 tuples produce valid IP strings" do
      check all(
              ip_tuple <- ipv6_tuple_generator(),
              port <- port_generator()
            ) do
        endpoint = Endpoint.from_tuple({ip_tuple, port})
        assert is_binary(endpoint.ip)
        assert endpoint.port == port
        {:ok, _parsed} = :inet.parse_address(to_charlist(endpoint.ip))
      end
    end
  end

  describe "from_tuple/2" do
    property "host is looked up from hosts_map" do
      check all(
              ip_tuple <- ipv4_tuple_generator(),
              port <- port_generator(),
              hosts_map <- hosts_map_generator()
            ) do
        endpoint = Endpoint.from_tuple({ip_tuple, port}, hosts_map)
        expected_host = Map.get(hosts_map, endpoint.ip)
        assert endpoint.host == expected_host
      end
    end
  end

  describe "with_hosts/2" do
    property "nil endpoint returns nil" do
      check all(hosts_map <- hosts_map_generator()) do
        assert Endpoint.with_hosts(nil, hosts_map) == nil
      end
    end

    property "applies host when IP matches" do
      check all(
              ip <- ip_string_generator(),
              port <- port_generator(),
              host <- hostname_generator()
            ) do
        endpoint = Endpoint.new(ip, port)
        hosts_map = %{ip => host}
        result = Endpoint.with_hosts(endpoint, hosts_map)
        assert result.host == host
        assert result.ip == ip
        assert result.port == port
      end
    end
  end

  describe "to_string/1" do
    property "nil endpoint returns nil" do
      assert Endpoint.to_string(nil) == nil
    end

    property "result always includes IP or host" do
      check all(
              ip <- ip_string_generator(),
              port <- StreamData.one_of([StreamData.constant(nil), port_generator()]),
              host <- StreamData.one_of([StreamData.constant(nil), hostname_generator()])
            ) do
        endpoint = Endpoint.new(ip, port, host)
        result = Endpoint.to_string(endpoint)
        assert is_binary(result)
        # Result should contain either host or IP
        assert String.contains?(result, host || ip)
      end
    end

    property "port is appended with colon when present" do
      check all(
              ip <- ip_string_generator(),
              port <- port_generator()
            ) do
        endpoint = Endpoint.new(ip, port)
        result = Endpoint.to_string(endpoint)
        assert String.contains?(result, ":#{port}")
      end
    end

    property "no colon when port is nil" do
      check all(ip <- ip_string_generator()) do
        endpoint = Endpoint.new(ip, nil)
        result = Endpoint.to_string(endpoint)
        refute String.contains?(result, ":")
      end
    end
  end

  describe "invariants" do
    property "from_tuple followed by to_string never raises" do
      check all(
              ip_tuple <- ipv4_tuple_generator(),
              port <- port_generator(),
              hosts_map <- hosts_map_generator()
            ) do
        endpoint = Endpoint.from_tuple({ip_tuple, port}, hosts_map)
        # Should not raise
        result = Endpoint.to_string(endpoint)
        assert is_binary(result)
      end
    end
  end
end
