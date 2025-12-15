defmodule PcapFileEx.HTTP2.HeadersTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.HTTP2.Headers

  describe "from_list/1" do
    test "separates pseudo-headers from regular headers" do
      header_list = [
        {":method", "GET"},
        {":path", "/api/users"},
        {":scheme", "https"},
        {":authority", "example.com"},
        {"content-type", "application/json"},
        {"accept", "application/json"}
      ]

      headers = Headers.from_list(header_list)

      assert headers.pseudo == %{
               ":method" => "GET",
               ":path" => "/api/users",
               ":scheme" => "https",
               ":authority" => "example.com"
             }

      assert headers.regular == %{
               "content-type" => "application/json",
               "accept" => "application/json"
             }
    end

    test "handles duplicate headers by creating list" do
      header_list = [
        {":status", "200"},
        {"set-cookie", "session=abc"},
        {"set-cookie", "user=123"}
      ]

      headers = Headers.from_list(header_list)

      assert headers.regular["set-cookie"] == ["session=abc", "user=123"]
    end

    test "normalizes header names to lowercase" do
      header_list = [
        {"Content-Type", "text/html"},
        {"X-Custom-Header", "value"}
      ]

      headers = Headers.from_list(header_list)

      assert Map.has_key?(headers.regular, "content-type")
      assert Map.has_key?(headers.regular, "x-custom-header")
    end

    test "handles empty list" do
      headers = Headers.from_list([])

      assert headers.pseudo == %{}
      assert headers.regular == %{}
    end
  end

  describe "request pseudo-header accessors" do
    setup do
      headers =
        Headers.from_list([
          {":method", "POST"},
          {":path", "/api/users"},
          {":scheme", "https"},
          {":authority", "api.example.com:8080"}
        ])

      {:ok, headers: headers}
    end

    test "method/1 returns :method value", %{headers: headers} do
      assert Headers.method(headers) == "POST"
    end

    test "path/1 returns :path value", %{headers: headers} do
      assert Headers.path(headers) == "/api/users"
    end

    test "scheme/1 returns :scheme value", %{headers: headers} do
      assert Headers.scheme(headers) == "https"
    end

    test "authority/1 returns :authority value", %{headers: headers} do
      assert Headers.authority(headers) == "api.example.com:8080"
    end

    test "returns nil when pseudo-header not present" do
      headers = Headers.from_list([{":method", "GET"}])

      assert Headers.path(headers) == nil
      assert Headers.scheme(headers) == nil
      assert Headers.authority(headers) == nil
    end
  end

  describe "response pseudo-header accessors" do
    test "status/1 returns :status as integer" do
      headers = Headers.from_list([{":status", "200"}])
      assert Headers.status(headers) == 200
    end

    test "status/1 returns nil when not present" do
      headers = Headers.from_list([{":method", "GET"}])
      assert Headers.status(headers) == nil
    end

    test "status_string/1 returns raw status string" do
      headers = Headers.from_list([{":status", "404"}])
      assert Headers.status_string(headers) == "404"
    end
  end

  describe "header type detection" do
    test "request?/1 returns true for request headers" do
      headers = Headers.from_list([{":method", "GET"}, {":path", "/"}])
      assert Headers.request?(headers) == true
    end

    test "request?/1 returns false for response headers" do
      headers = Headers.from_list([{":status", "200"}])
      assert Headers.request?(headers) == false
    end

    test "response?/1 returns true for response headers" do
      headers = Headers.from_list([{":status", "200"}])
      assert Headers.response?(headers) == true
    end

    test "response?/1 returns false for request headers" do
      headers = Headers.from_list([{":method", "GET"}])
      assert Headers.response?(headers) == false
    end

    test "trailers?/1 returns true when no pseudo-headers" do
      headers = Headers.from_list([{"grpc-status", "0"}, {"grpc-message", "OK"}])
      assert Headers.trailers?(headers) == true
    end

    test "trailers?/1 returns false when pseudo-headers present" do
      headers = Headers.from_list([{":status", "200"}, {"content-type", "text/plain"}])
      assert Headers.trailers?(headers) == false
    end
  end

  describe "informational?/1" do
    test "returns true for 1xx status codes" do
      for status <- [100, 101, 102, 103, 199] do
        headers = Headers.from_list([{":status", Integer.to_string(status)}])

        assert Headers.informational?(headers) == true,
               "Expected #{status} to be informational"
      end
    end

    test "returns false for non-1xx status codes" do
      for status <- [200, 301, 404, 500] do
        headers = Headers.from_list([{":status", Integer.to_string(status)}])
        assert Headers.informational?(headers) == false
      end
    end

    test "returns false when no status present" do
      headers = Headers.from_list([{":method", "GET"}])
      assert Headers.informational?(headers) == false
    end
  end

  describe "regular header access" do
    setup do
      headers =
        Headers.from_list([
          {":status", "200"},
          {"content-type", "application/json"},
          {"cache-control", "no-cache"},
          {"set-cookie", "a=1"},
          {"set-cookie", "b=2"}
        ])

      {:ok, headers: headers}
    end

    test "get/2 returns single header value", %{headers: headers} do
      assert Headers.get(headers, "content-type") == "application/json"
    end

    test "get/2 returns list for multi-value header", %{headers: headers} do
      assert Headers.get(headers, "set-cookie") == ["a=1", "b=2"]
    end

    test "get/2 returns nil for missing header", %{headers: headers} do
      assert Headers.get(headers, "x-missing") == nil
    end

    test "get/2 is case-insensitive", %{headers: headers} do
      assert Headers.get(headers, "Content-Type") == "application/json"
      assert Headers.get(headers, "CONTENT-TYPE") == "application/json"
    end

    test "get_string/2 returns single value as-is", %{headers: headers} do
      assert Headers.get_string(headers, "content-type") == "application/json"
    end

    test "get_string/2 joins multi-value headers", %{headers: headers} do
      assert Headers.get_string(headers, "set-cookie") == "a=1, b=2"
    end

    test "get_string/2 returns nil for missing header", %{headers: headers} do
      assert Headers.get_string(headers, "x-missing") == nil
    end
  end

  describe "has_pseudo?/1" do
    test "returns true when pseudo-header exists" do
      headers = Headers.from_list([{":method", "GET"}, {":path", "/"}])

      assert Headers.has_pseudo?(headers, ":method") == true
      assert Headers.has_pseudo?(headers, ":path") == true
    end

    test "returns false when pseudo-header missing" do
      headers = Headers.from_list([{":method", "GET"}])

      assert Headers.has_pseudo?(headers, ":status") == false
      assert Headers.has_pseudo?(headers, ":authority") == false
    end
  end

  describe "to_list/1 and all_to_list/1" do
    test "to_list/1 returns only regular headers" do
      headers =
        Headers.from_list([
          {":status", "200"},
          {"content-type", "text/html"},
          {"x-custom", "value"}
        ])

      list = Headers.to_list(headers)

      assert {"content-type", "text/html"} in list
      assert {"x-custom", "value"} in list
      refute Enum.any?(list, fn {k, _} -> String.starts_with?(k, ":") end)
    end

    test "to_list/1 expands multi-value headers" do
      headers =
        Headers.from_list([
          {"set-cookie", "a=1"},
          {"set-cookie", "b=2"}
        ])

      list = Headers.to_list(headers)

      assert {"set-cookie", "a=1"} in list
      assert {"set-cookie", "b=2"} in list
      assert length(list) == 2
    end

    test "all_to_list/1 includes pseudo-headers first" do
      headers =
        Headers.from_list([
          {":status", "200"},
          {"content-type", "text/html"}
        ])

      list = Headers.all_to_list(headers)

      assert [{":status", "200"}, {"content-type", "text/html"}] == list
    end
  end
end
