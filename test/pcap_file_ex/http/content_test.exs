defmodule PcapFileEx.HTTP.ContentTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.HTTP.Content

  describe "decode/2 with nil/empty content-type" do
    test "returns binary for nil content-type" do
      assert Content.decode(nil, "hello") == {:binary, "hello"}
    end

    test "returns binary for empty content-type" do
      assert Content.decode("", <<1, 2, 3>>) == {:binary, <<1, 2, 3>>}
    end
  end

  describe "decode/2 with JSON content" do
    test "decodes valid JSON object" do
      json = ~s({"key": "value", "num": 42})
      assert {:json, %{"key" => "value", "num" => 42}} = Content.decode("application/json", json)
    end

    test "decodes valid JSON array" do
      json = ~s([1, 2, 3])
      assert {:json, [1, 2, 3]} = Content.decode("application/json", json)
    end

    test "decodes application/problem+json" do
      json = ~s({"type": "about:blank", "title": "Not Found"})

      assert {:json, %{"type" => "about:blank", "title" => "Not Found"}} =
               Content.decode("application/problem+json", json)
    end

    test "ignores charset parameter" do
      json = ~s({"a": 1})
      assert {:json, %{"a" => 1}} = Content.decode("application/json; charset=utf-8", json)
    end

    test "returns binary for invalid JSON" do
      assert {:binary, "not json"} = Content.decode("application/json", "not json")
    end

    test "returns binary for empty JSON body" do
      assert {:binary, ""} = Content.decode("application/json", "")
    end
  end

  describe "decode/2 with text content" do
    test "decodes valid UTF-8 text/plain" do
      assert {:text, "hello world"} = Content.decode("text/plain", "hello world")
    end

    test "decodes text/html" do
      html = "<html><body>Hello</body></html>"
      assert {:text, ^html} = Content.decode("text/html", html)
    end

    test "decodes text/xml" do
      xml = "<?xml version=\"1.0\"?><root/>"
      assert {:text, ^xml} = Content.decode("text/xml", xml)
    end

    test "decodes UTF-8 with BOM" do
      # UTF-8 BOM + text
      body = <<0xEF, 0xBB, 0xBF, "hello"::binary>>
      assert {:text, ^body} = Content.decode("text/plain; charset=utf-8", body)
    end

    test "converts ISO-8859-1 to UTF-8" do
      # Latin-1 encoded "café" (0xE9 is é in Latin-1)
      latin1_body = <<99, 97, 102, 0xE9>>
      assert {:text, "café"} = Content.decode("text/plain; charset=iso-8859-1", latin1_body)
    end

    test "converts latin1 charset alias" do
      latin1_body = <<99, 97, 102, 0xE9>>
      assert {:text, "café"} = Content.decode("text/plain; charset=latin1", latin1_body)
    end

    test "returns binary for invalid UTF-8" do
      # Invalid UTF-8 sequence
      invalid = <<0xFF, 0xFE, 0x00>>
      assert {:binary, ^invalid} = Content.decode("text/plain", invalid)
    end

    test "returns binary for unknown charset" do
      body = "hello"
      assert {:binary, ^body} = Content.decode("text/plain; charset=windows-1252", body)
    end
  end

  describe "decode/2 with binary/unknown content" do
    test "returns binary for application/octet-stream" do
      body = <<1, 2, 3, 4, 5>>
      assert {:binary, ^body} = Content.decode("application/octet-stream", body)
    end

    test "returns binary for application/vnd.3gpp.ngap" do
      body = <<0, 4, 0, 13, 0, 0, 2>>
      assert {:binary, ^body} = Content.decode("application/vnd.3gpp.ngap", body)
    end

    test "returns binary for unknown types" do
      body = "some data"
      assert {:binary, ^body} = Content.decode("application/x-custom", body)
    end
  end

  describe "extract_boundary/1" do
    test "extracts unquoted boundary" do
      ct = "multipart/related; boundary=abc123"
      assert {:ok, "abc123"} = Content.extract_boundary(ct)
    end

    test "extracts quoted boundary" do
      ct = ~s(multipart/related; boundary="abc 123")
      assert {:ok, "abc 123"} = Content.extract_boundary(ct)
    end

    test "extracts boundary with special characters" do
      ct = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk"
      assert {:ok, "----WebKitFormBoundary7MA4YWxk"} = Content.extract_boundary(ct)
    end

    test "extracts boundary when not first parameter" do
      ct = "multipart/related; type=application/json; boundary=xyz789"
      assert {:ok, "xyz789"} = Content.extract_boundary(ct)
    end

    test "returns error when no boundary" do
      assert {:error, :no_boundary} = Content.extract_boundary("application/json")
    end

    test "returns error for empty content-type" do
      assert {:error, :no_boundary} = Content.extract_boundary("")
    end
  end

  describe "parse_parts/2" do
    test "parses single part" do
      body = "--abc\r\nContent-Type: text/plain\r\n\r\nhello\r\n--abc--"
      assert {:ok, [part]} = Content.parse_parts(body, "abc")
      assert part.headers["content-type"] == "text/plain"
      assert part.body == "hello"
    end

    test "parses multiple parts" do
      body = """
      --abc\r
      Content-Type: text/plain\r
      \r
      part1\r
      --abc\r
      Content-Type: application/json\r
      \r
      {"a":1}\r
      --abc--\
      """

      assert {:ok, parts} = Content.parse_parts(body, "abc")
      assert length(parts) == 2

      [p1, p2] = parts
      assert p1.body == "part1"
      assert p2.body == ~s({"a":1})
    end

    test "preserves binary content exactly" do
      # Binary data that shouldn't be modified
      binary_data = <<0, 4, 0, 13, 0, 0, 2, 0, 9, 0, 2>>

      body =
        "--boundary\r\nContent-Type: application/octet-stream\r\n\r\n" <>
          binary_data <> "\r\n--boundary--"

      assert {:ok, [part]} = Content.parse_parts(body, "boundary")
      assert part.body == binary_data
    end

    test "parses Content-Id header" do
      body = "--abc\r\nContent-Type: text/plain\r\nContent-Id: mypart\r\n\r\ndata\r\n--abc--"
      assert {:ok, [part]} = Content.parse_parts(body, "abc")
      assert part.headers["content-id"] == "mypart"
    end

    test "handles empty body part" do
      body = "--abc\r\nContent-Type: text/plain\r\n\r\n\r\n--abc--"
      assert {:ok, [part]} = Content.parse_parts(body, "abc")
      assert part.body == ""
    end

    test "returns error when no delimiter found" do
      assert {:error, :no_delimiter_found} = Content.parse_parts("no delimiter here", "abc")
    end
  end

  describe "decode/2 with multipart content" do
    test "decodes multipart with JSON part" do
      body = """
      --boundary\r
      Content-Type: application/json\r
      Content-Id: jsonData\r
      \r
      {"key":"value"}\r
      --boundary--\
      """

      ct = "multipart/related; boundary=boundary"
      assert {:multipart, [part]} = Content.decode(ct, body)
      assert part.content_type == "application/json"
      assert part.content_id == "jsonData"
      assert part.body == {:json, %{"key" => "value"}}
    end

    test "decodes multipart with text part" do
      body = "--abc\r\nContent-Type: text/plain\r\n\r\nhello\r\n--abc--"
      ct = "multipart/related; boundary=abc"
      assert {:multipart, [part]} = Content.decode(ct, body)
      assert part.body == {:text, "hello"}
    end

    test "decodes multipart with binary part" do
      binary_data = <<0, 1, 2, 3>>

      body =
        "--xyz\r\nContent-Type: application/vnd.3gpp.ngap\r\n\r\n" <>
          binary_data <> "\r\n--xyz--"

      ct = "multipart/related; boundary=xyz"
      assert {:multipart, [part]} = Content.decode(ct, body)
      assert part.content_type == "application/vnd.3gpp.ngap"
      assert part.body == {:binary, binary_data}
    end

    test "recursively decodes nested multipart" do
      inner = "--inner\r\nContent-Type: text/plain\r\n\r\nnested\r\n--inner--"

      body =
        "--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n" <>
          inner <> "\r\n--outer--"

      ct = "multipart/mixed; boundary=outer"
      assert {:multipart, [outer_part]} = Content.decode(ct, body)
      assert {:multipart, [inner_part]} = outer_part.body
      assert inner_part.body == {:text, "nested"}
    end

    test "decodes 5G SBI N2 notify pattern" do
      ngap_binary = <<0, 4, 0, 13, 0, 0, 2, 0, 9, 0, 2, 0, 2, 0, 0, 0, 4, 64, 1, 0>>

      body =
        """
        --boundary_ABC\r
        Content-Type: application/json\r
        Content-Id: jsonData\r
        \r
        {"n2InfoContainer":{"n2InformationClass":"NRPPa"}}\r
        --boundary_ABC\r
        Content-Type: application/vnd.3gpp.ngap\r
        Content-Id: nrppa1\r
        \r
        """ <> ngap_binary <> "\r\n--boundary_ABC--"

      ct = "multipart/related; boundary=boundary_ABC"
      assert {:multipart, [json_part, ngap_part]} = Content.decode(ct, body)

      assert json_part.content_type == "application/json"
      assert json_part.content_id == "jsonData"
      assert {:json, %{"n2InfoContainer" => _}} = json_part.body

      assert ngap_part.content_type == "application/vnd.3gpp.ngap"
      assert ngap_part.content_id == "nrppa1"
      assert {:binary, ^ngap_binary} = ngap_part.body
    end

    test "returns binary when boundary not found" do
      body = "no boundary markers"
      ct = "multipart/related; boundary=missing"
      assert {:binary, ^body} = Content.decode(ct, body)
    end

    test "returns binary when no boundary parameter" do
      body = "--abc\r\nContent-Type: text/plain\r\n\r\nhello\r\n--abc--"
      ct = "multipart/related"
      assert {:binary, ^body} = Content.decode(ct, body)
    end

    test "handles multipart/form-data" do
      body = "--abc\r\nContent-Type: text/plain\r\n\r\nfield value\r\n--abc--"
      ct = "multipart/form-data; boundary=abc"
      assert {:multipart, [part]} = Content.decode(ct, body)
      assert part.body == {:text, "field value"}
    end
  end

  describe "header parsing edge cases" do
    test "handles folded headers (RFC 2822)" do
      body = "--abc\r\nContent-Type: text/plain\r\n with-continuation\r\n\r\ndata\r\n--abc--"
      assert {:ok, [part]} = Content.parse_parts(body, "abc")
      # Folded header value should be joined
      assert part.headers["content-type"] == "text/plain with-continuation"
    end

    test "normalizes header names to lowercase" do
      body = "--abc\r\nCONTENT-TYPE: text/plain\r\nContent-ID: MyId\r\n\r\ndata\r\n--abc--"
      assert {:ok, [part]} = Content.parse_parts(body, "abc")
      assert part.headers["content-type"] == "text/plain"
      assert part.headers["content-id"] == "MyId"
    end

    test "handles missing Content-Type in part" do
      body = "--abc\r\nContent-Id: noct\r\n\r\nbinary data\r\n--abc--"
      ct = "multipart/related; boundary=abc"
      assert {:multipart, [part]} = Content.decode(ct, body)
      # Default to application/octet-stream
      assert part.content_type == "application/octet-stream"
      assert {:binary, "binary data"} = part.body
    end

    test "preserves colons in header values" do
      # Headers like Date contain colons in the value
      body =
        "--abc\r\nContent-Type: text/plain\r\nDate: Tue, 18 Jun 2024 12:34:56 GMT\r\n\r\ndata\r\n--abc--"

      assert {:ok, [part]} = Content.parse_parts(body, "abc")
      assert part.headers["content-type"] == "text/plain"
      assert part.headers["date"] == "Tue, 18 Jun 2024 12:34:56 GMT"
    end

    test "handles URL values with colons" do
      body = "--abc\r\nContent-Location: https://example.com:8080/path\r\n\r\ndata\r\n--abc--"
      assert {:ok, [part]} = Content.parse_parts(body, "abc")
      assert part.headers["content-location"] == "https://example.com:8080/path"
    end
  end
end
