defmodule PcapFileEx.HTTP.ContentCustomDecoderTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.HTTP.Content

  describe "decode/3 with custom decoders" do
    test "tries custom decoder for binary content-type" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body, content_type: "application/x-custom"},
        decoder: fn payload -> {:custom_decoded, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      result = Content.decode("application/x-custom", "test data", opts)

      assert {:custom, {:custom_decoded, "test data"}} = result
    end

    test "returns decode_error when decoder returns error" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body},
        decoder: fn _payload -> {:error, :parse_failed} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      result = Content.decode("application/octet-stream", "bad data", opts)

      assert {:decode_error, :parse_failed} = result
    end

    test "falls back to binary when decoder returns :skip" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body},
        decoder: fn _ctx, _payload -> :skip end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      result = Content.decode("application/octet-stream", "test data", opts)

      assert {:binary, "test data"} = result
    end

    test "does not invoke decoder for JSON content-type (built-in takes precedence)" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body},
        decoder: fn _payload -> :should_not_be_called end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      result = Content.decode("application/json", ~s({"key":"value"}), opts)

      # Built-in JSON decoder takes precedence
      assert {:json, %{"key" => "value"}} = result
    end

    test "invokes decoder when JSON parsing fails" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body, content_type: "application/json"},
        decoder: fn payload -> {:custom_json, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      # Invalid JSON
      result = Content.decode("application/json", "not valid json", opts)

      # Custom decoder is invoked because JSON parse failed
      assert {:custom, {:custom_json, "not valid json"}} = result
    end

    test "does not invoke decoder for text content-type (built-in takes precedence)" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body},
        decoder: fn _payload -> :should_not_be_called end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      result = Content.decode("text/plain", "hello world", opts)

      # Built-in text decoder takes precedence
      assert {:text, "hello world"} = result
    end

    test "multipart parts can have custom decoders" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :multipart_part, content_type: "application/x-custom"},
        decoder: fn payload -> {:decoded_part, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      multipart_body = """
      --boundary\r
      Content-Type: application/x-custom\r
      \r
      custom data\r
      --boundary--\
      """

      result = Content.decode("multipart/related; boundary=boundary", multipart_body, opts)

      assert {:multipart, [part]} = result
      assert part.content_type == "application/x-custom"
      assert {:custom, {:decoded_part, "custom data"}} = part.body
    end

    test "multipart JSON parts use built-in decoder" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :multipart_part},
        decoder: fn _payload -> :should_not_be_called end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      multipart_body = """
      --boundary\r
      Content-Type: application/json\r
      \r
      {"key":"value"}\r
      --boundary--\
      """

      result = Content.decode("multipart/related; boundary=boundary", multipart_body, opts)

      assert {:multipart, [part]} = result
      assert {:json, %{"key" => "value"}} = part.body
    end

    test "context scope is set to :multipart_part for parts" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :multipart_part},
        decoder: fn ctx, payload ->
          # Capture context for assertion
          send(self(), {:ctx, ctx})
          {:ok, payload}
        end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body, method: "POST", path: "/api"}
      opts = [decoders: [decoder], context: ctx]

      multipart_body = """
      --boundary\r
      Content-Type: application/octet-stream\r
      Content-ID: part1\r
      \r
      binary data\r
      --boundary--\
      """

      Content.decode("multipart/related; boundary=boundary", multipart_body, opts)

      assert_received {:ctx, part_ctx}
      assert part_ctx.scope == :multipart_part
      assert part_ctx.content_type == "application/octet-stream"
      assert part_ctx.content_id == "part1"
      assert part_ctx.method == "POST"
      assert part_ctx.path == "/api"
    end

    test "nil content-type tries custom decoders" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body},
        decoder: fn payload -> {:decoded_nil_ct, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      result = Content.decode(nil, "test data", opts)

      assert {:custom, {:decoded_nil_ct, "test data"}} = result
    end

    test "empty decoders list falls back to binary" do
      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [], context: ctx]

      result = Content.decode("application/octet-stream", "test data", opts)

      assert {:binary, "test data"} = result
    end

    test "no opts falls back to binary for unknown content-type" do
      result = Content.decode("application/octet-stream", "test data")

      assert {:binary, "test data"} = result
    end

    # Tests for code review fixes

    test "invokes decoder when text decoding fails (invalid UTF-8)" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body, content_type: "text/plain"},
        decoder: fn payload -> {:custom_text, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      # Invalid UTF-8 bytes
      invalid_utf8 = <<0xFF, 0xFE, 0x00>>
      result = Content.decode("text/plain", invalid_utf8, opts)

      # Custom decoder is invoked because text decode failed
      assert {:custom, {:custom_text, ^invalid_utf8}} = result
    end

    test "invokes decoder when text decoding fails (unknown charset)" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body, content_type: "text/plain"},
        decoder: fn payload -> {:custom_charset, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      # Unknown charset - should fall back to binary then try custom decoders
      result = Content.decode("text/plain; charset=unknown-charset", "test data", opts)

      # Custom decoder is invoked because unknown charset yields binary
      assert {:custom, {:custom_charset, "test data"}} = result
    end

    test "invokes decoder when multipart parsing fails (no boundary)" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body, content_type: "multipart/related"},
        decoder: fn payload -> {:custom_multipart, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      # Multipart without boundary parameter - parse should fail
      result = Content.decode("multipart/related", "some body data", opts)

      # Custom decoder is invoked because multipart parse failed
      assert {:custom, {:custom_multipart, "some body data"}} = result
    end

    test "invokes decoder when multipart parsing fails (malformed body)" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :body, content_type: "multipart/related"},
        decoder: fn payload -> {:custom_malformed, payload} end
      }

      ctx = %{protocol: :http1, direction: :request, scope: :body}
      opts = [decoders: [decoder], context: ctx]

      # Malformed multipart - no delimiter found
      malformed_body = "this is not a valid multipart body"
      result = Content.decode("multipart/related; boundary=myboundary", malformed_body, opts)

      # Custom decoder is invoked because multipart parse failed
      assert {:custom, {:custom_malformed, ^malformed_body}} = result
    end

    test "multipart part context includes part's own headers" do
      decoder = %{
        protocol: :http1,
        match: %{scope: :multipart_part},
        decoder: fn ctx, payload ->
          # Capture context for assertion
          send(self(), {:part_ctx, ctx})
          {:ok, payload}
        end
      }

      ctx = %{
        protocol: :http1,
        direction: :request,
        scope: :body,
        # Parent request headers - should be overridden for parts
        headers: %{"content-type" => "multipart/related", "x-parent" => "value"}
      }

      opts = [decoders: [decoder], context: ctx]

      multipart_body = """
      --boundary\r
      Content-Type: application/octet-stream\r
      X-Part-Header: part-value\r
      Content-ID: my-part-id\r
      \r
      binary data\r
      --boundary--\
      """

      Content.decode("multipart/related; boundary=boundary", multipart_body, opts)

      assert_received {:part_ctx, part_ctx}
      # Part context should have part's own headers, not parent request headers
      assert part_ctx.headers == %{
               "content-type" => "application/octet-stream",
               "x-part-header" => "part-value",
               "content-id" => "my-part-id"
             }

      # Should NOT have parent headers
      refute Map.has_key?(part_ctx.headers, "x-parent")
    end
  end
end
