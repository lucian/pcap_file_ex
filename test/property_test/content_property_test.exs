defmodule PcapFileEx.HTTP.ContentPropertyTest do
  @moduledoc """
  Property-based tests for PcapFileEx.HTTP.Content module.

  Tests key invariants:
  - decode/2 never raises on any input
  - decode/2 always returns a valid tagged tuple
  - JSON decoding roundtrips for valid JSON
  - Text content preserves valid UTF-8
  - Multipart parsing preserves binary content exactly
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.HTTP.Content
  import PcapFileEx.PropertyGenerators

  @moduletag :property

  # Number of iterations - higher in CI
  @iterations if System.get_env("CI"), do: 1000, else: 100

  describe "decode/2 robustness" do
    property "never raises for any binary body and content-type" do
      check all body <- binary(),
                ct <- one_of([binary(), constant(nil)]),
                max_runs: @iterations do
        # Should never raise
        result = Content.decode(ct, body)

        # Should always return valid tagged tuple
        assert match?({:json, _}, result) or
                 match?({:text, _}, result) or
                 match?({:multipart, _}, result) or
                 match?({:binary, _}, result)
      end
    end

    property "always returns binary for nil content-type" do
      check all body <- binary(),
                max_runs: @iterations do
        assert {:binary, ^body} = Content.decode(nil, body)
      end
    end

    property "always returns binary for empty content-type" do
      check all body <- binary(),
                max_runs: @iterations do
        assert {:binary, ^body} = Content.decode("", body)
      end
    end
  end

  describe "JSON decoding properties" do
    property "valid JSON is decoded correctly" do
      check all json_str <- json_content_generator(),
                ct <- json_content_type_generator(),
                max_runs: @iterations do
        result = Content.decode(ct, json_str)
        assert {:json, decoded} = result
        # Verify it matches what Jason would decode
        assert {:ok, expected} = Jason.decode(json_str)
        assert decoded == expected
      end
    end

    property "invalid JSON returns binary" do
      check all body <- filter(binary(), fn b -> match?({:error, _}, Jason.decode(b)) end),
                max_runs: @iterations do
        result = Content.decode("application/json", body)
        assert {:binary, ^body} = result
      end
    end

    property "JSON decoding is idempotent" do
      check all json_str <- json_content_generator(),
                max_runs: @iterations do
        {:json, decoded1} = Content.decode("application/json", json_str)
        # Re-encode and decode again
        json_str2 = Jason.encode!(decoded1)
        {:json, decoded2} = Content.decode("application/json", json_str2)
        assert decoded1 == decoded2
      end
    end
  end

  describe "text decoding properties" do
    property "valid UTF-8 text is decoded as text" do
      check all text <- utf8_text_generator(),
                ct <- text_content_type_generator(),
                max_runs: @iterations do
        result = Content.decode(ct, text)
        assert {:text, ^text} = result
      end
    end

    property "text decoding preserves content exactly" do
      check all text <- utf8_text_generator(),
                max_runs: @iterations do
        {:text, decoded} = Content.decode("text/plain", text)
        assert decoded == text
        assert byte_size(decoded) == byte_size(text)
      end
    end

    property "invalid UTF-8 returns binary for text/plain" do
      check all body <-
                  filter(random_binary_generator(), fn b ->
                    byte_size(b) > 0 and not String.valid?(b)
                  end),
                max_runs: @iterations do
        result = Content.decode("text/plain", body)
        assert {:binary, ^body} = result
      end
    end
  end

  describe "binary content properties" do
    property "unknown content types return binary" do
      check all body <- binary(),
                ct <- binary_content_type_generator(),
                max_runs: @iterations do
        result = Content.decode(ct, body)
        assert {:binary, ^body} = result
      end
    end

    property "binary content is preserved exactly" do
      check all body <- random_binary_generator(),
                max_runs: @iterations do
        {:binary, decoded} = Content.decode("application/octet-stream", body)
        assert decoded == body
      end
    end
  end

  describe "boundary extraction properties" do
    property "extract_boundary succeeds for valid boundaries" do
      check all boundary <- multipart_boundary_generator(),
                max_runs: @iterations do
        ct = "multipart/related; boundary=#{boundary}"
        assert {:ok, ^boundary} = Content.extract_boundary(ct)
      end
    end

    property "extract_boundary handles quoted boundaries with spaces" do
      check all prefix <- string(:alphanumeric, min_length: 3, max_length: 10),
                suffix <- string(:alphanumeric, min_length: 3, max_length: 10),
                max_runs: @iterations do
        boundary_with_space = "#{prefix} #{suffix}"
        ct = ~s(multipart/form-data; boundary="#{boundary_with_space}")
        assert {:ok, ^boundary_with_space} = Content.extract_boundary(ct)
      end
    end

    property "extract_boundary fails for non-multipart content types" do
      check all ct <-
                  one_of([
                    json_content_type_generator(),
                    text_content_type_generator()
                  ]),
                max_runs: @iterations do
        assert {:error, :no_boundary} = Content.extract_boundary(ct)
      end
    end
  end

  describe "multipart parsing properties" do
    property "multipart decoding returns multipart tuple" do
      check all {boundary, body} <- simple_multipart_generator(),
                max_runs: @iterations do
        ct = "multipart/related; boundary=#{boundary}"
        result = Content.decode(ct, body)

        assert {:multipart, parts} = result
        assert is_list(parts)
        assert not Enum.empty?(parts)
      end
    end

    property "multipart parts have required fields" do
      check all {boundary, body} <- simple_multipart_generator(),
                max_runs: @iterations do
        ct = "multipart/related; boundary=#{boundary}"
        {:multipart, parts} = Content.decode(ct, body)

        for part <- parts do
          assert Map.has_key?(part, :content_type)
          assert Map.has_key?(part, :content_id)
          assert Map.has_key?(part, :headers)
          assert Map.has_key?(part, :body)
          assert is_binary(part.content_type)
          assert is_map(part.headers)
        end
      end
    end

    property "multipart JSON parts are decoded" do
      check all json_obj <- json_object_generator(),
                boundary <- multipart_boundary_generator(),
                max_runs: @iterations do
        json_str = Jason.encode!(json_obj)

        body =
          "--#{boundary}\r\nContent-Type: application/json\r\n\r\n#{json_str}\r\n--#{boundary}--"

        ct = "multipart/related; boundary=#{boundary}"
        {:multipart, [part]} = Content.decode(ct, body)

        assert part.content_type == "application/json"
        assert {:json, decoded} = part.body
        assert decoded == json_obj
      end
    end

    property "multipart binary parts are preserved" do
      check all binary_data <- random_binary_generator(),
                boundary <- multipart_boundary_generator(),
                max_runs: @iterations do
        body =
          "--#{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n" <>
            binary_data <> "\r\n--#{boundary}--"

        ct = "multipart/related; boundary=#{boundary}"
        {:multipart, [part]} = Content.decode(ct, body)

        assert part.content_type == "application/octet-stream"
        assert {:binary, preserved} = part.body
        assert preserved == binary_data
      end
    end

    property "missing boundary returns binary" do
      check all body <- binary(),
                max_runs: @iterations do
        # Content-type says multipart but body doesn't have the boundary
        result = Content.decode("multipart/related; boundary=missing_boundary", body)
        assert {:binary, ^body} = result
      end
    end
  end

  describe "decode result structure invariants" do
    property "result type matches content-type pattern" do
      check all body <- binary(),
                ct <-
                  one_of([
                    json_content_type_generator(),
                    text_content_type_generator(),
                    binary_content_type_generator(),
                    constant("multipart/mixed; boundary=abc")
                  ]),
                max_runs: @iterations do
        result = Content.decode(ct, body)

        # The result type should be consistent with content-type
        case result do
          {:json, val} ->
            # JSON can decode to any valid JSON value: objects, arrays, strings, numbers, booleans, null
            assert is_map(val) or is_list(val) or is_binary(val) or is_number(val) or
                     is_boolean(val) or is_nil(val)

          {:text, val} ->
            assert is_binary(val)
            assert String.valid?(val)

          {:multipart, val} ->
            assert is_list(val)

          {:binary, val} ->
            assert is_binary(val)
        end
      end
    end

    property "decoded body size is bounded by original size (except multipart metadata)" do
      check all body <- binary(),
                ct <- one_of([constant(nil), constant("application/octet-stream")]),
                max_runs: @iterations do
        {:binary, decoded} = Content.decode(ct, body)
        assert byte_size(decoded) == byte_size(body)
      end
    end
  end
end
