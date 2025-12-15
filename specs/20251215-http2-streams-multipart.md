# Generic HTTP Content Decoding Specification

**Date**: 2025-12-15
**Status**: Draft
**Scope**: Content-Type based recursive body decoding for HTTP/1.1 and HTTP/2

## Overview

This specification defines a generic HTTP body content decoder that recursively decodes structured content based on `Content-Type` headers. It complements HTTP/2 stream reconstruction by providing automatic decoding of multipart bodies, JSON, and text content.

## Design Principles

1. **Content-Type driven** - Decode strategy determined by Content-Type header
2. **Recursive** - Multipart parts are decoded based on their own Content-Type
3. **Safe fallback** - Unknown types remain as binary (no crashes)
4. **Extensible** - Easy to add new decoders

---

## Decoded Content Types

| Content-Type Pattern | Decoded As | Elixir Type |
|---------------------|------------|-------------|
| `multipart/*` | Parsed parts | `{:multipart, [part()]}` |
| `application/json` | JSON decoded | `{:json, map() \| list()}` |
| `application/problem+json` | JSON decoded | `{:json, map()}` |
| `text/*` | UTF-8 string | `{:text, String.t()}` |
| (unknown) | Raw binary | `{:binary, binary()}` |

---

## Data Structures

### Content Module

```elixir
defmodule PcapFileEx.HTTP.Content do
  @moduledoc """
  Generic HTTP body content decoder based on Content-Type.
  Recursively decodes multipart bodies, JSON, and text.
  Unknown types remain as binary.
  """

  @type decoded ::
          {:json, map() | list()}
          | {:text, String.t()}
          | {:multipart, [part()]}
          | {:binary, binary()}

  @type part :: %{
          content_type: String.t(),
          content_id: String.t() | nil,
          headers: %{String.t() => String.t()},
          body: decoded()
        }

  @doc """
  Decode HTTP body based on Content-Type header.

  ## Examples

      iex> Content.decode("application/json", ~s({"key": "value"}))
      {:json, %{"key" => "value"}}

      iex> Content.decode("text/plain", "hello")
      {:text, "hello"}

      iex> Content.decode("application/octet-stream", <<1, 2, 3>>)
      {:binary, <<1, 2, 3>>}

      iex> Content.decode("multipart/related; boundary=abc", body)
      {:multipart, [%{content_type: "application/json", body: {:json, %{...}}}, ...]}
  """
  @spec decode(String.t() | nil, binary()) :: decoded()
  def decode(content_type, body)

  @doc """
  Extract boundary parameter from multipart Content-Type.

  ## Examples

      iex> Content.extract_boundary("multipart/related; boundary=abc123")
      {:ok, "abc123"}

      iex> Content.extract_boundary("application/json")
      {:error, :no_boundary}
  """
  @spec extract_boundary(String.t()) :: {:ok, String.t()} | {:error, :no_boundary}
  def extract_boundary(content_type)

  @doc """
  Parse MIME multipart body into parts.

  ## Examples

      iex> Content.parse_parts(body, "boundary123")
      {:ok, [%{headers: %{...}, body: "..."}, ...]}
  """
  @spec parse_parts(binary(), String.t()) :: {:ok, [raw_part()]} | {:error, term()}
  def parse_parts(body, boundary)
end
```

### Part Structure

Each multipart part contains:

| Field | Type | Description |
|-------|------|-------------|
| `content_type` | `String.t()` | Part's Content-Type header |
| `content_id` | `String.t() \| nil` | Part's Content-Id header (for cross-references) |
| `headers` | `map()` | All part headers (lowercase keys) |
| `body` | `decoded()` | Recursively decoded body |

---

## Algorithm

### Main Decode Function

```
FUNCTION decode(content_type, body):
    IF content_type is nil:
        RETURN {:binary, body}

    base_type = normalize_content_type(content_type)  // Strip params, lowercase

    IF base_type starts with "multipart/":
        boundary = extract_boundary(content_type)
        IF boundary is error:
            RETURN {:binary, body}

        parts = parse_mime_parts(body, boundary)
        IF parts is error:
            RETURN {:binary, body}

        decoded_parts = []
        FOR each part IN parts:
            part_ct = part.headers["content-type"] OR "application/octet-stream"
            decoded_body = decode(part_ct, part.body)  // RECURSIVE CALL
            decoded_parts.append(%{
                content_type: part_ct,
                content_id: part.headers["content-id"],
                headers: part.headers,
                body: decoded_body
            })

        RETURN {:multipart, decoded_parts}

    ELSE IF base_type IN ["application/json", "application/problem+json"]:
        CASE Jason.decode(body):
            {:ok, data} -> RETURN {:json, data}
            {:error, _} -> RETURN {:binary, body}  // Invalid JSON

    ELSE IF base_type starts with "text/":
        charset = extract_charset(content_type) OR "utf-8"
        RETURN decode_text(body, charset)

    ELSE:
        RETURN {:binary, body}


FUNCTION decode_text(body, charset):
    // Charset-aware text decoding with UTF-8 validation
    IF charset IN ["utf-8", "utf8"]:
        IF String.valid?(body):
            RETURN {:text, body}
        ELSE:
            RETURN {:binary, body}  // Invalid UTF-8, return as binary

    ELSE IF charset IN ["iso-8859-1", "latin1", "latin-1"]:
        // Convert ISO-8859-1 to UTF-8
        converted = :unicode.characters_to_binary(body, :latin1)
        RETURN {:text, converted}

    ELSE:
        // Unknown charset - return as binary (safe fallback)
        RETURN {:binary, body}


FUNCTION extract_charset(content_type):
    // "text/plain; charset=utf-8" → "utf-8"
    // "text/plain; charset=\"iso-8859-1\"" → "iso-8859-1"
    match = regex_match(content_type, /charset="?([^";\s]+)"?/i)
    IF match:
        RETURN match[1].downcase()
    ELSE:
        RETURN nil
```

### Helper Functions

```
FUNCTION normalize_content_type(content_type):
    // "application/json; charset=utf-8" → "application/json"
    base = content_type.split(";")[0]
    RETURN base.trim().downcase()


FUNCTION extract_boundary(content_type):
    // "multipart/related; boundary=abc123" → {:ok, "abc123"}
    // "multipart/related; boundary=\"abc 123\"" → {:ok, "abc 123"}

    // Try quoted boundary first (can contain spaces)
    quoted_match = regex_match(content_type, /boundary="([^"]+)"/)
    IF quoted_match:
        RETURN {:ok, quoted_match[1]}

    // Try unquoted boundary (no spaces allowed)
    unquoted_match = regex_match(content_type, /boundary=([^\s;]+)/)
    IF unquoted_match:
        RETURN {:ok, unquoted_match[1]}

    RETURN {:error, :no_boundary}
```

---

## MIME Multipart Parsing

### Structure

```
--boundary
Content-Type: application/json
Content-Id: part1

{"key": "value"}

--boundary
Content-Type: application/octet-stream
Content-Id: part2

<binary data>
--boundary--
```

### Parsing Algorithm (RFC 2046 Compliant)

**Key principles:**
- Use binary pattern matching (`:binary.split/2`) to preserve exact bytes
- Never trim or modify part body content
- Handle CRLF semantics correctly per RFC 2046

```
FUNCTION parse_mime_parts(body, boundary):
    // RFC 2046: delimiter = CRLF + "--" + boundary
    // First delimiter may omit leading CRLF (start of body)
    delimiter = "\r\n--" <> boundary
    first_delimiter = "--" <> boundary
    terminator = "\r\n--" <> boundary <> "--"

    // Skip preamble (content before first delimiter)
    body = skip_to_first_delimiter(body, first_delimiter)
    IF body == :not_found:
        RETURN {:error, :no_delimiter_found}

    parts = []
    WHILE body != <<>>:
        // Check for terminator
        IF :binary.match(body, terminator) == {0, _}:
            BREAK

        // Each part starts after CRLF following the delimiter
        // Format: --boundary\r\n<headers>\r\n\r\n<body>\r\n--boundary...
        body = skip_crlf_after_delimiter(body)

        // Find next delimiter using binary search
        CASE :binary.split(body, delimiter):
            [part_data, rest] ->
                part = parse_single_part(part_data)
                parts.append(part)
                body = rest

            [remaining] ->
                // No more delimiters - check for terminator at end
                terminator_no_crlf = "--" <> boundary <> "--"
                CASE :binary.split(remaining, terminator_no_crlf):
                    [part_data, _epilogue] ->
                        // Strip trailing CRLF before terminator (RFC 2046 requirement)
                        part_data = strip_trailing_crlf(part_data)
                        part = parse_single_part(part_data)
                        parts.append(part)
                    [_no_terminator] ->
                        // Malformed - no terminator found
                        :ok
                BREAK

    RETURN {:ok, parts}


FUNCTION skip_to_first_delimiter(body, first_delimiter):
    // Find "--boundary" at start or after preamble
    CASE :binary.match(body, first_delimiter):
        {pos, len} ->
            // Skip to end of delimiter
            :binary.part(body, pos + len, byte_size(body) - pos - len)
        :nomatch ->
            :not_found


FUNCTION skip_crlf_after_delimiter(body):
    // After delimiter, expect CRLF before headers
    IF body starts with "\r\n":
        :binary.part(body, 2, byte_size(body) - 2)
    ELSE:
        body  // Tolerate missing CRLF


FUNCTION strip_trailing_crlf(data):
    // RFC 2046: CRLF before delimiter is part of delimiter, not body
    size = byte_size(data)
    IF size >= 2 AND :binary.part(data, size - 2, 2) == "\r\n":
        :binary.part(data, 0, size - 2)
    ELSE:
        data


FUNCTION parse_single_part(data):
    // Split at CRLF+CRLF (headers/body separator)
    // IMPORTANT: Use :binary.split to preserve exact bytes in body
    CASE :binary.split(data, "\r\n\r\n"):
        [headers_raw, part_body] ->
            headers = parse_part_headers(headers_raw)
            // DO NOT modify part_body - preserve exact binary content
            RETURN %{headers: headers, body: part_body}

        [headers_only] ->
            // No body separator found - treat as headers only
            headers = parse_part_headers(headers_only)
            RETURN %{headers: headers, body: <<>>}


FUNCTION parse_part_headers(raw):
    // Input: "Content-Type: application/json\r\nContent-Id: foo"
    // Output: %{"content-type" => "application/json", "content-id" => "foo"}

    headers = %{}

    // Handle line continuations (folded headers per RFC 2822)
    unfolded = :binary.replace(raw, "\r\n ", " ", [:global])
    unfolded = :binary.replace(unfolded, "\r\n\t", " ", [:global])

    // Split into lines and parse each header
    lines = :binary.split(unfolded, "\r\n", [:global])

    FOR each line IN lines:
        // Skip empty lines (e.g., leading CRLF)
        IF byte_size(line) == 0:
            CONTINUE

        // Find colon separator
        CASE :binary.split(line, ":"):
            [name, value] ->
                // Trim and lowercase header name
                name = String.trim(name) |> String.downcase()
                value = String.trim(value)
                headers[name] = value
            [_no_colon] ->
                // Malformed header line - skip
                CONTINUE

    RETURN headers
```

**Why this approach is safe for binary content:**

1. **`:binary.split/2`** operates on raw bytes, not Unicode codepoints
2. **No trimming** of part body - preserves NGAP/ASN.1 blobs exactly
3. **CRLF handling** follows RFC 2046 - only strips delimiter-adjacent CRLFs
4. **Boundary collision**: Uses full `\r\n--boundary` pattern which is highly unlikely to appear in binary content (would require exact CRLF + `--` + boundary bytes)

---

## Integration with HTTP/2 Analyzer

By default, `HTTP2.analyze/1` automatically decodes request and response bodies based on Content-Type. This eliminates the need for manual `Content.decode/2` calls.

### Enhanced Exchange Structure

The `Exchange` struct includes both raw and decoded body:

```elixir
@type request :: %{
  headers: Headers.t(),
  trailers: Headers.t() | nil,
  body: binary(),                          # Raw bytes (always present)
  decoded_body: Content.decoded() | nil,   # nil when decode_content: false
  method: String.t(),
  path: String.t(),
  authority: String.t() | nil
}

@type response :: %{
  headers: Headers.t(),
  trailers: Headers.t() | nil,
  body: binary(),                          # Raw bytes (always present)
  decoded_body: Content.decoded() | nil,   # nil when decode_content: false
  status: integer(),
  informational: [Headers.t()]
}
```

### Default Behavior (Content Decoding Enabled)

```elixir
# Content decoding is ON by default
{:ok, exchanges, _incomplete} = HTTP2.analyze("capture.pcap")

for ex <- exchanges do
  # Decoded content is directly available
  case ex.request.decoded_body do
    {:multipart, parts} ->
      IO.puts("Multipart request with #{length(parts)} parts:")
      for part <- parts do
        IO.puts("  - #{part.content_type} (#{part.content_id})")
        case part.body do
          {:json, data} -> IO.inspect(data)
          {:binary, bin} -> IO.puts("    Binary: #{byte_size(bin)} bytes")
          {:text, txt} -> IO.puts("    Text: #{String.slice(txt, 0, 50)}...")
        end
      end

    {:json, data} ->
      IO.inspect(data, label: "JSON Request")

    {:text, text} ->
      IO.puts("Text: #{String.slice(text, 0, 100)}...")

    {:binary, bin} ->
      IO.puts("Binary: #{byte_size(bin)} bytes")
  end

  # Raw body is also available if needed
  IO.puts("Raw body size: #{byte_size(ex.request.body)} bytes")
end
```

### Disabling Content Decoding

For performance or when raw bodies are preferred:

```elixir
# Skip content decoding
{:ok, exchanges, _incomplete} = HTTP2.analyze("capture.pcap", decode_content: false)

for ex <- exchanges do
  # decoded_body is nil when decoding is disabled
  assert ex.request.decoded_body == nil
  assert ex.response.decoded_body == nil

  # Only raw body is available
  IO.puts("Raw body: #{byte_size(ex.request.body)} bytes")
end
```

### Accessing Multipart Parts

```elixir
{:ok, exchanges, _} = HTTP2.analyze("capture.pcap")

for ex <- exchanges do
  case ex.request.decoded_body do
    {:multipart, parts} ->
      # Find JSON metadata part
      json_part = Enum.find(parts, &(&1.content_type == "application/json"))

      case json_part do
        %{body: {:json, metadata}} ->
          IO.inspect(metadata["n2InfoContainer"])
        _ ->
          :no_json_part
      end

      # Find binary parts by Content-Id
      ngap_part = Enum.find(parts, &(&1.content_id == "nrppa1"))

      case ngap_part do
        %{body: {:binary, ngap_data}} ->
          # Pass to external NGAP decoder
          decode_ngap(ngap_data)
        _ ->
          :no_ngap_part
      end

    _ ->
      :not_multipart
  end
end
```

### Manual Decoding (Standalone)

The `Content` module can still be used standalone for other HTTP sources:

```elixir
alias PcapFileEx.HTTP.Content

# Decode any content based on Content-Type
# Returns decoded tuple directly (not wrapped in {:ok, ...})
{:multipart, parts} = Content.decode("multipart/related; boundary=abc", body)
{:json, data} = Content.decode("application/json", json_body)
{:binary, raw} = Content.decode("application/octet-stream", binary_body)
```

### API Changes to HTTP2 Module

```elixir
defmodule PcapFileEx.HTTP2 do
  @doc """
  Analyzes a PCAP file and returns HTTP/2 exchanges.

  ## Options

  - `:decode_content` - When `true` (default), automatically decodes request
    and response bodies based on Content-Type. Set to `false` to skip decoding
    and only populate raw `body` fields.

  ## Examples

      # Default: content decoding enabled
      {:ok, complete, incomplete} = HTTP2.analyze("capture.pcap")

      # Explicitly enable (same as default)
      {:ok, complete, incomplete} = HTTP2.analyze("capture.pcap", decode_content: true)

      # Disable content decoding for performance
      {:ok, complete, incomplete} = HTTP2.analyze("capture.pcap", decode_content: false)
  """
  @spec analyze(Path.t() | Enumerable.t(), keyword()) ::
          {:ok, [Exchange.t()], [IncompleteExchange.t()]} | {:error, term()}
  def analyze(source, opts \\ [])
end
```

---

## Example: 5G N2 Notify

### Input

```
Content-Type: multipart/related; boundary=boundary_ABC123

--boundary_ABC123
Content-Type: application/json
Content-Id: jsonData

{"lcsCorrelationId":"corr-123","n2InfoContainer":{"n2InformationClass":"NRPPa","nrppaInfo":{"nrppaPdu":{"ngapData":{"contentId":"nrppa1"},"ngapIeType":"NRPPA_PDU"}}}}

--boundary_ABC123
Content-Type: application/vnd.3gpp.ngap
Content-Id: nrppa1

<20 bytes binary NGAP/NRPPa ASN.1 PER>
--boundary_ABC123--
```

### Output

```elixir
{:multipart, [
  %{
    content_type: "application/json",
    content_id: "jsonData",
    headers: %{
      "content-type" => "application/json",
      "content-id" => "jsonData"
    },
    body: {:json, %{
      "lcsCorrelationId" => "corr-123",
      "n2InfoContainer" => %{
        "n2InformationClass" => "NRPPa",
        "nrppaInfo" => %{
          "nrppaPdu" => %{
            "ngapData" => %{"contentId" => "nrppa1"},
            "ngapIeType" => "NRPPA_PDU"
          }
        }
      }
    }}
  },
  %{
    content_type: "application/vnd.3gpp.ngap",
    content_id: "nrppa1",
    headers: %{
      "content-type" => "application/vnd.3gpp.ngap",
      "content-id" => "nrppa1"
    },
    body: {:binary, <<0, 4, 0, 13, 0, 0, 2, 0, 9, 0, 2, 0, 2, 0, 0, 0, 4, 64, 1, 0>>}
  }
]}
```

### Key Points

1. **JSON part decoded** - `application/json` → `{:json, map()}`
2. **NGAP part stays binary** - `application/vnd.3gpp.ngap` is unknown → `{:binary, binary()}`
3. **Cross-reference preserved** - JSON `contentId: "nrppa1"` matches part's `content_id: "nrppa1"`
4. **Headers available** - Original part headers preserved for inspection

### Complete Usage Example

```elixir
# Analyze 5G capture - content decoding is automatic
{:ok, exchanges, _} = PcapFileEx.HTTP2.analyze("5g_capture.pcap")

# Find N2 notify requests
n2_notifies = Enum.filter(exchanges, fn ex ->
  ex.request.path in ["/n2-notify", "/non-ue-n2-notify"]
end)

for ex <- n2_notifies do
  IO.puts("N2 Notify: #{ex.request.method} #{ex.request.path}")

  case ex.request.decoded_body do
    {:multipart, parts} ->
      # Get JSON metadata
      case Enum.find(parts, &(&1.content_type == "application/json")) do
        %{body: {:json, metadata}} ->
          correlation_id = metadata["lcsCorrelationId"]
          info_class = get_in(metadata, ["n2InfoContainer", "n2InformationClass"])
          IO.puts("  Correlation: #{correlation_id}, Class: #{info_class}")

          # Get referenced binary content
          content_id = get_in(metadata, ["n2InfoContainer", "nrppaInfo", "nrppaPdu", "ngapData", "contentId"])
          ngap_part = Enum.find(parts, &(&1.content_id == content_id))

          case ngap_part do
            %{body: {:binary, ngap_data}} ->
              IO.puts("  NGAP data: #{byte_size(ngap_data)} bytes")
              # Pass to external decoder: MyNgapDecoder.decode(ngap_data)
            _ ->
              IO.puts("  NGAP part not found")
          end

        _ ->
          IO.puts("  No JSON metadata")
      end

    _ ->
      IO.puts("  Not multipart")
  end

  IO.puts("  Response: #{ex.response.status}")
end
```

Output:
```
N2 Notify: POST /n2-notify
  Correlation: corr-123, Class: NRPPa
  NGAP data: 20 bytes
  Response: 204
```

---

## Module Architecture

```
PcapFileEx
├── HTTP2 (HTTP/2 stream reconstruction)
│   ├── Frame
│   ├── FrameBuffer
│   ├── Headers
│   ├── StreamState
│   ├── Connection
│   ├── Analyzer ─────────────┐
│   ├── Exchange              │ uses
│   └── IncompleteExchange    │
│                             ▼
└── HTTP (shared HTTP utilities)
    └── Content  ← Content decoding (this spec)
```

### Integration Flow

```
HTTP2.analyze(pcap, decode_content: true)
    │
    ▼
┌─────────────────────────────────────┐
│  HTTP2.Analyzer                     │
│  - Parse frames                     │
│  - Reconstruct streams              │
│  - Build Exchange structs           │
└─────────────────────────────────────┘
    │
    │ for each exchange:
    ▼
┌─────────────────────────────────────┐
│  HTTP.Content.decode/2              │
│  - Get Content-Type from headers    │
│  - Decode body (multipart/json/etc) │
│  - Set decoded_body field           │
└─────────────────────────────────────┘
    │
    ▼
  Exchange with both body and decoded_body
```

---

## Files

### New Files

| File | Description |
|------|-------------|
| `lib/pcap_file_ex/http/content.ex` | Generic content decoder |
| `test/pcap_file_ex/http/content_test.exs` | Unit tests |
| `test/property_test/content_property_test.exs` | Property tests |

### Modified Files

| File | Change |
|------|--------|
| `lib/pcap_file_ex/http2/exchange.ex` | Add `decoded_body` field to request/response types |
| `lib/pcap_file_ex/http2/analyzer.ex` | Call `Content.decode/2` when `decode_content: true` |
| `lib/pcap_file_ex/http2.ex` | Add `decode_content` option to `analyze/2` |

### Dependencies

- `jason` - JSON decoding (already a dependency)

---

## Testing Strategy

### Unit Tests

```elixir
# test/pcap_file_ex/http/content_test.exs

describe "decode/2" do
  test "decodes JSON content" do
    assert {:json, %{"key" => "value"}} =
      Content.decode("application/json", ~s({"key":"value"}))
  end

  test "decodes JSON with charset parameter" do
    assert {:json, %{}} =
      Content.decode("application/json; charset=utf-8", "{}")
  end

  test "decodes valid UTF-8 text content" do
    assert {:text, "hello"} =
      Content.decode("text/plain", "hello")
  end

  test "returns binary for invalid UTF-8 text" do
    invalid_utf8 = <<0xFF, 0xFE, 0x00, 0x01>>
    assert {:binary, ^invalid_utf8} =
      Content.decode("text/plain", invalid_utf8)
  end

  test "converts ISO-8859-1 to UTF-8" do
    # "café" in ISO-8859-1: 0x63 0x61 0x66 0xE9
    latin1_bytes = <<0x63, 0x61, 0x66, 0xE9>>
    assert {:text, "café"} =
      Content.decode("text/plain; charset=iso-8859-1", latin1_bytes)
  end

  test "returns binary for unknown charset" do
    body = "some data"
    assert {:binary, ^body} =
      Content.decode("text/plain; charset=unknown-charset", body)
  end

  test "returns binary for unknown types" do
    assert {:binary, <<1, 2, 3>>} =
      Content.decode("application/octet-stream", <<1, 2, 3>>)
  end

  test "returns binary for nil content-type" do
    assert {:binary, "data"} = Content.decode(nil, "data")
  end

  test "returns binary for invalid JSON" do
    assert {:binary, "not json"} =
      Content.decode("application/json", "not json")
  end

  test "decodes multipart with multiple parts" do
    body = """
    --boundary\r
    Content-Type: application/json\r
    Content-Id: part1\r
    \r
    {"a":1}\r
    --boundary\r
    Content-Type: text/plain\r
    \r
    hello\r
    --boundary--\r
    """

    assert {:multipart, [part1, part2]} =
      Content.decode("multipart/related; boundary=boundary", body)

    assert part1.content_type == "application/json"
    assert part1.content_id == "part1"
    assert {:json, %{"a" => 1}} = part1.body

    assert part2.content_type == "text/plain"
    assert {:text, "hello"} = part2.body
  end

  test "recursively decodes nested multipart" do
    # Multipart containing another multipart part
  end
end

describe "extract_boundary/1" do
  test "extracts unquoted boundary" do
    assert {:ok, "abc123"} =
      Content.extract_boundary("multipart/related; boundary=abc123")
  end

  test "extracts quoted boundary" do
    assert {:ok, "abc 123"} =
      Content.extract_boundary(~s(multipart/related; boundary="abc 123"))
  end

  test "returns error when no boundary" do
    assert {:error, :no_boundary} =
      Content.extract_boundary("application/json")
  end
end
```

### Property Tests

```elixir
# test/property_test/content_property_test.exs

property "decode never raises" do
  check all content_type <- content_type_generator(),
            body <- binary() do
    # Should always return a valid decoded tuple, never raise
    result = Content.decode(content_type, body)
    assert match?({:json, _} | {:text, _} | {:multipart, _} | {:binary, _}, result)
  end
end

property "valid JSON always decodes to {:json, _}" do
  check all data <- json_data_generator() do
    json = Jason.encode!(data)
    assert {:json, ^data} = Content.decode("application/json", json)
  end
end

property "valid UTF-8 text content-types return {:text, _}" do
  check all subtype <- string(:alphanumeric, min_length: 1),
            body <- string(:printable) do
    content_type = "text/#{subtype}"
    # Only valid UTF-8 strings return {:text, _}
    assert {:text, ^body} = Content.decode(content_type, body)
  end
end

property "invalid UTF-8 text returns {:binary, _}" do
  check all subtype <- string(:alphanumeric, min_length: 1),
            body <- binary() do
    content_type = "text/#{subtype}"
    result = Content.decode(content_type, body)

    if String.valid?(body) do
      assert {:text, ^body} = result
    else
      assert {:binary, ^body} = result
    end
  end
end
```

---

## Edge Cases

### Malformed Input Handling

| Input | Behavior |
|-------|----------|
| `nil` content-type | Return `{:binary, body}` |
| Invalid JSON | Return `{:binary, body}` |
| Missing boundary | Return `{:binary, body}` |
| Malformed multipart | Return `{:binary, body}` |
| Empty body | Return appropriate empty type |
| Binary with null bytes | Handle correctly (preserved in binary) |
| Invalid UTF-8 in text/* | Return `{:binary, body}` |
| Unknown charset | Return `{:binary, body}` |

### Content-Type Variations

All of these should decode as JSON:
- `application/json`
- `application/json; charset=utf-8`
- `APPLICATION/JSON`
- `application/json ; charset=utf-8`

### Charset Handling

| Charset | Behavior |
|---------|----------|
| `utf-8` (default) | Validate with `String.valid?/1`, fallback to binary |
| `iso-8859-1`, `latin1` | Convert to UTF-8 via `:unicode.characters_to_binary/2` |
| Unknown charset | Return `{:binary, body}` |

### Boundary Edge Cases

- Boundary with special characters: `boundary="--=_Part_123"`
- Boundary with spaces (quoted): `boundary="abc 123"`
- Very long boundary (UUID-based)
- Boundary appearing in binary content: Handled correctly (uses `\r\n--boundary` pattern)

### Binary Part Preservation

Critical for 5G/telecom use cases:
- NGAP blobs must be preserved exactly (no trimming)
- ASN.1 PER encoded data may contain any byte sequence
- Part body is never modified after extraction

---

## References

- **RFC 2046**: MIME Part Two: Media Types (multipart)
- **RFC 2387**: The MIME Multipart/Related Content-type
- **RFC 8259**: The JavaScript Object Notation (JSON) Data Interchange Format
- **RFC 7231**: HTTP/1.1 Semantics and Content (Content-Type)
