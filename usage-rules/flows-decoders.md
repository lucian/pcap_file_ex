# Custom Decoders for Flows

## Overview

The `decoders` option in `PcapFileEx.Flows.analyze/2` allows you to decode domain-specific binary payloads. Custom decoders transform raw binary data into structured terms based on matching criteria.

**When to use custom decoders:**
- UDP datagrams with application-specific protocols (telemetry, gaming, IoT)
- HTTP bodies with binary content-types (protobuf, custom formats)
- Multipart parts with 5G SBI protocols (NGAP, NAS, etc.)

**Key principle:** Custom decoders only apply to binary content. Built-in JSON/text decoding runs first.

## Quick Start

```elixir
# Decode UDP telemetry on port 5005
decoder = %{
  protocol: :udp,
  match: %{port: 5005},
  decoder: &MyTelemetry.decode/1
}

{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng",
  decoders: [decoder]
)

# Access decoded payload (BREAKING: payload type changed in v0.6.0)
datagram = hd(hd(result.udp).datagrams)
case datagram.payload do
  {:custom, data} -> IO.inspect(data)
  {:decode_error, reason} -> IO.puts("Error: #{inspect(reason)}")
  raw when is_binary(raw) -> IO.puts("No decoder matched")
end
```

## Decoder Specification

A decoder spec is a map with three required keys:

```elixir
%{
  protocol: :udp | :http1 | :http2,  # Filter by protocol
  match: matcher(),                   # Criteria to match
  decoder: decoder_fn() | module()    # Decoding function or module
}
```

### Protocol

Determines which traffic the decoder applies to:
- `:udp` - UDP datagrams
- `:http1` - HTTP/1.x bodies and multipart parts
- `:http2` - HTTP/2 bodies and multipart parts

### Match Criteria

Match can be a map or function:

```elixir
# Map matcher - all specified criteria must match
%{
  port: 5005,                              # UDP destination port
  scope: :body | :multipart_part,          # HTTP body vs multipart part
  content_type: "application/x-protobuf",  # Content-Type header
  content_id: "part1",                     # Multipart Content-ID
  method: "POST",                          # HTTP method
  path: "/api/v1"                          # Request path
}

# Function matcher - full control
fn ctx ->
  ctx.port in 5000..6000 and ctx.direction == :datagram
end
```

**Supported match values:**
| Field | Type | Example |
|-------|------|---------|
| `port` | integer, Range, list | `5005`, `5000..5100`, `[5005, 5006]` |
| `content_type` | string, Regex, list | `"application/json"`, `~r/vnd\.3gpp\..*/` |
| `content_id` | string, Regex | `"ngap-part"`, `~r/part-\d+/` |
| `method` | string, list | `"POST"`, `["POST", "PUT"]` |
| `path` | string, Regex | `"/api/users"`, `~r/\/api\/v\d+\/.*/ ` |
| `scope` | atom | `:body`, `:multipart_part` |

## Decoder Types

### Arity-1 (Simple)

Receives only payload. Any return value is wrapped as `{:custom, term}`.

```elixir
decoder = %{
  protocol: :udp,
  match: %{port: 5005},
  decoder: fn payload ->
    # Return any term - gets wrapped as {:custom, term}
    MyParser.parse(payload)
  end
}

# Or use a module function reference
decoder = %{
  protocol: :udp,
  match: %{port: 5005},
  decoder: &MyParser.parse/1
}
```

**Return values:**
- Any term → stored as `{:custom, term}`
- `{:error, reason}` → stored as `{:decode_error, reason}`

### Arity-2 (Context-Aware)

Receives context and payload. Must return `{:ok, term}`, `{:error, reason}`, or `:skip`.

```elixir
decoder = %{
  protocol: :http1,
  match: %{scope: :multipart_part, content_type: ~r/vnd\.3gpp\..*/},
  decoder: fn %{content_id: id, path: path}, payload ->
    case MyDecoder.parse(payload) do
      {:ok, data} -> {:ok, %{id: id, path: path, data: data}}
      {:error, reason} -> {:error, {:parse_failed, reason}}
    end
  end
}
```

**Return values:**
- `{:ok, term}` → stored as `{:custom, term}`
- `{:error, reason}` → stored as `{:decode_error, reason}` (terminal)
- `:skip` → try next decoder, or fall back to binary

### Module-Based

Implement the `PcapFileEx.Flows.Decoder` behaviour:

```elixir
defmodule MyNGAPDecoder do
  @behaviour PcapFileEx.Flows.Decoder

  @impl true
  def decode(%{content_id: id}, payload) do
    case NGAP.parse(payload) do
      {:ok, message} -> {:ok, {:ngap, id, message}}
      {:error, reason} -> {:error, {:ngap_error, reason}}
    end
  end

  # Optional: define fields for display filters
  @impl true
  def fields do
    [
      %{id: "ngap.procedure_code", type: :integer,
        extractor: fn {:ngap, _, msg} -> msg.procedure_code end}
    ]
  end
end

decoder = %{
  protocol: :http1,
  match: %{scope: :multipart_part, content_type: "application/vnd.3gpp.ngap"},
  decoder: MyNGAPDecoder
}
```

## Context Fields

The context passed to arity-2 decoders varies by protocol:

### UDP Context

```elixir
%{
  protocol: :udp,
  direction: :datagram,
  port: 5005,                    # Destination port
  from: %Endpoint{...},          # Source endpoint
  to: %Endpoint{...}             # Destination endpoint
}
```

### HTTP Body Context

```elixir
%{
  protocol: :http1 | :http2,
  direction: :request | :response,
  scope: :body,
  content_type: "application/x-protobuf",
  headers: %{"content-length" => "1024", ...},
  method: "POST",
  path: "/api/users",
  status: 200                    # Only for responses
}
```

### Multipart Part Context

```elixir
%{
  protocol: :http1 | :http2,
  direction: :request | :response,
  scope: :multipart_part,
  content_type: "application/vnd.3gpp.ngap",
  content_id: "ngap-part",       # May be nil
  headers: %{...},               # Part's own headers
  method: "POST",                # Parent request method
  path: "/sbi/v1"                # Parent request path
}
```

**Note:** For HTTP/2, `headers` excludes pseudo-headers (`:method`, `:path`, `:status`). Use the dedicated context fields instead.

## Decoding Pipeline

### HTTP Bodies

1. Built-in JSON decoder (`application/json` → `{:json, term}`)
2. Built-in text decoder (`text/*` → `{:text, string}`)
3. Built-in multipart parser (`multipart/*` → `{:multipart, parts}`)
4. **Custom decoders** (binary content only)
5. Binary fallback (`{:binary, payload}`)

### Multipart Parts

Each part follows the same pipeline:
1. Built-in JSON/text decoders
2. **Custom decoders** (binary parts only)
3. Binary fallback

### UDP Datagrams

1. **Custom decoders** (first match)
2. No fallback (payload remains raw binary)

## Result Wrapping

Custom decoder results are wrapped to distinguish from built-in decoding:

| Decoder Return | Stored Value |
|---------------|--------------|
| `{:ok, term}` (arity-2) | `{:custom, term}` |
| `term` (arity-1) | `{:custom, term}` |
| `{:error, reason}` | `{:decode_error, reason}` |
| Exception raised | `{:decode_error, %{exception: e, stacktrace: st}}` |
| `:skip` | Falls through to next decoder |

Pattern match on results:

```elixir
case exchange.response.decoded_body do
  {:custom, data} -> handle_custom(data)
  {:decode_error, reason} -> handle_error(reason)
  {:json, json} -> handle_json(json)
  {:text, text} -> handle_text(text)
  {:multipart, parts} -> handle_multipart(parts)
  {:binary, raw} -> handle_binary(raw)
end
```

## Examples

### UDP Telemetry Decoder

```elixir
# Decode custom telemetry protocol
telemetry_decoder = %{
  protocol: :udp,
  match: %{port: 5005..5010},  # Port range
  decoder: fn payload ->
    <<sensor_id::16, temperature::float-32, humidity::float-32>> = payload
    %{sensor_id: sensor_id, temp: temperature, humidity: humidity}
  end
}
```

### HTTP Protobuf Decoder

```elixir
# Decode protobuf bodies
protobuf_decoder = %{
  protocol: :http1,
  match: %{scope: :body, content_type: "application/x-protobuf"},
  decoder: fn %{path: path}, payload ->
    message_type = infer_message_type(path)
    {:ok, Protobuf.decode(message_type, payload)}
  end
}
```

### 5G SBI Multipart Decoder

```elixir
# Decode 3GPP binary parts in SBI multipart
sbi_decoder = %{
  protocol: :http2,
  match: %{scope: :multipart_part, content_type: ~r/application\/vnd\.3gpp\..*/},
  decoder: fn %{content_type: ct, content_id: id}, payload ->
    type = String.replace(ct, "application/vnd.3gpp.", "")
    {:ok, %{type: type, id: id, size: byte_size(payload), data: payload}}
  end
}
```

### Conditional Decoder with :skip

```elixir
# Try decoding, skip if not our format
conditional_decoder = %{
  protocol: :udp,
  match: %{port: 5005},
  decoder: fn _ctx, payload ->
    case payload do
      <<0xCA, 0xFE, rest::binary>> ->
        {:ok, {:magic_protocol, rest}}
      _ ->
        :skip  # Not our format, try next decoder
    end
  end
}
```

## Error Handling

Decoder errors are stored, not raised:

```elixir
# Check for decode errors in UDP
Enum.each(result.udp, fn flow ->
  Enum.each(flow.datagrams, fn dg ->
    case dg.payload do
      {:decode_error, %{exception: e}} ->
        Logger.error("Decoder crashed: #{inspect(e)}")
      {:decode_error, reason} ->
        Logger.warning("Decode failed: #{inspect(reason)}")
      {:custom, _data} ->
        :ok  # Successfully decoded
      raw when is_binary(raw) ->
        :ok  # No decoder matched
    end
  end)
end)

# Check for decode errors in HTTP multipart
case exchange.response.decoded_body do
  {:multipart, parts} ->
    Enum.each(parts, fn part ->
      case part.body do
        {:decode_error, reason} ->
          Logger.warning("Part #{part.content_id} failed: #{inspect(reason)}")
        _ ->
          :ok
      end
    end)
  _ ->
    :ok
end
```

## Best Practices

1. **Use arity-1 for simple decoders** - No context needed, cleaner code

2. **Return `:skip` for conditional decoders** - Let other decoders try

3. **Return `{:error, reason}` for failures** - Don't crash, store the error

4. **Match specifically** - Use `scope: :multipart_part` to avoid matching body

5. **Use Regex for content-type families** - `~r/vnd\.3gpp\..*/` matches all 3GPP types

6. **Register for both HTTP/1 and HTTP/2** - If your protocol appears in both:
   ```elixir
   http1_decoder = %{protocol: :http1, match: matcher, decoder: decoder}
   http2_decoder = %{protocol: :http2, match: matcher, decoder: decoder}
   decoders: [http1_decoder, http2_decoder]
   ```

7. **Implement `fields/0` for display filters** - Makes decoded data filterable

8. **Normalize headers are lowercase** - Match with `"content-type"`, not `"Content-Type"`

## Decoder Priority

Decoders are evaluated in the order they appear in the list. First match wins:

```elixir
decoders: [
  specific_decoder,   # Checked first
  fallback_decoder    # Only if specific doesn't match
]
```

For `:skip` returns, evaluation continues to the next matching decoder.

## Binary Preservation

When using custom decoders, you may need both the decoded data (for analysis) and the original binary (for playback/replay). The `keep_binary` option preserves the original binary alongside the decoded content.

### Usage

```elixir
{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng",
  decoders: [my_decoder],
  keep_binary: true  # Preserve original binary
)
```

### UDP Datagrams

When a custom decoder transforms a UDP datagram:

```elixir
datagram = hd(hd(result.udp).datagrams)

case datagram.payload do
  {:custom, decoded_data} ->
    # Decoded content for analysis
    IO.inspect(decoded_data)

    # Original binary for playback (only when keep_binary: true)
    if datagram.payload_binary do
      replay(datagram.payload_binary)
    end

  {:decode_error, reason} ->
    # Decoder failed, but binary preserved for debugging
    Logger.error("Decode failed: #{inspect(reason)}")
    if datagram.payload_binary do
      debug_binary(datagram.payload_binary)
    end

  raw when is_binary(raw) ->
    # No decoder matched - raw binary in payload, no payload_binary
    replay(raw)
end
```

**Key invariants:**
- `payload_binary` is ONLY set when a custom decoder was invoked AND `keep_binary: true`
- `:skip` returns don't set `payload_binary` (equivalent to "no decoder matched")
- When no decoder matches, `payload` is raw binary, `payload_binary` is nil

### Multipart Parts

For HTTP multipart responses with custom decoders:

```elixir
case exchange.response.decoded_body do
  {:multipart, parts} ->
    Enum.each(parts, fn part ->
      case part.body do
        {:custom, decoded_data} ->
          # Decoded content
          IO.inspect(decoded_data)
          # Original binary (only when keep_binary: true)
          if part.body_binary, do: replay(part.body_binary)

        {:decode_error, reason} ->
          Logger.error("Part decode failed: #{inspect(reason)}")
          # Binary preserved for debugging
          if part.body_binary, do: debug(part.body_binary)

        other ->
          # Built-in decoded ({:json, _}, {:text, _}, {:binary, _})
          # No body_binary field
          IO.inspect(other)
      end
    end)
  _ ->
    :ok
end
```

### Playback Helper

```elixir
@doc "Get raw binary for playback. Returns nil if not preserved."
def get_raw_payload(datagram) do
  case datagram.payload do
    raw when is_binary(raw) -> raw
    _decoded -> datagram.payload_binary
  end
end

# Usage
case get_raw_payload(datagram) do
  nil -> raise "Binary not preserved. Use keep_binary: true"
  raw -> send_to_server(raw)
end
```

### Memory Warning

`keep_binary: true` doubles memory for decoded content:

- UDP datagram with 1KB payload → ~2KB memory
- Multipart part with 10KB binary → ~20KB memory

**Recommendations:**
- Only use `keep_binary: true` when playback/replay is needed
- Default `keep_binary: false` avoids this overhead
- For large captures, consider streaming with selective processing
