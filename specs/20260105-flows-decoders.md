# Flows Decoders Specification

**Date**: 2026-01-05
**Status**: Draft
**Author**: Claude Code

## Overview

Extend `PcapFileEx.Flows.analyze/2` to accept custom decoders that decode protocol-specific payloads. Decoders are matched based on configurable criteria (port, content-type, etc.) and transform raw binary payloads into structured data.

## Motivation

The current Flows API provides built-in decoding for:
- JSON (`application/json`)
- Text (`text/*`)
- Multipart (recursive part parsing)

However, users working with domain-specific protocols need to:
1. Decode UDP datagrams based on destination port (e.g., custom telemetry on port 5005)
2. Decode HTTP top-level bodies based on content-type (e.g., `application/x-protobuf`)
3. Decode HTTP multipart parts based on content-type (e.g., `application/vnd.3gpp.ngap` for 5G SBI)
4. Apply custom decoders without modifying library internals

## Goals

- Allow per-call decoder registration without global state
- Match UDP payloads by protocol/port
- Match HTTP bodies and multipart parts by Content-Type
- Apply decoders during analysis so results include decoded content
- Maintain safe defaults when no decoders are provided

## Non-Goals

- Replacing the existing packet-level `DecoderRegistry`
- Auto-discovery of decoders from external registries
- Guaranteeing decoders are pure or side-effect free

## API Design

### Entry Point

```elixir
@spec PcapFileEx.Flows.analyze(Path.t(), keyword()) ::
  {:ok, AnalysisResult.t()} | {:error, term()}

# Existing options:
#   hosts_map: %{ip_string => hostname_string}
#   decode_content: boolean (default: true)
#
# New options:
#   decoders: [decoder_spec()]
#   keep_binary: boolean (default: false) - Preserve original binary when
#     custom decoders transform content. Stored in `payload_binary` (UDP)
#     or `body_binary` (multipart parts). WARNING: Doubles memory for decoded content.
```

### Decoder Specification Types

```elixir
defmodule PcapFileEx.Flows.Decoder do
  @moduledoc """
  Behaviour and types for custom flow decoders.

  Decoders transform raw binary payloads into structured data based on
  matching criteria (port, content-type, etc.).

  IMPORTANT: Custom decoders only apply to binary content. Built-in JSON/text
  decoding and multipart parsing run first. Custom decoders are invoked only
  when the decoded value would be `{:binary, payload}`.
  """

  @type match_context :: %{
    # Protocol identifier
    protocol: :udp | :http1 | :http2,

    # Direction
    direction: :request | :response | :datagram,

    # UDP context
    optional(:port) => non_neg_integer(),           # Destination port
    optional(:from) => Endpoint.t(),                # Source endpoint
    optional(:to) => Endpoint.t(),                  # Destination endpoint

    # HTTP body/part context
    optional(:scope) => :body | :multipart_part,
    optional(:content_type) => String.t(),          # Content-Type header (normalized, lowercase)
    optional(:content_id) => String.t() | nil,      # Content-ID (multipart only)
    # Headers are normalized to a string map with lowercase keys.
    # HTTP/2 pseudo-headers (e.g., ":path", ":method") are converted to regular keys.
    # Both HTTP/1 and HTTP/2 provide consistent %{"content-type" => "...", ...} format.
    optional(:headers) => %{String.t() => String.t()},

    # HTTP parent request context
    optional(:method) => String.t(),                # HTTP method
    optional(:path) => String.t(),                  # Request path
    optional(:status) => non_neg_integer()          # Response status (if response)
  }

  @type decode_result ::
    {:ok, term()}           # Wrapped as {:custom, term()} in result
    | {:error, term()}      # Stored as {:decode_error, reason}
    | :skip                 # This decoder declines; continue to next matching decoder

  # Matcher: either a function or a map of criteria.
  # IMPORTANT: Protocol filtering is done via decoder_spec.protocol, NOT in the matcher.
  # If you add :protocol to a match map, it will be ignored. Only decoder_spec.protocol
  # is used to filter decoders by protocol.
  @type matcher ::
    (match_context() -> boolean())
    | %{
        optional(:scope) => :body | :multipart_part,
        optional(:port) => non_neg_integer() | Range.t() | [non_neg_integer()],
        optional(:content_type) => String.t() | Regex.t() | [String.t()],
        optional(:content_id) => String.t() | Regex.t(),
        optional(:method) => String.t() | [String.t()],
        optional(:path) => String.t() | Regex.t()
      }

  # Arity-1: Receives only payload.
  #   Return type is `term() | {:error, term()}`:
  #   - `{:error, reason}` is recognized specially → stored as `{:decode_error, reason}` (terminal)
  #   - Any other term (including tuples) → wrapped as `{:custom, term}`
  #   Note: Arity-1 cannot return `:skip`; use arity-2 if you need to decline.
  #
  # Arity-2: Receives context and payload. Must return decode_result().
  @type decoder_fn ::
    (binary() -> {:error, term()} | term())           # Arity-1: {:error, _} or any term
    | (match_context(), binary() -> decode_result())  # Arity-2: must return decode_result()

  @type decoder_spec :: %{
    required(:protocol) => :udp | :http1 | :http2,  # Filter by protocol
    required(:match) => matcher(),
    required(:decoder) => decoder_fn() | module()
  }

  # Module invocation rule:
  # When `decoder` is a module, invoke `module.decode(ctx, payload)` (arity-2).
  # Modules MUST implement the Decoder behaviour with decode/2.
  # (Arity-1 module functions are not supported; use &Module.decode/1 explicitly.)

  # Field descriptor for display filter support (optional callback)
  @type field_descriptor :: %{
    id: String.t(),                                   # e.g., "ngap.procedure_code"
    type: :string | :integer | :boolean | :binary,
    extractor: (term() -> term())                     # Extracts value from decoded data
  }

  @doc """
  Decode a binary payload given the match context.

  Return `{:ok, decoded}` for successful decoding,
  `{:error, reason}` for failures (stored as {:decode_error, reason}),
  or `:skip` to skip this decoder (try next, or fall back to binary).
  """
  @callback decode(match_context(), binary()) :: decode_result()

  @doc """
  Optional: Return field descriptors for display filter support.
  """
  @callback fields() :: [field_descriptor()]

  @optional_callbacks [fields: 0]
end
```

## Examples

### UDP Decoder (port-based)

```elixir
# Simple arity-1 decoder
udp_telemetry_decoder = %{
  protocol: :udp,
  match: %{port: 5005},
  decoder: &MyTelemetry.decode/1  # Result wrapped as {:custom, decoded}
}

# Context-aware arity-2 decoder
udp_context_decoder = %{
  protocol: :udp,
  match: %{port: 5005},
  decoder: fn %{to: endpoint}, payload ->
    {:ok, %{endpoint: endpoint, data: MyTelemetry.decode(payload)}}
  end
}
```

### HTTP Top-Level Body Decoder

```elixir
# Decode protobuf bodies based on path
protobuf_decoder = %{
  protocol: :http1,
  match: %{scope: :body, content_type: "application/x-protobuf"},
  decoder: fn %{path: path}, payload ->
    message_type = infer_message_type(path)
    {:ok, Protobuf.decode(message_type, payload)}
  end
}
```

### HTTP Multipart Part Decoder

```elixir
# Decode 3GPP NGAP binary in multipart
ngap_decoder = %{
  protocol: :http1,
  match: %{scope: :multipart_part, content_type: "application/vnd.3gpp.ngap"},
  decoder: &MyNgapDecoder.decode/1
}

# Regex match for all 3GPP content types
sbi_decoder = %{
  protocol: :http2,
  match: %{scope: :multipart_part, content_type: ~r/application\/vnd\.3gpp\..*/},
  decoder: fn %{content_type: ct, content_id: id}, payload ->
    {:ok, %{type: ct, id: id, data: payload}}
  end
}
```

### Module-Based Decoder

```elixir
defmodule MyNGAPDecoder do
  @behaviour PcapFileEx.Flows.Decoder

  @impl true
  def decode(%{content_id: id}, payload) do
    {:ok, {:ngap, id, NGAP.parse(payload)}}
  end

  @impl true
  def fields do
    [
      %{id: "ngap.procedure_code", type: :integer,
        extractor: fn {:ngap, _, data} -> data.procedure_code end}
    ]
  end
end

ngap_module_decoder = %{
  protocol: :http1,
  match: %{scope: :multipart_part, content_type: "application/vnd.3gpp.ngap"},
  decoder: MyNGAPDecoder
}
```

### Usage in analyze/2

```elixir
{:ok, result} = PcapFileEx.Flows.analyze("capture.pcapng",
  hosts_map: hosts_map,
  decode_content: true,
  decoders: [
    # UDP decoder
    %{protocol: :udp, match: %{port: 5005}, decoder: &MyTelemetry.decode/1},

    # HTTP/1 multipart decoder
    %{protocol: :http1, match: %{scope: :multipart_part, content_type: "application/vnd.3gpp.ngap"}, decoder: &MyNgapDecoder.decode/1},

    # HTTP/2 multipart decoder (same logic, different protocol)
    %{protocol: :http2, match: %{scope: :multipart_part, content_type: "application/vnd.3gpp.ngap"}, decoder: &MyNgapDecoder.decode/1}
  ]
)
```

## Decoder Templates

### Simple Decoder (arity-1)

```elixir
defmodule MyNgapDecoder do
  @moduledoc """
  Decoder for 3GPP NGAP binary in multipart.

  Arity-1 decoders can return:
  - Any term (wrapped as {:custom, term})
  - {:error, reason} (stored as {:decode_error, reason})
  """

  @doc "Decode NGAP payload"
  @spec decode(binary()) :: term() | {:error, term()}
  def decode(payload) do
    case MyNgapLib.decode(payload) do
      {:ok, message} -> message  # Becomes {:custom, message}
      {:error, reason} -> {:error, {:ngap_decode_failed, reason}}  # Becomes {:decode_error, ...}
    end
  end
end

# Usage (for binary multipart parts only - JSON/text parts are skipped):
%{
  protocol: :http1,
  match: %{scope: :multipart_part, content_type: "application/vnd.3gpp.ngap"},
  decoder: &MyNgapDecoder.decode/1
}
```

### Context-Aware Decoder (arity-2)

```elixir
defmodule MyCustomDecoder do
  @moduledoc """
  Custom decoder for [protocol description].

  ## Usage

      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: MyCustomDecoder
      }

      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcap",
        decoders: [decoder]
      )
  """

  @behaviour PcapFileEx.Flows.Decoder

  @doc """
  Decode the binary payload with context.

  ## Context Fields

  For UDP (direction: :datagram):
    - `:protocol` - :udp
    - `:direction` - :datagram
    - `:port` - Destination port
    - `:from` - Source endpoint
    - `:to` - Destination endpoint

  For HTTP body (direction: :request | :response):
    - `:protocol` - :http1 | :http2
    - `:direction` - :request | :response
    - `:scope` - :body
    - `:content_type` - Content-Type header (normalized, lowercase)
    - `:headers` - All headers as %{"lowercase-key" => "value"} (both HTTP/1 and HTTP/2)
    - `:method` - HTTP method
    - `:path` - Request path
    - `:status` - Response status (if direction: :response)

  For HTTP multipart part:
    - Same as HTTP body, plus:
    - `:scope` - :multipart_part
    - `:content_id` - Part's Content-ID header (may be nil)

  ## Return Values

    - `{:ok, decoded}` - Successfully decoded (wrapped as {:custom, decoded})
    - `{:error, reason}` - Decoding failed (stored as {:decode_error, reason})
    - `:skip` - Skip this decoder, use default decoding
  """
  @impl true
  def decode(%{direction: direction} = ctx, payload) do
    case parse_payload(payload) do
      {:ok, data} ->
        {:ok, %{direction: direction, data: data}}

      {:error, reason} ->
        {:error, {:decode_failed, reason}}

      :not_my_protocol ->
        :skip  # Fall back to default decoding
    end
  end

  @doc """
  Optional: Define extractable fields for display filters.
  """
  @impl true
  def fields do
    [
      %{
        id: "my_proto.message_type",
        type: :string,
        extractor: fn %{data: data} -> data.message_type end
      }
    ]
  end

  defp parse_payload(<<0xCA, 0xFE, rest::binary>>) do
    {:ok, %{message_type: "example", data: rest}}
  end

  defp parse_payload(_), do: :not_my_protocol
end
```

## Behavior Details

### Matcher Evaluation

Candidate decoders are evaluated in order. A decoder "matches" when its `protocol` matches
the current context AND its `match` criteria are satisfied. Matching decoders are invoked
one by one; if a decoder returns `:skip`, evaluation continues to the next candidate.

**Map-based matchers** support (note: `protocol` is NOT in matcher, it's in decoder_spec):

| Field | Type | Matches |
|-------|------|---------|
| `scope` | atom | `:body`, `:multipart_part` |
| `port` | integer, Range, list | UDP destination port |
| `content_type` | string, Regex, list | Exact match, pattern, or any of list |
| `content_id` | string, Regex | Multipart Content-ID header |
| `method` | string, list | HTTP method |
| `path` | string, Regex | Request path |

**Header key normalization**: All header keys in `match_context.headers` are lowercase.
When using function matchers that access headers directly, use lowercase keys:
```elixir
# Correct:
match: fn ctx -> ctx.headers["x-custom-header"] == "value" end

# Incorrect (will not match):
match: fn ctx -> ctx.headers["X-Custom-Header"] == "value" end
```

**Function matchers** receive full context and return boolean.

### Decoder Evaluation

When a candidate decoder matches (protocol + match criteria satisfied), it is invoked:
1. Context is populated with all available metadata
2. Decoder is invoked:
   - **Arity-1**: `decoder.(payload)` is called
     - If result is `{:error, reason}` → stored as `{:decode_error, reason}` (terminal)
     - Otherwise → wrapped as `{:custom, result}`
   - **Arity-2**: `decoder.(ctx, payload)` is called, returns `decode_result()`
     - `{:ok, term}` → stored as `{:custom, term}`
     - `{:error, reason}` → stored as `{:decode_error, reason}` (terminal)
     - `:skip` → continue to next matching decoder
3. Result is stored in `decoded_body` (HTTP) or `payload` (UDP)

**Note**: `{:error, reason}` is terminal—the system does NOT continue to other decoders.
Use `:skip` (arity-2 only) if you want to decline and let other decoders try.

### Error Handling (Unified)

All decoder errors are stored consistently as `{:decode_error, reason}`:

| Scenario | Stored Value |
|----------|--------------|
| Arity-1 returns `{:error, reason}` | `{:decode_error, reason}` |
| Arity-2 returns `{:error, reason}` | `{:decode_error, reason}` |
| Decoder raises exception | `{:decode_error, %{exception: exception, stacktrace: stacktrace}}` |
| Matcher raises exception | Treated as no match, next decoder tried |

### Decoder Scope (Binary Only)

Custom decoders apply ONLY to binary content that would otherwise be `{:binary, payload}`:
1. **Top-level HTTP bodies** - Bodies with binary content-types (e.g., `application/x-protobuf`, `application/vnd.3gpp.ngap`)
2. **Multipart parts** - Binary parts within `multipart/*` bodies
3. **UDP datagrams** - Raw UDP payloads

Custom decoders are NOT invoked for JSON, text, or already-parsed multipart containers.

### Decoding Pipeline (Priority Order)

**HTTP Bodies:**
1. Built-in JSON decoder (`application/json` → `{:json, term}`)
   - If JSON parsing fails, result is `{:binary, payload}` (eligible for custom decoders)
2. Built-in text decoder (`text/*` → `{:text, string}`)
3. Built-in multipart parser (`multipart/*` → `{:multipart, parts}`)
4. **Custom decoders** (evaluated in order; if decoder returns `:skip`, try next matching decoder)
   - Applies when steps 1-3 yield `{:binary, payload}` (including JSON parse failures)
5. Binary fallback (`{:binary, payload}`) - only if no custom decoder matches or all return `:skip`

**Multipart Parts:**

Custom decoders run ONLY on parts where built-in decoding yields `{:binary, _}`:
1. Built-in JSON decoder (per-part `application/json` → `{:json, term}`)
   - If JSON parsing fails, result is `{:binary, payload}` (eligible for custom decoders)
2. Built-in text decoder (per-part `text/*` → `{:text, string}`)
3. If per-part yields `{:binary, payload}`:
   - **Custom decoders** evaluated in order
   - `:skip` → continue to next matching decoder
   - `{:error, reason}` → terminal, stored as `{:decode_error, reason}`, no further decoders tried
   - `{:ok, term}` or non-error term → stored as `{:custom, term}`, done
   - If no decoder matches or all return `:skip` → `{:binary, payload}` fallback
4. JSON/text parts are NOT re-processed by custom decoders

**UDP Datagrams:**
1. **Custom decoders** evaluated in order
   - `:skip` → continue to next matching decoder
   - `{:error, reason}` → terminal, stored as `{:decode_error, reason}`, no further decoders tried
   - `{:ok, term}` or non-error term → stored as `{:custom, term}`, done
2. If no decoder matches or all return `:skip`: `payload` remains raw binary
   (Unlike HTTP which uses `{:binary, payload}`, UDP payload is already binary,
   so no wrapper is needed. The `payload_binary` field remains nil.)

### :skip Behavior

When a decoder returns `:skip`, it means "this decoder declines to handle this content."
The system continues evaluating remaining matching decoders in order:

```
decoder_1 matches, returns :skip → try decoder_2
decoder_2 matches, returns :skip → try decoder_3
decoder_3 matches, returns {:ok, data} → use {:custom, data}
```

**Fallback when no decoder handles:**
- **HTTP bodies/parts**: `{:binary, payload}`
- **UDP datagrams**: `payload` remains raw binary (no `payload_binary`)

**Contrast with {:error, reason}:**
```
decoder_1 matches, returns {:error, reason} → STOP, store {:decode_error, reason}
# decoder_2 is NOT tried
```

Use `:skip` to decline gracefully; use `{:error, reason}` to signal a decode failure.

### Result Wrapping

Custom decoder results are wrapped to distinguish them from built-in decoding:

| Decoder Return | Stored Value |
|---------------|--------------|
| `{:ok, term}` (arity-2) | `{:custom, term}` |
| `term` (arity-1, not `{:error, _}`) | `{:custom, term}` |
| `{:error, reason}` (arity-1 or arity-2) | `{:decode_error, reason}` |
| Exception raised | `{:decode_error, %{exception: e, stacktrace: st}}` |
| `:skip` (arity-2 only) | Continue to next matching decoder (see :skip Behavior above) |

This allows pattern matching to identify custom-decoded content:

```elixir
case exchange.request.decoded_body do
  {:custom, ngap_data} -> handle_ngap(ngap_data)
  {:decode_error, reason} -> handle_error(reason)
  {:json, json} -> handle_json(json)
  {:multipart, parts} -> handle_multipart(parts)  # Parts may contain {:custom, _}
  {:text, text} -> handle_text(text)
  {:binary, raw} -> handle_binary(raw)
end
```

## Data Structure Changes

### UDP Datagram (BREAKING CHANGE)

The datagram structure has been **restructured** for consistency with HTTP multipart parts:

```elixir
defmodule PcapFileEx.Flows.UDP.Datagram do
  @type decoded :: {:custom, term()} | {:decode_error, term()}

  @type t :: %__MODULE__{
    flow_seq: non_neg_integer(),
    from: Endpoint.t(),
    to: Endpoint.t(),
    payload: decoded() | binary(),      # CHANGED: decoded or raw binary
    payload_binary: binary() | nil,     # NEW: original binary (when keep_binary: true)
    timestamp: Timestamp.t(),
    size: non_neg_integer(),
    relative_offset_ms: non_neg_integer()
  }
  # NOTE: decoded_payload field has been REMOVED
end
```

**Payload states:**
- **No decoders configured** → `payload` = raw binary, `payload_binary` = nil
- **Decoder returns `:skip`** → Same as no decoder (raw binary, no `payload_binary`)
- **Decoder returns `{:ok, _}`** → `payload` = `{:custom, decoded}`, `payload_binary` = raw (if `keep_binary: true`)
- **Decoder returns `{:error, _}`** → `payload` = `{:decode_error, reason}`, `payload_binary` = raw (if `keep_binary: true`)

**Migration:**
```elixir
# Before (OLD API - no longer works)
case datagram.decoded_payload do
  {:custom, data} -> handle(data)
  nil -> handle_raw(datagram.payload)
end

# After (NEW API)
case datagram.payload do
  {:custom, data} ->
    handle_decoded(data)
    # For playback: datagram.payload_binary (if keep_binary: true)

  {:decode_error, reason} ->
    handle_error(reason)
    # Recovery: datagram.payload_binary (if keep_binary: true)

  raw when is_binary(raw) ->
    handle_raw(raw)
    # Note: payload_binary is nil in this case
end
```

### HTTP Multipart Part

The existing multipart part structure now supports optional `body_binary`:

```elixir
@type part :: %{
  required(:content_type) => String.t(),
  required(:content_id) => String.t() | nil,
  required(:headers) => %{String.t() => String.t()},
  required(:body) => decoded(),  # Can be {:custom, term()} from custom decoder
  optional(:body_binary) => binary()  # NEW: original binary (when keep_binary: true)
}
```

**`body_binary` is only present when:**
1. `keep_binary: true` option was passed
2. A custom decoder was invoked (returned `{:ok, _}` or `{:error, _}`, NOT `:skip`)

## Module Structure

```
lib/pcap_file_ex/
  flows/
    decoder.ex              # NEW: Behaviour + types
    decoder_matcher.ex      # NEW: Matcher evaluation logic
  http/
    content.ex              # MODIFY: Hook for custom decoders
  flows/
    udp/
      collector.ex          # MODIFY: Apply custom decoders
```

## Testing Strategy

### Unit Tests
- Matcher evaluation with various match specs
- Decoder invocation and error handling
- Context population for each protocol

### Integration Tests
- End-to-end with real PCAP containing custom protocols
- Multiple decoders with priority ordering
- Error recovery and fallback behavior

### Property Tests
- Matcher consistency (same input = same result)
- Decoder never raises (all exceptions caught)
- Unknown content types return binary

## Backwards Compatibility

- Default `decoders: []` preserves current behavior
- Default `keep_binary: false` preserves current behavior (no memory overhead)
- Existing `decode_content: true/false` still works
- Built-in decoders remain unchanged
- **BREAKING**: UDP Datagram `decoded_payload` field removed, `payload` type changed
- HTTP multipart parts gain optional `body_binary` field (non-breaking)

## Future Extensions

- Decoder chaining (decoder output as input to next)
- Request/response correlation for HTTP decoders
- Per-flow decoder configuration
- Decoder plugins via Mix config
