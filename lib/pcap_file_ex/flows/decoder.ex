defmodule PcapFileEx.Flows.Decoder do
  @moduledoc """
  Behaviour and types for custom flow decoders.

  Decoders transform raw binary payloads into structured data based on
  matching criteria (port, content-type, etc.).

  ## Binary-Only Decoding

  **IMPORTANT**: Custom decoders only apply to binary content. Built-in JSON/text
  decoding and multipart parsing run first. Custom decoders are invoked only
  when the decoded value would be `{:binary, payload}`.

  If JSON parsing fails (invalid JSON), the result is `{:binary, payload}` and
  IS eligible for custom decoders.

  ## Decoder Types

  Decoders can be either:
  - **Arity-1 functions**: Receive only the payload, return any term or `{:error, reason}`
  - **Arity-2 functions**: Receive context and payload, return `decode_result()`
  - **Modules**: Implement this behaviour with `decode/2` callback

  ## Returning :skip vs error

  - `:skip` - Decoder declines to handle; continue to next matching decoder
  - `{:error, reason}` - Decoder tried and failed; terminal, no further decoders tried

  ## Example Usage

      # Simple arity-1 decoder
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: &MyTelemetry.decode/1
      }

      # Context-aware arity-2 decoder
      decoder = %{
        protocol: :http1,
        match: %{scope: :multipart_part, content_type: "application/vnd.3gpp.ngap"},
        decoder: fn %{content_id: id}, payload ->
          {:ok, {:ngap, id, NGAP.parse(payload)}}
        end
      }

      {:ok, result} = PcapFileEx.Flows.analyze("capture.pcap",
        decoders: [decoder]
      )
  """

  alias PcapFileEx.Endpoint

  @typedoc """
  Context passed to decoders with all available metadata.

  ## Common Fields

  - `:protocol` - Protocol identifier (`:udp`, `:http1`, `:http2`)
  - `:direction` - Direction (`:request`, `:response`, `:datagram`)

  ## UDP Fields (direction: :datagram)

  - `:port` - Destination port
  - `:from` - Source endpoint
  - `:to` - Destination endpoint

  ## HTTP Fields (direction: :request | :response)

  - `:scope` - `:body` or `:multipart_part`
  - `:content_type` - Content-Type header (normalized, lowercase)
  - `:headers` - Regular headers as `%{"lowercase-key" => "value"}` (excludes HTTP/2 pseudo-headers; use `:method`, `:path`, `:status` fields instead)
  - `:method` - HTTP method
  - `:path` - Request path
  - `:status` - Response status (if response)
  - `:content_id` - Part's Content-ID (multipart only)
  """
  @type match_context :: %{
          required(:protocol) => :udp | :http1 | :http2,
          required(:direction) => :request | :response | :datagram,
          optional(:port) => non_neg_integer(),
          optional(:from) => Endpoint.t(),
          optional(:to) => Endpoint.t(),
          optional(:scope) => :body | :multipart_part,
          optional(:content_type) => String.t(),
          optional(:content_id) => String.t() | nil,
          optional(:headers) => %{String.t() => String.t()},
          optional(:method) => String.t(),
          optional(:path) => String.t(),
          optional(:status) => non_neg_integer()
        }

  @typedoc """
  Result of decoding a payload.

  - `{:ok, term}` - Successfully decoded, wrapped as `{:custom, term}` in result
  - `{:error, term}` - Decoding failed (terminal), stored as `{:decode_error, reason}`
  - `:skip` - This decoder declines; continue to next matching decoder
  """
  @type decode_result ::
          {:ok, term()}
          | {:error, term()}
          | :skip

  @typedoc """
  Matcher for determining if a decoder applies.

  Can be either:
  - A function receiving `match_context()` and returning boolean
  - A map with optional criteria (all specified must match)

  Note: `protocol` is NOT in matcher; use `decoder_spec.protocol` instead.
  If you add `:protocol` to a match map, it will be ignored.
  """
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

  @typedoc """
  Decoder function.

  ## Arity-1

  Receives only payload. Returns:
  - `{:error, reason}` - Stored as `{:decode_error, reason}` (terminal)
  - Any other term - Wrapped as `{:custom, term}`

  Note: Arity-1 cannot return `:skip`; use arity-2 if you need to decline.

  ## Arity-2

  Receives context and payload. Must return `decode_result()`.
  """
  @type decoder_fn ::
          (binary() -> {:error, term()} | term())
          | (match_context(), binary() -> decode_result())

  @typedoc """
  Decoder specification for registration.

  - `:protocol` - Required. Filter by protocol (`:udp`, `:http1`, `:http2`)
  - `:match` - Required. Matcher for determining if decoder applies
  - `:decoder` - Required. Decoder function or module implementing this behaviour

  ## Module Invocation

  When `decoder` is a module, `module.decode(ctx, payload)` is invoked (arity-2).
  Modules MUST implement the Decoder behaviour with `decode/2`.
  Arity-1 module functions are not supported; use `&Module.decode/1` explicitly.
  """
  @type decoder_spec :: %{
          required(:protocol) => :udp | :http1 | :http2,
          required(:match) => matcher(),
          required(:decoder) => decoder_fn() | module()
        }

  @typedoc """
  Field descriptor for display filter support.

  Allows extracted fields to be used in display filters.
  """
  @type field_descriptor :: %{
          required(:id) => String.t(),
          required(:type) => :string | :integer | :boolean | :binary,
          required(:extractor) => (term() -> term())
        }

  @doc """
  Decode a binary payload given the match context.

  Return `{:ok, decoded}` for successful decoding (wrapped as `{:custom, decoded}`),
  `{:error, reason}` for failures (terminal, stored as `{:decode_error, reason}`),
  or `:skip` to skip this decoder (try next matching decoder).
  """
  @callback decode(match_context(), binary()) :: decode_result()

  @doc """
  Optional: Return field descriptors for display filter support.
  """
  @callback fields() :: [field_descriptor()]

  @optional_callbacks [fields: 0]
end
