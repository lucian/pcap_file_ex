# Decoder Registry Guide

This guide covers custom protocol decoder registration in PcapFileEx, including the new context-passing API introduced in v0.5.0.

## Table of Contents

- [Overview](#overview)
- [New API (v0.5.0+)](#new-api-v050)
- [Legacy API](#legacy-api)
- [Common Patterns](#common-patterns)
- [Anti-Patterns](#anti-patterns)
- [Best Practices](#best-practices)
- [Complete Examples](#complete-examples)
- [Migration Guide](#migration-guide)

## Overview

### What is the Decoder Registry?

The decoder registry allows you to extend PcapFileEx's protocol support beyond the built-in HTTP decoder. You can register custom decoders for any application-layer protocol.

**When to use custom decoders:**
- ✅ Working with proprietary protocols
- ✅ Need automatic protocol detection in packet streams
- ✅ Want to use DisplayFilter with custom protocol fields
- ✅ Processing protocols not supported by built-in decoders

**When NOT to use:**
- ❌ One-off parsing (just call your decoder directly)
- ❌ Pre-filtered data (if you already know the protocol)
- ❌ Performance-critical tight loops (direct decoding is faster)

### Architecture

```elixir
┌─────────────┐
│   Packet    │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│  find_decoder/2     │  ← Calls matcher for each registered decoder
│  (tries matchers)   │
└──────┬──────────────┘
       │ Match found! Returns {:match, context}
       ▼
┌─────────────────────┐
│  safe_decode/3      │  ← Calls decoder with context and payload
│  (calls decoder)    │
└──────┬──────────────┘
       │
       ▼
   Decoded Result
```

## New API (v0.5.0+)

### Context Passing Pattern

**Key Concept:** Matchers can return context that decoders receive.

```elixir
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, payload ->
    if my_protocol?(layers) do
      {:match, context}  # Return context when matched
    else
      false  # Return false when not matched
    end
  end,
  decoder: fn context, payload ->  # Receive context
    decode_with_context(payload, context)
  end,
  fields: [...]
})
```

### Type Signatures

```elixir
@type match_result :: false | {:match, context :: term()}
@type matcher_fun :: (list(), binary() -> match_result())
@type decoder_fun :: (term(), binary() -> {:ok, term()} | {:error, term()} | term())

@type entry :: %{
  protocol: atom(),
  matcher: matcher_fun(),
  decoder: decoder_fun(),
  fields: [field_descriptor()]
}
```

### Benefits

1. **Thread-safe** - No `Process.put` or shared state
2. **More efficient** - Decode once in matcher, reuse in decoder
3. **Easier to test** - Pure functions with explicit dependencies
4. **Clearer intent** - Context requirements are explicit

### Example: Caching Decoded Results

```elixir
DecoderRegistry.register(%{
  protocol: :json_protocol,
  matcher: fn layers, payload ->
    if udp_port_9000?(layers) do
      case Jason.decode(payload) do
        {:ok, decoded} -> {:match, decoded}  # Cache decoded JSON
        _ -> false
      end
    else
      false
    end
  end,
  decoder: fn cached_json, _payload ->
    # Reuse cached result (no re-decoding!)
    {:ok, cached_json}
  end,
  fields: [
    %{id: "json.message_type", type: :string, extractor: fn j -> j["type"] end}
  ]
})
```

## Legacy API

### Old Pattern (Deprecated)

```elixir
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, payload ->
    my_protocol?(layers)  # Returns true/false
  end,
  decoder: fn payload ->  # Arity-1
    decode(payload)
  end,
  fields: [...]
})
```

### Deprecation Timeline

- **v0.5.0** - New API introduced, old API works with warnings
- **v0.6.0-v0.9.0** - Both APIs supported
- **v1.0.0** - Old API removed

### Why Deprecate?

**Problems with old API:**
1. No way to pass information from matcher to decoder
2. Forces double decoding or `Process.put` workarounds
3. `Process.put` causes race conditions
4. Inefficient (decode same data twice)

## Common Patterns

### Pattern 1: Caching Decoded Results

**Use case:** Avoid decoding the same payload twice.

```elixir
DecoderRegistry.register(%{
  protocol: :msgpack_protocol,
  matcher: fn layers, payload ->
    if tcp_port_8080?(layers) do
      case Msgpax.unpack(payload) do
        {:ok, unpacked} -> {:match, unpacked}  # ✅ Cache result
        _ -> false
      end
    else
      false
    end
  end,
  decoder: fn cached_unpacked, _payload ->
    {:ok, cached_unpacked}  # ✅ Use cached result
  end,
  fields: [...]
})
```

### Pattern 2: Extracting Layer Context

**Use case:** Pass TCP/IP information to decoder.

```elixir
DecoderRegistry.register(%{
  protocol: :context_aware_protocol,
  matcher: fn layers, payload ->
    # Extract TCP port and IP from layers
    tcp_info = extract_tcp_info(layers)
    ip_info = extract_ip_info(layers)

    if valid_protocol?(payload) do
      {:match, %{tcp: tcp_info, ip: ip_info}}  # ✅ Pass layer context
    else
      false
    end
  end,
  decoder: fn context, payload ->
    # Decoder can use context.tcp and context.ip
    decode_with_metadata(payload, context)
  end,
  fields: [...]
})

defp extract_tcp_info(layers) do
  Enum.find_value(layers, fn
    {:tcp, src_port, dst_port, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} ->
      %{src_port: src_port, dst_port: dst_port}
    _ -> nil
  end)
end
```

### Pattern 3: Protocol Variant Detection

**Use case:** Different decoding based on protocol variant.

```elixir
DecoderRegistry.register(%{
  protocol: :multi_variant,
  matcher: fn layers, payload ->
    if tcp_port_5000?(layers) do
      variant = detect_variant(payload)
      {:match, %{variant: variant}}  # ✅ Pass variant info
    else
      false
    end
  end,
  decoder: fn %{variant: variant}, payload ->
    case variant do
      :v1 -> decode_v1(payload)
      :v2 -> decode_v2(payload)
      :v3 -> decode_v3(payload)
    end
  end,
  fields: [...]
})

defp detect_variant(<<version, _rest::binary>>), do: :"v#{version}"
defp detect_variant(_), do: :unknown
```

### Pattern 4: Partial Decoding in Matcher

**Use case:** Quick validation in matcher, full decode in decoder.

```elixir
DecoderRegistry.register(%{
  protocol: :custom_binary,
  matcher: fn layers, payload ->
    if udp_port_7777?(layers) do
      # Quick header check
      case parse_header(payload) do
        {:ok, header} -> {:match, header}  # ✅ Pass header
        _ -> false
      end
    else
      false
    end
  end,
  decoder: fn header, payload ->
    # Full decode with header context
    full_decode(payload, header)
  end,
  fields: [...]
})
```

## Anti-Patterns

### ❌ Anti-Pattern 1: Using Process.put

```elixir
# DON'T DO THIS
DecoderRegistry.register(%{
  protocol: :bad_example,
  matcher: fn layers, payload ->
    if my_protocol?(layers) do
      context = extract_context(layers)
      Process.put(:context, context)  # ❌ Race conditions!
      true
    else
      false
    end
  end,
  decoder: fn payload ->
    context = Process.get(:context)  # ❌ Not thread-safe!
    decode(payload, context)
  end
})

# DO THIS INSTEAD
DecoderRegistry.register(%{
  protocol: :good_example,
  matcher: fn layers, payload ->
    if my_protocol?(layers) do
      {:match, extract_context(layers)}  # ✅ Explicit context
    else
      false
    end
  end,
  decoder: fn context, payload ->  # ✅ Receive context
    decode(payload, context)
  end
})
```

**Problems:**
- Race conditions if multiple packets decoded concurrently
- Name collisions between decoders
- Implicit state makes testing difficult

### ❌ Anti-Pattern 2: Decoding Twice

```elixir
# DON'T DO THIS
DecoderRegistry.register(%{
  protocol: :inefficient,
  matcher: fn layers, payload ->
    tcp_layer?(layers) and match?({:ok, _}, MyProto.decode(payload))  # ❌ Decode #1
  end,
  decoder: &MyProto.decode/1  # ❌ Decode #2 - wasted work!
})

# DO THIS INSTEAD
DecoderRegistry.register(%{
  protocol: :efficient,
  matcher: fn layers, payload ->
    if tcp_layer?(layers) do
      case MyProto.decode(payload) do
        {:ok, decoded} -> {:match, decoded}  # ✅ Decode once
        _ -> false
      end
    else
      false
    end
  end,
  decoder: fn cached, _payload -> {:ok, cached} end  # ✅ Use cached
})
```

**Problems:**
- Performance overhead
- Wasted computation
- Especially bad for complex protocols

### ❌ Anti-Pattern 3: Not Handling nil Context

```elixir
# DON'T DO THIS
DecoderRegistry.register(%{
  protocol: :unsafe,
  matcher: fn layers, payload ->
    if my_protocol?(layers) do
      {:match, extract_optional_context(layers)}  # Might return nil
    else
      false
    end
  end,
  decoder: fn context, payload ->
    # ❌ Crashes if context is nil!
    decode_with_required_context(payload, context.required_field)
  end
})

# DO THIS INSTEAD
DecoderRegistry.register(%{
  protocol: :safe,
  matcher: fn layers, payload ->
    if my_protocol?(layers) do
      {:match, extract_optional_context(layers) || %{}}  # ✅ Default value
    else
      false
    end
  end,
  decoder: fn context, payload ->
    # ✅ Handle missing context gracefully
    case Map.get(context, :required_field) do
      nil -> decode_without_context(payload)
      field -> decode_with_context(payload, field)
    end
  end
})
```

## Best Practices

### ✅ Best Practice 1: Return Cached Decode from Matcher

```elixir
# If your matcher needs to decode to validate, cache the result
matcher: fn layers, payload ->
  if correct_layer?(layers) do
    case expensive_decode(payload) do
      {:ok, decoded} -> {:match, decoded}  # ✅ Cache it
      _ -> false
    end
  else
    false
  end
end,
decoder: fn cached, _payload -> {:ok, cached} end  # ✅ Reuse it
```

### ✅ Best Practice 2: Use Context for Variant Selection

```elixir
# Store variant/version info in context
matcher: fn layers, payload ->
  if protocol_port?(layers) do
    variant = detect_variant(payload)
    {:match, %{variant: variant}}  # ✅ Store variant
  else
    false
  end
end,
decoder: fn %{variant: v}, payload ->
  dispatch_to_variant_decoder(v, payload)  # ✅ Use variant
end
```

### ✅ Best Practice 3: Test Matchers and Decoders Independently

```elixir
# In your tests
test "matcher returns context for valid packets" do
  layers = build_tcp_layers(port: 8080)
  payload = build_valid_payload()

  result = matcher.(layers, payload)

  assert {:match, context} = result
  assert context.version == 1
end

test "decoder uses context correctly" do
  context = %{version: 1}
  payload = build_valid_payload()

  assert {:ok, decoded} = decoder.(context, payload)
  assert decoded.version == 1
end
```

### ✅ Best Practice 4: Validate Context in Decoder

```elixir
decoder: fn context, payload ->
  # Validate context before use
  with {:ok, validated_context} <- validate_context(context),
       {:ok, decoded} <- decode_with_validated_context(payload, validated_context) do
    {:ok, decoded}
  else
    {:error, :invalid_context} -> {:error, :decoder_context_invalid}
    error -> error
  end
end
```

## Complete Examples

### Example 1: DNS Decoder

```elixir
defmodule DNSDecoder do
  def register do
    PcapFileEx.DecoderRegistry.register(%{
      protocol: :dns,
      matcher: &match_dns/2,
      decoder: &decode_dns/2,
      fields: dns_fields()
    })
  end

  defp match_dns(layers, payload) do
    if udp_port_53?(layers) do
      case parse_dns_header(payload) do
        {:ok, header} -> {:match, header}  # Cache header
        _ -> false
      end
    else
      false
    end
  end

  defp decode_dns(header, payload) do
    # Full DNS parsing using cached header
    with {:ok, questions} <- parse_questions(payload, header.qd_count),
         {:ok, answers} <- parse_answers(payload, header.an_count) do
      {:ok, %{
        header: header,
        questions: questions,
        answers: answers
      }}
    end
  end

  defp udp_port_53?(layers) do
    Enum.any?(layers, fn
      {:udp, _, 53, _, _, _} -> true  # Dest port 53
      {:udp, 53, _, _, _, _} -> true  # Src port 53
      _ -> false
    end)
  end

  defp parse_dns_header(<<
    id::16,
    flags::16,
    qd_count::16,
    an_count::16,
    ns_count::16,
    ar_count::16,
    _rest::binary
  >>) do
    {:ok, %{
      id: id,
      flags: flags,
      qd_count: qd_count,
      an_count: an_count,
      ns_count: ns_count,
      ar_count: ar_count
    }}
  end
  defp parse_dns_header(_), do: {:error, :invalid_dns_header}

  defp dns_fields do
    [
      %{id: "dns.id", type: :integer, extractor: fn d -> d.header.id end},
      %{id: "dns.questions", type: :integer, extractor: fn d -> length(d.questions) end},
      %{id: "dns.answers", type: :integer, extractor: fn d -> length(d.answers) end}
    ]
  end

  # Simplified for brevity
  defp parse_questions(_payload, _count), do: {:ok, []}
  defp parse_answers(_payload, _count), do: {:ok, []}
end

# Usage
DNSDecoder.register()

{:ok, packets} = PcapFileEx.read_all("dns_traffic.pcap")
dns_packets = Enum.filter(packets, fn p -> :dns in p.protocols end)

Enum.each(dns_packets, fn packet ->
  {:ok, {:dns, dns}} = PcapFileEx.Packet.decode_registered(packet)
  IO.puts("DNS Query ID: #{dns.header.id}")
end)
```

### Example 2: Custom Binary Protocol with Variants

```elixir
defmodule CustomProtocol do
  @v1_magic <<0xAA, 0xBB>>
  @v2_magic <<0xCC, 0xDD>>

  def register do
    PcapFileEx.DecoderRegistry.register(%{
      protocol: :custom_proto,
      matcher: &match_protocol/2,
      decoder: &decode_protocol/2,
      fields: protocol_fields()
    })
  end

  defp match_protocol(layers, payload) do
    if tcp_port_9999?(layers) do
      case detect_version(payload) do
        {:ok, version, header} -> {:match, %{version: version, header: header}}
        :error -> false
      end
    else
      false
    end
  end

  defp detect_version(<<@v1_magic, header_data::binary-size(8), _rest::binary>>) do
    {:ok, :v1, parse_v1_header(header_data)}
  end
  defp detect_version(<<@v2_magic, header_data::binary-size(12), _rest::binary>>) do
    {:ok, :v2, parse_v2_header(header_data)}
  end
  defp detect_version(_), do: :error

  defp decode_protocol(%{version: :v1, header: header}, payload) do
    decode_v1_body(payload, header)
  end
  defp decode_protocol(%{version: :v2, header: header}, payload) do
    decode_v2_body(payload, header)
  end

  defp tcp_port_9999?(layers) do
    Enum.any?(layers, fn
      {:tcp, _, 9999, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} -> true
      {:tcp, 9999, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} -> true
      _ -> false
    end)
  end

  defp protocol_fields do
    [
      %{id: "custom.version", type: :string, extractor: fn d -> to_string(d.version) end},
      %{id: "custom.payload_len", type: :integer, extractor: fn d -> byte_size(d.body) end}
    ]
  end

  # Simplified implementations
  defp parse_v1_header(data), do: %{format: :v1, data: data}
  defp parse_v2_header(data), do: %{format: :v2, data: data}
  defp decode_v1_body(payload, header), do: {:ok, %{version: :v1, header: header, body: payload}}
  defp decode_v2_body(payload, header), do: {:ok, %{version: :v2, header: header, body: payload}}
end
```

## Migration Guide

### Step 1: Identify Old-Style Decoders

Search your codebase:
```bash
git grep "decoder: fn payload"  # Find arity-1 decoders
git grep "matcher:.*-> true"   # Find boolean matchers
```

### Step 2: Update Matcher to Return Context

**Before:**
```elixir
matcher: fn layers, payload ->
  tcp_layer?(layers) and valid_format?(payload)
end
```

**After:**
```elixir
matcher: fn layers, payload ->
  if tcp_layer?(layers) do
    case parse_and_validate(payload) do
      {:ok, parsed} -> {:match, parsed}  # Return context
      _ -> false
    end
  else
    false
  end
end
```

### Step 3: Update Decoder to Accept Context

**Before:**
```elixir
decoder: fn payload ->
  parse_and_validate(payload)  # Decode again!
end
```

**After:**
```elixir
decoder: fn cached_parsed, _payload ->
  {:ok, cached_parsed}  # Use cached result
end
```

### Step 4: Test Thoroughly

```elixir
# Test matcher returns context
test "matcher returns parsed data as context" do
  layers = build_layers()
  payload = build_payload()

  assert {:match, context} = matcher.(layers, payload)
  assert context.field == expected_value
end

# Test decoder uses context
test "decoder uses cached context" do
  context = %{parsed: :data}
  payload = build_payload()

  assert {:ok, result} = decoder.(context, payload)
  assert result == context  # Verify it's using cached data
end
```

### Step 5: Remove Process.put Workarounds

**Before:**
```elixir
matcher: fn layers, payload ->
  if match?(layers) do
    Process.put(:context, extract(layers))  # Remove this
    true
  else
    false
  end
end,
decoder: fn payload ->
  context = Process.get(:context)  # Remove this
  decode(payload, context)
end
```

**After:**
```elixir
matcher: fn layers, payload ->
  if match?(layers) do
    {:match, extract(layers)}  # Clean context passing
  else
    false
  end
end,
decoder: fn context, payload ->
  decode(payload, context)  # Receive context
end
```

## Performance Considerations

### Matcher Performance

Matchers are called for EVERY registered decoder on EVERY packet. Keep them fast:

```elixir
# ✅ GOOD: Quick port check first
matcher: fn layers, payload ->
  if quick_port_check?(layers) do  # Fast
    case expensive_decode(payload) do  # Only if port matches
      {:ok, decoded} -> {:match, decoded}
      _ -> false
    end
  else
    false
  end
end

# ❌ BAD: Expensive check for every packet
matcher: fn layers, payload ->
  case expensive_decode(payload) do  # Slow, runs on every packet!
    {:ok, decoded} ->
      if correct_port?(layers) do  # Check port AFTER decode
        {:match, decoded}
      else
        false
      end
    _ -> false
  end
end
```

### Context Size

Keep context reasonably sized - it's passed around:

```elixir
# ✅ GOOD: Minimal context
{:match, %{version: 1, type: :request}}

# ⚠️ ACCEPTABLE: Moderate context
{:match, %{parsed_header: header, metadata: small_map}}

# ❌ BAD: Huge context
{:match, %{
  entire_decoded_payload: massive_structure,  # Too large!
  full_layers: all_layers,  # Already available!
  redundant: everything  # Wasteful!
}}
```

## Troubleshooting

### Issue: Decoder Never Called

**Symptom:** Matcher returns `{:match, _}` but decoder not invoked.

**Cause:** Exception in matcher rescue clause.

**Solution:** Check matcher rescue block, add logging:

```elixir
matcher: fn layers, payload ->
  case my_parse(payload) do
    {:ok, parsed} -> {:match, parsed}
    _ -> false
  end
rescue
  e ->
    IO.inspect(e, label: "Matcher exception")  # Add debugging
    reraise e, __STACKTRACE__  # Or log and return false
end
```

### Issue: Context is nil

**Symptom:** Decoder receives `nil` as context.

**Cause:** Old API decoder (arity-1) wrapped by compatibility layer.

**Solution:** Migrate to arity-2 decoder:

```elixir
# Old (gets nil context from wrapper)
decoder: fn payload -> decode(payload) end

# New (receives actual context)
decoder: fn context, payload -> decode(payload, context) end
```

### Issue: Deprecation Warnings

**Symptom:** Seeing deprecation warnings for old API.

**Cause:** Using arity-1 decoder.

**Solution:** Follow migration guide above to update to arity-2 decoder.

## Related Documentation

- [Usage Rules](../usage-rules.md) - General PcapFileEx patterns
- [HTTP Guide](http.md) - HTTP-specific decoding (uses new API internally)
- [Examples](examples.md) - Complete working examples
- [CHANGELOG](../CHANGELOG.md#v0-5-0-2025-11-19) - v0.5.0 release notes
