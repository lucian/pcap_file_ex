# Decoder Registry Context Passing Enhancement

**Date:** November 19, 2025
**Status:** Proposed
**Priority:** Medium-High
**Effort:** Medium (2-3 days)
**Breaking Change:** Yes (with backward compatibility path)

---

## Executive Summary

The current PcapFileEx decoder registry API forces users to use `Process.put` (race conditions, not thread-safe) or re-decode data twice when they need to pass information discovered during matching to the decoder function. This spec proposes enhancing the API to allow matchers to return context that decoders can receive, enabling clean, pure data flow.

**Current Problem:**
```elixir
# Matcher can only return true/false
@callback matcher(layers :: term(), payload :: binary()) :: boolean()
# Decoder receives only payload - no context!
@callback decoder(payload :: binary()) :: term()
```

**Proposed Solution:**
```elixir
# Matcher returns context when it matches
@callback matcher(layers :: term(), payload :: binary()) ::
  false | {:match, context :: term()}
# Decoder receives context
@callback decoder(context :: term(), payload :: binary()) :: term()
```

---

## Problem Statement

### Current API Limitation

**File:** `lib/pcap_file_ex/decoder_registry.ex:24-29`

```elixir
@type entry :: %{
  protocol: atom(),
  matcher: (list(), binary() -> boolean()),           # Can only return true/false
  decoder: (binary() -> {:ok, term()} | {:error, term()} | term()),
  fields: [field_descriptor()]
}
```

**Validation:** `lib/pcap_file_ex/decoder_registry.ex:47-48`

```elixir
def register(%{protocol: protocol, matcher: matcher, decoder: decoder} = entry)
    when is_atom(protocol) and is_function(matcher, 2) and is_function(decoder, 1) do
```

The decoder **must** be arity-1 (accepts only payload).

### Real-World Impact

When a matcher needs to examine protocol layers to determine:
1. **Which variant** of a protocol this is
2. **Metadata** needed for decoding (e.g., SCTP port, NGAP identifiers)
3. **Context** from layers (IP addresses, timestamps)

...there is **no way** to pass this information to the decoder.

### Current Workarounds (Both Problematic)

#### Workaround 1: Process.put (Thread-Unsafe)

```elixir
DecoderRegistry.register(%{
  protocol: :nrppa,
  matcher: fn layers, _payload ->
    if sctp_ngap?(layers) do
      context = extract_sctp_context(layers)
      Process.put({:nrppa_context, self()}, context)  # ❌ Race conditions!
      true
    else
      false
    end
  end,
  decoder: fn payload ->
    context = Process.get({:nrppa_context, self()})  # ❌ Not thread-safe!
    decode_nrppa(payload, context)
  end
})
```

**Problems:**
- **Race conditions** if PcapFileEx pipelines packets
- **Name collisions** between multiple registries
- **Not thread-safe** (process dictionary is per-process)
- **Implicit state** makes testing difficult

#### Workaround 2: Decode Twice (Inefficient)

**Current HTTP decoder example:** `lib/pcap_file_ex/decoder_registry.ex:93-108`

```elixir
%{
  protocol: :http,
  matcher: fn layers, payload ->
    tcp_layer?(layers) and match?({:ok, _}, HTTP.decode(payload))  # Decode #1
  end,
  decoder: &HTTP.decode/1  # Decode #2 - redundant!
}
```

**Problems:**
- **Performance overhead** - decode same data twice
- **Wasted computation** - especially for complex protocols

### User Feedback

> "The matcher can only return true/false, and the decoder only receives the payload. There is **no way** to pass context from matcher to decoder without either Process dictionary or not using PcapFileEx's registry system at all."

User was forced to bypass the registry entirely and implement custom packet reading.

---

## Proposed Solution

### New API Signatures

```elixir
# Updated type definitions
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

### Example Usage

#### Before (Process.put workaround)

```elixir
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, _payload ->
    case detect_variant(layers) do
      {:ok, variant, metadata} ->
        Process.put(:variant, variant)
        Process.put(:metadata, metadata)
        true
      :no_match ->
        false
    end
  end,
  decoder: fn payload ->
    variant = Process.get(:variant)
    metadata = Process.get(:metadata)
    decode_with_context(payload, variant, metadata)
  end
})
```

#### After (Clean context passing)

```elixir
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, _payload ->
    case detect_variant(layers) do
      {:ok, variant, metadata} ->
        {:match, %{variant: variant, metadata: metadata}}  # ✅ Return context
      :no_match ->
        false
    end
  end,
  decoder: fn context, payload ->  # ✅ Receive context
    decode_with_context(payload, context.variant, context.metadata)
  end
})
```

#### HTTP Decoder Optimization

```elixir
# Before: Decode twice
%{
  protocol: :http,
  matcher: fn layers, payload ->
    tcp_layer?(layers) and match?({:ok, _}, HTTP.decode(payload))  # Decode #1
  end,
  decoder: &HTTP.decode/1  # Decode #2
}

# After: Decode once, cache result
%{
  protocol: :http,
  matcher: fn layers, payload ->
    if tcp_layer?(layers) do
      case HTTP.decode(payload) do
        {:ok, decoded} -> {:match, decoded}  # ✅ Cache decoded result
        _ -> false
      end
    else
      false
    end
  end,
  decoder: fn cached_decoded, _payload ->  # ✅ Use cached result
    {:ok, cached_decoded}
  end
}
```

### Benefits

- ✅ **No Process.put** - pure data flow
- ✅ **Thread-safe** - no shared state
- ✅ **No race conditions** - explicit context passing
- ✅ **More efficient** - decode once, not twice
- ✅ **Easier to test** - pure functions
- ✅ **Clearer intent** - explicit dependencies

---

## Implementation Plan

### Phase 1: Update Type Definitions (30 min)

**File:** `lib/pcap_file_ex/decoder_registry.ex`

**Changes:**

```elixir
# Add new types (after line 23)
@type match_result :: false | {:match, context :: term()}
@type matcher_fun :: (list(), binary() -> match_result())
@type decoder_fun :: (term(), binary() -> {:ok, term()} | {:error, term()} | term())

# Update entry type (line 24-29)
@type entry :: %{
  protocol: atom(),
  matcher: matcher_fun(),       # Updated signature
  decoder: decoder_fun(),       # Updated signature
  fields: [field_descriptor()]
}
```

### Phase 2: Support Both API Versions (Backward Compatibility) (2 hours)

**File:** `lib/pcap_file_ex/decoder_registry.ex`

**Strategy:** Accept both old (arity-1) and new (arity-2) decoder functions.

```elixir
# Update register/1 validation (line 47-57)
def register(%{protocol: protocol, matcher: matcher, decoder: decoder} = entry)
    when is_atom(protocol) and is_function(matcher, 2) and
         (is_function(decoder, 1) or is_function(decoder, 2)) do  # Accept both arities

  normalized_entry = normalize_entry(entry)
  # ... rest of function
end

# Add normalization helper
defp normalize_entry(%{matcher: matcher, decoder: decoder} = entry) do
  case {matcher_arity(matcher), decoder_arity(decoder)} do
    # Old API: matcher returns boolean, decoder arity-1
    {_, 1} ->
      %{entry |
        matcher: wrap_old_matcher(matcher),
        decoder: wrap_old_decoder(decoder)
      }

    # New API: matcher returns {:match, context}, decoder arity-2
    {_, 2} ->
      entry  # Already in new format
  end
end

defp wrap_old_matcher(matcher) do
  fn layers, payload ->
    case matcher.(layers, payload) do
      true -> {:match, nil}   # Old API: convert true to {:match, nil}
      false -> false
      other -> other          # Already new format
    end
  end
end

defp wrap_old_decoder(decoder) do
  fn _context, payload ->
    decoder.(payload)  # Old API: ignore context, call with payload only
  end
end

defp matcher_arity(fun), do: :erlang.fun_info(fun)[:arity]
defp decoder_arity(fun), do: :erlang.fun_info(fun)[:arity]
```

### Phase 3: Update Packet Invocation Logic (2 hours)

**File:** `lib/pcap_file_ex/packet.ex`

#### Change 1: Update find_decoder to capture context

**Current code:** Lines 371-384

```elixir
defp find_decoder(layers, payload) do
  DecoderRegistry.list()
  |> Enum.find(&safe_match?(&1, layers, payload))  # Returns entry or nil
  |> case do
    nil -> :no_match
    entry -> {:ok, entry}
  end
end

defp safe_match?(%{matcher: matcher}, layers, payload) do
  matcher.(layers, normalize_payload(payload))  # Returns true/false only
rescue
  _ -> false
end
```

**New code:**

```elixir
defp find_decoder(layers, payload) do
  DecoderRegistry.list()
  |> Enum.find_value(fn entry ->
    case safe_match?(entry, layers, payload) do
      {:match, context} -> {:ok, {entry, context}}  # Capture context
      false -> nil
      _ -> nil
    end
  end)
  |> case do
    nil -> :no_match
    result -> result  # {:ok, {entry, context}}
  end
end

defp safe_match?(%{matcher: matcher}, layers, payload) do
  case matcher.(layers, normalize_payload(payload)) do
    {:match, context} -> {:match, context}  # New API
    true -> {:match, nil}                   # Old API (backward compat)
    false -> false
    _ -> false
  end
rescue
  _ -> false
end
```

#### Change 2: Update decode_registered to pass context

**Current code:** Lines 212-229

```elixir
def decode_registered(%__MODULE__{} = packet) do
  with {:ok, {layers, payload}} <- layers_payload(packet),
       {:ok, entry} <- find_decoder(layers, payload) do
    case cached_decoded(packet, entry.protocol) do
      {:ok, value} ->
        {:ok, {entry.protocol, value}}

      :miss ->
        case safe_decode(entry, payload) do  # Only passes entry and payload
          {:ok, decoded} -> {:ok, {entry.protocol, decoded}}
          other -> other
        end
    end
  else
    :no_match -> :no_match
    {:error, reason} -> {:error, reason}
  end
end
```

**New code:**

```elixir
def decode_registered(%__MODULE__{} = packet) do
  with {:ok, {layers, payload}} <- layers_payload(packet),
       {:ok, {entry, context}} <- find_decoder(layers, payload) do  # Receive context
    case cached_decoded(packet, entry.protocol) do
      {:ok, value} ->
        {:ok, {entry.protocol, value}}

      :miss ->
        case safe_decode(entry, context, payload) do  # Pass context
          {:ok, decoded} -> {:ok, {entry.protocol, decoded}}
          other -> other
        end
    end
  else
    :no_match -> :no_match
    {:error, reason} -> {:error, reason}
  end
end
```

#### Change 3: Update safe_decode to accept context

**Current code:** Lines 386-394

```elixir
defp safe_decode(%{decoder: decoder}, payload) do
  case decoder.(normalize_payload(payload)) do  # Arity-1 call
    {:ok, value} -> {:ok, value}
    {:error, reason} -> {:error, reason}
    value -> {:ok, value}
  end
rescue
  exception -> {:error, exception}
end
```

**New code:**

```elixir
defp safe_decode(%{decoder: decoder}, context, payload) do
  case decoder.(context, normalize_payload(payload)) do  # Arity-2 call
    {:ok, value} -> {:ok, value}
    {:error, reason} -> {:error, reason}
    value -> {:ok, value}
  end
rescue
  exception -> {:error, exception}
end
```

### Phase 4: Update Built-in HTTP Decoder (30 min)

**File:** `lib/pcap_file_ex/decoder_registry.ex`

**Current code:** Lines 93-108

```elixir
defp default_decoders do
  [
    normalize_fields(%{
      protocol: :http,
      matcher: fn layers, payload ->
        Enum.any?(layers, fn
          {:tcp, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} -> true
          :tcp -> true
          %{protocol: :tcp} -> true
          _ -> false
        end) and match?({:ok, _}, HTTP.decode(payload))  # Decode in matcher
      end,
      decoder: &HTTP.decode/1,  # Decode again in decoder
      fields: default_http_fields()
    })
  ]
end
```

**New code (optimized):**

```elixir
defp default_decoders do
  [
    normalize_fields(%{
      protocol: :http,
      matcher: fn layers, payload ->
        if Enum.any?(layers, fn
          {:tcp, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} -> true
          :tcp -> true
          %{protocol: :tcp} -> true
          _ -> false
        end) do
          case HTTP.decode(payload) do
            {:ok, decoded} -> {:match, decoded}  # Cache result
            _ -> false
          end
        else
          false
        end
      end,
      decoder: fn decoded, _payload -> {:ok, decoded} end,  # Use cached result
      fields: default_http_fields()
    })
  ]
end
```

### Phase 5: Update Documentation (1 hour)

**Files to update:**
- `lib/pcap_file_ex/decoder_registry.ex` - Module doc with new examples
- `README.md` - Update decoder registration examples
- `CHANGELOG.md` - Document breaking change and migration path

**Add deprecation warning for old API:**

```elixir
@doc """
Registers a custom protocol decoder.

## New API (v0.5.0+)

Matchers can now return context to decoders:

    DecoderRegistry.register(%{
      protocol: :my_protocol,
      matcher: fn layers, payload ->
        if my_protocol?(layers) do
          {:match, extract_context(layers)}  # Return context
        else
          false
        end
      end,
      decoder: fn context, payload ->  # Receive context
        decode(payload, context)
      end,
      fields: [...]
    })

## Legacy API (deprecated)

The old API is still supported for backward compatibility:

    DecoderRegistry.register(%{
      protocol: :my_protocol,
      matcher: fn layers, _payload -> my_protocol?(layers) end,  # Returns boolean
      decoder: fn payload -> decode(payload) end,  # Arity-1
      fields: [...]
    })

**Note:** The legacy API will be removed in v1.0.0. Please migrate to the new API.
"""
```

---

## Testing Requirements

### Unit Tests

**File:** `test/pcap_file_ex/decoder_registry_test.exs`

```elixir
describe "context passing (new API)" do
  test "matcher can return context to decoder" do
    DecoderRegistry.register(%{
      protocol: :context_test,
      matcher: fn _layers, payload ->
        if String.contains?(payload, "CONTEXT") do
          {:match, %{found_at: :erlang.byte_size(payload)}}
        else
          false
        end
      end,
      decoder: fn context, payload ->
        {:ok, %{context: context, payload: payload}}
      end,
      fields: []
    })

    # Test that context is passed through
    packet = build_test_packet("DATA CONTEXT HERE")
    {:ok, {:context_test, decoded}} = Packet.decode_registered(packet)

    assert decoded.context == %{found_at: _}
    assert decoded.payload == "DATA CONTEXT HERE"
  end

  test "matcher returning false prevents decoder invocation" do
    decoder_called = Agent.start_link(fn -> false end)

    DecoderRegistry.register(%{
      protocol: :no_match_test,
      matcher: fn _layers, _payload -> false end,
      decoder: fn _context, _payload ->
        Agent.update(decoder_called, fn _ -> true end)
        {:ok, :should_not_reach}
      end,
      fields: []
    })

    packet = build_test_packet("DATA")
    :no_match = Packet.decode_registered(packet)

    refute Agent.get(decoder_called, & &1)
  end
end

describe "backward compatibility (old API)" do
  test "arity-1 decoder still works" do
    DecoderRegistry.register(%{
      protocol: :legacy_test,
      matcher: fn _layers, payload ->
        String.contains?(payload, "LEGACY")  # Returns boolean
      end,
      decoder: fn payload ->  # Arity-1
        {:ok, String.upcase(payload)}
      end,
      fields: []
    })

    packet = build_test_packet("legacy data")
    {:ok, {:legacy_test, decoded}} = Packet.decode_registered(packet)

    assert decoded == "LEGACY DATA"
  end

  test "mixed old and new decoders coexist" do
    # Register old API decoder
    DecoderRegistry.register(%{
      protocol: :old_api,
      matcher: fn _layers, payload -> String.contains?(payload, "OLD") end,
      decoder: fn payload -> {:ok, :old} end,
      fields: []
    })

    # Register new API decoder
    DecoderRegistry.register(%{
      protocol: :new_api,
      matcher: fn _layers, payload ->
        if String.contains?(payload, "NEW") do
          {:match, :context}
        else
          false
        end
      end,
      decoder: fn context, _payload -> {:ok, :new} end,
      fields: []
    })

    # Both should work
    assert {:ok, {:old_api, :old}} =
      Packet.decode_registered(build_test_packet("OLD data"))
    assert {:ok, {:new_api, :new}} =
      Packet.decode_registered(build_test_packet("NEW data"))
  end
end

describe "error handling" do
  test "matcher exception returns false" do
    DecoderRegistry.register(%{
      protocol: :crash_test,
      matcher: fn _layers, _payload ->
        raise "matcher crash"
      end,
      decoder: fn _context, _payload -> {:ok, :unreachable} end,
      fields: []
    })

    packet = build_test_packet("data")
    assert :no_match = Packet.decode_registered(packet)
  end

  test "decoder exception returns error tuple" do
    DecoderRegistry.register(%{
      protocol: :decoder_crash,
      matcher: fn _layers, _payload -> {:match, :ctx} end,
      decoder: fn _context, _payload ->
        raise ArgumentError, "decoder crash"
      end,
      fields: []
    })

    packet = build_test_packet("data")
    assert {:error, %ArgumentError{}} = Packet.decode_registered(packet)
  end
end
```

### Integration Tests

**File:** `test/integration/decoder_registry_integration_test.exs`

```elixir
defmodule PcapFileEx.DecoderRegistryIntegrationTest do
  use ExUnit.Case

  test "context passing with real PCAP file" do
    # Register custom decoder that extracts TCP port from layers
    DecoderRegistry.register(%{
      protocol: :tcp_with_port,
      matcher: fn layers, _payload ->
        Enum.find_value(layers, fn
          {:tcp, src_port, _dst_port, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} ->
            {:match, %{src_port: src_port}}
          _ -> nil
        end)
      end,
      decoder: fn context, payload ->
        {:ok, %{port: context.src_port, data: payload}}
      end,
      fields: []
    })

    # Process real PCAP file
    {:ok, packets} = PcapFileEx.read_all("test/fixtures/sample.pcap")

    decoded_packets =
      packets
      |> Enum.map(&Packet.decode_registered/1)
      |> Enum.filter(&match?({:ok, {:tcp_with_port, _}}, &1))

    assert length(decoded_packets) > 0

    for {:ok, {:tcp_with_port, decoded}} <- decoded_packets do
      assert is_integer(decoded.port)
      assert decoded.port > 0
    end
  end
end
```

### Property-Based Tests

**File:** `test/property_test/decoder_registry_property_test.exs`

```elixir
defmodule PcapFileEx.DecoderRegistryPropertyTest do
  use ExUnit.Case
  use ExUnitProperties

  property "context from matcher always reaches decoder" do
    check all(
      context <- term(),
      payload <- binary()
    ) do
      received_context = Agent.start_link(fn -> nil end)

      DecoderRegistry.register(%{
        protocol: :property_test,
        matcher: fn _layers, _payload -> {:match, context} end,
        decoder: fn ctx, _payload ->
          Agent.update(received_context, fn _ -> ctx end)
          {:ok, :decoded}
        end,
        fields: []
      })

      packet = build_test_packet(payload)
      {:ok, {:property_test, :decoded}} = Packet.decode_registered(packet)

      assert Agent.get(received_context, & &1) == context
    end
  end

  property "matcher returning false never calls decoder" do
    check all(payload <- binary()) do
      decoder_called = Agent.start_link(fn -> false end)

      DecoderRegistry.register(%{
        protocol: :no_call_test,
        matcher: fn _layers, _payload -> false end,
        decoder: fn _ctx, _payload ->
          Agent.update(decoder_called, fn _ -> true end)
          {:ok, :unreachable}
        end,
        fields: []
      })

      packet = build_test_packet(payload)
      :no_match = Packet.decode_registered(packet)

      refute Agent.get(decoder_called, & &1)
    end
  end
end
```

---

## Migration Guide

### For Library Users

#### Step 1: Identify Decoders Using Process.put

Search your codebase for:
```bash
git grep "Process.put.*DecoderRegistry"
git grep "Process.get.*matcher"
```

#### Step 2: Update to New API

**Before:**
```elixir
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, _payload ->
    if match_condition?(layers) do
      Process.put(:my_context, extract_context(layers))
      true
    else
      false
    end
  end,
  decoder: fn payload ->
    context = Process.get(:my_context)
    decode(payload, context)
  end
})
```

**After:**
```elixir
DecoderRegistry.register(%{
  protocol: :my_protocol,
  matcher: fn layers, _payload ->
    if match_condition?(layers) do
      {:match, extract_context(layers)}
    else
      false
    end
  end,
  decoder: fn context, payload ->
    decode(payload, context)
  end
})
```

#### Step 3: Test Thoroughly

- Verify decoders are called with correct context
- Check that `false` matchers don't invoke decoders
- Test error handling paths

### For Library Maintainers

#### Deprecation Timeline

- **v0.5.0:** New API introduced, old API works (with warnings)
- **v0.6.0-v0.9.0:** Both APIs supported
- **v1.0.0:** Old API removed, only new API supported

#### Deprecation Warnings

Add compile-time warnings for old API usage:

```elixir
def register(%{decoder: decoder} = entry) when is_function(decoder, 1) do
  IO.warn("""
  Decoder registry old API (arity-1 decoder) is deprecated and will be removed in v1.0.0.
  Please update your decoder to accept context as first argument:

    decoder: fn context, payload -> ... end

  See migration guide: https://hexdocs.pm/pcap_file_ex/decoder-migration.html
  """, Macro.Env.stacktrace(__ENV__))

  # ... rest of function
end
```

---

## References

### Code Locations

| File | Lines | Description |
|------|-------|-------------|
| `lib/pcap_file_ex/decoder_registry.ex` | 24-29 | Current type definitions |
| `lib/pcap_file_ex/decoder_registry.ex` | 47-57 | Registration validation |
| `lib/pcap_file_ex/decoder_registry.ex` | 93-108 | HTTP decoder (example to optimize) |
| `lib/pcap_file_ex/packet.ex` | 212-229 | decode_registered/1 |
| `lib/pcap_file_ex/packet.ex` | 371-394 | find_decoder and safe_decode |
| `test/pcap_file_ex/decoder_registry_test.exs` | 1-100 | Existing test suite |

### External Resources

- [Elixir Function Arity](https://hexdocs.pm/elixir/Kernel.html#is_function/2)
- [Process Dictionary Risks](https://elixirforum.com/t/why-is-the-process-dictionary-bad/14875)
- [Backward Compatibility Best Practices](https://hexdocs.pm/elixir/compatibility-and-deprecations.html)

---

## Success Criteria

- [ ] New API allows context passing without Process.put
- [ ] Old API continues to work (backward compatibility)
- [ ] HTTP decoder optimized (decode once, not twice)
- [ ] All existing tests pass
- [ ] New tests achieve >90% coverage on changed code
- [ ] Documentation updated with examples
- [ ] Migration guide published
- [ ] Deprecation warnings emitted for old API usage

---

## Implementation Checklist

### Code Changes

- [ ] Update type definitions in `decoder_registry.ex`
- [ ] Add backward compatibility wrappers
- [ ] Update `find_decoder` to capture context
- [ ] Update `decode_registered` to pass context
- [ ] Update `safe_decode` to accept context
- [ ] Optimize HTTP decoder
- [ ] Add deprecation warnings

### Tests

- [ ] Unit tests for new API
- [ ] Unit tests for backward compatibility
- [ ] Integration tests with real PCAP files
- [ ] Property-based tests for invariants
- [ ] Error handling tests

### Documentation

- [ ] Update module documentation
- [ ] Add examples to README
- [ ] Write migration guide
- [ ] Update CHANGELOG
- [ ] Add inline code comments

### Review

- [ ] Code review by maintainer
- [ ] Performance testing (ensure no regressions)
- [ ] Manual testing with example decoders
- [ ] CI pipeline passes

---

**End of Specification**
