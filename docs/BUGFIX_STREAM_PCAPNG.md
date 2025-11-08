# Bug Fix: Stream.from_reader/1 Support for PcapNg Readers

**Date:** 2025-11-04
**Severity:** High (prevents using pre-filtering with PCAPNG files)
**Status:** ✅ Fixed

---

## Problem

`PcapFileEx.Stream.from_reader/1` only accepted `Pcap` readers, causing a `FunctionClauseError` when used with `PcapNg` readers.

### Error Reproduction

```elixir
# This failed with FunctionClauseError
{:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
:ok = PcapFileEx.PcapNg.set_filter(reader, [PreFilter.protocol("tcp")])
packets = PcapFileEx.Stream.from_reader(reader) |> Enum.take(10)

# Error:
** (FunctionClauseError) no function clause matching in PcapFileEx.Pcap.next_packet/1
    The following arguments were given to PcapFileEx.Pcap.next_packet/1:
        # 1
        %PcapFileEx.PcapNg{...}
```

### Impact

- **Pre-filtering with PCAPNG files was broken**
- Users couldn't use the new high-performance filtering on PCAPNG format
- Workaround required manual packet iteration

---

## Root Cause

The `Stream.from_reader/1` function had a single function clause that only pattern-matched on `%Pcap{}` structs:

```elixir
# Old code (broken)
def from_reader(reader) do
  Stream.resource(
    fn -> reader end,
    fn reader ->
      case Pcap.next_packet(reader) do  # Only works with Pcap!
        {:ok, packet} -> {[packet], reader}
        :eof -> {:halt, reader}
        {:error, reason} -> raise "Failed to read packet: #{reason}"
      end
    end,
    fn _reader -> :ok end
  )
end
```

When a `PcapNg` struct was passed, it failed pattern matching.

---

## Solution

Added multiple function clauses with pattern matching on the reader type:

```elixir
# New code (fixed)
@spec from_reader(Pcap.t() | PcapNg.t()) :: Enumerable.t()

def from_reader(%Pcap{} = reader) do
  Stream.resource(
    fn -> reader end,
    fn reader ->
      case Pcap.next_packet(reader) do
        {:ok, packet} -> {[packet], reader}
        :eof -> {:halt, reader}
        {:error, reason} -> raise "Failed to read packet: #{reason}"
      end
    end,
    fn _reader -> :ok end
  )
end

def from_reader(%PcapNg{} = reader) do
  Stream.resource(
    fn -> reader end,
    fn reader ->
      case PcapNg.next_packet(reader) do
        {:ok, packet} -> {[packet], reader}
        :eof -> {:halt, reader}
        {:error, reason} -> raise "Failed to read packet: #{reason}"
      end
    end,
    fn _reader -> :ok end
  )
end
```

---

## Files Changed

### Modified

1. **`lib/pcap_file_ex/stream.ex`**
   - Added `PcapNg` to alias
   - Split `from_reader/1` into two clauses with pattern matching
   - Updated typespec to accept `Pcap.t() | PcapNg.t()`
   - Updated documentation

### Created

2. **`test/pcap_file_ex/stream_test.exs`**
   - 8 new tests covering both Pcap and PcapNg readers
   - Tests for pre-filtering with both formats
   - Tests for stream operations (take, map, filter)

---

## Testing

### New Tests Added

```elixir
describe "from_reader/1 with Pcap" do
  test "streams packets from Pcap reader"
  test "works with pre-filters on Pcap reader"
end

describe "from_reader/1 with PcapNg" do
  test "streams packets from PcapNg reader"
  test "works with pre-filters on PcapNg reader"
  test "handles combined filters on PcapNg reader"
end

describe "from_reader/1 with Elixir Stream operations" do
  test "can be used with Elixir Stream.take on Pcap"
  test "can be used with Elixir Stream.take on PcapNg"
  test "can be filtered and mapped on PcapNg"
end
```

### Test Results

```bash
$ mix test
Running ExUnit with seed: 128344, max_cases: 20
.....................................................................................................................
Finished in 0.1 seconds (0.1s async, 0.00s sync)
117 tests, 0 failures
```

**All 117 tests pass**, including 8 new tests for this fix.

---

## Verification

### Before Fix

```elixir
iex> {:ok, reader} = PcapFileEx.PcapNg.open("test.pcapng")
iex> PcapFileEx.Stream.from_reader(reader) |> Enum.take(1)
** (FunctionClauseError) no function clause matching...
```

### After Fix

```elixir
iex> {:ok, reader} = PcapFileEx.PcapNg.open("test.pcapng")
{:ok, %PcapFileEx.PcapNg{...}}

iex> filters = [PreFilter.protocol("tcp")]
[protocol: "tcp"]

iex> :ok = PcapFileEx.PcapNg.set_filter(reader, filters)
:ok

iex> packets = PcapFileEx.Stream.from_reader(reader) |> Enum.take(10)
[%PcapFileEx.Packet{...}, ...]  # ✓ Works!
```

---

## Documentation Updates

### Updated Files

1. **`docs/TROUBLESHOOTING.md`**
   - Added section on `FunctionClauseError` with Stream.from_reader
   - Documented the error, cause, and solution
   - Provided workaround for older versions

2. **`lib/pcap_file_ex/pre_filter.ex`**
   - Added note about file format auto-detection
   - Warned about "wrong magic number" errors

3. **`lib/pcap_file_ex/stream.ex`**
   - Updated docstring with both Pcap and PcapNg examples
   - Clarified that it works with both formats

---

## Usage Examples

### Pre-Filtering with PCAPNG (Now Works!)

```elixir
# Open PCAPNG file
{:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")

# Set pre-filter for TCP packets
filters = [
  PreFilter.protocol("tcp"),
  PreFilter.port_dest(80)
]
:ok = PcapFileEx.PcapNg.set_filter(reader, filters)

# Stream filtered packets (works now!)
packets =
  PcapFileEx.Stream.from_reader(reader)
  |> Enum.take(100)

PcapFileEx.PcapNg.close(reader)
```

### Combined Pre and Post Filtering

```elixir
{:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")

# Pre-filter (fast)
:ok = PcapFileEx.PcapNg.set_filter(reader, [
  PreFilter.protocol("tcp"),
  PreFilter.size_min(100)
])

# Post-filter for complex logic
http_requests =
  PcapFileEx.Stream.from_reader(reader)
  |> Enum.filter(fn packet ->
    :http in packet.protocols
  end)
  |> Enum.take(10)

PcapFileEx.PcapNg.close(reader)
```

---

## Backward Compatibility

✅ **Fully backward compatible**

- Existing code using `Pcap` readers continues to work
- New functionality added for `PcapNg` readers
- No breaking changes to API

---

## Related Issues

- Initial issue: User reported error when following documentation
- Root cause: Oversight when implementing pre-filtering feature
- Pre-filtering feature was implemented for both Pcap and PcapNg NIFs
- But `Stream.from_reader/1` wrapper only supported Pcap

---

## Lessons Learned

1. **Pattern matching on struct types** - Need separate clauses for different struct types
2. **Test both formats** - When adding features, ensure both PCAP and PCAPNG are tested
3. **Integration testing** - Testing NIFs alone isn't enough, need to test full API surface
4. **Documentation examples** - Should include examples for all supported formats

---

## Commit Message

```
Fix: Support PcapNg readers in Stream.from_reader/1

The Stream.from_reader/1 function only accepted Pcap readers,
causing FunctionClauseError when used with PcapNg readers.
This broke pre-filtering functionality for PCAPNG files.

Changes:
- Split from_reader/1 into two clauses with pattern matching
- Added support for PcapNg readers
- Updated typespec: Pcap.t() | PcapNg.t()
- Added 8 tests covering both formats
- Updated documentation

Impact:
- Pre-filtering now works correctly with PCAPNG files
- Fully backward compatible
- All 117 tests pass

Fixes issue discovered during documentation testing.
```

---

**Status:** ✅ Fixed and tested
**Impact:** Critical bug preventing PCAPNG pre-filtering
**Tests:** 117/117 passing
