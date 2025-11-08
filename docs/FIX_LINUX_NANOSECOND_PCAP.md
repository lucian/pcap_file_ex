# Fix Linux PCAP Nanosecond Precision Support

## ✅ RESOLVED

**Root Cause:** The Elixir validator code (`PcapFileEx.Validator` and `PcapFileEx`) was only checking for microsecond-precision magic numbers (`0xD4C3B2A1`, `0xA1B2C3D4`) and rejecting nanosecond-precision PCAP files (`0x4D3CB2A1`, `0xA1B23C4D`) before they reached the Rust NIF layer.

**Fix:** Added all four PCAP magic numbers to both validation modules:
- `lib/pcap_file_ex/validator.ex` - Lines 6-15
- `lib/pcap_file_ex.ex` - Lines 47-56

**Result:** Linux nanosecond PCAP files now parse successfully. All 15 comprehensive timestamp precision tests pass.

**Files Changed:**
- `lib/pcap_file_ex/validator.ex` - Added nanosecond magic number support
- `lib/pcap_file_ex.ex` - Added nanosecond magic number support
- `test/pcap_file_ex/timestamp_precision_test.exs` - New comprehensive test suite (15 tests)
- `README.md` - Added timestamp precision documentation section
- `CHANGELOG.md` - Documented fix under [Unreleased]

**Key Insight:** The underlying pcap-file Rust crate (`e60e2f9`) already supported all four magic numbers. The issue was purely in the Elixir validation layer preventing nanosecond files from being processed.

---

## Problem Statement (Original)

### Current Issue
Linux-generated PCAP files fail to parse with error:
```
Unknown file format (magic: <<77, 60, 178, 161>>)
```

### Magic Bytes Analysis
- `<<77, 60, 178, 161>>` = `0x4D3CB2A1` in hex
- This is **little-endian nanosecond-precision PCAP** format
- macOS dumpcap generates microsecond precision (`0xD4C3B2A1`) ✅ WORKS
- Linux dumpcap defaults to nanosecond precision (`0x4D3CB2A1`) ❌ FAILS
- Linux PCAPNG works correctly ✅ WORKS

### PCAP Magic Numbers (All Should Be Supported)
1. `0xD4C3B2A1` - Little-endian, **microsecond** precision
2. `0xA1B2C3D4` - Big-endian, **microsecond** precision
3. `0x4D3CB2A1` - Little-endian, **nanosecond** precision
4. `0xA1B23C4D` - Big-endian, **nanosecond** precision

### Key Constraints
- **NO timestamp conversion** - preserve original precision
- **Auto-detect** format from magic bytes
- Support **all four** magic number variants
- Work for both PCAP and PCAPNG formats

## Investigation Findings

### What We Know
1. ✅ pcap-file crate source code (commit `e60e2f9`) shows support for all four magic numbers
   - Location: `~/.cargo/git/checkouts/pcap-file-99367cb9ca57ae57/e60e2f9/src/pcap/header.rs` lines 55-58
2. ✅ Only `new_test.pcapng` is used in current tests (not `new_test.pcap`)
3. ✅ PCAPNG works fine on Linux (different code path)
4. ❌ PCAP format specifically fails on Linux with nanosecond precision
5. ❓ "Unknown file format" error source not found in simple grep

### What We Don't Know Yet
1. Where exactly does the "Unknown file format" error originate?
2. Is the compiled NIF using an old version of the crate?
3. Is there a feature flag or configuration needed?
4. Why does PCAPNG work but PCAP doesn't?

## Investigation Plan

### Phase 1: Locate Error Source

**Step 1.1: Search for error in pcap-file crate**
```bash
cd ~/.cargo/git/checkouts/pcap-file-99367cb9ca57ae57/e60e2f9
grep -r "Unknown file format" .
grep -r "magic" . | grep -i "unknown\|invalid\|error"
```

**Step 1.2: Check PcapReader::new implementation**
- Read `src/pcap/reader.rs` or `src/pcap/mod.rs`
- Find where magic number validation happens
- Verify all four magic numbers are in the match/if statement

**Step 1.3: Check for conditional compilation**
```bash
grep -r "cfg\|feature" src/pcap/
```
Look for feature flags that might disable nanosecond support.

### Phase 2: Add Debug Logging

**Modify `native/pcap_file_ex/src/pcap.rs` line 18:**
```rust
let reader = PcapReader::new(buf_reader).map_err(|e| {
    eprintln!("DEBUG: PcapReader::new failed: {:?}", e);
    eprintln!("DEBUG: Error details: {}", e);
    Error::Term(Box::new(format!("PCAP open failed: {:?}", e)))
})?;
```

This will print detailed error info to stderr when the NIF fails.

### Phase 3: Clean Rebuild Test

```bash
# Clean everything
cd native/pcap_file_ex
cargo clean
cd ../..
mix clean

# Force rebuild
mix compile --force

# Test with Linux PCAP
iex -S mix
```

Then in IEx:
```elixir
{:ok, reader} = PcapFileEx.Pcap.open("test/fixtures/linux_new_test.pcap")
```

Watch for DEBUG output in terminal.

### Phase 4: Compare PCAP vs PCAPNG Code Paths

**Examine differences:**
- `native/pcap_file_ex/src/pcap.rs` - PcapReader usage
- `native/pcap_file_ex/src/pcapng.rs` - PcapNgReader usage
- Check if they use different crate modules with different support levels

## Implementation Strategies

### Strategy A: Fix in Rust NIF (If crate is fine)
If pcap-file crate supports all formats but our NIF doesn't:
1. Update `native/pcap_file_ex/src/pcap.rs` to handle all magic numbers
2. Ensure proper error propagation
3. No code changes needed in crate

### Strategy B: Update Crate Version (If crate has bug)
If the commit `e60e2f9` doesn't actually support nanosecond:
1. Check latest commits in https://github.com/courvoif/pcap-file
2. Update `Cargo.toml` to use newer commit or tag
3. Test with updated version

### Strategy C: Custom Magic Number Handling (If needed)
If we need to pre-process the file:
1. Read first 4 bytes to detect magic number
2. Use appropriate reader based on detection
3. **Still preserve original timestamp precision** - no conversion!

### Strategy D: Feature Flag (If conditional compilation)
If nanosecond support is behind a feature flag:
1. Update `native/pcap_file_ex/Cargo.toml`
2. Add feature flag like `features = ["nanosecond"]` to pcap-file dependency
3. Rebuild and test

## Testing Strategy

### Test Files to Generate
1. **Microsecond PCAP** (macOS format)
   - Generated with: `dumpcap --time-precision usec`
   - Magic: `0xD4C3B2A1`

2. **Nanosecond PCAP** (Linux format)
   - Generated with: `dumpcap` (default on Linux)
   - Magic: `0x4D3CB2A1`
   - Already have: `test/fixtures/linux_new_test.pcap`

3. **Both PCAPNG formats** (already working)
   - Already have: `test/fixtures/linux_new_test.pcapng`
   - Already have: `test/fixtures/new_test.pcapng`

### Test Cases to Add

**File: `test/pcap_file_ex/timestamp_precision_test.exs`**
```elixir
defmodule PcapFileEx.TimestampPrecisionTest do
  use ExUnit.Case

  describe "PCAP microsecond precision" do
    test "parses macOS PCAP with microsecond timestamps" do
      # Magic: 0xD4C3B2A1
      {:ok, reader} = PcapFileEx.Pcap.open("test/fixtures/new_test.pcap")
      assert reader.header.magic_number == "0xD4C3B2A1"
      # Verify packets parse correctly
    end
  end

  describe "PCAP nanosecond precision" do
    test "parses Linux PCAP with nanosecond timestamps" do
      # Magic: 0x4D3CB2A1
      {:ok, reader} = PcapFileEx.Pcap.open("test/fixtures/linux_new_test.pcap")
      assert reader.header.magic_number == "0x4D3CB2A1"
      # Verify packets parse correctly
    end

    test "preserves nanosecond precision in timestamps" do
      {:ok, packets} = PcapFileEx.Pcap.read_all("test/fixtures/linux_new_test.pcap")
      # Verify timestamp_nanos field is populated
      assert Enum.all?(packets, fn p -> p.timestamp_nanos >= 0 end)
    end
  end

  describe "PCAPNG formats" do
    test "parses Linux PCAPNG" do
      {:ok, reader} = PcapFileEx.Pcapng.open("test/fixtures/linux_new_test.pcapng")
      # Should work (already does)
    end

    test "parses macOS PCAPNG" do
      {:ok, reader} = PcapFileEx.Pcapng.open("test/fixtures/new_test.pcapng")
      # Should work (already does)
    end
  end
end
```

### Validation Criteria
Each test file should:
- ✅ Open without errors
- ✅ Parse header correctly with right magic number
- ✅ Read all packets successfully
- ✅ Preserve timestamp precision (no conversion)
- ✅ Match expected packet count

## Implementation Checklist

### Investigation Phase
- [ ] Find exact error source in pcap-file crate
- [ ] Verify magic number support in crate code
- [ ] Check for feature flags or conditional compilation
- [ ] Add debug logging to NIF
- [ ] Clean rebuild and test

### Fix Phase
- [ ] Implement appropriate fix (Strategy A/B/C/D based on findings)
- [ ] Ensure all four magic numbers supported
- [ ] Verify timestamp precision preserved (no conversion)
- [ ] Test with both Linux and macOS PCAP files

### Testing Phase
- [ ] Create `test/pcap_file_ex/timestamp_precision_test.exs`
- [ ] Test microsecond PCAP (macOS format)
- [ ] Test nanosecond PCAP (Linux format)
- [ ] Test both PCAPNG formats
- [ ] Verify all tests pass on both macOS and Linux

### Documentation Phase
- [ ] Update README.md - document timestamp precision support
- [ ] Update CHANGELOG.md - record fix under [Unreleased]
- [ ] Update `docs/FIX_MULTI_OS_SUPPORT.md` - add findings
- [ ] Add code comments explaining magic number handling

## Expected Outcomes

### After Fix
1. **All PCAP formats work:**
   - ✅ macOS microsecond PCAP
   - ✅ Linux nanosecond PCAP
   - ✅ macOS PCAPNG
   - ✅ Linux PCAPNG

2. **Timestamp precision preserved:**
   - Microsecond files: `timestamp_nanos % 1000 == 0`
   - Nanosecond files: `timestamp_nanos` has full precision
   - NO automatic conversion between formats

3. **Comprehensive test coverage:**
   - Tests for all timestamp precision variants
   - Tests pass on both macOS and Linux
   - CI/CD can verify cross-platform compatibility

4. **Clear documentation:**
   - README explains timestamp precision handling
   - CHANGELOG records the fix
   - Code comments explain magic number detection

## Next Steps

1. **Start investigation** - Run Phase 1 steps to locate error source
2. **Add debug logging** - Modify pcap.rs to capture detailed errors
3. **Clean rebuild** - Ensure NIF uses latest crate code
4. **Test reproduction** - Verify we can reproduce the issue
5. **Implement fix** - Based on investigation findings
6. **Add tests** - Comprehensive coverage for all formats
7. **Update docs** - README, CHANGELOG, code comments

## Questions to Resolve

1. Does pcap-file commit `e60e2f9` actually support nanosecond PCAP?
2. Is there a feature flag we're missing?
3. Why does PCAPNG work but PCAP doesn't?
4. Is the NIF compiled against an old cached version?
5. Are there any platform-specific compilation differences?

## References

- pcap-file crate: https://github.com/courvoif/pcap-file
- Current commit: `e60e2f9b614812360fdf6909b90a8b05283adb05`
- PCAP spec: https://wiki.wireshark.org/Development/LibpcapFileFormat
- Magic number reference: libpcap documentation
