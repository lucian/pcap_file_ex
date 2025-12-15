# Changelog

## [0.5.2-dev] - Unreleased

### Added
- **Automatic Content-Type based body decoding for HTTP/2 exchanges**
  - New `PcapFileEx.HTTP.Content` module for generic content decoding
  - Supports JSON, text (UTF-8/ISO-8859-1), multipart/*, binary fallback
  - Request and response bodies automatically decoded based on Content-Type header
  - New `decoded_body` field in HTTP/2 Exchange request/response structs
  - New `:decode_content` option for `HTTP2.analyze/2` and `analyze_segments/2` (default: true)
  - Multipart/related support with recursive part decoding
  - Comprehensive test suite: 42 unit tests + 21 property tests
- **HTTP/2 Cleartext (h2c) Analysis** - Reconstruct HTTP/2 request/response exchanges from PCAP files
  - New `PcapFileEx.HTTP2` module with public API
    - `HTTP2.analyze/2` - Analyze PCAP file for HTTP/2 exchanges (options: `:port`, `:decode_content`)
    - `HTTP2.analyze_segments/2` - Analyze pre-parsed TCP segments (options: `:decode_content`)
    - `HTTP2.http2?/1` - Detect HTTP/2 connection preface
    - `HTTP2.connection_preface/0` - Get preface string
  - New submodules for HTTP/2 protocol handling:
    - `HTTP2.Frame` - Frame parsing with padding and priority handling
    - `HTTP2.FrameBuffer` - Cross-packet frame reassembly
    - `HTTP2.Headers` - Pseudo/regular header separation with trailer support
    - `HTTP2.StreamState` - Per-stream state with CONTINUATION handling
    - `HTTP2.Connection` - Dual HPACK tables per direction with SETTINGS
    - `HTTP2.Analyzer` - Main stream reconstruction algorithm
    - `HTTP2.Exchange` - Complete request/response pair struct
    - `HTTP2.IncompleteExchange` - Partial exchange with reason tracking
  - Returns complete and incomplete exchanges separately
  - Supports mid-connection captures (with HPACK limitations)
  - HPACK header decompression via `hpax` library
  - TCP sequence number ordering and retransmission detection
  - Handles RST_STREAM, GOAWAY, and truncated streams
  - **Limitations**: Cleartext only (no TLS), prior-knowledge h2c only (no HTTP/1.1 Upgrade)
  - Comprehensive test suite:
    - Unit tests for Frame, FrameBuffer, Headers modules
    - Property-based tests (22 properties) for frame parsing and headers
    - Integration tests (16 tests) including real PCAP file analysis
  - New dependency: `{:hpax, "~> 1.0"}` for HPACK decompression
  - Documentation: `usage-rules/http2.md` guide with patterns and best practices

### Changed
- Updated dependencies:
  - bandit 1.8.0 → 1.9.0
  - ex_doc 0.39.1 → 0.39.3
  - rustler_precompiled 0.8.3 → 0.8.4
  - plug 1.18.1 → 1.19.1 (transitive)
  - thousand_island 1.4.2 → 1.4.3 (transitive)
  - castore 1.0.16 → 1.0.17 (transitive)

## [0.5.1] - 2025-12-01
- dependencies updates

## [0.5.0] - 2025-11-19

⚠️ **BREAKING CHANGES** - Decoder Registry API Enhanced with Context Passing

### Added
- **Context passing in decoder registry** - Matchers can now return context to decoders
  - New API: Matchers return `{:match, context}` instead of `true`
  - New API: Decoders accept `(context, payload)` instead of just `(payload)`
  - Eliminates need for `Process.put` workarounds (thread-safe, no race conditions)
  - More efficient: decode once in matcher, use cached result in decoder
  - Pure data flow makes testing easier
  - Backward compatible via runtime detection (old API still works with deprecation warnings)

### Changed
- **Decoder registration now accepts both old (arity-1) and new (arity-2) decoders**
- **HTTP decoder optimized** to decode once instead of twice (no visible API change)
  - Decodes payload in matcher, caches result as context
  - Decoder uses cached result instead of re-decoding
  - Performance improvement: 50% reduction in HTTP decode time for matched packets

### Deprecated
- **Legacy decoder API (arity-1 decoders)** will be removed in v1.0.0
  - Runtime deprecation warnings emitted when registering old-style decoders
  - Migration guide: See "Migration Guide" section below

### Migration Guide

**Old API (still works with warnings):**
```elixir
DecoderRegistry.register(%{
  matcher: fn layers, payload -> my_protocol?(layers) end,  # Returns boolean
  decoder: fn payload -> decode(payload) end,  # Arity-1
})
```

**New API (recommended):**
```elixir
DecoderRegistry.register(%{
  matcher: fn layers, payload ->
    if my_protocol?(layers) do
      {:match, extract_context(layers)}  # Return context
    else
      false
    end
  end,
  decoder: fn context, payload -> decode(payload, context) end,  # Arity-2
})
```

### Benefits

- ✅ **Thread-safe** - No `Process.put` or shared state
- ✅ **No race conditions** - Explicit context passing
- ✅ **More efficient** - Decode once, not twice
- ✅ **Easier to test** - Pure functions with explicit dependencies
- ✅ **Clearer intent** - Context requirements are explicit in type signatures

### Implementation Details

- **Updated modules:**
  - `lib/pcap_file_ex/decoder_registry.ex` - New type definitions, backward compatibility wrappers
  - `lib/pcap_file_ex/packet.ex` - Updated invocation logic to pass context through

- **Testing:** (372 tests → 393 tests, +21 tests)
  - New unit tests for context passing, backward compatibility, error handling
  - New integration tests with real PCAP files
  - New property-based tests for invariants
  - All existing tests continue to pass

- **Documentation:**
  - Updated module documentation with new API examples
  - Added deprecation warnings for old API usage
  - CHANGELOG entry with migration guide

### Technical Notes

- Based on spec `specs/20251119-decoder-registry-context-passing.md`
- Backward compatibility achieved via runtime arity detection and wrapper functions
- Deprecation timeline: v0.5.0 (warning) → v1.0.0 (removal)

## [0.4.0] - 2025-11-09

**MAJOR FEATURE** - PCAP/PCAPNG Writer API (MVP)

### Added
- **Writer API** - Create PCAP and PCAPNG files from packets
  - New `PcapFileEx.PcapWriter` module for PCAP file creation
    - `PcapWriter.open/2` - Create new PCAP files with header
    - `PcapWriter.write_packet/2` - Write individual packets
    - `PcapWriter.write_all/3` - Convenience batch writer
    - `PcapWriter.close/1` - Explicit close with flush
  - New `PcapFileEx.PcapNgWriter` module for PCAPNG file creation
    - `PcapNgWriter.open/1` - Create new PCAPNG files
    - `PcapNgWriter.write_interface/2` - Register interfaces
    - `PcapNgWriter.write_packet/2` - Write packets with interface tracking
    - `PcapNgWriter.write_all/4` - Batch write with auto-interface registration
    - `PcapNgWriter.close/1` - Explicit close with flush
  - 64KB buffered writes for optimal throughput
  - Full nanosecond timestamp precision preservation
  - Thread-safe Rust NIF implementation with Mutex-protected resources

- **High-Level Convenience API**
  - `PcapFileEx.write/4` - Format auto-detection from file extension
  - `PcapFileEx.write!/4` - Bang variant that raises on errors
  - `PcapFileEx.copy/3` - Copy/convert PCAP files with format conversion
  - `PcapFileEx.export_filtered/4` - Filter and export packets to new file
  - `:on_error` option (`:halt` or `:skip`) for handling corrupt packets during copy/export
  - Automatic PCAP ↔ PCAPNG format conversion with interface preservation

- **Timestamp Utilities**
  - New `PcapFileEx.TimestampShift` module for timestamp manipulation
  - `TimestampShift.shift_all/2` - Shift timestamps by nanosecond offset
  - `TimestampShift.normalize_to_epoch/1` - Normalize first packet to Unix epoch
  - Useful for anonymization and reproducible test files

- **Data Structure Enhancements**
  - `Header.to_map/1` - Convert header to NIF-compatible map
  - `Packet.to_map/1` - Convert packet to NIF-compatible map
  - `Interface.to_map/1` - Convert interface to NIF-compatible map
  - Bidirectional type conversions (Elixir ↔ Rust)

### Limitations (MVP)
- **Append mode not supported**
  - PCAP append: Not supported by upstream pcap-file crate (clear error returned)
  - PCAPNG append: Not implemented in MVP (requires block scanning/truncation)
  - Both formats return clear error messages explaining limitations
  - Create new files or use format conversion as workaround
  - Future versions will add PCAPNG append support

### Implementation Details
- **Rust NIFs** (native/pcap_file_ex/src/)
  - `pcap_writer.rs` - PCAP writer with 4 NIFs (open, write, close, append stub)
  - `pcapng_writer.rs` - PCAPNG writer with 5 NIFs (open, write_interface, write, close, append stub)
  - `types.rs` - Reverse type conversions (Elixir → Rust) for all data structures
  - Rustler Resources for thread-safe writer state management
  - Interface tracking in Rust NIF layer for PCAPNG validation

- **Testing**
  - New `test/pcap_file_ex/writer_smoke_test.exs` with 6 tests
  - Tests cover: PCAP write, PCAPNG write, copy, filter/export, append limitations
  - All tests pass with round-trip validation (write → read → verify)

### Changed
- Module aliases in `PcapFileEx` to avoid naming conflicts with `Elixir.Stream`
- Updated `Native` module with 9 new NIF stubs for writer functions

### Technical Notes
- Based on spec `specs/20251109-pcap-writer-api.md` (v1.3)
- Streaming architecture: O(1) memory for files of any size
- Error propagation: Consistent `{:ok, result} | {:error, reason}` pattern
- Format detection: Auto-detect from file extension (.pcap vs .pcapng)
- Interface metadata: Derived from source headers during PCAP→PCAPNG conversion

## [0.3.0] - 2025-11-09

**MAJOR FEATURE** - Multi-File PCAP Timeline Merge

### Added
- **Multi-File Merge API** - Chronologically merge multiple PCAP/PCAPNG files
  - New `PcapFileEx.Merge` module with comprehensive merge capabilities
  - `Merge.stream/2` - Creates lazy chronologically-sorted packet stream from multiple files
  - `Merge.stream!/2` - Bang variant that raises on errors
  - `Merge.count/1` - Fast total packet count across multiple files
  - `Merge.validate_clocks/1` - Clock synchronization validation with drift detection
  - Supports mixed PCAP and PCAPNG files in single merge operation
  - Memory-efficient: O(N files) memory usage via min-heap algorithm
  - Performance: O(M log N) time complexity (M packets, N files)
  - Comprehensive test coverage: 352 tests (including 8 new property tests)

- **Nanosecond-Precision Chronological Ordering**
  - Uses `Timestamp.compare/2` for accurate chronological merging
  - Preserves microsecond and nanosecond precision from source files
  - Deterministic ordering for packets with identical timestamps
  - Stable sort using file index and packet index as tiebreakers

- **PCAPNG Interface ID Remapping** (Critical for Multi-File PCAPNG Merges)
  - Automatic global interface ID assignment prevents collisions
  - Maintains invariant: `packet.interface_id == packet.interface.id`
  - New `PcapFileEx.Merge.InterfaceMapper` module handles remapping logic
  - Clones `Interface` struct to update nested `id` field correctly
  - Per-file interface scanning and global ID allocation

- **Source Annotation** (`:annotate_source` option)
  - Track packet origins with rich metadata
  - Metadata includes: `:source_file`, `:file_index`, `:packet_index`
  - PCAPNG-specific metadata: `:original_interface_id`, `:remapped_interface_id`
  - Enables packet provenance tracking and debugging
  - Stream format: `{packet, metadata}` tuples when enabled

- **Flexible Error Handling** (`:on_error` option)
  - `:halt` - Stop streaming on first error (default, safe behavior)
  - `:skip` - Skip corrupt packets, emit `{:skipped_packet, meta}` markers
  - `:collect` - Wrap all items in result tuples: `{:ok, packet}` or `{:error, meta}`
  - Works seamlessly with annotation (nested tuples: `{:ok, {packet, meta}}`)
  - Error metadata includes: `:reason`, `:source_file`, `:packet_index`

- **Clock Validation and Drift Detection**
  - `validate_clocks/1` checks timestamp alignment across files
  - Returns `:ok` with stats or `{:error, :excessive_drift, stats}`
  - Drift threshold: 10 seconds (configurable)
  - Per-file statistics: min/max timestamps, packet counts
  - Helps identify unsynchronized capture clocks

- **Priority Queue Implementation**
  - New `PcapFileEx.Merge.Heap` module for min-heap operations
  - Optimized for streaming merge with O(log N) push/pop
  - Efficient chronological packet ordering
  - Custom comparison using `Timestamp.compare/2`

- **Comprehensive Property-Based Tests**
  - 8 new property tests in `test/property_test/merge_property_test.exs`
  - Properties tested:
    - Chronological ordering invariant
    - Total packet count preservation
    - Source annotation completeness
    - Deterministic ordering for identical timestamps
    - Error mode behavior (`:collect`, `:skip`, `:halt`)
    - PCAPNG interface ID invariant
    - Interface ID annotation completeness
  - Environment-aware: 100 iterations locally, 1000 in CI

### Changed
- **Code Review Remediation** - Two rounds of thorough review and fixes
  - Round 1 (5 findings): Fixed 2 CRITICAL, 2 HIGH, 1 MEDIUM priority issues
    - Fixed premature resource cleanup (CRITICAL)
    - Added explicit file validation (CRITICAL)
    - Fixed NIF error propagation (HIGH)
    - Added comprehensive error metadata (HIGH)
    - Enhanced property test coverage (MEDIUM)
  - Round 2 (2 findings): Fixed remaining invariant and metadata issues
    - Fixed PCAPNG interface invariant breach (CRITICAL)
    - Added `remapped_interface_id` to metadata (HIGH)
    - Added regression tests for both issues

- **Test Suite Enhancements**
  - Removed unused `@sample2_pcapng` module attribute
  - Added "PCAPNG interface remapping maintains invariant" property test
  - Added "PCAPNG annotation includes both interface IDs" property test
  - Updated existing annotation test to assert both interface ID fields

### Fixed
- **Interface ID Remapping** (CRITICAL, Code Review Round 2)
  - `InterfaceMapper.remap_packet/3` now updates both fields:
    - Updates `packet.interface_id` (top-level field)
    - Clones and updates `packet.interface.id` (nested struct field)
  - Maintains invariant: `packet.interface_id == packet.interface.id`
  - Prevents packets from carrying original interface IDs in merged streams

- **Metadata Completeness** (HIGH, Code Review Round 2)
  - Annotation now includes both `:original_interface_id` and `:remapped_interface_id`
  - API contract fully met for PCAPNG multi-file merges
  - Users can track both original source interface and global merged interface

### Documentation
- Complete feature specification: `specs/20251109-multi-file-pcap-timeline-merge.md` (v1.4)
  - 85+ pages covering design, implementation, and code review
  - Includes two rounds of code review findings and fixes
  - Comprehensive examples and edge case documentation
- See README.md for usage examples and integration guide
- See `usage-rules/merging.md` for detailed merge patterns and best practices

## [0.2.1] - 2025-11-09

- improve CI pipeline - add dialyzer, credo, package audit
- optimize rust NIFs build process

## [0.2.0] - 2025-11-09

⚠️ **BREAKING CHANGES** - Stream API now follows Elixir conventions

### Added
- **Safe Stream API** - New tuple-returning functions following Elixir conventions
  - `PcapFileEx.stream/1` and `stream/2` now return `{:ok, stream} | {:error, reason}` instead of raising
  - `PcapFileEx.Stream.packets/1` now returns `{:ok, stream} | {:error, reason}`
  - `PcapFileEx.Stream.from_reader/1` now returns `{:ok, stream}` for consistency
  - Added bang variants for convenience (old behavior):
    - `stream!/1`, `stream!/2` - raises on error
    - `PcapFileEx.Stream.packets!/1` - raises on error
    - `PcapFileEx.Stream.from_reader!/1` - raises on error
  - Comprehensive migration guide in module documentation
- **Unified Format Detection** - New `PcapFileEx.Format` module
  - Single source of truth for PCAP/PCAPNG format detection
  - Eliminates 70+ lines of duplicate code between `PcapFileEx` and `PcapFileEx.Validator`
  - `Format.detect/1` function for file format detection
- **CI Version Synchronization** - Prevents version drift
  - New CI job verifies `mix.exs` and `Cargo.toml` versions match
  - Rejects `-dev` suffix on release tags to prevent accidental dev releases
  - Ensures Elixir and Rust packages stay synchronized
- **CONTRIBUTING.md** - Contributor onboarding guide
  - Development setup instructions (Elixir, Rust, Git)
  - Tidewave MCP integration guide for development
  - Rust development workflow (linting, formatting, testing)
  - Testing guidelines (example-based and property-based)
  - Code quality standards and PR guidelines
- **Tidewave MCP Integration** for enhanced development experience
  - Live code evaluation in project context via `mcp__tidewave__project_eval`
  - Module/function documentation access via `mcp__tidewave__get_docs`
  - Source location lookup via `mcp__tidewave__get_source_location`
  - Application log inspection via `mcp__tidewave__get_logs`
  - Dependency documentation search via `mcp__tidewave__search_package_docs`
  - Configured in `.mcp.json` for seamless integration with AI coding assistants
  - Particularly useful with Claude Code for live introspection and testing
  - Includes two Mix aliases for starting the MCP server:
    - `mix tidewave` - Background server (no IEx shell)
    - `iex -S mix tidewave-iex` - Interactive IEx shell with MCP server
- **Nanosecond Timestamp Precision Support** (v0.2.0)
  - New `PcapFileEx.Timestamp` module for nanosecond-precision timestamps
  - All packets now include both `timestamp` (DateTime, microsecond precision) and `timestamp_precise` (Timestamp, nanosecond precision)
  - Zero breaking changes - existing code using `packet.timestamp` continues to work
  - Full API for timestamp operations: `new/2`, `to_unix_nanos/1`, `to_datetime/1`, `from_datetime/2`, `compare/2`, `diff/2`
  - Implements String.Chars and Inspect protocols for pretty printing
  - Ideal for merging packets from multiple files chronologically with nanosecond accuracy
  - Comprehensive test suite with 80+ test cases
- **Property-Based Testing with StreamData**
  - 94 new property tests covering timestamps, packets, filters, streams, and decoding
  - Comprehensive generators for all core data types (timestamps, packets, filters, etc.)
  - Environment-aware configuration: 100 test runs locally, 1000 in CI
  - Tests edge cases automatically: boundary timestamps, truncated packets, filter compositions
  - Validates invariants: timestamp ordering, packet consistency, filter count properties
  - Zero performance impact: tests run in ~0.9 seconds (total suite: ~1.2s)
  - In-memory testing for fast, deterministic results
  - See `test/property_test/` for 5 test files and `test/support/generators.ex` for reusable generators

### Changed
- **BREAKING**: `PcapFileEx.stream/1` and `stream/2` signature changed from returning `Enumerable.t()` to `{:ok, Enumerable.t()} | {:error, String.t()}`
- **BREAKING**: `PcapFileEx.Stream.packets/1` now returns `{:ok, stream} | {:error, reason}`
- **BREAKING**: `PcapFileEx.Stream.from_reader/1` now returns `{:ok, stream}` instead of bare stream
- **Error Handling**: `Pcap.read_all/1` and `PcapNg.read_all/1` now return `{:error, reason}` on packet parsing errors instead of silently dropping errors
  - Prevents corrupted files or decoder regressions from appearing as "short captures"
  - Properly closes file handles even on error
- **CI Improvements**:
  - Fixed formatter condition to use `startsWith(matrix.elixir_version, '1.19')` - formatter now actually runs!
  - Removed duplicate `rust-ci.yml` workflow (Rust linting consolidated in main CI)
- **Documentation Updates**:
  - All README.md examples updated to v0.2.0 API (shows both safe and bang patterns)
  - All usage-rules documentation updated (~90 code blocks across 6 files)
  - Comprehensive migration guide in stream module documentation
- **Roadmap Reorganized** in README.md:
  - Split into "Completed Features" and "Planned Features" sections
  - Added 5 new planned features from CODEX review
- Improved documentation
- Updated `PcapFileEx.Packet` struct to include `timestamp_precise` field
- Modified timestamp conversion to preserve nanosecond precision when possible
- Added `test/support` to elixirc_paths for test environment (supports property test generators)
- Version bumped to 0.2.0 in both `mix.exs` and `native/pcap_file_ex/Cargo.toml`

### Fixed
- **Format Detection**: Eliminated duplicate magic number detection logic
  - Previously duplicated between `PcapFileEx` and `PcapFileEx.Validator`
  - Now uses single `PcapFileEx.Format.detect/1` function
- **CI Formatter**: Formatter check was never running due to incorrect version match (`'1.19'` vs `'1.19.1'`)
- **Error Propagation**: Packet parsing errors in `read_all/1` are now properly surfaced instead of being silently dropped
- **Stats Module**: Updated to use `stream!/1` to maintain backward compatibility in internal calls

### Removed
- Duplicate `.github/workflows/rust-ci.yml` - Rust linting now handled exclusively in main CI workflow

## [0.1.5] - 2025-11-08

### Added
- **Expanded platform support with CPU variants** (inspired by [elixir-explorer/explorer](https://github.com/elixir-explorer/explorer))
  - Added FreeBSD support (`x86_64-unknown-freebsd`)
  - Implemented CPU capability detection for automatic legacy artifact selection
  - Added variant system for x86_64 platforms (Linux, Windows, FreeBSD)
  - Now shipping **11 precompiled NIF artifacts** (up from 6):
    - `aarch64-apple-darwin` (macOS ARM)
    - `aarch64-unknown-linux-gnu` (Linux ARM)
    - `x86_64-apple-darwin` (macOS Intel)
    - `x86_64-unknown-linux-gnu` (Linux Intel/AMD)
    - `x86_64-unknown-linux-gnu--legacy_cpu` (Linux Intel/AMD, legacy CPUs)
    - `x86_64-pc-windows-msvc` (Windows MSVC)
    - `x86_64-pc-windows-msvc--legacy_cpu` (Windows MSVC, legacy CPUs)
    - `x86_64-pc-windows-gnu` (Windows GCC)
    - `x86_64-pc-windows-gnu--legacy_cpu` (Windows GCC, legacy CPUs)
    - `x86_64-unknown-freebsd` (FreeBSD)
    - `x86_64-unknown-freebsd--legacy_cpu` (FreeBSD, legacy CPUs)
- **Automatic CPU detection** - Linux x86_64 systems automatically select the appropriate binary variant based on CPU capabilities (AVX, FMA, SSE4.2, etc.)
- **Manual legacy override** - Set `PCAP_FILE_EX_USE_LEGACY_ARTIFACTS=1` to force legacy CPU variants on any platform
- Compile-time CPU capability detection for automatic binary selection

### Changed
- Updated NIF configuration to match elixir-explorer/explorer best practices
- Reorganized target list alphabetically for better maintainability
- Enhanced checksum file to include all platform variants

### Fixed
- Legacy CPU support for systems without AVX/FMA instruction sets
- Checksum generation now covers all 11 artifacts instead of only 6

## [0.1.4] - 2025-11-08
- Improve CI/CD pipeline

## [0.1.3] - 2025-11-08

### Fixed
- **CRITICAL**: Include checksum files in Hex package to enable precompiled NIF downloads
  - Added `checksum-*.exs` to package files list in mix.exs
  - Users can now install from Hex without requiring Rust compiler
  - Previously, checksums were only on GitHub releases but not in Hex package
  - This caused `RuntimeError: the precompiled NIF file does not exist in the checksum file`
  - Follows elixir-explorer/explorer best practices for rustler_precompiled

## [0.1.2] - 2025-11-08

### Added
- **LLM-friendly usage rules**: Comprehensive documentation for AI coding assistants
  - Main `usage-rules.md` with decision trees and common patterns
  - Detailed sub-guides: `usage-rules/performance.md`, `filtering.md`, `http.md`, `formats.md`, `examples.md`
  - Guidance on format auto-detection, resource management, and filtering strategies
  - Performance optimization recommendations (PreFilter for 10-100x speedup)
  - Common mistakes section with wrong vs correct patterns
  - Complete working examples for real-world scenarios
- Usage rules integrated with HEX package for distribution to dependencies
- README section on AI-assisted development with integration instructions

### Changed
- Package files list now includes `usage-rules.md` and `usage-rules/` directory for HEX distribution
- Added "Usage Rules" link to package metadata
- Updated version requirements to Elixir 1.19.2 and Erlang/OTP 28.1.1
- Updated Rust toolchain to 1.91.0 in GitHub Actions

### Fixed
- **Major GitHub Actions workflow improvements** (based on elixir-explorer/explorer best practices)
  - **CRITICAL**: Switched from manual cargo builds to `rustler-precompiled-action@v1.1.4`
    - Fixes artifact naming to match RustlerPrecompiled expectations: `pcap_file_ex-nif-2.15-{target}.tar.gz`
    - Previously used incompatible naming: `libpcap_file_ex-{target}.so` (raw files)
    - Ensures precompiled binary downloads work correctly
  - **Compatibility**: Changed Linux builds from Ubuntu 24.04 to 22.04
    - Better glibc compatibility (2.35 vs 2.39)
    - Precompiled binaries work on more Linux distributions
  - **Performance**: Added Rust caching with `Swatinem/rust-cache@v2`
    - Expected 5-10x faster builds on subsequent runs
    - Target-specific cache keys for optimal reuse
  - **Security**: Added build attestation with `actions/attest-build-provenance@v1`
    - Cryptographic proof of build provenance
    - Enhanced supply chain security
  - **Configuration**: Added explicit NIF version ("2.15") in Native module
    - Required for OTP 28 compatibility
    - Enables RustlerPrecompiled to match artifacts to OTP versions
  - **Permissions**: Added workflow permissions (contents, id-token, attestations)
  - Updated runner images:
    - Linux: `ubuntu-22.04` (was ubuntu-24.04, ImageOS: ubuntu22)
    - Windows: `windows-2022` (was windows-2019, ImageOS: win22)
    - macOS: `macos-13` (Intel x86_64) and `macos-14` (ARM aarch64)
  - Upgraded actions to v4 (`checkout@v4`, `upload-artifact@v4`, `download-artifact@v4`)
  - Updated Elixir to 1.19.2 and OTP to 28.1.1 in all jobs
  - Pinned Rust version to 1.91.0 for reproducible builds

## [0.1.1] - 2025-11-08

### Added
- **HEX package publication support**: Added comprehensive metadata for publishing to hex.pm
  - MIT License file
  - Package metadata (description, maintainers, links, files list)
  - ExDoc configuration with README and CHANGELOG
  - Rustler precompiled support with GitHub Actions workflow for cross-platform NIF builds
  - Mix clean task that removes Rust build artifacts, priv/ directory, and generated test fixtures
- Comprehensive timestamp precision tests (`test/pcap_file_ex/timestamp_precision_test.exs`) covering microsecond and nanosecond PCAP formats, PCAPNG compatibility, and cross-platform support (15 test cases).

### Fixed
- **PCAP nanosecond precision support**: Fixed Linux PCAP file parsing failure. The Elixir validator was only checking for microsecond-precision magic numbers (0xD4C3B2A1, 0xA1B2C3D4) and rejecting nanosecond-precision files (0x4D3CB2A1, 0xA1B23C4D) before they reached the Rust NIF. Added support for all four PCAP magic number variants in both `PcapFileEx.Validator` and `PcapFileEx` modules. The underlying pcap-file Rust crate already supported all formats.
- **Cross-platform compatibility**: Linux dumpcap defaults to nanosecond precision while macOS uses microsecond precision. Both formats are now fully supported with automatic detection and no timestamp conversion.

### Changed
- Updated .gitignore to exclude build artifacts (native/target/, priv/), generated test fixtures, and AI configuration files
- Synced version numbers across mix.exs and Cargo.toml
- Updated GitHub repository URLs from placeholder to actual repository

## [69e8fdc] - 2025-11-03
### Added
- Wireshark-style display filter engine (`PcapFileEx.DisplayFilter`) with inline `filter/2`, reusable `compile/1` + `run/2`, and parser support for boolean/relational operators.
- Dynamic field integration with the decoder registry so decoded payloads expose filterable fields automatically.
- `%PcapFileEx.Endpoint{}` usage throughout docs and helpers demonstrating endpoint pattern matching.
- Display filter tests covering HTTP and transport-layer queries, plus documentation recipes.

### Changed
- Packets now carry cached decoded payloads, layers, and endpoint structs while display filters reuse cached data.
- Decoder registry default HTTP decoder publishes request/response field descriptors.

## [5a036d5] - 2025-11-03
### Added
- `%PcapFileEx.Endpoint{ip, port}` struct and `Packet.endpoint_to_string/1` helper to simplify matching/filtering on endpoints.
- Updated tests and docs to reflect structured endpoints.

### Changed
- Packet construction caches decoded layers/payload for reuse (`decode_registered/1`, `attach_decoded/1`).
- API usage streamlined with attach/decode helpers.

## [7e47baa] - 2025-11-03
### Added
- Decoder caching helpers (`decode_registered!/1`, `attach_decoded/1`) and endpoint metadata improvements.

### Changed
- Optimized packet metadata extraction and decoder integration; cleaned up docs to show updated API usage.

## [2ec8193] - 2025-11-02
### Added
- Decoder registry with default HTTP decoder, enabling protocol-aware payload decoding and caching.
- Documentation describing decoder registration workflow and storing decoded payloads on packets.

## [31d7e85] - 2025-11-02
### Added
- UDP fixtures/tests ensuring loopback handling, protocol metadata, and decoder integration behave correctly.

## [11066d2] - 2025-11-02
### Added
- HTTP decoding helpers tied to `pkt` library and automatic loopback normalization.
- Protocol-aware filtering (`Filter.by_protocol/2`) and metadata enrichment (`protocols`, `protocol`).

### Fixed
- Loopback interface handling; ensure `ipv4`/`ipv6` classification and pseudo-header stripping.

## [be90371] - 2025-11-02
### Added
- Initial filtering DSL (size/time/content) with composable helpers.

## [5c205f7] - 2025-11-02
### Added
- Core PCAP and PCAPNG format support with automatic detection, streaming API, packet/header structs, and docs/tests for both formats.

## [7152143] - 2025-11-02
### Added
- Initial mix project skeleton.

## [Unreleased]
### Added
- **BPF-style pre-filtering** in Rust layer for high-performance packet filtering (10-100x speedup)
  - Filter by IP address (exact match and CIDR ranges)
  - Filter by port (exact match and ranges)
  - Filter by protocol (TCP, UDP, ICMP, IPv4, IPv6)
  - Filter by packet size (min/max/range)
  - Filter by timestamp (Unix seconds)
  - Logical operators (AND, OR, NOT)
  - `PcapFileEx.PreFilter` module with type-safe filter constructors
  - `set_filter/2` and `clear_filter/1` for both PCAP and PCAPNG readers
- **Streaming statistics** via `PcapFileEx.Stats.compute_streaming/1`
  - Constant memory usage for huge files (no size limit)
  - Can be combined with filtering and other stream operations
  - Produces identical results to `compute/1` but never loads all packets into memory
  - Accepts both file paths and streams
- PCAPNG interface metadata exposure (`PcapFileEx.PcapNg.interfaces/1`) and per-packet fields (`interface_id`, `interface`, `timestamp_resolution`).
- Test fixture script option `--interfaces ... --nanosecond` for generating multi-interface nanosecond captures; documentation on advanced capture workflows.
- Comprehensive documentation:
  - `docs/pre_filtering_feature_spec.md` - Complete feature specification
  - `docs/benchmarks.md` - Benchmark guide
  - `docs/epcap_comparison.md` - Comparison with epcap library
  - `docs/TROUBLESHOOTING.md` - User troubleshooting guide
  - `docs/SECURITY_ETF_FIX.md` - ETF security fix documentation

### Changed
- `PcapFileEx.Stream.from_reader/1` now supports both `Pcap` and `PcapNg` readers (previously only supported Pcap)
- `PcapFileEx.Packet` struct docs/examples updated with interface metadata and resolution info.
- Capture script defaults now auto-name multi-interface nanosecond captures (`sample_multi_nanosecond.pcapng`).
- Documented automatic decoder attachment and the `decode: false` opt-out in README and User Guide.
- Updated benchmarks with pre-filtering vs post-filtering comparisons

### Fixed
- `PcapFileEx.Stream.from_reader/1` now correctly handles PcapNg readers (previously caused FunctionClauseError)
- **Security:** ETF (Erlang Term Format) decoding now uses `:safe` flag to prevent code execution from malicious PCAP files
- **Cross-platform:** Test fixture generation scripts now work on both macOS and Linux
  - Auto-detect loopback interface (`lo` on Linux, `lo0` on macOS)
  - Permission checking for dumpcap with platform-specific guidance
  - Port checking uses `ss` on Linux (faster), falls back to `lsof` on macOS
  - Interface validation before capture starts
  - Tests auto-generate missing fixtures on fresh clones

### Added (Cross-Platform Support)
- Mix task `mix test.fixtures` for manual fixture generation
- Automatic fixture generation in test setup (test/test_helper.exs)
- Comprehensive development setup documentation with platform-specific instructions:
  - macOS: Homebrew installation and ChmodBPF setup
  - Ubuntu/Debian: apt-get installation and wireshark group configuration
  - Fedora/RHEL: dnf installation instructions
  - Arch Linux: pacman installation instructions
- Troubleshooting guide covering:
  - Interface detection errors ("No such device")
  - Permission denied errors with platform-specific solutions
  - dumpcap setup verification
  - Fixture generation debugging
- Enhanced test/fixtures/README.md with platform compatibility matrix
- Smart interface detection and validation in capture scripts
- Platform detection (`uname -s`) for Darwin (macOS) vs Linux

### Improved
- Test fixture scripts work seamlessly on both macOS and Linux without modification
- Better error messages for missing tools or permission issues
- Graceful degradation when dumpcap is unavailable (tests skip with clear message)
- Documentation covers both Git dependency and future Hex publishing scenarios
