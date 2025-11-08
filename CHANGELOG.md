# Changelog

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
- `Stream.from_reader/1` now correctly handles PcapNg readers (previously caused FunctionClauseError)
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
