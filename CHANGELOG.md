# Changelog

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
- PCAPNG interface metadata exposure (`PcapFileEx.PcapNg.interfaces/1`) and per-packet fields (`interface_id`, `interface`, `timestamp_resolution`).
- Test fixture script option `--interfaces ... --nanosecond` for generating multi-interface nanosecond captures; documentation on advanced capture workflows.
- Comprehensive documentation:
  - `docs/pre_filtering_feature_spec.md` - Complete feature specification
  - `docs/benchmarks.md` - Benchmark guide
  - `docs/epcap_comparison.md` - Comparison with epcap library
  - `docs/TROUBLESHOOTING.md` - User troubleshooting guide

### Changed
- `PcapFileEx.Stream.from_reader/1` now supports both `Pcap` and `PcapNg` readers (previously only supported Pcap)
- `PcapFileEx.Packet` struct docs/examples updated with interface metadata and resolution info.
- Capture script defaults now auto-name multi-interface nanosecond captures (`sample_multi_nanosecond.pcapng`).
- Documented automatic decoder attachment and the `decode: false` opt-out in README and User Guide.
- Updated benchmarks with pre-filtering vs post-filtering comparisons

### Fixed
- `Stream.from_reader/1` now correctly handles PcapNg readers (previously caused FunctionClauseError)
