# Changelog

## [Unreleased]
- TBD

## [0.1.0] - 2025-11-03
### Added
- Wireshark-style display filter engine (`PcapFileEx.DisplayFilter`) with inline pipeline helper and reusable compiled filters.
- Dynamic field integration with decoder registry so decoded payloads contribute filterable fields automatically.
- `%PcapFileEx.Endpoint{}` struct for `src`/`dst`, plus `Packet.endpoint_to_string/1` helper.
- Helpers `Packet.decode_registered!/1` and `Packet.attach_decoded/1` to persist decoded payloads on packet structs.
- Documentation recipes covering endpoint pattern matching, streaming with decoded payloads, custom decoder field registration, and display filters.
- Display-filter test suite and expanded decoder registry tests.

### Changed
- `PcapFileEx.Packet` now caches decoded layers/payloads, records the full protocol stack, and exposes a `decoded` map keyed by protocol atoms.
- `PcapFileEx.DecoderRegistry` default HTTP decoder now advertises HTTP request/response fields.
- README, user guide, and plan updated to document the new filtering and decoder features.

### Fixed
- Avoid redundant `:pkt.decode/2` calls by reusing cached layers/payload.

## [0.0.4] - 2025-11-03
### Added
- Structured endpoints: `src`/`dst` now surfaced as `%PcapFileEx.Endpoint{ip, port}` for easier pattern matching.
- Additional optimizer pass over packet metadata extraction and decoder API usage.

### Changed
- Cached packet metadata reused across decoder calls, reducing repeated processing.
- Documentation examples updated to show endpoint helpers and decoded payload usage.

## [0.0.3] - 2025-11-02
### Added
- Decoder registry with HTTP default, enabling application payload decoding and caching (`Packet.decode_http/1`, registry APIs).
- Documentation on extending the decoder registry and storing decoded payloads on packets.

## [0.0.2] - 2025-11-02
### Added
- Packet filtering helpers (size, time, content) and protocol-aware filtering (`Filter.by_protocol/2`).
- HTTP payload decoding with automatic loopback handling and `pkt` integration helpers.
- UDP protocol tests and fixtures to validate loopback, payload, and decoder behaviour.

### Fixed
- Loopback interface handling (strip pseudo-header, map to `ipv4`/`ipv6`).
- Protocol metadata (`protocols`, `protocol`) captured for each packet.

## [0.0.1] - 2025-11-02
### Added
- Initial mix project structure.
- Core PCAP/PCAPNG reading support with automatic format detection and streaming API.
- Packet and header structs, validation helpers, and initial documentation.

