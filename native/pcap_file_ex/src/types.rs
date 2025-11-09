use pcap_file::pcap::{PcapHeader, PcapPacket};
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption, TsResolution as InterfaceTsResolution,
};
use pcap_file::PcapError;
use pcap_file::{DataLink, Endianness, TsResolution};
use rustler::NifMap;

#[derive(NifMap)]
pub struct HeaderMap {
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub datalink: String,
    pub ts_resolution: String,
    pub endianness: String,
}

#[derive(NifMap)]
pub struct PacketMap {
    pub timestamp_secs: u64,
    pub timestamp_nanos: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
    pub datalink: String,
    pub timestamp_resolution: Option<String>,
    pub interface_id: Option<u32>,
    pub interface: Option<InterfaceMap>,
}

#[derive(Clone, NifMap)]
pub struct InterfaceMap {
    pub id: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub linktype: String,
    pub snaplen: u32,
    pub timestamp_resolution: String,
    pub timestamp_offset_secs: u64,
}

pub fn pcap_header_to_map(header: &PcapHeader) -> HeaderMap {
    HeaderMap {
        version_major: header.version_major,
        version_minor: header.version_minor,
        snaplen: header.snaplen,
        datalink: datalink_to_string(&header.datalink),
        ts_resolution: ts_resolution_to_string(&header.ts_resolution),
        endianness: endianness_to_string(&header.endianness),
    }
}

pub fn pcap_packet_to_map(packet: PcapPacket, datalink: &DataLink) -> PacketMap {
    PacketMap {
        timestamp_secs: packet.timestamp.as_secs(),
        timestamp_nanos: packet.timestamp.subsec_nanos(),
        orig_len: packet.orig_len,
        data: packet.data.into_owned(),
        datalink: datalink_to_string(datalink),
        timestamp_resolution: None,
        interface_id: None,
        interface: None,
    }
}

pub(crate) fn datalink_to_string(datalink: &DataLink) -> String {
    match datalink {
        DataLink::ETHERNET => "ethernet".to_string(),
        DataLink::RAW => "raw".to_string(),
        DataLink::IPV4 => "ipv4".to_string(),
        DataLink::IPV6 => "ipv6".to_string(),
        DataLink::IEEE802_11 => "ieee802_11".to_string(),
        DataLink::LINUX_SLL => "linux_sll".to_string(),
        DataLink::LINUX_SLL2 => "linux_sll2".to_string(),
        DataLink::NULL => "null".to_string(),
        DataLink::LOOP => "loop".to_string(),
        DataLink::PPP => "ppp".to_string(),
        DataLink::Unknown(n) => format!("unknown_{}", n),
        _ => format!("{:?}", datalink).to_lowercase(),
    }
}

pub(crate) fn parse_datalink_string(datalink_str: &str) -> DataLink {
    match datalink_str.to_lowercase().as_str() {
        "ethernet" => DataLink::ETHERNET,
        "raw" => DataLink::RAW,
        "ipv4" => DataLink::IPV4,
        "ipv6" => DataLink::IPV6,
        "ieee802_11" => DataLink::IEEE802_11,
        "linux_sll" => DataLink::LINUX_SLL,
        "linux_sll2" => DataLink::LINUX_SLL2,
        "null" => DataLink::NULL,
        "loop" => DataLink::LOOP,
        "ppp" => DataLink::PPP,
        _ => {
            if let Some(num_str) = datalink_str.strip_prefix("unknown_") {
                if let Ok(num) = num_str.parse::<u32>() {
                    return DataLink::Unknown(num);
                }
            }
            DataLink::ETHERNET // Default fallback
        }
    }
}

fn ts_resolution_to_string(ts_resolution: &TsResolution) -> String {
    match ts_resolution {
        TsResolution::MicroSecond => "microsecond".to_string(),
        TsResolution::NanoSecond => "nanosecond".to_string(),
    }
}

fn interface_ts_resolution_to_string(ts_resolution: &InterfaceTsResolution) -> String {
    match ts_resolution.to_nano_secs() {
        1 => "nanosecond".to_string(),
        1_000 => "microsecond".to_string(),
        1_000_000 => "millisecond".to_string(),
        1_000_000_000 => "second".to_string(),
        nanos => format!("{}ns", nanos),
    }
}

fn endianness_to_string(endianness: &Endianness) -> String {
    match endianness {
        Endianness::Big => "big".to_string(),
        Endianness::Little => "little".to_string(),
    }
}

pub fn interface_to_map(
    interface_id: u32,
    interface: &InterfaceDescriptionBlock<'_>,
) -> Result<InterfaceMap, PcapError> {
    let mut name = None;
    let mut description = None;

    for option in &interface.options {
        match option {
            InterfaceDescriptionOption::IfName(value) => {
                name = Some(value.to_string());
            }
            InterfaceDescriptionOption::IfDescription(value) => {
                description = Some(value.to_string());
            }
            _ => {}
        }
    }

    let ts_resolution = interface.ts_resolution()?;
    let timestamp_resolution = interface_ts_resolution_to_string(&ts_resolution);
    let timestamp_offset_secs = interface.ts_offset().as_secs();

    Ok(InterfaceMap {
        id: interface_id,
        name,
        description,
        linktype: datalink_to_string(&interface.linktype),
        snaplen: interface.snaplen,
        timestamp_resolution,
        timestamp_offset_secs,
    })
}

// ============================================================================
// Reverse conversions (Elixir → Rust) for writer support
// ============================================================================

use rustler::Error;
use std::borrow::Cow;
use std::time::Duration;

/// Parse timestamp resolution string to TsResolution enum
fn parse_ts_resolution(ts_resolution_str: &str) -> Result<TsResolution, Error> {
    match ts_resolution_str.to_lowercase().as_str() {
        "microsecond" => Ok(TsResolution::MicroSecond),
        "nanosecond" => Ok(TsResolution::NanoSecond),
        _ => Err(Error::Term(Box::new(format!(
            "Invalid timestamp resolution: {}. Expected 'microsecond' or 'nanosecond'",
            ts_resolution_str
        )))),
    }
}

/// Parse endianness string to Endianness enum
fn parse_endianness(endianness_str: &str) -> Result<Endianness, Error> {
    match endianness_str.to_lowercase().as_str() {
        "big" => Ok(Endianness::Big),
        "little" => Ok(Endianness::Little),
        _ => Err(Error::Term(Box::new(format!(
            "Invalid endianness: {}. Expected 'big' or 'little'",
            endianness_str
        )))),
    }
}

/// Parse interface timestamp resolution string to InterfaceTsResolution
/// Returns the TsResolution byte value to be used with InterfaceTsResolution::new()
fn parse_interface_ts_resolution_byte(ts_resolution_str: &str) -> Result<u8, Error> {
    match ts_resolution_str.to_lowercase().as_str() {
        "nanosecond" => Ok(9),  // TsResolution::NANO
        "microsecond" => Ok(6), // TsResolution::MICRO
        "millisecond" => Ok(3), // TsResolution::MILLI
        "second" => Ok(0),      // TsResolution::SEC
        _ => {
            // Try parsing custom format like "100ns" - need to encode as byte
            // For now, default to microsecond for unknown formats
            Err(Error::Term(Box::new(format!(
                "Invalid interface timestamp resolution: {}. Expected 'nanosecond', 'microsecond', 'millisecond', or 'second'",
                ts_resolution_str
            ))))
        }
    }
}

/// Convert HeaderMap to PcapHeader
pub fn map_to_pcap_header(map: &HeaderMap) -> Result<PcapHeader, Error> {
    let datalink = parse_datalink_string(&map.datalink);
    let ts_resolution = parse_ts_resolution(&map.ts_resolution)?;
    let endianness = parse_endianness(&map.endianness)?;

    Ok(PcapHeader {
        version_major: map.version_major,
        version_minor: map.version_minor,
        ts_correction: 0, // Should always be 0 per PCAP spec
        ts_accuracy: 0,   // Should always be 0 per PCAP spec
        snaplen: map.snaplen,
        datalink,
        ts_resolution,
        endianness,
    })
}

/// Convert PacketMap to PcapPacket
pub fn map_to_pcap_packet(map: &PacketMap) -> Result<PcapPacket<'static>, Error> {
    let timestamp = Duration::new(map.timestamp_secs, map.timestamp_nanos);

    // Validate orig_len >= data.len()
    if map.orig_len < map.data.len() as u32 {
        return Err(Error::Term(Box::new(format!(
            "Invalid packet: orig_len ({}) must be >= data length ({})",
            map.orig_len,
            map.data.len()
        ))));
    }

    Ok(PcapPacket {
        timestamp,
        orig_len: map.orig_len,
        data: Cow::Owned(map.data.clone()),
    })
}

/// Convert InterfaceMap to InterfaceDescriptionBlock
pub fn map_to_interface_block(
    map: &InterfaceMap,
) -> Result<InterfaceDescriptionBlock<'static>, Error> {
    let linktype = parse_datalink_string(&map.linktype);
    let ts_resolution_byte = parse_interface_ts_resolution_byte(&map.timestamp_resolution)?;
    let ts_resolution = InterfaceTsResolution::new(ts_resolution_byte)
        .map_err(|e| Error::Term(Box::new(format!("Invalid timestamp resolution: {}", e))))?;

    let mut options = Vec::new();

    // Add interface name if provided
    if let Some(ref name) = map.name {
        options.push(InterfaceDescriptionOption::IfName(Cow::Owned(name.clone())));
    }

    // Add interface description if provided
    if let Some(ref description) = map.description {
        options.push(InterfaceDescriptionOption::IfDescription(Cow::Owned(
            description.clone(),
        )));
    }

    // Add timestamp resolution option
    options.push(InterfaceDescriptionOption::IfTsResol(
        ts_resolution.to_raw(),
    ));

    // Add timestamp offset if non-zero
    if map.timestamp_offset_secs > 0 {
        options.push(InterfaceDescriptionOption::IfTsOffset(
            map.timestamp_offset_secs, // Already u64, no cast needed
        ));
    }

    Ok(InterfaceDescriptionBlock {
        linktype,
        snaplen: map.snaplen,
        options, // No Cow wrapper needed - options is already Vec
    })
}
