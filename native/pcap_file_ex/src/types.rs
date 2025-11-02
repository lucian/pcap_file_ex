use pcap_file::pcap::{PcapHeader, PcapPacket};
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

fn ts_resolution_to_string(ts_resolution: &TsResolution) -> String {
    match ts_resolution {
        TsResolution::MicroSecond => "microsecond".to_string(),
        TsResolution::NanoSecond => "nanosecond".to_string(),
    }
}

fn endianness_to_string(endianness: &Endianness) -> String {
    match endianness {
        Endianness::Big => "big".to_string(),
        Endianness::Little => "little".to_string(),
    }
}
