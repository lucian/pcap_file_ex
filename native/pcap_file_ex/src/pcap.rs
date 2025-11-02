use crate::types::{pcap_header_to_map, pcap_packet_to_map, HeaderMap, PacketMap};
use pcap_file::pcap::PcapReader;
use rustler::{Error, ResourceArc};
use std::fs::File;
use std::io::BufReader;
use std::sync::Mutex;

pub struct PcapReaderResource {
    reader: Mutex<PcapReader<BufReader<File>>>,
}

#[rustler::nif]
pub fn pcap_open(path: String) -> Result<ResourceArc<PcapReaderResource>, Error> {
    let file = File::open(&path).map_err(|e| Error::Term(Box::new(e.to_string())))?;
    let buf_reader = BufReader::new(file);
    let reader = PcapReader::new(buf_reader).map_err(|e| Error::Term(Box::new(e.to_string())))?;

    Ok(ResourceArc::new(PcapReaderResource {
        reader: Mutex::new(reader),
    }))
}

#[rustler::nif]
pub fn pcap_close(_resource: ResourceArc<PcapReaderResource>) -> rustler::types::atom::Atom {
    rustler::types::atom::ok()
}

#[rustler::nif]
pub fn pcap_get_header(resource: ResourceArc<PcapReaderResource>) -> Result<HeaderMap, Error> {
    let reader = resource.reader.lock().unwrap();
    let header = reader.header();
    Ok(pcap_header_to_map(&header))
}

#[rustler::nif]
pub fn pcap_next_packet(resource: ResourceArc<PcapReaderResource>) -> Result<Option<PacketMap>, Error> {
    let mut reader = resource.reader.lock().unwrap();

    match reader.next_packet() {
        Some(Ok(packet)) => Ok(Some(pcap_packet_to_map(packet))),
        Some(Err(e)) => Err(Error::Term(Box::new(e.to_string()))),
        None => Ok(None),
    }
}
