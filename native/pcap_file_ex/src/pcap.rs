use crate::filter::{FilterContext, PacketFilter};
use crate::types::{pcap_header_to_map, pcap_packet_to_map, HeaderMap, PacketMap};
use pcap_file::pcap::PcapReader;
use rustler::{Error, ResourceArc};
use std::fs::File;
use std::io::BufReader;
use std::sync::Mutex;

pub struct PcapReaderResource {
    reader: Mutex<PcapReader<BufReader<File>>>,
    filter: Mutex<Option<FilterContext>>,
}

#[rustler::nif]
pub fn pcap_open(path: String) -> Result<ResourceArc<PcapReaderResource>, Error> {
    let file = File::open(&path).map_err(|e| Error::Term(Box::new(e.to_string())))?;
    let buf_reader = BufReader::new(file);
    let reader = PcapReader::new(buf_reader).map_err(|e| Error::Term(Box::new(e.to_string())))?;

    Ok(ResourceArc::new(PcapReaderResource {
        reader: Mutex::new(reader),
        filter: Mutex::new(None),
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
    let filter = resource.filter.lock().unwrap();
    let datalink = reader.header().datalink.clone();

    loop {
        match reader.next_packet() {
            Some(Ok(packet)) => {
                let timestamp_secs = packet.timestamp.as_secs();
                let orig_len = packet.orig_len;
                let data = packet.data.as_ref();

                // Check if packet matches filter
                if let Some(ref filter_ctx) = *filter {
                    if !filter_ctx.matches(data, &datalink, orig_len, timestamp_secs) {
                        continue; // Skip this packet, try next one
                    }
                }

                return Ok(Some(pcap_packet_to_map(packet, &datalink)));
            }
            Some(Err(e)) => return Err(Error::Term(Box::new(e.to_string()))),
            None => return Ok(None),
        }
    }
}

#[rustler::nif]
pub fn pcap_set_filter(
    resource: ResourceArc<PcapReaderResource>,
    filters: Vec<PacketFilter>,
) -> Result<rustler::types::atom::Atom, Error> {
    let mut filter = resource.filter.lock().unwrap();

    if filters.is_empty() {
        *filter = None;
    } else {
        *filter = Some(FilterContext::new(filters));
    }

    Ok(rustler::types::atom::ok())
}

#[rustler::nif]
pub fn pcap_clear_filter(
    resource: ResourceArc<PcapReaderResource>,
) -> Result<rustler::types::atom::Atom, Error> {
    let mut filter = resource.filter.lock().unwrap();
    *filter = None;
    Ok(rustler::types::atom::ok())
}
