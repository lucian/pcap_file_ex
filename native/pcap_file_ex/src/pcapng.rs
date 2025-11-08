use crate::filter::{FilterContext, PacketFilter};
use crate::types::{interface_to_map, InterfaceMap, PacketMap};
use pcap_file::pcapng::blocks::Block;
use pcap_file::pcapng::PcapNgReader;
use rustler::{Error, ResourceArc};
use std::fs::File;
use std::io::BufReader;
use std::sync::Mutex;

pub struct PcapNgReaderResource {
    reader: Mutex<PcapNgReader<BufReader<File>>>,
    filter: Mutex<Option<FilterContext>>,
}

#[rustler::nif]
pub fn pcapng_open(path: String) -> Result<ResourceArc<PcapNgReaderResource>, Error> {
    let file = File::open(&path).map_err(|e| Error::Term(Box::new(e.to_string())))?;
    let buf_reader = BufReader::new(file);
    let reader = PcapNgReader::new(buf_reader).map_err(|e| Error::Term(Box::new(e.to_string())))?;

    Ok(ResourceArc::new(PcapNgReaderResource {
        reader: Mutex::new(reader),
        filter: Mutex::new(None),
    }))
}

#[rustler::nif]
pub fn pcapng_close(_resource: ResourceArc<PcapNgReaderResource>) -> rustler::types::atom::Atom {
    rustler::types::atom::ok()
}

#[rustler::nif]
pub fn pcapng_interfaces(
    resource: ResourceArc<PcapNgReaderResource>,
) -> Result<Vec<InterfaceMap>, Error> {
    let reader = resource.reader.lock().unwrap();
    let mut interfaces = Vec::with_capacity(reader.interfaces().len());

    for (idx, interface) in reader.interfaces().iter().enumerate() {
        let interface_map = interface_to_map(idx as u32, interface)
            .map_err(|e| Error::Term(Box::new(e.to_string())))?;
        interfaces.push(interface_map);
    }

    Ok(interfaces)
}

#[rustler::nif]
pub fn pcapng_next_packet(
    resource: ResourceArc<PcapNgReaderResource>,
) -> Result<Option<PacketMap>, Error> {
    let mut reader = resource.reader.lock().unwrap();
    let filter = resource.filter.lock().unwrap();

    // Iterate through blocks to find packet blocks
    loop {
        let next = reader.next_block_and_state();

        match next {
            Some(Ok((Block::EnhancedPacket(packet_block), state))) => {
                let interface = state
                    .interfaces()
                    .get(packet_block.interface_id as usize)
                    .ok_or_else(|| {
                        Error::Term(Box::new(
                            "Missing interface description for packet".to_string(),
                        ))
                    })?
                    .clone();

                let interface_map = interface_to_map(packet_block.interface_id, &interface)
                    .map_err(|e| Error::Term(Box::new(e.to_string())))?;
                let datalink = interface_map.linktype.clone();
                let timestamp_resolution = Some(interface_map.timestamp_resolution.clone());

                // Parse datalink for filtering
                let datalink_parsed = crate::types::parse_datalink_string(&datalink);
                let timestamp_secs = packet_block.timestamp.as_secs();
                let orig_len = packet_block.original_len;
                let data = packet_block.data.as_ref();

                // Check if packet matches filter
                if let Some(ref filter_ctx) = *filter {
                    if !filter_ctx.matches(data, &datalink_parsed, orig_len, timestamp_secs) {
                        continue; // Skip this packet, try next one
                    }
                }

                let packet_map = PacketMap {
                    timestamp_secs,
                    timestamp_nanos: packet_block.timestamp.subsec_nanos(),
                    orig_len,
                    data: packet_block.data.into_owned(),
                    datalink,
                    timestamp_resolution,
                    interface_id: Some(packet_block.interface_id),
                    interface: Some(interface_map),
                };

                return Ok(Some(packet_map));
            }
            Some(Ok((_block, _state))) => continue,
            Some(Err(e)) => return Err(Error::Term(Box::new(e.to_string()))),
            None => return Ok(None),
        }
    }
}

#[rustler::nif]
pub fn pcapng_set_filter(
    resource: ResourceArc<PcapNgReaderResource>,
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
pub fn pcapng_clear_filter(
    resource: ResourceArc<PcapNgReaderResource>,
) -> Result<rustler::types::atom::Atom, Error> {
    let mut filter = resource.filter.lock().unwrap();
    *filter = None;
    Ok(rustler::types::atom::ok())
}
