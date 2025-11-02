use crate::types::PacketMap;
use pcap_file::pcapng::PcapNgReader;
use rustler::{Error, ResourceArc};
use std::fs::File;
use std::io::BufReader;
use std::sync::Mutex;

pub struct PcapNgReaderResource {
    reader: Mutex<PcapNgReader<BufReader<File>>>,
}

#[rustler::nif]
pub fn pcapng_open(path: String) -> Result<ResourceArc<PcapNgReaderResource>, Error> {
    let file = File::open(&path).map_err(|e| Error::Term(Box::new(e.to_string())))?;
    let buf_reader = BufReader::new(file);
    let reader = PcapNgReader::new(buf_reader).map_err(|e| Error::Term(Box::new(e.to_string())))?;

    Ok(ResourceArc::new(PcapNgReaderResource {
        reader: Mutex::new(reader),
    }))
}

#[rustler::nif]
pub fn pcapng_close(_resource: ResourceArc<PcapNgReaderResource>) -> rustler::types::atom::Atom {
    rustler::types::atom::ok()
}

#[rustler::nif]
pub fn pcapng_next_packet(
    resource: ResourceArc<PcapNgReaderResource>,
) -> Result<Option<PacketMap>, Error> {
    let mut reader = resource.reader.lock().unwrap();

    // Iterate through blocks to find packet blocks
    loop {
        match reader.next_block() {
            Some(Ok(block)) => {
                // Try to convert block to enhanced packet
                if let Some(packet_block) = block.into_enhanced_packet() {
                    // Directly construct PacketMap from EnhancedPacketBlock fields
                    let packet_map = PacketMap {
                        timestamp_secs: packet_block.timestamp.as_secs(),
                        timestamp_nanos: packet_block.timestamp.subsec_nanos(),
                        orig_len: packet_block.original_len,
                        data: packet_block.data.into_owned(),
                    };

                    return Ok(Some(packet_map));
                }

                // If not enhanced packet, continue to next block
                // (we'll skip other block types for now)
                continue;
            }
            Some(Err(e)) => return Err(Error::Term(Box::new(e.to_string()))),
            None => return Ok(None),
        }
    }
}
