use crate::types::{map_to_interface_block, InterfaceMap, PacketMap};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::Endianness;
use rustler::{Error, NifMap, ResourceArc};
use std::borrow::Cow;
use std::fs::File;
use std::io::BufWriter;
use std::sync::Mutex;

pub struct PcapNgWriterResource {
    writer: Mutex<Option<PcapNgWriter<BufWriter<File>>>>,
    interfaces: Mutex<Vec<InterfaceDescriptionBlock<'static>>>,
}

#[derive(NifMap)]
pub struct SectionMap {
    pub interfaces_count: u32,
}

#[rustler::nif]
pub fn pcapng_writer_open(
    path: String,
    endianness_str: String,
) -> Result<ResourceArc<PcapNgWriterResource>, Error> {
    // Parse endianness
    let endianness = match endianness_str.to_lowercase().as_str() {
        "big" => Endianness::Big,
        "little" => Endianness::Little,
        _ => {
            return Err(Error::Term(Box::new(format!(
                "Invalid endianness: {}. Expected 'big' or 'little'",
                endianness_str
            ))))
        }
    };

    // Create file with 64KB buffer for optimal throughput
    let file = File::create(&path)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create file: {}", e))))?;
    let buf_writer = BufWriter::with_capacity(64 * 1024, file);

    // Create PCAPNG writer
    let writer = PcapNgWriter::with_endianness(buf_writer, endianness)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create PCAPNG writer: {}", e))))?;

    Ok(ResourceArc::new(PcapNgWriterResource {
        writer: Mutex::new(Some(writer)),
        interfaces: Mutex::new(Vec::new()),
    }))
}

#[rustler::nif]
pub fn pcapng_writer_append(
    _path: String,
) -> Result<(ResourceArc<PcapNgWriterResource>, SectionMap), Error> {
    // PCAPNG append mode not implemented in MVP
    // Will be added in future version after investigating pcap-file crate append support
    Err(Error::Term(Box::new(
        "PCAPNG append mode not yet implemented. This feature requires scanning for the last packet block \
         and truncating trailing metadata blocks. It will be added in a future version. \
         Create a new file instead for now.".to_string()
    )))
}

#[rustler::nif]
pub fn pcapng_writer_write_interface(
    resource: ResourceArc<PcapNgWriterResource>,
    interface_map: InterfaceMap,
) -> Result<u32, Error> {
    // Convert interface map to interface block
    let interface_block = map_to_interface_block(&interface_map)?;

    // Get interface ID (next index)
    let mut interfaces = resource.interfaces.lock().unwrap();
    let interface_id = interfaces.len() as u32;

    // Write interface block
    let mut writer_opt = resource.writer.lock().unwrap();
    let writer = writer_opt
        .as_mut()
        .ok_or_else(|| Error::Term(Box::new("Writer already closed".to_string())))?;

    writer
        .write_block(&pcap_file::pcapng::Block::InterfaceDescription(
            interface_block.clone(),
        ))
        .map_err(|e| Error::Term(Box::new(format!("Failed to write interface block: {}", e))))?;

    // Track interface
    interfaces.push(interface_block);

    Ok(interface_id)
}

#[rustler::nif]
pub fn pcapng_writer_write_packet(
    resource: ResourceArc<PcapNgWriterResource>,
    packet_map: PacketMap,
) -> Result<rustler::types::atom::Atom, Error> {
    // Validate interface_id
    let interface_id = packet_map.interface_id.ok_or_else(|| {
        Error::Term(Box::new(
            "Packet must have interface_id set for PCAPNG format".to_string(),
        ))
    })?;

    let interfaces = resource.interfaces.lock().unwrap();
    if interface_id as usize >= interfaces.len() {
        return Err(Error::Term(Box::new(format!(
            "Invalid interface_id: {}. Only {} interfaces registered. Call write_interface first.",
            interface_id,
            interfaces.len()
        ))));
    }

    // Create enhanced packet block
    // Timestamp is a Duration (std::time::Duration)
    use std::time::Duration;
    let enhanced_packet = EnhancedPacketBlock {
        interface_id,
        timestamp: Duration::new(packet_map.timestamp_secs, packet_map.timestamp_nanos),
        original_len: packet_map.orig_len,
        data: Cow::Owned(packet_map.data),
        options: vec![],
    };

    // Write packet
    let mut writer_opt = resource.writer.lock().unwrap();
    let writer = writer_opt
        .as_mut()
        .ok_or_else(|| Error::Term(Box::new("Writer already closed".to_string())))?;

    writer
        .write_block(&pcap_file::pcapng::Block::EnhancedPacket(enhanced_packet))
        .map_err(|e| Error::Term(Box::new(format!("Failed to write packet block: {}", e))))?;

    Ok(rustler::types::atom::ok())
}

#[rustler::nif]
pub fn pcapng_writer_close(
    resource: ResourceArc<PcapNgWriterResource>,
) -> Result<rustler::types::atom::Atom, Error> {
    // Take ownership of the writer to ensure it's dropped and flushed
    // The take() moves the writer out of the Option, and dropping it will
    // trigger BufWriter's Drop which flushes the buffer
    let mut writer_opt = resource.writer.lock().unwrap();
    let _writer = writer_opt.take();
    // Writer is dropped here when it goes out of scope
    // BufWriter::drop() flushes the buffer to the file
    drop(writer_opt);
    drop(_writer);

    Ok(rustler::types::atom::ok())
}
