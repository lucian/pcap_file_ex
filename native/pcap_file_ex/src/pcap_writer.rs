use crate::types::{map_to_pcap_header, map_to_pcap_packet, HeaderMap, PacketMap};
use pcap_file::pcap::PcapWriter;
use rustler::{Error, ResourceArc};
use std::fs::File;
use std::io::BufWriter;
use std::sync::Mutex;

pub struct PcapWriterResource {
    writer: Mutex<PcapWriter<BufWriter<File>>>,
}

#[rustler::nif]
pub fn pcap_writer_open(
    path: String,
    header_map: HeaderMap,
) -> Result<ResourceArc<PcapWriterResource>, Error> {
    // Convert header map to PCAP header
    let header = map_to_pcap_header(&header_map)?;

    // Create file with 64KB buffer for optimal throughput
    let file = File::create(&path)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create file: {}", e))))?;
    let buf_writer = BufWriter::with_capacity(64 * 1024, file);

    // Create PCAP writer
    let writer = PcapWriter::with_header(buf_writer, header)
        .map_err(|e| Error::Term(Box::new(format!("Failed to create PCAP writer: {}", e))))?;

    Ok(ResourceArc::new(PcapWriterResource {
        writer: Mutex::new(writer),
    }))
}

#[rustler::nif]
pub fn pcap_writer_append(_path: String) -> Result<ResourceArc<PcapWriterResource>, Error> {
    // PCAP append mode is not supported by the pcap-file crate
    // The crate always writes a header when creating a writer
    Err(Error::Term(Box::new(
        "PCAP append mode not supported. The pcap-file crate does not support appending to existing PCAP files. \
         Create a new file instead, or use PCAPNG format which will support append in a future version.".to_string()
    )))
}

#[rustler::nif]
pub fn pcap_writer_write_packet(
    resource: ResourceArc<PcapWriterResource>,
    packet_map: PacketMap,
) -> Result<rustler::types::atom::Atom, Error> {
    // Convert packet map to PCAP packet
    let packet = map_to_pcap_packet(&packet_map)?;

    // Write packet
    let mut writer = resource.writer.lock().unwrap();
    writer
        .write_packet(&packet)
        .map_err(|e| Error::Term(Box::new(format!("Failed to write packet: {}", e))))?;

    Ok(rustler::types::atom::ok())
}

#[rustler::nif]
pub fn pcap_writer_close(
    resource: ResourceArc<PcapWriterResource>,
) -> Result<rustler::types::atom::Atom, Error> {
    // Flush and close the writer
    let mut writer = resource.writer.lock().unwrap();
    writer
        .flush()
        .map_err(|e| Error::Term(Box::new(format!("Failed to flush writer: {}", e))))?;

    // Note: File is automatically closed when BufWriter is dropped
    Ok(rustler::types::atom::ok())
}
