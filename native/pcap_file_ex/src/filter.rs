use etherparse::err::packet::SliceError;
use etherparse::err::Layer;
use etherparse::{LenSource, NetSlice, SlicedPacket, TransportSlice};
use ipnetwork::IpNetwork;
use pcap_file::DataLink;
use rustler::NifTaggedEnum;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, NifTaggedEnum)]
pub enum PacketFilter {
    IpSource(String),
    IpDest(String),
    IpSourceCidr(String),
    IpDestCidr(String),
    PortSource(u16),
    PortDest(u16),
    PortSourceRange(u16, u16),
    PortDestRange(u16, u16),
    Protocol(String),
    SizeMin(u32),
    SizeMax(u32),
    SizeRange(u32, u32),
    TimestampMin(u64),
    TimestampMax(u64),
    And(Vec<PacketFilter>),
    Or(Vec<PacketFilter>),
    Not(Box<PacketFilter>),
}

pub struct FilterContext {
    filters: Vec<PacketFilter>,
}

impl FilterContext {
    pub fn new(filters: Vec<PacketFilter>) -> Self {
        FilterContext { filters }
    }

    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    pub fn matches(
        &self,
        packet_data: &[u8],
        datalink: &DataLink,
        orig_len: u32,
        timestamp_secs: u64,
    ) -> bool {
        if self.is_empty() {
            return true;
        }

        self.filters.iter().all(|filter| {
            self.evaluate_filter(filter, packet_data, datalink, orig_len, timestamp_secs)
        })
    }

    fn evaluate_filter(
        &self,
        filter: &PacketFilter,
        packet_data: &[u8],
        datalink: &DataLink,
        orig_len: u32,
        timestamp_secs: u64,
    ) -> bool {
        match filter {
            // Size filters (don't require parsing)
            PacketFilter::SizeMin(min) => orig_len >= *min,
            PacketFilter::SizeMax(max) => orig_len <= *max,
            PacketFilter::SizeRange(min, max) => orig_len >= *min && orig_len <= *max,

            // Timestamp filters
            PacketFilter::TimestampMin(min) => timestamp_secs >= *min,
            PacketFilter::TimestampMax(max) => timestamp_secs <= *max,

            // Logical operators
            PacketFilter::And(filters) => filters
                .iter()
                .all(|f| self.evaluate_filter(f, packet_data, datalink, orig_len, timestamp_secs)),
            PacketFilter::Or(filters) => filters
                .iter()
                .any(|f| self.evaluate_filter(f, packet_data, datalink, orig_len, timestamp_secs)),
            PacketFilter::Not(filter) => {
                !self.evaluate_filter(filter, packet_data, datalink, orig_len, timestamp_secs)
            }

            // Packet content filters (require parsing)
            _ => self.evaluate_content_filter(filter, packet_data, datalink),
        }
    }

    fn evaluate_content_filter(
        &self,
        filter: &PacketFilter,
        packet_data: &[u8],
        datalink: &DataLink,
    ) -> bool {
        // Parse the packet based on datalink type
        let parsed = match self.parse_packet(packet_data, datalink) {
            Ok(p) => p,
            Err(_) => return false, // If we can't parse, filter out
        };

        match filter {
            PacketFilter::IpSource(ip_str) => {
                if let Ok(target_ip) = IpAddr::from_str(ip_str) {
                    self.check_source_ip(&parsed, &target_ip)
                } else {
                    false
                }
            }
            PacketFilter::IpDest(ip_str) => {
                if let Ok(target_ip) = IpAddr::from_str(ip_str) {
                    self.check_dest_ip(&parsed, &target_ip)
                } else {
                    false
                }
            }
            PacketFilter::IpSourceCidr(cidr_str) => {
                if let Ok(network) = IpNetwork::from_str(cidr_str) {
                    self.check_source_network(&parsed, &network)
                } else {
                    false
                }
            }
            PacketFilter::IpDestCidr(cidr_str) => {
                if let Ok(network) = IpNetwork::from_str(cidr_str) {
                    self.check_dest_network(&parsed, &network)
                } else {
                    false
                }
            }
            PacketFilter::Protocol(proto_str) => self.check_protocol(&parsed, proto_str),
            PacketFilter::PortSource(port) => self.check_source_port(&parsed, *port),
            PacketFilter::PortDest(port) => self.check_dest_port(&parsed, *port),
            PacketFilter::PortSourceRange(min, max) => {
                self.check_source_port_range(&parsed, *min, *max)
            }
            PacketFilter::PortDestRange(min, max) => {
                self.check_dest_port_range(&parsed, *min, *max)
            }
            _ => false,
        }
    }

    fn parse_packet<'a>(
        &self,
        packet_data: &'a [u8],
        datalink: &DataLink,
    ) -> Result<SlicedPacket<'a>, SliceError> {
        match datalink {
            DataLink::ETHERNET => SlicedPacket::from_ethernet(packet_data),
            DataLink::IPV4 | DataLink::RAW => SlicedPacket::from_ip(packet_data),
            DataLink::NULL | DataLink::LOOP => {
                // Loopback: skip 4 bytes family header, then parse as IP
                if packet_data.len() >= 4 {
                    SlicedPacket::from_ip(&packet_data[4..])
                } else {
                    Err(SliceError::Len(etherparse::err::LenError {
                        required_len: 4,
                        len: packet_data.len(),
                        len_source: LenSource::Slice,
                        layer: Layer::Ipv4Header,
                        layer_start_offset: 4,
                    }))
                }
            }
            _ => SlicedPacket::from_ethernet(packet_data), // Default to Ethernet
        }
    }

    fn check_source_ip(&self, parsed: &SlicedPacket, target_ip: &IpAddr) -> bool {
        match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().source_addr()) == *target_ip,
            Some(NetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().source_addr()) == *target_ip,
            Some(NetSlice::Arp(_)) => false, // ARP packets don't have IP addresses
            None => false,
        }
    }

    fn check_dest_ip(&self, parsed: &SlicedPacket, target_ip: &IpAddr) -> bool {
        match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                IpAddr::V4(ipv4.header().destination_addr()) == *target_ip
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                IpAddr::V6(ipv6.header().destination_addr()) == *target_ip
            }
            Some(NetSlice::Arp(_)) => false, // ARP packets don't have IP addresses
            None => false,
        }
    }

    fn check_source_network(&self, parsed: &SlicedPacket, network: &IpNetwork) -> bool {
        match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let ip = IpAddr::V4(ipv4.header().source_addr());
                network.contains(ip)
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                let ip = IpAddr::V6(ipv6.header().source_addr());
                network.contains(ip)
            }
            Some(NetSlice::Arp(_)) => false, // ARP packets don't have IP addresses
            None => false,
        }
    }

    fn check_dest_network(&self, parsed: &SlicedPacket, network: &IpNetwork) -> bool {
        match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let ip = IpAddr::V4(ipv4.header().destination_addr());
                network.contains(ip)
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                let ip = IpAddr::V6(ipv6.header().destination_addr());
                network.contains(ip)
            }
            Some(NetSlice::Arp(_)) => false, // ARP packets don't have IP addresses
            None => false,
        }
    }

    fn check_protocol(&self, parsed: &SlicedPacket, proto_str: &str) -> bool {
        match proto_str.to_lowercase().as_str() {
            "tcp" => matches!(parsed.transport, Some(TransportSlice::Tcp(_))),
            "udp" => matches!(parsed.transport, Some(TransportSlice::Udp(_))),
            "icmp" => matches!(parsed.transport, Some(TransportSlice::Icmpv4(_))),
            "icmpv6" => matches!(parsed.transport, Some(TransportSlice::Icmpv6(_))),
            "ipv4" => matches!(parsed.net, Some(NetSlice::Ipv4(_))),
            "ipv6" => matches!(parsed.net, Some(NetSlice::Ipv6(_))),
            _ => false,
        }
    }

    fn check_source_port(&self, parsed: &SlicedPacket, port: u16) -> bool {
        match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp.source_port() == port,
            Some(TransportSlice::Udp(udp)) => udp.source_port() == port,
            _ => false,
        }
    }

    fn check_dest_port(&self, parsed: &SlicedPacket, port: u16) -> bool {
        match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp.destination_port() == port,
            Some(TransportSlice::Udp(udp)) => udp.destination_port() == port,
            _ => false,
        }
    }

    fn check_source_port_range(&self, parsed: &SlicedPacket, min: u16, max: u16) -> bool {
        match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let port = tcp.source_port();
                port >= min && port <= max
            }
            Some(TransportSlice::Udp(udp)) => {
                let port = udp.source_port();
                port >= min && port <= max
            }
            _ => false,
        }
    }

    fn check_dest_port_range(&self, parsed: &SlicedPacket, min: u16, max: u16) -> bool {
        match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let port = tcp.destination_port();
                port >= min && port <= max
            }
            Some(TransportSlice::Udp(udp)) => {
                let port = udp.destination_port();
                port >= min && port <= max
            }
            _ => false,
        }
    }
}
