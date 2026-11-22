//! Bounded, slice-based protocol decoding shared by all capture sources.

mod dns;
pub mod http1;
pub mod http2;
mod ip;
mod link;
pub mod protocols;
mod quic;
mod stream;
mod tls;
mod transport;

use std::{fmt::Display, net::IpAddr};

use crate::packet::PacketRecord;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    Unknown,
    Ethernet,
    Vlan,
    Sll,
    Arp,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Dns,
    Quic,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Ethernet => "Ethernet",
            Self::Vlan => "VLAN",
            Self::Sll => "Linux cooked",
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Dns => "DNS",
            Self::Quic => "QUIC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    pub sequence: u32,
    pub flags: u16,
    pub payload_offset: usize,
    pub captured_payload_len: usize,
    pub original_payload_len: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub protocol: Protocol,
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub tcp: Option<TcpSegment>,
    pub fragmented: bool,
    pub issue: Option<&'static str>,
    layers: u16,
}

impl Summary {
    pub fn has(self, protocol: Protocol) -> bool {
        self.layers & (1 << protocol as u16) != 0
    }
}

#[derive(Debug)]
pub struct Field {
    pub key: &'static str,
    pub value: String,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug)]
pub struct Layer {
    pub name: &'static str,
    pub fields: Vec<Field>,
}

#[derive(Debug)]
pub struct Details {
    pub summary: Summary,
    pub layers: Vec<Layer>,
}

pub fn summarize(packet: &PacketRecord) -> Summary {
    decode(packet, false).summary
}

pub fn details(packet: &PacketRecord) -> Details {
    let decoder = decode(packet, true);
    Details {
        summary: decoder.summary,
        layers: decoder.layers.unwrap_or_default(),
    }
}

fn decode(packet: &PacketRecord, with_details: bool) -> Decoder {
    let mut decoder = Decoder {
        summary: Summary::default(),
        layers: with_details.then(Vec::new),
    };
    if packet.is_truncated() {
        decoder.issue("packet was truncated during capture");
    }
    decoder.link(packet.link_type().0, packet.bytes());
    decoder
}

struct Decoder {
    summary: Summary,
    layers: Option<Vec<Layer>>,
}

impl Decoder {
    fn issue(&mut self, issue: &'static str) {
        self.summary.issue.get_or_insert(issue);
    }

    fn layer(&mut self, protocol: Protocol) {
        self.summary.protocol = protocol;
        self.summary.layers |= 1 << protocol as u16;
        if let Some(layers) = &mut self.layers {
            layers.push(Layer {
                name: protocol.name(),
                fields: Vec::new(),
            });
        }
    }

    fn field(&mut self, key: &'static str, value: impl Display, offset: usize, len: usize) {
        if let Some(layer) = self.layers.as_mut().and_then(|layers| layers.last_mut()) {
            layer.fields.push(Field {
                key,
                value: value.to_string(),
                offset,
                len,
            });
        }
    }
}

fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
