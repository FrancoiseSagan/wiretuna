use std::{fmt, net::Ipv4Addr};

use super::{Decoder, Protocol, be16};

impl Decoder {
    pub(super) fn link(&mut self, link_type: u16, bytes: &[u8]) {
        let (mut ether_type, mut offset) = match link_type {
            1 => {
                self.layer(Protocol::Ethernet);
                let Some(header) = bytes.get(..14) else {
                    self.issue("incomplete Ethernet header");
                    return;
                };
                self.field("eth.dst", Mac(&header[..6]), 0, 6);
                self.field("eth.src", Mac(&header[6..12]), 6, 6);
                self.field("eth.type", format_args!("{:#06x}", be16(header, 12)), 12, 2);
                (be16(header, 12), 14)
            }
            113 | 276 => {
                self.layer(Protocol::Sll);
                let (header_len, type_offset) = if link_type == 113 { (16, 14) } else { (20, 0) };
                let Some(header) = bytes.get(..header_len) else {
                    self.issue("incomplete Linux cooked header");
                    return;
                };
                let ether_type = be16(header, type_offset);
                self.field(
                    "sll.protocol",
                    format_args!("{ether_type:#06x}"),
                    type_offset,
                    2,
                );
                (ether_type, header_len)
            }
            101 | 228 | 229 => {
                self.network_version(bytes, 0);
                return;
            }
            0 | 108 => {
                if let Some(payload) = bytes.get(4..) {
                    self.network_version(payload, 4);
                } else {
                    self.issue("incomplete loopback header");
                }
                return;
            }
            _ => {
                self.issue("unsupported link type");
                return;
            }
        };

        let mut tags = 0;
        while matches!(ether_type, 0x8100 | 0x88a8) {
            if tags == 8 {
                self.issue("VLAN nesting limit reached");
                return;
            }
            let Some(tag) = bytes.get(offset..offset + 4) else {
                self.issue("incomplete VLAN header");
                return;
            };
            self.layer(Protocol::Vlan);
            self.field("vlan.id", be16(tag, 0) & 0x0fff, offset, 2);
            ether_type = be16(tag, 2);
            self.field(
                "vlan.type",
                format_args!("{ether_type:#06x}"),
                offset + 2,
                2,
            );
            offset += 4;
            tags += 1;
        }
        match ether_type {
            0x0800 => self.ipv4(&bytes[offset..], offset),
            0x86dd => self.ipv6(&bytes[offset..], offset),
            0x0806 => self.arp(&bytes[offset..], offset),
            _ => {}
        }
    }

    fn network_version(&mut self, bytes: &[u8], offset: usize) {
        match bytes.first().map(|byte| byte >> 4) {
            Some(4) => self.ipv4(bytes, offset),
            Some(6) => self.ipv6(bytes, offset),
            _ => self.issue("missing or unsupported IP version"),
        }
    }

    fn arp(&mut self, bytes: &[u8], offset: usize) {
        self.layer(Protocol::Arp);
        let Some(header) = bytes.get(..8) else {
            self.issue("incomplete ARP header");
            return;
        };
        self.field("arp.opcode", be16(header, 6), offset + 6, 2);
        let hardware = usize::from(header[4]);
        let protocol = usize::from(header[5]);
        if bytes.len() < 8 + 2 * (hardware + protocol) {
            self.issue("incomplete ARP addresses");
            return;
        }
        if (hardware, protocol, be16(header, 2)) == (6, 4, 0x0800) {
            let source = Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]);
            let destination = Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]);
            self.summary.source = Some(source.into());
            self.summary.destination = Some(destination.into());
            self.field("arp.src.mac", Mac(&bytes[8..14]), offset + 8, 6);
            self.field("arp.src.ip", source, offset + 14, 4);
            self.field("arp.dst.mac", Mac(&bytes[18..24]), offset + 18, 6);
            self.field("arp.dst.ip", destination, offset + 24, 4);
        }
    }
}

struct Mac<'a>(&'a [u8]);

impl fmt::Display for Mac<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(":")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
