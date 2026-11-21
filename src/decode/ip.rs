use std::net::{Ipv4Addr, Ipv6Addr};

use super::{Decoder, Protocol, be16};

impl Decoder {
    pub(super) fn ipv4(&mut self, bytes: &[u8], offset: usize) {
        self.layer(Protocol::Ipv4);
        let Some(header) = bytes.get(..20) else {
            self.issue("incomplete IPv4 header");
            return;
        };
        let header_len = usize::from(header[0] & 0x0f) * 4;
        let total_len = usize::from(be16(header, 2));
        if header[0] >> 4 != 4 || header_len < 20 || total_len < header_len {
            self.issue("invalid IPv4 header length or version");
            return;
        }
        let source = Ipv4Addr::from(<[u8; 4]>::try_from(&header[12..16]).unwrap());
        let destination = Ipv4Addr::from(<[u8; 4]>::try_from(&header[16..20]).unwrap());
        self.summary.source = Some(source.into());
        self.summary.destination = Some(destination.into());

        let fragment = be16(header, 6);
        self.summary.fragmented = fragment & 0x3fff != 0;
        self.field("ip.len", total_len, offset + 2, 2);
        self.field("ip.fragment_offset", (fragment & 0x1fff) * 8, offset + 6, 2);
        self.field("ip.ttl", header[8], offset + 8, 1);
        self.field("ip.protocol", header[9], offset + 9, 1);
        self.field("ip.src", source, offset + 12, 4);
        self.field("ip.dst", destination, offset + 16, 4);
        if bytes.len() < total_len {
            self.issue("incomplete IPv4 payload");
        }
        if fragment & 0x1fff != 0 {
            return;
        }
        let Some(payload) = bytes.get(header_len..total_len.min(bytes.len())) else {
            self.issue("incomplete IPv4 options");
            return;
        };
        self.transport(
            header[9],
            payload,
            offset + header_len,
            total_len - header_len,
        );
    }

    pub(super) fn ipv6(&mut self, bytes: &[u8], offset: usize) {
        self.layer(Protocol::Ipv6);
        let Some(header) = bytes.get(..40) else {
            self.issue("incomplete IPv6 header");
            return;
        };
        if header[0] >> 4 != 6 {
            self.issue("invalid IPv6 version");
            return;
        }
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&header[8..24]).unwrap());
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&header[24..40]).unwrap());
        self.summary.source = Some(source.into());
        self.summary.destination = Some(destination.into());
        let payload_len = usize::from(be16(header, 4));
        let end = 40 + payload_len;
        self.field("ipv6.payload_len", payload_len, offset + 4, 2);
        self.field("ipv6.next_header", header[6], offset + 6, 1);
        self.field("ipv6.hop_limit", header[7], offset + 7, 1);
        self.field("ipv6.src", source, offset + 8, 16);
        self.field("ipv6.dst", destination, offset + 24, 16);
        if bytes.len() < end {
            self.issue("incomplete IPv6 payload");
        }

        let bounded = &bytes[..end.min(bytes.len())];
        let mut next = header[6];
        let mut start = 40;
        for count in 0..=8 {
            if !matches!(next, 0 | 43 | 44 | 51 | 60) {
                self.transport(next, &bounded[start..], offset + start, end - start);
                return;
            }
            if count == 8 {
                self.issue("IPv6 extension limit reached");
                return;
            }
            let Some(extension) = bounded.get(start..start + 2) else {
                self.issue("incomplete IPv6 extension");
                return;
            };
            let len = match next {
                44 => 8,
                51 => (usize::from(extension[1]) + 2) * 4,
                _ => (usize::from(extension[1]) + 1) * 8,
            };
            let Some(extension) = bounded.get(start..start + len) else {
                self.issue("incomplete IPv6 extension");
                return;
            };
            self.field("ipv6.extension", next, offset + start, len);
            if next == 44 {
                let fragment = be16(extension, 2);
                self.summary.fragmented |= fragment & 0xfff9 != 0;
                self.field(
                    "ipv6.fragment_offset",
                    fragment & 0xfff8,
                    offset + start + 2,
                    2,
                );
                if fragment & 0xfff8 != 0 {
                    return;
                }
            }
            next = extension[0];
            start += len;
        }
    }
}
