use super::{Decoder, Protocol, TcpSegment, be16, be32};

impl Decoder {
    pub(super) fn transport(&mut self, protocol: u8, bytes: &[u8], offset: usize, expected: usize) {
        match protocol {
            6 => self.tcp(bytes, offset, expected),
            17 => self.udp(bytes, offset),
            1 | 58 => {
                self.layer(if protocol == 1 {
                    Protocol::Icmp
                } else {
                    Protocol::Icmpv6
                });
                let Some(header) = bytes.get(..4) else {
                    self.issue("incomplete ICMP header");
                    return;
                };
                self.field("icmp.type", header[0], offset, 1);
                self.field("icmp.code", header[1], offset + 1, 1);
                self.field(
                    "icmp.checksum",
                    format_args!("{:#06x}", be16(header, 2)),
                    offset + 2,
                    2,
                );
            }
            _ => {}
        }
    }

    fn tcp(&mut self, bytes: &[u8], offset: usize, expected: usize) {
        self.layer(Protocol::Tcp);
        let Some(header) = bytes.get(..20) else {
            self.issue("incomplete TCP header");
            return;
        };
        let source_port = be16(header, 0);
        let destination_port = be16(header, 2);
        let sequence = be32(header, 4);
        let flags = be16(header, 12) & 0x01ff;
        self.summary.source_port = Some(source_port);
        self.summary.destination_port = Some(destination_port);
        self.field("tcp.srcport", source_port, offset, 2);
        self.field("tcp.dstport", destination_port, offset + 2, 2);
        self.field("tcp.seq", sequence, offset + 4, 4);
        self.field("tcp.ack", be32(header, 8), offset + 8, 4);
        self.field("tcp.flags", format_args!("{flags:#05x}"), offset + 12, 2);
        self.field("tcp.window", be16(header, 14), offset + 14, 2);
        let header_len = usize::from(header[12] >> 4) * 4;
        if header_len < 20 || header_len > expected {
            self.issue("invalid TCP header length");
            return;
        }
        if header_len > bytes.len() {
            self.issue("incomplete TCP options");
            return;
        }
        if !self.summary.fragmented {
            self.summary.tcp = Some(TcpSegment {
                sequence,
                flags,
                payload_offset: offset + header_len,
                captured_payload_len: bytes.len() - header_len,
                original_payload_len: expected - header_len,
            });
        }
    }

    fn udp(&mut self, bytes: &[u8], offset: usize) {
        self.layer(Protocol::Udp);
        let Some(header) = bytes.get(..8) else {
            self.issue("incomplete UDP header");
            return;
        };
        let source = be16(header, 0);
        let destination = be16(header, 2);
        let len = usize::from(be16(header, 4));
        self.summary.source_port = Some(source);
        self.summary.destination_port = Some(destination);
        self.field("udp.srcport", source, offset, 2);
        self.field("udp.dstport", destination, offset + 2, 2);
        self.field("udp.len", len, offset + 4, 2);
        if len < 8 {
            self.issue("invalid UDP length");
            return;
        }
        if self.summary.fragmented {
            return;
        }
        if len > bytes.len() {
            self.issue("incomplete UDP payload");
        }
        let payload = &bytes[8..len.min(bytes.len())];
        if source == 53 || destination == 53 {
            if len <= bytes.len() {
                self.dns(payload, offset + 8);
            }
        } else {
            self.quic(
                payload,
                offset + 8,
                len - 8,
                source == 443 || destination == 443,
            );
        }
    }
}
