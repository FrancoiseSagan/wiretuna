use std::{
    fmt::Write,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::{Decoder, Protocol, be16, be32};

impl Decoder {
    pub(super) fn dns(&mut self, bytes: &[u8], offset: usize) {
        let Some(header) = bytes.get(..12) else {
            return;
        };
        self.layer(Protocol::Dns);
        self.field(
            "dns.id",
            format_args!("{:#06x}", be16(header, 0)),
            offset,
            2,
        );
        self.field(
            "dns.flags",
            format_args!("{:#06x}", be16(header, 2)),
            offset + 2,
            2,
        );
        for (index, key) in [
            "dns.questions",
            "dns.answers",
            "dns.authority",
            "dns.additional",
        ]
        .into_iter()
        .enumerate()
        {
            let start = 4 + 2 * index;
            self.field(key, be16(header, start), offset + start, 2);
        }
        if self.layers.is_some()
            && let Err(issue) = self.dns_entries(bytes, offset)
        {
            self.issue(issue);
        }
    }

    fn dns_entries(&mut self, bytes: &[u8], offset: usize) -> Result<(), &'static str> {
        let questions = usize::from(be16(bytes, 4));
        let records = [6, 8, 10]
            .into_iter()
            .map(|index| usize::from(be16(bytes, index)))
            .sum::<usize>();
        if questions + records > 128 {
            return Err("DNS entry limit reached");
        }
        let mut index = 12;
        for _ in 0..questions {
            let (name, len) = name(bytes, index)?;
            self.field("dns.qry.name", name, offset + index, len);
            index += len;
            let header = bytes
                .get(index..index + 4)
                .ok_or("incomplete DNS question")?;
            self.field("dns.qry.type", be16(header, 0), offset + index, 2);
            index += 4;
        }
        for _ in 0..records {
            let (owner, len) = name(bytes, index)?;
            self.field("dns.rr.name", owner, offset + index, len);
            index += len;
            let header = bytes
                .get(index..index + 10)
                .ok_or("incomplete DNS resource record")?;
            let kind = be16(header, 0);
            self.field("dns.rr.type", kind, offset + index, 2);
            self.field("dns.rr.ttl", be32(header, 4), offset + index + 4, 4);
            let len = usize::from(be16(header, 8));
            index += 10;
            let data = bytes
                .get(index..index + len)
                .ok_or("incomplete DNS record data")?;
            match (kind, data) {
                (1, [a, b, c, d]) => {
                    self.field("dns.a", Ipv4Addr::new(*a, *b, *c, *d), offset + index, len)
                }
                (28, data) if len == 16 => {
                    let address = Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap());
                    self.field("dns.aaaa", address, offset + index, len);
                }
                (5, _) => {
                    let (target, consumed) = name(bytes, index)?;
                    if consumed != len {
                        return Err("invalid DNS CNAME length");
                    }
                    self.field("dns.cname", target, offset + index, len);
                }
                _ => self.field("dns.rr.data_len", len, offset + index, len),
            }
            index += len;
        }
        Ok(())
    }
}

fn name(bytes: &[u8], start: usize) -> Result<(String, usize), &'static str> {
    let mut out = String::new();
    let mut index = start;
    let mut end = None;
    let mut expanded = 0;
    let mut pointers = 0;
    loop {
        let len = *bytes.get(index).ok_or("incomplete DNS name")?;
        if len == 0 {
            if out.is_empty() {
                out.push('.');
            }
            return Ok((out, end.unwrap_or(index + 1) - start));
        }
        if len & 0xc0 == 0xc0 {
            let low = *bytes.get(index + 1).ok_or("incomplete DNS name pointer")?;
            let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
            pointers += 1;
            if target < 12 || target >= index || pointers > 16 {
                return Err("invalid DNS name pointer");
            }
            end.get_or_insert(index + 2);
            index = target;
            continue;
        }
        let len = usize::from(len);
        expanded += len + 1;
        if len > 63 || expanded >= 255 {
            return Err("invalid DNS label length");
        }
        let label = bytes
            .get(index + 1..index + 1 + len)
            .ok_or("incomplete DNS label")?;
        if !out.is_empty() {
            out.push('.');
        }
        for &byte in label {
            if byte.is_ascii_graphic() && !matches!(byte, b'.' | b'\\') {
                out.push(char::from(byte));
            } else {
                write!(out, "\\x{byte:02x}").unwrap();
            }
        }
        index += len + 1;
    }
}
