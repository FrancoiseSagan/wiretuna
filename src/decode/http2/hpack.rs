//! Directional HPACK state. Only HTTP pseudo-headers are emitted in the report.

use std::collections::VecDeque;

use super::{Head, huffman};

const MAX_TABLE_BYTES: usize = 64 * 1024;
const MAX_STRING_BYTES: usize = 8 * 1024;
const MAX_HEADER_COUNT: usize = 256;

type Entry = (Vec<u8>, Vec<u8>);

pub(super) struct Decoder {
    entries: VecDeque<Entry>,
    size: usize,
    capacity: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            capacity: 4096,
        }
    }
}

impl Decoder {
    pub(super) fn decode(&mut self, mut bytes: &[u8]) -> Result<Head, &'static str> {
        let mut head = Head::default();
        let mut fields = 0;
        let mut updates = 0;
        while let Some(&first) = bytes.first() {
            if first & 0xe0 == 0x20 {
                updates += 1;
                if fields != 0 || updates > 2 {
                    return Err("hpack_invalid");
                }
                self.capacity = integer(&mut bytes, 5).ok_or("hpack_invalid")?;
                if self.capacity > MAX_TABLE_BYTES {
                    return Err("hpack_limit");
                }
                self.evict(0);
                continue;
            }
            fields += 1;
            if fields > MAX_HEADER_COUNT {
                return Err("hpack_limit");
            }
            if first & 0x80 != 0 {
                let index = integer(&mut bytes, 7).ok_or("hpack_invalid")?;
                let (name, value) = self.get(index).ok_or("hpack_invalid")?;
                head.record(name, value);
                continue;
            }
            let indexed = first & 0x40 != 0;
            let prefix = if indexed { 6 } else { 4 };
            let index = integer(&mut bytes, prefix).ok_or("hpack_invalid")?;
            let name = if index == 0 {
                string(&mut bytes)?
            } else {
                self.get(index).ok_or("hpack_invalid")?.0.to_vec()
            };
            let value = string(&mut bytes)?;
            head.record(&name, &value);
            if indexed {
                self.insert(name, value);
            }
        }
        Ok(head)
    }

    fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        let index = index.checked_sub(1)?;
        if index < STATIC.len() {
            return Some(STATIC[index]);
        }
        let (name, value) = self.entries.get(index - STATIC.len())?;
        Some((name, value))
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let size = entry_size(&name, &value);
        if size > self.capacity {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict(size);
        self.entries.push_front((name, value));
        self.size += size;
    }

    fn evict(&mut self, additional: usize) {
        while self.size + additional > self.capacity {
            let (name, value) = self.entries.pop_back().expect("table size tracks entries");
            self.size -= entry_size(&name, &value);
        }
    }
}

fn entry_size(name: &[u8], value: &[u8]) -> usize {
    32 + name.len() + value.len()
}

fn integer(bytes: &mut &[u8], prefix: u8) -> Option<usize> {
    let (first, rest) = bytes.split_first()?;
    *bytes = rest;
    let mask = (1 << prefix) - 1;
    let mut value = u64::from(first & mask);
    if value < u64::from(mask) {
        return Some(value as usize);
    }
    for shift in (0..35).step_by(7) {
        let (byte, rest) = bytes.split_first()?;
        *bytes = rest;
        value += u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return u32::try_from(value).ok().map(|value| value as usize);
        }
    }
    None
}

fn string(bytes: &mut &[u8]) -> Result<Vec<u8>, &'static str> {
    let huffman = bytes.first().ok_or("hpack_invalid")? & 0x80 != 0;
    let len = integer(bytes, 7).ok_or("hpack_invalid")?;
    if len > MAX_STRING_BYTES {
        return Err("hpack_limit");
    }
    let (value, rest) = bytes.split_at_checked(len).ok_or("hpack_invalid")?;
    *bytes = rest;
    if !huffman {
        return Ok(value.to_vec());
    }
    huffman::decode(value, MAX_STRING_BYTES)
}

// RFC 7541 Appendix A. Indices start at 1.
const STATIC: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];
