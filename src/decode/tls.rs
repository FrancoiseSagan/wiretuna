//! Visible TLS hello messages in the contiguous TCP prefix.

use super::{
    be16,
    protocols::{Direction, Message},
    stream::Prefix,
};

const MAX_RECORD_BYTES: usize = 1 << 14;
const MAX_HELLOS: usize = 16;
const MAX_LIST_ITEMS: usize = 64;
type Fields = Vec<(&'static str, String)>;

pub(super) fn recognized(prefix: &Prefix) -> bool {
    matches!(prefix.bytes.as_slice(), [22, 3, 0..=3, ..])
        && prefix.bytes.get(5).is_none_or(|kind| matches!(kind, 1 | 2))
}

pub(super) fn direction(prefix: &Prefix) -> Direction {
    let mut report = Direction::default();
    if !recognized(prefix) {
        return report;
    }
    let mut handshake = Vec::new();
    let mut sources = Vec::new();
    let mut offset = 0;
    while offset < prefix.bytes.len() {
        let bytes = &prefix.bytes[offset..];
        // Older TLS versions can carry encrypted handshake messages after CCS.
        if matches!(bytes[0], 20 | 21 | 23) {
            break;
        }
        let Some(header) = bytes.get(..5) else {
            report.issue = Some("tls_incomplete_record");
            break;
        };
        let length = usize::from(be16(header, 3));
        if !matches!(header[..3], [22, 3, 0..=3]) || !(1..=MAX_RECORD_BYTES).contains(&length) {
            report.issue = Some("tls_invalid_record");
            break;
        }
        let Some(payload) = bytes.get(5..5 + length) else {
            report.issue = Some("tls_incomplete_record");
            break;
        };
        sources.push((handshake.len(), offset + 5));
        handshake.extend_from_slice(payload);
        offset += 5 + length;
    }
    let mut position = 0;
    while position < handshake.len() {
        if report.messages.len() == MAX_HELLOS {
            report.issue = Some("message_limit");
            break;
        }
        let bytes = &handshake[position..];
        let Some(&[kind, a, b, c]) = bytes.first_chunk::<4>() else {
            report.issue.get_or_insert("tls_incomplete_handshake");
            break;
        };
        let length = u32::from_be_bytes([0, a, b, c]) as usize;
        let Some(body) = bytes.get(4..4 + length) else {
            report.issue.get_or_insert("tls_incomplete_handshake");
            break;
        };
        if matches!(kind, 1 | 2) {
            let index = sources.partition_point(|&(start, _)| start <= position) - 1;
            let (start, stream_offset) = sources[index];
            let offset = stream_offset + position - start;
            let fields = hello(kind == 1, body);
            let issue = fields.is_none().then_some("tls_invalid_hello");
            report.messages.push(Message {
                kind: if kind == 1 {
                    "client_hello"
                } else {
                    "server_hello"
                },
                offset,
                packet: prefix.packet_at(offset),
                fields: fields.unwrap_or_default(),
                issue,
            });
        }
        position += 4 + length;
    }
    report
}

fn hello(client: bool, body: &[u8]) -> Option<Fields> {
    let mut hello = Reader(body);
    let legacy_version = hello.u16()?;
    let random = hello.take(32)?;
    if hello.vec8()?.len() > 32 {
        return None;
    }
    let mut fields = vec![("tls.legacy_version", version(legacy_version))];
    if client {
        let suites = u16_list(hello.vec16()?, cipher)?;
        if hello.vec8()?.is_empty() {
            return None;
        }
        fields.push(("tls.cipher_suites", suites));
    } else {
        fields.push(("tls.cipher_suite", cipher(hello.u16()?)));
        hello.u8()?;
        // TLS 1.3 encodes HelloRetryRequest as a ServerHello with this random.
        if random == b"\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c" {
            fields.push(("tls.hello_retry_request", "true".into()));
        }
    }
    let extension_bytes = if hello.0.is_empty() {
        &[][..]
    } else {
        hello.vec16()?
    };
    let mut extensions = Reader(extension_bytes);
    if !hello.0.is_empty() {
        return None;
    }
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let mut data = Reader(extensions.vec16()?);
        match (kind, client) {
            (0, true) => fields.push(("tls.sni", server_name(&mut data)?)),
            (16, _) => fields.push(("tls.alpn", alpn(&mut data, client)?)),
            (43, true) => fields.push(("tls.offered_versions", u16_list(data.vec8()?, version)?)),
            (43, false) => fields.push(("tls.selected_version", version(data.u16()?))),
            _ => continue,
        }
        if !data.0.is_empty() {
            return None;
        }
    }
    if !client && !fields.iter().any(|(key, _)| *key == "tls.selected_version") {
        fields.push(("tls.selected_version", version(legacy_version)));
    }
    Some(fields)
}

fn server_name(data: &mut Reader<'_>) -> Option<String> {
    let mut names = Reader(data.vec16()?);
    // host_name is the only defined name type and can occur only once.
    if names.u8()? != 0 {
        return None;
    }
    let name = names.vec16()?;
    if !names.0.is_empty() || name.is_empty() || !name.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    String::from_utf8(name.to_vec()).ok()
}

fn alpn(data: &mut Reader<'_>, client: bool) -> Option<String> {
    let mut names = Reader(data.vec16()?);
    let mut values = Vec::new();
    let mut count = 0;
    while !names.0.is_empty() {
        let name = names.vec8()?;
        if name.is_empty() {
            return None;
        }
        if count < MAX_LIST_ITEMS {
            values.push(
                name.iter()
                    .flat_map(|byte| std::ascii::escape_default(*byte))
                    .map(char::from)
                    .collect(),
            );
        }
        count += 1;
    }
    if count == 0 || (!client && count != 1) {
        return None;
    }
    Some(join_list(values, count))
}

fn u16_list(bytes: &[u8], format: fn(u16) -> String) -> Option<String> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let values = bytes
        .chunks_exact(2)
        .take(MAX_LIST_ITEMS)
        .map(|item| format(be16(item, 0)))
        .collect();
    Some(join_list(values, bytes.len() / 2))
}

fn join_list(values: Vec<String>, count: usize) -> String {
    let mut result = values.join(", ");
    if count > values.len() {
        result.push_str(&format!(", … ({count})"));
    }
    result
}

fn version(value: u16) -> String {
    match value {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        _ => format!("{value:#06x}"),
    }
}

fn cipher(value: u16) -> String {
    format!("{value:#06x}")
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (result, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(result)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(be16(self.take(2)?, 0))
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::stream::test_snapshot as snapshot;

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        [&[kind, 0, 0, body.len() as u8], body].concat()
    }

    #[test]
    fn client_hello_crosses_records_and_packets() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(b"\0\0\x02\x13\x01\x01\0\0\x25");
        body.extend_from_slice(b"\0\0\0\x11\0\x0f\0\0\x0cexample.test");
        body.extend_from_slice(b"\0\x10\0\x05\0\x03\x02h2");
        body.extend_from_slice(b"\0\x2b\0\x03\x02\x03\x04");
        let hello = handshake(1, &body);
        let stream = [record(&hello[..3]), record(&hello[3..])].concat();
        let prefix = Prefix::new(&snapshot(&[&stream[..5], &stream[5..13], &stream[13..]]));
        let report = direction(&prefix);
        assert_eq!(report.issue, None);
        let message = &report.messages[0];
        assert_eq!(
            (message.kind, message.offset, message.packet),
            ("client_hello", 5, 2)
        );
        assert!(message.fields.contains(&("tls.sni", "example.test".into())));
        assert!(message.fields.contains(&("tls.alpn", "h2".into())));
        assert!(
            message
                .fields
                .contains(&("tls.offered_versions", "TLS 1.3".into()))
        );
    }

    #[test]
    fn server_hello_reports_selected_version_and_stops_at_encryption() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(b"\0\x13\x01\0\0\x06\0\x2b\0\x02\x03\x04");
        let stream = [
            record(&handshake(2, &body)),
            vec![20, 3, 3, 0, 1, 1],
            record(b"opaque"),
        ]
        .concat();
        let report = direction(&Prefix::new(&snapshot(&[&stream])));
        assert_eq!(report.issue, None);
        assert_eq!(report.messages.len(), 1);
        assert!(
            report.messages[0]
                .fields
                .contains(&("tls.selected_version", "TLS 1.3".into()))
        );
    }

    #[test]
    fn incomplete_records_and_messages_do_not_produce_hello_fields() {
        let incomplete_record = &[22, 3, 3, 0, 5, 1];
        let stream = Prefix::new(&snapshot(&[incomplete_record]));
        let report = direction(&stream);
        assert!(report.messages.is_empty());
        assert_eq!(report.issue, Some("tls_incomplete_record"));

        let stream = Prefix::new(&snapshot(&[&record(&[1, 0, 0, 9, 3, 3])]));
        let report = direction(&stream);
        assert!(report.messages.is_empty());
        assert_eq!(report.issue, Some("tls_incomplete_handshake"));
    }
}
