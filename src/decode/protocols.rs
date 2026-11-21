//! Application protocols identified in retained TCP streams.

use crate::flow::{Flow, StreamSnapshot};

use super::{Decoder, Summary, be16, stream::Prefix, tls};

const MAX_MESSAGES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Dns,
    Tls,
}

#[derive(Debug)]
pub struct Report {
    pub protocol: Protocol,
    pub directions: [Direction; 2],
}

#[derive(Debug, Default)]
pub struct Direction {
    pub messages: Vec<Message>,
    pub issue: Option<&'static str>,
}

#[derive(Debug)]
pub struct Message {
    pub kind: &'static str,
    pub offset: usize,
    pub packet: u64,
    pub fields: Vec<(&'static str, String)>,
    pub issue: Option<&'static str>,
}

pub fn analyze(flow: &Flow, streams: &[StreamSnapshot; 2]) -> Option<Report> {
    let prefixes = streams.each_ref().map(Prefix::new);
    let is_dns = flow.endpoints.iter().any(|endpoint| endpoint.port() == 53);
    let (protocol, decode): (_, fn(&Prefix) -> Direction) = if is_dns {
        (Protocol::Dns, dns)
    } else if prefixes.iter().any(tls::recognized) {
        (Protocol::Tls, tls::direction)
    } else {
        return None;
    };
    let directions = prefixes.each_ref().map(|prefix| {
        let mut direction = decode(prefix);
        if prefix.incomplete {
            direction.issue.get_or_insert("stream_gap");
        }
        direction
    });
    Some(Report {
        protocol,
        directions,
    })
}

fn dns(prefix: &Prefix) -> Direction {
    let mut report = Direction::default();
    let mut offset = 0;
    while offset < prefix.bytes.len() {
        if report.messages.len() == MAX_MESSAGES {
            report.issue = Some("message_limit");
            break;
        }
        let remaining = &prefix.bytes[offset..];
        if remaining.len() < 2 {
            report.issue = Some("dns_incomplete");
            break;
        }
        let length = usize::from(be16(remaining, 0));
        if length < 12 {
            report.issue = Some("dns_invalid_length");
            break;
        }
        let Some(message) = remaining.get(2..2 + length) else {
            report.issue = Some("dns_incomplete");
            break;
        };
        let mut decoder = Decoder {
            summary: Summary::default(),
            layers: Some(Vec::new()),
        };
        decoder.dns(message, 0);
        report.messages.push(Message {
            kind: if message[2] & 0x80 == 0 {
                "dns_query"
            } else {
                "dns_response"
            },
            offset,
            packet: prefix.packet_at(offset),
            fields: decoder
                .layers
                .unwrap()
                .into_iter()
                .flat_map(|layer| {
                    layer
                        .fields
                        .into_iter()
                        .map(|field| (field.key, field.value))
                })
                .collect(),
            issue: decoder.summary.issue,
        });
        offset += 2 + length;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::stream::test_snapshot as snapshot;

    #[test]
    fn dns_frames_span_packets_and_keep_compression_relative_to_the_message() {
        let mut query = vec![0, 0, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
        query[1] = (query.len() - 2) as u8;
        let mut response = query.clone();
        response[4] = 0x81;
        response[9] = 1;
        response.extend_from_slice(b"\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04\xc0\0\x02\x01");
        response[1] = (response.len() - 2) as u8;
        let sequence = [&query[1..], &response, &[0, 12, 0]].concat();
        let prefix = Prefix::new(&snapshot(&[&query[..1], &sequence]));
        let report = dns(&prefix);
        assert_eq!(report.messages.len(), 2);
        assert_eq!(report.messages[0].packet, 1);
        assert_eq!(report.messages[1].packet, 2);
        assert_eq!(report.messages[1].kind, "dns_response");
        assert!(
            report.messages[1]
                .fields
                .contains(&("dns.a", "192.0.2.1".into()))
        );
        assert_eq!(report.issue, Some("dns_incomplete"));
    }

    #[test]
    fn dns_does_not_read_past_a_gap() {
        let mut stream = snapshot(&[&[0], &[12; 13]]);
        stream.chunks[1].offset += 1;
        stream.observed_end += 1;
        let prefix = Prefix::new(&stream);
        assert!(prefix.incomplete);
        let report = dns(&prefix);
        assert!(report.messages.is_empty());
        assert_eq!(report.issue, Some("dns_incomplete"));
    }
}
