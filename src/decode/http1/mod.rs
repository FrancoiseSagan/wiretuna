//! HTTP/1.1 analysis of retained, contiguous TCP bytes.

mod framing;

use super::stream::Prefix;
use crate::flow::{Flow, StreamSnapshot};
use framing::{Body, Framing};

const MAX_PREVIEW_BYTES: usize = 256;
const MAX_HEADERS: usize = 64;
const MAX_HEAD_BYTES: usize = 32 * 1024;
const MAX_TRANSACTIONS: usize = 128;
const MAX_INFORMATIONAL: usize = 8;

#[derive(Debug)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug)]
pub struct Message {
    pub method: Option<String>,
    pub target: Option<String>,
    pub status: Option<u16>,
    pub headers: Vec<Header>,
    pub direction: usize,
    pub offset: u64,
    pub first_packet: u64,
    pub last_packet: u64,
    pub body_bytes: usize,
    pub preview: Vec<u8>,
    pub issue: Option<&'static str>,
}

#[derive(Debug)]
pub struct Transaction {
    pub request: Option<Message>,
    pub responses: Vec<Message>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub transactions: Vec<Transaction>,
    pub note: Option<&'static str>,
}

pub fn analyze(flow: &Flow, streams: &[StreamSnapshot; 2]) -> Report {
    analyze_selected(flow, streams, None)
}

/// Reads the selected body within the retained TCP prefix, after HTTP framing.
pub fn read_body(
    flow: &Flow,
    streams: &[StreamSnapshot; 2],
    direction: usize,
    offset: u64,
) -> Option<Vec<u8>> {
    analyze_selected(flow, streams, Some((direction, offset)))
        .transactions
        .into_iter()
        .flat_map(|transaction| transaction.request.into_iter().chain(transaction.responses))
        .find(|message| message.direction == direction && message.offset == offset)
        .map(|message| message.preview)
}

fn analyze_selected(
    flow: &Flow,
    streams: &[StreamSnapshot; 2],
    body_target: Option<(usize, u64)>,
) -> Report {
    let prefixes = streams.each_ref().map(Prefix::new);
    let client = if looks_like_request(&prefixes[0]) {
        Some(0)
    } else if looks_like_request(&prefixes[1]) {
        Some(1)
    } else {
        flow.initiator
    };
    let Some(client) = client.or_else(|| {
        prefixes
            .iter()
            .position(|prefix| prefix.bytes.starts_with(b"HTTP/1.1 "))
            .map(|server| 1 - server)
    }) else {
        return Report::default();
    };
    let server = 1 - client;
    let mut report = Report::default();
    if streams.iter().any(|stream| stream.overlap_conflict) {
        report.note = Some("Conflicting TCP overlap. HTTP interpretation is uncertain.");
    } else if flow.missing_start {
        report.note =
            Some("Capture begins mid-connection. HTTP pairing is based on the visible messages.");
    }

    let mut requests = Reader::new(client, &prefixes[client], body_target);
    let mut responses = Reader::new(server, &prefixes[server], body_target);
    while report.transactions.len() < MAX_TRANSACTIONS {
        let Some(request) = requests.read(Kind::Request) else {
            break;
        };
        let method = request.method.as_deref().unwrap_or_default();
        let mut replies = Vec::new();
        let mut final_received = false;
        let mut upgraded = false;
        for _ in 0..=MAX_INFORMATIONAL {
            let Some(response) = responses.read(Kind::Response(Some(method))) else {
                break;
            };
            let status = response.status.unwrap_or_default();
            let informational = (100..200).contains(&status) && status != 101;
            upgraded = status == 101 || (method == "CONNECT" && (200..300).contains(&status));
            let incomplete = response.issue.is_some();
            replies.push(response);
            if !informational || incomplete {
                final_received = !informational && !incomplete;
                break;
            }
        }
        let incomplete = request.issue.is_some();
        report.transactions.push(Transaction {
            request: Some(request),
            responses: replies,
        });
        if upgraded || incomplete || !final_received {
            break;
        }
    }

    if report.transactions.is_empty()
        && let Some(response) = responses.read(Kind::Response(None))
    {
        report.transactions.push(Transaction {
            request: None,
            responses: vec![response],
        });
    }
    if report.transactions.len() == MAX_TRANSACTIONS {
        report.note.get_or_insert("HTTP transaction limit reached.");
    }
    if !report.transactions.is_empty() && prefixes.iter().any(|prefix| prefix.incomplete) {
        report
            .note
            .get_or_insert("HTTP analysis stops at the first gap in either direction.");
    }
    report
}

fn looks_like_request(prefix: &Prefix) -> bool {
    let limit = prefix.bytes.len().min(MAX_HEAD_BYTES);
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    matches!(
        request.parse(&prefix.bytes[..limit]),
        Ok(httparse::Status::Complete(_))
    ) && request.version == Some(1)
}

#[derive(Clone, Copy)]
enum Kind<'a> {
    Request,
    Response(Option<&'a str>),
}

struct Reader<'a> {
    direction: usize,
    prefix: &'a Prefix,
    position: usize,
    body_target: Option<(usize, u64)>,
}

impl<'a> Reader<'a> {
    fn new(direction: usize, prefix: &'a Prefix, body_target: Option<(usize, u64)>) -> Self {
        Self {
            direction,
            prefix,
            position: 0,
            body_target,
        }
    }

    fn read(&mut self, kind: Kind<'_>) -> Option<Message> {
        let start = self.position;
        let remaining = self.prefix.bytes.get(start..)?;
        let limited = &remaining[..remaining.len().min(MAX_HEAD_BYTES)];
        let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let (head_len, method, target, status, headers) = match kind {
            Kind::Request => {
                let mut request = httparse::Request::new(&mut slots);
                let httparse::Status::Complete(head_len) = request.parse(limited).ok()? else {
                    return None;
                };
                if request.version != Some(1) {
                    return None;
                }
                (
                    head_len,
                    request.method,
                    request.path,
                    None,
                    request.headers,
                )
            }
            Kind::Response(_) => {
                let mut response = httparse::Response::new(&mut slots);
                let httparse::Status::Complete(head_len) = response.parse(limited).ok()? else {
                    return None;
                };
                if response.version != Some(1) {
                    return None;
                }
                (head_len, None, None, response.code, response.headers)
            }
        };

        let bytes = &remaining[head_len..];
        let body = match kind {
            Kind::Response(None) => Body::failed("Request context is unavailable."),
            Kind::Response(Some(method))
                if method == "HEAD"
                    || status.is_some_and(|code| {
                        matches!(code, 100..=199 | 204 | 304)
                            || (method == "CONNECT" && (200..300).contains(&code))
                    }) =>
            {
                Body::empty()
            }
            _ => match Framing::from_headers(headers, matches!(kind, Kind::Request)) {
                Ok(framing) => {
                    let limit = if self.body_target == Some((self.direction, start as u64)) {
                        bytes.len()
                    } else {
                        MAX_PREVIEW_BYTES
                    };
                    framing.read(bytes, self.prefix.finished, limit)
                }
                Err(issue) => Body::failed(issue),
            },
        };
        self.position = if body.issue.is_none() {
            start + head_len + body.consumed
        } else {
            self.prefix.bytes.len()
        };
        let headers = headers
            .iter()
            .map(|header| Header {
                name: header.name.to_owned(),
                value: if [
                    "authorization",
                    "proxy-authorization",
                    "cookie",
                    "set-cookie",
                ]
                .iter()
                .any(|name| header.name.eq_ignore_ascii_case(name))
                {
                    "[redacted]".to_owned()
                } else {
                    String::from_utf8_lossy(header.value).into_owned()
                },
            })
            .collect();
        Some(Message {
            method: method.map(str::to_owned),
            target: target.map(str::to_owned),
            status,
            headers,
            direction: self.direction,
            offset: start as u64,
            first_packet: self.prefix.packet_at(start),
            last_packet: self.prefix.packet_at(start + head_len + body.consumed - 1),
            body_bytes: body.bytes,
            preview: body.preview,
            issue: body.issue,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Chunk, State};
    use std::sync::Arc;

    fn stream(parts: &[&[u8]]) -> StreamSnapshot {
        let mut end = 0;
        let chunks = parts
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let chunk = Chunk {
                    offset: end,
                    packet_id: (index + 1) as u64,
                    bytes: Arc::from(*bytes),
                };
                end = chunk.end();
                chunk
            })
            .collect();
        StreamSnapshot {
            chunks,
            observed_end: end,
            fin_offset: None,
            overlap_conflict: false,
            limited: false,
        }
    }

    fn flow() -> Flow {
        Flow {
            id: 1,
            endpoints: [
                "127.0.0.1:30000".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
            ],
            directions: Default::default(),
            initiator: Some(0),
            missing_start: false,
            state: State::Established,
            first_packet: 1,
            last_packet: 2,
            first_time: None,
            last_time: None,
        }
    }

    #[test]
    fn pairs_persistent_http_with_informational_chunked_and_head_responses() {
        let client = stream(&[
            b"GET /one HTTP/1.1\r\nHost: localhost\r\n",
            b"\r\nHEAD /two HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]);
        let server = stream(&[
            b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"3\r\nabc\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n",
        ]);
        let report = analyze(&flow(), &[client, server]);
        assert_eq!(report.transactions.len(), 2);
        let first = &report.transactions[0];
        let request = first.request.as_ref().unwrap();
        assert_eq!(request.target.as_deref(), Some("/one"));
        assert_eq!((request.first_packet, request.last_packet), (1, 2));
        assert_eq!(first.responses[0].status, Some(103));
        assert_eq!(first.responses[1].preview, b"abc");
        assert_eq!(first.responses[1].issue, None);
        assert_eq!(report.transactions[1].responses[0].body_bytes, 0);
    }

    #[test]
    fn reads_selected_chunked_body_beyond_the_preview_limit() {
        let summary = "正文".repeat(190);
        let client = stream(&[b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"]);
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for chunk in summary.as_bytes().chunks(127) {
            response.extend(format!("{:x}\r\n", chunk.len()).bytes());
            response.extend(chunk);
            response.extend(b"\r\n");
        }
        response.extend(b"0\r\n\r\n");
        let parts = [&response[..300], &response[300..]];
        let streams = [client, stream(&parts)];
        let report = analyze(&flow(), &streams);
        let message = &report.transactions[0].responses[0];
        assert_eq!(message.preview.len(), 256);
        assert_eq!(message.body_bytes, summary.len());
        assert_eq!(
            read_body(&flow(), &streams, 1, 0).unwrap(),
            summary.as_bytes()
        );
        assert_eq!(read_body(&flow(), &streams, 1, 1), None);
    }

    #[test]
    fn labels_partial_messages_and_keeps_sensitive_headers_out_of_reports() {
        let client = stream(&[b"GET / HTTP/1.1\r\nAuthorization: secret\r\n\r\n"]);
        let mut server = stream(&[b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12"]);
        server.observed_end += 3;
        let report = analyze(&flow(), &[client, server]);
        let transaction = &report.transactions[0];
        assert_eq!(
            transaction.request.as_ref().unwrap().headers[0].value,
            "[redacted]"
        );
        assert_eq!(transaction.responses[0].issue, Some("Body is incomplete."));
        assert!(report.note.is_some());
    }
}
