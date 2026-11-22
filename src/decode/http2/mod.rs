//! Cleartext HTTP/2 framing and request/response metadata in retained TCP streams.

mod hpack;
mod huffman;

use crate::flow::StreamSnapshot;

use super::{be16, be32, http1, stream::Prefix};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAMES: usize = 256;
const MAX_DISPLAY_BYTES: usize = 512;
const MAX_FIELD_BLOCK: usize = 64 * 1024;
const END_HEADERS: u8 = 0x04;
const PADDED: u8 = 0x08;
const STREAM_MASK: u32 = 0x7fff_ffff;

#[derive(Debug, Default)]
pub struct Head {
    pub method: Option<String>,
    pub path: Option<String>,
    pub authority: Option<String>,
    pub scheme: Option<String>,
    pub status: Option<String>,
    pub protocol: Option<String>,
}

impl Head {
    fn record(&mut self, name: &[u8], value: &[u8]) {
        let field = match name {
            b":method" => &mut self.method,
            b":path" => &mut self.path,
            b":authority" => &mut self.authority,
            b":scheme" => &mut self.scheme,
            b":status" => &mut self.status,
            b":protocol" => &mut self.protocol,
            _ => return,
        };
        if field.is_none() {
            let mut display =
                String::from_utf8_lossy(&value[..value.len().min(MAX_DISPLAY_BYTES)]).into_owned();
            if value.len() > MAX_DISPLAY_BYTES {
                display.push('…');
            }
            *field = Some(display);
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub kind: &'static str,
    pub stream_id: u32,
    pub flags: u8,
    pub length: usize,
    pub offset: usize,
    pub packet: u64,
    pub issue: Option<&'static str>,
    pub head: Option<Head>,
    pub promised_stream: Option<u32>,
    pub fields: Vec<(&'static str, u32)>,
}

#[derive(Debug, Default)]
pub struct Direction {
    pub frames: Vec<Frame>,
    pub issue: Option<&'static str>,
}

#[derive(Debug)]
pub struct Report {
    pub directions: [Direction; 2],
    pub upgraded: bool,
}

pub fn analyze(streams: &[StreamSnapshot; 2]) -> Option<Report> {
    let prefixes = streams.each_ref().map(Prefix::new);
    let mut starts = [0; 2];
    let mut upgraded = false;
    let mut upgrade_frame = None;
    let mut client = None;
    for direction in 0..2 {
        let server = 1 - direction;
        if prefixes[direction].bytes.starts_with(PREFACE) {
            starts[direction] = PREFACE.len();
        } else if prefixes[direction]
            .bytes
            .windows(PREFACE.len())
            .any(|bytes| bytes == PREFACE)
            && let Some((request, start, reply)) =
                http1::h2c_upgrade(&prefixes[direction], &prefixes[server])
            && prefixes[direction].bytes[start..].starts_with(PREFACE)
        {
            starts[direction] = start + PREFACE.len();
            starts[server] = reply;
            upgraded = true;
            let authority = request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("Host"))
                .map(|header| header.value.as_bytes());
            let mut head = Head::default();
            for (name, value) in [
                (
                    b":method".as_slice(),
                    request.method.as_deref().map(str::as_bytes),
                ),
                (b":path", request.target.as_deref().map(str::as_bytes)),
                (b":authority", authority),
                (b":scheme", Some(b"http".as_slice())),
            ] {
                if let Some(value) = value {
                    head.record(name, value);
                }
            }
            let offset = request.offset as usize;
            upgrade_frame = Some(Frame {
                kind: "HTTP/1.1 Upgrade",
                stream_id: 1,
                flags: 0,
                length: start - offset,
                offset,
                packet: request.first_packet,
                issue: None,
                head: Some(head),
                promised_stream: None,
                fields: Vec::new(),
            });
        } else {
            continue;
        }
        client = Some(direction);
        break;
    }
    let client = client?;
    let mut directions = std::array::from_fn(|side| decode(&prefixes[side], starts[side]));
    if let Some(frame) = upgrade_frame {
        directions[client].frames.insert(0, frame);
    }
    Some(Report {
        directions,
        upgraded,
    })
}

fn decode(prefix: &Prefix, mut offset: usize) -> Direction {
    let mut result = Direction::default();
    let mut blocks = Blocks {
        hpack: Some(hpack::Decoder::default()),
        pending: None,
    };
    while offset < prefix.bytes.len() {
        if result.frames.len() == MAX_FRAMES {
            result.issue = Some("frame_limit");
            break;
        }
        let bytes = &prefix.bytes[offset..];
        let Some(header) = bytes.get(..9) else {
            result.issue = Some("incomplete_frame_header");
            break;
        };
        let length = be32(header, 0) as usize >> 8;
        let frame_type = header[3];
        let flags = header[4];
        let stream_id = be32(header, 5) & STREAM_MASK;
        if result.frames.is_empty() && !(frame_type == 4 && flags & 1 == 0 && stream_id == 0) {
            result.issue = Some("invalid_preface");
            break;
        }
        let mut frame = Frame {
            kind: frame_name(frame_type),
            stream_id,
            flags,
            length,
            offset,
            packet: prefix.packet_at(offset),
            issue: None,
            head: None,
            promised_stream: None,
            fields: Vec::new(),
        };
        if frame.kind == "Unknown" {
            frame.fields.push(("frame_type", u32::from(frame_type)));
        }
        let Some(payload) = bytes.get(9..9 + length) else {
            frame.issue = Some("incomplete_frame_payload");
            result.frames.push(frame);
            break;
        };
        let completes = blocks.handle(&mut frame, frame_type, payload, result.frames.len());
        if let Some((start, head)) = completes {
            if let Some(original) = result.frames.get_mut(start) {
                original.head = Some(head);
            } else {
                frame.head = Some(head);
            }
        }
        result.frames.push(frame);
        offset += 9 + length;
    }
    if let Some(block) = blocks.pending {
        result.frames[block.frame]
            .issue
            .get_or_insert("incomplete_field_block");
    }
    if prefix.incomplete {
        result.issue.get_or_insert("stream_gap");
    }
    result
}

struct FieldBlock {
    stream_id: u32,
    frame: usize,
    bytes: Vec<u8>,
}

struct Blocks {
    hpack: Option<hpack::Decoder>,
    pending: Option<FieldBlock>,
}

impl Blocks {
    fn handle(
        &mut self,
        frame: &mut Frame,
        kind: u8,
        payload: &[u8],
        index: usize,
    ) -> Option<(usize, Head)> {
        if self
            .pending
            .as_ref()
            .is_some_and(|block| kind != 9 || frame.stream_id != block.stream_id)
        {
            self.pending = None;
            self.hpack = None;
            frame.issue = Some("interrupted_field_block");
        }
        if !matches!(kind, 1 | 5 | 9) {
            if describe(frame, kind, payload).is_none() {
                frame.issue.get_or_insert("invalid_frame");
            }
            return None;
        }
        let result = self.field_block(frame, kind, payload, index);
        match result {
            Ok(block) => block,
            Err(issue) => {
                frame.issue.get_or_insert(issue);
                self.hpack = None;
                self.pending = None;
                None
            }
        }
    }

    fn field_block(
        &mut self,
        frame: &mut Frame,
        kind: u8,
        payload: &[u8],
        index: usize,
    ) -> Result<Option<(usize, Head)>, &'static str> {
        if frame.stream_id == 0 {
            return Err("invalid_frame");
        }
        let fragment = if kind == 9 {
            payload
        } else {
            let mut fragment = unpad(payload, frame.flags).ok_or("invalid_frame")?;
            if kind == 1 && frame.flags & 0x20 != 0 {
                priority(frame, fragment.get(..5).ok_or("invalid_frame")?);
                fragment = &fragment[5..];
            }
            if kind == 5 {
                let promised = be32(fragment.get(..4).ok_or("invalid_frame")?, 0) & STREAM_MASK;
                if promised == 0 {
                    return Err("invalid_frame");
                }
                frame.promised_stream = Some(promised);
                fragment = &fragment[4..];
            }
            fragment
        };
        let Some(decoder) = &mut self.hpack else {
            return Err("hpack_unavailable");
        };
        let mut block = if kind == 9 {
            self.pending.take().ok_or("unexpected_continuation")?
        } else {
            FieldBlock {
                stream_id: frame.stream_id,
                frame: index,
                bytes: Vec::new(),
            }
        };
        if fragment.len() > MAX_FIELD_BLOCK - block.bytes.len() {
            return Err("hpack_limit");
        }
        if frame.flags & END_HEADERS != 0 && block.bytes.is_empty() {
            return decoder
                .decode(fragment)
                .map(|head| Some((block.frame, head)));
        }
        block.bytes.extend_from_slice(fragment);
        if frame.flags & END_HEADERS == 0 {
            self.pending = Some(block);
            Ok(None)
        } else {
            decoder
                .decode(&block.bytes)
                .map(|head| Some((block.frame, head)))
        }
    }
}

fn unpad(bytes: &[u8], flags: u8) -> Option<&[u8]> {
    if flags & PADDED == 0 {
        return Some(bytes);
    }
    let (&padding, rest) = bytes.split_first()?;
    rest.get(..rest.len().checked_sub(usize::from(padding))?)
}

fn priority(frame: &mut Frame, payload: &[u8]) {
    frame
        .fields
        .push(("dependency", be32(payload, 0) & STREAM_MASK));
    frame.fields.push(("weight", u32::from(payload[4]) + 1));
}

fn describe(frame: &mut Frame, kind: u8, payload: &[u8]) -> Option<()> {
    let stream = frame.stream_id;
    let ack = frame.flags & 1 != 0;
    match (kind, stream, payload.len()) {
        (0, 1.., _) => frame
            .fields
            .push(("data_bytes", unpad(payload, frame.flags)?.len() as u32)),
        (2, 1.., 5) => priority(frame, payload),
        (3, 1.., 4) => frame.fields.push(("error_code", be32(payload, 0))),
        (4, 0, 0) => {}
        (4, 0, len) if !ack && len.is_multiple_of(6) => {
            for setting in payload.chunks_exact(6).take(32) {
                let name = match be16(setting, 0) {
                    1 => "HEADER_TABLE_SIZE",
                    2 => "ENABLE_PUSH",
                    3 => "MAX_CONCURRENT_STREAMS",
                    4 => "INITIAL_WINDOW_SIZE",
                    5 => "MAX_FRAME_SIZE",
                    6 => "MAX_HEADER_LIST_SIZE",
                    8 => "ENABLE_CONNECT_PROTOCOL",
                    9 => "NO_RFC7540_PRIORITIES",
                    _ => {
                        frame
                            .fields
                            .push(("setting_id", u32::from(be16(setting, 0))));
                        "setting_value"
                    }
                };
                frame.fields.push((name, be32(setting, 2)));
            }
            if len / 6 > 32 {
                frame.issue = Some("settings_limit");
            }
        }
        (6, 0, 8) => {}
        (7, 0, 8..) => {
            frame
                .fields
                .push(("last_stream", be32(payload, 0) & STREAM_MASK));
            frame.fields.push(("error_code", be32(payload, 4)));
        }
        (8, _, 4) if be32(payload, 0) & STREAM_MASK != 0 => {
            frame
                .fields
                .push(("window_increment", be32(payload, 0) & STREAM_MASK));
        }
        (0..=9, _, _) => return None,
        _ => {}
    }
    Some(())
}

fn frame_name(kind: u8) -> &'static str {
    match kind {
        0 => "DATA",
        1 => "HEADERS",
        2 => "PRIORITY",
        3 => "RST_STREAM",
        4 => "SETTINGS",
        5 => "PUSH_PROMISE",
        6 => "PING",
        7 => "GOAWAY",
        8 => "WINDOW_UPDATE",
        9 => "CONTINUATION",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::stream::test_snapshot as snapshot;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() as u32).to_be_bytes();
        [&len[1..], &[kind, flags], &stream.to_be_bytes(), payload].concat()
    }

    #[test]
    fn decodes_multiplexed_exchanges_and_directional_hpack() {
        // RFC 7541 C.4.1, a Huffman-coded authority inserted into the dynamic table.
        let authority = [
            0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let opening = [
            PREFACE,
            &frame(4, 0, 0, &[]),
            &frame(1, 1, 1, &[0x82, 0x86, 0x84]),
        ]
        .concat();
        let continuation = frame(9, 4, 1, &authority);
        let third_stream = frame(1, 5, 3, &[0x82, 0x86, 0x85, 0xbe]);
        let server = [
            frame(4, 0, 0, &[]),
            frame(1, 4, 3, &[0x89]),
            frame(1, 4, 1, &[0x88]),
            frame(0, 9, 1, b"\x02hi\0\0"),
        ]
        .concat();
        let report = analyze(&[
            snapshot(&[&opening[..9], &opening[9..], &continuation, &third_stream]),
            snapshot(&[&server]),
        ])
        .unwrap();
        let [client, server] = report.directions;
        assert_eq!(client.issue, None);
        let first = &client.frames[1];
        assert_eq!((first.stream_id, first.packet), (1, 2));
        assert_eq!(
            first.head.as_ref().unwrap().authority.as_deref(),
            Some("www.example.com")
        );
        let third = &client.frames[3];
        assert_eq!(third.stream_id, 3);
        assert_eq!(
            third.head.as_ref().unwrap().authority.as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            third.head.as_ref().unwrap().path.as_deref(),
            Some("/index.html")
        );
        assert_eq!(
            server.frames[1].head.as_ref().unwrap().status.as_deref(),
            Some("204")
        );
        assert_eq!(server.frames[3].fields, vec![("data_bytes", 2)]);
    }

    #[test]
    fn maps_upgrade_request_to_stream_one() {
        let prior = b"GET /ready HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request = b"POST /upgrade HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABk\r\nContent-Length: 2\r\n\r\nok";
        let switched = b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";
        let client = [request, PREFACE, &frame(4, 0, 0, &[])].concat();
        let server = [
            switched.as_slice(),
            &frame(4, 0, 0, &[]),
            &frame(1, 5, 1, &[0x88]),
        ]
        .concat();
        let report = analyze(&[snapshot(&[prior, &client]), snapshot(&[&server])]).unwrap();
        assert!(report.upgraded);
        let upgrade = &report.directions[0].frames[0];
        assert_eq!(
            (
                upgrade.stream_id,
                upgrade.packet,
                upgrade.offset,
                upgrade.length
            ),
            (1, 2, prior.len(), request.len())
        );
        assert_eq!(
            upgrade.head.as_ref().unwrap().method.as_deref(),
            Some("POST")
        );
        assert_eq!(report.directions[1].frames[1].stream_id, 1);
    }

    #[test]
    fn does_not_resume_hpack_after_missing_or_malformed_fragments() {
        let failed = [
            PREFACE,
            &frame(4, 0, 0, &[]),
            &frame(1, 0, 1, &[0x82]),
            &frame(9, 4, 3, &[0x84]),
            &frame(1, 4, 5, &[0x82]),
        ]
        .concat();
        let report = analyze(&[snapshot(&[&failed]), snapshot(&[])]).unwrap();
        let frames = &report.directions[0].frames;
        assert_eq!(frames[2].issue, Some("interrupted_field_block"));
        assert_eq!(frames[3].issue, Some("hpack_unavailable"));
        assert!(frames.iter().all(|frame| frame.head.is_none()));

        let start = [PREFACE, &frame(4, 0, 0, &[]), &frame(1, 0, 1, &[0x82])].concat();
        let tail = frame(9, 4, 1, &[0x84]);
        let mut stream = snapshot(&[&start, &tail]);
        stream.chunks[1].offset += 1;
        stream.observed_end += 1;
        let report = analyze(&[stream, snapshot(&[])]).unwrap();
        assert_eq!(report.directions[0].issue, Some("stream_gap"));
        assert_eq!(
            report.directions[0].frames[1].issue,
            Some("incomplete_field_block")
        );
    }
}
