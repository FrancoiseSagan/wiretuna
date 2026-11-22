//! QUIC long headers and unprotected fields. Packet numbers are protected.

use std::{fmt, ops::Range};

use super::{Decoder, Protocol, be32};

const V1: u32 = 1;
const V2: u32 = 0x6b33_43cf;
const MAX_PACKETS: usize = 16;
const MAX_VERSIONS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    VersionNegotiation,
    UnknownVersion,
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::VersionNegotiation => "Version Negotiation",
            Self::UnknownVersion => "Long Header (unknown version)",
            Self::Initial => "Initial",
            Self::ZeroRtt => "0-RTT",
            Self::Handshake => "Handshake",
            Self::Retry => "Retry",
        }
    }
}

struct Header {
    kind: Kind,
    version: u32,
    dcid: Range<usize>,
    scid: Range<usize>,
}

impl Header {
    fn read(bytes: &[u8], standard_port: bool) -> Option<Self> {
        let first = *bytes.first()?;
        if first & 0x80 == 0 || bytes.len() < 7 {
            return None;
        }
        let version = be32(bytes, 1);
        let known = matches!(version, V1 | V2);
        if !known && !standard_port {
            return None;
        }
        let dcid = 6..6 + usize::from(bytes[5]);
        let scid_len = usize::from(*bytes.get(dcid.end)?);
        let scid = dcid.end + 1..dcid.end + 1 + scid_len;
        if scid.end > bytes.len() || (known && (dcid.len() > 20 || scid.len() > 20)) {
            return None;
        }
        let mut packet_type = (first >> 4) & 3;
        if version == V2 {
            packet_type = packet_type.wrapping_sub(1) & 3;
        }
        let kind = match (version, packet_type) {
            (0, _) => Kind::VersionNegotiation,
            (_, _) if !known => Kind::UnknownVersion,
            (_, 0) => Kind::Initial,
            (_, 1) => Kind::ZeroRtt,
            (_, 2) => Kind::Handshake,
            _ => Kind::Retry,
        };
        Some(Self {
            kind,
            version,
            dcid,
            scid,
        })
    }
}

impl Decoder {
    pub(super) fn quic(
        &mut self,
        mut bytes: &[u8],
        mut offset: usize,
        mut expected: usize,
        standard_port: bool,
    ) {
        for _ in 0..MAX_PACKETS {
            let Some(header) = Header::read(bytes, standard_port) else {
                return;
            };
            let cursor = header.scid.end;
            let remainder = expected - cursor;
            if (header.kind == Kind::VersionNegotiation
                && (remainder == 0 || !remainder.is_multiple_of(4)))
                || (header.kind == Kind::Retry && remainder <= 16)
            {
                return;
            }
            self.layer(Protocol::Quic);
            // Classification needs only the first header. Decode coalesced packets on demand.
            if self.layers.is_none() {
                return;
            }
            self.field("quic.type", header.kind.name(), offset, 1);
            self.field(
                "quic.version",
                format_args!("{:#010x}", header.version),
                offset + 1,
                4,
            );
            self.quic_cid("quic.dcid", bytes, offset, &header.dcid);
            self.quic_cid("quic.scid", bytes, offset, &header.scid);
            match header.kind {
                Kind::VersionNegotiation => {
                    for (i, version) in bytes[cursor..]
                        .chunks_exact(4)
                        .take(MAX_VERSIONS)
                        .enumerate()
                    {
                        self.field(
                            "quic.supported_version",
                            format_args!("{:#010x}", be32(version, 0)),
                            offset + cursor + i * 4,
                            4,
                        );
                    }
                    if remainder / 4 > MAX_VERSIONS {
                        self.issue("QUIC version list limit reached");
                    }
                    return;
                }
                Kind::Retry => {
                    let token = remainder - 16;
                    if bytes.len() == expected {
                        self.field("quic.retry_token_length", token, offset + cursor, token);
                    }
                    return;
                }
                Kind::UnknownVersion => return,
                _ => {}
            }
            let Some(end) = self.quic_packet_end(&header, bytes, offset, expected) else {
                return;
            };
            bytes = &bytes[end..];
            offset += end;
            expected -= end;
            if bytes.first().is_none_or(|first| first & 0x80 == 0) {
                return;
            }
        }
        self.issue("QUIC coalesced packet limit reached");
    }

    fn quic_cid(&mut self, key: &'static str, bytes: &[u8], offset: usize, range: &Range<usize>) {
        self.field(
            key,
            ConnectionId(&bytes[range.clone()]),
            offset + range.start,
            range.len(),
        );
    }

    fn quic_packet_end(
        &mut self,
        header: &Header,
        bytes: &[u8],
        offset: usize,
        expected: usize,
    ) -> Option<usize> {
        let mut cursor = header.scid.end;
        if header.kind == Kind::Initial {
            let (token, width) = self.quic_length(bytes, offset, cursor, "quic.token_length")?;
            cursor += width;
            if token > bytes.len() - cursor {
                self.issue("incomplete QUIC Initial token");
                return None;
            }
            cursor += token;
        }
        let (length, width) = self.quic_length(bytes, offset, cursor, "quic.protected_length")?;
        cursor += width;
        if length < 20 || length > expected - cursor {
            self.issue("invalid QUIC protected length");
            return None;
        }
        let end = cursor + length;
        if end > bytes.len() {
            self.issue("incomplete QUIC protected payload");
            return None;
        }
        Some(end)
    }

    fn quic_length(
        &mut self,
        bytes: &[u8],
        offset: usize,
        cursor: usize,
        key: &'static str,
    ) -> Option<(usize, usize)> {
        let Some((value, width)) = varint(&bytes[cursor..]) else {
            self.issue("incomplete QUIC variable-length integer");
            return None;
        };
        self.field(key, value, offset + cursor, width);
        // Values larger than an addressable slice can never fit this datagram.
        Some((usize::try_from(value).unwrap_or(usize::MAX), width))
    }
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let width = 1 << (first >> 6);
    let rest = bytes.get(1..width)?;
    let value = rest.iter().fold(u64::from(first & 0x3f), |value, byte| {
        (value << 8) | u64::from(*byte)
    });
    Some((value, width))
}

struct ConnectionId<'a>(&'a [u8]);

impl fmt::Display for ConnectionId<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return formatter.write_str("—");
        }
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
