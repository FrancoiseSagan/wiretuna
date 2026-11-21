//! Streaming reader and exporter for classic pcap 2.4 files.

mod export;
pub use export::PcapExport;

use std::{
    error::Error,
    fmt,
    io::{self, Read},
};

use super::{PacketSource, SourceEvent};
use crate::packet::{LinkType, PacketRecord, Timestamp, TimestampResolution};

const MAX_PACKET_BYTES: u32 = 1024 * 1024;

#[derive(Clone, Copy)]
enum ByteOrder {
    Big,
    Little,
}

impl ByteOrder {
    fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Big => u16::from_be_bytes(bytes),
            Self::Little => u16::from_le_bytes(bytes),
        }
    }

    fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Big => u32::from_be_bytes(bytes),
            Self::Little => u32::from_le_bytes(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapHeader {
    pub snaplen: u32,
    pub link_type: LinkType,
    pub timestamp_resolution: TimestampResolution,
    /// Length of the frame check sequence in bytes, if declared by the file.
    pub fcs_length: Option<u8>,
}

pub struct PcapReader<R> {
    input: R,
    offset: u64,
    order: ByteOrder,
    header: PcapHeader,
    finished: bool,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut input: R) -> Result<Self, PcapError> {
        use ByteOrder::{Big, Little};
        use TimestampResolution::{Microseconds, Nanoseconds};

        let mut bytes = [0; 24];
        let mut offset = 0;
        let (magic, rest) = bytes.split_at_mut(4);
        read_field(&mut input, &mut offset, magic, "file magic", false)?;
        let (order, timestamp_resolution) = match magic {
            [0xa1, 0xb2, 0xc3, 0xd4] => (Big, Microseconds),
            [0xd4, 0xc3, 0xb2, 0xa1] => (Little, Microseconds),
            [0xa1, 0xb2, 0x3c, 0x4d] => (Big, Nanoseconds),
            [0x4d, 0x3c, 0xb2, 0xa1] => (Little, Nanoseconds),
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                return Err(PcapError::invalid(0, "pcapng is not supported"));
            }
            _ => return Err(PcapError::invalid(0, "unrecognized pcap magic")),
        };
        read_field(&mut input, &mut offset, rest, "file header", false)?;

        let major = order.u16([bytes[4], bytes[5]]);
        let minor = order.u16([bytes[6], bytes[7]]);
        if (major, minor) != (2, 4) {
            return Err(PcapError::invalid(
                4,
                format!("unsupported pcap version {major}.{minor}"),
            ));
        }

        let snaplen = order.u32(bytes[16..20].try_into().unwrap());
        if snaplen == 0 {
            return Err(PcapError::invalid(16, "snapshot length is zero"));
        }
        let link_info = order.u32(bytes[20..24].try_into().unwrap());
        // The remaining high bits are reserved. Keep the defined link type and FCS metadata.
        let link_type = LinkType(link_info as u16);
        let fcs_length = (link_info & (1 << 26) != 0).then_some(((link_info >> 28) as u8) * 2);
        Ok(Self {
            input,
            offset,
            order,
            header: PcapHeader {
                snaplen,
                link_type,
                timestamp_resolution,
                fcs_length,
            },
            finished: false,
        })
    }

    pub fn header(&self) -> PcapHeader {
        self.header
    }

    fn read_record(&mut self) -> Result<SourceEvent, PcapError> {
        let start = self.offset;
        let mut header = [0; 16];
        if !read_field(
            &mut self.input,
            &mut self.offset,
            &mut header,
            "packet header",
            true,
        )? {
            return Ok(SourceEvent::End);
        }

        let seconds = self.order.u32(header[..4].try_into().unwrap());
        let fraction = self.order.u32(header[4..8].try_into().unwrap());
        let captured = self.order.u32(header[8..12].try_into().unwrap());
        let original = self.order.u32(header[12..].try_into().unwrap());

        let timestamp = Timestamp::from_fraction(
            i64::from(seconds),
            fraction,
            self.header.timestamp_resolution,
        )
        .ok_or_else(|| {
            PcapError::invalid(start + 4, "timestamp fraction exceeds its resolution")
        })?;
        if captured > original {
            return Err(PcapError::invalid(
                start + 8,
                format!("captured length {captured} exceeds original length {original}"),
            ));
        }
        let limit = self.header.snaplen.min(MAX_PACKET_BYTES);
        if captured > limit {
            return Err(PcapError::invalid(
                start + 8,
                format!("captured length {captured} exceeds limit {limit}"),
            ));
        }

        let mut payload = vec![0; captured as usize].into_boxed_slice();
        read_field(
            &mut self.input,
            &mut self.offset,
            &mut payload,
            "packet data",
            false,
        )?;
        PacketRecord::new(0, self.header.link_type, Some(timestamp), original, payload)
            .map(|packet| SourceEvent::Packet(packet.with_fcs_length(self.header.fcs_length)))
            .map_err(|error| PcapError::invalid(start + 8, error.to_string()))
    }
}

impl<R: Read> PacketSource for PcapReader<R> {
    type Error = PcapError;

    /// A read error terminates this stream. Subsequent calls return End.
    fn next_packet(&mut self) -> Result<SourceEvent, Self::Error> {
        if self.finished {
            return Ok(SourceEvent::End);
        }
        let result = self.read_record();
        self.finished = !matches!(&result, Ok(SourceEvent::Packet(_)));
        result
    }
}

fn read_field(
    input: &mut impl Read,
    offset: &mut u64,
    mut bytes: &mut [u8],
    description: &str,
    clean_end_allowed: bool,
) -> Result<bool, PcapError> {
    let start = *offset;
    while !bytes.is_empty() {
        match input.read(bytes) {
            Ok(0) if clean_end_allowed && *offset == start => return Ok(false),
            Ok(0) => {
                return Err(PcapError::invalid(
                    *offset,
                    format!("incomplete {description}"),
                ));
            }
            Ok(n) => {
                *offset += n as u64;
                bytes = &mut bytes[n..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(PcapError {
                    offset: *offset,
                    message: format!("reading {description}"),
                    cause: Some(error),
                });
            }
        }
    }
    Ok(true)
}

#[derive(Debug)]
pub struct PcapError {
    offset: u64,
    message: String,
    cause: Option<io::Error>,
}

impl PcapError {
    fn invalid(offset: u64, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
            cause: None,
        }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }
}

impl fmt::Display for PcapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "pcap at byte {}: {}", self.offset, self.message)?;
        if let Some(cause) = &self.cause {
            write!(formatter, ": {cause}")?;
        }
        Ok(())
    }
}

impl Error for PcapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_ref().map(|cause| cause as &dyn Error)
    }
}
