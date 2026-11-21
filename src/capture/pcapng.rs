//! Streaming reader and exporter for pcapng 1.0.

mod export;
pub use export::PcapNgExport;

use std::io::Read;

use super::{
    PacketSource, SourceEvent,
    file::{ByteOrder, CaptureFileError, MAX_PACKET_BYTES, read_field},
};
use crate::packet::{
    LinkType, PacketRecord, PcapNgInterface, PcapNgOrigin, Timestamp, TimestampResolution,
};

pub(super) const SECTION_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;
const MAX_SECTION_INTERFACES: usize = 65_536;

#[derive(Clone, Copy)]
struct Interface {
    id: u32,
    link: LinkType,
    metadata: PcapNgInterface,
}

impl Interface {
    fn packet_limit(self) -> u32 {
        if self.metadata.snaplen == 0 {
            u32::MAX
        } else {
            self.metadata.snaplen
        }
    }

    fn packet(
        self,
        captured: u32,
        original: u32,
        data: &[u8],
        ticks: Option<u64>,
        fcs_override: Option<u8>,
    ) -> Result<PacketRecord, &'static str> {
        if captured > MAX_PACKET_BYTES || captured > self.packet_limit() || captured > original {
            return Err("invalid captured packet length");
        }
        let payload = data
            .get(..captured as usize)
            .ok_or("incomplete packet data")?;
        let timestamp = match ticks {
            Some(ticks) => Some(
                Timestamp::from_ticks(ticks, self.metadata.time_offset, self.metadata.resolution)
                    .ok_or("packet timestamp is outside the supported range")?,
            ),
            None => None,
        };
        let fcs_length = fcs_override.or_else(|| {
            self.metadata
                .fcs_bits
                .filter(|bits| bits.is_multiple_of(8))
                .map(|bits| bits / 8)
        });
        PacketRecord::new(self.id, self.link, timestamp, original, payload.into())
            .map(|packet| {
                packet
                    .with_fcs_length(fcs_length)
                    .with_pcapng_origin(PcapNgOrigin {
                        interface: self.metadata,
                        ticks,
                    })
            })
            .map_err(|_| "invalid captured packet length")
    }
}

pub struct PcapNgReader<R> {
    input: R,
    offset: u64,
    order: ByteOrder,
    interfaces: Vec<Interface>,
    next_interface: u64,
    section_number: u64,
    body: Vec<u8>,
    finished: bool,
}

impl<R: Read> PcapNgReader<R> {
    pub fn new(input: R) -> Result<Self, CaptureFileError> {
        let mut reader = Self {
            input,
            offset: 0,
            order: ByteOrder::Little,
            interfaces: Vec::new(),
            next_interface: 0,
            section_number: 0,
            body: Vec::new(),
            finished: false,
        };
        let mut magic = [0; 4];
        reader.read(&mut magic, "section magic", false)?;
        if magic != SECTION_MAGIC {
            return Err(invalid(0, "expected a Section Header Block"));
        }
        reader.section(0)?;
        Ok(reader)
    }

    pub fn interface_count(&self) -> u64 {
        self.next_interface
    }

    fn section(&mut self, start: u64) -> Result<(), CaptureFileError> {
        let mut header = [0; 8];
        self.read(&mut header, "section header", false)?;
        self.order = match header[4..] {
            [0x1a, 0x2b, 0x3c, 0x4d] => ByteOrder::Big,
            [0x4d, 0x3c, 0x2b, 0x1a] => ByteOrder::Little,
            _ => return Err(invalid(start + 8, "invalid byte-order magic")),
        };
        let length = self.order.u32(header[..4].try_into().unwrap()) as usize;
        self.block_body(start, length, 28, 16)?;
        let version = (
            u16_at(self.order, &self.body, 0),
            u16_at(self.order, &self.body, 2),
        );
        // Legacy writers emitted 1.2 without an incompatible format change.
        if !matches!(version, (1, 0 | 2)) {
            return Err(invalid(
                start + 12,
                format!("unsupported section version {}.{}", version.0, version.1),
            ));
        }
        for option in Options::new(&self.body[12..], self.order) {
            option.map_err(|error| invalid(start + 24, error))?;
        }
        self.interfaces.clear();
        Ok(())
    }

    fn read_packet(&mut self) -> Result<SourceEvent, CaptureFileError> {
        loop {
            let start = self.offset;
            let mut kind = [0; 4];
            if !self.read(&mut kind, "block type", true)? {
                return Ok(SourceEvent::End);
            }
            if kind == SECTION_MAGIC {
                self.section(start)?;
                self.section_number += 1;
                continue;
            }
            let kind = self.order.u32(kind);
            let mut length = [0; 4];
            self.read(&mut length, "block length", false)?;
            let length = self.order.u32(length) as usize;
            let minimum = match kind {
                1 => 20,
                3 => 16,
                6 => 32,
                _ => 12,
            };
            self.block_body(start, length, minimum, 12)?;
            match kind {
                1 => self
                    .add_interface()
                    .map_err(|error| invalid(start + 8, error))?,
                3 | 6 => {
                    return self
                        .packet(kind)
                        .map(SourceEvent::Packet)
                        .map_err(|error| invalid(start + 8, error));
                }
                // An obsolete Packet Block still contains capture data, so report it explicitly.
                2 => return Err(invalid(start, "obsolete Packet Blocks are not supported")),
                _ => {}
            }
        }
    }

    fn add_interface(&mut self) -> Result<(), &'static str> {
        if self.interfaces.len() == MAX_SECTION_INTERFACES {
            return Err("too many interfaces in section");
        }
        let id = u32::try_from(self.next_interface).map_err(|_| "too many interfaces in file")?;
        let mut interface = Interface {
            id,
            link: LinkType(u16_at(self.order, &self.body, 0)),
            metadata: PcapNgInterface {
                section: self.section_number,
                snaplen: u32_at(self.order, &self.body, 4),
                resolution: TimestampResolution::Microseconds,
                time_offset: 0,
                fcs_bits: None,
            },
        };
        for option in Options::new(&self.body[8..], self.order) {
            match option? {
                (9, [6]) => interface.metadata.resolution = TimestampResolution::Microseconds,
                (9, [9]) => interface.metadata.resolution = TimestampResolution::Nanoseconds,
                (9, [value]) if value & 0x80 == 0 => {
                    interface.metadata.resolution = TimestampResolution::Decimal(*value)
                }
                (9, [value]) => {
                    interface.metadata.resolution = TimestampResolution::Binary(value & 0x7f)
                }
                (13, [bits]) => interface.metadata.fcs_bits = Some(*bits),
                (14, value) if value.len() == 8 => {
                    interface.metadata.time_offset = self.order.i64(value.try_into().unwrap());
                }
                (9 | 13 | 14, _) => return Err("invalid interface option length"),
                _ => {}
            }
        }
        self.interfaces.push(interface);
        self.next_interface += 1;
        Ok(())
    }

    fn packet(&self, kind: u32) -> Result<PacketRecord, &'static str> {
        let order = self.order;
        if kind == 3 {
            let interface = self
                .interfaces
                .first()
                .ok_or("missing interface for Simple Packet Block")?;
            let original = u32_at(order, &self.body, 0);
            let captured = original.min(interface.packet_limit());
            let data = &self.body[4..];
            if captured > MAX_PACKET_BYTES || data.len() != padded_len(captured as usize) {
                return Err("invalid Simple Packet Block length");
            }
            return interface.packet(captured, original, data, None, None);
        }

        let index = u32_at(order, &self.body, 0) as usize;
        let interface = *self
            .interfaces
            .get(index)
            .ok_or("unknown packet interface")?;
        let ticks = (u64::from(u32_at(order, &self.body, 4)) << 32)
            | u64::from(u32_at(order, &self.body, 8));
        let captured = u32_at(order, &self.body, 12);
        if captured > MAX_PACKET_BYTES {
            return Err("packet exceeds the capture size limit");
        }
        let original = u32_at(order, &self.body, 16);
        let options_at = 20 + padded_len(captured as usize);
        let options = self
            .body
            .get(options_at..)
            .ok_or("incomplete Enhanced Packet Block data or padding")?;
        let mut fcs_override = None;
        for option in Options::new(options, order) {
            match option? {
                (2, flags) if flags.len() == 4 => {
                    let length = ((u32_at(order, flags, 0) >> 5) & 0xf) as u8;
                    if length != 0 {
                        fcs_override = Some(length);
                    }
                }
                (2, _) => return Err("invalid packet flags option length"),
                _ => {}
            }
        }
        interface.packet(
            captured,
            original,
            &self.body[20..options_at],
            Some(ticks),
            fcs_override,
        )
    }

    fn block_body(
        &mut self,
        start: u64,
        length: usize,
        minimum: usize,
        overhead: usize,
    ) -> Result<(), CaptureFileError> {
        if length < minimum || length > MAX_BLOCK_BYTES || !length.is_multiple_of(4) {
            return Err(invalid(
                start + 4,
                "invalid block length or block exceeds 16 MiB",
            ));
        }
        self.body.resize(length - overhead, 0);
        read_field(
            &mut self.input,
            &mut self.offset,
            &mut self.body,
            "block data",
            false,
        )
        .map_err(CaptureFileError::pcapng)?;
        let mut tail = [0; 4];
        self.read(&mut tail, "trailing block length", false)?;
        if self.order.u32(tail) as usize != length {
            return Err(invalid(self.offset - 4, "block lengths do not match"));
        }
        Ok(())
    }

    fn read(
        &mut self,
        buf: &mut [u8],
        label: &str,
        clean_end: bool,
    ) -> Result<bool, CaptureFileError> {
        read_field(&mut self.input, &mut self.offset, buf, label, clean_end)
            .map_err(CaptureFileError::pcapng)
    }
}

impl<R: Read> PacketSource for PcapNgReader<R> {
    type Error = CaptureFileError;

    fn next_packet(&mut self) -> Result<SourceEvent, Self::Error> {
        if self.finished {
            return Ok(SourceEvent::End);
        }
        let result = self.read_packet();
        self.finished = !matches!(&result, Ok(SourceEvent::Packet(_)));
        result
    }
}

struct Options<'a> {
    remaining: &'a [u8],
    order: ByteOrder,
}

impl<'a> Options<'a> {
    fn new(remaining: &'a [u8], order: ByteOrder) -> Self {
        Self { remaining, order }
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = Result<(u16, &'a [u8]), &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        let input = std::mem::take(&mut self.remaining);
        if input.is_empty() {
            return None;
        }
        if input.len() < 4 {
            return Some(Err("incomplete block option"));
        }
        let kind = u16_at(self.order, input, 0);
        let length = usize::from(u16_at(self.order, input, 2));
        if kind == 0 {
            return if length == 0 && input.len() == 4 {
                None
            } else {
                Some(Err("invalid end-of-options marker"))
            };
        }
        let (value, rest) = match input[4..].split_at_checked(padded_len(length)) {
            Some(parts) => parts,
            None => return Some(Err("incomplete block option data or padding")),
        };
        self.remaining = rest;
        Some(Ok((kind, &value[..length])))
    }
}

fn padded_len(length: usize) -> usize {
    length + ((4 - length % 4) % 4)
}
fn u16_at(order: ByteOrder, bytes: &[u8], offset: usize) -> u16 {
    order.u16(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(order: ByteOrder, bytes: &[u8], offset: usize) -> u32 {
    order.u32(bytes[offset..offset + 4].try_into().unwrap())
}
fn invalid(offset: u64, message: impl Into<String>) -> CaptureFileError {
    CaptureFileError::invalid(offset, message).pcapng()
}
