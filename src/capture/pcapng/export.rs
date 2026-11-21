use std::{
    collections::{BTreeMap, btree_map::Entry},
    io,
    sync::Arc,
};

use crate::packet::{LinkType, PacketRecord, PcapNgInterface, TimestampResolution};

use super::{MAX_PACKET_BYTES, MAX_SECTION_INTERFACES, padded_len};

/// A validated pcapng snapshot. Metadata precedes each section's packet records.
pub struct PcapNgExport {
    blocks: std::vec::IntoIter<Block>,
    file_size: u64,
}

enum Block {
    Metadata(Vec<u8>),
    Packet(PacketBlock),
}

struct PacketBlock {
    packet: Arc<PacketRecord>,
    interface: u32,
    ticks: Option<u64>,
    fcs_override: Option<u8>,
}

#[derive(Clone, Copy)]
struct Interface {
    index: u32,
    link: LinkType,
    original: Option<PcapNgInterface>,
    snaplen: u32,
    resolution: TimestampResolution,
    fcs_bits: Option<u8>,
}

impl Interface {
    fn new(packet: &PacketRecord) -> Self {
        let original = packet.pcapng_origin().map(|origin| origin.interface);
        Self {
            index: 0,
            link: packet.link_type(),
            original,
            snaplen: original.map_or(1, |metadata| metadata.snaplen),
            resolution: original.map_or(TimestampResolution::Microseconds, |metadata| {
                metadata.resolution
            }),
            fcs_bits: original.map_or_else(
                || packet.fcs_length().and_then(|bytes| bytes.checked_mul(8)),
                |metadata| metadata.fcs_bits,
            ),
        }
    }

    fn include(&mut self, packet: &PacketRecord) -> io::Result<()> {
        if self.link != packet.link_type()
            || self.original != packet.pcapng_origin().map(|origin| origin.interface)
        {
            return Err(invalid("A pcapng interface has inconsistent metadata."));
        }
        if packet.captured_len() > MAX_PACKET_BYTES {
            return Err(invalid(
                "A packet exceeds the supported pcapng record limit.",
            ));
        }
        if self.original.is_none() {
            self.snaplen = self.snaplen.max(packet.captured_len());
            if packet
                .timestamp()
                .is_some_and(|time| time.resolution() != TimestampResolution::Microseconds)
            {
                self.resolution = TimestampResolution::Nanoseconds;
            }
        }
        Ok(())
    }

    fn block(self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.link.0.to_le_bytes());
        data.extend_from_slice(&[0; 2]);
        data.extend_from_slice(&self.snaplen.to_le_bytes());
        let resolution = match self.resolution {
            TimestampResolution::Microseconds => 6,
            TimestampResolution::Nanoseconds => 9,
            TimestampResolution::Decimal(exponent) => exponent,
            TimestampResolution::Binary(exponent) => 0x80 | exponent,
        };
        if resolution != 6 {
            append_option(&mut data, 9, &[resolution]);
        }
        if let Some(bits) = self.fcs_bits {
            append_option(&mut data, 13, &[bits]);
        }
        if let Some(metadata) = self.original
            && metadata.time_offset != 0
        {
            append_option(&mut data, 14, &metadata.time_offset.to_le_bytes());
        }
        if data.len() > 8 {
            data.extend_from_slice(&[0; 4]);
        }
        block(1, &data)
    }
}

impl PcapNgExport {
    pub fn new(packets: Vec<Arc<PacketRecord>>) -> io::Result<Self> {
        if packets.is_empty() {
            return Err(invalid("No packets to export."));
        }
        let mut blocks = Vec::with_capacity(packets.len());
        let mut file_size = 0;
        for section in packets.chunk_by(|a, b| section_of(a) == section_of(b)) {
            let (metadata, interfaces) = prepare_section(section)?;
            file_size += metadata.len() as u64;
            blocks.push(Block::Metadata(metadata));
            for packet in section {
                let packet =
                    PacketBlock::new(Arc::clone(packet), interfaces[&packet.interface_id()])?;
                file_size += packet.encoded_len() as u64;
                blocks.push(Block::Packet(packet));
            }
        }
        Ok(Self {
            blocks: blocks.into_iter(),
            file_size,
        })
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }
}

impl Iterator for PcapNgExport {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.blocks.next()? {
            Block::Metadata(bytes) => Some(bytes),
            Block::Packet(packet) => Some(packet.encode()),
        }
    }
}

fn prepare_section(
    packets: &[Arc<PacketRecord>],
) -> io::Result<(Vec<u8>, BTreeMap<u32, Interface>)> {
    let mut interfaces = BTreeMap::new();
    let mut first_interface = None;
    for packet in packets {
        let id = packet.interface_id();
        if packet.timestamp().is_none() && first_interface.replace(id).is_some_and(|old| old != id)
        {
            return Err(invalid(
                "Timestamp-free packets require interface zero in each pcapng section.",
            ));
        }
        let interface = match interfaces.entry(id) {
            Entry::Occupied(found) => found.into_mut(),
            Entry::Vacant(missing) => missing.insert(Interface::new(packet)),
        };
        interface.include(packet)?;
    }
    if interfaces.len() > MAX_SECTION_INTERFACES {
        return Err(invalid("Too many interfaces in a pcapng section."));
    }

    let mut body = Vec::new();
    body.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(-1i64).to_le_bytes());
    let mut metadata = block(0x0a0d_0d0a, &body);

    let first = first_interface.and_then(|id| interfaces.remove_entry(&id));
    let mut next = 0;
    if let Some((_, interface)) = &first {
        metadata.extend(interface.block());
        next = 1;
    }
    for interface in interfaces.values_mut() {
        interface.index = next;
        next += 1;
        metadata.extend(interface.block());
    }
    if let Some((id, interface)) = first {
        interfaces.insert(id, interface);
    }
    Ok((metadata, interfaces))
}

impl PacketBlock {
    fn new(packet: Arc<PacketRecord>, interface: Interface) -> io::Result<Self> {
        let ticks = match (packet.pcapng_origin(), packet.timestamp()) {
            (Some(origin), _) => origin.ticks,
            (None, Some(time)) => {
                let seconds = u64::try_from(time.seconds())
                    .map_err(|_| invalid("A timestamp is outside the pcapng range."))?;
                let (scale, fraction) = match interface.resolution {
                    TimestampResolution::Microseconds => (1_000_000, time.nanoseconds() / 1000),
                    _ => (1_000_000_000, time.nanoseconds()),
                };
                Some(
                    seconds
                        .checked_mul(scale)
                        .and_then(|ticks| ticks.checked_add(u64::from(fraction)))
                        .ok_or_else(|| invalid("A timestamp is outside the pcapng range."))?,
                )
            }
            (None, None) => None,
        };

        // Imported records preserve the original default and any per-packet override.
        let default_fcs = interface
            .fcs_bits
            .filter(|bits| bits.is_multiple_of(8))
            .map(|bits| bits / 8);
        let fcs_override = if packet.fcs_length() == default_fcs {
            None
        } else {
            let length = packet
                .fcs_length()
                .filter(|length| (1..=15).contains(length))
                .ok_or_else(|| {
                    invalid("A frame check sequence cannot be represented by pcapng packet flags.")
                })?;
            Some(length)
        };
        if ticks.is_none() {
            let limit = if interface.snaplen == 0 {
                u32::MAX
            } else {
                interface.snaplen
            };
            if interface.index != 0
                || fcs_override.is_some()
                || packet.captured_len() != limit.min(packet.original_len())
            {
                return Err(invalid(
                    "A timestamp-free packet cannot be represented as a Simple Packet Block.",
                ));
            }
        }
        Ok(Self {
            packet,
            interface: interface.index,
            ticks,
            fcs_override,
        })
    }

    fn encoded_len(&self) -> usize {
        let data = padded_len(self.packet.bytes().len());
        if self.ticks.is_some() {
            32 + data + if self.fcs_override.is_some() { 12 } else { 0 }
        } else {
            16 + data
        }
    }

    fn encode(self) -> Vec<u8> {
        let size = self.encoded_len();
        let kind = if self.ticks.is_some() { 6u32 } else { 3u32 };
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        if let Some(ticks) = self.ticks {
            bytes.extend_from_slice(&self.interface.to_le_bytes());
            bytes.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
            bytes.extend_from_slice(&(ticks as u32).to_le_bytes());
            bytes.extend_from_slice(&self.packet.captured_len().to_le_bytes());
        }
        bytes.extend_from_slice(&self.packet.original_len().to_le_bytes());
        bytes.extend_from_slice(self.packet.bytes());
        bytes.resize(padded_len(bytes.len()), 0);
        if let Some(length) = self.fcs_override {
            append_option(&mut bytes, 2, &(u32::from(length) << 5).to_le_bytes());
            bytes.extend_from_slice(&[0; 4]);
        }
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        bytes
    }
}

fn section_of(packet: &PacketRecord) -> Option<u64> {
    packet
        .pcapng_origin()
        .map(|origin| origin.interface.section)
}

fn append_option(bytes: &mut Vec<u8>, kind: u16, data: &[u8]) {
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bytes.extend_from_slice(data);
    bytes.resize(padded_len(bytes.len()), 0);
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let length = (body.len() + 12) as u32;
    let mut bytes = Vec::with_capacity(length as usize);
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
