use std::{io, sync::Arc};

use crate::packet::{PacketRecord, TimestampResolution};

use super::MAX_PACKET_BYTES;

/// A validated classic pcap snapshot, encoded one record at a time.
pub struct PcapExport {
    header: Option<[u8; 24]>,
    packets: std::vec::IntoIter<Arc<PacketRecord>>,
    timestamps: TimestampResolution,
    file_size: u64,
}

impl PcapExport {
    pub fn new(packets: Vec<Arc<PacketRecord>>) -> io::Result<Self> {
        let first = packets
            .first()
            .ok_or_else(|| invalid("No packets to export."))?;
        let mut timestamps = TimestampResolution::Microseconds;
        let mut snaplen = 1;
        let mut file_size = 24;
        for packet in &packets {
            if packet.link_type() != first.link_type()
                || packet.interface_id() != first.interface_id()
            {
                return Err(invalid(
                    "Classic pcap export requires one interface and link type.",
                ));
            }
            if packet.fcs_length() != first.fcs_length() {
                return Err(invalid(
                    "Classic pcap export requires consistent frame check sequence metadata.",
                ));
            }
            let timestamp = packet.timestamp().ok_or_else(|| {
                invalid("Classic pcap export requires a timestamp for every packet.")
            })?;
            if u32::try_from(timestamp.seconds()).is_err() {
                return Err(invalid(
                    "A packet timestamp is outside the classic pcap range.",
                ));
            }
            if timestamp.resolution() == TimestampResolution::Nanoseconds {
                timestamps = TimestampResolution::Nanoseconds;
            }
            snaplen = snaplen.max(packet.captured_len());
            file_size += 16 + u64::from(packet.captured_len());
        }
        if snaplen > MAX_PACKET_BYTES {
            return Err(invalid(
                "A packet exceeds the supported classic pcap record limit.",
            ));
        }

        let mut link = u32::from(first.link_type().0);
        if let Some(length) = first.fcs_length() {
            link |= (1 << 26) | (u32::from(length / 2) << 28);
        }
        let magic: u32 = match timestamps {
            TimestampResolution::Microseconds => 0xa1b2_c3d4,
            TimestampResolution::Nanoseconds => 0xa1b2_3c4d,
        };
        let mut header = [0; 24];
        header[..4].copy_from_slice(&magic.to_le_bytes());
        header[4..6].copy_from_slice(&2u16.to_le_bytes());
        header[6..8].copy_from_slice(&4u16.to_le_bytes());
        header[16..20].copy_from_slice(&snaplen.to_le_bytes());
        header[20..].copy_from_slice(&link.to_le_bytes());
        Ok(Self {
            header: Some(header),
            packets: packets.into_iter(),
            timestamps,
            file_size,
        })
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }
}

impl Iterator for PcapExport {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if let Some(header) = self.header.take() {
            return Some(header.to_vec());
        }
        let packet = self.packets.next()?;
        // The constructor has validated the timestamp and its range.
        let timestamp = packet.timestamp().unwrap();
        let fraction = match self.timestamps {
            TimestampResolution::Microseconds => timestamp.nanoseconds() / 1000,
            TimestampResolution::Nanoseconds => timestamp.nanoseconds(),
        };
        let mut record = Vec::with_capacity(16 + packet.bytes().len());
        record.extend_from_slice(&(timestamp.seconds() as u32).to_le_bytes());
        record.extend_from_slice(&fraction.to_le_bytes());
        record.extend_from_slice(&packet.captured_len().to_le_bytes());
        record.extend_from_slice(&packet.original_len().to_le_bytes());
        record.extend_from_slice(packet.bytes());
        Some(record)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
