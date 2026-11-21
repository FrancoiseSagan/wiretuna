use std::sync::Arc;

use wiretuna::{
    capture::{
        PacketSource, SourceEvent, offline::OfflineReader, pcap::PcapExport, pcapng::PcapNgReader,
    },
    packet::{LinkType, PacketRecord, TimestampResolution},
};

#[derive(Clone, Copy)]
struct Order(bool);

impl Order {
    const LE: Self = Self(false);
    const BE: Self = Self(true);

    fn u16(self, number: u16) -> [u8; 2] {
        if self.0 {
            number.to_be_bytes()
        } else {
            number.to_le_bytes()
        }
    }

    fn u32(self, number: u32) -> [u8; 4] {
        if self.0 {
            number.to_be_bytes()
        } else {
            number.to_le_bytes()
        }
    }

    fn i64(self, number: i64) -> [u8; 8] {
        if self.0 {
            number.to_be_bytes()
        } else {
            number.to_le_bytes()
        }
    }

    fn block(self, kind: u32, contents: &[u8]) -> Vec<u8> {
        assert!(contents.len().is_multiple_of(4));
        let length = (contents.len() + 12) as u32;
        let mut block = Vec::new();
        block.extend(self.u32(kind));
        block.extend(self.u32(length));
        block.extend(contents);
        block.extend(self.u32(length));
        block
    }

    fn section(self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(self.u32(0x1a2b3c4d));
        body.extend(self.u16(1));
        body.extend(self.u16(0));
        body.extend(self.i64(-1));
        self.block(0x0a0d0d0a, &body)
    }

    fn interface(self, link: u16, snaplen: u32, options: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(self.u16(link));
        body.extend(self.u16(0));
        body.extend(self.u32(snaplen));
        for &(code, value) in options {
            body.extend(self.u16(code));
            body.extend(self.u16(value.len() as u16));
            body.extend(value);
            pad(&mut body);
        }
        if !options.is_empty() {
            body.extend([0; 4]);
        }
        self.block(1, &body)
    }

    fn enhanced(self, interface: u32, ticks: u64, original: u32, bytes: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for field in [
            interface,
            (ticks >> 32) as u32,
            ticks as u32,
            bytes.len() as u32,
            original,
        ] {
            body.extend(self.u32(field));
        }
        body.extend(bytes);
        pad(&mut body);
        self.block(6, &body)
    }
}

fn pad(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}

fn next(source: &mut impl PacketSource) -> PacketRecord {
    let SourceEvent::Packet(packet) = source.next_packet().unwrap() else {
        panic!("expected packet");
    };
    packet
}

#[test]
fn reads_multiple_interfaces_and_resets_indices_on_new_sections() {
    let (le, be) = (Order::LE, Order::BE);
    let mut file = le.section();
    file.extend(le.interface(1, 3, &[]));
    file.extend(le.interface(101, 0, &[(9, &[9]), (14, &le.i64(-2))]));
    file.extend(le.enhanced(1, 3_000_000_012, 3, b"abc"));
    file.extend(le.block(0x101, b"skip"));
    file.extend(le.block(3, &[9, 0, 0, 0, 4, 5, 6, 0]));
    let mut second_section = be.section();
    second_section[14..16].copy_from_slice(&be.u16(2));
    file.extend(second_section);
    file.extend(be.interface(1, 0, &[(9, &[0x8a])]));
    file.extend(be.enhanced(0, 1025, 2, b"xy"));

    let mut reader = OfflineReader::new(file.as_slice()).unwrap();
    assert!(reader.classic_header().is_none());

    let first = next(&mut reader);
    let timestamp = first.timestamp().unwrap();
    assert_eq!(
        (first.interface_id(), first.link_type()),
        (1, LinkType(101))
    );
    assert_eq!((timestamp.seconds(), timestamp.nanoseconds()), (1, 12));
    assert_eq!(timestamp.resolution(), TimestampResolution::Nanoseconds);

    let simple = next(&mut reader);
    assert_eq!(
        (
            simple.interface_id(),
            simple.captured_len(),
            simple.original_len()
        ),
        (0, 3, 9)
    );
    assert_eq!(simple.timestamp(), None);

    let last = next(&mut reader);
    let timestamp = last.timestamp().unwrap();
    assert_eq!(last.interface_id(), 2);
    assert_eq!((timestamp.seconds(), timestamp.nanoseconds()), (1, 976_562));
    assert_eq!(timestamp.resolution(), TimestampResolution::Binary(10));
    assert!(PcapExport::new(vec![Arc::new(last)]).is_err());
    assert_eq!(reader.next_packet().unwrap(), SourceEvent::End);
    assert_eq!(reader.interface_count(), 3);
}

#[test]
fn rejects_missing_interfaces_and_bad_block_lengths() {
    let order = Order::LE;
    let section = order.section();
    let mut missing = section.clone();
    missing.extend(order.enhanced(1, 0, 1, b"x"));
    let mut reader = PcapNgReader::new(missing.as_slice()).unwrap();
    assert!(
        reader
            .next_packet()
            .unwrap_err()
            .to_string()
            .contains("unknown packet interface")
    );
    assert_eq!(reader.next_packet().unwrap(), SourceEvent::End);

    let mut bad = section.clone();
    bad.extend(order.interface(1, 0, &[]));
    *bad.last_mut().unwrap() = 1;
    let mut reader = PcapNgReader::new(bad.as_slice()).unwrap();
    let error = reader.next_packet().unwrap_err();
    assert_eq!(error.offset(), (bad.len() - 4) as u64);
    assert!(error.to_string().starts_with("pcapng at byte "));

    let mut oversized = section;
    oversized.extend(order.u32(1));
    oversized.extend(order.u32(16 * 1024 * 1024 + 4));
    let mut reader = PcapNgReader::new(oversized.as_slice()).unwrap();
    assert!(
        reader
            .next_packet()
            .unwrap_err()
            .to_string()
            .contains("block exceeds 16 MiB")
    );
}

#[test]
fn rejects_options_with_missing_padding_and_handles_finer_decimal_ticks() {
    let order = Order::LE;
    let mut file = order.section();
    let mut bad_option = order.interface(1, 0, &[]);
    bad_option.truncate(16);
    bad_option[4..8].copy_from_slice(&24u32.to_le_bytes());
    bad_option.extend([9, 0, 1, 0]);
    bad_option.extend(24u32.to_le_bytes());
    file.extend(bad_option);
    let mut reader = PcapNgReader::new(file.as_slice()).unwrap();
    assert!(
        reader
            .next_packet()
            .unwrap_err()
            .to_string()
            .contains("padding")
    );

    let mut file = order.section();
    file.extend(order.interface(1, 0, &[(9, &[38]), (14, &order.i64(-1))]));
    file.extend(order.enhanced(0, 1, 1, b"a"));
    let packet = next(&mut PcapNgReader::new(file.as_slice()).unwrap());
    let timestamp = packet.timestamp().unwrap();
    assert_eq!((timestamp.seconds(), timestamp.nanoseconds()), (-1, 0));
    assert_eq!(timestamp.resolution(), TimestampResolution::Decimal(38));
}
