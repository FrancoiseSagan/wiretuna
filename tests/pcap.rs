use std::io::{self, Cursor, Read};

use wiretuna::{
    capture::{PacketSource, SourceEvent, pcap::PcapReader},
    packet::{LinkType, TimestampResolution},
};

fn header(little: bool, resolution: TimestampResolution, snaplen: u32, link_info: u32) -> Vec<u8> {
    let magic: u32 = match resolution {
        TimestampResolution::Microseconds => 0xa1b2_c3d4,
        TimestampResolution::Nanoseconds => 0xa1b2_3c4d,
    };
    let mut result = Vec::new();
    for word in [
        magic,
        if little { 0x0004_0002 } else { 0x0002_0004 },
        0,
        0,
        snaplen,
        link_info,
    ] {
        result.extend(if little {
            word.to_le_bytes()
        } else {
            word.to_be_bytes()
        });
    }
    result
}

fn record(
    file: &mut Vec<u8>,
    little: bool,
    fraction: u32,
    captured: u32,
    original: u32,
    body: &[u8],
) {
    for word in [1_700_000_000u32, fraction, captured, original] {
        file.extend(if little {
            word.to_le_bytes()
        } else {
            word.to_be_bytes()
        });
    }
    file.extend(body);
}

#[test]
fn reads_all_byte_orders_and_timestamp_resolutions() {
    use TimestampResolution::{Microseconds, Nanoseconds};

    for little in [true, false] {
        for resolution in [Microseconds, Nanoseconds] {
            let mut file = header(little, resolution, 65535, 0x2400_f123);
            record(&mut file, little, 123_456, 3, 5, &[1, 2, 3]);
            record(&mut file, little, 654_321, 2, 2, &[4, 5]);

            let mut reader = PcapReader::new(Cursor::new(file)).unwrap();
            assert_eq!(reader.header().link_type, LinkType(0xf123));
            assert_eq!(reader.header().fcs_length, Some(4));
            assert_eq!(reader.header().timestamp_resolution, resolution);
            let SourceEvent::Packet(first) = reader.next_packet().unwrap() else {
                panic!("expected first packet");
            };
            assert_eq!(first.bytes(), &[1, 2, 3]);
            assert_eq!(first.original_len(), 5);
            assert!(first.is_truncated());
            let time = first.timestamp().unwrap();
            assert_eq!(time.seconds(), 1_700_000_000);
            assert_eq!(
                time.nanoseconds(),
                if resolution == Microseconds {
                    123_456_000
                } else {
                    123_456
                }
            );
            let SourceEvent::Packet(second) = reader.next_packet().unwrap() else {
                panic!("expected second packet");
            };
            assert_eq!(second.bytes(), &[4, 5]);
            assert!(!second.is_truncated());
            assert_eq!(reader.next_packet().unwrap(), SourceEvent::End);
            assert_eq!(reader.next_packet().unwrap(), SourceEvent::End);
        }
    }
}

#[test]
fn distinguishes_clean_end_from_incomplete_headers_and_payloads() {
    let file = header(true, TimestampResolution::Microseconds, 32, 1);
    assert_eq!(
        PcapReader::new(file.as_slice())
            .unwrap()
            .next_packet()
            .unwrap(),
        SourceEvent::End
    );
    for len in [0, 3, 4, 12, 23] {
        let error = PcapReader::new(&file[..len])
            .err()
            .expect("expected incomplete file header");
        assert_eq!(error.offset(), len as u64);
    }
    let mut file = file;
    record(&mut file, true, 0, 3, 3, &[1, 2, 3]);
    for len in [25, 39, 40, 42] {
        let error = PcapReader::new(&file[..len])
            .unwrap()
            .next_packet()
            .unwrap_err();
        assert_eq!(error.offset(), len as u64);
    }
}

#[test]
fn checks_lengths_before_reading_packet_data() {
    use TimestampResolution::Microseconds;

    for (snaplen, captured, original, expected) in [
        (32, 20, 10, "original length 10"),
        (32, 33, 33, "limit 32"),
        (u32::MAX, u32::MAX, u32::MAX, "limit 1048576"),
    ] {
        let mut file = header(false, Microseconds, snaplen, 1);
        record(&mut file, false, 0, captured, original, &[]);
        let mut reader = PcapReader::new(file.as_slice()).unwrap();
        let error = reader.next_packet().unwrap_err();
        assert_eq!(error.offset(), 32);
        assert!(error.to_string().contains(expected));
        assert_eq!(reader.next_packet().unwrap(), SourceEvent::End);
    }
}

#[test]
fn rejects_invalid_timestamp_fraction() {
    let mut file = header(true, TimestampResolution::Microseconds, 32, 1);
    record(&mut file, true, 1_000_000, 0, 0, &[]);
    let error = PcapReader::new(file.as_slice())
        .unwrap()
        .next_packet()
        .unwrap_err();
    assert_eq!(error.offset(), 28);
}

#[test]
fn accepts_fragmented_io_and_retries_interrupted_reads() {
    struct OneByteAtATime<'a> {
        bytes: &'a [u8],
        interrupt: bool,
    }

    impl Read for OneByteAtATime<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }

            let limit = buffer.len().min(1);
            self.bytes.read(&mut buffer[..limit])
        }
    }

    let mut file = header(true, TimestampResolution::Microseconds, 32, 1);
    record(&mut file, true, 0, 1, 1, &[42]);
    let input = OneByteAtATime {
        bytes: &file,
        interrupt: false,
    };
    let mut reader = PcapReader::new(input).unwrap();
    let SourceEvent::Packet(packet) = reader.next_packet().unwrap() else {
        panic!("expected packet");
    };
    assert_eq!(packet.bytes(), &[42]);
    assert_eq!(reader.next_packet().unwrap(), SourceEvent::End);
}
