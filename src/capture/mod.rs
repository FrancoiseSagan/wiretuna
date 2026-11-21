mod file;
pub use file::CaptureFileError;
#[cfg(all(target_os = "linux", feature = "live-capture"))]
pub mod helper;
#[cfg(all(target_os = "linux", feature = "live-capture"))]
pub mod live;
pub mod offline;
pub mod pcap;
pub mod pcapng;

use crate::packet::PacketRecord;

#[derive(Debug, PartialEq, Eq)]
pub enum SourceEvent {
    Packet(PacketRecord),
    /// A live poll expired. The source can still yield packets.
    Idle,
    /// The source has ended. Successful subsequent reads also return End.
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendStats {
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}

pub trait PacketSource {
    type Error: std::error::Error;

    fn next_packet(&mut self) -> Result<SourceEvent, Self::Error>;

    /// Releases a running source and makes its final backend statistics available.
    fn stop(&mut self) {}

    fn backend_stats(&mut self) -> Option<BackendStats> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, convert::Infallible};

    use super::*;
    use crate::packet::LinkType;

    struct MemorySource(VecDeque<PacketRecord>);

    impl PacketSource for MemorySource {
        type Error = Infallible;

        fn next_packet(&mut self) -> Result<SourceEvent, Self::Error> {
            Ok(self
                .0
                .pop_front()
                .map_or(SourceEvent::End, SourceEvent::Packet))
        }
    }

    #[test]
    fn source_yields_owned_records_in_order_and_then_ends() {
        let packets = [1, 2]
            .map(|byte| PacketRecord::new(0, LinkType(1), None, 1, Box::new([byte])).unwrap());
        let mut source = MemorySource(packets.into());

        for expected in [1, 2] {
            let SourceEvent::Packet(packet) = source.next_packet().unwrap() else {
                panic!("expected packet");
            };
            assert_eq!(packet.bytes(), &[expected]);
        }
        assert_eq!(source.next_packet().unwrap(), SourceEvent::End);
        assert_eq!(source.next_packet().unwrap(), SourceEvent::End);
    }
}
