use crate::packet::PacketRecord;

#[derive(Debug, PartialEq, Eq)]
pub enum SourceEvent {
    Packet(PacketRecord),
    /// A live poll expired. The source can still yield packets.
    Idle,
    /// The source has ended. Successful subsequent reads also return End.
    End,
}

pub trait PacketSource {
    type Error: std::error::Error;

    fn next_packet(&mut self) -> Result<SourceEvent, Self::Error>;
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
