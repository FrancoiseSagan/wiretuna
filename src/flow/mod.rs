//! TCP connection tracking within a capture session.

mod reassembly;

use reassembly::Stream;
pub use reassembly::{Chunk, StreamSnapshot};

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    ops::Bound::{Excluded, Unbounded},
};

use crate::{
    decode::Summary,
    packet::{PacketRecord, Timestamp},
};

const MAX_FLOWS: usize = 8192;
const STREAM_BUDGET: usize = 24 * 1024 * 1024;
const FIN: u16 = 0x01;
const SYN: u16 = 0x02;
const RST: u16 = 0x04;
const ACK: u16 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    interface: u32,
    ends: [SocketAddr; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Handshake,
    Established,
    Observed,
    HalfClosed,
    Closed,
    Reset,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::Established => "established",
            Self::Observed => "observed",
            Self::HalfClosed => "half closed",
            Self::Closed => "closed",
            Self::Reset => "reset",
        }
    }

    fn closed(self) -> bool {
        matches!(self, Self::Closed | Self::Reset)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Direction {
    pub packets: u64,
    pub captured_bytes: u64,
    pub fin: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub id: u64,
    pub endpoints: [SocketAddr; 2],
    pub directions: [Direction; 2],
    pub initiator: Option<usize>,
    pub missing_start: bool,
    pub state: State,
    pub first_packet: u64,
    pub last_packet: u64,
    pub first_time: Option<Timestamp>,
    pub last_time: Option<Timestamp>,
}

struct Connection {
    flow: Flow,
    key: Key,
    initial_sequence: [Option<u32>; 2],
    streams: [Stream; 2],
}

#[derive(Default)]
pub struct Tracker {
    connections: BTreeMap<u64, Connection>,
    current: HashMap<Key, u64>,
    next_id: u64,
    evicted: u64,
    stream_bytes: usize,
}

impl Tracker {
    pub fn observe(
        &mut self,
        packet_id: u64,
        packet: &PacketRecord,
        summary: &Summary,
    ) -> Option<u64> {
        let segment = summary.tcp?;
        let source = SocketAddr::new(summary.source?, summary.source_port?);
        let destination = SocketAddr::new(summary.destination?, summary.destination_port?);
        let direction = usize::from(source > destination);
        let ends = if direction == 0 {
            [source, destination]
        } else {
            [destination, source]
        };
        let key = Key {
            interface: packet.interface_id(),
            ends,
        };
        let opens = segment.flags & (SYN | ACK) == SYN;
        let previous = self.current.get(&key).copied();
        let id = previous
            .filter(|id| {
                let connection = &self.connections[id];
                !opens
                    || (!connection.flow.state.closed()
                        && connection.initial_sequence[direction] == Some(segment.sequence))
            })
            .unwrap_or_else(|| self.create(key, packet_id, packet.timestamp(), opens, direction));

        let connection = self.connections.get_mut(&id).unwrap();
        let payload = &packet.bytes()
            [segment.payload_offset..segment.payload_offset + segment.captured_payload_len];
        self.stream_bytes += connection.streams[direction].observe(
            packet_id,
            segment,
            payload,
            STREAM_BUDGET - self.stream_bytes,
        );
        let flow = &mut connection.flow;
        let counters = &mut flow.directions[direction];
        counters.packets = counters.packets.saturating_add(1);
        counters.captured_bytes = counters
            .captured_bytes
            .saturating_add(u64::from(packet.captured_len()));
        flow.last_packet = packet_id;
        flow.last_time = packet.timestamp();
        if segment.flags & SYN != 0 {
            connection.initial_sequence[direction].get_or_insert(segment.sequence);
        }
        if segment.flags & FIN != 0 {
            counters.fin = true;
        }
        if !flow.state.closed() {
            if segment.flags & RST != 0 {
                flow.state = State::Reset;
            } else if flow.directions.iter().all(|side| side.fin) {
                flow.state = State::Closed;
            } else if flow.directions.iter().any(|side| side.fin) {
                flow.state = State::HalfClosed;
            } else if flow.state == State::Handshake
                && segment.flags & (SYN | ACK) == ACK
                && connection.initial_sequence.iter().all(Option::is_some)
            {
                flow.state = State::Established;
            }
        }
        Some(id)
    }

    fn create(
        &mut self,
        key: Key,
        packet_id: u64,
        timestamp: Option<Timestamp>,
        opens: bool,
        direction: usize,
    ) -> u64 {
        if self.connections.len() == MAX_FLOWS {
            let (id, connection) = self.connections.pop_first().unwrap();
            if self.current.get(&connection.key) == Some(&id) {
                self.current.remove(&connection.key);
            }
            self.stream_bytes -= connection.streams.iter().map(Stream::cost).sum::<usize>();
            self.evicted += 1;
        }
        self.next_id += 1;
        let id = self.next_id;
        let flow = Flow {
            id,
            endpoints: key.ends,
            directions: Default::default(),
            initiator: opens.then_some(direction),
            missing_start: !opens,
            state: if opens {
                State::Handshake
            } else {
                State::Observed
            },
            first_packet: packet_id,
            last_packet: packet_id,
            first_time: timestamp,
            last_time: timestamp,
        };
        self.current.insert(key, id);
        self.connections.insert(
            id,
            Connection {
                flow,
                key,
                initial_sequence: [None; 2],
                streams: Default::default(),
            },
        );
        id
    }

    pub fn flow(&self, id: u64) -> Option<Flow> {
        self.connections.get(&id).map(|connection| connection.flow)
    }

    pub fn flows(&self, after: u64, limit: usize) -> Vec<Flow> {
        self.connections
            .range((Excluded(after), Unbounded))
            .take(limit)
            .map(|(_, connection)| connection.flow)
            .collect()
    }

    pub fn streams(&self, id: u64) -> Option<[StreamSnapshot; 2]> {
        let connection = self.connections.get(&id)?;
        Some(connection.streams.each_ref().map(Stream::snapshot))
    }

    pub fn stream_bytes(&self) -> usize {
        self.stream_bytes
    }

    pub fn count(&self) -> usize {
        self.connections.len()
    }

    pub fn newest_id(&self) -> u64 {
        self.next_id
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode::summarize, packet::LinkType};

    fn packet(from_a: bool, seq: u32, flags: u8) -> PacketRecord {
        let mut data = vec![0; 40];
        data[0] = 0x45;
        data[2..4].copy_from_slice(&40u16.to_be_bytes());
        data[9] = 6;
        data[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        data[20..24].copy_from_slice(&[0x12, 0x34, 0, 80]);
        if !from_a {
            data[12..20].rotate_left(4);
            data[20..24].rotate_left(2);
        }
        data[24..28].copy_from_slice(&seq.to_be_bytes());
        data[32] = 0x50;
        data[33] = flags;
        PacketRecord::new(0, LinkType(101), None, 40, data.into_boxed_slice()).unwrap()
    }

    #[test]
    fn tracks_both_directions_and_separates_reused_endpoints() {
        let mut tracker = Tracker::default();
        for (index, (from_a, seq, flags, expected_id, expected_state)) in [
            (true, 10, 2, 1, State::Handshake),
            (true, 10, 2, 1, State::Handshake),
            (false, 20, 18, 1, State::Handshake),
            (true, 11, 16, 1, State::Established),
            (true, 11, 17, 1, State::HalfClosed),
            (false, 21, 17, 1, State::Closed),
            (true, 42, 2, 2, State::Handshake),
            (false, 80, 4, 2, State::Reset),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = packet(from_a, seq, flags);
            let id = tracker
                .observe(index as u64 + 1, &packet, &summarize(&packet))
                .unwrap();
            assert_eq!(id, expected_id);
            assert_eq!(tracker.flow(id).unwrap().state, expected_state);
        }
        let first = tracker.flow(1).unwrap();
        assert_eq!(
            (first.directions[0].packets, first.directions[1].packets),
            (4, 2)
        );
    }

    #[test]
    fn marks_midstream_capture() {
        let mut tracker = Tracker::default();
        let packet = packet(false, 123, 16);
        let id = tracker.observe(1, &packet, &summarize(&packet)).unwrap();
        let flow = tracker.flow(id).unwrap();
        assert!(flow.missing_start);
        assert_eq!(flow.initiator, None);
        assert_eq!(flow.state, State::Observed);
    }
}
