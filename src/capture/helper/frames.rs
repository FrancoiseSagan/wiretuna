use std::io::{self, Read, Write};

use crate::{
    capture::BackendStats,
    packet::{LinkType, PacketRecord, Timestamp, TimestampResolution},
};

const MAX_FRAME: usize = 1024 * 1024 + 18;
const PACKET: u8 = 1;
const STATS: u8 = 2;
const ERROR: u8 = 3;
const READY: u8 = 4;
const DONE: u8 = 5;

pub(super) enum Frame {
    Packet(PacketRecord),
    Stats(BackendStats),
    Error(String),
    Ready,
    Done,
    Idle,
}

pub(super) fn ready(output: &mut impl Write) -> io::Result<()> {
    output.write_all(&[READY, 0, 0, 0, 0])
}

pub(super) fn done(output: &mut impl Write) -> io::Result<()> {
    output.write_all(&[DONE, 0, 0, 0, 0])
}

pub(super) fn error(output: &mut impl Write, error: &io::Error) -> io::Result<()> {
    let message = error.to_string();
    let bytes = message.as_bytes();
    let bytes = &bytes[..bytes.len().min(4096)];
    write_header(output, ERROR, bytes.len())?;
    output.write_all(bytes)
}

pub(super) fn stats(output: &mut impl Write, stats: BackendStats) -> io::Result<()> {
    let mut frame = [0; 17];
    frame[..5].copy_from_slice(&[STATS, 0, 0, 0, 12]);
    frame[5..9].copy_from_slice(&stats.received.to_be_bytes());
    frame[9..13].copy_from_slice(&stats.dropped.to_be_bytes());
    frame[13..17].copy_from_slice(&stats.interface_dropped.to_be_bytes());
    output.write_all(&frame)
}

pub(super) fn packet(output: &mut impl Write, packet: &PacketRecord) -> io::Result<()> {
    let timestamp = packet
        .timestamp()
        .ok_or_else(|| io::Error::other("live packet timestamp is missing"))?;
    write_header(output, PACKET, 18 + packet.bytes().len())?;
    output.write_all(&packet.link_type().0.to_be_bytes())?;
    output.write_all(&timestamp.seconds().to_be_bytes())?;
    output.write_all(&(timestamp.nanoseconds() / 1000).to_be_bytes())?;
    output.write_all(&packet.original_len().to_be_bytes())?;
    output.write_all(packet.bytes())
}

fn write_header(output: &mut impl Write, kind: u8, len: usize) -> io::Result<()> {
    let mut header = [kind, 0, 0, 0, 0];
    header[1..].copy_from_slice(&(len as u32).to_be_bytes());
    output.write_all(&header)
}

#[derive(Default)]
pub(super) struct Reader {
    buffer: Vec<u8>,
    offset: usize,
}

impl Reader {
    pub fn poll(&mut self, input: &mut impl Read) -> io::Result<Frame> {
        loop {
            let available = &self.buffer[self.offset..];
            if available.len() >= 5 {
                let len = u32::from_be_bytes(available[1..5].try_into().unwrap()) as usize;
                if len > MAX_FRAME {
                    return Err(invalid_frame());
                }
                if available.len() >= 5 + len {
                    let frame = decode(available[0], &available[5..5 + len]);
                    self.offset += 5 + len;
                    return frame;
                }
            }

            if self.offset > 0 {
                self.buffer.drain(..self.offset);
                self.offset = 0;
            }
            let mut batch = [0; 16 * 1024];
            match input.read(&mut batch) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "capture helper exited",
                    ));
                }
                Ok(count) => self.buffer.extend_from_slice(&batch[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(Frame::Idle);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn decode(kind: u8, body: &[u8]) -> io::Result<Frame> {
    match (kind, body.len()) {
        (READY, 0) => Ok(Frame::Ready),
        (DONE, 0) => Ok(Frame::Done),
        (ERROR, 1..=4096) => Ok(Frame::Error(String::from_utf8_lossy(body).into_owned())),
        (STATS, 12) => Ok(Frame::Stats(BackendStats {
            received: u32::from_be_bytes(body[..4].try_into().unwrap()),
            dropped: u32::from_be_bytes(body[4..8].try_into().unwrap()),
            interface_dropped: u32::from_be_bytes(body[8..].try_into().unwrap()),
        })),
        (PACKET, 18..) => {
            let link = LinkType(u16::from_be_bytes(body[..2].try_into().unwrap()));
            let seconds = i64::from_be_bytes(body[2..10].try_into().unwrap());
            let fraction = u32::from_be_bytes(body[10..14].try_into().unwrap());
            let original = u32::from_be_bytes(body[14..18].try_into().unwrap());
            let timestamp =
                Timestamp::from_fraction(seconds, fraction, TimestampResolution::Microseconds)
                    .ok_or_else(invalid_frame)?;
            PacketRecord::new(0, link, Some(timestamp), original, body[18..].into())
                .map(Frame::Packet)
                .map_err(io::Error::other)
        }
        _ => Err(invalid_frame()),
    }
}

fn invalid_frame() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid capture helper frame")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_reject_large_lengths_before_allocation() {
        let mut buffer = Vec::new();
        ready(&mut buffer).unwrap();
        let timestamp = Timestamp::from_fraction(10, 42, TimestampResolution::Microseconds);
        let expected = PacketRecord::new(0, LinkType(1), timestamp, 2, Box::new([7])).unwrap();
        packet(&mut buffer, &expected).unwrap();
        done(&mut buffer).unwrap();
        let mut input = buffer.as_slice();
        let mut reader = Reader::default();
        assert!(matches!(reader.poll(&mut input).unwrap(), Frame::Ready));
        let Frame::Packet(actual) = reader.poll(&mut input).unwrap() else {
            panic!("expected packet");
        };
        assert_eq!(actual, expected);
        assert!(matches!(reader.poll(&mut input).unwrap(), Frame::Done));
        assert!(
            Reader::default()
                .poll(&mut [PACKET, 255, 255, 255, 255].as_slice())
                .is_err()
        );
    }
}
