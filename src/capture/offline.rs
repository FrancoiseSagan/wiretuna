//! Format detection shared by the CLI and offline Web sessions.

use std::io::{Chain, Cursor, Read};

use super::{
    PacketSource, SourceEvent,
    file::{CaptureFileError, read_field},
    pcap::{PcapHeader, PcapReader},
    pcapng::{PcapNgReader, SECTION_MAGIC},
};

type Prefixed<R> = Chain<Cursor<[u8; 4]>, R>;

pub enum OfflineReader<R> {
    Pcap(PcapReader<Prefixed<R>>),
    PcapNg(PcapNgReader<Prefixed<R>>),
}

impl<R: Read> OfflineReader<R> {
    pub fn new(mut input: R) -> Result<Self, CaptureFileError> {
        let mut magic = [0; 4];
        let mut offset = 0;
        read_field(&mut input, &mut offset, &mut magic, "file magic", false)?;
        let input = Cursor::new(magic).chain(input);
        if magic == SECTION_MAGIC {
            PcapNgReader::new(input).map(Self::PcapNg)
        } else {
            PcapReader::new(input).map(Self::Pcap)
        }
    }

    pub fn classic_header(&self) -> Option<PcapHeader> {
        match self {
            Self::Pcap(reader) => Some(reader.header()),
            Self::PcapNg(_) => None,
        }
    }

    pub fn interface_count(&self) -> u64 {
        match self {
            Self::Pcap(_) => 1,
            Self::PcapNg(reader) => reader.interface_count(),
        }
    }
}

impl<R: Read> PacketSource for OfflineReader<R> {
    type Error = CaptureFileError;

    fn next_packet(&mut self) -> Result<SourceEvent, Self::Error> {
        match self {
            Self::Pcap(reader) => reader.next_packet(),
            Self::PcapNg(reader) => reader.next_packet(),
        }
    }
}
