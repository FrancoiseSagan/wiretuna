use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkType(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampResolution {
    Microseconds,
    Nanoseconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    seconds: i64,
    nanoseconds: u32,
    resolution: TimestampResolution,
}

impl Timestamp {
    /// Creates a timestamp from UTC Unix seconds and a fraction in the source's units.
    pub fn from_fraction(
        seconds: i64,
        fraction: u32,
        resolution: TimestampResolution,
    ) -> Option<Self> {
        let units_per_second = match resolution {
            TimestampResolution::Microseconds => 1_000_000,
            TimestampResolution::Nanoseconds => 1_000_000_000,
        };
        if fraction >= units_per_second {
            return None;
        }
        Some(Self {
            seconds,
            nanoseconds: fraction * (1_000_000_000 / units_per_second),
            resolution,
        })
    }

    pub fn seconds(self) -> i64 {
        self.seconds
    }

    pub fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    pub fn resolution(self) -> TimestampResolution {
        self.resolution
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PacketRecord {
    interface_id: u32,
    link_type: LinkType,
    timestamp: Option<Timestamp>,
    original_len: u32,
    fcs_length: Option<u8>,
    bytes: Box<[u8]>,
}

impl PacketRecord {
    pub fn new(
        interface_id: u32,
        link_type: LinkType,
        timestamp: Option<Timestamp>,
        original_len: u32,
        bytes: Box<[u8]>,
    ) -> Result<Self, InvalidCapturedLength> {
        if bytes.len() > original_len as usize {
            return Err(InvalidCapturedLength {
                captured: bytes.len(),
                original: original_len,
            });
        }
        Ok(Self {
            interface_id,
            link_type,
            timestamp,
            original_len,
            fcs_length: None,
            bytes,
        })
    }

    pub(crate) fn with_fcs_length(mut self, length: Option<u8>) -> Self {
        self.fcs_length = length;
        self
    }

    pub(crate) fn fcs_length(&self) -> Option<u8> {
        self.fcs_length
    }

    pub fn interface_id(&self) -> u32 {
        self.interface_id
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    pub fn timestamp(&self) -> Option<Timestamp> {
        self.timestamp
    }

    pub fn captured_len(&self) -> u32 {
        // The constructor bounds this by original_len.
        self.bytes.len() as u32
    }

    pub fn original_len(&self) -> u32 {
        self.original_len
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_truncated(&self) -> bool {
        self.captured_len() < self.original_len
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidCapturedLength {
    pub captured: usize,
    pub original: u32,
}

impl fmt::Display for InvalidCapturedLength {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "captured length {} exceeds original length {}",
            self.captured, self.original
        )
    }
}

impl Error for InvalidCapturedLength {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_preserve_precision_and_reject_out_of_range_fractions() {
        let timestamp =
            Timestamp::from_fraction(42, 999_999, TimestampResolution::Microseconds).unwrap();
        assert_eq!(timestamp.seconds(), 42);
        assert_eq!(timestamp.nanoseconds(), 999_999_000);
        assert_eq!(timestamp.resolution(), TimestampResolution::Microseconds);
        assert!(
            Timestamp::from_fraction(42, 1_000_000, TimestampResolution::Microseconds).is_none()
        );
        assert!(
            Timestamp::from_fraction(42, 1_000_000_000, TimestampResolution::Nanoseconds).is_none()
        );
    }

    #[test]
    fn records_preserve_capture_truncation() {
        let packet = PacketRecord::new(3, LinkType(1), None, 5, Box::new([1, 2, 3])).unwrap();
        assert_eq!(packet.interface_id(), 3);
        assert_eq!(packet.link_type(), LinkType(1));
        assert_eq!(packet.captured_len(), 3);
        assert_eq!(packet.original_len(), 5);
        assert!(packet.is_truncated());
        assert!(PacketRecord::new(0, LinkType(1), None, 2, Box::new([1, 2, 3])).is_err());
    }
}
