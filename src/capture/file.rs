use std::{
    error::Error,
    fmt,
    io::{self, Read},
};

pub(super) const MAX_PACKET_BYTES: u32 = 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum ByteOrder {
    Big,
    Little,
}

impl ByteOrder {
    pub(super) fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Big => u16::from_be_bytes(bytes),
            Self::Little => u16::from_le_bytes(bytes),
        }
    }

    pub(super) fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Big => u32::from_be_bytes(bytes),
            Self::Little => u32::from_le_bytes(bytes),
        }
    }

    pub(super) fn i64(self, bytes: [u8; 8]) -> i64 {
        match self {
            Self::Big => i64::from_be_bytes(bytes),
            Self::Little => i64::from_le_bytes(bytes),
        }
    }
}

pub(super) fn read_field(
    input: &mut impl Read,
    offset: &mut u64,
    mut bytes: &mut [u8],
    description: &str,
    clean_end_allowed: bool,
) -> Result<bool, CaptureFileError> {
    let start = *offset;
    while !bytes.is_empty() {
        match input.read(bytes) {
            Ok(0) if clean_end_allowed && *offset == start => return Ok(false),
            Ok(0) => {
                return Err(CaptureFileError::invalid(
                    *offset,
                    format!("incomplete {description}"),
                ));
            }
            Ok(n) => {
                *offset += n as u64;
                bytes = &mut bytes[n..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(CaptureFileError {
                    format: "pcap",
                    offset: *offset,
                    message: format!("reading {description}"),
                    cause: Some(error),
                });
            }
        }
    }
    Ok(true)
}

#[derive(Debug)]
pub struct CaptureFileError {
    format: &'static str,
    offset: u64,
    message: String,
    cause: Option<io::Error>,
}

impl CaptureFileError {
    pub(super) fn invalid(offset: u64, message: impl Into<String>) -> Self {
        Self {
            format: "pcap",
            offset,
            message: message.into(),
            cause: None,
        }
    }

    pub(super) fn pcapng(mut self) -> Self {
        self.format = "pcapng";
        self
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }
}

impl fmt::Display for CaptureFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at byte {}: {}",
            self.format, self.offset, self.message
        )?;
        if let Some(cause) = &self.cause {
            write!(formatter, ": {cause}")?;
        }
        Ok(())
    }
}

impl Error for CaptureFileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_ref().map(|cause| cause as &dyn Error)
    }
}
