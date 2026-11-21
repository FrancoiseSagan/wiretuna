//! Linux live packet source backed by libpcap.

use std::{
    io,
    time::{Duration, Instant},
};

use ::pcap::{Active, Capture, Device};
use nix::net::if_::if_nametoindex;

use super::{BackendStats, PacketSource, SourceEvent};
use crate::packet::{LinkType, PacketRecord, Timestamp, TimestampResolution};

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
}

pub fn interfaces() -> io::Result<Vec<Interface>> {
    let devices = Device::list().map_err(|error| backend_error("enumerating interfaces", error))?;
    let mut interfaces: Vec<_> = devices
        .into_iter()
        .filter(|device| if_nametoindex(device.name.as_str()).is_ok())
        .map(|device| Interface {
            name: device.name,
            description: device.desc,
        })
        .collect();
    interfaces.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(interfaces)
}

#[derive(Debug)]
pub struct Config {
    pub snaplen: i32,
    pub buffer_size: i32,
    pub filter: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            snaplen: 65_535,
            buffer_size: 2 * 1024 * 1024,
            filter: None,
        }
    }
}

pub struct LiveCapture {
    capture: Capture<Active>,
    link_type: LinkType,
    interface: String,
    interface_index: u32,
    next_interface_check: Instant,
}

impl LiveCapture {
    pub fn open(interface: &str, config: &Config) -> io::Result<Self> {
        if !(1..=1024 * 1024).contains(&config.snaplen) || config.buffer_size <= 0 {
            return Err(invalid_input(
                "snaplen must be 1–1048576 and buffer size must be positive",
            ));
        }
        if config
            .filter
            .as_ref()
            .is_some_and(|filter| filter.trim().is_empty() || filter.contains('\0'))
        {
            return Err(invalid_input(
                "capture filter must be nonempty and contain no NUL bytes",
            ));
        }
        let interface_index = if_nametoindex(interface).map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("network interface {interface:?}: {error}"),
            )
        })?;

        let mut capture = Capture::from_device(interface)
            .and_then(|capture| {
                capture
                    .promisc(false)
                    .snaplen(config.snaplen)
                    .buffer_size(config.buffer_size)
                    .timeout(20)
                    .open()
            })
            .map_err(|error| backend_error(&format!("opening interface {interface:?}"), error))?;
        if let Some(filter) = &config.filter {
            capture
                .filter(filter, true)
                .map_err(|error| backend_error("installing capture filter", error))?;
        }
        let capture = capture
            .setnonblock()
            .map_err(|error| backend_error("enabling nonblocking capture", error))?;
        let link_type = u16::try_from(capture.get_datalink().0)
            .map(LinkType)
            .map_err(|_| {
                io::Error::other("capture returned a link type outside the supported range")
            })?;

        Ok(Self {
            capture,
            link_type,
            interface: interface.to_owned(),
            interface_index,
            next_interface_check: Instant::now(),
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    pub fn stats(&mut self) -> io::Result<BackendStats> {
        let stats = self
            .capture
            .stats()
            .map_err(|error| backend_error("reading capture statistics", error))?;
        Ok(BackendStats {
            received: stats.received,
            dropped: stats.dropped,
            interface_dropped: stats.if_dropped,
        })
    }
}

impl PacketSource for LiveCapture {
    type Error = io::Error;

    fn next_packet(&mut self) -> io::Result<SourceEvent> {
        let packet = match self.capture.next_packet() {
            Ok(packet) => packet,
            Err(::pcap::Error::TimeoutExpired) => {
                let now = Instant::now();
                if now >= self.next_interface_check {
                    self.next_interface_check = now + Duration::from_secs(1);
                    if if_nametoindex(self.interface.as_str()) != Ok(self.interface_index) {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("network interface {:?} disappeared", self.interface),
                        ));
                    }
                }
                return Ok(SourceEvent::Idle);
            }
            Err(error) => return Err(backend_error("reading from capture interface", error)),
        };

        let time = packet.header.ts;
        let timestamp = u32::try_from(time.tv_usec)
            .ok()
            .and_then(|fraction| {
                Timestamp::from_fraction(
                    time.tv_sec as _,
                    fraction,
                    TimestampResolution::Microseconds,
                )
            })
            .ok_or_else(|| io::Error::other("capture returned an invalid timestamp"))?;
        PacketRecord::new(
            0,
            self.link_type,
            Some(timestamp),
            packet.header.len,
            packet.data.into(),
        )
        .map(SourceEvent::Packet)
        .map_err(io::Error::other)
    }

    fn backend_stats(&mut self) -> Option<BackendStats> {
        self.stats().ok()
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn backend_error(operation: &str, error: ::pcap::Error) -> io::Error {
    io::Error::other(format!("{operation}: {error}"))
}
