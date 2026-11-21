//! Separate capture process and private IPC transport for the local Web server.

mod frames;

use std::{
    io::{self, BufWriter, Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use super::{
    BackendStats, PacketSource, SourceEvent,
    live::{Config, LiveCapture},
};
use frames::Frame;

pub fn executable() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name("wiretuna-capture"))
}

pub struct HelperSource {
    child: Child,
    output: UnixStream,
    reader: frames::Reader,
    stats: Option<BackendStats>,
    finished: bool,
}

impl HelperSource {
    pub fn open(path: &Path, interface: &str, config: &Config) -> io::Result<Self> {
        let (output, child_output) = UnixStream::pair()?;
        output.set_read_timeout(Some(Duration::from_millis(10)))?;
        let child = Command::new(path)
            .arg(interface)
            .arg(config.snaplen.to_string())
            .arg(config.buffer_size.to_string())
            .arg(config.filter.as_deref().unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::from(OwnedFd::from(child_output)))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("starting capture helper {}: {error}", path.display()),
                )
            })?;
        let mut source = Self {
            child,
            output,
            reader: frames::Reader::default(),
            stats: None,
            finished: false,
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match source.reader.poll(&mut source.output)? {
                Frame::Ready => return Ok(source),
                Frame::Error(error) => return Err(io::Error::other(error)),
                Frame::Idle if Instant::now() < deadline => {}
                Frame::Idle => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "capture helper startup timed out",
                    ));
                }
                _ => {
                    return Err(io::Error::other(
                        "capture helper sent an unexpected startup frame",
                    ));
                }
            }
        }
    }

    fn stop_inner(&mut self) {
        self.child.stdin.take();
        if !self.finished {
            let deadline = Instant::now() + Duration::from_millis(250);
            while Instant::now() < deadline {
                match self.reader.poll(&mut self.output) {
                    Ok(Frame::Stats(stats)) => self.stats = Some(stats),
                    Ok(Frame::Done) | Err(_) => {
                        self.finished = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

impl PacketSource for HelperSource {
    type Error = io::Error;

    fn next_packet(&mut self) -> io::Result<SourceEvent> {
        if self.finished {
            return Ok(SourceEvent::End);
        }
        loop {
            match self.reader.poll(&mut self.output)? {
                Frame::Packet(packet) => return Ok(SourceEvent::Packet(packet)),
                Frame::Idle => return Ok(SourceEvent::Idle),
                Frame::Done => {
                    self.finished = true;
                    return Ok(SourceEvent::End);
                }
                Frame::Stats(stats) => self.stats = Some(stats),
                Frame::Error(error) => return Err(io::Error::other(error)),
                Frame::Ready => {
                    return Err(io::Error::other(
                        "capture helper sent an unexpected ready frame",
                    ));
                }
            }
        }
    }

    fn backend_stats(&mut self) -> Option<BackendStats> {
        self.stats
    }

    fn stop(&mut self) {
        self.stop_inner();
    }
}

impl Drop for HelperSource {
    fn drop(&mut self) {
        self.stop_inner();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn run(interface: &str, config: &Config) -> io::Result<()> {
    let mut output = BufWriter::with_capacity(64 * 1024, io::stdout().lock());
    match capture(interface, config, &mut output) {
        Ok(()) => Ok(()),
        Err(error) => {
            frames::error(&mut output, &error)?;
            output.flush()?;
            Err(error)
        }
    }
}

fn capture(interface: &str, config: &Config, output: &mut impl Write) -> io::Result<()> {
    let mut capture = LiveCapture::open(interface, config)?;
    frames::ready(output)?;
    output.flush()?;

    // Closing the parent's control pipe stops capture even if no packets arrive.
    let stop = Arc::new(AtomicBool::new(false));
    let control = Arc::clone(&stop);
    thread::Builder::new()
        .name("wiretuna-helper-control".into())
        .spawn(move || {
            let _ = io::stdin().read(&mut [0]);
            control.store(true, Ordering::Relaxed);
        })?;

    let mut flush_at = Instant::now();
    let mut stats_at = flush_at;
    while !stop.load(Ordering::Relaxed) {
        match capture.next_packet()? {
            SourceEvent::Packet(packet) => frames::packet(output, &packet)?,
            SourceEvent::Idle => thread::sleep(Duration::from_millis(5)),
            SourceEvent::End => break,
        }
        let now = Instant::now();
        if now >= stats_at {
            if let Some(stats) = capture.backend_stats() {
                frames::stats(output, stats)?;
            }
            stats_at = now + Duration::from_millis(250);
        }
        if now >= flush_at {
            output.flush()?;
            flush_at = now + Duration::from_millis(15);
        }
    }
    if let Some(stats) = capture.backend_stats() {
        frames::stats(output, stats)?;
    }
    frames::done(output)?;
    output.flush()
}
