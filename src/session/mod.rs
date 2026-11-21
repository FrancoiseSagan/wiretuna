mod page;
pub use page::{PacketSummary, Page};
mod queue;

use std::{
    collections::VecDeque,
    fmt::Display,
    io,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    capture::{BackendStats, PacketSource, SourceEvent},
    decode::{Summary, summarize},
    flow::{Flow, StreamSnapshot, Tracker},
    packet::PacketRecord,
};

use queue::Queue;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Offline,
    Live,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Starting,
    Running,
    Stopping,
    Finished,
    Failed,
}

impl Phase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Finished | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub input_packets: usize,
    pub input_bytes: usize,
    pub retained_packets: usize,
    pub retained_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            input_packets: 4096,
            input_bytes: 8 * 1024 * 1024,
            retained_packets: 100_000,
            retained_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub error: Option<String>,
    pub seen: u64,
    pub first: u64,
    pub retained: usize,
    pub bytes: usize,
    pub evicted: u64,
    pub input_dropped: u64,
    pub backend: Option<BackendStats>,
    pub flows: usize,
    pub newest_flow: u64,
    pub evicted_flows: u64,
    pub stream_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: u64,
    pub packet: Arc<PacketRecord>,
    pub summary: Summary,
    pub flow_id: Option<u64>,
}

impl Entry {
    fn cost(&self) -> usize {
        self.packet.bytes().len()
            + size_of::<Self>()
            + size_of::<PacketRecord>()
            + 2 * size_of::<usize>()
    }
}

struct Window {
    phase: Phase,
    error: Option<String>,
    entries: VecDeque<Entry>,
    seen: u64,
    bytes: usize,
    backend: Option<BackendStats>,
    limits: Limits,
    tracker: Tracker,
}

impl Window {
    fn first(&self) -> u64 {
        self.entries.front().map_or(self.seen + 1, |entry| entry.id)
    }

    fn append(&mut self, packet: PacketRecord, summary: Summary) {
        self.seen += 1;
        let flow_id = self.tracker.observe(self.seen, &packet, &summary);
        let entry = Entry {
            id: self.seen,
            packet: Arc::new(packet),
            summary,
            flow_id,
        };
        let bytes = entry.cost();
        while self.entries.len() == self.limits.retained_packets
            || bytes > self.limits.retained_bytes - self.bytes
        {
            let Some(evicted) = self.entries.pop_front() else {
                return;
            };
            self.bytes -= evicted.cost();
        }
        self.bytes += bytes;
        self.entries.push_back(entry);
    }
}

struct Shared {
    queue: Queue,
    window: Mutex<Window>,
}

pub struct Session {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl Session {
    pub fn start<S, E>(
        mode: Mode,
        limits: Limits,
        open: impl FnOnce() -> Result<S, E> + Send + 'static,
    ) -> io::Result<Self>
    where
        S: PacketSource,
        E: Display,
    {
        if [
            limits.input_packets,
            limits.input_bytes,
            limits.retained_packets,
            limits.retained_bytes,
        ]
        .contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session budgets must be positive",
            ));
        }
        let shared = Arc::new(Shared {
            queue: Queue::new(limits.input_packets, limits.input_bytes),
            window: Mutex::new(Window {
                phase: Phase::Starting,
                error: None,
                entries: VecDeque::new(),
                seen: 0,
                bytes: 0,
                backend: None,
                limits,
                tracker: Tracker::default(),
            }),
        });
        let state = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("wiretuna-session".into())
            .spawn(move || ingest(&state, mode, open))?;
        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }

    pub fn stop(&self) {
        let mut window = self.shared.window.lock().unwrap();
        if !window.phase.terminal() {
            window.phase = Phase::Stopping;
            self.shared.queue.stop();
        }
    }

    pub fn status(&self) -> Status {
        let window = self.shared.window.lock().unwrap();
        Status {
            phase: window.phase,
            error: window.error.clone(),
            seen: window.seen,
            first: window.first(),
            retained: window.entries.len(),
            bytes: window.bytes,
            evicted: window.seen - window.entries.len() as u64,
            input_dropped: self.shared.queue.dropped(),
            backend: window.backend,
            flows: window.tracker.count(),
            newest_flow: window.tracker.newest_id(),
            evicted_flows: window.tracker.evicted(),
            stream_bytes: window.tracker.stream_bytes(),
        }
    }

    pub fn packet(&self, id: u64) -> Option<Entry> {
        let window = self.shared.window.lock().unwrap();
        let index = usize::try_from(id.checked_sub(window.first())?).ok()?;
        window.entries.get(index).cloned()
    }

    /// Returns retained entries after the cursor, in ingestion order.
    pub fn packets(&self, after: u64, limit: usize) -> Vec<Entry> {
        let window = self.shared.window.lock().unwrap();
        let index = after.saturating_add(1).saturating_sub(window.first());
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        window
            .entries
            .iter()
            .skip(index)
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn flow(&self, id: u64) -> Option<Flow> {
        self.shared.window.lock().unwrap().tracker.flow(id)
    }

    pub fn flows(&self, after: u64, limit: usize) -> Vec<Flow> {
        self.shared
            .window
            .lock()
            .unwrap()
            .tracker
            .flows(after, limit)
    }

    pub fn streams(&self, id: u64) -> Option<(Flow, [StreamSnapshot; 2])> {
        let window = self.shared.window.lock().unwrap();
        Some((window.tracker.flow(id)?, window.tracker.streams(id)?))
    }

    pub fn wait(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
        self.wait();
    }
}

fn ingest<S: PacketSource, E: Display>(
    shared: &Shared,
    mode: Mode,
    open: impl FnOnce() -> Result<S, E> + Send,
) {
    let result = thread::scope(|scope| {
        let producer = thread::Builder::new()
            .name("wiretuna-source".into())
            .spawn_scoped(scope, || {
                struct Finish<'a>(&'a Queue);
                impl Drop for Finish<'_> {
                    fn drop(&mut self) {
                        self.0.finish();
                    }
                }

                let _finish = Finish(&shared.queue);
                produce(shared, mode, open)
            })
            .map_err(|error| error.to_string())?;
        while let Some(packet) = shared.queue.pop() {
            let summary = summarize(&packet);
            shared.window.lock().unwrap().append(packet, summary);
        }
        producer
            .join()
            .map_err(|_| "packet source panicked".to_owned())?
    });
    let mut window = shared.window.lock().unwrap();
    window.phase = if result.is_ok() {
        Phase::Finished
    } else {
        Phase::Failed
    };
    window.error = result.err();
}

fn produce<S: PacketSource, E: Display>(
    shared: &Shared,
    mode: Mode,
    open: impl FnOnce() -> Result<S, E>,
) -> Result<(), String> {
    if shared.queue.stopped() {
        return Ok(());
    }
    let mut source = open().map_err(|error| error.to_string())?;
    {
        let mut window = shared.window.lock().unwrap();
        if window.phase == Phase::Starting {
            window.phase = Phase::Running;
        }
    }
    let mut next_stats = Instant::now() + Duration::from_secs(1);
    let result = loop {
        if shared.queue.stopped() {
            break Ok(());
        }
        match source.next_packet() {
            Ok(SourceEvent::Packet(packet)) => match shared.queue.push(packet, mode) {
                Ok(true) => {}
                Ok(false) => break Ok(()),
                Err(error) => break Err(error.to_owned()),
            },
            Ok(SourceEvent::Idle) => thread::sleep(Duration::from_millis(5)),
            Ok(SourceEvent::End) => break Ok(()),
            Err(error) => break Err(error.to_string()),
        }
        if mode == Mode::Live && Instant::now() >= next_stats {
            shared.window.lock().unwrap().backend = source.backend_stats();
            next_stats = Instant::now() + Duration::from_secs(1);
        }
    };
    source.stop();
    if mode == Mode::Live {
        let stats = source.backend_stats();
        if stats.is_some() {
            shared.window.lock().unwrap().backend = stats;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::LinkType;

    struct TestSource(Option<u8>);

    impl PacketSource for TestSource {
        type Error = io::Error;

        fn next_packet(&mut self) -> io::Result<SourceEvent> {
            let Some(index) = &mut self.0 else {
                return Ok(SourceEvent::Idle);
            };
            if *index == 5 {
                return Ok(SourceEvent::End);
            }
            *index += 1;
            let packet = PacketRecord::new(0, LinkType(1), None, 1, Box::new([*index])).unwrap();
            Ok(SourceEvent::Packet(packet))
        }
    }

    #[test]
    fn bounds_retained_window_and_preserves_ids_under_eviction() {
        let limits = Limits {
            retained_packets: 2,
            ..Limits::default()
        };
        let mut session = Session::start(Mode::Offline, limits, || {
            Ok::<_, io::Error>(TestSource(Some(0)))
        })
        .unwrap();
        session.wait();
        let status = session.status();
        assert_eq!(status.phase, Phase::Finished);
        assert_eq!(
            (status.seen, status.first, status.retained, status.evicted),
            (5, 4, 2, 3)
        );
        assert_eq!(status.input_dropped, 0);
        assert!(session.packet(3).is_none());
        assert_eq!(session.packet(5).unwrap().packet.bytes(), &[5]);
        assert_eq!(session.packets(4, 1)[0].id, 5);
    }

    #[test]
    fn preserves_terminal_failure_and_accepts_repeated_stop_requests() {
        let mut failed = Session::start(Mode::Live, Limits::default(), || {
            Err::<TestSource, _>("source unavailable")
        })
        .unwrap();
        failed.wait();
        failed.stop();
        assert_eq!(failed.status().phase, Phase::Failed);
        assert_eq!(failed.status().error.as_deref(), Some("source unavailable"));

        let mut idle = Session::start(Mode::Live, Limits::default(), || {
            Ok::<_, io::Error>(TestSource(None))
        })
        .unwrap();
        idle.stop();
        idle.stop();
        idle.wait();
        assert_eq!(idle.status().phase, Phase::Finished);
    }
}
