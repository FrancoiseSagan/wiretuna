use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex},
};

use crate::packet::PacketRecord;

use super::Mode;

#[derive(Default)]
struct State {
    packets: VecDeque<PacketRecord>,
    bytes: usize,
    dropped: u64,
    closed: bool,
    stopped: bool,
}

pub(super) struct Queue {
    state: Mutex<State>,
    changed: Condvar,
    max_packets: usize,
    max_bytes: usize,
}

impl Queue {
    pub fn new(max_packets: usize, max_bytes: usize) -> Self {
        assert!(max_packets > 0 && max_bytes > 0);
        Self {
            state: Mutex::default(),
            changed: Condvar::new(),
            max_packets,
            max_bytes,
        }
    }

    /// Returns false on stop. Live sources count drops and keep reading.
    pub fn push(&self, packet: PacketRecord, mode: Mode) -> Result<bool, &'static str> {
        let bytes = packet.bytes().len();
        let mut state = self.state.lock().unwrap();
        if bytes > self.max_bytes && mode == Mode::Offline {
            return Err("packet exceeds the input queue byte budget");
        }
        while !state.stopped
            && (state.packets.len() == self.max_packets || bytes > self.max_bytes - state.bytes)
        {
            if mode == Mode::Live {
                state.dropped += 1;
                return Ok(true);
            }
            state = self.changed.wait(state).unwrap();
        }
        if state.stopped {
            return Ok(false);
        }
        state.bytes += bytes;
        state.packets.push_back(packet);
        self.changed.notify_all();
        Ok(true)
    }

    pub fn pop(&self) -> Option<PacketRecord> {
        let mut state = self.state.lock().unwrap();
        while state.packets.is_empty() && !state.closed {
            state = self.changed.wait(state).unwrap();
        }
        let packet = state.packets.pop_front()?;
        state.bytes -= packet.bytes().len();
        self.changed.notify_all();
        Some(packet)
    }

    pub fn finish(&self) {
        self.state.lock().unwrap().closed = true;
        self.changed.notify_all();
    }

    pub fn stop(&self) {
        self.state.lock().unwrap().stopped = true;
        self.changed.notify_all();
    }

    pub fn stopped(&self) -> bool {
        self.state.lock().unwrap().stopped
    }

    pub fn dropped(&self) -> u64 {
        self.state.lock().unwrap().dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_queue_bounds_bytes_and_offline_stop_wakes_a_waiter() {
        fn packet() -> PacketRecord {
            PacketRecord::new(0, crate::packet::LinkType(1), None, 2, Box::new([1, 2])).unwrap()
        }
        let queue = Queue::new(2, 3);
        assert_eq!(queue.push(packet(), Mode::Live), Ok(true));
        assert_eq!(queue.push(packet(), Mode::Live), Ok(true));
        assert_eq!(queue.dropped(), 1);
        std::thread::scope(|scope| {
            let blocked = scope.spawn(|| queue.push(packet(), Mode::Offline));
            queue.stop();
            assert_eq!(blocked.join().unwrap(), Ok(false));
        });
        queue.finish();
        assert!(queue.pop().is_some());
        assert!(queue.pop().is_none());
    }
}
