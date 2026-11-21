use std::{collections::BTreeMap, sync::Arc};

use crate::decode::TcpSegment;

use super::{FIN, SYN};

const MAX_DIRECTION_BYTES: usize = 256 * 1024;
const MAX_DIRECTION_CHUNKS: usize = 1024;
const CHUNK_OVERHEAD: usize = 128;

#[derive(Debug, Clone)]
pub struct Chunk {
    pub offset: u64,
    pub packet_id: u64,
    pub bytes: Arc<[u8]>,
}

impl Chunk {
    pub fn end(&self) -> u64 {
        self.offset + self.bytes.len() as u64
    }
}

#[derive(Debug, Clone)]
pub struct StreamSnapshot {
    pub chunks: Vec<Chunk>,
    pub observed_end: u64,
    pub fin_offset: Option<u64>,
    pub overlap_conflict: bool,
    pub limited: bool,
}

#[derive(Default)]
pub(super) struct Stream {
    base: Option<u32>,
    end: u64,
    fin_offset: Option<u64>,
    chunks: BTreeMap<u64, Chunk>,
    stored_bytes: usize,
    used: usize,
    conflict: bool,
    limited: bool,
}

impl Stream {
    pub fn cost(&self) -> usize {
        self.used
    }

    pub fn observe(
        &mut self,
        packet_id: u64,
        segment: TcpSegment,
        data: &[u8],
        budget: usize,
    ) -> usize {
        let sequence = segment
            .sequence
            .wrapping_add(u32::from(segment.flags & SYN != 0));
        let base = *self.base.get_or_insert(sequence);
        // Compare against a nearby observed position to continue correctly after wraparound.
        let relative = i64::from(sequence.wrapping_sub(base.wrapping_add(self.end as u32)) as i32);
        let start = (self.end as i64).saturating_add(relative);
        let end = start.saturating_add(segment.original_payload_len as i64);
        if end < 0 {
            return 0;
        }
        let end = end as u64;
        self.end = self.end.max(end);
        if segment.flags & FIN != 0 {
            self.fin_offset = Some(end);
        }
        let skip = usize::try_from(start.saturating_neg().max(0)).unwrap_or(usize::MAX);
        let Some(data) = data.get(skip..) else {
            return 0;
        };
        let mut cursor = start.max(0) as u64;
        let start = cursor;
        let captured_end = cursor + data.len() as u64;
        let mut used = 0;
        while cursor < captured_end {
            if let Some((_, existing)) = self.chunks.range(..=cursor).next_back()
                && existing.end() > cursor
            {
                let next = existing.end().min(captured_end);
                let old = (cursor - existing.offset) as usize;
                let new = (cursor - start) as usize;
                let len = (next - cursor) as usize;
                if existing.bytes[old..old + len] != data[new..new + len] {
                    self.conflict = true;
                }
                cursor = next;
                continue;
            }

            let next = self
                .chunks
                .range(cursor..)
                .next()
                .map_or(captured_end, |(&offset, _)| offset.min(captured_end));
            let capacity = (MAX_DIRECTION_BYTES - self.stored_bytes)
                .min(budget.saturating_sub(used + CHUNK_OVERHEAD));
            let len = ((next - cursor) as usize).min(capacity);
            if len == 0 || self.chunks.len() == MAX_DIRECTION_CHUNKS {
                self.limited = true;
                break;
            }
            let offset = (cursor - start) as usize;
            self.chunks.insert(
                cursor,
                Chunk {
                    offset: cursor,
                    packet_id,
                    bytes: Arc::from(&data[offset..offset + len]),
                },
            );
            self.stored_bytes += len;
            used += len + CHUNK_OVERHEAD;
            cursor += len as u64;
        }
        self.used += used;
        used
    }

    pub(super) fn snapshot(&self) -> StreamSnapshot {
        StreamSnapshot {
            chunks: self.chunks.values().cloned().collect(),
            observed_end: self.end,
            fin_offset: self.fin_offset,
            overlap_conflict: self.conflict,
            limited: self.limited,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe(stream: &mut Stream, seq: u32, data: &[u8], expected: usize, budget: usize) {
        stream.observe(
            1,
            TcpSegment {
                sequence: seq,
                flags: 0,
                payload_offset: 0,
                captured_payload_len: data.len(),
                original_payload_len: expected,
            },
            data,
            budget,
        );
    }

    #[test]
    fn orders_retransmissions_with_wrap_and_flags_conflicts() {
        let mut stream = Stream::default();
        observe(&mut stream, u32::MAX - 2, b"abc", 3, 4096);
        observe(&mut stream, 3, b"ghi", 4, 4096);
        observe(&mut stream, 0, b"defg", 4, 4096);
        observe(&mut stream, 0, b"dxfg", 4, 4096);
        let snapshot = stream.snapshot();
        let bytes: Vec<_> = snapshot
            .chunks
            .iter()
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect();
        assert_eq!(bytes, b"abcdefghi");
        assert_eq!(snapshot.observed_end, 10);
        assert!(snapshot.overlap_conflict);
    }

    #[test]
    fn retains_partial_data_when_budget_is_exhausted() {
        let mut stream = Stream::default();
        observe(&mut stream, 100, b"ab", 2, CHUNK_OVERHEAD + 1);
        let snapshot = stream.snapshot();
        assert_eq!(snapshot.chunks[0].bytes.as_ref(), b"a");
        assert_eq!(snapshot.observed_end, 2);
        assert!(snapshot.limited);
    }
}
