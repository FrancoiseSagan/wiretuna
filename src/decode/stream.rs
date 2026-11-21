use crate::flow::StreamSnapshot;

/// The retained TCP bytes before the first gap, with their source packets.
pub(super) struct Prefix {
    pub(super) bytes: Vec<u8>,
    sources: Vec<(usize, u64)>,
    pub(super) finished: bool,
    pub(super) incomplete: bool,
}

impl Prefix {
    pub(super) fn new(snapshot: &StreamSnapshot) -> Self {
        let mut prefix = Self {
            bytes: Vec::new(),
            sources: Vec::new(),
            finished: false,
            incomplete: false,
        };
        for chunk in &snapshot.chunks {
            if chunk.offset != prefix.bytes.len() as u64 {
                break;
            }
            prefix.bytes.extend_from_slice(&chunk.bytes);
            prefix.sources.push((prefix.bytes.len(), chunk.packet_id));
        }
        prefix.incomplete = (prefix.bytes.len() as u64) < snapshot.observed_end;
        prefix.finished =
            snapshot.fin_offset == Some(prefix.bytes.len() as u64) && !prefix.incomplete;
        prefix
    }

    pub(super) fn packet_at(&self, byte: usize) -> u64 {
        self.sources
            .get(self.sources.partition_point(|(end, _)| *end <= byte))
            .map_or(0, |(_, packet)| *packet)
    }
}

#[cfg(test)]
pub(super) fn test_snapshot(chunks: &[&[u8]]) -> StreamSnapshot {
    use std::sync::Arc;

    use crate::flow::Chunk;

    let mut observed_end = 0;
    let chunks = chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let offset = observed_end;
            observed_end += bytes.len() as u64;
            Chunk {
                offset,
                packet_id: index as u64 + 1,
                bytes: Arc::from(*bytes),
            }
        })
        .collect();
    StreamSnapshot {
        chunks,
        observed_end,
        fin_offset: None,
        overlap_conflict: false,
        limited: false,
    }
}
