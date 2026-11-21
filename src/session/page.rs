use crate::{decode::Summary, filter::Filter, packet::Timestamp};

use super::Session;

#[derive(Clone, Copy)]
pub struct PacketSummary {
    pub id: u64,
    pub timestamp: Option<Timestamp>,
    pub captured_len: u32,
    pub original_len: u32,
    pub summary: Summary,
    pub flow_id: Option<u64>,
}

pub struct Page {
    pub packets: Vec<PacketSummary>,
    pub cursor: u64,
    pub first: u64,
    pub last: u64,
    pub more: bool,
    pub skipped: u64,
}

impl Session {
    pub fn page(
        &self,
        after: u64,
        until: u64,
        limit: usize,
        filter: &Filter,
        flow: Option<u64>,
    ) -> Page {
        let window = self.shared.window.lock().unwrap();
        let first = window.first();
        let last = window.seen.min(until);
        let cut = first.saturating_sub(1).min(last);
        let mut page = Page {
            packets: Vec::with_capacity(limit.min(1024)),
            cursor: after.max(cut),
            first,
            last,
            more: false,
            skipped: cut.saturating_sub(after),
        };
        let start = usize::try_from(page.cursor.saturating_add(1).saturating_sub(first))
            .unwrap_or(usize::MAX);
        if limit == 0 {
            return page;
        }
        for entry in window.entries.iter().skip(start).take(4096) {
            if entry.id > last {
                break;
            }
            page.cursor = entry.id;
            if flow.is_none_or(|id| entry.flow_id == Some(id)) && filter.matches(&entry.summary) {
                page.packets.push(PacketSummary {
                    id: entry.id,
                    timestamp: entry.packet.timestamp(),
                    captured_len: entry.packet.captured_len(),
                    original_len: entry.packet.original_len(),
                    summary: entry.summary,
                    flow_id: entry.flow_id,
                });
                if page.packets.len() >= limit.min(1024) {
                    break;
                }
            }
        }
        page.more = page.cursor < last;
        page
    }
}
