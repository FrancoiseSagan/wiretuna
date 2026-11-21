use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    decode::http1::{self, Message},
    flow::{Flow, StreamSnapshot},
    packet::Timestamp,
    session::Session,
};

use super::{
    ApiError,
    api::timestamp_json,
    service::{Active, Service},
};

#[derive(Deserialize)]
pub(super) struct ListQuery {
    after: Option<u64>,
    limit: Option<usize>,
}

pub(super) async fn list(
    State(service): State<Arc<Service>>,
    Path(id): Path<u64>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let active = service.get(id)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 256);
    let after = query.after.unwrap_or(0);
    let flows = active.session.flows(after, limit + 1);
    let more = flows.len() > limit;
    let flows: Vec<_> = flows.into_iter().take(limit).collect();
    let cursor = flows.last().map_or(after, |flow| flow.id);
    Ok(Json(json!({
        "flows": flows.iter().map(flow_json).collect::<Vec<_>>(),
        "cursor": cursor.to_string(),
        "more": more,
    })))
}

pub(super) async fn get(
    State(service): State<Arc<Service>>,
    Path((id, flow_id)): Path<(u64, u64)>,
) -> Result<Json<Value>, ApiError> {
    let active = service.get(id)?;
    let flow = active
        .session
        .flow(flow_id)
        .ok_or_else(|| flow_missing(&active, flow_id))?;
    Ok(Json(flow_json(&flow)))
}

#[derive(Deserialize)]
pub(super) struct StreamQuery {
    direction: Option<usize>,
    offset: Option<u64>,
    limit: Option<usize>,
}

pub(super) async fn segments(
    State(service): State<Arc<Service>>,
    Path((id, flow_id)): Path<(u64, u64)>,
    Query(query): Query<StreamQuery>,
) -> Result<Json<Value>, ApiError> {
    let direction = query.direction.unwrap_or(0);
    let stream = snapshot(&service, id, flow_id, direction)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(48).clamp(1, 128);
    let (segments, cursor) = segment_page(&stream, offset, limit);
    Ok(Json(json!({
        "segments": segments,
        "cursor": cursor.to_string(),
        "more": cursor < stream.observed_end,
        "observed_end": stream.observed_end.to_string(),
        "overlap_conflict": stream.overlap_conflict,
        "limited": stream.limited,
        "closed": stream.fin_offset.is_some(),
    })))
}

fn segment_page(stream: &StreamSnapshot, offset: u64, limit: usize) -> (Vec<Value>, u64) {
    let mut segments = Vec::new();
    let mut cursor = offset;
    let start = stream.chunks.partition_point(|chunk| chunk.end() <= cursor);
    for chunk in &stream.chunks[start..] {
        if chunk.offset > cursor {
            segments.push(json!({
                "kind": "gap", "offset": cursor.to_string(),
                "length": (chunk.offset - cursor).to_string(),
            }));
            cursor = chunk.offset;
            if segments.len() == limit {
                return (segments, cursor);
            }
        }
        segments.push(json!({
            "kind": "data", "offset": cursor.to_string(),
            "length": (chunk.end() - cursor).to_string(),
            "packet_id": chunk.packet_id.to_string(),
        }));
        cursor = chunk.end();
        if segments.len() == limit {
            return (segments, cursor);
        }
    }

    if cursor < stream.observed_end {
        segments.push(json!({
            "kind": "gap", "offset": cursor.to_string(),
            "length": (stream.observed_end - cursor).to_string(),
        }));
        cursor = stream.observed_end;
    }
    (segments, cursor)
}

pub(super) async fn bytes(
    State(service): State<Arc<Service>>,
    Path((id, flow_id)): Path<(u64, u64)>,
    Query(query): Query<StreamQuery>,
) -> Result<Vec<u8>, ApiError> {
    let stream = snapshot(&service, id, flow_id, query.direction.unwrap_or(0))?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(4096).clamp(1, 65536);
    let data = contiguous_bytes(&stream, offset, limit);
    if data.is_empty() && offset != stream.observed_end {
        return Err(ApiError::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "stream_gap",
            "No retained bytes at this offset.",
        ));
    }
    Ok(data)
}

fn contiguous_bytes(stream: &StreamSnapshot, offset: u64, limit: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut cursor = offset;
    let start = stream.chunks.partition_point(|chunk| chunk.end() <= offset);
    for chunk in &stream.chunks[start..] {
        if chunk.offset > cursor || result.len() == limit {
            break;
        }
        let index = (cursor - chunk.offset) as usize;
        let data = &chunk.bytes[index..];
        let take = data.len().min(limit - result.len());
        result.extend_from_slice(&data[..take]);
        cursor += take as u64;
    }
    result
}

#[derive(Deserialize)]
pub(super) struct HttpQuery {
    offset: Option<usize>,
    limit: Option<usize>,
    method: Option<String>,
    status: Option<u16>,
}

pub(super) async fn http(
    State(service): State<Arc<Service>>,
    Path((id, flow_id)): Path<(u64, u64)>,
    Query(query): Query<HttpQuery>,
) -> Result<Json<Value>, ApiError> {
    let active = service.get(id)?;
    let (flow, streams) = active
        .session
        .streams(flow_id)
        .ok_or_else(|| flow_missing(&active, flow_id))?;
    let report = http1::analyze(&flow, &streams);
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(32).clamp(1, 64);
    let transactions = report.transactions.iter().filter(|transaction| {
        query.method.as_deref().is_none_or(|method| {
            transaction
                .request
                .as_ref()
                .and_then(|request| request.method.as_deref())
                == Some(method)
        }) && query.status.is_none_or(|status| {
            transaction
                .responses
                .iter()
                .any(|response| response.status == Some(status))
        })
    });
    let transactions: Vec<_> = transactions.skip(offset).take(limit + 1).collect();
    let more = transactions.len() > limit;
    let result: Vec<_> = transactions
        .into_iter()
        .take(limit)
        .map(|transaction| {
            json!({
                "request": transaction.request.as_ref().map(message_json),
                "responses": transaction.responses.iter().map(message_json).collect::<Vec<_>>(),
                "response_ms": response_delay(&active.session, transaction),
            })
        })
        .collect();
    Ok(Json(json!({
        "transactions": result,
        "next": offset.saturating_add(result.len()),
        "more": more,
        "note": report.note,
    })))
}

pub(super) async fn message(
    State(service): State<Arc<Service>>,
    Path((id, flow_id, message_id)): Path<(u64, u64, String)>,
) -> Result<Json<Value>, ApiError> {
    let active = service.get(id)?;
    let (flow, streams) = active
        .session
        .streams(flow_id)
        .ok_or_else(|| flow_missing(&active, flow_id))?;
    let report = http1::analyze(&flow, &streams);
    let message = report
        .transactions
        .into_iter()
        .flat_map(|transaction| transaction.request.into_iter().chain(transaction.responses))
        .find(|message| message_key(message) == message_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "message_not_found",
                "No such HTTP message.",
            )
        })?;
    let mut detail = message_json(&message);
    detail["headers"] = json!(
        message
            .headers
            .iter()
            .map(|header| json!({
                "name": header.name, "value": header.value
            }))
            .collect::<Vec<_>>()
    );
    detail["preview"] = json!(message.preview);
    Ok(Json(detail))
}

fn snapshot(
    service: &Service,
    session_id: u64,
    flow_id: u64,
    direction: usize,
) -> Result<StreamSnapshot, ApiError> {
    if direction > 1 {
        return Err(ApiError::bad("stream direction must be 0 or 1"));
    }
    let active = service.get(session_id)?;
    let (_, streams) = active
        .session
        .streams(flow_id)
        .ok_or_else(|| flow_missing(&active, flow_id))?;
    let [left, right] = streams;
    Ok(if direction == 0 { left } else { right })
}

fn flow_missing(active: &Active, id: u64) -> ApiError {
    if id > 0 && id <= active.session.status().newest_flow {
        ApiError::new(
            StatusCode::GONE,
            "flow_evicted",
            "The connection left the retention window.",
        )
    } else {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "flow_not_found",
            "No such connection.",
        )
    }
}

fn flow_json(flow: &Flow) -> Value {
    json!({
        "id": flow.id.to_string(),
        "endpoints": flow.endpoints.map(|end| end.to_string()),
        "initiator": flow.initiator,
        "missing_start": flow.missing_start,
        "state": flow.state.name(),
        "directions": flow.directions.map(|side| json!({
            "packets": side.packets.to_string(), "bytes": side.captured_bytes.to_string(), "fin": side.fin,
        })),
        "first_packet": flow.first_packet.to_string(), "last_packet": flow.last_packet.to_string(),
        "first_time": timestamp_json(flow.first_time), "last_time": timestamp_json(flow.last_time),
        "duration_ms": elapsed_ms(flow.first_time, flow.last_time),
    })
}

fn response_delay(session: &Session, transaction: &http1::Transaction) -> Option<f64> {
    let request = transaction.request.as_ref()?;
    let response = transaction.responses.iter().find(|response| {
        response
            .status
            .is_some_and(|status| status == 101 || status >= 200)
    })?;
    let first = session.packet(request.first_packet)?.packet.timestamp();
    let last = session.packet(response.first_packet)?.packet.timestamp();
    elapsed_ms(first, last)
}

fn elapsed_ms(first: Option<Timestamp>, last: Option<Timestamp>) -> Option<f64> {
    let first = first?;
    let last = last?;
    let delta = (i128::from(last.seconds()) - i128::from(first.seconds())) * 1_000_000_000
        + i128::from(last.nanoseconds())
        - i128::from(first.nanoseconds());
    (delta >= 0).then_some(delta as f64 / 1_000_000.0)
}

fn message_key(message: &Message) -> String {
    format!("{}-{}", message.direction, message.offset)
}

fn message_json(message: &Message) -> Value {
    json!({
        "id": message_key(message),
        "method": message.method, "target": message.target, "status": message.status,
        "direction": message.direction, "offset": message.offset.to_string(),
        "first_packet": message.first_packet.to_string(), "last_packet": message.last_packet.to_string(),
        "body_bytes": message.body_bytes, "issue": message.issue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::Chunk;

    #[test]
    fn segments_page_reports_gaps_and_byte_reads_do_not_bridge_them() {
        let stream = StreamSnapshot {
            chunks: vec![
                Chunk {
                    offset: 2,
                    packet_id: 10,
                    bytes: Arc::from(&b"ab"[..]),
                },
                Chunk {
                    offset: 4,
                    packet_id: 11,
                    bytes: Arc::from(&b"cd"[..]),
                },
                Chunk {
                    offset: 8,
                    packet_id: 12,
                    bytes: Arc::from(&b"ef"[..]),
                },
            ],
            observed_end: 11,
            fin_offset: None,
            overlap_conflict: false,
            limited: false,
        };
        let (segments, next) = segment_page(&stream, 0, 2);
        assert_eq!(segments[0]["kind"], "gap");
        assert_eq!(segments[1]["packet_id"], "10");
        assert_eq!(next, 4);
        assert_eq!(contiguous_bytes(&stream, 3, 10), b"bcd");
        assert!(contiguous_bytes(&stream, 6, 10).is_empty());
        assert_eq!(contiguous_bytes(&stream, 8, 1), b"e");
    }
}
