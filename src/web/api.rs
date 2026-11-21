use std::{
    convert::Infallible,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    decode::{self, Summary},
    filter::Filter,
    packet::Timestamp,
    session::{PacketSummary, Phase, Status},
};

use super::{
    ApiError,
    service::{Active, Service},
};

pub(super) async fn interfaces() -> Result<Json<Value>, ApiError> {
    #[cfg(all(target_os = "linux", feature = "live-capture"))]
    {
        let interfaces = tokio::task::spawn_blocking(crate::capture::live::interfaces)
            .await
            .map_err(|error| ApiError::io(std::io::Error::other(error)))?
            .map_err(ApiError::io)?;
        Ok(Json(
            json!({"live": true, "interfaces": interfaces.into_iter()
            .map(|interface| json!({"name": interface.name, "description": interface.description}))
            .collect::<Vec<_>>() }),
        ))
    }
    #[cfg(not(all(target_os = "linux", feature = "live-capture")))]
    Ok(Json(json!({"live": false, "interfaces": []})))
}

#[derive(Deserialize)]
pub(super) struct Start {
    #[cfg_attr(
        not(all(target_os = "linux", feature = "live-capture")),
        allow(dead_code)
    )]
    interface: String,
    #[cfg_attr(
        not(all(target_os = "linux", feature = "live-capture")),
        allow(dead_code)
    )]
    snaplen: Option<i32>,
    #[cfg_attr(
        not(all(target_os = "linux", feature = "live-capture")),
        allow(dead_code)
    )]
    filter: Option<String>,
}

pub(super) async fn start(
    State(service): State<Arc<Service>>,
    Json(start): Json<Start>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    #[cfg(all(target_os = "linux", feature = "live-capture"))]
    {
        use crate::capture::live::Config;
        let config = Config {
            snaplen: start.snaplen.unwrap_or(65_535),
            filter: start.filter.filter(|value| !value.trim().is_empty()),
            ..Config::default()
        };
        if start.interface.len() > 32
            || start.interface.contains('\0')
            || start.interface.is_empty()
            || !(1..=1024 * 1024).contains(&config.snaplen)
            || config
                .filter
                .as_ref()
                .is_some_and(|value| value.len() > 4096 || value.contains('\0'))
        {
            return Err(ApiError::bad("invalid capture configuration"));
        }
        let active = service.start_live(start.interface, config)?;
        Ok((
            StatusCode::CREATED,
            Json(session_json(&active, &active.session.status())),
        ))
    }
    #[cfg(not(all(target_os = "linux", feature = "live-capture")))]
    {
        let _ = (service, start);
        Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "live_unavailable",
            "This build supports offline captures.",
        ))
    }
}

pub(super) async fn sessions(State(service): State<Arc<Service>>) -> Json<Value> {
    let session = service
        .current()
        .map(|active| session_json(&active, &active.session.status()));
    Json(json!({"sessions": session.into_iter().collect::<Vec<_>>()}))
}

pub(super) async fn stop(
    State(service): State<Arc<Service>>,
    Path(id): Path<u64>,
) -> Result<Json<Value>, ApiError> {
    let active = service.get(id)?;
    active.session.stop();
    Ok(Json(session_json(&active, &active.session.status())))
}

pub(super) async fn remove(
    State(service): State<Arc<Service>>,
    Path(id): Path<u64>,
) -> Result<StatusCode, ApiError> {
    service.remove(id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Default, Deserialize)]
pub(super) struct PacketQuery {
    after: Option<u64>,
    until: Option<u64>,
    limit: Option<usize>,
    filter: Option<String>,
    flow: Option<u64>,
}

pub(super) async fn packets(
    State(service): State<Arc<Service>>,
    Path(id): Path<u64>,
    Query(query): Query<PacketQuery>,
) -> Result<Json<Value>, ApiError> {
    let active = service.get(id)?;
    let filter = Filter::parse(query.filter.as_deref().unwrap_or_default())
        .map_err(|error| ApiError::bad(error.to_string()))?;
    let page = active.session.page(
        query.after.unwrap_or(0),
        query.until.unwrap_or(u64::MAX),
        query.limit.unwrap_or(256).clamp(1, 1024),
        &filter,
        query.flow,
    );
    let packets: Vec<_> = page.packets.into_iter().map(packet_json).collect();
    Ok(Json(json!({
        "packets": packets,
        "cursor": page.cursor.to_string(),
        "first": page.first.to_string(),
        "last": page.last.to_string(),
        "more": page.more,
        "skipped": page.skipped.to_string(),
    })))
}

pub(super) async fn packet(
    State(service): State<Arc<Service>>,
    Path((id, packet_id)): Path<(u64, u64)>,
) -> Result<Json<Value>, ApiError> {
    let entry = get_packet(&service, id, packet_id)?;
    let details = decode::details(&entry.packet);
    let layers: Vec<_> = details
        .layers
        .into_iter()
        .map(|layer| {
            let fields: Vec<_> = layer.fields.into_iter().map(|field| json!({
            "key": field.key, "value": field.value, "offset": field.offset, "length": field.len
        })).collect();
            json!({"name": layer.name, "fields": fields})
        })
        .collect();
    Ok(Json(json!({
        "id": entry.id.to_string(), "link_type": entry.packet.link_type().0,
        "captured_len": entry.packet.captured_len(), "original_len": entry.packet.original_len(),
        "timestamp": timestamp_json(entry.packet.timestamp()), "issue": details.summary.issue,
        "flow_id": entry.flow_id.map(|id| id.to_string()), "layers": layers,
    })))
}

#[derive(Default, Deserialize)]
pub(super) struct ByteQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

pub(super) async fn bytes(
    State(service): State<Arc<Service>>,
    Path((id, packet_id)): Path<(u64, u64)>,
    Query(query): Query<ByteQuery>,
) -> Result<Vec<u8>, ApiError> {
    let entry = get_packet(&service, id, packet_id)?;
    let data = entry.packet.bytes();
    let offset = query.offset.unwrap_or(0);
    let rest = data
        .get(offset..)
        .ok_or_else(|| ApiError::bad("byte offset exceeds capture length"))?;
    Ok(rest[..rest.len().min(query.limit.unwrap_or(16384).clamp(1, 65536))].to_vec())
}

fn get_packet(
    service: &Service,
    id: u64,
    packet_id: u64,
) -> Result<crate::session::Entry, ApiError> {
    let active = service.get(id)?;
    if let Some(entry) = active.session.packet(packet_id) {
        return Ok(entry);
    }
    let status = active.session.status();
    if packet_id > 0 && packet_id < status.first {
        Err(ApiError::new(
            StatusCode::GONE,
            "packet_evicted",
            "The packet left the retention window.",
        ))
    } else {
        Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "packet_not_found",
            "No such packet.",
        ))
    }
}

pub(super) async fn events(
    State(service): State<Arc<Service>>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    subscribe(service, None).await
}

pub(super) async fn session_events(
    State(service): State<Arc<Service>>,
    Path(id): Path<u64>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    service.get(id)?;
    subscribe(service, Some(id)).await
}

async fn subscribe(
    service: Arc<Service>,
    id: Option<u64>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let permit = Arc::clone(&service.subscriptions)
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "subscriptions_full",
                "Too many open subscriptions.",
            )
        })?;
    let delay = tokio::time::interval(Duration::from_millis(50));
    let events = futures_util::stream::unfold(
        (service, permit, delay, None),
        move |(service, permit, mut delay, previous)| async move {
            loop {
                delay.tick().await;
                if service.closing.load(Ordering::Relaxed) {
                    return None;
                }
                let active = service
                    .current()
                    .filter(|active| id.is_none_or(|id| id == active.id));
                let status = active
                    .as_ref()
                    .map(|active| (active.id, active.session.status()));
                if previous.as_ref() == Some(&status) {
                    continue;
                }
                let data = active
                    .zip(status.as_ref())
                    .map(|(active, (_, status))| session_json(&active, status));
                let event = Event::default()
                    .event("status")
                    .data(json!({"session": data}).to_string());
                return Some((
                    Ok::<_, Infallible>(event),
                    (service, permit, delay, Some(status)),
                ));
            }
        },
    );
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}

pub(super) fn timestamp_json(timestamp: Option<Timestamp>) -> Value {
    timestamp.map_or(
        Value::Null,
        |time| json!({"seconds": time.seconds(), "nanoseconds": time.nanoseconds()}),
    )
}

fn packet_json(packet: PacketSummary) -> Value {
    let Summary {
        source,
        destination,
        source_port,
        destination_port,
        protocol,
        issue,
        fragmented,
        ..
    } = packet.summary;
    json!({
        "id": packet.id.to_string(), "timestamp": timestamp_json(packet.timestamp),
        "source": source.map(|ip| ip.to_string()), "destination": destination.map(|ip| ip.to_string()),
        "source_port": source_port, "destination_port": destination_port,
        "protocol": protocol.name(), "captured_len": packet.captured_len, "original_len": packet.original_len,
        "issue": issue, "fragmented": fragmented, "flow_id": packet.flow_id.map(|id| id.to_string()),
    })
}

fn session_json(active: &Active, status: &Status) -> Value {
    let phase = match status.phase {
        Phase::Starting => "starting",
        Phase::Running => "running",
        Phase::Stopping => "stopping",
        Phase::Finished => "finished",
        Phase::Failed => "failed",
    };
    json!({
        "id": active.id.to_string(), "label": active.label.as_ref(),
        "phase": phase, "error": status.error,
        "seen": status.seen.to_string(), "first": status.first.to_string(),
        "retained": status.retained, "retained_bytes": status.bytes,
        "evicted": status.evicted.to_string(), "input_dropped": status.input_dropped.to_string(),
        "flows": status.flows, "newest_flow": status.newest_flow.to_string(),
        "evicted_flows": status.evicted_flows.to_string(), "stream_bytes": status.stream_bytes,
        "backend": status.backend.map(|stats| json!({
            "received": stats.received, "dropped": stats.dropped, "interface_dropped": stats.interface_dropped,
        })),
    })
}
