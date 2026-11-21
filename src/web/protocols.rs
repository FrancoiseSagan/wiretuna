use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use crate::decode::protocols::{self, Protocol};

use super::{ApiError, flows::flow_missing, service::Service};

pub(super) async fn get(
    State(service): State<Arc<Service>>,
    Path((id, flow_id)): Path<(u64, u64)>,
) -> Result<Json<Value>, ApiError> {
    let active = service.get(id)?;
    let (flow, streams) = active
        .session
        .streams(flow_id)
        .ok_or_else(|| flow_missing(&active, flow_id))?;
    let Some(report) = protocols::analyze(&flow, &streams) else {
        return Ok(Json(json!({ "protocol": null })));
    };
    Ok(Json(json!({
        "protocol": match report.protocol {
            Protocol::Dns => "dns",
            Protocol::Tls => "tls",
        },
        "missing_start": flow.missing_start,
        "directions": report.directions.into_iter().zip(streams).map(|(direction, stream)| json!({
            "issue": direction.issue,
            "overlap_conflict": stream.overlap_conflict,
            "limited": stream.limited,
            "messages": direction.messages.into_iter().map(|message| json!({
                "kind": message.kind,
                "offset": message.offset,
                "packet": message.packet.to_string(),
                "fields": message.fields.into_iter().map(|(key, value)| json!({ "key": key, "value": value })).collect::<Vec<_>>(),
                "issue": message.issue,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })))
}
