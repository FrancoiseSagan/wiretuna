use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use crate::decode::http2::{self, Frame};

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
    let Some(report) = http2::analyze(&streams) else {
        return Ok(Json(json!({ "recognized": false })));
    };
    let mut by_stream: BTreeMap<u32, Vec<(usize, &Frame)>> = BTreeMap::new();
    for (side, direction) in report.directions.iter().enumerate() {
        for frame in &direction.frames {
            by_stream
                .entry(frame.stream_id)
                .or_default()
                .push((side, frame));
            if let Some(id) = frame.promised_stream
                && id != frame.stream_id
            {
                by_stream.entry(id).or_default().push((side, frame));
            }
        }
    }
    let frames = by_stream
        .into_iter()
        .map(|(id, mut frames)| {
            frames.sort_by_key(|(_, frame)| (frame.packet, frame.offset));
            let frames = frames
                .into_iter()
                .map(|(side, frame)| frame_json(side, frame))
                .collect::<Vec<_>>();
            json!({ "id": id, "frames": frames })
        })
        .collect::<Vec<_>>();
    let directions = report
        .directions
        .iter()
        .zip(streams)
        .map(|(direction, stream)| {
            json!({
                "issue": direction.issue,
                "overlap_conflict": stream.overlap_conflict,
                "limited": stream.limited,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "recognized": true,
        "upgraded": report.upgraded,
        "missing_start": flow.missing_start,
        "directions": directions,
        "streams": frames,
    })))
}

fn frame_json(side: usize, frame: &Frame) -> Value {
    let head = frame.head.as_ref().map(|head| {
        json!({
            "method": head.method,
            "path": head.path,
            "authority": head.authority,
            "scheme": head.scheme,
            "status": head.status,
            "protocol": head.protocol,
        })
    });
    let fields = frame
        .fields
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    json!({
        "direction": side, "kind": frame.kind, "stream_id": frame.stream_id,
        "flags": frame.flags, "length": frame.length, "packet": frame.packet.to_string(),
        "offset": frame.offset, "issue": frame.issue, "head": head, "fields": fields,
        "promised_stream": frame.promised_stream,
    })
}
