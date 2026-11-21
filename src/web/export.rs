use std::{convert::Infallible, sync::Arc};

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::capture::{pcap::PcapExport, pcapng::PcapNgExport};

use super::{ApiError, service::Service};

#[derive(Deserialize)]
pub(super) struct ExportRange {
    first: u64,
    last: u64,
}

pub(super) async fn pcap(
    State(service): State<Arc<Service>>,
    Path(id): Path<u64>,
    Query(range): Query<ExportRange>,
) -> Result<Response, ApiError> {
    download(service, id, range, Format::Pcap)
}

pub(super) async fn pcapng(
    State(service): State<Arc<Service>>,
    Path(id): Path<u64>,
    Query(range): Query<ExportRange>,
) -> Result<Response, ApiError> {
    download(service, id, range, Format::PcapNg)
}

#[derive(Clone, Copy)]
enum Format {
    Pcap,
    PcapNg,
}

impl Format {
    fn extension(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        }
    }
}

type Blocks = Box<dyn Iterator<Item = Vec<u8>> + Send>;

fn download(
    service: Arc<Service>,
    id: u64,
    ExportRange { first, last }: ExportRange,
    format: Format,
) -> Result<Response, ApiError> {
    if first == 0 || last < first {
        return Err(ApiError::bad("Invalid packet export range."));
    }
    let active = service.get(id)?;
    let permit = Arc::clone(&service.exports)
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "export_in_progress",
                "Another capture export is in progress.",
            )
        })?;
    let packets = active
        .session
        .snapshot_packets(first, last)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "export_range_unavailable",
                "The requested packets are no longer available. Try the current retained range.",
            )
        })?;
    let (size, export): (u64, Blocks) = match format {
        Format::Pcap => {
            let writer = PcapExport::new(packets).map_err(unrepresentable)?;
            (writer.file_size(), Box::new(writer))
        }
        Format::PcapNg => {
            let writer = PcapNgExport::new(packets).map_err(unrepresentable)?;
            (writer.file_size(), Box::new(writer))
        }
    };
    let extension = format.extension();
    let stream =
        futures_util::stream::unfold((export, permit), |(mut export, permit)| async move {
            let bytes = export.next()?;
            Some((Ok::<_, Infallible>(bytes), (export, permit)))
        });
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, size.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"wiretuna-session-{id}-{first}-{last}.{extension}\""
                ),
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

fn unrepresentable(error: std::io::Error) -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "pcap_unrepresentable",
        error.to_string(),
    )
}
