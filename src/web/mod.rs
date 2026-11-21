//! Local HTTP service. The core session and decoder modules are independent of it.

mod api;
mod assets;
mod export;
mod flows;
mod service;

use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderValue, Method, StatusCode, header, uri::Authority},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde_json::json;

use self::service::Service;

pub struct Config {
    pub port: u16,
    pub input: Option<PathBuf>,
}

pub fn run(config: Config) -> io::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(config))
}

async fn serve(config: Config) -> io::Result<()> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| io::Error::new(error.kind(), format!("binding {address}: {error}")))?;
    let address = listener.local_addr()?;
    let service = Arc::new(Service::new());
    if let Some(path) = config.input {
        service
            .start_offline(path)
            .map_err(|error| io::Error::other(error.message))?;
    }
    println!("Wiretuna is listening on http://{address}");
    let shutdown = Arc::clone(&service);
    axum::serve(listener, router(service))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            shutdown.closing.store(true, Ordering::Relaxed);
            if let Some(active) = shutdown.current() {
                active.session.stop();
            }
        })
        .await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        let interrupt = std::pin::pin!(tokio::signal::ctrl_c());
        let terminate = std::pin::pin!(terminate.recv());
        futures_util::future::select(interrupt, terminate).await;
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route("/", get(assets::index))
        .route("/assets/{name}", get(assets::asset))
        .route("/api/v1/interfaces", get(api::interfaces))
        .route("/api/v1/sessions", get(api::sessions).post(api::start))
        .route("/api/v1/sessions/{id}", delete(api::remove))
        .route("/api/v1/sessions/{id}/stop", post(api::stop))
        .route("/api/v1/sessions/{id}/export.pcap", get(export::pcap))
        .route("/api/v1/sessions/{id}/export.pcapng", get(export::pcapng))
        .route("/api/v1/sessions/{id}/packets", get(api::packets))
        .route(
            "/api/v1/sessions/{id}/packets/{packet_id}",
            get(api::packet),
        )
        .route(
            "/api/v1/sessions/{id}/packets/{packet_id}/bytes",
            get(api::bytes),
        )
        .route("/api/v1/sessions/{id}/events", get(api::session_events))
        .route("/api/v1/events", get(api::events))
        .route("/api/v1/sessions/{id}/flows", get(flows::list))
        .route("/api/v1/sessions/{id}/flows/{flow_id}", get(flows::get))
        .route(
            "/api/v1/sessions/{id}/flows/{flow_id}/segments",
            get(flows::segments),
        )
        .route(
            "/api/v1/sessions/{id}/flows/{flow_id}/bytes",
            get(flows::bytes),
        )
        .route(
            "/api/v1/sessions/{id}/flows/{flow_id}/http",
            get(flows::http),
        )
        .route(
            "/api/v1/sessions/{id}/flows/{flow_id}/http/{message_id}",
            get(flows::message),
        )
        .route(
            "/api/v1/sessions/{id}/flows/{flow_id}/http/{message_id}/body",
            get(flows::message_body),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(Arc::clone(&service), access))
        .with_state(service)
}

fn is_loopback_authority(raw: &str) -> bool {
    let Ok(authority) = raw.parse::<Authority>() else {
        return false;
    };
    let host = authority.host();
    !raw.contains('@')
        && (host.eq_ignore_ascii_case("localhost") || matches!(host, "127.0.0.1" | "[::1]"))
        && (raw == host || authority.port_u16().is_some())
}

async fn access(State(service): State<Arc<Service>>, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let Some(host) = host.filter(|host| is_loopback_authority(host)) else {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_host",
            "Use a loopback address to access Wiretuna.",
        )
        .into_response();
    };
    let expected_origin = format!("http://{host}");
    let origin = request.headers().get(header::ORIGIN);
    let valid_origin = origin.is_some_and(|origin| origin.as_bytes() == expected_origin.as_bytes());
    let read_only = matches!(*request.method(), Method::GET | Method::HEAD);
    if (origin.is_some() || !read_only) && !valid_origin {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "Only same-origin requests are accepted.",
        )
        .into_response();
    }

    let _permit = if request.uri().path().ends_with("/events") {
        None
    } else if let Ok(permit) = Arc::clone(&service.queries).try_acquire_owned() {
        Some(permit)
    } else {
        return ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "requests_full",
            "The server is busy.",
        )
        .into_response();
    };
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    response
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    fn io(error: io::Error) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "io_error",
            error.to_string(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"code": self.code, "message": self.message})),
        )
            .into_response()
    }
}
