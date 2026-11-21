use std::{
    fs::File,
    io::{self, BufReader},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::http::StatusCode;
use tokio::sync::Semaphore;

use crate::{
    capture::pcap::PcapReader,
    session::{Limits, Mode, Session},
};

use super::ApiError;

#[derive(Clone)]
pub(super) struct Active {
    pub id: u64,
    pub label: Arc<str>,
    pub session: Arc<Session>,
}

#[derive(Default)]
struct Registry {
    next_id: u64,
    session: Option<Active>,
}

pub(super) struct Service {
    registry: Mutex<Registry>,
    pub subscriptions: Arc<Semaphore>,
    pub queries: Arc<Semaphore>,
    pub exports: Arc<Semaphore>,
    pub closing: AtomicBool,
}

impl Service {
    pub fn new() -> Self {
        Self {
            registry: Mutex::default(),
            subscriptions: Arc::new(Semaphore::new(8)),
            queries: Arc::new(Semaphore::new(12)),
            exports: Arc::new(Semaphore::new(1)),
            closing: AtomicBool::new(false),
        }
    }

    pub fn current(&self) -> Option<Active> {
        self.registry.lock().unwrap().session.clone()
    }

    pub fn get(&self, id: u64) -> Result<Active, ApiError> {
        self.current()
            .filter(|active| active.id == id)
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "session_not_found",
                    "No such session.",
                )
            })
    }

    pub fn start_offline(&self, path: PathBuf) -> Result<Active, ApiError> {
        let label = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned();
        self.start(label, || {
            Session::start(Mode::Offline, Limits::default(), move || {
                if !path.metadata()?.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "offline input must be a regular file",
                    ));
                }
                let file = File::open(&path)?;
                PcapReader::new(BufReader::new(file)).map_err(io::Error::other)
            })
        })
    }

    #[cfg(all(target_os = "linux", feature = "live-capture"))]
    pub fn start_live(
        &self,
        interface: String,
        config: crate::capture::live::Config,
    ) -> Result<Active, ApiError> {
        use crate::capture::helper::{self, HelperSource};
        let helper = helper::executable().map_err(ApiError::io)?;
        self.start(interface.clone(), || {
            Session::start(Mode::Live, Limits::default(), move || {
                HelperSource::open(&helper, &interface, &config)
            })
        })
    }

    fn start(
        &self,
        label: String,
        open: impl FnOnce() -> io::Result<Session>,
    ) -> Result<Active, ApiError> {
        let mut registry = self.registry.lock().unwrap();
        if self.closing.load(Ordering::Relaxed) {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "shutting_down",
                "Server is shutting down.",
            ));
        }
        if registry.session.is_some() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "session_in_use",
                "Clear the previous session before starting another.",
            ));
        }
        let session = Arc::new(open().map_err(ApiError::io)?);
        registry.next_id += 1;
        let active = Active {
            id: registry.next_id,
            label: label.into(),
            session,
        };
        registry.session = Some(active.clone());
        Ok(active)
    }

    pub fn remove(&self, id: u64) -> Result<(), ApiError> {
        let mut registry = self.registry.lock().unwrap();
        let session = registry
            .session
            .as_ref()
            .filter(|active| active.id == id)
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "session_not_found",
                    "No such session.",
                )
            })?;
        if !session.session.status().phase.terminal() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "session_running",
                "Stop the session before clearing it.",
            ));
        }
        registry.session.take();
        Ok(())
    }
}
