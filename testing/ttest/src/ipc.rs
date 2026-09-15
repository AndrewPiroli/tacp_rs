use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum Who {
    Server,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum AAA {
    Authen,
    Author,
    Acct,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Info {
    pub who: Who,
    pub ty: AAA,
    pub success: bool,
    pub user: String,
    pub otherdata: Option<String>,
}

#[derive(Clone, serde::Serialize)]
struct ServerConfig {
    key: String,
    users: HashMap<String, String>,
    denied_commands: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    config: Arc<ServerConfig>,
    reports: mpsc::Sender<Info>,
    ready: mpsc::Sender<SocketAddr>,
}

pub struct Controller {
    pub addr: SocketAddr,
    reports: mpsc::Receiver<Info>,
    ready: mpsc::Receiver<SocketAddr>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Controller {
    pub fn start() -> Self {
        let (bound_tx, bound_rx) = mpsc::sync_channel(1);
        let (report_tx, report_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("failed to build controller runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("failed to bind test controller");
                bound_tx
                    .send(
                        listener
                            .local_addr()
                            .expect("controller has no local address"),
                    )
                    .expect("test stopped before controller started");

                let state = AppState {
                    config: Arc::new(ServerConfig {
                        key: "b".to_owned(),
                        users: HashMap::from([("test".to_owned(), "test".to_owned())]),
                        denied_commands: vec!["test-deny-string".to_owned()],
                    }),
                    reports: report_tx,
                    ready: ready_tx,
                };
                let app = Router::new()
                    .route("/server_config", get(server_config))
                    .route("/ready", post(server_ready))
                    .route("/report", post(report))
                    .with_state(state);

                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("test controller failed");
            });
        });

        let addr = bound_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("test controller did not start");
        Self {
            addr,
            reports: report_rx,
            ready: ready_rx,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    pub fn wait_for_server(&self, timeout: Duration) -> Result<SocketAddr, String> {
        self.ready
            .recv_timeout(timeout)
            .map_err(|error| format!("server did not become ready: {error}"))
    }

    pub fn receive_report(&self, timeout: Duration) -> Result<Info, String> {
        self.reports
            .recv_timeout(timeout)
            .map_err(|error| format!("server did not report a result: {error}"))
    }

    fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn server_config(State(state): State<AppState>) -> Json<ServerConfig> {
    Json((*state.config).clone())
}

async fn server_ready(State(state): State<AppState>, body: String) -> StatusCode {
    let Ok(addr) = body.parse() else {
        return StatusCode::BAD_REQUEST;
    };
    if state.ready.send(addr).is_err() {
        return StatusCode::GONE;
    }
    StatusCode::NO_CONTENT
}

async fn report(State(state): State<AppState>, Json(payload): Json<Info>) -> StatusCode {
    if state.reports.send(payload).is_err() {
        return StatusCode::GONE;
    }
    StatusCode::NO_CONTENT
}
