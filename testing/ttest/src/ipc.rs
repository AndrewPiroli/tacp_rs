use std::{collections::VecDeque, fmt::Write, sync::{atomic::AtomicBool, OnceLock, RwLock}};
use axum::{
    http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router
};
use axum::extract::rejection::JsonRejection;
use axum_extra::extract::WithRejection;
use std::net::SocketAddr;

pub static CurrentPolicy: RwLock<String> = RwLock::new(String::new());
pub static ListenAddr: OnceLock<SocketAddr> = OnceLock::new();
pub static ReceivedInfos: RwLock<VecDeque<Info>> = RwLock::new(VecDeque::new());
pub static HeardFromServer: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum Who {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum AAA {
    Authen,
    Author,
    Acct,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Info {
    pub who: Who,
    pub ty: AAA,
    pub success: bool,
    pub user: String,
    pub otherdata: Option<String>,
}

impl PartialEq for Info {
    fn eq(&self, other: &Self) -> bool {
        // for otherdata we can do Some("") == None
        let emptystr = |x: &String|x.len() == 0;
        let otherdata = self.otherdata == other.otherdata || (self.otherdata.is_none() && other.otherdata.as_ref().is_some_and(emptystr)) || (self.otherdata.as_ref().is_some_and(emptystr) && other.otherdata.is_none());
        self.who == other.who && self.ty == other.ty && self.success == other.success && self.user == other.user && otherdata
    }
}
impl Eq for Info {}

pub fn start_webserver() {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread().enable_io().build().unwrap().block_on(start());
    });
}

async fn it_works() -> &'static str {
    "It works!"
}

async fn server_policy() -> String {
    HeardFromServer.store(true, std::sync::atomic::Ordering::Release);
    CurrentPolicy.read().unwrap().clone()
}


async fn report(WithRejection(Json(payload), _): WithRejection<Json<Info>, DebugJson>) -> impl IntoResponse {
    ReceivedInfos.write().unwrap().push_back(payload);
    StatusCode::OK
}

async fn start() {
    let app = Router::new()
        .route("/", get(it_works))
        .route("/server_policy", get(server_policy))
        .route("/report", post(report));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    ListenAddr.set(addr).unwrap();
    axum::serve(listener, app).await.unwrap();
}




#[allow(dead_code)]
#[derive(Debug)]
struct DebugJson(JsonRejection);
impl From<JsonRejection> for DebugJson {
    fn from(value: JsonRejection) -> Self {
        Self(dbg!(value))
    }
}
impl std::fmt::Display for DebugJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_char('a')
    }
}
impl std::error::Error for DebugJson {}

impl IntoResponse for DebugJson {
    fn into_response(self) -> axum::response::Response {
        StatusCode::from_u16(422).unwrap().into_response()
    }
}