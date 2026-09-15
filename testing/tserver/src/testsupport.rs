use crate::TestConfig;

#[derive(serde::Serialize)]
enum Who {
    Server,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(serde::Serialize)]
enum AAA {
    Authen,
    Author,
    Acct,
}

#[derive(serde::Serialize)]
struct Report<'a> {
    who: Who,
    ty: AAA,
    success: bool,
    user: &'a str,
    otherdata: Option<&'a str>,
}

pub fn get_config(controller: &str) -> TestConfig {
    reqwest::blocking::get(format!("http://{controller}/server_config"))
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap()
}

pub async fn ready(controller: &str, server_addr: std::net::SocketAddr) {
    reqwest::Client::new()
        .post(format!("http://{controller}/ready"))
        .body(server_addr.to_string())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}

pub async fn report(
    controller: &str,
    ty: tacp::PacketType,
    success: bool,
    user: &str,
    otherdata: Option<&str>,
) {
    let ty = match ty {
        tacp::PacketType::AUTHEN => AAA::Authen,
        tacp::PacketType::AUTHOR => AAA::Author,
        tacp::PacketType::ACCT => AAA::Acct,
    };
    reqwest::Client::new()
        .post(format!("http://{controller}/report"))
        .json(&Report {
            who: Who::Server,
            ty,
            success,
            user,
            otherdata,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}
