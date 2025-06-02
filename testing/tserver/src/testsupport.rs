use crate::TEST_MODE;

pub fn getpolicy_blocking(url: &str) -> String {
    reqwest::blocking::get(url).unwrap().text().unwrap()
}
pub async fn report(ty: tacp::PacketType, success: bool, user: &str, other: &str) {
    let addr = TEST_MODE.get();
    if addr.is_none() {
        return;
    }
    let addr = format!("http://{}/report", addr.unwrap());
    let ty = match ty {
        tacp::PacketType::AUTHEN => "Authen",
        tacp::PacketType::AUTHOR => "Author",
        tacp::PacketType::ACCT => "Acct",
    };
    let body = format!("{{
        \"who\": \"Server\",
        \"ty\": \"{ty}\",
        \"success\":{success},
        \"user\":\"{user}\",
        \"otherdata\":\"{other}\"
    }}");
    let res = reqwest::Client::new()
        .post(addr)
        .header("Content-Type", "application/json")
        .body(body)
        .send().await;
    dbg!(res.unwrap());
}