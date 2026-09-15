#![allow(clippy::needless_return, clippy::upper_case_acronyms)]

use std::collections::HashMap;
use std::sync::Arc;

use tacp::obfuscation::obfuscate_in_place;
use tacp::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, instrument};

mod testsupport;

#[derive(Debug, serde::Deserialize)]
struct TestConfig {
    key: String,
    users: HashMap<String, String>,
    denied_commands: Vec<String>,
}

enum AuthenState {
    Start,
    NeedUser,
    NeedPassword(String),
}

enum ServerReply {
    Authen(Box<AuthenReplyPacket>),
    Author(Box<AuthorReplyPacket>),
    Acct(Box<AcctReplyPacket>),
    Abort,
}

fn main() {
    tracing_subscriber::fmt::init();
    let controller =
        std::env::var("TACP_SERVER_TEST").expect("tserver must be started by the test controller");
    let config = Arc::new(testsupport::get_config(&controller));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        testsupport::ready(&controller, listener.local_addr().unwrap()).await;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(handle_conn(stream, Arc::clone(&config), controller.clone()));
        }
    });
}

#[instrument(skip_all)]
async fn handle_conn(mut stream: TcpStream, config: Arc<TestConfig>, controller: String) {
    let mut session_id = None;
    let mut expected_seq = 1;
    let mut authen_state = AuthenState::Start;

    loop {
        let mut header_bytes = [0; 12];
        if let Err(error) = stream.read_exact(&mut header_bytes).await {
            error!(?error, "failed to read packet header");
            return;
        }
        let header = match PacketHeader::try_from_bytes_ref(&header_bytes) {
            Ok(header) => header,
            Err(error) => {
                error!(?error, "failed to parse packet header");
                return;
            }
        };
        if header.seq_no != expected_seq {
            error!(
                actual = header.seq_no,
                expected = expected_seq,
                "unexpected client sequence number"
            );
            return;
        }
        if session_id.is_some_and(|id| id != header.session_id) {
            error!("session ID changed on an existing connection");
            return;
        }
        session_id = Some(header.session_id);

        let mut body = vec![0; header.length.get() as usize];
        if let Err(error) = stream.read_exact(&mut body).await {
            error!(?error, "failed to read packet body");
            return;
        }
        obfuscate_in_place(header, config.key.as_bytes(), &mut body);

        let reply = match header.ty {
            PacketType::AUTHEN => {
                handle_authen(&body, &mut authen_state, &config, &controller).await
            }
            PacketType::AUTHOR => handle_author(&body, &config, &controller).await,
            PacketType::ACCT => handle_acct(&body, &controller).await,
        };
        let (reply_type, mut reply_body, terminate_session) = match reply {
            ServerReply::Authen(packet) => {
                let terminate_session = matches!(
                    packet.status,
                    AuthenReplyStatus::PASS | AuthenReplyStatus::FAIL | AuthenReplyStatus::ERROR
                );
                (
                    PacketType::AUTHEN,
                    AuthenReplyPacket::boxed_to_bytes(packet),
                    terminate_session,
                )
            }
            ServerReply::Author(packet) => (
                PacketType::AUTHOR,
                AuthorReplyPacket::boxed_to_bytes(packet),
                true,
            ),
            ServerReply::Acct(packet) => (
                PacketType::ACCT,
                AcctReplyPacket::boxed_to_bytes(packet),
                true,
            ),
            ServerReply::Abort => return,
        };

        let reply_header = PacketHeader::new(
            header.version,
            reply_type,
            header.seq_no + 1,
            Flags(0),
            header.session_id.get(),
            reply_body.len() as u32,
        );
        obfuscate_in_place(&reply_header, config.key.as_bytes(), &mut reply_body);
        if let Err(error) = send_reply(&mut stream, reply_header, &reply_body).await {
            error!(?error, "failed to send reply");
            return;
        }
        if terminate_session {
            return;
        }
        expected_seq += 2;
    }
}

async fn send_reply(
    stream: &mut TcpStream,
    header: PacketHeader,
    body: &[u8],
) -> tokio::io::Result<()> {
    stream.write_all(header.bytes()).await?;
    stream.write_all(body).await
}

async fn handle_authen(
    body: &[u8],
    state: &mut AuthenState,
    config: &TestConfig,
    controller: &str,
) -> ServerReply {
    match state {
        AuthenState::Start => {
            let packet = match AuthenStartPacket::try_from_bytes_ref(body) {
                Ok(packet) if packet.len() == body.len() => packet,
                Ok(_) => return authen_error("packet length mismatch"),
                Err(error) => return authen_error(&error.to_string()),
            };
            match packet.authen_type {
                AuthenType::ASCII => {
                    let Some(username) = packet
                        .get_user()
                        .filter(|value| !value.is_empty())
                        .map(|value| String::from_utf8_lossy(value).into_owned())
                    else {
                        *state = AuthenState::NeedUser;
                        return ServerReply::Authen(
                            AuthenReplyPacket::new(
                                AuthenReplyStatus::GETUSER,
                                AuthenReplyFlags(0),
                                b"Username required",
                                &[],
                            )
                            .unwrap(),
                        );
                    };
                    *state = AuthenState::NeedPassword(username);
                    request_password()
                }
                AuthenType::PAP => {
                    let username = String::from_utf8_lossy(packet.get_user().unwrap_or_default());
                    let password = String::from_utf8_lossy(packet.get_data().unwrap_or_default());
                    authentication_result(config, controller, &username, &password).await
                }
                _ => authen_error("unsupported authentication type"),
            }
        }
        AuthenState::NeedUser => {
            let Some(message) = authen_continue(body) else {
                return authen_error("invalid authentication continuation");
            };
            if message.0 {
                return ServerReply::Abort;
            }
            if message.1.is_empty() {
                return authen_error("username was not supplied");
            }
            *state = AuthenState::NeedPassword(message.1);
            request_password()
        }
        AuthenState::NeedPassword(username) => {
            let Some(message) = authen_continue(body) else {
                return authen_error("invalid authentication continuation");
            };
            if message.0 {
                return ServerReply::Abort;
            }
            authentication_result(config, controller, username, &message.1).await
        }
    }
}

fn authen_continue(body: &[u8]) -> Option<(bool, String)> {
    let packet = AuthenContinuePacket::try_from_bytes_ref(body).ok()?;
    if packet.len() != body.len() {
        return None;
    }
    Some((
        packet.flags.intersects(AuthenContinueFlags::FLAG_ABORT),
        String::from_utf8_lossy(packet.get_user_msg().unwrap_or_default()).into_owned(),
    ))
}

fn request_password() -> ServerReply {
    ServerReply::Authen(
        AuthenReplyPacket::new(
            AuthenReplyStatus::GETPASS,
            AuthenReplyFlags::REPLY_NOECHO,
            b"Password required",
            &[],
        )
        .unwrap(),
    )
}

async fn authentication_result(
    config: &TestConfig,
    controller: &str,
    username: &str,
    password: &str,
) -> ServerReply {
    let success = config
        .users
        .get(username)
        .is_some_and(|expected| expected == password);
    testsupport::report(controller, PacketType::AUTHEN, success, username, None).await;
    let (status, message): (_, &[u8]) = if success {
        (AuthenReplyStatus::PASS, b"Authentication PASS")
    } else {
        (AuthenReplyStatus::FAIL, b"Authentication FAIL")
    };
    ServerReply::Authen(AuthenReplyPacket::new(status, AuthenReplyFlags(0), message, &[]).unwrap())
}

fn authen_error(message: &str) -> ServerReply {
    ServerReply::Authen(
        AuthenReplyPacket::new(
            AuthenReplyStatus::ERROR,
            AuthenReplyFlags(0),
            message.as_bytes(),
            &[],
        )
        .unwrap(),
    )
}

async fn handle_author(body: &[u8], config: &TestConfig, controller: &str) -> ServerReply {
    let packet = match AuthorRequestPacket::try_from_bytes_ref(body) {
        Ok(packet) if packet.len() == body.len() => packet,
        _ => return author_error("invalid authorization request"),
    };
    let username = String::from_utf8_lossy(packet.get_user().unwrap_or_default()).into_owned();
    let command = packet.iter_args().flatten().find_map(|argument| {
        if argument.argument == "cmd" {
            argument.value.as_str().map(str::to_owned)
        } else {
            None
        }
    });
    let success = command.is_some_and(|command| {
        config.users.contains_key(&username)
            && !config
                .denied_commands
                .iter()
                .any(|denied| denied == &command)
    });
    testsupport::report(controller, PacketType::AUTHOR, success, &username, None).await;
    let (status, message): (_, &[u8]) = if success {
        (AuthorStatus::PASS_ADD, b"Approved")
    } else {
        (AuthorStatus::FAIL, b"Denied")
    };
    ServerReply::Author(AuthorReplyPacket::new(status, &[], message, &[]).unwrap())
}

fn author_error(message: &str) -> ServerReply {
    ServerReply::Author(
        AuthorReplyPacket::new(AuthorStatus::ERROR, &[], message.as_bytes(), &[]).unwrap(),
    )
}

async fn handle_acct(body: &[u8], controller: &str) -> ServerReply {
    let packet = match AcctRequestPacket::try_from_bytes_ref(body) {
        Ok(packet) if packet.len() == body.len() => packet,
        _ => return acct_error("invalid accounting request"),
    };
    let username = String::from_utf8_lossy(packet.get_user().unwrap_or_default()).into_owned();
    let arguments = packet
        .iter_args()
        .flatten()
        .map(|argument| argument.to_string())
        .collect::<Vec<_>>()
        .join(";");
    testsupport::report(
        controller,
        PacketType::ACCT,
        true,
        &username,
        Some(&arguments),
    )
    .await;
    ServerReply::Acct(AcctReplyPacket::new(AcctStatus::SUCCESS, b"Ok", &[]).unwrap())
}

fn acct_error(message: &str) -> ServerReply {
    ServerReply::Acct(AcctReplyPacket::new(AcctStatus::ERROR, message.as_bytes(), &[]).unwrap())
}
