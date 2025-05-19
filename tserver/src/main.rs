#![allow(clippy::needless_return, clippy::upper_case_acronyms, clippy::single_match)]
#![deny(clippy::await_holding_lock)]
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use policy::{ClientPolicy, Policy};
use tacp::*;
use tacp::obfuscation::obfuscate_in_place;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::*;
use smallvec::*;
use fnv::FnvHashMap;
use std::ops::Deref;
use tracing::{error, info, instrument, debug};
use zerocopy::byteorder::network_endian::U32;

mod policy;
mod testsupport;
type PacketBuf = [u8;256];

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
/// Tracks current client authentication state within a session
enum AuthenState {
    None,
    ASCIIGETUSER,
    ASCIIGETPASS,
}

/// Represents reply packets from the server to the client
enum SrvPacket {
    /// Authen REPLY packet (may or may not terminate session)
    AuthenReply(Box<AuthenReplyPacket>),
    /// Acknowledge a client AUTH packet with the client abort flag set (terminates session).
    /// The attached String is a message from the client with an explanation, it is logged to the console.
    AuthenClientAbort(String),
    /// An Authen REPLY packet indicating server side error with an optional ASCII message (terminates session)
    AuthenGenericError(Option<Vec<u8>>),
    /// Author REPLY packet (terminates session)
    AuthorReply(Box<AuthorReplyPacket>),
    /// Author REPLY packet indicating server side error with an optional ASCII message (terminates session)
    AuthorGenericError(Option<Vec<u8>>),
    /// Acct REPLY packet (terminates session)
    AcctReply(Box<AcctReplyPacket>),
    /// Acct REPLY packet indicating server side error with an optional ASCII message (terminates session)
    AcctGenericError(Option<Vec<u8>>),
}

#[derive(Clone, Hash, Default)]
/// A String wrapper designed to hold secrets.
/// It's main purpose is to prevent the unintentional logging of said secrets.
/// This is acomplished by not implementing `Display` and manually implementing `Debug`.
/// Any other security is not a hard goal, but it does attempt to clear it's own memory on destruction.
struct SString(String);
impl Drop for SString {
    fn drop(&mut self) {
        self.zero();
        let _ = std::hint::black_box(self);
    }
}
impl std::fmt::Debug for SString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SString: Data Masked")
    }
}
impl SString {
    fn zero(&mut self) {
        const _: () = assert!(std::mem::align_of::<u8>() == 1); // Is there an arch where this is false?
        let ptr = self.0.as_mut_ptr();
        let len = self.0.capacity();
        for off in 0..len {
            unsafe { std::ptr::write_volatile(ptr.add(off), 0); }
        }
    }
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}



#[derive(Debug, Clone, Hash, Default)]
/// The currently known info about a clients authentication attempt
/// When a client is done giving us info, this struct is used to determine
/// if authentication will PASS or FAIL
struct AuthenInfo {
    pub username: Option<String>,
    pub pass: Option<SString>,
}

#[derive(Debug, Clone, Hash)]
/// Main client state. One per session.
struct Client {
    addr: std::net::SocketAddr,
    session: SessionID,
    seq_no: SeqNo,
    authen_state: AuthenState,
    authen_info: AuthenInfo,
    key: SString,
}

#[derive(Debug, Default)]
/// Maps sessions to the corresponding state. One per server shard (sharding not implemented)
struct ServerState(FnvHashMap<SessionID, Client>);
/// Application wide instance of the state
static GLOBAL_STATE: OnceLock<Mutex<ServerState>> = OnceLock::new();
/// Application wide instance of the policy
static POLICY: OnceLock<Policy> = OnceLock::new();
/// HTTP endpoint for testing
static TEST_MODE: OnceLock<String> = OnceLock::new();

fn main() {
    tracing_subscriber::fmt::init();
    GLOBAL_STATE.set(Default::default()).unwrap();
    let policy_file_str = if let Ok(addr) = std::env::var("TACP_SERVER_TEST") {
        TEST_MODE.set(addr.clone()).unwrap();
        testsupport::getpolicy_blocking(&format!("http://{addr}/server_policy"))
    }
    else {
        let f = std::env::var("TACP_SERVER_POLICY_FILE").unwrap_or("policy.yaml".to_owned());
        let policy_file = std::fs::read_to_string(&f);
        if let Err(e) = policy_file {
            panic!("Failed to read policy file: {f}\n{e:?}");
        }
        policy_file.unwrap()
    };
    match policy::parse::load(&    policy_file_str) {
        Ok(pol) => {
            POLICY.set(pol).unwrap();
        },
        Err(e) => {
            error!("Failed to load policy {e}");
            return;
        },
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build().unwrap();
    rt.block_on(async {
        let bind_info = POLICY.get().unwrap().bind_info.to_socket_addrs().unwrap().next().unwrap();
        let s = TcpListener::bind(bind_info).await.unwrap();
        loop {
            let (stream, addr) = s.accept().await.unwrap();
            tokio::task::spawn(handle_conn(stream, addr));
        }
    });
}

#[instrument]
async fn handle_conn(mut stream: TcpStream, addr: std::net::SocketAddr) {
    let policy = POLICY.get().unwrap();
    let client_policy = match policy.clients.get(&addr.ip()) {
        Some(client_pol) => {
            client_pol.clone()
        },
        None if policy.allow_unconfigured => {
            ClientPolicy::default()
        }
        None => {
            error!("Unconfigured client disallowed");
            return;
        }
    };
    let key = match (&client_policy.key, &policy.default_key) {
        (None, Some(dk)) => dk,
        (Some(ck), None) |
        (Some(ck), Some(_)) => ck,
        (None, None) => {
            error!("No client key and no default key");
            return;
        },
    };
    debug!(policy = ?client_policy, "client setup done");
    loop {
        let mut header = [0;12];
        match stream.read_exact(&mut header).await {
            Ok(_) => { /* read exact */}
            Err(e) => {
                error!(err = ?e, "Error reading packet header from stream.");
                break;
            }
        }
        let parsed_header = match PacketHeader::try_ref_from_bytes(&header) {
            Ok(ph) => ph,
            Err(e) => {
                error!(err = ?e, "Failed to parse packet header");
                break;
            }
        };
        if parsed_header.seq_no % 2 == 0 {
            error!(seq_no = ?parsed_header.seq_no, "Clients MUST send odd sequence numbers.");
            break;
        }
        let mut cstate: Client;
        {
            let mut gs = GLOBAL_STATE.get().unwrap().lock().unwrap();
            if let Some(cs) = gs.0.get(&parsed_header.session_id) {
                cstate = cs.clone();
            } else {
                assert!(parsed_header.seq_no == 1);
                cstate = Client {
                    addr,
                    session: parsed_header.session_id,
                    seq_no: parsed_header.seq_no,
                    authen_state: AuthenState::None,
                    authen_info: Default::default(),
                    key: SString(Default::default()),
                };
                gs.0.insert(parsed_header.session_id, cstate.clone());
            }
        }
        if addr != cstate.addr || parsed_header.seq_no < cstate.seq_no {
            error!(state_addr = ?cstate.addr, our_seq = ?parsed_header.seq_no, state_seq = ?cstate.seq_no,
                "Internal consistency error. Malicious client or stale entry in global state");
            break;
        }
        if (parsed_header.seq_no - 1 != cstate.seq_no) && !(cstate.seq_no == 1 && parsed_header.seq_no == 1) {
            error!(state_addr = ?cstate.addr, our_seq = ?parsed_header.seq_no, state_seq = ?cstate.seq_no,
                "Missed packet or malicious client. Sequence number incremented by more than 1");
            break;
        }
        cstate.seq_no = parsed_header.seq_no;
        debug!(?parsed_header);
        let mut packet: SmallVec<PacketBuf> = SmallVec::with_capacity(parsed_header.length.get() as usize);
        packet.resize_with(parsed_header.length.get() as usize, Default::default);
        if let Err(e) = stream.read_exact(&mut packet).await {
            error!(err = ?e, "Error reading packet body from stream");
            break;
        }
        obfuscate_in_place(parsed_header, key.as_bytes(), &mut packet);
        let reply = match parsed_header.ty {
            PacketType::AUTHEN => handle_authen_packet(parsed_header.length.get() as usize, packet, &mut cstate).await,
            PacketType::AUTHOR => handle_author_packet(parsed_header.length.get() as usize, packet, &mut cstate).await,
            PacketType::ACCT   => handle_acct_packet(parsed_header.length.get() as usize, packet, &mut cstate).await,
        };
        let mut terminate_session = false;
        match reply {
            SrvPacket::AuthenReply(pkt) => {
                match pkt.status {
                    AuthenReplyStatus::PASS |
                    AuthenReplyStatus::FAIL |
                    AuthenReplyStatus::ERROR => {
                        terminate_session = true;
                    },
                    _ => {},
                }
                cstate.seq_no += 1;
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::AUTHEN,
                    seq_no: cstate.seq_no,
                    flags: 0,
                    session_id: cstate.session,
                    length: U32::new(pkt.len() as u32),
                };
                let mut packet_body = unsafe { AuthenReplyPacket::boxed_to_bytes(pkt) };
                obfuscate_in_place(&header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            },
            SrvPacket::AuthenClientAbort(reason) => {
                terminate_session = true;
                println!("Client abort: reason: {}", reason);
            }
            SrvPacket::AuthenGenericError(msg) => {
                terminate_session = true;
                let mut pkt = unsafe { AuthenReplyPacket::boxed_to_bytes(AuthenReplyPacket::new(
                    AuthenReplyStatus::ERROR,
                    0,
                    &msg.unwrap_or("Unimplemented".into()),
                    &Vec::with_capacity(0)
                ).unwrap())};
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::AUTHEN,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: U32::new(pkt.len() as u32),
                };
                obfuscate_in_place(&header, key.as_bytes(), &mut pkt);
                send_reply(&mut stream, header, &pkt).await.unwrap();
            }
            SrvPacket::AuthorReply(pkt) => {
                terminate_session = true;
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::AUTHOR,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: U32::new(pkt.len() as u32),
                };
                let mut packet_body = unsafe { AuthorReplyPacket::boxed_to_bytes(pkt) };
                obfuscate_in_place(&header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            },
            SrvPacket::AuthorGenericError(msg) => {
                terminate_session = true;
                let mut pkt = unsafe {AuthorReplyPacket::boxed_to_bytes(AuthorReplyPacket::new(
                    AuthorStatus::ERROR,
                    &Vec::with_capacity(0),
                    &msg.unwrap_or("Generic error".into()),
                    &Vec::with_capacity(0),
                ).unwrap())};
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::AUTHOR,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: U32::new(pkt.len() as u32),
                };
                obfuscate_in_place(&header, key.as_bytes(), &mut pkt);
                send_reply(&mut stream, header, &pkt).await.unwrap();
            }
            SrvPacket::AcctReply(pkt) => {
                terminate_session = true;
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::ACCT,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: U32::new(pkt.len() as u32),
                };
                let mut packet_body = unsafe { AcctReplyPacket::boxed_to_bytes(pkt) };
                obfuscate_in_place(&header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            }
            SrvPacket::AcctGenericError(msg) => {
                terminate_session = true;
                let mut pkt = unsafe { AcctReplyPacket::boxed_to_bytes(AcctReplyPacket::new(
                    AcctStatus::ERROR,
                    &msg.unwrap_or("Generic error".into()),
                    &Vec::with_capacity(0),
                ).unwrap())};
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::ACCT,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: U32::new(pkt.len() as u32),
                };
                obfuscate_in_place(&header, key.as_bytes(), &mut pkt);
                send_reply(&mut stream, header, &pkt).await.unwrap();
            }
        }
        {
            let mut gs = GLOBAL_STATE.get().unwrap().lock().unwrap();
            if terminate_session {
                info!(session = ?cstate.session, "Session terminated");
                if gs.0.remove(&cstate.session).is_none() {
                    error!(session = ?cstate.session, "Internal consistency error, no client state for this session.")
                }
                break;
            }
            else if let Some(cs) = gs.0.get_mut(&cstate.session) {
                *cs = cstate;
            }
            else {
                error!(session = ?cstate.session, "Internal consistency error, no client state for session.");
                break;
            }
        }
        // Allow other tasks to run
        tokio::task::yield_now().await;
    } /* Loop */
}

#[instrument]
async fn send_reply(stream: &mut TcpStream, header: PacketHeader, obfuscated_body: &[u8]) -> tokio::io::Result<()> {
    use zerocopy::*;
    assert!(header.seq_no % 2 == 0); // Servers MUST send even sequence numbers. If this trips, we're off somewhere.
    let mut reply = Vec::with_capacity(header.length.get() as usize);
    reply.resize(12, 0);
    header.write_to_prefix(&mut reply).unwrap();
    reply.extend_from_slice(obfuscated_body);
    stream.write_all(&reply).await?;
    Ok(())
}

#[instrument]
async fn handle_authen_packet(expected_length: usize, packet: SmallVec<PacketBuf>, cstate: &mut Client) -> SrvPacket {
    hexdump::hexdump(&packet);
    match cstate.authen_state {
        AuthenState::None => { // We have nothing so far, so this is a AUTHEN START packet
            info!("Authen START");
            let pkt = AuthenStartPacket::try_ref_from_bytes(&packet);
            if let Err(err) = pkt {
                error!("Packet Parse Failure");
                return SrvPacket::AuthenGenericError(Some(err.to_string().into()));
            }
            let pkt = pkt.unwrap();
            if pkt.len() != expected_length { // probably key failure
                error!(expected = ?expected_length, actual = ?pkt.len(), "Packet len does not match expected. Probable key failure");
                return SrvPacket::AuthenGenericError(Some("pkt len does not match header len".into()));
            }
            match pkt.authen_type {
                AuthenType::ASCII => return authen_start_ascii(pkt, cstate).await,
                AuthenType::PAP => return authen_start_pap(pkt, cstate).await,
                AuthenType::CHAP |
                AuthenType::MSCHAP_V1 |
                AuthenType::MSCHAP_V2 => return SrvPacket::AuthenGenericError(Some("This server does not implement CHAP".into())),
            }
        },
        AuthenState::ASCIIGETUSER => { // We've replied, so this is a AUTHEN CONTINUE packet
            let pkt = parse_authen_continue(packet.deref(), expected_length).unwrap();
            if pkt.flags & 0x1 == 1 { //FIXME Abort flag
                let reason = String::from_utf8_lossy(pkt.get_data().unwrap_or_default());
                info!(reason = ?reason, "Client Aborted Authentication Session");
                return SrvPacket::AuthenClientAbort(reason.into());
            }
            if pkt.get_user_msg().is_none() || pkt.get_user_msg().is_some_and(|x|x.is_empty()) {
                error!("Server request username but none provided");
                return SrvPacket::AuthenGenericError(Some("Server requested username but none provided".into())); // We asked for a username
            }
            cstate.authen_info.username = Some(String::from_utf8_lossy(pkt.get_user_msg().unwrap()).into());
            debug!(username = ?cstate.authen_info.username, "Client provides username");
            let ret = unsafe { AuthenReplyPacket::new(AuthenReplyStatus::GETPASS, 1<<REPLY_FLAG_NOECHO, &Vec::from(b"Enter pass"), &Vec::with_capacity(0)).unwrap() };
            cstate.authen_state = AuthenState::ASCIIGETPASS;
            info!("requesting ascii password from client");
            return SrvPacket::AuthenReply(ret);
        },
        AuthenState::ASCIIGETPASS => {
            let pkt = parse_authen_continue(packet.deref(), expected_length).unwrap();
            if pkt.flags & 0x1 == 1 { //FIXME Abort flag
                let reason = String::from_utf8_lossy(pkt.get_data().unwrap_or_default());
                return SrvPacket::AuthenClientAbort(reason.into());
            }
            if pkt.get_user_msg().is_none() || pkt.get_user_msg().is_some_and(|x|x.is_empty()) {
                return SrvPacket::AuthenGenericError(Some("Server requested a password but none provided".into())); // We asked for a pass
            }
            cstate.authen_info.pass = Some(
                SString(String::from_utf8_lossy(pkt.get_user_msg().unwrap()).into())
            );
            let ret = unsafe {
                if check_auth(&cstate.authen_info, cstate.addr.ip()) {
                    testsupport::report(PacketType::AUTHEN, true, &cstate.authen_info.username.as_ref().unwrap(), "").await;
                    AuthenReplyPacket::new(
                        AuthenReplyStatus::PASS,
                        0,
                        &Vec::from(b"Authentication Pass"),
                        &Vec::with_capacity(0),
                    ).unwrap()
                }
                else {
                    testsupport::report(PacketType::AUTHEN, false, &cstate.authen_info.username.as_ref().unwrap(), "").await;
                    AuthenReplyPacket::new(
                        AuthenReplyStatus::FAIL,
                        0,
                        &Vec::from(b"Authentication Fail"),
                        &Vec::with_capacity(0),
                    ).unwrap()
                }};
            return SrvPacket::AuthenReply(ret);
        },
    }
}

#[instrument]
fn parse_authen_continue(data: &[u8], expected_length: usize) -> core::result::Result<&AuthenContinuePacket, TacpErr> {

    let pkt = AuthenContinuePacket::try_ref_from_bytes(data)?;
    if pkt.len() != expected_length {
        return Err(TacpErr::ParseError(format!("Parsed AuthenContinuePacket length {}. Header length: {expected_length}", pkt.len())));
    }
    Ok(pkt)
}

fn check_auth(info: &AuthenInfo, client: IpAddr) -> bool {
    if info.username.is_none() || info.pass.is_none() {
        return false;
    }
    let user: &String = info.username.as_ref().unwrap();
    let pass: &SString = info.pass.as_ref().unwrap();
    let policy = POLICY.get().unwrap();
    policy::enforce::authenticate(policy, client, user, pass)
}

async fn authen_start_ascii(pkt: &AuthenStartPacket, cstate: &mut Client) -> SrvPacket {
    if pkt.get_user().is_none() {
        let ret = unsafe { AuthenReplyPacket::new(
            AuthenReplyStatus::GETUSER,
            0,
            &Vec::from(b"Username required: "),
            &Vec::with_capacity(0),
        ).unwrap()};
        cstate.authen_state = AuthenState::ASCIIGETUSER;
        return SrvPacket::AuthenReply(ret);
    }
    cstate.authen_info.username = Some(String::from_utf8_lossy(pkt.get_user().unwrap()).into());
    if cstate.authen_info.pass.is_none() {
        let ret = unsafe { AuthenReplyPacket::new(
            AuthenReplyStatus::GETPASS,
            1 << REPLY_FLAG_NOECHO,
            &Vec::from(b"Enter pass"),
            &Vec::with_capacity(0),
        ).unwrap()};
        cstate.authen_state = AuthenState::ASCIIGETPASS;
        return SrvPacket::AuthenReply(ret);
    }
    return SrvPacket::AuthenGenericError(None);
}

async fn authen_start_pap(pkt: &AuthenStartPacket, cstate: &Client) -> SrvPacket {
    if pkt.get_user().is_none() {
        let ret = unsafe { AuthenReplyPacket::new(
            AuthenReplyStatus::ERROR,
            0,
            &Vec::from(b"Failed to supply username"),
            &Vec::with_capacity(0),
        ).unwrap()};
        return SrvPacket::AuthenReply(ret);
    }
    let info = AuthenInfo {
        username: Some(String::from_utf8_lossy(pkt.get_user().unwrap()).into()),
        pass: Some(SString(String::from_utf8_lossy(pkt.get_data().unwrap_or_default()).into())),
    };
    let ret = unsafe {
        if check_auth(&info, cstate.addr.ip()) {
            testsupport::report(PacketType::AUTHEN, true, info.username.as_ref().unwrap(), "").await;
            AuthenReplyPacket::new(
                AuthenReplyStatus::PASS,
                0,
                &Vec::from(b"PAP Authentication PASS"),
                &Vec::with_capacity(0),
            ).unwrap()
        }
        else {
            testsupport::report(PacketType::AUTHEN, false, info.username.as_ref().unwrap(), "").await;
            AuthenReplyPacket::new(
                AuthenReplyStatus::FAIL,
                0,
                &Vec::from(b"PAP Authentication FAIL"),
                &Vec::with_capacity(0),
            ).unwrap()
        }};
    return SrvPacket::AuthenReply(ret);
}

#[instrument]
async fn handle_author_packet(expected_length: usize, packet: SmallVec<PacketBuf>, cstate: &mut Client) -> SrvPacket {
    let pkt = AuthorRequestPacket::try_ref_from_bytes(&packet);
    if pkt.is_err() {
        return SrvPacket::AuthorGenericError(Some("Failed to parse".into()));
    }
    let pkt = pkt.unwrap();
    if pkt.len() != expected_length {
        dbg!((pkt.len(), expected_length));
        return SrvPacket::AuthorGenericError(Some("Packet length mismatch".into()));
    }
    let mut cmd = None;
    for arg in pkt.iter_args().flatten() {
        if arg.argument == "cmd" && arg.value.as_str().is_some() {
            cmd = Some(arg);
            break;
        }
    }
    // reporting
    let user = pkt.get_user().unwrap_or(&[]);
    let user = String::from_utf8_lossy(user).into_owned();
    if cmd.is_none() {
        testsupport::report(tacp::PacketType::AUTHOR, false, &user, "No Command AV Pair").await;
        return unsafe { SrvPacket::AuthorReply(AuthorReplyPacket::new(
            AuthorStatus::FAIL, // fixme; use reply
            &Vec::with_capacity(0),
            &Vec::from("No cmd argument. Can not authorize!"),
            &Vec::with_capacity(0),
        ).unwrap())};
    }
    // Stupid lifetimes
    let cmd = cmd.unwrap().value;
    let cmd = cmd.as_str().unwrap();

    let res = policy::enforce::authorize(POLICY.get().unwrap(), cstate.addr.ip(), &String::from_utf8_lossy(pkt.get_user().unwrap_or_default()), cmd);
    let ret = unsafe { if res {
        testsupport::report(tacp::PacketType::AUTHOR, true, &user, "").await;
        AuthorReplyPacket::new(
            AuthorStatus::PASS_ADD,
            &Vec::with_capacity(0),
            &Vec::from(b"Approved"),
            &Vec::with_capacity(0),
        ).unwrap()
    }
    else {
        testsupport::report(tacp::PacketType::AUTHOR, false, &user, "").await;
        AuthorReplyPacket::new(
            AuthorStatus::FAIL,
            &Vec::with_capacity(0),
            &Vec::from(b"Denied"),
            &Vec::with_capacity(0),
        ).unwrap()
    }};
    return SrvPacket::AuthorReply(ret);
}

#[instrument]
async fn handle_acct_packet(expected_length: usize, packet: SmallVec<PacketBuf>, cstate: &mut Client) -> SrvPacket {
    let pkt = AcctRequestPacket::try_ref_from_bytes(&packet);
    // let pkt = AcctRequestPacket::try_from(packet.deref());
    if pkt.is_err() {
        return SrvPacket::AcctGenericError(Some("Failed to parse".into()));
    }
    let pkt = pkt.unwrap();
    if pkt.len() != expected_length {
        dbg!((pkt.len(), expected_length));
        return SrvPacket::AcctGenericError(Some("Length mismatch".into()));
    }
    let user = pkt.get_user().unwrap_or(&[]);
    let user = String::from_utf8_lossy(user).into_owned();
    let mut to_log = String::new(); // this is a bit gross
    for x in pkt.iter_args() {
        if let Ok(y) = x {
            to_log.push_str(&String::from_utf8_lossy(&y.to_vec()));
            to_log.push(';');
        }
    }
    let ret;
    { // scoped because Box<dyn ...> ruins async
        // fixme, log string better
        let x = policy::enforce::account(
            POLICY.get().unwrap(),
            cstate.addr.ip(),
            &user,
            &to_log
        ).await;
        ret = match x {
            Ok(_) => {
                unsafe { AcctReplyPacket::new(
                    AcctStatus::SUCCESS,
                    &Vec::from(b"Ok"),
                    &Vec::with_capacity(0),
                ).unwrap() }
            },
            Err(ref e) => {
                error!("{e:?}");
                unsafe { AcctReplyPacket::new(
                    AcctStatus::ERROR,
                    &Vec::from(b"Failed"),
                    &Vec::with_capacity(0)
                    ).unwrap() }
            }
        };
    }
    match ret.status {
        AcctStatus::SUCCESS => {
            testsupport::report(tacp::PacketType::ACCT, true, &user, "").await;
        },
        AcctStatus::ERROR => {
            testsupport::report(tacp::PacketType::ACCT, false, &user, "").await;
        },
    }
    return SrvPacket::AcctReply(ret);
}