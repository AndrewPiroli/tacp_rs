#![feature(let_chains)]
#![allow(clippy::needless_return, clippy::upper_case_acronyms)]
#![deny(clippy::await_holding_lock)]
use std::sync::Mutex;
use policy::Policy;
use tacp::argvalpair::Value;
use tacp::*;
use tacp::obfuscation::obfuscate_in_place;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::*;
use smallvec::*;
use fnv::FnvHashMap;
use std::sync::OnceLock;
use std::ops::Deref;
use tracing::{error, info, instrument, debug};

mod policy;
type PacketBuf = [u8;256];

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
/// Tracks current client authentication state within a session
enum AuthenState {
    None,
    ASCIIGETUSER,
    ASCIIGETPASS,
}

#[derive(Debug, Clone)]
/// Represents reply packets from the server to the client
enum SrvPacket {
    /// Authen REPLY packet (may or may not terminate session)
    AuthenReply(AuthenReplyPacket),
    /// Acknowledge a client AUTH packet with the client abort flag set (terminates session).
    /// The attached String is a message from the client with an explanation, it is logged to the console.
    AuthenClientAbort(String),
    /// An Authen REPLY packet indicating server side error with an optional ASCII message (terminates session)
    AuthenGenericError(Option<Vec<u8>>),
    /// Author REPLY packet (terminates session)
    AuthorReply(AuthorReplyPacket),
    /// Author REPLY packet indicating server side error with an optional ASCII message (terminates session)
    AuthorGenericError(Option<Vec<u8>>),
    /// Acct REPLY packet (terminates session)
    AcctReply(AcctReplyPacket),
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
        let len = self.0.len();
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

fn main() {
    tracing_subscriber::fmt::init();
    GLOBAL_STATE.set(Default::default()).unwrap();
    match policy::parse::load() {
        Ok(pol) => {
            POLICY.set(pol).unwrap();
        },
        Err(e) => {
            error!("Failed to load policy {e}");
            return;
        },
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_io().build().unwrap();
    rt.block_on(async {
        let s = TcpListener::bind("0.0.0.0:9999").await.unwrap();
        loop {
            let (stream, addr) = s.accept().await.unwrap();
            tokio::task::spawn(handle_conn(stream, addr));
        }
    });
}

#[instrument]
async fn handle_conn(mut stream: TcpStream, addr: std::net::SocketAddr) {
    let policy = POLICY.get().unwrap();
    if !policy.clients.contains_key(&addr.ip()) && !policy.allow_unconfigured {
        error!("Unconfigured client disallowed");
        return;
    }
    let client_policy = policy.clients.get(&addr.ip()).cloned().unwrap_or_default();
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
            }
        }
        let parsed_header = PacketHeader::try_from(&header).unwrap();
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
        debug!(?parsed_header);
        let mut packet: SmallVec<PacketBuf> = SmallVec::with_capacity(parsed_header.length as usize);
        packet.resize_with(parsed_header.length as usize, Default::default);
        match stream.read_exact(&mut packet).await {
            Ok(_) => {},
            Err(e) => {
                error!(err = ?e, "Error reading packet body from stream");
                break;
            }
        }
        obfuscate_in_place(parsed_header, key.as_bytes(), &mut packet);
        let reply = match parsed_header.ty {
            PacketType::AUTHEN => handle_authen_packet(parsed_header.length as usize, packet, &mut cstate),
            PacketType::AUTHOR => handle_author_packet(parsed_header.length as usize, packet, &mut cstate),
            PacketType::ACCT   => handle_acct_packet(parsed_header.length as usize, packet, &mut cstate),
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
                    length: pkt.len() as u32,
                };
                let mut packet_body = pkt.encode();
                obfuscate_in_place(header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            },
            SrvPacket::AuthenClientAbort(reason) => {
                terminate_session = true;
                println!("Client abort: reason: {}", reason);
            }
            SrvPacket::AuthenGenericError(msg) => {
                terminate_session = true;
                let pkt = AuthenReplyPacket {
                    status: AuthenReplyStatus::ERROR,
                    flags: 0,
                    serv_msg: msg.unwrap_or(Vec::from(b"Unimplemented")),
                    data: Vec::with_capacity(0)
                };
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::AUTHEN,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: pkt.len() as u32,
                };
                let mut packet_body = pkt.encode();
                obfuscate_in_place(header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            }
            SrvPacket::AuthorReply(pkt) => {
                terminate_session = true;
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::AUTHOR,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: pkt.len() as u32,
                };
                let mut packet_body = pkt.encode();
                obfuscate_in_place(header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            },
            SrvPacket::AuthorGenericError(msg) => {
                terminate_session = true;
                let pkt = AuthorReplyPacket {
                    status: AuthorStatus::ERROR,
                    args: Vec::with_capacity(0),
                    server_msg: msg.unwrap_or(Vec::from(b"Generic error")),
                    data: Vec::with_capacity(0),
                };
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::AUTHOR,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: pkt.len() as u32,
                };
                let mut packet_body = pkt.encode();
                obfuscate_in_place(header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            }
            SrvPacket::AcctReply(pkt) => {
                terminate_session = true;
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::ACCT,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: pkt.len() as u32,
                };
                let mut packet_body = pkt.encode();
                obfuscate_in_place(header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
            }
            SrvPacket::AcctGenericError(msg) => {
                terminate_session = true;
                let pkt = AcctReplyPacket{
                    status: AcctStatus::ERROR,
                    server_msg: msg.unwrap_or(Vec::from(b"Generic error")),
                    data: Vec::with_capacity(0),
                };
                let header = PacketHeader {
                    version: parsed_header.version,
                    ty: PacketType::ACCT,
                    seq_no: cstate.seq_no + 1,
                    flags: 0,
                    session_id: cstate.session,
                    length: pkt.len() as u32,
                };
                let mut packet_body = pkt.encode();
                obfuscate_in_place(header, key.as_bytes(), &mut packet_body);
                send_reply(&mut stream, header, &packet_body).await.unwrap();
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
        tokio::task::yield_now().await;
    }
}

#[instrument]
async fn send_reply(stream: &mut TcpStream, header: PacketHeader, obfuscated_body: &[u8]) -> tokio::io::Result<()> {
    let mut reply = header.encode();
    reply.extend_from_slice(obfuscated_body);
    stream.write_all(&reply).await?;
    Ok(())
}

#[instrument]
fn handle_authen_packet(expected_length: usize, packet: SmallVec<PacketBuf>, cstate: &mut Client) -> SrvPacket {
    hexdump::hexdump(&packet);
    match cstate.authen_state {
        AuthenState::None => { // We have nothing so far, so this is a AUTHEN START packet
            info!("Authen START");
            let pkt = AuthenStartPacket::try_from(packet.deref());
            if pkt.is_err() {
                error!("Packet Parse Failure");
                return SrvPacket::AuthenGenericError(Some(pkt.unwrap_err().into()));
            }
            let pkt = pkt.unwrap();
            if pkt.len != expected_length { // probably key failure
                error!(expected = ?expected_length, actual = ?pkt.len, "Packet len does not match expected. Probable key failure");
                return SrvPacket::AuthenGenericError(Some(Vec::from(b"pkt len does not match header len")));
            }
            match pkt.authen_type {
                AuthenType::ASCII => return authen_start_ascii(&pkt, cstate),
                AuthenType::PAP => return authen_start_pap(&pkt),
                AuthenType::CHAP |
                AuthenType::MSCHAP_V1 |
                AuthenType::MSCHAP_V2 => return SrvPacket::AuthenGenericError(None),
            }
        },
        AuthenState::ASCIIGETUSER => { // We've replied, so this is a AUTHEN CONTINUE packet
            let pkt = parse_authen_continue(packet.deref(), expected_length).unwrap();
            if pkt.abort {
                let reason = String::from_utf8_lossy(&pkt.data);
                info!(reason = ?reason, "Client Aborted Authentication Session");
                return SrvPacket::AuthenClientAbort(reason.into());
            }
            if pkt.user_msg.is_empty() {
                error!("Server request username but none provided");
                return SrvPacket::AuthenGenericError(Some(Vec::from(b"Server requested username but none provided"))); // We asked for a username
            }
            cstate.authen_info.username = Some(String::from_utf8_lossy(&pkt.user_msg).into());
            debug!(username = ?cstate.authen_info.username, "Client provides username");
            let ret = AuthenReplyPacket {
                status: AuthenReplyStatus::GETPASS,
                flags: 1 << REPLY_FLAG_NOECHO,
                serv_msg: Vec::from(b"Enter pass"),
                data: Vec::with_capacity(0),
            };
            cstate.authen_state = AuthenState::ASCIIGETPASS;
            info!("requesting ascii password from client");
            return SrvPacket::AuthenReply(ret);
        },
        AuthenState::ASCIIGETPASS => {
            let pkt = parse_authen_continue(packet.deref(), expected_length).unwrap();
            if pkt.abort {
                let reason = String::from_utf8_lossy(&pkt.data);
                return SrvPacket::AuthenClientAbort(reason.into());
            }
            if pkt.user_msg.is_empty() {
                return SrvPacket::AuthenGenericError(Some(Vec::from(b"Server requested a password but none provided"))); // We asked for a pass
            }
            cstate.authen_info.pass = Some(
                SString(String::from_utf8_lossy(&pkt.user_msg).into())
            );
            let ret: AuthenReplyPacket =
                if check_auth(&cstate.authen_info) {
                    AuthenReplyPacket {
                        status: AuthenReplyStatus::PASS,
                        flags: 0,
                        serv_msg: Vec::from(b"Authentication Pass"),
                        data: Vec::with_capacity(0),
                    }
                }
                else {
                    AuthenReplyPacket {
                        status: AuthenReplyStatus::FAIL,
                        flags: 0,
                        serv_msg: Vec::from(b"Authentication Fail"),
                        data: Vec::with_capacity(0),
                    }
                };
            return SrvPacket::AuthenReply(ret);
        },
    }
}

#[instrument]
fn parse_authen_continue(data: &[u8], expected_length: usize) -> core::result::Result<AuthenContinuePacket, <AuthenContinuePacket as TryFrom<&[u8]>>::Error> {
    let pkt = AuthenContinuePacket::try_from(data)?;
    if pkt.len() != expected_length {
        return Err("Failed length check".to_owned());
    }
    Ok(pkt)
}

fn check_auth(info: &AuthenInfo) -> bool {
    if info.username.is_none() || info.pass.is_none() {
        return false;
    }
    let user: &String = info.username.as_ref().unwrap();
    let pass: &SString = info.pass.as_ref().unwrap();
    let policy = POLICY.get().unwrap();
    if let Some(user_pol) = policy.users.get(user)
        && user_pol.password.is_some()
    {
        return user_pol.password.as_ref().unwrap().0 == pass.0;
    }
    return false;
}

fn authen_start_ascii(pkt: &AuthenStartPacket, cstate: &mut Client) -> SrvPacket {
    if pkt.user.is_empty() {
        let ret = AuthenReplyPacket {
            status: AuthenReplyStatus::GETUSER,
            flags: 0,
            serv_msg: Vec::from(b"Username required: "),
            data: Vec::with_capacity(0),
        };
        cstate.authen_state = AuthenState::ASCIIGETUSER;
        return SrvPacket::AuthenReply(ret);
    }
    cstate.authen_info.username = Some(String::from_utf8_lossy(&pkt.user).into());
    if cstate.authen_info.pass.is_none() {
        let ret = AuthenReplyPacket {
            status: AuthenReplyStatus::GETPASS,
            flags: 1 << REPLY_FLAG_NOECHO,
            serv_msg: Vec::from(b"Enter pass"),
            data: Vec::with_capacity(0),
        };
        cstate.authen_state = AuthenState::ASCIIGETPASS;
        return SrvPacket::AuthenReply(ret);
    }
    return SrvPacket::AuthenGenericError(None);
}

fn authen_start_pap(pkt: &AuthenStartPacket) -> SrvPacket {
    if pkt.user.is_empty() {
        let ret = AuthenReplyPacket {
            status: AuthenReplyStatus::ERROR,
            flags: 0,
            serv_msg: Vec::from(b"Failed to supply username"),
            data: Vec::with_capacity(0),
        };
        return SrvPacket::AuthenReply(ret);
    }
    let info = AuthenInfo {
        username: Some(String::from_utf8_lossy(&pkt.user).into()),
        pass: Some(SString(String::from_utf8_lossy(&pkt.data).into())),
    };
    let ret =
        if check_auth(&info) {
            AuthenReplyPacket {
                status: AuthenReplyStatus::PASS,
                flags: 0,
                serv_msg: Vec::from(b"PAP Authentication PASS"),
                data: Vec::with_capacity(0),
            }
        }
        else {
            AuthenReplyPacket {
                status: AuthenReplyStatus::FAIL,
                flags: 0,
                serv_msg: Vec::from(b"PAP Authentication FAIL"),
                data: Vec::with_capacity(0),
            }
        };
    return SrvPacket::AuthenReply(ret);
}

#[instrument]
fn handle_author_packet(expected_length: usize, packet: SmallVec<PacketBuf>, cstate: &mut Client) -> SrvPacket {
    let pkt = AuthorRequestPacket::try_from(packet.deref());
    if pkt.is_err() {
        return SrvPacket::AuthorGenericError(Some(Vec::from(b"Failed to parse")));
    }
    let pkt = pkt.unwrap();
    if pkt.len != expected_length {
        dbg!((pkt.len, expected_length));
        return SrvPacket::AuthorGenericError(Some(Vec::from(b"Packet length mismatch")));
    }
    //fixme fixme fixme
    let mut cmd: Option<String> = None;
    for avp in pkt.args.iter() {
        if &avp.argument == "cmd" {
            match &avp.value {
                Value::Str(x) => {
                    cmd = Some(x.clone());
                }
                _ => { break; }
            }
        }
    }
    if cmd.is_none() {
        return SrvPacket::AuthorReply(AuthorReplyPacket {
            status: AuthorStatus::FAIL, // fixme; use reply
            args: Vec::with_capacity(0),
            server_msg: Vec::from("No cmd argument. Can not authorize!"),
            data: Vec::with_capacity(0),
        });
    }
    let cmd = cmd.unwrap();
    // fixme
    let res = policy::enforce::authorize(POLICY.get().unwrap(), cstate.addr.ip(), &String::from_utf8_lossy(&pkt.user), &cmd);
    let ret = if res {
        AuthorReplyPacket {
            status: AuthorStatus::PASS_ADD,
            args: Vec::with_capacity(0),
            server_msg: Vec::from(b"Approved"),
            data: Vec::with_capacity(0),
        }
    }
    else {
        AuthorReplyPacket {
            status: AuthorStatus::FAIL,
            args: Vec::with_capacity(0),
            server_msg: Vec::from(b"Denied"),
            data: Vec::with_capacity(0),
        }
    };
    return SrvPacket::AuthorReply(ret);
}

#[instrument]
fn handle_acct_packet(expected_length: usize, packet: SmallVec<PacketBuf>, _cstate: &mut Client) -> SrvPacket {
    let pkt = AcctRequestPacket::try_from(packet.deref());
    if pkt.is_err() {
        return SrvPacket::AcctGenericError(Some(Vec::from(b"Failed to parse")));
    }
    let pkt = pkt.unwrap();
    if pkt.len != expected_length {
        dbg!((pkt.len, expected_length));
        return SrvPacket::AcctGenericError(Some(Vec::from(b"Length mismatch")));
    }
    // for now we just tell them we were able to log everthing
    let ret = AcctReplyPacket {
        status: AcctStatus::SUCCESS,
        server_msg: Vec::from(b"Ok (FIXME)"),
        data: Vec::with_capacity(0),
    };
    return SrvPacket::AcctReply(ret);
}