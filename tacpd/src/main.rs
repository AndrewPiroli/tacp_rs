#![feature(let_chains)]
use std::sync::Mutex;
use policy::Policy;
use tacp::*;
use tacp::obfuscation::obfuscate_in_place;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::*;
use smallvec::*;
use fnv::FnvHashMap;
use std::sync::OnceLock;
use std::ops::Deref;

mod policy;
type PacketBuf = [u8;256];

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
enum AuthenState {
    None,
    ASCIIGETUSER,
    ASCIIGETPASS,
}

#[derive(Debug, Clone)]
enum SrvPacket {
    AuthenReply(AuthenReplyPacket),
    AuthenClientAbort(String),
    AuthenGenericError(Option<Vec<u8>>),
    AuthorReply(AuthorReplyPacket),
    AuthorGenericError(Option<Vec<u8>>),
    AcctReply(AcctReplyPacket),
    AcctGenericError(Option<Vec<u8>>),
}

/// More secure than String (still not secure!!)
#[derive(Clone, Hash, Default)]
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
struct AuthenInfo {
    pub username: Option<String>,
    pub pass: Option<SString>,
}

#[derive(Debug, Clone, Hash)]
struct Client {
    addr: std::net::SocketAddr,
    session: SessionID,
    seq_no: SeqNo,
    authen_state: AuthenState,
    authen_info: AuthenInfo,
    key: SString,
}

#[derive(Debug, Default)]
struct GlobalState(FnvHashMap<SessionID, Client>);
static GLOBAL_STATE: OnceLock<Mutex<GlobalState>> = OnceLock::new();
static POLICY: OnceLock<Policy> = OnceLock::new();

fn main() {
    GLOBAL_STATE.set(Default::default()).unwrap();
    match policy::load() {
        Ok(pol) => {
            POLICY.set(pol).unwrap();
        },
        Err(e) => {
            println!("Failed to load policy {e}");
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


async fn handle_conn(mut stream: TcpStream, addr: std::net::SocketAddr) {
    let policy = POLICY.get().unwrap();
    if !policy.clients.contains_key(&addr.ip()) {
        if !policy.allow_unconfigured {
            println!("Unconfigured client: {addr} disallowed");
            return;
        }
    }
    let client_policy = policy.clients.get(&addr.ip()).cloned().unwrap_or_default();
    let key = match (&client_policy.key, &policy.default_key) {
        (None, Some(dk)) => dk,
        (Some(ck), None) |
        (Some(ck), Some(_)) => ck,
        (None, None) => {
            println!("No client key and no default key");
            return;
        },
    };
    loop {
        let mut header = [0;12];
        if stream.read(&mut header).await.is_err() {
            break;
        }
        let parsed_header = PacketHeader::try_from(&header).unwrap();
        if parsed_header.seq_no % 2 == 0 {
            // Client MUST send odd seq_nos
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
            break;
        }
        dbg!(parsed_header);
        let mut packet: SmallVec<PacketBuf> = SmallVec::with_capacity(parsed_header.length as usize);
        packet.resize_with(parsed_header.length as usize, Default::default);
        if stream.read(&mut packet).await.is_err() {
            break;
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
                gs.0.remove(&cstate.session);
                break;
            }
            else {
                if let Some(cs) = gs.0.get_mut(&cstate.session) {
                    *cs = cstate;
                }
                else {
                    panic!();
                }
            }
        }
        tokio::task::yield_now().await;
    }
    println!("Connection terminated");
}

async fn send_reply(stream: &mut TcpStream, header: PacketHeader, obfuscated_body: &[u8]) -> tokio::io::Result<()> {
    stream.write(&header.encode()).await?;
    stream.write(&obfuscated_body).await?;
    Ok(())
}

fn handle_authen_packet(expected_length: usize, packet: SmallVec<PacketBuf>, cstate: &mut Client) -> SrvPacket {
    hexdump::hexdump(&packet);
    match cstate.authen_state {
        AuthenState::None => { // We have nothing so far, so this is a AUTHEN START packet
            let pkt = AuthenStartPacket::try_from(packet.deref());
            if pkt.is_err() {
                return SrvPacket::AuthenGenericError(Some(pkt.unwrap_err().into()));
            }
            let pkt = pkt.unwrap();
            dbg!(&pkt.action);
            dbg!(&pkt.authen_type);
            dbg!(&pkt.authen_svc);
            if pkt.len != expected_length { // probably key failure
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
                return SrvPacket::AuthenClientAbort(reason.into());
            }
            if pkt.user_msg.is_empty() {
                return SrvPacket::AuthenGenericError(Some(Vec::from(b"Server requested username but none provided"))); // We asked for a username
            }
            cstate.authen_info.username = Some(String::from_utf8_lossy(&pkt.user_msg).into());
            let ret = AuthenReplyPacket {
                status: AuthenReplyStatus::GETPASS,
                flags: 1 << REPLY_FLAG_NOECHO,
                serv_msg: Vec::from(b"Enter pass"),
                data: Vec::with_capacity(0),
            };
            cstate.authen_state = AuthenState::ASCIIGETPASS;
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
            let ret: AuthenReplyPacket;
            if check_auth(&cstate.authen_info) {
                ret = AuthenReplyPacket {
                    status: AuthenReplyStatus::PASS,
                    flags: 0,
                    serv_msg: Vec::from(b"Authentication Pass"),
                    data: Vec::with_capacity(0),
                };
            }
            else {
                ret = AuthenReplyPacket {
                    status: AuthenReplyStatus::FAIL,
                    flags: 0,
                    serv_msg: Vec::from(b"Authentication Fail"),
                    data: Vec::with_capacity(0),
                };
            }
            return SrvPacket::AuthenReply(ret);
        },
    }
}

fn parse_authen_continue(data: &[u8], expected_length: usize) -> core::result::Result<AuthenContinuePacket, <AuthenContinuePacket as TryFrom<&[u8]>>::Error> {
    let pkt = AuthenContinuePacket::try_from(data)?;
    if pkt.len() != expected_length {
        return Err("Failed length check".to_owned());
    }
    // dbg!(&pkt);
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
    let ret: AuthenReplyPacket;
    if check_auth(&info) {
        ret = AuthenReplyPacket {
            status: AuthenReplyStatus::PASS,
            flags: 0,
            serv_msg: Vec::from(b"PAP Authentication PASS"),
            data: Vec::with_capacity(0),
        };
    }
    else {
        ret = AuthenReplyPacket {
            status: AuthenReplyStatus::FAIL,
            flags: 0,
            serv_msg: Vec::from(b"PAP Authentication FAIL"),
            data: Vec::with_capacity(0),
        };
    }
    return SrvPacket::AuthenReply(ret);
}


fn handle_author_packet(expected_length: usize, packet: SmallVec<PacketBuf>, _cstate: &mut Client) -> SrvPacket {
    let pkt = AuthorRequestPacket::try_from(packet.deref());
    if pkt.is_err() {
        return SrvPacket::AuthorGenericError(Some(Vec::from(b"Failed to parse")));
    }
    let pkt = pkt.unwrap();
    if pkt.len != expected_length {
        dbg!((pkt.len, expected_length));
        return SrvPacket::AuthorGenericError(Some(Vec::from(b"Packet length mismatch")));
    }
    // for now we just approve everthing from a user we know
    let ret = if POLICY.get().unwrap().users.contains_key(&String::from_utf8_lossy(&pkt.user).to_string()) {
        AuthorReplyPacket {
            status: AuthorStatus::PASS_ADD,
            args: Vec::with_capacity(0),
            server_msg: Vec::from(b"Approved (FIXME)"),
            data: Vec::with_capacity(0),
        }
    }
    else {
        AuthorReplyPacket {
            status: AuthorStatus::FAIL,
            args: Vec::with_capacity(0),
            server_msg: Vec::from(b"Unknown user"),
            data: Vec::with_capacity(0),
        }
    };
    return SrvPacket::AuthorReply(ret);
}

fn handle_acct_packet(expected_length: usize, packet: SmallVec<PacketBuf>, _cstate: &mut Client) -> SrvPacket {
    hexdump::hexdump(packet.deref());
    let pkt = AcctRequestPacket::try_from(packet.deref());
    if pkt.is_err() {
        return SrvPacket::AcctGenericError(Some(Vec::from(b"Failed to parse")));
    }
    let pkt = pkt.unwrap();
    if pkt.len != expected_length {
        dbg!((pkt.len, expected_length));
        return SrvPacket::AcctGenericError(Some(Vec::from(b"Length mismatch")));
    }
    // for now we just approve everthing from a user we know
    let ret = if POLICY.get().unwrap().users.contains_key(&String::from_utf8_lossy(&pkt.user).to_string()) {
        AcctReplyPacket {
            status: AcctStatus::SUCCESS,
            server_msg: Vec::from(b"Approved (FIXME)"),
            data: Vec::with_capacity(0),
        }
    }
    else {
        AcctReplyPacket {
            status: AcctStatus::ERROR,
            server_msg: Vec::from(b"Unknown user"),
            data: Vec::with_capacity(0),
        }
    };
    return SrvPacket::AcctReply(ret);
}