mod util;
use util::SupportedEncryption;

use clap::{Parser, Subcommand};
use tacp::*;
use std::{io::{Read, Write}, net::TcpStream};

const DEFAULT_PORT: u16 = 49;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum NextPacket {
    None,
    AuthenReply,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Subcommand)]
enum Action {
    AsciiLogin { username: Option<String> },
    PAPLogin { username: String, password: Option<String> },
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    server: String,
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,
    #[arg(short, long)]
    key: String,
    #[command(subcommand)]
    action: Action,
}

fn main() {
    let args = Args::parse();
    let blank = "";

    let mut addr = args.server.clone();
    addr.push_str(":");
    addr.push_str(&args.port.to_string());
    let mut stream = TcpStream::connect(addr).unwrap();

    #[allow(unused_assignments)]
    let mut expected_reply = NextPacket::None;
    let mut seq_no = 1u8;

    let session_id = util::getrand();
    let header: PacketHeader;
    let mut pkt_bytes = match args.action {
        Action::AsciiLogin { username } => {
            let body = unsafe { AuthenStartPacket::boxed_to_bytes(AuthenStartPacket::new(
                AuthenStartAction::LOGIN,
                15,
                AuthenType::ASCII,
                AuthenService::LOGIN,
                username.unwrap_or_default().as_bytes(),
                blank.as_bytes(),
            blank.as_bytes(),
                blank.as_bytes()))};
            header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, seq_no, 0, session_id, body.len() as u32);
            seq_no += 1;
            expected_reply = NextPacket::AuthenReply;
            body
        },
        Action::PAPLogin { username, password } => {
            let password = match password {
                Some(p) => p,
                None => util::prompt_user_input("Enter password for PAP: ", true),
            };
            let body = unsafe { AuthenStartPacket::boxed_to_bytes(AuthenStartPacket::new(
                AuthenStartAction::LOGIN,
                15,
                AuthenType::PAP,
                AuthenService::LOGIN,
                username.as_bytes(),
                blank.as_bytes(),
            blank.as_bytes(),
                password.as_bytes()))};
            header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, seq_no, 0, session_id, body.len() as u32);
            seq_no += 1;
            expected_reply = NextPacket::AuthenReply;
            body
        },
    };
    util::encrypt(&mut pkt_bytes, SupportedEncryption::RfcMd5 { key: args.key.as_bytes(), header: header });
    let pkt = util::alloc_pkt(header, &pkt_bytes);
    util::send_packet(&mut stream, &pkt).unwrap();
    drop(pkt);
    drop(pkt_bytes);

    while expected_reply != NextPacket::None {
        let (header, mut recv_body) = util::recv_packet(&mut stream).unwrap();
        if header.seq_no != seq_no {
            println!("seq_no mismatch: expected {seq_no} got: {}", header.seq_no);
            break;
        }
        seq_no += 1;
        util::encrypt(&mut recv_body, SupportedEncryption::RfcMd5 { key: args.key.as_bytes(), header: header });
        match expected_reply {
            NextPacket::AuthenReply => {
                let recv_parsed = AuthenReplyPacket::try_ref_from_bytes(&recv_body);
                if recv_parsed.is_err() {
                    eprintln!("err {:?}", recv_parsed.unwrap_err());
                    util::hexdump(&recv_body);
                    break;
                }
                handle_authen_reply(recv_parsed.unwrap(), &mut expected_reply, &mut stream, &mut seq_no, session_id, args.key.as_bytes());
            },
            NextPacket::None => unreachable!(),
        }
    }
}

fn handle_authen_reply(packet: &AuthenReplyPacket, next_packet: &mut NextPacket, stream: &mut TcpStream, seq_no: &mut u8, session_id: u32, key: &[u8]) {
    let blank = "";
    match packet.status {
        // Terminate
        AuthenReplyStatus::PASS => {
            println!("Authentication passed");
            if let Some(msg) = packet.get_serv_msg() {
                let msg = String::from_utf8_lossy(msg);
                println!("Server Message: {msg}");
            }
            if let Some(data) = packet.get_data() {
                println!("Server Data: ");
                util::hexdump(data);
                println!();
            }
            *next_packet = NextPacket::None;
        },
        AuthenReplyStatus::FAIL => {
            println!("Authentication failed");
            if let Some(msg) = packet.get_serv_msg() {
                let msg = String::from_utf8_lossy(msg);
                println!("Server Message: {msg}");
            }
            if let Some(data) = packet.get_data() {
                println!("Server Data: ");
                util::hexdump(data);
                println!();
            }
            *next_packet = NextPacket::None;
        },
        AuthenReplyStatus::RESTART => {
            println!("Error: Server sent Authen Status RESTART");
            if let Some(msg) = packet.get_serv_msg() {
                let msg = String::from_utf8_lossy(msg);
                println!("Server Message: {msg}");
            }
            if let Some(data) = packet.get_data() {
                println!("Server Data: ");
                util::hexdump(data);
                println!();
            }
            *next_packet = NextPacket::None;
        },
        AuthenReplyStatus::ERROR => {
            println!("Error: Server sent Authen Status ERROR");
            if let Some(msg) = packet.get_serv_msg() {
                let msg = String::from_utf8_lossy(msg);
                println!("Server Message: {msg}");
            }
            if let Some(data) = packet.get_data() {
                println!("Server Data: ");
                util::hexdump(data);
                println!();
            }
            *next_packet = NextPacket::None;
        },
        // Reply
        AuthenReplyStatus::GETDATA => {
            if let Some(msg) = packet.get_serv_msg() {
                let msg = String::from_utf8_lossy(msg);
                println!("Server Message: {msg}");
            }
            if let Some(data) = packet.get_data() {
                println!("Server Data: ");
                util::hexdump(data);
                println!();
            }
            println!("Server requests \"data!\"");
            use tacp::REPLY_FLAG_NOECHO;
            let user_msg = util::prompt_user_input("Enter data for reply: ", packet.flags & 1 << REPLY_FLAG_NOECHO == 1);
            let mut reply_body = unsafe {
                AuthenContinuePacket::boxed_to_bytes(AuthenContinuePacket::new(0, user_msg.as_bytes(), blank.as_bytes()))
            };
            let reply_header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, *seq_no, 0, session_id, reply_body.len() as u32);
            util::encrypt(&mut reply_body, SupportedEncryption::RfcMd5 { key: key, header: reply_header });
            let pkt = util::alloc_pkt(reply_header, &reply_body);
            if let Err(e) = util::send_packet(stream,&pkt) {
                println!("Error sending reply: {:?}", e);
                return;
            }
            *seq_no += 1;
            //expected reply fall through
        },
        AuthenReplyStatus::GETUSER => {
            if let Some(msg) = packet.get_serv_msg() {
                let msg = String::from_utf8_lossy(msg);
                println!("Server Message: {msg}");
            }
            if let Some(data) = packet.get_data() {
                println!("Server Data: ");
                util::hexdump(data);
                println!();
            }
            println!("Server requests username!");
            let username = util::prompt_user_input("Enter username: ", false);
            let mut reply_body = unsafe {
                AuthenContinuePacket::boxed_to_bytes(AuthenContinuePacket::new(0, username.as_bytes(), blank.as_bytes()))
            };
            let reply_header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, *seq_no, 0, session_id, reply_body.len() as u32);
            util::encrypt(&mut reply_body, SupportedEncryption::RfcMd5 { key: key, header: reply_header });
            let pkt = util::alloc_pkt(reply_header, &reply_body);
            if let Err(e) = util::send_packet(stream,&pkt) {
                println!("Error sending reply: {:?}", e);
                return;
            }
            *seq_no += 1;
            //expected reply fall through
        },
        AuthenReplyStatus::GETPASS => {
            if let Some(msg) = packet.get_serv_msg() {
                let msg = String::from_utf8_lossy(msg);
                println!("Server Message: {msg}");
            }
            if let Some(data) = packet.get_data() {
                println!("Server Data: ");
                util::hexdump(data);
                println!();
            }
            println!("Server requests password!");
            let pass = util::prompt_user_input("Enter password: ", true);
            let mut reply_body = unsafe {
                AuthenContinuePacket::boxed_to_bytes(AuthenContinuePacket::new(0, pass.as_bytes(), blank.as_bytes()))
            };
            let reply_header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, *seq_no, 0, session_id, reply_body.len() as u32);
            util::encrypt(&mut reply_body, SupportedEncryption::RfcMd5 { key: key, header: reply_header });
            let pkt = util::alloc_pkt(reply_header, &reply_body);
            if let Err(e) = util::send_packet(stream,&pkt) {
                println!("Error sending reply: {:?}", e);
                return;
            }
            *seq_no += 1;
            //expected reply fall through
        },
        AuthenReplyStatus::FOLLOW => {
            println!("Authen Follow not implemented");
            return;
        },
    }
}