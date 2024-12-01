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
                None => rpassword::prompt_password("Enter password for PAP: ").unwrap(),
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
                let recv_parsed = recv_parsed.unwrap();
                match recv_parsed.status {
                    // Terminate
                    AuthenReplyStatus::PASS => {
                        println!("Authentication passed");
                        if let Some(msg) = recv_parsed.get_serv_msg() {
                            let msg = String::from_utf8_lossy(msg);
                            println!("Server Message: {msg}");
                        }
                        if let Some(data) = recv_parsed.get_data() {
                            println!("Server Data: ");
                            util::hexdump(data);
                            println!();
                        }
                        expected_reply = NextPacket::None;
                    },
                    AuthenReplyStatus::FAIL => {
                        println!("Authentication failed");
                        if let Some(msg) = recv_parsed.get_serv_msg() {
                            let msg = String::from_utf8_lossy(msg);
                            println!("Server Message: {msg}");
                        }
                        if let Some(data) = recv_parsed.get_data() {
                            println!("Server Data: ");
                            util::hexdump(data);
                            println!();
                        }
                        expected_reply = NextPacket::None;
                    },
                    AuthenReplyStatus::RESTART => {
                        println!("Error: Server sent Authen Status RESTART");
                        if let Some(msg) = recv_parsed.get_serv_msg() {
                            let msg = String::from_utf8_lossy(msg);
                            println!("Server Message: {msg}");
                        }
                        if let Some(data) = recv_parsed.get_data() {
                            println!("Server Data: ");
                            util::hexdump(data);
                            println!();
                        }
                        expected_reply = NextPacket::None;
                    },
                    AuthenReplyStatus::ERROR => {
                        println!("Error: Server sent Authen Status ERROR");
                        if let Some(msg) = recv_parsed.get_serv_msg() {
                            let msg = String::from_utf8_lossy(msg);
                            println!("Server Message: {msg}");
                        }
                        if let Some(data) = recv_parsed.get_data() {
                            println!("Server Data: ");
                            util::hexdump(data);
                            println!();
                        }
                        expected_reply = NextPacket::None;
                    },
                    // Reply
                    AuthenReplyStatus::GETDATA => {
                        if let Some(msg) = recv_parsed.get_serv_msg() {
                            let msg = String::from_utf8_lossy(msg);
                            println!("Server Message: {msg}");
                        }
                        if let Some(data) = recv_parsed.get_data() {
                            println!("Server Data: ");
                            util::hexdump(data);
                            println!();
                        }
                        println!("Server requests data!");
                        let data = rpassword::prompt_password("Enter Data for reply (noecho): ").unwrap();
                        let mut reply_body = unsafe {
                            AuthenContinuePacket::boxed_to_bytes(AuthenContinuePacket::new(0, data.as_bytes(), blank.as_bytes()))
                        };
                        let reply_header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, seq_no, 0, session_id, reply_body.len() as u32);
                        util::encrypt(&mut reply_body, SupportedEncryption::RfcMd5 { key: args.key.as_bytes(), header: reply_header });
                        let pkt = util::alloc_pkt(reply_header, &reply_body);
                        if let Err(e) = util::send_packet(&mut stream,&pkt) {
                            println!("Error sending reply: {:?}", e);
                            break;
                        }
                        seq_no += 1;
                        //expected reply fall through
                    },
                    AuthenReplyStatus::GETUSER => {
                        if let Some(msg) = recv_parsed.get_serv_msg() {
                            let msg = String::from_utf8_lossy(msg);
                            println!("Server Message: {msg}");
                        }
                        if let Some(data) = recv_parsed.get_data() {
                            println!("Server Data: ");
                            util::hexdump(data);
                            println!();
                        }
                        println!("Server requests username!");
                        let mut username = String::new();
                        print!("Enter username: ");
                        std::io::stdout().flush().unwrap();
                        std::io::stdin().read_line(&mut username).unwrap();
                        let mut reply_body = unsafe {
                            AuthenContinuePacket::boxed_to_bytes(AuthenContinuePacket::new(0, username.trim_ascii_end().as_bytes(), blank.as_bytes()))
                        };
                        let reply_header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, seq_no, 0, session_id, reply_body.len() as u32);
                        util::encrypt(&mut reply_body, SupportedEncryption::RfcMd5 { key: args.key.as_bytes(), header: reply_header });
                        let pkt = util::alloc_pkt(reply_header, &reply_body);
                        if let Err(e) = util::send_packet(&mut stream,&pkt) {
                            println!("Error sending reply: {:?}", e);
                            break;
                        }
                        seq_no += 1;
                        //expected reply fall through
                    },
                    AuthenReplyStatus::GETPASS => {
                        if let Some(msg) = recv_parsed.get_serv_msg() {
                            let msg = String::from_utf8_lossy(msg);
                            println!("Server Message: {msg}");
                        }
                        if let Some(data) = recv_parsed.get_data() {
                            println!("Server Data: ");
                            util::hexdump(data);
                            println!();
                        }
                        println!("Server requests password!");
                        let pass = rpassword::prompt_password("Enter password: ").unwrap();
                        let mut reply_body = unsafe {
                            AuthenContinuePacket::boxed_to_bytes(AuthenContinuePacket::new(0, pass.as_bytes(), blank.as_bytes()))
                        };
                        let reply_header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, seq_no, 0, session_id, reply_body.len() as u32);
                        util::encrypt(&mut reply_body, SupportedEncryption::RfcMd5 { key: args.key.as_bytes(), header: reply_header });
                        let pkt = util::alloc_pkt(reply_header, &reply_body);
                        if let Err(e) = util::send_packet(&mut stream,&pkt) {
                            println!("Error sending reply: {:?}", e);
                            break;
                        }
                        seq_no += 1;
                        //expected reply fall through
                    },
                    AuthenReplyStatus::FOLLOW => {
                        println!("Authen Follow not implemented");
                        break;
                    },
                }
            },
            NextPacket::None => unreachable!(),
        }
    }
}