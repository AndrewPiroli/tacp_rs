use clap::Parser;
use obfuscation::obfuscate_in_place;
use tacp::*;
use std::{io::{Read, Write}, net::TcpStream};
use rand::prelude::*;
use hexdump::hexdump;

const DEFAULT_PORT: u16 = 49;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    server: String,
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,
    #[arg(short, long)]
    key: String,
}

fn main() {
    let args = Args::parse();
    let blank = "";
    let pkt = unsafe { AuthenStartPacket::new(
        AuthenStartAction::LOGIN,
        15,
        AuthenType::ASCII,
        AuthenService::LOGIN,
        "test".as_bytes(),
        blank.as_bytes(),
    blank.as_bytes(),
        blank.as_bytes())};
    let mut addr = args.server.clone();
    addr.push_str(":");
    addr.push_str(&args.port.to_string());
    let mut stream = TcpStream::connect(addr).unwrap();
    let mut rng = StdRng::from_os_rng();
    let session_id = rng.random::<u32>();
    let mut pkt_bytes = unsafe { AuthenStartPacket::boxed_to_bytes(pkt) };
    let header = PacketHeader::new(Version::VersionDefault, PacketType::AUTHEN, 1, 0, session_id, pkt_bytes.len() as u32);
    obfuscate_in_place(&header, args.key.as_bytes(), &mut pkt_bytes);
    let mut buf = Vec::with_capacity(pkt_bytes.len() + 12);
    buf.extend(header.as_bytes());
    buf.extend_from_slice(&pkt_bytes);
    stream.write(&buf).unwrap();
    let mut recv_header = vec![0; 12];
    stream.read_exact(&mut recv_header).unwrap();
    let parsed_header = PacketHeader::try_ref_from_bytes(&recv_header).unwrap();
    let len = parsed_header.length.get() as usize;
    let mut recv_body = vec![0;len];
    stream.read_exact(&mut recv_body).unwrap();
    obfuscate_in_place(parsed_header, args.key.as_bytes(), &mut recv_body);
    hexdump(&recv_body);
}