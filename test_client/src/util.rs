use super::*;

pub use hexdump::hexdump;
use tacp::obfuscation::obfuscate_in_place;
use rand::prelude::*;
use std::sync::{LazyLock, RwLock};
use anyhow::*;
static RNG: LazyLock<RwLock<StdRng>> = LazyLock::new(||RwLock::new(StdRng::from_os_rng()));
const MAXPKTLEN: usize = 2_usize.pow(22);

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SupportedEncryption<'a> {
    RfcMd5 {
        key: &'a [u8],
        header: PacketHeader,
    },
}

pub fn getrand() -> u32 {
    RNG.write().unwrap().next_u32()
}

pub fn encrypt(unencrypted_body: &mut [u8], method: SupportedEncryption) {
    match method {
        SupportedEncryption::RfcMd5 { key, header } => {
            obfuscate_in_place(&header, key, unencrypted_body);
        },
    }
}

pub fn alloc_pkt(header: PacketHeader, pre_encrypted_body: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(12 + pre_encrypted_body.len());
    ret.extend_from_slice(header.as_bytes());
    ret.extend_from_slice(pre_encrypted_body);
    ret
}

pub fn send_packet(s: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    s.write_all(&bytes)
}

pub fn recv_packet(s: &mut TcpStream) -> anyhow::Result<(PacketHeader, Box<[u8]>)> {
    let mut header_buf = [0;12];
    s.read_exact(&mut header_buf)?;
    // lifetimes being weird, FIXME later
    let header: PacketHeader;
    if let std::result::Result::Ok(parsed_header) = PacketHeader::try_read_from_bytes(&header_buf) {
        header = parsed_header;
    }
    else {
        bail!("FIXME FIXME FIXME: header parse fail");
    }
    if header.seq_no % 2 == 1 {
        bail!("Servers must send EVEN sequence numbers. Got: {}", header.seq_no);
    }
    let len = header.length.get() as usize;
    if len > MAXPKTLEN {
        bail!("header len too big {len} > {MAXPKTLEN}");
    }
    let mut ret = Vec::with_capacity(len);
    ret.resize(len, 0);
    s.read_exact(&mut ret)?;
    Ok((header, ret.into_boxed_slice()))
}