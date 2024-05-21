use crate::PacketHeader;
use md5::{Md5, Digest};

/// The packet body can then be de-obfuscated by XORing it bytewise with a pseudo-random pad.
/// 
/// data = ENCRYPTED {data} ^ pseudo_pad
/// The pad is generated by concatenating a series of MD5 hashes (each 16 bytes long) and truncating it to the length of the input data.
/// Whenever used in this document, MD5 refers to the "RSA Data Security, Inc.  MD5 Message-Digest Algorithm" as specified in [RFC1321].
/// 
/// pseudo_pad = {MD5_1 [,MD5_2 [ ... ,MD5_n]]} truncated to len(data)
/// The first MD5 hash is generated by concatenating the session_id, the secret key, the version number, and the sequence number, and then
/// running MD5 over that stream. All of those input values are available in the packet header, except for the secret key, which is a shared
/// secret between the TACACS+ client and server. The version number and session_id are extracted from the header. Subsequent hashes are
/// generated by using the same input stream but concatenating the previous hash value at the end of the input stream.
/// 
/// MD5_1 = MD5{session_id, key, version, seq_no} MD5_2 = MD5{session_id, key, version, seq_no, MD5_1} .... MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1}
/// When a server detects that the secrets it has configured for the device do not match, it MUST return ERROR.
/// 

#[allow(clippy::zero_prefixed_literal, clippy::identity_op)]
pub fn gen_psuedo_pad(header: PacketHeader, shared_secret: &[u8]) -> Vec<u8> {
    let len = header.length as usize;
    // Endianness !
    let sesssion_id = &[
        ((header.session_id & 0xff000000) >> 24) as u8,
        ((header.session_id & 0x00ff0000) >> 16) as u8,
        ((header.session_id & 0x0000ff00) >> 08) as u8,
        ((header.session_id & 0x000000ff) >> 00) as u8,
    ];
    let ver_plus_seq = &[header.version, header.seq_no];

    let mut pad: Vec<u8> = Vec::with_capacity(len + 16);

    let mut base = Md5::new(); // rust-analyzer fail
    base.update(sesssion_id);
    base.update(shared_secret);
    base.update(ver_plus_seq);
    let base = base.finalize();

    pad.extend(base.iter());

    let mut prev = base;
    while pad.len() < len {
        let mut next = Md5::new();
        next.update(sesssion_id);
        next.update(shared_secret);
        next.update(ver_plus_seq);
        next.update(prev);
        prev = next.finalize();
        pad.extend(prev);
    }

    pad.truncate(len);
    pad
}

pub fn obfuscate_in_place(header: PacketHeader, shared_secret: &[u8], packet_body: &mut [u8]) {
    for (idx, padbyte) in gen_psuedo_pad(header, shared_secret).iter().enumerate() {
        packet_body[idx] ^= *padbyte;
    }
}