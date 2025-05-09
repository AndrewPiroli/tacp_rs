//! TACACS+ Encryption/Obfuscation Algorithm
//!
//! RFC8907 Section 4.5
//!
//! The body of packets may be obfuscated. The following sections describe the obfuscation method
//! that is supported in the protocol. In "The Draft", this process was actually referred to as
//! Encryption, but the algorithm would not meet modern standards and so will not be termed as
//! encryption in this document.
//!
//! The obfuscation mechanism relies on a secret key, a shared secret value that is known to both
//! the client and the server. The secret keys **MUST** remain secret.
//!
//! Server implementations **MUST** allow a unique secret key to be associated with each client. It
//! is a site-dependent decision as to whether or not the use of separate keys is appropriate.
//!
//! The flag field **MUST** be configured with TAC_PLUS_UNENCRYPTED_FLAG
//! set to - so that the packet body is obfuscated by XORing it bytewise with a pseudo-random pad:
//!
//! ENCRYPTED {data} = data ^ pseudo_pad
//!
//! The packet body can then be de-obfuscated by XORing it bytewise with a pseudo-random pad.
//!
//! data = ENCRYPTED {data} ^ pseudo_pad
//!
//! The pad is generated by concatenating a series of MD5 hashes (each 16 bytes long) and truncating it to the length of the input data.
//! Whenever used in this document, MD5 refers to the "RSA Data Security, Inc.  MD5 Message-Digest Algorithm" as specified in \[RFC1321\].
//!
//! pseudo_pad = {MD5_1 \[,MD5_2 \[ ... ,MD5_n\]\]} truncated to len(data)
//! The first MD5 hash is generated by concatenating the session_id, the secret key, the version number, and the sequence number, and then
//! running MD5 over that stream. All of those input values are available in the packet header, except for the secret key, which is a shared
//! secret between the TACACS+ client and server.
//!
//! The version number and session_id are extracted from the header.
//!
//! Subsequent hashes are
//! generated by using the same input stream but concatenating the previous hash value at the end of the input stream.
//!
//! MD5_1 = MD5{session_id, key, version, seq_no}
//!
//! MD5_2 = MD5{session_id, key, version, seq_no, MD5_1}
//!
//! ...
//!
//! MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1}
//!
//! When a server detects that the secrets it has configured for the device do not match, it MUST return ERROR.
//!
//! After a packet body is de-obfuscated, the lengths of the component values in the packet are
//! summed. If the sum is not identical to the cleartext datalength value from the header, the
//! packet **MUST** be discarded and an ERROR signaled. Refer to "Session Completion" Section 4.4
//!
//! Commonly, such failures are seen when the keys are mismatched between the client and the
//! TACACS+ server.
use crate::PacketHeader;
use md5::{digest::core_api::CoreWrapper, Digest, Md5, Md5Core};


/// Iterator that generates the pseudo random PAD for obfuscation of TACACS+ packets
#[repr(C, align(32))]
pub struct TacacsMd5Pad<'a> {
    session_id: [u8; 4],
    ver_plus_seq: [u8; 2],
    remaining: u32,
    shared_secret: &'a[u8],
    md5_state: CoreWrapper<Md5Core>,
    md5_buf: [u8; 16],
    buf_ptr: u8,
}
impl<'a> TacacsMd5Pad<'a> {
    #[allow(clippy::zero_prefixed_literal, clippy::identity_op)]
    pub fn new(header: &PacketHeader, shared_secret: &'a [u8]) -> Self {
        let mut s = TacacsMd5Pad {
            session_id: [0; 4],
            ver_plus_seq: [0;2],
            remaining: 0,
            shared_secret,
            md5_state: Md5::new(),
            md5_buf: [0; 16],
            buf_ptr: 16,
        };
        s.remaining = header.length.get();
        s.session_id = header.session_id.to_bytes();
        s.ver_plus_seq[0] = header.version as u8;
        s.ver_plus_seq[1] = header.seq_no;
        s.md5_state.update(s.session_id.iter());
        s.md5_state.update(shared_secret);
        s.md5_state.update(s.ver_plus_seq.iter());
        s.md5_state.finalize_into_reset((&mut s.md5_buf).into());
        s
    }
}

impl Iterator for TacacsMd5Pad<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let mut p = self.buf_ptr as usize;
        if p > 0 {
            self.buf_ptr -= 1;
            self.remaining -= 1;
        }
        else {
            self.md5_state.update(self.session_id.iter());
            self.md5_state.update(self.shared_secret);
            self.md5_state.update(self.ver_plus_seq.iter());
            self.md5_state.update(self.md5_buf.iter());
            self.md5_state.finalize_into_reset((&mut self.md5_buf).into());
            self.remaining -= 1;
            self.buf_ptr = 15;
            p = 16;
        }
        Some(unsafe {*self.md5_buf.get_unchecked(16-p)})
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining as usize, Some(self.remaining as usize))
    }
}

/// Run the obfuscation algorithm in place on a packet. The process is symmetric so this handles
/// obfucation and de-obfuscation. NOTE: The caller should check header.length == packet_body.len()
pub fn obfuscate_in_place(header: &PacketHeader, shared_secret: &[u8], packet_body: &mut [u8]) {
    core::iter::zip(packet_body.iter_mut(), TacacsMd5Pad::new(header, shared_secret))
    .for_each(|(packet_byte, padbyte)|{
        *packet_byte ^= padbyte;
    });
}
