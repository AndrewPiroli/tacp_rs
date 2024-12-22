#![allow(stable_features, non_camel_case_types, clippy::len_without_is_empty)]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(error_in_core, ptr_metadata)]
#![no_std]
extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::boxed::Box;
use argvalpair::ArgValPairCopyIter;

use zerocopy::*;
use zerocopy_derive::*;
pub use zerocopy::byteorder::network_endian::{U32, U16};
pub use zerocopy::{IntoBytes, TryFromBytes, FromBytes};

pub mod obfuscation;
pub mod argvalpair;

//https://datatracker.ietf.org/doc/html/rfc8907
// The following general rules apply to all TACACS+ packet types:
// * To signal that any variable-length data fields are unused, the corresponding length values are set to zero. Such fields MUST be ignored, and treated as if not present.
// * The lengths of data and message fields in a packet are specified by their corresponding length field (and are not null terminated).
// * All length values are unsigned and in network byte order.

/// TACACS+ Header Version Field

#[derive(Copy, Clone, Debug, TryFromBytes, KnownLayout, Immutable, PartialEq, Eq, Unaligned, IntoBytes)]
#[repr(u8)]
pub enum Version {
    VersionDefault = 0xc << 4,
    VersionOne = (Self::VersionDefault as u8) | 0x1,
}


/// Currently the only defined TACACS+ major version.
pub const MAJOR_VER: u8 = 0xc;
/// TACACS+ minor version 0 aka \"default\". Differences specificed in the RFC section 5.4.1 \"Version Behavior\"
pub const MINOR_VER_DEFAULT: u8 = 0x0;
/// TACACS+ minor version 1. Differences specificed in the RFC section 5.4.1 \"Version Behavior\"
pub const MINOR_VER_ONE: u8 = 0x1;

#[derive(Copy, Clone, Debug, TryFromBytes, KnownLayout, Immutable, PartialEq, Eq, Unaligned, IntoBytes)]
#[repr(u8)]
/// All TACACS+ packets are one of the following 3 types
pub enum PacketType {
    /// Authentication
    AUTHEN = 0x1,
    /// Authorization
    AUTHOR = 0x2,
    /// Accounting
    ACCT = 0x3,
}

/// This is the sequence number of the current packet.
/// The first packet in a session **MUST** have the sequence number 1, and each
/// subsequent packet will increment the sequence number by one.
/// TACACS+ clients only send packets containing odd sequence numbers,
/// and TACACS+ servers only send packets containing even sequence numbers.
///
/// The sequence number must never wrap, i.e., if the sequence number 2^8 - 1 is ever reached, that session must terminate and be restarted with a sequence number of 1.
pub type SeqNo = u8;

/// This field contains various bitmapped flags
/// ...
/// TAC_PLUS_UNENCRYPTED_FLAG := 0x01
/// ...
/// TAC_PLUS_SINGLE_CONNECT_FLAG := 0x04
/// ...
/// All other bits **MUST** be ignored when reading, and SHOULD be set to zero when writing.
pub type Flags = u8;

/// This flag indicates that the sender did not obfuscate the body of the packet. This option **MUST** NOT be used in production
/// This flag **SHOULD** be clear in all deployments. Modern network traffic tools support encrypted traffic when configured with
/// the shared secret, so obfuscated mode can and **SHOULD** be used even during test.
pub const UNENCRYPTED_FLAG: u8 = 0x1;

/// This flag is used to allow a client and server to negotiate "Single Connection Mode"
pub const SINGLE_CONNECT_FLAG: u8 = 0x4;

/// The Id for this TACACS+ session. This field does not change for
/// the duration of the TACACS+ session. This number **MUST** be generated
/// by a cryptographically strong random number generation method.
/// Failure to do so will compromise security of the session. For more details, refer to RFC4086
pub type SessionID = U32;

/// The total length of the packet body (not including the header).
/// Implementations **MUST** allow control over maximum packet sizes
/// accepted by TACACS+ Servers. The recommended maximum packet size
/// is 2^12
pub type PacketLength = U32;

/**
All TACACS+ packets begin with the following 12-byte header.

Encoding:
```
1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|major  | minor  |                |                |                |
|version| version|      type      |     seq_no     |   flags        |
+----------------+----------------+----------------+----------------+
|                                                                   |
|                            session_id                             |
+----------------+----------------+----------------+----------------+
|                                                                   |
|                              length                               |
+----------------+----------------+----------------+----------------+
```
*/
#[repr(C)]
#[derive(Copy, Clone, Debug, TryFromBytes, KnownLayout, Immutable, Unaligned, IntoBytes)]
pub struct PacketHeader {
    pub version: Version,
    pub ty: PacketType,
    pub seq_no: SeqNo,
    pub flags: Flags,
    pub session_id: SessionID,
    pub length: PacketLength,
}

impl PacketHeader {
    pub fn new(version: Version, ty: PacketType, seq_no: SeqNo, flags: Flags, session_id: u32, length: u32) -> Self {
        Self { version, ty, seq_no, flags, session_id: U32::new(session_id), length: U32::new(length) }
    }
}

/**
Authentication START Packet Body

Encoding:
```
1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|    action      |    priv_lvl    |  authen_type   | authen_service |
+----------------+----------------+----------------+----------------+
|    user_len    |    port_len    |  rem_addr_len  |    data_len    |
+----------------+----------------+----------------+----------------+
|    user ...                                                       |
+----------------+----------------+----------------+----------------+
|    port ...                                                       |
+----------------+----------------+----------------+----------------+
|    rem_addr ...                                                   |
+----------------+----------------+----------------+----------------+
|    data...                                                        |
+----------------+----------------+----------------+----------------+
```
*/
#[repr(u8)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, KnownLayout, Unaligned, TryFromBytes, Immutable)]
pub enum AuthenStartAction {
    LOGIN    = 0x1,
    CHPASS   = 0x2,
    SENDAUTH = 0x4,
}

/// Indicates what method of authentication is being requested/used.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, KnownLayout, Unaligned, TryFromBytes, Immutable)]
pub enum AuthenType {
    ASCII = 0x1,
    PAP = 0x2,
    CHAP = 0x3,
    MSCHAP_V1 = 0x5,
    MSCHAP_V2 = 0x6,
}

/// Authen Privilege Level Packet Field
pub type PrivLevel = u8;

/// Indicates the Service that authentication is being requested for.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, KnownLayout, Unaligned, TryFromBytes, Immutable)]
pub enum AuthenService {
    NONE = 0x0,
    LOGIN = 0x1,
    ENABLE = 0x2,
    PPP = 0x3,
    PT = 0x5,
    RCMD = 0x6,
    X25 = 0x7,
    NASI = 0x8,
    FWPROXY = 0x9,
}

/**
The Authentication START Packet Body

Encoding:
```
1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|    action      |    priv_lvl    |  authen_type   | authen_service |
+----------------+----------------+----------------+----------------+
|    user_len    |    port_len    |  rem_addr_len  |    data_len    |
+----------------+----------------+----------------+----------------+
|    user ...
+----------------+----------------+----------------+----------------+
|    port ...
+----------------+----------------+----------------+----------------+
|    rem_addr ...
+----------------+----------------+----------------+----------------+
|    data...
+----------------+----------------+----------------+----------------+
```
*/
#[derive(Debug, KnownLayout, Immutable, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct AuthenStartPacket {
    pub action: AuthenStartAction,
    pub priv_level: PrivLevel,
    pub authen_type: AuthenType,
    pub authen_svc: AuthenService,
    pub user_len: u8,
    pub port_len: u8,
    pub rem_addr_len: u8,
    pub data_len: u8,
    pub varidata: [u8]
}
impl AuthenStartPacket {
    pub fn get_user(&self) -> Option<&[u8]> {
        let start = 0usize;
        let end = self.user_len as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_port(&self) -> Option<&[u8]> {
        let start = self.user_len as usize;
        let end = start + self.port_len as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_rem_addr(&self) -> Option<&[u8]> {
        let start = self.user_len as usize + self.port_len as usize;
        let end = start + self.rem_addr_len as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.user_len as usize + self.port_len as usize + self.rem_addr_len as usize;
        let end = start + self.data_len as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn len(&self) -> usize {
        8 // Fixed portion of packet
        + self.varidata.len()
    }
}
#[cfg(feature = "dst-construct")]
impl AuthenStartPacket {
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, self.len()) }
    }
    /// # Safety
    /// 
    /// Caller must maintain endianness, length, enum variants. **Do not use this to encrypt packets**, use `boxed_to_bytes` instead.
    /// Also marked unsafe due to untested slice-DST wrangling internals. More testing is required.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, self.len()) }
    }
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn boxed_to_bytes(s: Box<Self>) -> Box<[u8]> {
        let real_len = s.len();
        let thinptr = Box::into_raw(s) as *mut ();
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(thinptr as *mut u8, real_len)) }
    }
    /// # Safety
    /// 
    /// The memory at (mem.0)..(mem.0 + mem.1) must be valid for writing and must not overlap with the memory pointed to be `args`, `server_msg` or `data`
    /// 
    /// Note that mem.0 is a **thin** pointer.
    /// If this functions returns Ok, mem.0 may be combined with the correct metadata to create a slice for ease of use.
    pub unsafe fn initialize(mem: (*mut u8, usize), action: AuthenStartAction, priv_level: PrivLevel, authen_type: AuthenType, authen_service: AuthenService, user: &[u8], port: &[u8], rem_addr: &[u8], data: &[u8]) -> Result<(), TacpErr> {unsafe {
        use core::ptr::copy_nonoverlapping;
        let len = mem.1;
        let mem = mem.0;
        let required_mem = 8 + user.len() + port.len() + rem_addr.len() + data.len();
        if len < required_mem {
            return Err(TacpErr::ParseError("FIXME".to_owned()));
        }
        *mem.add(0) = action as u8;
        *mem.add(1) = priv_level as u8;
        *mem.add(2) = authen_type as u8;
        *mem.add(3) = authen_service as u8;
        *mem.add(4) = user.len() as u8;
        *mem.add(5) = port.len() as u8;
        *mem.add(6) = rem_addr.len() as u8;
        *mem.add(7) = data.len() as u8;
        let mut varidata_ptr = 8_usize;
        copy_nonoverlapping(user.as_ptr(), mem.add(varidata_ptr), user.len() as u8 as usize);
        varidata_ptr += user.len() as u8 as usize;
        copy_nonoverlapping(port.as_ptr(), mem.add(varidata_ptr), port.len() as u8 as usize);
        varidata_ptr += port.len() as u8 as usize;
        copy_nonoverlapping(rem_addr.as_ptr(), mem.add(varidata_ptr), rem_addr.len() as u8 as usize);
        varidata_ptr += rem_addr.len() as u8 as usize;
        copy_nonoverlapping(data.as_ptr(), mem.add(varidata_ptr), data.len() as u8 as usize);
        varidata_ptr += data.len() as u8 as usize;
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }}
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn new(action: AuthenStartAction, priv_level: PrivLevel, authen_type: AuthenType, authen_service: AuthenService, user: &[u8], port: &[u8], rem_addr: &[u8], data: &[u8]) -> Box<Self> {unsafe {
        use core::alloc::*;
        let len = 8 + user.len() + port.len() + rem_addr.len() + data.len();
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = alloc::alloc::alloc(layout);
        if ptr.is_null() {
            panic!();
        }
        Self::initialize((ptr, len), action, priv_level, authen_type, authen_service, user, port, rem_addr, data).unwrap();
        let fatref: &mut [u8] = core::mem::transmute(core::ptr::from_raw_parts_mut(ptr, len) as *mut [u8]);
        let fatptr: *mut Self = Self::try_mut_from_bytes(fatref).unwrap() as *mut Self;
        let ret = Box::from_raw(fatptr);
        ret
    }}
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, KnownLayout, Unaligned, TryFromBytes, Immutable)]
pub enum AuthenReplyStatus {
    PASS = 0x01,
    FAIL = 0x02,
    GETDATA = 0x03,
    GETUSER = 0x04,
    GETPASS = 0x05,
    RESTART = 0x06,
    ERROR = 0x07,
    FOLLOW = 0x21,
}

/// Authentication REPLY Flag TAC_PLUS_REPLY_FLAG_NOECHO
///
/// If the information being requested by the server from the client is sensitive, then the server should set
/// the this flag. When the client queries the user for the information, the response MUST NOT be reflected in
/// the user interface as it is entered.
pub const REPLY_FLAG_NOECHO: u8 = 1;

/**
The Authentication REPLY Packet Body

Encoding:
```
 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|     status     |      flags     |        server_msg_len           |
+----------------+----------------+----------------+----------------+
|           data_len              |        server_msg ...
+----------------+----------------+----------------+----------------+
|           data ...
+----------------+----------------+
```
*/
#[derive(Debug, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(C)]
pub struct AuthenReplyPacket {
    pub status: AuthenReplyStatus,
    pub flags: u8,
    pub serv_msg_len: U16,
    pub data_len: U16,
    pub varidata: [u8],
}
impl AuthenReplyPacket {
    pub fn get_serv_msg(&self) -> Option<&[u8]> {
        let start = 0;
        let end = self.serv_msg_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.serv_msg_len.get() as usize;
        let end = start + self.data_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn len(&self) -> usize {
        6 + self.data_len.get() as usize + self.serv_msg_len.get() as usize
    }
}
#[cfg(feature = "dst-construct")]
impl AuthenReplyPacket {
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, self.len()) }
    }
    /// # Safety
    /// 
    /// Caller must maintain endianness, length, enum variants. **Do not use this to encrypt packets**, use `boxed_to_bytes` instead.
    /// Also marked unsafe due to untested slice-DST wrangling internals. More testing is required.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, self.len()) }
    }
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn boxed_to_bytes(s: Box<Self>) -> Box<[u8]> {
        let real_len = s.len();
        let thinptr = Box::into_raw(s) as *mut ();
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(thinptr as *mut u8, real_len)) }
    }
    /// # Safety
    /// 
    /// The memory at (mem.0)..(mem.0 + mem.1) must be valid for writing and must not overlap with the memory pointed to by `serv_msg` or `data`
    /// 
    /// Note that mem.0 is a **thin** pointer.
    /// If this functions returns Ok, mem.0 may be combined with the correct metadata to create a slice for ease of use.
    pub unsafe fn initialize(mem: (*mut u8, usize), status: AuthenReplyStatus, flags: u8, serv_msg: &[u8], data: &[u8]) -> Result<(), TacpErr> {unsafe {
        use core::ptr::copy_nonoverlapping;
        let len = mem.1;
        let mem = mem.0;
        if len < 6+serv_msg.len()+data.len() {
            return Err(TacpErr::ParseError("FIXME error message".to_owned()));
        }
        let serv_msg_len = U16::new(serv_msg.len() as u16);
        let serv_msg_bytes = serv_msg_len.as_bytes();
        let data_len = U16::new(data.len() as u16);
        let data_len_bytes = data_len.as_bytes();
        *mem.add(0) = status as u8;
        *mem.add(1) = flags;
        *mem.add(2) = serv_msg_bytes[0];
        *mem.add(3) = serv_msg_bytes[1];
        *mem.add(4) = data_len_bytes[0];
        *mem.add(5) = data_len_bytes[1];
        let start = 6;
        let end = start + serv_msg.len() as u16 as usize;
        copy_nonoverlapping(serv_msg.as_ptr(), mem.add(start), end-start);
        let start = end;
        let end = start + data.len() as u16 as usize;
        copy_nonoverlapping(data.as_ptr(), mem.add(start), end-start);
        debug_assert!(end == len);
        Ok(())
    }}
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn new(status: AuthenReplyStatus, flags: u8, serv_msg: &[u8], data: &[u8]) -> Box<Self> { unsafe {
        use core::alloc::*;
        let len = 6 + serv_msg.len() + data.len();
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = alloc::alloc::alloc(layout);
        if ptr.is_null() {
            panic!();
        }
        Self::initialize((ptr, len), status, flags, serv_msg, data).unwrap();
        let fatref: &mut [u8] = core::mem::transmute(core::ptr::from_raw_parts_mut(ptr, len) as *mut [u8]);
        let fatptr: *mut Self = Self::try_mut_from_bytes(fatref).unwrap() as *mut Self;
        let ret = Box::from_raw(fatptr);
        ret
    }}
}

/**
Authentication CONTINUE Packet Body

This packet is sent from the client to the server following the receipt of a REPLY packet.

Encoding:
```

1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|          user_msg len           |            data_len             |
+----------------+----------------+----------------+----------------+
|     flags      |  user_msg ...
+----------------+----------------+----------------+----------------+
|    data ...
+----------------+
```
*/
#[derive(Debug, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(C)]
pub struct AuthenContinuePacket {
    pub user_msg_len: U16,
    pub data_len: U16,
    pub flags: u8,
    pub varidata: [u8],
}

impl AuthenContinuePacket {
    pub fn get_user_msg(&self) -> Option<&[u8]> {
        let start = 0;
        let end = self.user_msg_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.user_msg_len.get() as usize;
        let end = start + self.data_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn len(&self) -> usize {
        5 + self.user_msg_len.get() as usize + self.data_len.get() as usize
    }
}
#[cfg(feature = "dst-construct")]
impl AuthenContinuePacket {
    #[doc=include_str!("untested_safety_msg.txt")]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, self.len())}
    }
    /// # Safety
    /// 
    /// Caller must maintain endianness, length, enum variants. **Do not use this to encrypt packets**, use `boxed_to_bytes` instead.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, self.len()) }
    }
    #[doc=include_str!("untested_safety_msg.txt")]
    pub fn boxed_to_bytes(s: Box<Self>) -> Box<[u8]> {
        let real_len = s.len();
        let thinptr = Box::into_raw(s) as *mut ();
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(thinptr as *mut u8, real_len)) }
    }
    /// # Safety
    /// 
    /// The memory at (mem.0)..(mem.0 + mem.1) must be valid for writing and must not overlap with the memory pointed to by `user_msg` or `data`
    /// 
    /// Note that mem.0 is a **thin** pointer.
    /// If this functions returns Ok, mem.0 may be combined with the correct metadata to create a slice for ease of use.
    pub unsafe fn initialize(mem: (*mut u8, usize), flags: u8, user_msg: &[u8], data: &[u8]) -> Result<(), TacpErr> {unsafe {
        use core::ptr::copy_nonoverlapping;
        let len = mem.1;
        let mem = mem.0;
        if len < 5 + user_msg.len() + data.len() {
            return Err(TacpErr::ParseError("FIXME".to_owned()));
        }
        let user_msg_len_be = U16::new(user_msg.len() as u16);
        let data_len_be = U16::new(data.len() as u16);
        let user_msg_len_bytes = user_msg_len_be.as_bytes();
        let data_len_bytes = data_len_be.as_bytes();
        *mem.add(0) = user_msg_len_bytes[0];
        *mem.add(1) = user_msg_len_bytes[1];
        *mem.add(2) = data_len_bytes[0];
        *mem.add(3) = data_len_bytes[1];
        *mem.add(4) = flags;
        let start = 5;
        let end = 5+user_msg.len() as u16 as usize;
        copy_nonoverlapping(user_msg.as_ptr(), mem.add(start), end-start);
        let start = end;
        let end = start + data.len() as u16 as usize;
        copy_nonoverlapping(data.as_ptr(), mem.add(start), end-start);
        debug_assert!(end == len);
        Ok(())
    }}
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn new(flags: u8, user_msg: &[u8], data: &[u8]) -> Box<Self> {unsafe {
        use core::alloc::*;
        let len = 5 + user_msg.len() + data.len();
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = alloc::alloc::alloc(layout);
        if ptr.is_null() {
            panic!();
        }
        Self::initialize((ptr, len), flags, user_msg, data).unwrap();
        let fatref: &mut [u8] = core::mem::transmute(core::ptr::from_raw_parts_mut(ptr, len) as *mut [u8]);
        let fatptr: *mut Self = Self::try_mut_from_bytes(fatref).unwrap() as *mut Self;
        let ret = Box::from_raw(fatptr);
        ret
    }}
}


/// Indicates the authentication method used to acquire use information
///
/// As this information is not always subject to verification, it MUST NOT be used in policy evaluation.
/// LINE refers to a fixed password associated with the terminal line used to gain access.
/// LOCAL is a client local user database. ENABLE is a command that authenticates in order to grant new privileges.
/// TACACSPLUS is, of course, TACACS+. GUEST is an unqualified guest authentication.
/// RADIUS is the RADIUS authentication protocol. RCMD refers to authentication provided via the R-command protocols from Berkeley Unix.
/// KRB5 \[RFC4120\] and KRB4 \[KRB4\] are Kerberos versions 5 and 4.
/// As mentioned above, this field is used by the client to indicate how it performed the authentication.
/// One of the options (TAC_PLUS_AUTHEN_METH_TACACSPLUS := 0x06) is TACACS+ itself, and so the detail of how the client performed this option is given in "Authentication" (Section 5).
/// For all other options, such as KRB and RADIUS, the TACACS+ protocol did not play any part in the authentication phase;
/// as those interactions were not conducted using the TACACS+ protocol, they will not be documented here.
/// For implementers of clients who need details of the other protocols, please refer to the respective Kerberos \[RFC4120\] and RADIUS \[RFC3579\] RFCs.
#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, Immutable)]
pub enum AuthorMethod {
    NOT_SET = 0x00,
    NONE = 0x01,
    KRB5 = 0x02,
    LINE = 0x03,
    ENABLE = 0x04,
    LOCAL = 0x05,
    TACACSPLUS = 0x06,
    GUEST = 0x08,
    RADIUS = 0x10,
    KRB4 = 0x11,
    RCMD = 0x20,
}

/**
The Authroization REQUEST Packet Body

Encoding:
```
  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|  authen_method |    priv_lvl    |  authen_type   | authen_service |
+----------------+----------------+----------------+----------------+
|    user_len    |    port_len    |  rem_addr_len  |    arg_cnt     |
+----------------+----------------+----------------+----------------+
|   arg_1_len    |   arg_2_len    |      ...       |   arg_N_len    |
+----------------+----------------+----------------+----------------+
|   user ...
+----------------+----------------+----------------+----------------+
|   port ...
+----------------+----------------+----------------+----------------+
|   rem_addr ...
+----------------+----------------+----------------+----------------+
|   arg_1 ...
+----------------+----------------+----------------+----------------+
|   arg_2 ...
+----------------+----------------+----------------+----------------+
|   ...
+----------------+----------------+----------------+----------------+
|   arg_N ...
+----------------+----------------+----------------+----------------+
```
*/
#[derive(Debug, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(C)]
pub struct AuthorRequestPacket {
    pub method: AuthorMethod,
    pub priv_level: PrivLevel,
    pub authen_type: AuthenType,
    pub authen_svc: AuthenService,
    pub user_len: u8,
    pub port_len: u8,
    pub rem_addr_len: u8,
    pub arg_cnt: u8,
    pub varidata: [u8]
}

impl AuthorRequestPacket {
    pub fn get_user(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize;
        let end = start + self.user_len as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_port(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.user_len as usize;
        let end = start + self.port_len as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_rem_addr(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.user_len as usize + self.port_len as usize;
        let end = start + self.rem_addr_len as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_raw_argvalpair(&self, idx: u8) -> Option<&[u8]> {
        if idx > self.arg_cnt {
            return None;
        }
        let arg_len = self.varidata[idx as usize] as usize;
        let mut skip = 
            self.arg_cnt as usize
            + self.user_len as usize
            + self.port_len as usize
            + self.rem_addr_len as usize;
        for n in 0..idx {
            skip += self.varidata[n as usize] as usize;
        }
        Some(&self.varidata[skip..(skip+arg_len)])
    }
    pub fn iter_arg_copy(&self) -> ArgValPairCopyIter {
        let lengths_range = 0..(self.arg_cnt as usize);
        let data_range_base = 
            self.arg_cnt as usize + self.user_len as usize + self.port_len as usize + self.rem_addr_len as usize;
        ArgValPairCopyIter::new(&self.arg_cnt, &self.varidata[lengths_range], &self.varidata[data_range_base..])
    }
    pub fn len(&self) -> usize {
        8 + self.varidata.len()
    }
}
#[cfg(feature = "dst-construct")]
impl AuthorRequestPacket {
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, self.len()) }
    }
    /// # Safety
    /// 
    /// Caller must maintain endianness, length, enum variants. **Do not use this to encrypt packets**, use `boxed_to_bytes` instead.
    /// Also marked unsafe due to untested slice-DST wrangling internals. More testing is required.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, self.len()) }
    }
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn boxed_to_bytes(s: Box<Self>) -> Box<[u8]> {
        let real_len = s.len();
        let thinptr = Box::into_raw(s) as *mut ();
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(thinptr as *mut u8, real_len)) }
    }
    /// # Safety
    /// 
    /// The memory at (mem.0)..(mem.0 + mem.1) must be valid for writing and must not overlap with the memory pointed to by `user`, `port`, `rem_addr` or `args`
    /// 
    /// Note that mem.0 is a **thin** pointer.
    /// If this functions returns Ok, mem.0 may be combined with the correct metadata to create a slice for ease of use.
    pub unsafe fn initialize(mem: (*mut u8, usize), method: AuthorMethod, priv_level: PrivLevel, authen_type: AuthenType, authen_svc: AuthenService, user: &[u8], port: &[u8], rem_addr: &[u8], args:&[&[u8]]) -> Result<(), TacpErr> { unsafe {
        use core::ptr::copy_nonoverlapping;
        let len = mem.1;
        let mem = mem.0;
        let required_mem = 8 + user.len() + port.len() + rem_addr.len() + args.iter().fold(0, |acc, arg|acc+arg.len());
        if len < required_mem {
            return Err(TacpErr::ParseError("Fixme".to_owned()));
        }
        *mem.add(0) = method as u8;
        *mem.add(1) = priv_level as u8;
        *mem.add(2) = authen_type as u8;
        *mem.add(3) = authen_svc as u8;
        *mem.add(4) = user.len() as u8;
        *mem.add(5) = port.len() as u8;
        *mem.add(6) = rem_addr.len() as u8;
        *mem.add(7) = args.len() as u8;
        let mut varidata_ptr = 8usize;
        for arg_n in 0..(args.len() as u8 as usize) {
            *mem.add(varidata_ptr) = args[arg_n].len() as u8;
            varidata_ptr += 1;
        }
        copy_nonoverlapping(user.as_ptr(), mem.add(varidata_ptr), user.len() as u8 as usize);
        varidata_ptr += user.len() as u8 as usize;
        copy_nonoverlapping(port.as_ptr(), mem.add(varidata_ptr), port.len() as u8 as usize);
        varidata_ptr += port.len() as u8 as usize;
        copy_nonoverlapping(rem_addr.as_ptr(), mem.add(varidata_ptr), rem_addr.len() as u8 as usize);
        varidata_ptr += rem_addr.len() as u8 as usize;
        for arg in args.iter() {
            let arg_len = arg.len() as u8 as usize;
            copy_nonoverlapping(arg.as_ptr(), mem.add(varidata_ptr), arg_len);
            varidata_ptr += arg_len;
        }
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }}
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn new(method: AuthorMethod, priv_level: PrivLevel, authen_type: AuthenType, authen_svc: AuthenService, user: &[u8], port: &[u8], rem_addr: &[u8], args:&[&[u8]]) -> Box<Self> {unsafe {
        use core::alloc::*;
        let len = 8 + user.len() + port.len() + rem_addr.len() + args.iter().fold(0, |acc, arg|acc+arg.len());
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = alloc::alloc::alloc(layout);
        if ptr.is_null() {
            panic!();
        }
        Self::initialize((ptr, len), method, priv_level, authen_type, authen_svc, user, port, rem_addr, args).unwrap();
        let fatref: &mut [u8] = core::mem::transmute(core::ptr::from_raw_parts_mut(ptr, len) as *mut [u8]);
        let fatptr: *mut Self = Self::try_mut_from_bytes(fatref).unwrap() as *mut Self;
        let ret = Box::from_raw(fatptr);
        ret
    }}
}

/**
The Authorization REPLY Packet Body

Encoding:
```
 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|    status      |     arg_cnt    |         server_msg len          |
+----------------+----------------+----------------+----------------+
+            data_len             |    arg_1_len   |    arg_2_len   |
+----------------+----------------+----------------+----------------+
|      ...       |   arg_N_len    |         server_msg ...
+----------------+----------------+----------------+----------------+
|   data ...
+----------------+----------------+----------------+----------------+
|   arg_1 ...
+----------------+----------------+----------------+----------------+
|   arg_2 ...
+----------------+----------------+----------------+----------------+
|   ...
+----------------+----------------+----------------+----------------+
|   arg_N ...
+----------------+----------------+----------------+----------------+
```
*/
#[derive(Debug, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(C)]
pub struct AuthorReplyPacket {
    pub status: AuthorStatus,
    pub arg_cnt: u8,
    pub server_msg_len: U16,
    pub data_len: U16,
    pub varidata: [u8],
}

impl AuthorReplyPacket {
    pub fn get_serv_msg(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize;
        let end = start+self.server_msg_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.server_msg_len.get() as usize;
        let end = start+self.data_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_raw_argvalpair(&self, idx: u8) -> Option<&[u8]> {
        if idx > self.arg_cnt {
            return None;
        }
        let arg_len = self.varidata[idx as usize] as usize;
        let mut skip = 
            self.arg_cnt as usize
            + self.server_msg_len.get() as usize
            + self.data_len.get() as usize;
        for n in 0..idx {
            skip += self.varidata[n as usize] as usize;
        }
        Some(&self.varidata[skip..(skip+arg_len)])
    }
    pub fn iter_arg_copy(&self) -> ArgValPairCopyIter {
        let lengths_range = 0..(self.arg_cnt as usize);
        let data_range_base = 
            self.arg_cnt as usize + self.server_msg_len.get() as usize + self.data_len.get() as usize;
        ArgValPairCopyIter::new(&self.arg_cnt, &self.varidata[lengths_range], &self.varidata[data_range_base..])
    }
    pub fn len(&self) -> usize {
        6 + self.varidata.len()
    }
}
#[cfg(feature = "dst-construct")]
impl AuthorReplyPacket {
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, self.len()) }
    }
    /// # Safety
    /// 
    /// Caller must maintain endianness, length, enum variants. **Do not use this to encrypt packets**, use `boxed_to_bytes` instead.
    /// Also marked unsafe due to untested slice-DST wrangling internals. More testing is required.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, self.len()) }
    }
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn boxed_to_bytes(s: Box<Self>) -> Box<[u8]> {
        let real_len = s.len();
        let thinptr = Box::into_raw(s) as *mut ();
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(thinptr as *mut u8, real_len)) }
    }
    /// # Safety
    /// 
    /// The memory at (mem.0)..(mem.0 + mem.1) must be valid for writing and must not overlap with the memory pointed to be `args`, `server_msg` or `data`
    /// 
    /// Note that mem.0 is a **thin** pointer.
    /// If this functions returns Ok, mem.0 may be combined with the correct metadata to create a slice for ease of use.
    pub unsafe fn initialize(mem: (*mut u8, usize), status: AuthorStatus, args: &[&[u8]], server_msg: &[u8], data: &[u8]) -> Result<(), TacpErr> { unsafe {
        use core::ptr::copy_nonoverlapping;
        let len = mem.1;
        let mem = mem.0;
        let required_mem = 6 + server_msg.len() + data.len() + args.iter().fold(0, |acc, arg|acc+arg.len());
        if len < required_mem {
            return Err(TacpErr::ParseError("FIXME".to_owned()));
        }
        *mem.add(0) = status as u8;
        *mem.add(1) = args.len() as u8;
        let server_msg_len_be = U16::new(server_msg.len() as u16);
        let data_len_be = U16::new(data.len() as u16);
        let server_msg_len_bytes = server_msg_len_be.as_bytes();
        let data_len_bytes = data_len_be.as_bytes();
        *mem.add(2) = server_msg_len_bytes[0];
        *mem.add(3) = server_msg_len_bytes[1];
        *mem.add(4) = data_len_bytes[0];
        *mem.add(5) = data_len_bytes[1];
        let server_msg_start = 6 + args.len();
        let server_msg_end = server_msg_start + server_msg.len();
        copy_nonoverlapping(server_msg.as_ptr(), mem.add(server_msg_start), server_msg_end-server_msg_start);
        let data_msg_start = server_msg_end;
        let data_msg_end = data_msg_start + data.len();
        copy_nonoverlapping(data.as_ptr(), mem.add(data_msg_start), data_msg_end-data_msg_start);
        let mut endptr = data_msg_end;
        for (idx, arg) in args.iter().enumerate() {
            let arg = *arg;
            let len = arg.len();
            *mem.add(6 + idx) = len as u8;
            copy_nonoverlapping(arg.as_ptr(), mem.add(endptr), len);
            endptr += len
        }
        debug_assert!(endptr == required_mem);
        Ok(())
    }}
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn new(status: AuthorStatus, args: &[&[u8]], server_msg: &[u8], data: &[u8]) -> Box<Self> { unsafe {
        use core::alloc::*;
        let len = 6 + server_msg.len() + data.len() + args.iter().fold(0, |acc, arg|acc+arg.len());
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = alloc::alloc::alloc(layout);
        if ptr.is_null() {
            panic!();
        }
        Self::initialize((ptr, len), status, args, server_msg, data).unwrap();
        let fatref: &mut [u8] = core::mem::transmute(core::ptr::from_raw_parts_mut(ptr, len) as *mut [u8]);
        let fatptr: *mut Self = Self::try_mut_from_bytes(fatref).unwrap() as *mut Self;
        let ret = Box::from_raw(fatptr);
        ret
    }}
}

/// Status of the Authorization Request
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(u8)]
pub enum AuthorStatus {
    /// Authorized as-is
    PASS_ADD = 0x1,
    /// Authroized, but the client must use the provided argument-value pairs instead of the
    /// provided ones.
    PASS_REPL = 0x2,
    /// Authorization Denied
    FAIL = 0x10,
    /// Server error
    ERROR = 0x11,
    /// Follow to other TACACS+ server (deprecated)
    FOLLOW = 0x21,
}

/**
The Account REQUEST Packet Body

Encoding:
```
 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|      flags     |  authen_method |    priv_lvl    |  authen_type   |
+----------------+----------------+----------------+----------------+
| authen_service |    user_len    |    port_len    |  rem_addr_len  |
+----------------+----------------+----------------+----------------+
|    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
+----------------+----------------+----------------+----------------+
|   arg_N_len    |    user ...
+----------------+----------------+----------------+----------------+
|   port ...
+----------------+----------------+----------------+----------------+
|   rem_addr ...
+----------------+----------------+----------------+----------------+
|   arg_1 ...
+----------------+----------------+----------------+----------------+
|   arg_2 ...
+----------------+----------------+----------------+----------------+
|   ...
+----------------+----------------+----------------+----------------+
|   arg_N ...
+----------------+----------------+----------------+----------------+
```
 
NOTE: This is basically the same as the Authorization Request Packet body,
    We take advantage of this by parsing it as such, then adding the flags
*/
#[derive(Debug, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(C)]
pub struct AcctRequestPacket {
    pub flags: AcctFlags,
    pub inner: AuthorRequestPacket,
}
impl AcctRequestPacket {
    pub fn get_user(&self) -> Option<&[u8]> {
        self.inner.get_user()
    }
    pub fn get_port(&self) -> Option<&[u8]> {
        self.inner.get_port()
    }
    pub fn get_rem_addr(&self) -> Option<&[u8]> {
        self.inner.get_rem_addr()
    }
    pub fn get_raw_argvalpair(&self, idx: u8) -> Option<&[u8]> {
        self.inner.get_raw_argvalpair(idx)
    }
    pub fn iter_arg_copy(&self) -> ArgValPairCopyIter {
        self.inner.iter_arg_copy()
    }
    pub fn len(&self) -> usize {
        1 + self.inner.len()
    }
}
#[cfg(feature = "dst-construct")]
impl AcctRequestPacket {
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, self.len()) }
    }
    /// # Safety
    /// 
    /// Caller must maintain endianness, length, enum variants. **Do not use this to encrypt packets**, use `boxed_to_bytes` instead.
    /// Also marked unsafe due to untested slice-DST wrangling internals. More testing is required.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, self.len()) }
    }
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn boxed_to_bytes(s: Box<Self>) -> Box<[u8]> {
        let real_len = s.len();
        let thinptr = Box::into_raw(s) as *mut ();
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(thinptr as *mut u8, real_len)) }
    }
    /// # Safety
    /// 
    /// The memory at (mem.0)..(mem.0 + mem.1) must be valid for writing and must not overlap with the memory pointed to by `user`, `port`, `rem_addr` or `args`
    /// 
    /// Note that mem.0 is a **thin** pointer.
    /// If this functions returns Ok, mem.0 may be combined with the correct metadata to create a slice for ease of use.
    pub unsafe fn initialize(mem: (*mut u8, usize), flags: AcctFlags, method: AuthorMethod, priv_level: PrivLevel, authen_type: AuthenType, authen_svc: AuthenService, user: &[u8], port: &[u8], rem_addr: &[u8], args:&[&[u8]]) -> Result<(), TacpErr> { unsafe {
        let len = mem.1;
        let mem = mem.0;
        let required_mem = 9 + user.len() + port.len() + rem_addr.len() + args.iter().fold(0, |acc, arg|acc+arg.len());
        if len < required_mem {
            return Err(TacpErr::ParseError("FIXME".to_owned()));
        }
        *mem = flags as u8;
        AuthorRequestPacket::initialize((mem.add(1), len-1), method, priv_level, authen_type, authen_svc, user, port, rem_addr, args)
    }}
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn new(flags: AcctFlags, method: AuthorMethod, priv_level: PrivLevel, authen_type: AuthenType, authen_svc: AuthenService, user: &[u8], port: &[u8], rem_addr: &[u8], args:&[&[u8]]) -> Box<Self> {unsafe {
        use core::alloc::*;
        let len = 8 + user.len() + port.len() + rem_addr.len() + args.iter().fold(0, |acc, arg|acc+arg.len());
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = alloc::alloc::alloc(layout);
        if ptr.is_null() {
            panic!();
        }
        Self::initialize((ptr, len), flags, method, priv_level, authen_type, authen_svc, user, port, rem_addr, args).unwrap();
        let fatref: &mut [u8] = core::mem::transmute(core::ptr::from_raw_parts_mut(ptr, len) as *mut [u8]);
        let fatptr: *mut Self = Self::try_mut_from_bytes(fatref).unwrap() as *mut Self;
        let ret = Box::from_raw(fatptr);
        ret
    }}
}

/**
Accounting Flags

Parsed from the first byte of the Accounting REQUEST packet according to the following tables
(RFC8907 Section 7.2)


| Watchdog | Stop | Start | Flags & 0xE | Meaning                 |
|----------|------|-------|-------------|-------------------------|
| 0        | 0    | 0     | 0           | INVALID                 |
| 0        | 0    | 1     | 2           | Start Accounting Record |
| 0        | 1    | 0     | 4           | Stop Accounting Record  |
| 0        | 1    | 1     | 6           | INVALID                 |
| 1        | 0    | 0     | 8           | Watchdog, no update     |
| 1        | 0    | 1     | A           | Watchdog, with update   |
| 1        | 1    | 0     | C           | INVALID                 |
| 1        | 1    | 1     | E           | INVALID                 |

where:

FLAG_START = 0x2

FLAG_STOP = 0x4

FLAG_WATCHDOG = 0x8
*/
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(u8)]
pub enum AcctFlags {
    RecordStart = 0x2,
    RecordStop = 0x4,
    WatchdogNoUpdate = 0x8,
    WatchdogUpdate = 0xA,
}


/**
The Accounting REPLY Packet Body

Encoding:
```
 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
+----------------+----------------+----------------+----------------+
|         server_msg len          |            data_len             |
+----------------+----------------+----------------+----------------+
|     status     |         server_msg ...
+----------------+----------------+----------------+----------------+
|     data ...
+----------------+
```
*/
#[derive(Debug, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(C)]
pub struct AcctReplyPacket {
    pub server_msg_len: U16,
    pub data_len: U16,
    pub status: AcctStatus,
    pub varidata: [u8]
}
impl AcctReplyPacket {
    pub fn get_serv_msg(&self) -> Option<&[u8]> {
        let start = 0usize;
        let end = start + self.server_msg_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.server_msg_len.get() as usize;
        let end = start + self.data_len.get() as usize;
        if end-start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    pub fn len(&self) -> usize {
        5 + self.varidata.len()
    }
}
#[cfg(feature = "dst-construct")]
impl AcctReplyPacket {
    /// # Safety
    /// 
    /// The memory at (mem.0)..(mem.0 + mem.1) must be valid for writing and must not overlap with the memory pointed to by `server_msg` or `data`
    /// 
    /// Note that mem.0 is a **thin** pointer.
    /// If this functions returns Ok, mem.0 may be combined with the correct metadata to create a slice for ease of use.
    pub unsafe fn initialize(mem: (*mut u8, usize), status: AcctStatus, server_msg: &[u8], data: &[u8]) -> Result<(), TacpErr> { unsafe {
        use core::ptr::copy_nonoverlapping;
        let len = mem.1;
        let mem = mem.0;
        let required_mem = 5 + server_msg.len() as u16 as usize + data.len() as u16 as usize;
        if len < required_mem {
            return Err(TacpErr::ParseError("FIXME".to_owned()));
        }
        let server_msg_len_be = U16::new(server_msg.len() as u16);
        let server_msg_len_bytes = server_msg_len_be.as_bytes();
        let data_len_be = U16::new(data.len() as u16);
        let data_len_bytes = data_len_be.as_bytes();
        *mem.add(0) = server_msg_len_bytes[0];
        *mem.add(1) = server_msg_len_bytes[1];
        *mem.add(2) = data_len_bytes[0];
        *mem.add(3) = data_len_bytes[1];
        *mem.add(4) = status as u8;
        let mut start = 5usize;
        let mut end = start+server_msg.len() as u16 as usize;
        copy_nonoverlapping(server_msg.as_ptr(), mem.add(start), server_msg.len() as u16 as usize);
        start = end;
        end = start + data.len() as u16 as usize;
        copy_nonoverlapping(data.as_ptr(), mem.add(start), data.len() as u16 as usize);
        debug_assert!(end == required_mem);
        Ok(())
    }}
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn new(status: AcctStatus, server_msg: &[u8], data: &[u8]) -> Box<Self> { unsafe {
        use core::alloc::*;
        let len = 5 + server_msg.len() + data.len();
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = alloc::alloc::alloc(layout);
        if ptr.is_null() {
            panic!();
        }
        Self::initialize((ptr, len), status, server_msg, data).unwrap();
        let fatref: &mut [u8] = core::mem::transmute(core::ptr::from_raw_parts_mut(ptr, len) as *mut [u8]);
        let fatptr: *mut Self = Self::try_mut_from_bytes(fatref).unwrap() as *mut Self;
        let ret = Box::from_raw(fatptr);
        ret
    }}

    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, self.len()) }
    }
    /// # Safety
    /// 
    /// Caller must maintain endianness, length, enum variants. **Do not use this to encrypt packets**, use `boxed_to_bytes` instead.
    /// Also marked unsafe due to untested slice-DST wrangling internals. More testing is required.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, self.len()) }
    }
    #[doc=include_str!("untested_safety_msg.txt")]
    pub unsafe fn boxed_to_bytes(s: Box<Self>) -> Box<[u8]> {
        let real_len = s.len();
        let thinptr = Box::into_raw(s) as *mut ();
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(thinptr as *mut u8, real_len)) }
    }
}

/// Accounting Status Field
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, Immutable)]
#[repr(u8)]
pub enum AcctStatus {
    SUCCESS = 0x1,
    ERROR = 0x2,
}

/// Unified Error type for this crate
#[derive(Debug, Clone)]
pub enum TacpErr {
    /// An error in parsing a packet or field with an explanation.
    ParseError(String),
    /// A mismatch between a parameter from the header and packet body with an explanation.
    HeaderMismatch(String),
}
impl core::fmt::Display for TacpErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        (self as &dyn core::fmt::Debug).fmt(f)
    }
}
impl core::error::Error for TacpErr {}

impl From<TacpErr> for Vec<u8> {
    fn from(value: TacpErr) -> Self {
        value.to_string().as_bytes().to_owned()
    }
}

impl<S, D> From<zerocopy::error::AlignmentError<S, D>> for TacpErr {
    fn from(_value: zerocopy::error::AlignmentError<S, D>) -> Self {
        todo!()
    }
}
impl From<zerocopy::error::AllocError> for TacpErr {
    fn from(_value: zerocopy::error::AllocError) -> Self {
        todo!()
    }
}
impl<S, D> From<zerocopy::error::SizeError<S,D>> for TacpErr {
    fn from(_value: zerocopy::error::SizeError<S,D>) -> Self {
        todo!()
    }
}
impl<A, S, V> From<ConvertError<A, S, V>> for TacpErr {
    fn from(_value: ConvertError<A, S, V>) -> Self {
        todo!()
    }
}