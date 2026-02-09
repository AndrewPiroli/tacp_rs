//! A `no_std` TACACS+ protocol implementation for Rust.
//!
//! This library provides zero-copy parsing and packet construction for the
//! TACACS+ authentication, authorization, and accounting protocol as defined
//! in [RFC 8907] and updated by [RFC 9887].
//!
//! # Features
//!
//! - **Zero-copy parsing** - Parse TACACS+ packets directly from network buffers with no further copies needed.
//! - **Packet construction** - Build TACACS+ packets using memory efficient APIs with in-place constuction and allocator_api support
//! - **`no_std` compatible** - Works in embedded and bare-metal environments (requires `alloc`)
//! - **Type-safe** - Leverages Rust's type system to prevent protocol errors
//! - **Efficient** - Powered with DSTs and zerocopy for minimal overhead
//!
//! # Feature Flags
//!
//! - **`obfuscation`** (enabled by default) - MD5-based legacy obfuscation support.
//!   
//!   **Note:** RFC 9887 deprecates this method in favor of TLS encryption.
//!   This feature is included for compatibility with older TACACS+ implementations
//!   that do not support TLS. Modern deployments should use TLS and set the
//!   [`UNENCRYPTED`](Flags::UNENCRYPTED) flag.
//!
//! # Quick Start
//!
//! ## Parsing a TACACS+ Packet
//!
//! ```rust,no_run
//! use tacp::{PacketHeader, PacketType, AuthenStartPacket};
//!
//! # fn example(buffer: &[u8]) -> Result<(), tacp::TacpErr> {
//! // Parse the 12-byte header
//! let header = PacketHeader::try_ref_from_bytes(&buffer[..12])?;
//!
//! // Parse the packet body based on type
//! if header.ty == PacketType::AUTHEN {
//!     let packet = AuthenStartPacket::try_ref_from_bytes(&buffer[12..])?;
//!     if let Some(user) = packet.get_user() {
//!         println!("Authenticating user: {:?}", user);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Constructing a TACACS+ Packet
//!
//! ```rust,no_run
//! use tacp::{AuthenReplyPacket, AuthenReplyStatus, AuthenReplyFlags};
//!
//! # fn example() -> Result<(), tacp::TacpErr> {
//! // Create an authentication reply packet
//! let reply = AuthenReplyPacket::new(
//!     AuthenReplyStatus::PASS,
//!     AuthenReplyFlags::empty(),
//!     b"Login successful",
//!     &[],
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Packet Structure
//!
//! All TACACS+ packets share a common structure:
//! - A 12-byte [`PacketHeader`] containing metadata
//! - A variable-length body specific to the packet type
//!
//! The library provides zero-copy parsing via `try_ref_from_bytes()` and
//! efficient construction via `new()` or `initialize()` methods.
//!
//! # Protocol Overview
//!
//! TACACS+ defines three packet exchange types:
//!
//! - **Authentication** - Verify user identity
//!   - Client sends: [`AuthenStartPacket`]
//!   - Server replies: [`AuthenReplyPacket`]
//!   - Client continues: [`AuthenContinuePacket`] (if needed)
//!   
//! - **Authorization** - Approve commands or services
//!   - Client sends: [`AuthorRequestPacket`]
//!   - Server replies: [`AuthorReplyPacket`]
//!   
//! - **Accounting** - Log session information
//!   - Client sends: [`AcctRequestPacket`]
//!   - Server replies: [`AcctReplyPacket`]
//!
//! # Security Considerations
//!
//! - **Use TLS in production** - The legacy obfuscation method is deprecated per RFC 9887
//! - **Cryptographic RNG required** - Session IDs must be generated using a cryptographically
//!   secure random number generator (see [`SessionID`] documentation)
//! - **Validate input** - Always validate packet data from untrusted sources
//! - See the [`obfuscation`] module for details on the deprecated obfuscation method
//!
//! # Requirements
//!
//! - Rust nightly compiler (uses unstable `allocator_api` and `layout_for_ptr` features)
//! - `no_std` compatible, but requires `alloc` for dynamic packet construction
//!
//! [RFC 8907]: https://datatracker.ietf.org/doc/html/rfc8907
//! [RFC 9887]: https://datatracker.ietf.org/doc/html/rfc9887

#![allow(stable_features, non_camel_case_types)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![feature(allocator_api, layout_for_ptr)]
#![no_std]
extern crate alloc;


use alloc::alloc::Allocator;
use alloc::boxed::Box;
use argvalpair::ArgValPairIter;

use bitflags::bitflags;
pub use zerocopy::byteorder::network_endian::{U16, U32};
use zerocopy::{ConvertError, KnownLayout, TryCastError};
pub use zerocopy::{FromBytes, IntoBytes, TryFromBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

pub mod argvalpair;
#[cfg(feature = "obfuscation")]
pub mod obfuscation;

/// Helper macro to precheck packet components before performing narrowing casts.
macro_rules! max {
    ($maxty:ty, $($val:expr),+) => {
        $(
            {
                if ($val.len()) > <$maxty>::MAX as usize {
                    Err(TacpErr::OversizedComponent { component_name: stringify!($val), component_size: $val.len(), max_size: <$maxty>::MAX as usize })
                }
                else { Ok(()) }?
            }
        )+
    };
}

/// Helper macro to precheck argument lengths before performing narrowing casts.
macro_rules! arg_len {
    ($args:ident) => {
        for (arg_idx, arg) in $args.iter().enumerate() {
            if arg.len() > u8::MAX as usize {
                Err(TacpErr::OversizedArgument {
                    arg_index: arg_idx,
                    arg_len: arg.len(),
                })
            } else {
                Ok(())
            }?
        }
    };
}

/// Helper macro to populate packet fields.
macro_rules! mem_cpy {
    ($mem: ident, $ptr: ident, $($ssrc:ident),+) => {
        $(
            $mem[$ptr..($ptr+$ssrc.len())].copy_from_slice($ssrc);
            $ptr += $ssrc.len();
        )+
    };
}

// Original protocol specification RFC 8907 https://datatracker.ietf.org/doc/html/rfc8907
// * Explains data structures, protocol operation, and deployment guidelines.
// Updated by RFC 9887 https://datatracker.ietf.org/doc/html/rfc9887
// * Deprecates the obfuscation method in the orginal protocol and replaces it with TLS, provides updated deployment guidelines.
//   Otherwise no protocol changes. So you will see quotes from original RFC used in most places throught the documentation of this crate.
//
// The following general rules apply to all TACACS+ packet types:
// * To signal that any variable-length data fields are unused, the corresponding length values are set to zero. Such fields MUST be ignored, and treated as if not present.
// * The lengths of data and message fields in a packet are specified by their corresponding length field (and are not null terminated).
// * All length values are unsigned and in network byte order.

/// TACACS+ Header Version Field
///
/// The TACACS+ protocol is versioned to allow revisions while maintaining backwards compatibility. The version number is in every packet header.
/// The changes between minor version 0 and 1 apply only to the authentication process, and all deal with the way that Challenge Handshake Authentication Protocol (CHAP)
/// and Password Authentication Protocol (PAP) authentications are handled.
/// PAP, CHAP, and MS-CHAP login use minor version 1. The normal exchange is a single START packet from the client and a single REPLY from the server.
/// All authorization and accounting and ASCII authentication use minor version 0.
#[repr(u8)]
#[derive(
    Copy, Clone, Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Eq, Unaligned,
)]
pub enum Version {
    /// Minor version 0 (default) - Used for ASCII authentication, authorization, and accounting.
    VersionDefault = 0xc << 4,
    /// Minor version 1 - Used for PAP, CHAP, and MS-CHAP authentication.
    VersionOne = (Self::VersionDefault as u8) | 0x1,
}

#[repr(u8)]
#[derive(
    Copy, Clone, Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, PartialEq, Eq, Unaligned,
)]
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
///
/// The first packet in a session **MUST** have the sequence number 1, and each
/// subsequent packet will increment the sequence number by one.
/// TACACS+ clients only send packets containing odd sequence numbers,
/// and TACACS+ servers only send packets containing even sequence numbers.
///
/// The sequence number must never wrap, i.e., if the sequence number 2^8 - 1 is ever reached, that session must terminate and be restarted with a sequence number of 1.
pub type SeqNo = u8;

/// The ID for this TACACS+ session.
///
/// This field does not change for the duration of the TACACS+ session.
/// This number **MUST** be generated by a cryptographically strong random
/// number generation method.
///
/// Failure to do so will compromise security of the session. For more details, refer to RFC4086
pub type SessionID = U32;

/// The total length of the packet body (not including the header)
///
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
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct PacketHeader {
    /// Version Field
    pub version: Version,
    /// Defines Packet Type
    pub ty: PacketType,
    /// Sequence Number for this session
    pub seq_no: SeqNo,
    /// TACACS+ Flags
    pub flags: Flags,
    /// Uniquely identifies this session
    pub session_id: SessionID,
    /// Length of the packet body
    pub length: PacketLength,
}

impl PacketHeader {
    /// Creates a new packet header with the specified fields.
    ///
    /// This is a const constructor that can be used in const contexts.
    ///
    /// # Parameters
    ///
    /// - `version` - Protocol version (typically [`VersionDefault`](Version::VersionDefault))
    /// - `ty` - Packet type (authentication, authorization, or accounting)
    /// - `seq_no` - Sequence number (see [`SeqNo`] for requirements)
    /// - `flags` - Header flags (see [`Flags`])
    /// - `session_id` - Session identifier (must be cryptographically random)
    /// - `length` - Length of packet body in bytes
    pub const fn new(
        version: Version,
        ty: PacketType,
        seq_no: SeqNo,
        flags: Flags,
        session_id: u32,
        length: u32,
    ) -> Self {
        Self {
            version,
            ty,
            seq_no,
            flags,
            session_id: U32::new(session_id),
            length: U32::new(length),
        }
    }
}

#[repr(transparent)]
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, KnownLayout, FromBytes, IntoBytes, Immutable, Unaligned,
)]
/// Flags for the TACACS+ Header
// All bits not defined (currently UNENCRYPTED and SINGLE_CONNECT) **MUST** be ignored when reading, and **SHOULD** be set to zero when writing
pub struct Flags(pub u8);

bitflags! {
    impl Flags: u8 {
        /// This flag indicates that the sender did not obfuscate the body of the packet. In modern deployments where TLS is used to secure the protocol,
        /// the built in obfuscation is obsoleted
        ///
        /// RFC 9887 §4
        /// > Peers MUST NOT use obfuscation with TLS. A TACACS+ client initiating a TACACS+ TLS connection MUST
        /// > set the TAC_PLUS_UNENCRYPTED_FLAG bit, thereby asserting that obfuscation is not used for the session.
        /// > All subsequent packets MUST have the TAC_PLUS_UNENCRYPTED_FLAG bit set to 1
        ///
        /// For legacy deployments where TLS is not used, this flag should be cleared so the built in obfuscation method is used, as that is better than nothing.
        ///
        /// RFC 8907 §4.1
        /// > This option **MUST** NOT be used in production This flag **SHOULD** be clear in all deployments.
        /// > Modern network traffic tools support encrypted traffic when configured with the shared secret, so obfuscated mode can and **SHOULD** be used even during test.
        ///
        const UNENCRYPTED = 0x1;
        /// This flag is used to allow a client and server to negotiate "Single Connection Mode" as defined in RFC 8907 §4.3
        const SINGLE_CONNECT = 0x4;
    }
}

/// Indicates the authentication action: login, change password, or the insecure and deprecated "sendauth"
#[repr(u8)]
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    KnownLayout,
    Unaligned,
    TryFromBytes,
    IntoBytes,
    Immutable,
)]
pub enum AuthenStartAction {
    /// Standard login authentication.
    LOGIN = 0x1,
    /// Change password operation.
    CHPASS = 0x2,
    /// Deprecated insecure "sendauth" method.
    ///
    /// **Do not use in production.** This method is obsolete and insecure.
    SENDAUTH = 0x4,
}

/// Indicates what method of authentication is being requested/used.
#[repr(u8)]
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    KnownLayout,
    Unaligned,
    TryFromBytes,
    IntoBytes,
    Immutable,
)]
pub enum AuthenType {
    /// ASCII text-based authentication (minor version 0).
    ASCII = 0x1,
    /// Password Authentication Protocol (minor version 1).
    PAP = 0x2,
    /// Challenge-Handshake Authentication Protocol (minor version 1).
    CHAP = 0x3,
    /// Microsoft CHAP version 1 (minor version 1).
    MSCHAP_V1 = 0x5,
    /// Microsoft CHAP version 2 (minor version 1).
    MSCHAP_V2 = 0x6,
}

/// Privilege level (0-15).
///
/// Defines the privilege level for authentication and authorization requests.
/// Higher numbers indicate greater privilege.
///
/// Common values:
/// - `0` - Minimum privilege (typically user/exec mode)
/// - `15` - Maximum privilege (typically enable/admin mode)
/// - `1-14` - Implementation-defined intermediate levels
///
/// The exact meaning of privilege levels is implementation-specific.
pub type PrivLevel = u8;

/// Indicates the Service that authentication is being requested for.
#[repr(u8)]
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    KnownLayout,
    Unaligned,
    TryFromBytes,
    IntoBytes,
    Immutable,
)]
pub enum AuthenService {
    /// No specific service.
    NONE = 0x0,
    /// Standard login service (telnet, SSH, etc.).
    LOGIN = 0x1,
    /// Enable privileged/admin mode.
    ENABLE = 0x2,
    /// Point-to-Point Protocol.
    PPP = 0x3,
    /// Terminal access (Pseudo Terminal).
    PT = 0x5,
    /// Remote command execution (rsh, rexec).
    RCMD = 0x6,
    /// X.25 network protocol.
    X25 = 0x7,
    /// NetWare Asynchronous Services Interface.
    NASI = 0x8,
    /// Firewall proxy authentication.
    FWPROXY = 0x9,
}

/**
Authentication START packet sent by the client to begin authentication.

This is the first packet in an authentication exchange. The server responds
with an [`AuthenReplyPacket`]. If the server's reply indicates more information
is needed, the client sends an [`AuthenContinuePacket`].

See [RFC 8907 Section 5.1](https://datatracker.ietf.org/doc/html/rfc8907#section-5.1) for the complete specification.

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
#[repr(C, packed)]
#[derive(KnownLayout, Immutable, TryFromBytes, IntoBytes, Unaligned)]
pub struct AuthenStartPacket {
    /// Authenication Action from the client
    pub action: AuthenStartAction,
    /// Privilege Level of this packet
    pub priv_level: PrivLevel,
    /// Authentication Type from the client
    pub authen_type: AuthenType,
    /// Authentication Service from the client
    pub authen_svc: AuthenService,
    /// Size of the `user` variable length field
    pub user_len: u8,
    /// Size of the `port` variable length field
    pub port_len: u8,
    /// Size of the `rem_addr` variable length field
    pub rem_addr_len: u8,
    /// Size of the `data` variable length field
    pub data_len: u8,
    /// Variable length packet data. Use get_ functions to extract.
    pub varidata: [u8],
}
impl AuthenStartPacket {
    /// Returns the user field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_user(&self) -> Option<&[u8]> {
        let start = 0usize;
        let end = self.user_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the port field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_port(&self) -> Option<&[u8]> {
        let start = self.user_len as usize;
        let end = start + self.port_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the remote address field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_rem_addr(&self) -> Option<&[u8]> {
        let start = self.user_len as usize + self.port_len as usize;
        let end = start + self.rem_addr_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the data field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.user_len as usize + self.port_len as usize + self.rem_addr_len as usize;
        let end = start + self.data_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the total in-memory size of this packet in bytes.
    ///
    /// Includes both the fixed header fields and all variable-length data.
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // self had to be constructed so it can not be over the isize limit
    pub fn len(&self) -> usize {
        Self::size_for_metadata(self.varidata.len()).unwrap()
    }
}

impl AuthenStartPacket {
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // debug_assert + we shouldn't be having layout issues
    /// Untype a boxed pointer to self, typically for obfuscation before sending.
    pub fn boxed_to_bytes<A: Allocator>(s: Box<Self, A>) -> Box<[u8], A> {
        use alloc::alloc::Layout;
        let real_len = s.len();
        let (ptr, allocator) = Box::into_raw_with_allocator(s);
        unsafe {
            debug_assert!(Layout::for_value_raw(ptr) == Layout::array::<u8>(real_len).unwrap());
        }
        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), real_len),
                allocator,
            )
        }
    }
    /// Initializes an authentication START packet in the provided buffer.
    ///
    /// Writes the packet structure directly into `mem`, avoiding heap allocation.
    /// After successful initialization, convert the buffer to a packet reference
    /// using [`try_mut_from_bytes`](zerocopy::TryFromBytes::try_mut_from_bytes).
    ///
    /// # Parameters
    ///
    /// - `mem` - Buffer to write the packet into (must be large enough)
    /// - `action` - Authentication action (LOGIN, CHPASS, etc.)
    /// - `priv_level` - Privilege level (0-15)
    /// - `authen_type` - Authentication method (ASCII, PAP, CHAP, etc.)
    /// - `authen_service` - Service type (LOGIN, ENABLE, etc.)
    /// - `user` - Username
    /// - `port` - Port identifier
    /// - `rem_addr` - Remote address
    /// - `data` - Additional authentication data
    ///
    /// # Errors
    ///
    /// Returns [`TacpErr::BufferSize`] if `mem` is too small for the packet.
    /// Returns [`TacpErr::OversizedComponent`] if any field exceeds its maximum size.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// |    data   |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck + debug_assert
    pub fn initialize(
        mem: &mut [u8],
        action: AuthenStartAction,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_service: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        data: &[u8],
    ) -> Result<(), TacpErr> {
        max!(u8, user, port, rem_addr, data);
        let len = mem.len();
        let required_mem =
            Self::size_for_metadata(user.len() + port.len() + rem_addr.len() + data.len()).unwrap();
        if len < required_mem {
            return Err(TacpErr::BufferSize {
                required_size: required_mem,
                given_size: len,
            });
        }
        mem[0] = action as u8;
        mem[1] = priv_level;
        mem[2] = authen_type as u8;
        mem[3] = authen_service as u8;
        #[allow(clippy::cast_possible_truncation)]
        {
            mem[4] = user.len() as u8;
            mem[5] = port.len() as u8;
            mem[6] = rem_addr.len() as u8;
            mem[7] = data.len() as u8;
        }
        let mut varidata_ptr = Self::size_for_metadata(0usize).unwrap();
        mem_cpy!(mem, varidata_ptr, user, port, rem_addr, data);
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }
    /// Creates a new authentication START packet with a custom allocator.
    ///
    /// Allocates and constructs the packet in a single operation using the
    /// provided allocator. Returns a `Box` containing the packet.
    ///
    /// # Errors
    ///
    /// Returns [`TacpErr::AllocError`] if allocation fails.
    /// Returns [`TacpErr::OversizedComponent`] if any field exceeds its maximum size.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// |    data   |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck
    pub fn new_in<A: Allocator>(
        the_alloc: A,
        action: AuthenStartAction,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_service: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        data: &[u8],
    ) -> Result<Box<Self, A>, TacpErr> {
        unsafe {
            use core::alloc::Layout;
            use core::ptr::NonNull;
            use core::slice::from_raw_parts_mut as mk_slice;
            max!(u8, user, port, rem_addr, data);
            let len =
                Self::size_for_metadata(user.len() + port.len() + rem_addr.len() + data.len())
                    .unwrap();
            let layout = Layout::array::<u8>(len)?;
            let ptr = the_alloc.allocate(layout)?.as_ptr().cast::<u8>();
            if let Err(e) = Self::initialize(
                mk_slice(ptr, len),
                action,
                priv_level,
                authen_type,
                authen_service,
                user,
                port,
                rem_addr,
                data,
            ) {
                the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                return Err(e);
            }
            let sliced = mk_slice(ptr, len);
            let typed_ptr = match Self::try_mut_from_bytes(sliced) {
                Ok(typed_ref) => core::ptr::from_mut(typed_ref),
                Err(e) => {
                    let e: TacpErr = e.into();
                    the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                    return Err(e);
                }
            };
            Ok(Box::from_raw_in(typed_ptr, the_alloc))
        }
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// |    data   |    255   |
    /// Creates a new authentication START packet using the global allocator.
    ///
    /// This is a convenience wrapper around [`new_in`](Self::new_in) that uses
    /// the default global allocator.
    ///
    /// # Errors
    ///
    /// See [`new_in`](Self::new_in) for error conditions and size limits.
    pub fn new(
        action: AuthenStartAction,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_service: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        data: &[u8],
    ) -> Result<Box<Self>, TacpErr> {
        Self::new_in(
            alloc::alloc::Global,
            action,
            priv_level,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            data,
        )
    }
}

#[repr(u8)]
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable,
)]
/// Status field for Authentication Reply Packets
pub enum AuthenReplyStatus {
    /// Authentication succeeded.
    PASS = 0x01,
    /// Authentication failed.
    FAIL = 0x02,
    /// Server needs additional data from client.
    GETDATA = 0x03,
    /// Server requests username from client.
    GETUSER = 0x04,
    /// Server requests password from client.
    GETPASS = 0x05,
    /// Restart authentication sequence from the beginning.
    RESTART = 0x06,
    /// An error occurred during authentication.
    ERROR = 0x07,
    /// Client should redirect to a different server.
    FOLLOW = 0x21,
}

/**
Authentication REPLY packet sent by the server in response to a START or CONTINUE.

Sent in response to either an [`AuthenStartPacket`] or [`AuthenContinuePacket`].
The [`status`](Self::status) field indicates whether authentication succeeded, failed,
or requires more information. The client may send an [`AuthenContinuePacket`] if more
information is needed.

See [RFC 8907 Section 5.2](https://datatracker.ietf.org/doc/html/rfc8907#section-5.2) for the complete specification.

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
#[repr(C, packed)]
#[derive(KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub struct AuthenReplyPacket {
    /// Authentication Status from the server
    pub status: AuthenReplyStatus,
    /// Authentication Flags of this packet
    pub flags: AuthenReplyFlags,
    /// Size of the `server_msg` variable length field
    pub serv_msg_len: U16,
    /// Size of the `data` variable length field
    pub data_len: U16,
    /// Variable length packet data. Use get_ functions to extract.
    pub varidata: [u8],
}
impl AuthenReplyPacket {
    /// Returns the server message field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_serv_msg(&self) -> Option<&[u8]> {
        let start = 0;
        let end = self.serv_msg_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the data field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.serv_msg_len.get() as usize;
        let end = start + self.data_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the total in-memory size of this packet in bytes.
    ///
    /// Includes both the fixed header fields and all variable-length data.
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // self had to be constructed so it can not be over the isize limit
    pub fn len(&self) -> usize {
        Self::size_for_metadata(self.varidata.len()).unwrap()
    }
}

impl AuthenReplyPacket {
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // debug_assert + we shouldn't be having layout issues
    /// Untype a boxed pointer to self, typically for obfuscation before sending.
    pub fn boxed_to_bytes<A: Allocator>(s: Box<Self, A>) -> Box<[u8], A> {
        use alloc::alloc::Layout;
        let real_len = s.len();
        let (ptr, allocator) = Box::into_raw_with_allocator(s);
        unsafe {
            debug_assert!(Layout::for_value_raw(ptr) == Layout::array::<u8>(real_len).unwrap());
        }
        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), real_len),
                allocator,
            )
        }
    }
    /// In-place initializer. If this returns Ok(()), you may perform a conversion to Self via TryFromBytes::try_mut_from_bytes
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck + debug_assert
    pub fn initialize(
        mem: &mut [u8],
        status: AuthenReplyStatus,
        flags: AuthenReplyFlags,
        serv_msg: &[u8],
        data: &[u8],
    ) -> Result<(), TacpErr> {
        max!(u16, serv_msg, data);
        let len = mem.len();
        let required_mem = Self::size_for_metadata(serv_msg.len() + data.len()).unwrap();
        if len < required_mem {
            return Err(TacpErr::BufferSize {
                required_size: required_mem,
                given_size: len,
            });
        }
        #[allow(clippy::cast_possible_truncation)]
        let serv_msg_len = U16::new(serv_msg.len() as u16);
        let serv_msg_bytes = serv_msg_len.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        let data_len = U16::new(data.len() as u16);
        let data_len_bytes = data_len.as_bytes();
        mem[0] = status as u8;
        mem[1] = flags.0;
        mem[2] = serv_msg_bytes[0];
        mem[3] = serv_msg_bytes[1];
        mem[4] = data_len_bytes[0];
        mem[5] = data_len_bytes[1];
        let mut varidata_ptr = Self::size_for_metadata(0usize).unwrap();
        mem_cpy!(mem, varidata_ptr, serv_msg, data);
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck
    pub fn new_in<A: Allocator>(
        the_alloc: A,
        status: AuthenReplyStatus,
        flags: AuthenReplyFlags,
        serv_msg: &[u8],
        data: &[u8],
    ) -> Result<Box<Self, A>, TacpErr> {
        unsafe {
            use core::alloc::Layout;
            use core::ptr::NonNull;
            use core::slice::from_raw_parts_mut as mk_slice;
            max!(u16, serv_msg, data);
            let len = Self::size_for_metadata(serv_msg.len() + data.len()).unwrap();
            let layout = Layout::array::<u8>(len)?;
            let ptr = the_alloc.allocate(layout)?.as_ptr().cast::<u8>();
            if let Err(e) = Self::initialize(mk_slice(ptr, len), status, flags, serv_msg, data) {
                the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                return Err(e);
            }
            let sliced = mk_slice(ptr, len);
            let typed_ptr = match Self::try_mut_from_bytes(sliced) {
                Ok(typed_ref) => core::ptr::from_mut(typed_ref),
                Err(e) => {
                    let e: TacpErr = e.into();
                    the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                    return Err(e);
                }
            };
            Ok(Box::from_raw_in(typed_ptr, the_alloc))
        }
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    pub fn new(
        status: AuthenReplyStatus,
        flags: AuthenReplyFlags,
        serv_msg: &[u8],
        data: &[u8],
    ) -> Result<Box<Self>, TacpErr> {
        Self::new_in(alloc::alloc::Global, status, flags, serv_msg, data)
    }
}

#[repr(transparent)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
/// Flags for the Authentication Reply packet
pub struct AuthenReplyFlags(pub u8);

bitflags! {
    impl AuthenReplyFlags: u8 {
        /// If the information being requested by the server from the client is sensitive, then the server should set
        /// the this flag. When the client queries the user for the information, the response MUST NOT be reflected in
        /// the user interface as it is entered.
        const REPLY_NOECHO = 1;
    }
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
#[repr(C, packed)]
#[derive(KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub struct AuthenContinuePacket {
    /// Size of the `user_msg` variable length field
    pub user_msg_len: U16,
    /// Size of the `data` variable length field
    pub data_len: U16,
    /// Authentication Flags for this packet
    pub flags: AuthenContinueFlags,
    /// Variable length packet data. Use get_ functions to extract.
    pub varidata: [u8],
}

impl AuthenContinuePacket {
    /// Returns the user message field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_user_msg(&self) -> Option<&[u8]> {
        let start = 0;
        let end = self.user_msg_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the data field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.user_msg_len.get() as usize;
        let end = start + self.data_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the total in-memory size of this packet in bytes.
    ///
    /// Includes both the fixed header fields and all variable-length data.
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // self had to be constructed so it can not be over the isize limit
    pub fn len(&self) -> usize {
        Self::size_for_metadata(self.user_msg_len.get() as usize + self.data_len.get() as usize)
            .unwrap()
    }
}

impl AuthenContinuePacket {
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // debug_assert + we shouldn't be having layout issues
    /// Untype a boxed pointer to self, typically for obfuscation before sending.
    pub fn boxed_to_bytes<A: Allocator>(s: Box<Self, A>) -> Box<[u8], A> {
        use alloc::alloc::Layout;
        let real_len = s.len();
        let (ptr, allocator) = Box::into_raw_with_allocator(s);
        unsafe {
            debug_assert!(Layout::for_value_raw(ptr) == Layout::array::<u8>(real_len).unwrap());
        }
        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), real_len),
                allocator,
            )
        }
    }
    /// In-place initializer. If this returns Ok(()), you may perform a conversion to Self via TryFromBytes::try_mut_from_bytes
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  user_msg |   65535  |
    /// |    data   |   65535  |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck + debug_assert
    pub fn initialize(
        mem: &mut [u8],
        flags: AuthenContinueFlags,
        user_msg: &[u8],
        data: &[u8],
    ) -> Result<(), TacpErr> {
        max!(u16, user_msg, data);
        let len = mem.len();
        let required_mem = Self::size_for_metadata(user_msg.len() + data.len()).unwrap();
        if len < required_mem {
            return Err(TacpErr::BufferSize {
                required_size: required_mem,
                given_size: len,
            });
        }
        #[allow(clippy::cast_possible_truncation)]
        let user_msg_len_be = U16::new(user_msg.len() as u16);
        #[allow(clippy::cast_possible_truncation)]
        let data_len_be = U16::new(data.len() as u16);
        let user_msg_len_bytes = user_msg_len_be.as_bytes();
        let data_len_bytes = data_len_be.as_bytes();
        mem[0] = user_msg_len_bytes[0];
        mem[1] = user_msg_len_bytes[1];
        mem[2] = data_len_bytes[0];
        mem[3] = data_len_bytes[1];
        mem[4] = flags.0;
        let mut varidata_ptr = Self::size_for_metadata(0usize).unwrap();
        mem_cpy!(mem, varidata_ptr, user_msg, data);
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  user_msg |   65535  |
    /// |    data   |   65535  |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck
    pub fn new_in<A: Allocator>(
        the_alloc: A,
        flags: AuthenContinueFlags,
        user_msg: &[u8],
        data: &[u8],
    ) -> Result<Box<Self, A>, TacpErr> {
        unsafe {
            use core::alloc::Layout;
            use core::ptr::NonNull;
            use core::slice::from_raw_parts_mut as mk_slice;
            max!(u16, user_msg, data);
            let len = Self::size_for_metadata(user_msg.len() + data.len()).unwrap();
            let layout = Layout::array::<u8>(len)?;
            let ptr = the_alloc.allocate(layout)?.as_ptr().cast::<u8>();
            if let Err(e) = Self::initialize(mk_slice(ptr, len), flags, user_msg, data) {
                the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                return Err(e);
            }
            let sliced = mk_slice(ptr, len);
            let typed_ptr = match Self::try_mut_from_bytes(sliced) {
                Ok(typed_ref) => core::ptr::from_mut(typed_ref),
                Err(e) => {
                    let e: TacpErr = e.into();
                    the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                    return Err(e);
                }
            };
            Ok(Box::from_raw_in(typed_ptr, the_alloc))
        }
    }
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  user_msg |   65535  |
    /// |    data   |   65535  |
    pub fn new(
        flags: AuthenContinueFlags,
        user_msg: &[u8],
        data: &[u8],
    ) -> Result<Box<Self>, TacpErr> {
        Self::new_in(alloc::alloc::Global, flags, user_msg, data)
    }
}

#[repr(transparent)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
/// Flags for the Authentication Continue Packet
pub struct AuthenContinueFlags(pub u8);

bitflags! {
    impl AuthenContinueFlags: u8 {
        /// The client may prematurely terminate a session by setting the TAC_PLUS_CONTINUE_FLAG_ABORT flag in the CONTINUE message.
        /// If this flag is set, the data portion of the message may contain a text explaining the reason for the abort. This text will
        /// be handled by the server according to the requirements of the deployment.
        const FLAG_ABORT = 1;
    }
}

/// Indicates the authentication method used to acquire user information
///
/// As this information is not always subject to verification, it MUST NOT be used in policy evaluation.
/// LINE refers to a fixed password associated with the terminal line used to gain access.
/// LOCAL is a client local user database. ENABLE is a command that authenticates in order to grant new privileges.
/// TACACSPLUS is, of course, TACACS+. GUEST is an unqualified guest authentication.
/// RADIUS is the RADIUS authentication protocol. RCMD refers to authentication provided via the R-command protocols from Berkeley Unix.
/// KRB5 \[RFC4120\] and KRB4 \[KRB4\] are Kerberos versions 5 and 4.
/// As mentioned above, this field is used by the client to indicate how it performed the authentication.
/// One of the options (`TAC_PLUS_AUTHEN_METH_TACACSPLUS` := 0x06) is TACACS+ itself, and so the detail of how the client performed this option is given in "Authentication" (Section 5).
/// For all other options, such as KRB and RADIUS, the TACACS+ protocol did not play any part in the authentication phase;
/// as those interactions were not conducted using the TACACS+ protocol, they will not be documented here.
/// For implementers of clients who need details of the other protocols, please refer to the respective Kerberos \[RFC4120\] and RADIUS \[RFC3579\] RFCs.
#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub enum AuthorMethod {
    /// No authentication method set.
    NOT_SET = 0x00,
    /// No authentication required.
    NONE = 0x01,
    /// Kerberos version 5.
    KRB5 = 0x02,
    /// Line password authentication.
    LINE = 0x03,
    /// Enable password authentication.
    ENABLE = 0x04,
    /// Local username/password database.
    LOCAL = 0x05,
    /// TACACS+ authentication.
    TACACSPLUS = 0x06,
    /// Guest authentication (unauthenticated).
    GUEST = 0x08,
    /// RADIUS authentication.
    RADIUS = 0x10,
    /// Kerberos version 4 (deprecated).
    KRB4 = 0x11,
    /// Remote Command Authentication.
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
#[repr(C, packed)]
#[derive(KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub struct AuthorRequestPacket {
    /// Associated authentication method for this request
    pub method: AuthorMethod,
    /// Privilege Level of this packet
    pub priv_level: PrivLevel,
    /// Associated authentication type for this request
    pub authen_type: AuthenType,
    /// Associated authentication service for this request
    pub authen_svc: AuthenService,
    /// Size of the `user` variable length field
    pub user_len: u8,
    /// Size of the `port` variable length field
    pub port_len: u8,
    /// Size of the `rem_addr` variable length field
    pub rem_addr_len: u8,
    /// Number of arguments in this request
    pub arg_cnt: u8,
    /// Variable length packet data. Use get_ functions to extract.
    pub varidata: [u8],
}

impl AuthorRequestPacket {
    /// Returns the user field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_user(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize;
        let end = start + self.user_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the port field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_port(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.user_len as usize;
        let end = start + self.port_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the remote addr field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_rem_addr(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.user_len as usize + self.port_len as usize;
        let end = start + self.rem_addr_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the entire argument-value section from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_raw_argvalpair(&self, idx: u8) -> Option<&[u8]> {
        if idx > self.arg_cnt {
            return None;
        }
        let arg_len = self.varidata[idx as usize] as usize;
        let mut skip = self.arg_cnt as usize
            + self.user_len as usize
            + self.port_len as usize
            + self.rem_addr_len as usize;
        for n in 0..idx {
            skip += self.varidata[n as usize] as usize;
        }
        Some(&self.varidata[skip..(skip + arg_len)])
    }
    /// Returns an iterator of the Argument-Value pairs of this packet.
    pub fn iter_args(&self) -> ArgValPairIter<'_> {
        let lengths_range = 0..(self.arg_cnt as usize);
        let data_range_base = self.arg_cnt as usize
            + self.user_len as usize
            + self.port_len as usize
            + self.rem_addr_len as usize;
        ArgValPairIter::new(
            self.arg_cnt,
            &self.varidata[lengths_range],
            &self.varidata[data_range_base..],
        )
    }
    /// Returns the total in-memory size of this packet in bytes.
    ///
    /// Includes both the fixed header fields and all variable-length data.
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // self had to be constructed so it can not be over the isize limit
    pub fn len(&self) -> usize {
        Self::size_for_metadata(self.varidata.len()).unwrap()
    }
}

impl AuthorRequestPacket {
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // debug_assert + we shouldn't be having layout issues
    /// Untype a boxed pointer to self, typically for obfuscation before sending.
    pub fn boxed_to_bytes<A: Allocator>(s: Box<Self, A>) -> Box<[u8], A> {
        use alloc::alloc::Layout;
        let real_len = s.len();
        let (ptr, allocator) = Box::into_raw_with_allocator(s);
        unsafe {
            debug_assert!(Layout::for_value_raw(ptr) == Layout::array::<u8>(real_len).unwrap());
        }
        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), real_len),
                allocator,
            )
        }
    }
    /// In-place initializer. If this returns Ok(()), you may perform a conversion to Self via TryFromBytes::try_mut_from_bytes
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck + debug_assert
    pub fn initialize(
        mem: &mut [u8],
        method: AuthorMethod,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_svc: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        args: &[&[u8]],
    ) -> Result<(), TacpErr> {
        max!(u8, user, port, rem_addr, args);
        arg_len!(args);
        let len = mem.len();
        let required_mem = Self::size_for_metadata(
            user.len()
                + port.len()
                + rem_addr.len()
                + args.len()
                + args.iter().fold(0, |acc, arg| acc + arg.len()),
        )
        .unwrap();
        if len < required_mem {
            return Err(TacpErr::BufferSize {
                required_size: required_mem,
                given_size: len,
            });
        }
        mem[0] = method as u8;
        mem[1] = priv_level;
        mem[2] = authen_type as u8;
        mem[3] = authen_svc as u8;
        #[allow(clippy::cast_possible_truncation)]
        {
            mem[4] = user.len() as u8;
            mem[5] = port.len() as u8;
            mem[6] = rem_addr.len() as u8;
            mem[7] = args.len() as u8;
        }
        let fixed_part = Self::size_for_metadata(0usize).unwrap();
        let mut varidata_ptr = fixed_part + args.len();
        mem_cpy!(mem, varidata_ptr, user, port, rem_addr);
        for (arg_idx, arg) in args.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let arg_len = arg.len() as u8;
            mem[fixed_part + arg_idx] = arg_len;
            mem[varidata_ptr..(varidata_ptr + arg_len as usize)].copy_from_slice(arg);
            varidata_ptr += arg_len as usize;
        }
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck
    pub fn new_in<A: Allocator>(
        the_alloc: A,
        method: AuthorMethod,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_svc: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        args: &[&[u8]],
    ) -> Result<Box<Self, A>, TacpErr> {
        unsafe {
            use core::alloc::Layout;
            use core::ptr::NonNull;
            use core::slice::from_raw_parts_mut as mk_slice;
            max!(u8, user, port, rem_addr, args);
            arg_len!(args);
            let len = Self::size_for_metadata(
                user.len()
                    + port.len()
                    + rem_addr.len()
                    + args.len()
                    + args.iter().fold(0, |acc, arg| acc + arg.len()),
            )
            .unwrap();
            let layout = Layout::array::<u8>(len)?;
            let ptr = the_alloc.allocate(layout)?.as_ptr().cast::<u8>();
            if let Err(e) = Self::initialize(
                mk_slice(ptr, len),
                method,
                priv_level,
                authen_type,
                authen_svc,
                user,
                port,
                rem_addr,
                args,
            ) {
                the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                return Err(e);
            }
            let sliced = mk_slice(ptr, len);
            let typed_ptr = match Self::try_mut_from_bytes(sliced) {
                Ok(typed_ref) => core::ptr::from_mut(typed_ref),
                Err(e) => {
                    let e: TacpErr = e.into();
                    the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                    return Err(e);
                }
            };
            Ok(Box::from_raw_in(typed_ptr, the_alloc))
        }
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    pub fn new(
        method: AuthorMethod,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_svc: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        args: &[&[u8]],
    ) -> Result<Box<Self>, TacpErr> {
        Self::new_in(
            alloc::alloc::Global,
            method,
            priv_level,
            authen_type,
            authen_svc,
            user,
            port,
            rem_addr,
            args,
        )
    }
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
#[repr(C, packed)]
#[derive(KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub struct AuthorReplyPacket {
    /// Authorization Status field from the server
    pub status: AuthorStatus,
    /// Number of argument value pairs present in this packet
    pub arg_cnt: u8,
    /// Size of the `server_msg` variable length field
    pub server_msg_len: U16,
    /// Size of the `data` variable length field
    pub data_len: U16,
    /// Variable length packet data. Use get_ functions to extract.
    pub varidata: [u8],
}

impl AuthorReplyPacket {
    /// Returns the server message field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_serv_msg(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize;
        let end = start + self.server_msg_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the data field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.server_msg_len.get() as usize;
        let end = start + self.data_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the entire argument-value section from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_raw_argvalpair(&self, idx: u8) -> Option<&[u8]> {
        if idx > self.arg_cnt {
            return None;
        }
        let arg_len = self.varidata[idx as usize] as usize;
        let mut skip = self.arg_cnt as usize
            + self.server_msg_len.get() as usize
            + self.data_len.get() as usize;
        for n in 0..idx {
            skip += self.varidata[n as usize] as usize;
        }
        Some(&self.varidata[skip..(skip + arg_len)])
    }
    /// Returns an iterator of the Argument-Value pairs of this packet.
    pub fn iter_args(&self) -> ArgValPairIter<'_> {
        let lengths_range = 0..(self.arg_cnt as usize);
        let data_range_base = self.arg_cnt as usize
            + self.server_msg_len.get() as usize
            + self.data_len.get() as usize;
        ArgValPairIter::new(
            self.arg_cnt,
            &self.varidata[lengths_range],
            &self.varidata[data_range_base..],
        )
    }
    /// Returns the total in-memory size of this packet in bytes.
    ///
    /// Includes both the fixed header fields and all variable-length data.
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // self had to be constructed so it can not be over the isize limit
    pub fn len(&self) -> usize {
        Self::size_for_metadata(self.varidata.len()).unwrap()
    }
}

impl AuthorReplyPacket {
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // debug_assert + we shouldn't be having layout issues
    /// Untype a boxed pointer to self, typically for obfuscation before sending.
    pub fn boxed_to_bytes<A: Allocator>(s: Box<Self, A>) -> Box<[u8], A> {
        use alloc::alloc::Layout;
        let real_len = s.len();
        let (ptr, allocator) = Box::into_raw_with_allocator(s);
        unsafe {
            debug_assert!(Layout::for_value_raw(ptr) == Layout::array::<u8>(real_len).unwrap());
        }
        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), real_len),
                allocator,
            )
        }
    }
    /// In-place initializer. If this returns Ok(()), you may perform a conversion to Self via TryFromBytes::try_mut_from_bytes
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck + debug_assert
    pub fn initialize(
        mem: &mut [u8],
        status: AuthorStatus,
        args: &[&[u8]],
        server_msg: &[u8],
        data: &[u8],
    ) -> Result<(), TacpErr> {
        max!(u8, args);
        max!(u16, server_msg, data);
        arg_len!(args);
        let len = mem.len();
        let required_mem = Self::size_for_metadata(
            server_msg.len()
                + data.len()
                + args.len()
                + args.iter().fold(0, |acc, arg| acc + arg.len()),
        )
        .unwrap();
        if len < required_mem {
            return Err(TacpErr::BufferSize {
                required_size: required_mem,
                given_size: len,
            });
        }
        mem[0] = status as u8;
        #[allow(clippy::cast_possible_truncation)]
        {
            mem[1] = args.len() as u8;
            let server_msg_len_be = U16::new(server_msg.len() as u16);
            let data_len_be = U16::new(data.len() as u16);
            let server_msg_len_bytes = server_msg_len_be.as_bytes();
            let data_len_bytes = data_len_be.as_bytes();
            mem[2] = server_msg_len_bytes[0];
            mem[3] = server_msg_len_bytes[1];
            mem[4] = data_len_bytes[0];
            mem[5] = data_len_bytes[1];
        }
        let fixed_part = Self::size_for_metadata(0usize).unwrap();
        let mut varidata_ptr = fixed_part + args.len();
        mem_cpy!(mem, varidata_ptr, server_msg, data);
        for (arg_idx, arg) in args.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let arg_len = arg.len() as u8;
            mem[fixed_part + arg_idx] = arg_len;
            mem[varidata_ptr..(varidata_ptr + arg_len as usize)].copy_from_slice(arg);
            varidata_ptr += arg_len as usize;
        }
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }
    /// In-place initializer. If this returns Ok(()), you may perform a conversion to Self via TryFromBytes::try_mut_from_bytes
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck
    pub fn new_in<A: Allocator>(
        the_alloc: A,
        status: AuthorStatus,
        args: &[&[u8]],
        server_msg: &[u8],
        data: &[u8],
    ) -> Result<Box<Self, A>, TacpErr> {
        unsafe {
            use core::alloc::Layout;
            use core::ptr::NonNull;
            use core::slice::from_raw_parts_mut as mk_slice;
            max!(u8, args);
            max!(u16, server_msg, data);
            arg_len!(args);
            let len = Self::size_for_metadata(
                server_msg.len()
                    + data.len()
                    + args.len()
                    + args.iter().fold(0, |acc, arg| acc + arg.len()),
            )
            .unwrap();
            let layout = Layout::array::<u8>(len)?;
            let ptr = the_alloc.allocate(layout)?.as_ptr().cast::<u8>();
            if let Err(e) = Self::initialize(mk_slice(ptr, len), status, args, server_msg, data) {
                the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                return Err(e);
            }
            let sliced = mk_slice(ptr, len);
            let typed_ptr = match Self::try_mut_from_bytes(sliced) {
                Ok(typed_ref) => core::ptr::from_mut(typed_ref),
                Err(e) => {
                    let e: TacpErr = e.into();
                    the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                    return Err(e);
                }
            };
            Ok(Box::from_raw_in(typed_ptr, the_alloc))
        }
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    pub fn new(
        status: AuthorStatus,
        args: &[&[u8]],
        server_msg: &[u8],
        data: &[u8],
    ) -> Result<Box<Self>, TacpErr> {
        Self::new_in(alloc::alloc::Global, status, args, server_msg, data)
    }
}

/// Status of the Authorization Request
#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub enum AuthorStatus {
    /// Authorization granted with additional attributes.
    ///
    /// The server may add attributes to those provided by the client.
    PASS_ADD = 0x1,
    /// Authorization granted with replacement attributes.
    ///
    /// The server replaces client-provided attributes with its own.
    PASS_REPL = 0x2,
    /// Authorization denied.
    FAIL = 0x10,
    /// An error occurred during authorization.
    ERROR = 0x11,
    /// Client should redirect to a different server.
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
*/
#[repr(C, packed)]
#[derive(KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub struct AcctRequestPacket {
    /// Accounting Flags from the client
    pub flags: AcctFlags,
    /// Associated authorization method for this request
    pub method: AuthorMethod,
    /// Privilege Level of this packet
    pub priv_level: PrivLevel,
    /// Associated authentication type for this request
    pub authen_type: AuthenType,
    /// Associated authentication service for this request
    pub authen_svc: AuthenService,
    /// Size of the `user` variable length field
    pub user_len: u8,
    /// Size of the `port` variable length field
    pub port_len: u8,
    /// Size of the `rem_addr` variable length field
    pub rem_addr_len: u8,
    /// Number of Argument-Value pairs present in this request
    pub arg_cnt: u8,
    /// Variable length packet data. Use get_ functions to extract.
    pub varidata: [u8],
}
impl AcctRequestPacket {
    /// Returns the user field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_user(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize;
        let end = start + self.user_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the port field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_port(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.user_len as usize;
        let end = start + self.port_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the remote addr field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_rem_addr(&self) -> Option<&[u8]> {
        let start = self.arg_cnt as usize + self.user_len as usize + self.port_len as usize;
        let end = start + self.rem_addr_len as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the entire argument-value section from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_raw_argvalpair(&self, idx: u8) -> Option<&[u8]> {
        if idx > self.arg_cnt {
            return None;
        }
        let arg_len = self.varidata[idx as usize] as usize;
        let mut skip = self.arg_cnt as usize
            + self.user_len as usize
            + self.port_len as usize
            + self.rem_addr_len as usize;
        for n in 0..idx {
            skip += self.varidata[n as usize] as usize;
        }
        Some(&self.varidata[skip..(skip + arg_len)])
    }
    /// Returns an iterator of the Argument-Value pairs of this packet.
    pub fn iter_args(&self) -> ArgValPairIter<'_> {
        let lengths_range = 0..(self.arg_cnt as usize);
        let data_range_base = self.arg_cnt as usize
            + self.user_len as usize
            + self.port_len as usize
            + self.rem_addr_len as usize;
        ArgValPairIter::new(
            self.arg_cnt,
            &self.varidata[lengths_range],
            &self.varidata[data_range_base..],
        )
    }
    /// Returns the total in-memory size of this packet in bytes.
    ///
    /// Includes both the fixed header fields and all variable-length data.
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // self had to be constructed so it can not be over the isize limit
    pub fn len(&self) -> usize {
        Self::size_for_metadata(self.varidata.len()).unwrap()
    }
}

impl AcctRequestPacket {
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // debug_assert + we shouldn't be having layout issues
    /// Untype a boxed pointer to self, typically for obfuscation before sending.
    pub fn boxed_to_bytes<A: Allocator>(s: Box<Self, A>) -> Box<[u8], A> {
        use alloc::alloc::Layout;
        let real_len = s.len();
        let (ptr, allocator) = Box::into_raw_with_allocator(s);
        unsafe {
            debug_assert!(Layout::for_value_raw(ptr) == Layout::array::<u8>(real_len).unwrap());
        }
        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), real_len),
                allocator,
            )
        }
    }
    /// In-place initializer. If this returns Ok(()), you may perform a conversion to Self via TryFromBytes::try_mut_from_bytes
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck + debug_assert
    pub fn initialize(
        mem: &mut [u8],
        flags: AcctFlags,
        method: AuthorMethod,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_svc: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        args: &[&[u8]],
    ) -> Result<(), TacpErr> {
        max!(u8, user, port, rem_addr, args);
        arg_len!(args);
        let len = mem.len();
        let required_mem = Self::size_for_metadata(
            user.len()
                + port.len()
                + rem_addr.len()
                + args.len()
                + args.iter().fold(0, |acc, arg| acc + arg.len()),
        )
        .unwrap();
        if len < required_mem {
            return Err(TacpErr::BufferSize {
                required_size: required_mem,
                given_size: len,
            });
        }
        mem[0] = flags as u8;
        mem[1] = method as u8;
        mem[2] = priv_level;
        mem[3] = authen_type as u8;
        mem[4] = authen_svc as u8;
        #[allow(clippy::cast_possible_truncation)]
        {
            mem[5] = user.len() as u8;
            mem[6] = port.len() as u8;
            mem[7] = rem_addr.len() as u8;
            mem[9] = args.len() as u8;
        }
        let fixed_part = Self::size_for_metadata(0usize).unwrap();
        let mut varidata_ptr = fixed_part + args.len();
        mem_cpy!(mem, varidata_ptr, user, port, rem_addr);
        for (arg_idx, arg) in args.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let arg_len = arg.len() as u8;
            mem[fixed_part + arg_idx] = arg_len;
            mem[varidata_ptr..(varidata_ptr + arg_len as usize)].copy_from_slice(arg);
            varidata_ptr += arg_len as usize;
        }
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck
    pub fn new_in<A: Allocator>(
        the_alloc: A,
        flags: AcctFlags,
        method: AuthorMethod,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_svc: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        args: &[&[u8]],
    ) -> Result<Box<Self, A>, TacpErr> {
        unsafe {
            use core::alloc::Layout;
            use core::ptr::NonNull;
            use core::slice::from_raw_parts_mut as mk_slice;
            max!(u8, user, port, rem_addr, args);
            arg_len!(args);
            let len = Self::size_for_metadata(
                user.len()
                    + port.len()
                    + rem_addr.len()
                    + args.len()
                    + args.iter().fold(0, |acc, arg| acc + arg.len()),
            )
            .unwrap();
            let layout = Layout::array::<u8>(len)?;
            let ptr = the_alloc.allocate(layout)?.as_ptr().cast::<u8>();
            if let Err(e) = Self::initialize(
                mk_slice(ptr, len),
                flags,
                method,
                priv_level,
                authen_type,
                authen_svc,
                user,
                port,
                rem_addr,
                args,
            ) {
                the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                return Err(e);
            }
            let sliced = mk_slice(ptr, len);
            let typed_ptr = match Self::try_mut_from_bytes(sliced) {
                Ok(typed_ref) => core::ptr::from_mut(typed_ref),
                Err(e) => {
                    let e: TacpErr = e.into();
                    the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                    return Err(e);
                }
            };
            Ok(Box::from_raw_in(typed_ptr, the_alloc))
        }
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation failure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |    user   |    255   |
    /// |    port   |    255   |
    /// |  rem_addr |    255   |
    /// | # of args |    255   |
    /// |  each arg |    255   |
    pub fn new(
        flags: AcctFlags,
        method: AuthorMethod,
        priv_level: PrivLevel,
        authen_type: AuthenType,
        authen_svc: AuthenService,
        user: &[u8],
        port: &[u8],
        rem_addr: &[u8],
        args: &[&[u8]],
    ) -> Result<Box<Self>, TacpErr> {
        Self::new_in(
            alloc::alloc::Global,
            flags,
            method,
            priv_level,
            authen_type,
            authen_svc,
            user,
            port,
            rem_addr,
            args,
        )
    }
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

`FLAG_START` = 0x2

`FLAG_STOP` = 0x4

`FLAG_WATCHDOG` = 0x8
*/
#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub enum AcctFlags {
    /// Start accounting record - session is beginning.
    RecordStart = 0x2,
    /// Stop accounting record - session has ended.
    RecordStop = 0x4,
    /// Watchdog accounting record without updates.
    WatchdogNoUpdate = 0x8,
    /// Watchdog/update accounting record - session is ongoing.
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
#[repr(C, packed)]
#[derive(KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub struct AcctReplyPacket {
    /// Size of the `server_msg` variable length field
    pub server_msg_len: U16,
    /// Size of the `data` variable length field
    pub data_len: U16,
    /// Accounting Status response from server
    pub status: AcctStatus,
    /// Variable length packet data. Use get_ functions to extract.
    pub varidata: [u8],
}
impl AcctReplyPacket {
    /// Returns the server message field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_serv_msg(&self) -> Option<&[u8]> {
        let start = 0usize;
        let end = start + self.server_msg_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the data field from this packet.
    ///
    /// Returns `None` if the field is not present (length is 0).
    pub fn get_data(&self) -> Option<&[u8]> {
        let start = self.server_msg_len.get() as usize;
        let end = start + self.data_len.get() as usize;
        if end - start == 0 {
            return None;
        }
        Some(&self.varidata[start..end])
    }
    /// Returns the total in-memory size of this packet in bytes.
    ///
    /// Includes both the fixed header fields and all variable-length data.
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // self had to be constructed so it can not be over the isize limit
    pub fn len(&self) -> usize {
        Self::size_for_metadata(self.varidata.len()).unwrap()
    }
}

impl AcctReplyPacket {
    /// In-place initializer. If this returns Ok(()), you may perform a conversion to Self via TryFromBytes::try_mut_from_bytes
    ///
    /// # Errors
    ///
    /// Will return Err if not enough memory is provided to initilize the packet or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck + debug_assert
    pub fn initialize(
        mem: &mut [u8],
        status: AcctStatus,
        server_msg: &[u8],
        data: &[u8],
    ) -> Result<(), TacpErr> {
        max!(u16, server_msg, data);
        let len = mem.len();
        let required_mem = Self::size_for_metadata(server_msg.len() + data.len()).unwrap();
        if len < required_mem {
            return Err(TacpErr::BufferSize {
                required_size: required_mem,
                given_size: len,
            });
        }
        #[allow(clippy::cast_possible_truncation)]
        let server_msg_len_be = U16::new(server_msg.len() as u16);
        let server_msg_len_bytes = server_msg_len_be.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        let data_len_be = U16::new(data.len() as u16);
        let data_len_bytes = data_len_be.as_bytes();
        mem[0] = server_msg_len_bytes[0];
        mem[1] = server_msg_len_bytes[1];
        mem[2] = data_len_bytes[0];
        mem[3] = data_len_bytes[1];
        mem[4] = status as u8;
        let mut varidata_ptr = Self::size_for_metadata(0usize).unwrap();
        mem_cpy!(mem, varidata_ptr, server_msg, data);
        debug_assert!(varidata_ptr == required_mem);
        Ok(())
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation fauilure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    #[allow(clippy::missing_panics_doc, reason = "infallible")] // size_for_metadata only called after length ck
    pub fn new_in<A: Allocator>(
        the_alloc: A,
        status: AcctStatus,
        server_msg: &[u8],
        data: &[u8],
    ) -> Result<Box<Self, A>, TacpErr> {
        unsafe {
            use core::alloc::Layout;
            use core::ptr::NonNull;
            use core::slice::from_raw_parts_mut as mk_slice;
            max!(u16, server_msg, data);
            let len = Self::size_for_metadata(server_msg.len() + data.len()).unwrap();
            let layout = Layout::array::<u8>(len)?;
            let ptr = the_alloc.allocate(layout)?.as_ptr().cast::<u8>();
            if let Err(e) = Self::initialize(mk_slice(ptr, len), status, server_msg, data) {
                the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                return Err(e);
            }
            let sliced = mk_slice(ptr, len);
            let typed_ptr = match Self::try_mut_from_bytes(sliced) {
                Ok(typed_ref) => core::ptr::from_mut(typed_ref),
                Err(e) => {
                    let e: TacpErr = e.into();
                    the_alloc.deallocate(NonNull::new_unchecked(ptr), layout);
                    return Err(e);
                }
            };
            Ok(Box::from_raw_in(typed_ptr, the_alloc))
        }
    }
    ///
    /// # Errors
    ///
    /// Will return Err on allocation fauilure or if a variable length component exceeeds the maximum encodable size for this packet.
    ///
    /// | Component | Max Size |
    /// |:---------:|:--------:|
    /// |  serv_msg |   65535  |
    /// |    data   |   65535  |
    pub fn new(status: AcctStatus, server_msg: &[u8], data: &[u8]) -> Result<Box<Self>, TacpErr> {
        Self::new_in(alloc::alloc::Global, status, server_msg, data)
    }

    #[allow(clippy::missing_panics_doc, reason = "infallible")] // debug_assert + we shouldn't be having layout issues
    /// Untype a boxed pointer to self, typically for obfuscation before sending.
    pub fn boxed_to_bytes<A: Allocator>(s: Box<Self, A>) -> Box<[u8], A> {
        use alloc::alloc::Layout;
        let real_len = s.len();
        let (ptr, allocator) = Box::into_raw_with_allocator(s);
        unsafe {
            debug_assert!(Layout::for_value_raw(ptr) == Layout::array::<u8>(real_len).unwrap());
        }
        unsafe {
            Box::from_raw_in(
                core::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), real_len),
                allocator,
            )
        }
    }
}

/// Accounting Status Field
#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Unaligned, TryFromBytes, IntoBytes, Immutable)]
pub enum AcctStatus {
    /// Accounting record received and processed successfully.
    SUCCESS = 0x1,
    /// Error processing accounting record.
    ERROR = 0x2,
}

/// Error type for all operations in this crate.
#[derive(Debug, Clone)]
pub enum TacpErr {
    /// Failed to parse a packet or field.
    ///
    /// Occurs when input data doesn't conform to the TACACS+ protocol specification.
    ParseError(&'static str),
    /// Memory allocation failed.
    ///
    /// Occurs during packet construction when the allocator cannot provide the requested memory.
    AllocError(&'static str),
    /// Buffer is too small for the operation.
    ///
    /// When using [`initialize()`] methods, the buffer must be large enough for the entire packet.
    BufferSize {
        /// Number of bytes required
        required_size: usize,
        /// Number of bytes provided
        given_size: usize,
    },
    /// Failed to convert packet bytes to UTF-8.
    ///
    /// TACACS+ fields are binary data and may not always be valid UTF-8.
    Utf8ConversionError(alloc::str::Utf8Error),
    /// A packet component exceeds its maximum encodable size.
    ///
    /// See individual packet documentation for size limits.
    OversizedComponent {
        /// Name of the oversized component
        component_name: &'static str,
        /// Actual size of the component
        component_size: usize,
        /// Maximum allowed size
        max_size: usize,
    },
    /// An argument exceeds the maximum length of 255 bytes.
    ///
    /// Authorization and accounting packets contain argument lists where each argument must be ≤255 bytes.
    OversizedArgument {
        /// Index of the oversized argument (0-based)
        arg_index: usize,
        /// Actual length of the argument
        arg_len: usize,
    },
}

impl core::fmt::Display for TacpErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParseError(d) =>
                write!(f, "parsing failure: {d}"),
            Self::AllocError(d) =>
                write!(f, "allocation failure: {d}"),
            Self::BufferSize { required_size, given_size } =>
                write!(f, "{required_size} bytes required for this operation but were provided only {given_size}"),
            Self::Utf8ConversionError(inner) =>
                inner.fmt(f),
            Self::OversizedComponent { component_name, component_size, max_size } =>
                write!(f, "component {component_name} too large to be encoded into this packet. {component_size} > {max_size}"),
            Self::OversizedArgument { arg_index, arg_len } =>
                write!(f, "argument #{arg_index} with length {arg_len} too large (>255)"),
        }
    }
}

impl core::error::Error for TacpErr {}

impl<S, D> From<zerocopy::error::AlignmentError<S, D>> for TacpErr {
    fn from(_: zerocopy::error::AlignmentError<S, D>) -> Self {
        // No really, we went out of our way to make things unaligned...
        Self::ParseError("Alignment error: this is should never happen")
    }
}

impl<S, D> From<zerocopy::error::SizeError<S, D>> for TacpErr {
    fn from(_value: zerocopy::error::SizeError<S, D>) -> Self {
        Self::ParseError("ZC size error")
    }
}

impl<S, D: ?Sized + TryFromBytes> From<TryCastError<S, D>> for TacpErr {
    fn from(value: TryCastError<S, D>) -> Self {
        match value {
            ConvertError::Alignment(_) => {
                Self::ParseError("Alignment error: this is should never happen")
            }
            ConvertError::Size(_) => Self::ParseError("ZC size error"),
            ConvertError::Validity(_) => Self::ParseError("ZC Failed to validate"),
        }
    }
}

impl From<core::alloc::LayoutError> for TacpErr {
    fn from(_: core::alloc::LayoutError) -> Self {
        Self::AllocError(
            "LayoutError: requested allocation would overflow isize (max_size_for_align [u8])",
        )
    }
}

impl From<core::alloc::AllocError> for TacpErr {
    fn from(_: core::alloc::AllocError) -> Self {
        Self::AllocError("AllocError: allocation failure")
    }
}

impl From<alloc::str::Utf8Error> for TacpErr {
    fn from(value: alloc::str::Utf8Error) -> Self {
        Self::Utf8ConversionError(value)
    }
}
