use argvalpair::ArgValPair;

pub mod obfuscation;
pub mod argvalpair;
//https://datatracker.ietf.org/doc/html/rfc8907
// All TACACS+ packets begin with the following 12-byte header.
//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |major  | minor  |                |                |                |
// |version| version|      type      |     seq_no     |   flags        |
// +----------------+----------------+----------------+----------------+
// |                                                                   |
// |                            session_id                             |
// +----------------+----------------+----------------+----------------+
// |                                                                   |
// |                              length                               |
// +----------------+----------------+----------------+----------------+
//
// The following general rules apply to all TACACS+ packet types:
// * To signal that any variable-length data fields are unused, the corresponding length values are set to zero. Such fields MUST be ignored, and treated as if not present.
// * The lengths of data and message fields in a packet are specified by their corresponding length field (and are not null terminated).
// * All length values are unsigned and in network byte order.

pub type Version = u8;

pub const MAJOR_VER: u8 = 0xc;
pub const MINOR_VER_DEFAULT: u8 = 0x0;
pub const MINOR_VER_ONE: u8 = 0x1;

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum PacketType {
    /// Authentication
    AUTHEN = 0x1,
    /// Authorization
    AUTHOR = 0x2,
    /// Accounting
    ACCT = 0x3,
}
impl TryFrom<u8> for PacketType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = u8::from_be(value);
        match value {
            1 => Ok(PacketType::AUTHEN),
            2 => Ok(PacketType::AUTHOR),
            3 => Ok(PacketType::ACCT),
            _ => Err("value out of range"),
        }
    }
}

/// This is the sequence number of the current packet.
/// The first packet in a session **MUST** have the sequence number 1, and each
/// subsequent packet will increment the sequence number by one.
/// TACACS+ clients only send packets containing odd sequence numbers,
/// and TACACS+ servers only send packets containing even sequence numbers.
///
///The sequence number must never wrap, i.e., if the sequence number 2^8 - 1 is ever reached, that session must terminate and be restarted with a sequence number of 1.
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
pub type SessionID = u32;

/// The total length of the packet body (not including the header).
/// Implementations **MUST** allow control over maximum packet sizes
/// accepted by TACACS+ Servers. The recommended maximum packet size
/// is 2^12
pub type PacketLength = u32;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketHeader {
    pub version: Version,
    pub ty: PacketType,
    pub seq_no: SeqNo,
    pub flags: Flags,
    pub session_id: SessionID,
    pub length: PacketLength,
}
impl TryFrom<&[u8;12]> for PacketHeader {
    type Error = String;
    fn try_from(value: &[u8;12]) -> Result<Self, Self::Error> {
        let ver = u8::from_be(value[0]);
        if ver != (MAJOR_VER << 4 | MINOR_VER_DEFAULT) && ver != (MAJOR_VER << 4 | MINOR_VER_ONE) {
            return Err(format!("version fail {:x}", ver));
        }
        let mut temp32 = [0u8;4];
        temp32.copy_from_slice(&value[4..8]);
        let session_id = SessionID::from_be_bytes(temp32);
        temp32.copy_from_slice(&value[8..12]);
        let length = PacketLength::from_be_bytes(temp32);
        Ok(Self {
            version: value[0],
            ty: PacketType::try_from(value[1])?,
            seq_no: u8::from_be(value[2]),
            flags: u8::from_be(value[3]),
            session_id: session_id,
            length: length,
        })
    }
}
impl PacketHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(12);
        res.push(self.version);
        res.push(self.ty as u8);
        res.push(self.seq_no);
        res.push(self.flags);
        let mut swap = self.session_id;
        res.push(((swap >> 24) & 0xff) as u8);
        res.push(((swap >> 16) & 0xff) as u8);
        res.push(((swap >> 08) & 0xff) as u8);
        res.push(((swap >> 00) & 0xff) as u8);
        swap = self.length;
        res.push(((swap >> 24) & 0xff) as u8);
        res.push(((swap >> 16) & 0xff) as u8);
        res.push(((swap >> 08) & 0xff) as u8);
        res.push(((swap >> 00) & 0xff) as u8);
        res
    }
}

// Authentication START Packet Body
// 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |    action      |    priv_lvl    |  authen_type   | authen_service |
// +----------------+----------------+----------------+----------------+
// |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
// +----------------+----------------+----------------+----------------+
// |    user ...                                                       |
// +----------------+----------------+----------------+----------------+
// |    port ...                                                       |
// +----------------+----------------+----------------+----------------+
// |    rem_addr ...                                                   |
// +----------------+----------------+----------------+----------------+
// |    data...                                                        |
// +----------------+----------------+----------------+----------------+
//
#[repr(u8)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum AuthenStartAction {
    LOGIN    = 0x1,
    CHPASS   = 0x2,
    SENDAUTH = 0x4,
}

impl TryFrom<u8> for AuthenStartAction {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x1 => Ok(AuthenStartAction::LOGIN),
            0x2 => Ok(AuthenStartAction::CHPASS),
            0x4 => Ok(AuthenStartAction::SENDAUTH),
            _ => Err("Out of range")
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum AuthenType {
    ASCII = 0x1,
    PAP = 0x2,
    CHAP = 0x3,
    MSCHAP_V1 = 0x5,
    MSCHAP_V2 = 0x6,
}
impl TryFrom<u8> for AuthenType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x1 => Ok(AuthenType::ASCII),
            0x2 => Ok(AuthenType::PAP),
            0x3 => Ok(AuthenType::CHAP),
            0x5 => Ok(AuthenType::MSCHAP_V1),
            0x6 => Ok(AuthenType::MSCHAP_V2),
            _   => Err("Out of range"),
        }
    }
}
pub type PrivLevel = u8;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
#[allow(non_camel_case_types)]
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
impl TryFrom<u8> for AuthenService {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(AuthenService::NONE),
            0x1 => Ok(AuthenService::LOGIN),
            0x2 => Ok(AuthenService::ENABLE),
            0x3 => Ok(AuthenService::PPP),
            0x5 => Ok(AuthenService::PT),
            0x6 => Ok(AuthenService::RCMD),
            0x7 => Ok(AuthenService::X25),
            0x8 => Ok(AuthenService::NASI),
            0x9 => Ok(AuthenService::FWPROXY),
            _   => Err("Out of range"),
        }
    }
}

pub type AuthenStartVariDataLen = u8;

#[derive(Debug, Clone)]
pub struct AuthenStartPacket {
    pub action: AuthenStartAction,
    pub priv_level: PrivLevel,
    pub authen_type: AuthenType,
    pub authen_svc: AuthenService,
    pub user: Vec<u8>,
    pub port: Vec<u8>,
    pub rem_addr: Vec<u8>,
    pub data: Vec<u8>,
    pub len: usize,
}

impl TryFrom<&[u8]> for AuthenStartPacket {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 7 {
            return Err("Packet is impossibly short");
        }
        let user_len = value[4] as usize;
        let port_len = value[5] as usize;
        let rem_addr_len = value[6] as usize;
        let data_len = value[7] as usize;
        if value.len() < 8 + user_len + port_len + rem_addr_len + data_len {
            return  Err("Packet length does not match parsed lengths from header. Key mismatch likey");
        }
        let user_range = 8..8+user_len;
        let port_range = user_range.end..(user_range.end + port_len);
        let rem_addr_range = port_range.end..(port_range.end + rem_addr_len);
        let data_range = rem_addr_range.end..(rem_addr_range.end + data_len);
        Ok(
            Self {
                action: AuthenStartAction::try_from(value[0])?,
                priv_level: value[1],
                authen_type: AuthenType::try_from(value[2])?,
                authen_svc: AuthenService::try_from(value[3])?,
                user: Vec::from(&value[user_range]),
                port: Vec::from(&value[port_range]),
                rem_addr: Vec::from(&value[rem_addr_range]),
                data: Vec::from(&value[data_range]),
                len: 8+user_len+port_len+rem_addr_len+data_len
            }
        )
    }
}


// Authentication REPLY Packet Body
/// 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |     status     |      flags     |        server_msg_len           |
/// +----------------+----------------+----------------+----------------+
/// |           data_len              |        server_msg ...
/// +----------------+----------------+----------------+----------------+
/// |           data ...
/// +----------------+----------------+

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

/// flags
/// Bitmapped flags that modify the action to be taken
/// Only one flag is defined currently.
pub const REPLY_FLAG_NOECHO: u8 = 1;

#[derive(Debug, Clone)]
pub struct AuthenReplyPacket {
    pub status: AuthenReplyStatus,
    pub flags: u8,
    pub serv_msg: Vec<u8>,
    pub data: Vec<u8>,
}
impl AuthenReplyPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(self.len());
        res.push(self.status as u8);
        res.push(self.flags);
        let mut len = self.serv_msg.len() as u16;
        res.push((len & 0xff) as u8);
        res.push(((len >> 8) & 0xff) as u8);
        len = self.data.len() as u16;
        res.push((len & 0xff) as u8);
        res.push(((len >> 8) & 0xff) as u8);
        res.extend(self.serv_msg.iter());
        res.extend(self.data.iter());
        res
    }
    pub fn len(&self) -> usize {
        6 + self.serv_msg.len() + self.data.len()
    }
}

/// Authentication CONTINUE Packet Body
/// This packet is sent from the client to the server following the receipt of a REPLY packet.
///
/// 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |          user_msg len           |            data_len             |
/// +----------------+----------------+----------------+----------------+
/// |     flags      |  user_msg ...
/// +----------------+----------------+----------------+----------------+
/// |    data ...
/// +----------------+

#[derive(Debug, Clone)]
pub struct AuthenContinuePacket {
    pub abort: bool,
    pub user_msg: Vec<u8>,
    pub data: Vec<u8>
}
impl TryFrom<&[u8]> for AuthenContinuePacket {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let user_msg_len = (value[0] as usize) << 8 | value[1] as usize;
        let data_len = (value[2] as usize) << 8 | value[3] as usize;
        let flags = value[4];
        let abort = flags & 0x1 == 1;
        let mut user_msg = vec!(0; user_msg_len);
        user_msg.copy_from_slice(&value[5..(5+user_msg_len)]);
        let mut data = vec!(0; data_len);
        data.copy_from_slice(&value[(5+user_msg_len)..(5+user_msg_len+data_len)]);
        if value.len() != 5+user_msg_len+data_len {
            return Err(format!("AuthenContinuePacket length fields does not match packet length: {:x} vs {:x}", value.len(), 5+user_msg_len+data_len));
        }
        Ok(
            Self {
                abort,
                user_msg,
                data,
            }
        )
    }
}
impl AuthenContinuePacket {
    pub fn len(&self) -> usize {
        5 + self.user_msg.len() + self.data.len()
    }
}

/// The Authroization REQUEST Packet Body
///   1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |  authen_method |    priv_lvl    |  authen_type   | authen_service |
/// +----------------+----------------+----------------+----------------+
/// |    user_len    |    port_len    |  rem_addr_len  |    arg_cnt     |
/// +----------------+----------------+----------------+----------------+
/// |   arg_1_len    |   arg_2_len    |      ...       |   arg_N_len    |
/// +----------------+----------------+----------------+----------------+
/// |   user ...
/// +----------------+----------------+----------------+----------------+
/// |   port ...
/// +----------------+----------------+----------------+----------------+
/// |   rem_addr ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_1 ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_2 ...
/// +----------------+----------------+----------------+----------------+
/// |   ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_N ...
/// +----------------+----------------+----------------+----------------+


/// This field allows the client to indicate the authentication method used to acquire user information.
/// As this information is not always subject to verification, it MUST NOT be used in policy evaluation.
/// LINE refers to a fixed password associated with the terminal line used to gain access.
/// LOCAL is a client local user database. ENABLE is a command that authenticates in order to grant new privileges.
/// TACACSPLUS is, of course, TACACS+. GUEST is an unqualified guest authentication.
/// RADIUS is the RADIUS authentication protocol. RCMD refers to authentication provided via the R-command protocols from Berkeley Unix.
/// KRB5 [RFC4120] and KRB4 [KRB4] are Kerberos versions 5 and 4.
/// As mentioned above, this field is used by the client to indicate how it performed the authentication.
/// One of the options (TAC_PLUS_AUTHEN_METH_TACACSPLUS := 0x06) is TACACS+ itself, and so the detail of how the client performed this option is given in "Authentication" (Section 5).
/// For all other options, such as KRB and RADIUS, the TACACS+ protocol did not play any part in the authentication phase;
/// as those interactions were not conducted using the TACACS+ protocol, they will not be documented here.
/// For implementers of clients who need details of the other protocols, please refer to the respective Kerberos [RFC4120] and RADIUS [RFC3579] RFCs.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
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

impl TryFrom<u8> for AuthorMethod {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => AuthorMethod::NOT_SET,
            0x01 => AuthorMethod::NONE,
            0x02 => AuthorMethod::KRB5,
            0x03 => AuthorMethod::LINE,
            0x04 => AuthorMethod::ENABLE,
            0x05 => AuthorMethod::LOCAL,
            0x06 => AuthorMethod::TACACSPLUS,
            0x08 => AuthorMethod::GUEST,
            0x10 => AuthorMethod::RADIUS,
            0x11 => AuthorMethod::KRB4,
            0x20 => AuthorMethod::RCMD,
            _ => { return Err("Value out of range") }
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthorRequestPacket {
    pub method: AuthorMethod,
    pub priv_level: PrivLevel,
    pub authen_type: AuthenType,
    pub authen_svc: AuthenService,
    pub user: Vec<u8>,
    pub port: Vec<u8>,
    pub rem_addr: Vec<u8>,
    pub args: Vec<ArgValPair>,
    pub len: usize,
}

impl TryFrom<&[u8]> for AuthorRequestPacket {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        fn bounds_check(pkt_size: usize, ptr: usize, file: &'static str, line: u32) -> Result<usize, &'static str> {
            if ptr > pkt_size {
                println!("oob at {file}:{line}");
                Err("out of bounds")
            }
            else {
                Ok(ptr)
            }
        }
        let pkt_size = value.len();
        if pkt_size < 8 {
            return Err("Packet is impossibly small");
        }
        let method = AuthorMethod::try_from(value[0])?;
        let priv_level = value[1];
        let authen_type = AuthenType::try_from(value[2])?;
        let authen_svc = AuthenService::try_from(value[3])?;
        let user_len = value[4] as usize;
        let port_len = value[5] as usize;
        let rem_addr_len = value[6] as usize;
        let arg_cnt = value[7] as usize;
        if pkt_size < 8+arg_cnt {
            return Err("packet too small for arguments");
        }
        let mut args = Vec::with_capacity(arg_cnt);
        let mut arg_lens = Vec::with_capacity(arg_cnt);
        let mut ptr = 8;
        while ptr < 8 + arg_cnt {
            arg_lens.push(value[bounds_check(pkt_size, ptr, file!(), line!())?] as usize);
            ptr += 1;
        }
        ptr = bounds_check(pkt_size, ptr+user_len, file!(), line!())?;
        let user = Vec::from(&value[(ptr-user_len)..ptr]);
        ptr = bounds_check(pkt_size, ptr+port_len, file!(), line!())?;
        let port = Vec::from(&value[(ptr-user_len)..ptr]);
        ptr = bounds_check(pkt_size, ptr+rem_addr_len, file!(), line!())?;
        let rem_addr = Vec::from(&value[(ptr-rem_addr_len)..ptr]);

        for arg_counter in 0..arg_lens.len() {
            let this_arg_len = arg_lens[arg_counter];
            ptr = bounds_check(pkt_size, ptr+this_arg_len, file!(), line!())?;
            let mut temp = vec!(0; this_arg_len);
            temp.copy_from_slice(&value[(ptr-this_arg_len)..ptr]);
            args.push(ArgValPair::try_from(String::from_utf8_lossy(&temp).into_owned())?);
        }

        Ok(AuthorRequestPacket {
            method,
            priv_level,
            authen_type,
            authen_svc,
            user,
            port,
            rem_addr,
            args,
            len: ptr as usize,
        })
    }
}

/// The Authorization REPLY Packet Body
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |    status      |     arg_cnt    |         server_msg len          |
/// +----------------+----------------+----------------+----------------+
/// +            data_len             |    arg_1_len   |    arg_2_len   |
/// +----------------+----------------+----------------+----------------+
/// |      ...       |   arg_N_len    |         server_msg ...
/// +----------------+----------------+----------------+----------------+
/// |   data ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_1 ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_2 ...
/// +----------------+----------------+----------------+----------------+
/// |   ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_N ...
/// +----------------+----------------+----------------+----------------+
#[derive(Debug, Clone)]
pub struct AuthorReplyPacket {
    pub status: AuthorStatus,
    pub args: Vec<ArgValPair>,
    pub server_msg: Vec<u8>,
    pub data: Vec<u8>,
}

impl AuthorReplyPacket {
    pub fn encode(&self) -> Vec<u8> {
        let args = self.args.iter().map(|c|c.to_bytes()).collect::<Vec<_>>();
        let mut ret = Vec::with_capacity(self.len());
        ret.push(self.status as u8);
        ret.push(self.args.len() as u8);
        let server_msg_len = self.server_msg.len() as u16;
        ret.push(((server_msg_len >> 8 )& 0xff) as u8); // endian
        ret.push((server_msg_len & 0xff) as u8);
        let data_len = self.data.len();
        ret.push(((data_len >> 8 )& 0xff) as u8); // endian
        ret.push((data_len & 0xff) as u8);
        for arg in args.iter() {
            ret.push(arg.len() as u8);
        }
        ret.extend(self.server_msg.iter());
        ret.extend(self.data.iter());
        for arg in args.iter() {
            ret.extend(arg.iter());
        }
        ret
    }
    pub fn len(&self) -> usize {
        6 + self.args.len() + self.server_msg.len() + self.data.len() + self.args.iter().map(|arg|arg.to_bytes().len()).sum::<usize>()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AuthorStatus {
    PASS_ADD = 0x1,
    PASS_REPL = 0x2,
    FAIL = 0x10,
    ERROR = 0x11,
    FOLLOW = 0x21,
}

/// The Account REQUEST Packet Body
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |      flags     |  authen_method |    priv_lvl    |  authen_type   |
/// +----------------+----------------+----------------+----------------+
/// | authen_service |    user_len    |    port_len    |  rem_addr_len  |
/// +----------------+----------------+----------------+----------------+
/// |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
/// +----------------+----------------+----------------+----------------+
/// |   arg_N_len    |    user ...
/// +----------------+----------------+----------------+----------------+
/// |   port ...
/// +----------------+----------------+----------------+----------------+
/// |   rem_addr ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_1 ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_2 ...
/// +----------------+----------------+----------------+----------------+
/// |   ...
/// +----------------+----------------+----------------+----------------+
/// |   arg_N ...
/// +----------------+----------------+----------------+----------------+
/// 
/// NOTE: This is basically the same as the Authorization START Packet body,
///     We take advantage of this by parsing it as such, then adding the flags
/// 
#[derive(Debug, Clone)]
pub struct AcctRequestPacket {
    pub flags: AcctFlags,
    pub method: AuthorMethod,
    pub priv_level: PrivLevel,
    pub authen_type: AuthenType,
    pub authen_svc: AuthenService,
    pub user: Vec<u8>,
    pub port: Vec<u8>,
    pub rem_addr: Vec<u8>,
    pub args: Vec<ArgValPair>,
    pub len: usize,
}
#[derive(Debug, Clone, Copy)]
pub enum AcctFlags {
    RecordStart,
    RecordStop,
    WatchdogNoUpdate,
    WatchdogUpdate,
}
impl TryFrom<u8> for AcctFlags {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0xE {
            0x2 => Ok(Self::RecordStart),
            0x4 => Ok(Self::RecordStop),
            0x8 => Ok(Self::WatchdogNoUpdate),
            0xA => Ok(Self::WatchdogUpdate),
            _ => Err("Invalid flags"),
        }
    }
}

impl TryFrom<&[u8]> for AcctRequestPacket {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 9 {
            return Err("Packet is impossibly small");
        }
        let flags = AcctFlags::try_from(value[0])?;
        Ok(
            Self::from((flags, AuthorRequestPacket::try_from(&value[1..])?))
        )
    }
}
impl From<(AcctFlags, AuthorRequestPacket)> for AcctRequestPacket {
    fn from(value: (AcctFlags, AuthorRequestPacket)) -> Self {
        Self {
            flags: value.0,
            method: value.1.method,
            priv_level: value.1.priv_level,
            authen_type: value.1.authen_type,
            authen_svc: value.1.authen_svc,
            user: value.1.user,
            port: value.1.port,
            rem_addr: value.1.rem_addr,
            args: value.1.args,
            len: value.1.len + 1, // + 1 for flags
        }
    }
}

/// The Accounting REPLY Packet Body
///  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
/// +----------------+----------------+----------------+----------------+
/// |         server_msg len          |            data_len             |
/// +----------------+----------------+----------------+----------------+
/// |     status     |         server_msg ...
/// +----------------+----------------+----------------+----------------+
/// |     data ...
/// +----------------+
#[derive(Debug, Clone)]
pub struct AcctReplyPacket {
    pub status: AcctStatus,
    pub server_msg: Vec<u8>,
    pub data: Vec<u8>,
}

impl AcctReplyPacket {
    pub fn encode(&self) -> Vec<u8> {
        let server_msg_len = self.server_msg.len();
        let data_len = self.server_msg.len();
        let mut ret = Vec::with_capacity(5 + server_msg_len + data_len);
        ret.push(((server_msg_len >> 8) & 0xff) as u8);
        ret.push((server_msg_len & 0xff) as u8);
        ret.push(((data_len >> 8) & 0xff) as u8);
        ret.push((data_len & 0xff) as u8);
        ret.push(self.status as u8);
        ret.extend(self.server_msg.iter());
        ret.extend(self.data.iter());
        ret
    }
    pub fn len(&self) -> usize {
        5 + self.server_msg.len() + self.data.len()
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AcctStatus {
    SUCCESS = 0x1,
    ERROR = 0x2,
}