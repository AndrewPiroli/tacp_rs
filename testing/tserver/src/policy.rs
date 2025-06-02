use fnv::FnvHashMap;
use crate::{TacpServerError, SString};
use std::{net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs}, path::PathBuf, str::FromStr};
use regex::Regex;

pub(crate) mod enforce;
pub(crate) mod parse;

#[derive(Debug, Clone, Default)]
/// Describes the administrative policy of a specific client
pub(crate) struct ClientPolicy {
    pub key: Option<SString>,
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
/// Describes the administrative policy of a specific user account
pub(crate) struct UserPolicy {
    pub password: Option<SString>,
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupsPolicy {
    pub author_policy: Option<AuthorPolicy>,
    pub acct_policy: Option<AcctPolicy>,
    pub authen_policy: Option<AuthenPolicy>,
}

#[derive(Debug, Clone)]
/// The address and port the server will listen to on startup
/// Defaults to any v4 address and TCP port 49
pub(crate) struct BindInfo(pub IpAddr, pub u16);
impl Default for BindInfo {
    fn default() -> Self {
        Self(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 49)
    }
}
impl ToSocketAddrs for BindInfo {
    type Iter= std::option::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let (ip, port) = (self.0, self.1);
        match ip {
            IpAddr::V4(ref a) => (*a, port).to_socket_addrs(),
            IpAddr::V6(ref a) => (*a, port).to_socket_addrs(),
        }
    }
}


#[derive(Debug, Clone, Default)]
/// Describes the entire administrative policy of the server
pub(crate) struct Policy {
    pub bind_info: BindInfo,
    pub default_key: Option<SString>,
    pub clients: FnvHashMap<IpAddr, ClientPolicy>,
    pub users: FnvHashMap<String, UserPolicy>,
    pub groups: FnvHashMap<String, GroupsPolicy>,
    pub allow_unconfigured: bool,
}



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ACLActions {
    Default,
    Defer,
    Deny,
    Allow,
}
impl TryFrom<&str> for ACLActions {
    type Error = TacpServerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.to_lowercase();
        Ok(match value.as_str() {
            "default" => Self::Default,
            "defer" => Self::Defer,
            "deny" => Self::Deny,
            "permit" | "allow" => Self::Allow,
            _ => { return Err(TacpServerError::ParseError(format!("ACLAction should be one of default, defer, deny, permit, allow. Got: {value}"))); }
        })
    }
}


#[derive(Debug, Clone)]
pub struct AuthorPolicy {
    default_action: Option<ACLActions>,
    list: Vec<(ACLActions, Regex)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyslogTransport {
    TCP,
    UDP,
}

impl TryFrom<&str> for SyslogTransport {
    type Error = TacpServerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("tcp") {
            return Ok(Self::TCP);
        }
        else if value.eq_ignore_ascii_case("udp") {
            return Ok(Self::UDP);
        }
        else {
            return Err(TacpServerError::ParseError(format!("SyslogTransport must be tcp or udp. Got: {value}")))
        }
    }
}

#[derive(Debug, Clone)]
enum AcctTarget {
    File(PathBuf),
    Syslog((IpAddr, u16, SyslogTransport)),
}

#[derive(Debug, Clone)]
pub struct AcctPolicy(AcctTarget);

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenType {
    Local((ACLActions, Vec<(ACLActions, AuthenTarget)>)),
}

#[derive(Debug, Clone)]
pub struct AuthenPolicy(AuthenType);


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenTarget {
    User(String),
    Group(String)
}

impl TryFrom<&str> for AuthenTarget {
    type Error = TacpServerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some((u_or_g, target)) = value.split_once(' ') {
            if u_or_g.eq_ignore_ascii_case("group") {
                return Ok(AuthenTarget::Group(target.to_owned()))
            }
            else if u_or_g.eq_ignore_ascii_case("user") {
                return Ok(AuthenTarget::User(target.to_owned()))
            }
            else {
                return Err(TacpServerError::ParseError(format!("AuthenTarget must start with group or user. Got {u_or_g}")));
            }
        }
        Err(TacpServerError::ParseError("Malformed AuthenTarget. No separator.".to_owned()))
    }
}