use fnv::FnvHashMap;
use crate::SString;
use std::{net::IpAddr, path::PathBuf};
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

#[derive(Debug, Clone, Default)]
/// Describes the entire administrative policy of the server
pub(crate) struct Policy {
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
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value.to_lowercase();
        Ok(match value.as_str() {
            "default" => Self::Default,
            "defer" => Self::Defer,
            "deny" => Self::Deny,
            "permit" | "allow" => Self::Allow,
            _ => { return Err(()); }
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
    type Error= ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("tcp") {
            return Ok(Self::TCP);
        }
        else if value.eq_ignore_ascii_case("udp") {
            return Ok(Self::UDP);
        }
        else {
            todo!();
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
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some((u_or_g, target)) = value.split_once(' ') {
            if u_or_g.eq_ignore_ascii_case("group") {
                return Ok(AuthenTarget::Group(target.to_owned()))
            }
            else if u_or_g.eq_ignore_ascii_case("user") {
                return Ok(AuthenTarget::User(target.to_owned()))
            }
            else {
                return Err(());
            }
        }
        todo!()
    }
}