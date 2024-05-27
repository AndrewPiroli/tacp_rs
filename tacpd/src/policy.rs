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
pub(crate) enum AuthorActions {
    Default,
    Defer,
    Deny,
    Allow,
}
impl TryFrom<&str> for AuthorActions {
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
    default_action: AuthorActions,
    list: Vec<(AuthorActions, Regex)>,
}

#[derive(Debug, Clone)]
enum AcctTarget {
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct AcctPolicy(AcctTarget);