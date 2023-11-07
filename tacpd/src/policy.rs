use std::{error::Error, net::IpAddr};
use toml::Table;
use fnv::FnvHashMap;
use crate::SString;

#[derive(Debug, Clone, Default)]
pub(crate) struct ClientPolicy {
    pub key: Option<SString>,
}

#[derive(Debug, Clone)]
pub(crate) struct UserPolicy {
    pub password: Option<SString>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Policy {
    pub default_key: Option<SString>,
    pub clients: FnvHashMap<IpAddr, ClientPolicy>,
    pub users: FnvHashMap<String, UserPolicy>,
    pub allow_unconfigured: bool,
}

pub(crate) fn load() -> Result<Policy, Box<dyn Error>>{
    let mut ret: Policy = Default::default();
    let policy_file = std::fs::read_to_string("policy.toml")?.parse::<Table>()?;
    for (section, val) in policy_file {
        match section.as_str() {
            "global" => {
                if let Some(gk) = val.get("default_key")
                    && gk.is_str()
                {
                    ret.default_key = Some(SString(gk.as_str().unwrap().into()));
                }
                if let Some(allow_unconfig_client) = val.get("block_unconfigured_client")
                    && allow_unconfig_client.is_bool()
                {
                    ret.allow_unconfigured = allow_unconfig_client.as_bool().unwrap();
                }
            },
            "client" => {
                if val.is_table() {
                    for (maybe_ip, client_policy) in val.as_table().unwrap() {
                        if let Ok(ip) = maybe_ip.parse::<IpAddr>() &&
                            client_policy.is_table()
                        {
                            ret.clients.insert(ip, ClientPolicy { key: None} );
                            if let Some(client_key) = client_policy.as_table().unwrap().get("key") &&
                            client_key.is_str()
                            {
                                ret.clients.get_mut(&ip).unwrap().key = Some(SString(client_key.as_str().unwrap().into()));
                            }
                        }
                        else {
                            // log error
                            continue;
                        }
                    }
                }
                else { todo!() }
            },
            "user" => {
                if val.is_table() {
                    for (username, user_policy) in val.as_table().unwrap() {
                        if user_policy.is_table() {
                            ret.users.insert(username.clone(), UserPolicy { password: None });
                            if let Some(user_pass) = user_policy.as_table().unwrap().get("password")
                                && user_pass.is_str()
                                {
                                    ret.users.get_mut(username).unwrap().password = Some(SString(user_pass.as_str().unwrap().into()));
                                }
                        }
                        else { /* log error */ continue; }
                    }
                }
            }
            _ => {},
        }
    }
    dbg!(&ret);
    return Ok(ret);
}