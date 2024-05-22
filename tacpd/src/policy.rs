use std::{error::Error, net::IpAddr};
use yaml::{StrictYaml, StrictYamlLoader};
use fnv::FnvHashMap;
use crate::SString;
use tracing::{error, info, instrument};

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

#[derive(Debug, Clone, Default)]
/// Describes the entire administrative policy of the server
pub(crate) struct Policy {
    pub default_key: Option<SString>,
    pub clients: FnvHashMap<IpAddr, ClientPolicy>,
    pub users: FnvHashMap<String, UserPolicy>,
    pub allow_unconfigured: bool,
}

#[instrument]
pub(crate) fn load() -> Result<Policy, Box<dyn Error>>{
    let mut ret: Policy = Default::default();
    let mut policy_file = StrictYamlLoader::load_from_str(&std::fs::read_to_string("policy.yaml")?)?;
    if policy_file.len() != 1 {
        panic!(); // fixme
    }
    let policy_file = policy_file.pop().unwrap();
    let root = policy_file.as_hash().unwrap();
    for (section, val) in root {
        match section.as_str().unwrap() {
            "global" => parse_policy_global_section(&mut ret, val),
            "clients" => parse_policy_clients_section(&mut ret, val),
            "users" => parse_policy_users_section(&mut ret, val),
            "groups" => parse_policy_groups_section(&mut ret, val),
            _ => { panic!() }
        }
    }
    info!(policy = ?ret, "Final Parsed Policy");
    return Ok(ret);
}

#[instrument]
fn parse_policy_global_section(policy: &mut Policy, section: &StrictYaml) {
    let section = section.as_hash().unwrap();
    for (setting, val) in section {
        let setting = setting.as_str().unwrap();
        let val = val.as_str().unwrap();
        match setting {
            "default-key" => {
                policy.default_key = Some(SString(val.to_owned()));
            }
            "block-unconfigured" => {
                policy.allow_unconfigured = val.eq_ignore_ascii_case("false");
            }
            _ => {
                error!("unknown setting \"{setting}\" in global section");
            }
        }
    }
}

#[instrument]
fn parse_policy_clients_section(policy: &mut Policy, section: &StrictYaml) {
    let section = section.as_hash().unwrap();
    for (setting, val) in section {
        let setting = setting.as_str().unwrap();
        let val = val.as_hash().unwrap();
        if let Ok(client_ip) = setting.parse::<IpAddr>() {
            let mut client_policy = ClientPolicy { key: None, groups: None};
            for (client_setting, client_val) in val {
                let client_setting = client_setting.as_str().unwrap();
                let client_val = client_val.as_str().unwrap();
                match client_setting {
                    "key" => {
                        client_policy.key = Some(SString(client_val.to_owned()));
                    }
                    "groups" => {
                        client_policy.groups = Some(client_val.split_ascii_whitespace().map(str::to_ascii_lowercase).collect());
                    }
                    _ => {
                        error!("Unknown client policy setting \"{client_setting}\"");
                    }
                }
            }
            policy.clients.insert(client_ip, client_policy);
        }
        else {
            error!("Failed to parse client policy: \"{setting}\" not an IP Address");
        }
    }
}

#[instrument]
fn parse_policy_users_section(policy: &mut Policy, section: &StrictYaml) {
    let section = section.as_hash().unwrap();
    for (username, user_settings) in section {
        let username = username.as_str().unwrap();
        let user_settings = user_settings.as_hash().unwrap();
        for (setting, val) in user_settings {
            let mut user_policy = UserPolicy { password: None, groups: None };
            let setting = setting.as_str().unwrap();
            let val = val.as_str().unwrap();
            match setting {
                "password" => {
                    user_policy.password = Some(SString(val.to_owned()));
                },
                "groups" => {
                    user_policy.groups = Some(val.split_ascii_whitespace().map(str::to_ascii_lowercase).collect());
                },
                _ => {
                    error!("Unknwon user policy setting \"{setting}\"");
                }
            }
            policy.users.insert(username.to_owned(), user_policy);
        }
    }
}

#[instrument]
fn parse_policy_groups_section(_policy: &mut Policy, _section: &StrictYaml) {
    error!("groups policy not implemented");
}