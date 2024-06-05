use std::{error::Error, net::IpAddr};
use yaml::{StrictYaml, StrictYamlLoader};
use crate::SString;
use tracing::{error, info, instrument};
use regex::Regex;
use super::*;

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
fn parse_policy_groups_section(policy: &mut Policy, section: &StrictYaml) {
    let section = section.as_hash().unwrap();
    for (groupname, group_settings) in section {
        let groupname = groupname.as_str().unwrap();
        if group_settings.as_hash().is_none() {continue;}
        let group_settings = group_settings.as_hash().unwrap();
        let mut author_policy: Option<AuthorPolicy> = None;
        let mut acct_policy: Option<AcctPolicy> = None;
        let mut authen_policy: Option<AuthenPolicy> = None;
        for (setting, val) in group_settings {
            match setting.as_str().unwrap() {
                "author_policy" => {
                    author_policy = Some(parse_author_policy(val.as_str().unwrap()));
                },
                "acct_policy" => {
                    acct_policy = Some(parse_acct_policy(val));
                }
                "authen_policy" => {
                    authen_policy = Some(parse_authen_policy(val));
                }
                _ => error!("Unsupported group setting \"{val:?}\""),
            }
        }
        policy.groups.insert(groupname.to_owned(), GroupsPolicy { author_policy, acct_policy, authen_policy });
    }
}

fn parse_author_policy(policy: &str) -> AuthorPolicy {
    let mut ret = AuthorPolicy { default_action: ACLActions::Deny, list: Vec::new() };
    for line in policy.lines() {
        match line.split_once(' ') {
            Some((action, val)) => {
                let action = action.trim();
                let val = val.trim();
                let action = ACLActions::try_from(action).unwrap();
                if action == ACLActions::Default {
                        let default_action = ACLActions::try_from(val).unwrap_or(ACLActions::Deny);
                        assert_ne!(default_action, ACLActions::Default);
                        ret.default_action = default_action;
                        continue;
                }
                let re = Regex::new(val).unwrap();
                ret.list.push((action, re));
            },
            None => todo!(),
        }
    }
    ret
}

fn parse_acct_policy(policy: &StrictYaml) -> AcctPolicy {
    let policy = policy.as_hash().unwrap();
    for (target, value) in policy {
        if let Some(setting) = target.as_str() {
            if setting == "file" {
                return AcctPolicy(AcctTarget::File(value.as_str().unwrap().into()));
            }
            if setting == "syslog" {
                let mut ip = None;
                let mut port = None;
                let mut proto = None;
                let syslog_settings = value.as_hash().unwrap();
                for (syslog_setting, syslog_val) in syslog_settings {
                    if let Some(syslog_setting) = syslog_setting.as_str() {
                        let syslog_val = syslog_val.as_str().unwrap();
                        match syslog_setting {
                            "port" => {
                                port = Some(syslog_val.parse::<u16>().unwrap());
                            },
                            "ip" | "host" => {
                                ip = Some(syslog_val.parse::<IpAddr>().unwrap());
                            },
                            "proto" | "protocol" => {
                                proto = Some(SyslogTransport::try_from(syslog_val).unwrap());
                            },
                            _ => {
                                todo!()
                            }
                        }
                    }
                    else {
                        todo!()
                    }
                }
                if ip.is_none() {
                    todo!();
                }
                return AcctPolicy(AcctTarget::Syslog((ip.unwrap(), port.unwrap_or(514), proto.unwrap_or(SyslogTransport::UDP))));
            }
        }
        else {todo!()}
    }
    todo!();
}

fn parse_authen_policy(policy: &StrictYaml) -> AuthenPolicy {
    let policy = policy.as_hash().unwrap();
    let mut ty = None;
    let mut list = None;
    for (setting, val) in policy {
        let setting = setting.as_str().unwrap();
        match setting {
            "type" => {
                ty = Some(val.as_str().unwrap());
            },
            "list" => {
                list = Some(val.as_str().unwrap());
            },
            _ => {todo!();}
        }
    }
    if ty.is_some() && list.is_some() {
        let ty = ty.unwrap();
        let list = list.unwrap();
        if ty.eq_ignore_ascii_case("local") {
            let mut default_action = ACLActions::Deny;
            let mut acl = Vec::new();
            for line in list.lines() {
                match line.split_once(' ') {
                    Some((action, user)) => {
                        let action = ACLActions::try_from(action).unwrap();
                        if action == ACLActions::Default {
                            default_action = ACLActions::try_from(user).unwrap_or(ACLActions::Deny);
                            assert_ne!(default_action, ACLActions::Default);
                            continue;
                        }
                        acl.push((action, user.trim().to_owned()));
                    },
                    None => todo!(),
                }
            }
            return AuthenPolicy(AuthenType::Local((default_action, acl)));
        }
        else {
            todo!()
        }
    }
    else {
        todo!()
    }
}