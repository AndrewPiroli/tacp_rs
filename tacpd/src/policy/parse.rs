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
    if policy_file.is_empty() {
        error!("Policy parsed ok but is empty.");
        let ret = Box::new(TacpErr::ParseError("Policy Parsed ok but is empty".to_owned()));
        return Err(ret);
    }
    if policy_file.len() != 1 {
        error!("Policy parsed ok but multiple documents resulted. Only the first will be considered");
    }
    let policy_file = policy_file.pop().unwrap();
    let root = policy_file.as_hash().unwrap();
    for (section, val) in root {
        let section = match section.as_str() {
            Some(s) => s,
            None => {
                error!("Policy section parsing: root section should be a str but is not");
                continue;
            }
        };
        match section {
            "global" => parse_policy_global_section(&mut ret, val),
            "clients" => parse_policy_clients_section(&mut ret, val),
            "users" => parse_policy_users_section(&mut ret, val),
            "groups" => parse_policy_groups_section(&mut ret, val),
            _ => {
                error!("Policy section parsing: unknown root section: \"{section}\"");
                continue;
            }
        }
    }
    info!(policy = ?ret, "Final Parsed Policy");
    return Ok(ret);
}

#[instrument]
fn parse_policy_global_section(policy: &mut Policy, section: &StrictYaml) {
    if let Some(section) = section.as_hash() {
        for (setting, val) in section {
            if let Some(setting) = setting.as_str()
            && let Some(val) = val.as_str()
            {
                match setting {
                    "default-key" => {
                        policy.default_key = Some(SString(val.to_owned()));
                    }
                    "block-unconfigured" => {
                        policy.allow_unconfigured = val.eq_ignore_ascii_case("false");
                    }
                    "bind-addr" => {
                        if let Ok(ip) = IpAddr::from_str(val) {
                            policy.bind_info.0 = ip;
                        }
                        else {
                            error!("Failed to parse bind addr: {val}");
                        }
                    },
                    "bind-port" => {
                        if let Ok(port) = u16::from_str(val) {
                            policy.bind_info.1 = port;
                        }
                        else {
                            error!("Failed to parse bind port: {val}");
                        }
                    },
                    _ => {
                        error!("unknown setting \"{setting}\" in global section");
                    }
                }
            } else { error!("Policy Global section failed to parse YAML as str"); }
        }
    } else { error!("Failed to parse entire global policy section"); }
}

#[instrument]
fn parse_policy_clients_section(policy: &mut Policy, section: &StrictYaml) {
    if let Some(section) = section.as_hash() {
        for (setting, val) in section {
            if let Some(setting) = setting.as_str()
            && let Some(val) = val.as_hash()
            && let Ok(client_ip) = setting.parse::<IpAddr>() {
                let mut client_policy = ClientPolicy { key: None, groups: None};
                for (client_setting, client_val) in val {
                    if let Some(client_setting) = client_setting.as_str()
                    && let Some(client_val) = client_val.as_str() {
                        match client_setting {
                            "key" => {
                                client_policy.key = Some(SString(client_val.to_owned()));
                            }
                            "groups" => {
                                client_policy.groups = Some(client_val.split_ascii_whitespace().map(str::to_ascii_lowercase).collect());
                            }
                            _ => { error!("Unknown client policy setting \"{client_setting}\""); }
                        }
                    }
                    else { error!("Failed to parse client setting for client: {client_ip}"); }
                }
                policy.clients.insert(client_ip, client_policy);
            } else { error!("Failed to parse client policy"); }
        }
    } else { error!("Failed to parse entire client section!"); }
}

#[instrument]
fn parse_policy_users_section(policy: &mut Policy, section: &StrictYaml) {
    if let Some(section) = section.as_hash() {
        for (username, user_settings) in section {
            if let Some(username) = username.as_str()
            && let Some(user_settings) = user_settings.as_hash()
            {
                for (setting, val) in user_settings {
                    let mut user_policy = UserPolicy { password: None, groups: None };
                    if let Some(setting) = setting.as_str()
                    && let Some(val) = val.as_str()
                    {
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
                    } else { error!("Failed to parse settings for user {username}"); }
                }
            } else { error!("Failed to parse user settings"); }
        }
    } else { error!("Failed to parse entire users section"); }
}

#[instrument]
fn parse_policy_groups_section(policy: &mut Policy, section: &StrictYaml) {
    if let Some(section) = section.as_hash() {
        for (groupname, group_settings) in section {
            if group_settings.as_hash().is_none() {continue;} // silent ignore (why?)
            let group_settings = group_settings.as_hash().unwrap();
            if let Some(groupname) = groupname.as_str() {
                let mut author_policy: Option<AuthorPolicy> = None;
                let mut acct_policy: Option<AcctPolicy> = None;
                let mut authen_policy: Option<AuthenPolicy> = None;
                for (setting, val) in group_settings {
                    if let Some(setting) = setting.as_str() {
                        match setting {
                            "author_policy" => {
                                author_policy = Some(parse_author_policy(val, groupname));
                            },
                            "acct_policy" => {
                                if let Ok(parsed_pol) = parse_acct_policy(val, groupname) {
                                    acct_policy = Some(parsed_pol);
                                }
                            }
                            "authen_policy" => {
                                authen_policy = Some(parse_authen_policy(val, groupname));
                            }
                            _ => error!("Unsupported group setting \"{val:?}\" for group {groupname}"),
                        }
                    } else { error!("Failed to parse group setting for group \"{groupname}\""); }
                }
                policy.groups.insert(groupname.to_owned(), GroupsPolicy { author_policy, acct_policy, authen_policy });
            } else { error!("Failed to parse group policy"); }
        }
    } else { error!("failed to parse entire groups section"); }
}

fn parse_author_policy(policy: &StrictYaml, groupname: &str) -> AuthorPolicy {
    let mut ret = AuthorPolicy { default_action: None, list: Vec::new() };
    if let Some(policy) = policy.as_str() {
        for line in policy.lines() {
            match line.split_once(' ') {
                Some((action, val)) => {
                    let action = action.trim();
                    let val = val.trim();
                    let action = match ACLActions::try_from(action) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("Error parsing author policy for group {groupname}: {e}");
                            return AuthorPolicy {default_action: Some(ACLActions::Deny), list: Vec::with_capacity(0) };
                        }
                    };
                    if action == ACLActions::Default {
                            let default_action = ACLActions::try_from(val).unwrap_or(ACLActions::Deny);
                            match default_action {
                                ACLActions::Default => {
                                    error!("Error parsing author policy default action for group {groupname}");
                                }
                                ACLActions::Allow |
                                ACLActions::Defer |
                                ACLActions::Deny => ret.default_action = Some(default_action)
                            }
                            continue;
                    }
                    let re = Regex::new(val);
                    match re {
                        Ok(re) => ret.list.push((action, re)),
                        Err(re_err) => {
                            use regex::Error;
                            let err_msg = match re_err {
                                Error::Syntax(explain) => format!("Syntax error: {explain}"),
                                Error::CompiledTooBig(size) => format!("Exceeded reasonable size limit: {size}"),
                                _ => "Unknown reason".to_owned(),
                            };
                            error!("AuthorPolicy for group: {groupname} regex error: {err_msg}",);
                            return AuthorPolicy { default_action: Some(ACLActions::Deny), list: Vec::with_capacity(0) };
                        }
                    }
                },
                None => {
                    error!("AuthorPolicy Parse Error failed for Group {groupname}");
                    return AuthorPolicy { default_action: Some(ACLActions::Deny), list: Vec::with_capacity(0) };
                },
            }
        }
    }
    if ret.list.is_empty() && ret.default_action.is_none() {
        error!("Did not parse any author policies for group {groupname}, defaulting to deny all");
        ret.default_action = Some(ACLActions::Deny);
    }
    ret
}

fn parse_acct_policy(policy: &StrictYaml, groupname: &str) -> Result<AcctPolicy, TacpErr> {
    if let Some(policy) = policy.as_hash() {
        for (target, value) in policy {
            if let Some(setting) = target.as_str() {
                if setting.eq_ignore_ascii_case("file") {
                    if let Some(filename) = value.as_str() { return Ok(AcctPolicy(AcctTarget::File(filename.into()))); }
                    else { return Err(TacpErr::ParseError(format!("AcctPolicy for group {groupname} specified file but filename malformed"))); }
                }
                if setting.eq_ignore_ascii_case("syslog") {
                    let mut ip = None;
                    let mut port = None;
                    let mut proto = None;
                    if let Some(syslog_settings) = value.as_hash() {
                        for (syslog_setting, syslog_val) in syslog_settings {
                            if let Some(syslog_setting) = syslog_setting.as_str()
                            && let Some(syslog_val) = syslog_val.as_str()
                            {
                                match syslog_setting {
                                    "port" => { port = syslog_val.parse::<u16>().ok(); },
                                    "ip" | "host" => { ip = syslog_val.parse::<IpAddr>().ok(); },
                                    "proto" | "protocol" => { proto = SyslogTransport::try_from(syslog_val).ok(); },
                                    _ => { error!("Unknown syslog setting: \"{syslog_setting}\" for groupname {groupname}"); }
                                }
                            } else { error!("Parse error in syslog settings for group {groupname}."); }
                        }
                    } else { error!("Failed to parse syslog settings for group {groupname}"); } //will fall through to no IP case. which is fine.
                    if let Some(ip) = ip {
                        return Ok(AcctPolicy(AcctTarget::Syslog((ip, port.unwrap_or(514), proto.unwrap_or(SyslogTransport::UDP)))));
                    }
                    else {
                        error!("Policy syslog section: finished parsing syslog settings but no target IP was specified. Groupname: {groupname}");
                        return Err(TacpErr::ParseError(format!("Policy syslog section: finished parsing syslog settings but no target IP was specified. Groupname: {groupname}")))
                    }
                } else { error!("Unknown Acct Policy target: \"{setting}\" for group {groupname}") }
            }
            else {
                error!("AcctPolicy parse error(group {groupname}), acct target is not a string");
                return Err(TacpErr::ParseError(format!("AcctPolicy parse error, acct target is not a string for group {groupname}")));
            }
        }
    } else { error!("Failed to parse entrire AcctPolicy section for group {groupname}"); }
    error!("Reached end of AcctPolicy parsing for group {groupname} with nothing to show for myself.");
    Err(TacpErr::ParseError(format!("Reached end of AcctPolicy parsing for group {groupname} with nothing to show for myself.")))
}

fn parse_authen_policy(policy: &StrictYaml, groupname: &str) -> AuthenPolicy {
    let mut ty = None;
    let mut list = None;
    if let Some(policy) = policy.as_hash() {
        for (setting, val) in policy {
            if let Some(setting) = setting.as_str() {
                if setting.eq_ignore_ascii_case("type") {
                    ty = val.as_str();
                }
                else if setting.eq_ignore_ascii_case("list") {
                    list = val.as_str();
                }
                else { error!("Unknown setting \"{setting}\" while parsing authen policy for group {groupname}"); }
            }
        }
    }
    if let Some(ty) = ty
    && let Some(list) = list
    {
        if ty.eq_ignore_ascii_case("local") {
            let mut default_action = ACLActions::Deny;
            let mut acl = Vec::new();
            for line in list.lines() {
                match line.split_once(' ') {
                    Some((action, target)) => {
                        let action = match ACLActions::try_from(action) {
                            Ok(a) => a,
                            Err(e) => {
                                error!("Error parsing authen policy for group {groupname}: {e}");
                                return AuthenPolicy(AuthenType::Local((ACLActions::Deny, Vec::with_capacity(0))));
                            }
                        };
                        if action == ACLActions::Default {
                            let parsed_target = ACLActions::try_from(target).unwrap_or(ACLActions::Deny);
                            match parsed_target {
                                ACLActions::Default => {
                                    error!("Error parsing authen policy default action for group {groupname}");
                                }
                                ACLActions::Allow |
                                ACLActions::Defer |
                                ACLActions::Deny => {
                                    default_action = parsed_target;
                                }
                            }
                            continue;
                        }
                        if let Ok(target) = AuthenTarget::try_from(target) {
                            acl.push((action, target));
                        }
                    },
                    None => {
                        error!("AuthenPolicy Failed to parse line for group {groupname}");
                        return AuthenPolicy(AuthenType::Local((ACLActions::Deny, Vec::with_capacity(0))));
                    },
                }
            }
            return AuthenPolicy(AuthenType::Local((default_action, acl)));
        }
        else {
            error!("Unkown AuthenType \"{ty}\" for group {groupname}");
        }
    } else { error!("Failed to parse both a authen type and list from the authen policy for group {groupname}"); }
    AuthenPolicy(AuthenType::Local((ACLActions::Deny, Vec::with_capacity(0))))
}