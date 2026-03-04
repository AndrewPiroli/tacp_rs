use std::error::Error;
use tokio::io::AsyncWriteExt;
use tracing::instrument;

use super::*;


pub(crate) fn authorize(policy: &Policy, client: IpAddr, user: &str, cmd: &str) -> bool {
    fn run_list(policies: &[&AuthorPolicy], cmd: &str) -> bool {
        let mut default_action = ACLActions::Deny;
        for policy in policies {
            if let Some(default) = policy.default_action {
                default_action = default;
            }
            for (action, ck) in policy.list.iter() {
                if ck.is_match(cmd) {
                    match action {
                        ACLActions::Default => unreachable!(),
                        ACLActions::Defer => { continue },
                        ACLActions::Deny => { return false;},
                        ACLActions::Allow => { return true; },
                    }
                }
            }
        }
        default_action == ACLActions::Allow
    }

    let mut policy_list = Vec::new();

    match policy.clients.get(&client) {
        Some(client) => {
            match &client.groups {
                Some(cgs) => {
                    for cg in cgs {
                        if let Some(pol) = policy.groups.get(cg) && pol.author_policy.is_some() {
                            policy_list.push(pol.author_policy.as_ref().unwrap());
                        }
                    }
                },
                None => {},
            }
        },
        None => {},
    }

    match policy.users.get(user) {
        Some(user) => {
            match &user.groups {
                Some(ugs) => {
                    for ug in ugs {
                        if let Some(pol) = policy.groups.get(ug) && pol.author_policy.is_some() {
                            policy_list.push(pol.author_policy.as_ref().unwrap());
                        }
                    }
                },
                None => {},
            }
        },
        None => { return false; },
    }
    run_list(&policy_list, cmd)
}

#[instrument]
pub(crate) async fn account(policy: &Policy, client: IpAddr, user: &str, to_acct: &str) -> Result<bool, Box<dyn Error>> {
    let mut policy_list = Vec::new();
    match policy.clients.get(&client) {
        Some(client_policy) => {
            match &client_policy.groups {
                Some(cgs) => {
                    for cg in cgs {
                        if let Some(pol) = policy.groups.get(cg) && pol.acct_policy.is_some() {
                            policy_list.push(pol.acct_policy.as_ref().unwrap());
                        }
                    }
                },
                None => {},
            }
        },
        None => {},
    }
    match policy.users.get(user) {
        Some(user) => {
            match &user.groups {
                Some(ugs) => {
                    for ug in ugs {
                        if let Some(pol) = policy.groups.get(ug) && pol.acct_policy.is_some() {
                            policy_list.push(pol.acct_policy.as_ref().unwrap());
                        }
                    }
                },
                None => {},
            }
        },
        None => { /* Should we allow this? Probably for accounting */},
    }
    let to_acct = format!("{to_acct:?}");
    for pol in policy_list.iter() {
        match &pol.0 {
            AcctTarget::File(fp) => {
                let mut f = tokio::fs::File::open(fp).await?;
                f.write_all(to_acct.as_bytes()).await?;
            },
        }
    }
    Ok(true)
}

pub(crate) fn authenticate(policy: &Policy, client: IpAddr, user: &str, pass: &SString) -> bool {
    let mut policy_list = Vec::new();
    match policy.clients.get(&client) {
        Some(client_policy) => {
            match &client_policy.groups {
                Some(cgs) => {
                    for cg in cgs {
                        if let Some(pol) = policy.groups.get(cg) && pol.authen_policy.is_some() {
                            policy_list.push(pol.authen_policy.as_ref().unwrap());
                        }
                    }
                },
                None => {},
            }
        },
        None => {},
    }
    match policy.users.get(user) {
        Some(user) => {
            match &user.groups {
                Some(ugs) => {
                    for ug in ugs {
                        if let Some(pol) = policy.groups.get(ug) && pol.authen_policy.is_some() {
                            policy_list.push(pol.authen_policy.as_ref().unwrap());
                        }
                    }
                },
                None => {},
            }
        },
        None => {/* Should we allow this? Probably not, but when non-local auth is allowed - probably yes */},
    }

    fn check_pw(policy: &Policy, user: &str, pass: &SString) -> bool {
        if let Some(user) = policy.users.get(user) {
            if let Some(user_pass) = &user.password {
                pass.0 == user_pass.0
            }
            else {
                false
            }
        }
        else {
            false
        }
    }

    if policy_list.is_empty() {
        return check_pw(policy, user, pass);
    }

    let mut last_default = ACLActions::Deny;
    for pol in policy_list.iter() {
        let pol = &pol.0;
        match pol {
            AuthenType::Local((default, acl)) => {
                last_default = *default;
                for (action, target) in acl.iter() {
                    match target {
                        AuthenTarget::Group(g) => {
                            if check_group_membership(policy, user, g) {
                                match action {
                                    ACLActions::Default => unreachable!(),
                                    ACLActions::Defer => { continue },
                                    ACLActions::Deny => { return false; },
                                    ACLActions::Allow => {
                                        return check_pw(policy, user, pass);
                                    },
                                }
                            }
                        },
                        AuthenTarget::User(u) => {
                            if user.eq_ignore_ascii_case(u) {
                                match action {
                                    ACLActions::Default => unreachable!(),
                                    ACLActions::Defer => { continue },
                                    ACLActions::Deny => { return false; },
                                    ACLActions::Allow => {
                                        return check_pw(policy, user, pass);
                                    },
                                }
                            }
                        },

                    }

                }
            },
        }
    }
    return last_default == ACLActions::Allow;
}

fn check_group_membership(policy: &Policy, user: &str, group: &str) -> bool {
    if let Some(user) = policy.users.get(user) && let Some(user_groups) = &user.groups {
        return user_groups.iter().any(|user_group|user_group.eq_ignore_ascii_case(group));
    }
    false
}