use std::error::Error;
use tokio::io::AsyncWriteExt;
use tracing::instrument;

use super::*;


pub(crate) fn authorize(policy: &Policy, client: IpAddr, user: &str, cmd: &str) -> bool {
    fn run_list(policies: &[&AuthorPolicy], cmd: &str) -> bool {
        for policy in policies {
            let default = policy.default_action;
            for (action, ck) in policy.list.iter() {
                if ck.is_match(cmd) {
                    match action {
                        AuthorActions::Default => unreachable!(),
                        AuthorActions::Defer => { continue },
                        AuthorActions::Deny => { return false;},
                        AuthorActions::Allow => { return true; },
                    }
                }
                match default {
                    AuthorActions::Default => unreachable!(),
                    AuthorActions::Defer => { continue; }
                    AuthorActions::Deny => { return false; },
                    AuthorActions::Allow => { return true; },
                }
            }
        }
        false // no matches, no default allow, no one to defer to, DENY
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
                None => todo!(),
            }
        },
        None => todo!(),
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
                None => todo!(),
            }
        },
        None => todo!(),
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