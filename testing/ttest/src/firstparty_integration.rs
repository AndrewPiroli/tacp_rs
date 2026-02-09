use crate::ipc::*;
use crate::process::*;
use std::borrow::Cow;
use std::net::SocketAddr;
pub fn launch_server_with_test_mode(addr: &SocketAddr) -> ProcessHandle {
    HeardFromServer.store(false, std::sync::atomic::Ordering::Release);
    cargo_run("tserver", &[], &[("TACP_SERVER_TEST", &addr.to_string())])
}

pub fn test_pap_authen_success() -> bool {
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "pap-login", "test", "test"], Info {
        who: Who::Server,
        ty: AAA::Authen,
        success: true,
        user: "test".to_owned(),
        otherdata: None,
    })
}

pub fn test_pap_authen_fail() -> bool {
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "pap-login", "test", "asdf"], Info {
        who: Who::Server,
        ty: AAA::Authen,
        success: false,
        user: "test".to_owned(),
        otherdata: None,
    })
}

pub fn test_author_success() -> bool {
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "authorize", "--username", "test", "cmd=testing"], Info {
        who: Who::Server,
        ty: AAA::Author,
        success: true,
        user: "test".to_owned(),
        otherdata: None,
    })
}

pub fn test_author_fail() -> bool {
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "authorize", "--username", "test", "cmd=test-deny-string"], Info {
        who: Who::Server,
        ty: AAA::Author,
        success: false,
        user: "test".to_owned(),
        otherdata: None,
    })
}

pub fn test_acct_success() -> bool {
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "account", "--username", "test", "testing"], Info {
        who: Who::Server,
        ty: AAA::Acct,
        success: true,
        user: "test".to_owned(),
        otherdata: None,
    })
}


pub fn native_client_test(inverted: bool, args: &[&str], expected: Info) -> bool {
    fn run_client_with_args(args: &[&str]) -> ProcessHandle {
        cargo_run("tclient", args, &[])
    }
    let client = run_client_with_args(args);
    while let Ok(_s) = client.stdout.recv_timeout(std::time::Duration::from_secs(1)) {/*dbg!(_s);*/}
    let mut found = false;
    ReceivedInfos.write().unwrap().retain(|x|{
        if !found && x == &expected {
            found = true;
            return false;
        }
        true
    });
    found != inverted
}

pub fn test_avp_parse_and_fmt() -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use tacp::argvalpair::*;
    // Basic test cases
    let basic = [
        ("test=abc", ("test", false, Value::Str(Cow::Borrowed("abc")))),
        ("abc=123", ("abc", false, Value::Numeric(123.0))),
        ("working*true", ("working", true, Value::Boolean(true))),
        ("floating*4321.949", ("floating", true, Value::Numeric(4321.949))),
        ("empty=", ("empty", false, Value::Empty)),
        ("ip4=192.168.1.1", ("ip4", false, Value::IPAddr(IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap())))),
        ("ip6=2001:db8::dead", ("ip6", false, Value::IPAddr(IpAddr::V6(Ipv6Addr::from_str("2001:db8::dead").unwrap()))))
    ];
    for (toparse, (arg, optional, val)) in basic {
        let parsed = ArgValPair::try_from(toparse);
        match parsed {
            Ok(parsed) => {
                if parsed.argument != arg {
                    eprintln!("parsed argument doesn't match: {}!={}", parsed.argument, arg);
                    return false;
                }
                if parsed.optional != optional {
                    eprintln!("parsed optional value doesn't match: {}!={}", parsed.optional, optional);
                    return false;
                }
                if parsed.value != val {
                    eprintln!("parsed value doesn't match: {:?}!={:?}", parsed.value, val);
                    return false;
                }
            },
            Err(err) => {
                eprintln!("Failed AVP test case: \"{}\" should be \"{}\" opt={} \"{:?}\"", toparse, arg, optional, val);
                eprintln!("{err:?}");
                return false;
            },
        }
    }
    let v4_addrs = [
        "192.168.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "10.0.0.255",
        "172.16.254.1",
        "8.8.8.8",
        "1.2.3.4",
        "169.254.0.1",
        "100.64.0.1",
    ];
    let v6_addrs = [
        "2001:0db8:0000:0000:0000:ff00:0042:8329",
        "2001:db8::ff00:42:8329",
        "::1",
        "::",
        "0:0:0:0:0:0:0:1",
        "fe80::1",
        "2001:db8:0:0:0:0:2:1",
        "2001:db8::2:1",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        "0000:0000:0000:0000:0000:0000:0000:0000",
    ];
    for v4addr in v4_addrs {
        let addr = Ipv4Addr::from_str(v4addr).unwrap();
        let val = Value::IPAddr(IpAddr::V4(addr)).to_string();
        let addr = addr.to_string();
        if addr != val {
            eprintln!("ArgValPair IP formatter fail: expected:{addr} got:{val}");
            // return false;
        }
    }
    for v6addr in v6_addrs {
        let addr = Ipv6Addr::from_str(v6addr).unwrap();
        let val = Value::IPAddr(IpAddr::V6(addr)).to_string();
        let addr = addr.to_string();
        if addr != val {
            eprintln!("ArgValPair IP formatter fail: expected:{addr} got:{val}");
            return false;
        }
    }
    true
}

/// This test makes sure you can't construct a Packet with components too large to have their length encoded properly for that packet type.
pub fn packet_data_overflow() -> bool {
    static empty: &[u8;0] = &[0;0];
    static big8: &[u8;266] = &[0;266];
    static big16: &[u8;65536] = &[0;65536];
    use tacp::*;
    [
        // AuthenStart - max u8 for user, port, rem_addr, data
        AuthenStartPacket::new(AuthenStartAction::LOGIN, 15, AuthenType::ASCII, AuthenService::NONE, big8, empty, empty, empty).is_err(),
        AuthenStartPacket::new(AuthenStartAction::LOGIN, 15, AuthenType::ASCII, AuthenService::NONE, empty, big8, empty, empty).is_err(),
        AuthenStartPacket::new(AuthenStartAction::LOGIN, 15, AuthenType::ASCII, AuthenService::NONE, empty, empty, big8, empty).is_err(),
        AuthenStartPacket::new(AuthenStartAction::LOGIN, 15, AuthenType::ASCII, AuthenService::NONE, empty, empty, empty, big8).is_err(),
        // AuthenReply u16 serv_msg, data
        AuthenReplyPacket::new(AuthenReplyStatus::ERROR, AuthenReplyFlags(0), big16, empty).is_err(),
        AuthenReplyPacket::new(AuthenReplyStatus::ERROR, AuthenReplyFlags(0), empty, big16).is_err(),
        // AuthenContinue u16 user_msg, data
        AuthenContinuePacket::new(AuthenContinueFlags(0), big16, empty).is_err(),
        AuthenContinuePacket::new(AuthenContinueFlags(0), empty, big16).is_err(),
        // Author Request u8 user, port, rem_addr, args
        AuthorRequestPacket::new(AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, big8, empty, empty, &[empty]).is_err(),
        AuthorRequestPacket::new(AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, empty, big8, empty, &[empty]).is_err(),
        AuthorRequestPacket::new(AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, empty, empty, big8, &[empty]).is_err(),
        AuthorRequestPacket::new(AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, empty, empty, empty, &[big8]).is_err(),
        // Author Reply u16 server_msg, data u8 args
        AuthorReplyPacket::new(AuthorStatus::ERROR, &[empty], big16, empty).is_err(),
        AuthorReplyPacket::new(AuthorStatus::ERROR, &[empty], empty, big16).is_err(),
        AuthorReplyPacket::new(AuthorStatus::ERROR, &[big8], empty, empty).is_err(),
        // Acct Request u8 user, port, rem_addr, args
        AcctRequestPacket::new(AcctFlags::RecordStart, AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, big8, empty, empty, &[empty]).is_err(),
        AcctRequestPacket::new(AcctFlags::RecordStart, AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, empty, big8, empty, &[empty]).is_err(),
        AcctRequestPacket::new(AcctFlags::RecordStart, AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, empty, empty, big8, &[empty]).is_err(),
        AcctRequestPacket::new(AcctFlags::RecordStart, AuthorMethod::ENABLE, 15, AuthenType::ASCII, AuthenService::ENABLE, empty, empty, empty, &[big8]).is_err(),
        // Acct Reply u16 server_msg, data
        AcctReplyPacket::new(AcctStatus::SUCCESS, big16, empty).is_err(),
        AcctReplyPacket::new(AcctStatus::SUCCESS, empty, big16).is_err(),
    ].iter().all(|x|*x)
}

/*
fn has_python_client() -> bool {
    which::which("tacacs_client").is_ok()
}

fn python_client_test(args: &[&str], expected: Info) -> bool {
    use std::process::*;
    let exe = which::which("tacacs_client").unwrap();
    let mut cmd = Command::new(exe);
    cmd.args(args);
    let ph = spawn(cmd);
    while let Ok(_s) = ph.stdout.recv_timeout(Duration::from_secs(1)) {/*dbg!(_s);*/}
    let mut found = false;
    ReceivedInfos.write().unwrap().retain(|x|{
        if !found && x == &expected {
            found = true;
            return false;
        }
        return true;
    });
    found
}
*/
