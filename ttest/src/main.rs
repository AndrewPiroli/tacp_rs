#![allow(non_upper_case_globals)]
#![cfg_attr(miri, allow(unused_assignments, dead_code, unused_imports, unused_macros))]

use std::{error::*, net::SocketAddr};
use std::result::Result;
use std::time::Duration;
use ipc::{start_webserver, CurrentPolicy, HeardFromServer, Info, ListenAddr, ReceivedInfos};

use crate::process::*;
mod process;
mod ipc;
mod pcap;

macro_rules! runtest {
    ($name:literal, $fn:ident, $stream:ident) => {
        writeln!($stream, "{}: {}",
            $name,
            if $fn() { "PASS" } else { "FAIL" }
        ).unwrap();
    };
}

#[cfg(miri)]
fn main() -> Result<(), Box<dyn Error>> {
    if pcap::check_pcap() {
        println!("PCAP Replay Test - PASS");
    }
    else {
        println!("PCAP Replay Test - FAIL");
    }
    Ok(())
}

#[cfg(not(miri))]
fn main() -> Result<(), Box<dyn Error>> {
    // Start web server in the background while we do pcap stuff
    start_webserver();
    if pcap::check_pcap() {
        println!("PCAP Replay Test - PASS");
    }
    else {
        println!("PCAP Replay Test - FAIL");
    }
    // Back to client server testing stuff
    *CurrentPolicy.write().unwrap() = include_str!("../basicpolicy.yaml").to_owned();
    while let None = ListenAddr.get() {}
    let addr = ListenAddr.get().unwrap();
    let _s = launch_server_with_test_mode(addr);
    let mut tries = 10;
    loop {
        use std::sync::atomic::Ordering::*;
        let current = HeardFromServer.load(Acquire);
        if current { break; }
        std::thread::sleep(Duration::from_secs(1 * (10-tries) ));
        if tries == 0 { panic!("server never checked in"); }
        tries -= 1;
    }
    {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        runtest!("1st Party PAP Authentication 1", test_pap_authen_success, stdout);
        runtest!("1st Party PAP Authentication 2", test_pap_authen_fail, stdout);
        runtest!("1st Party Command Authorization 1", test_author_success, stdout);
        runtest!("1st Party Command Authorization 2", test_author_fail, stdout);
        runtest!("1st Party Accounting 1", test_acct_success, stdout);
        /*
        if has_python_client() {
            todo!();
        }
        else {
            println!("No python client detected, install it with pip install tacacs_client");
        }
        */
    }
    Ok(())
}

fn launch_server_with_test_mode(addr: &SocketAddr) -> ProcessHandle {
    HeardFromServer.store(false, std::sync::atomic::Ordering::Release);
    let server = cargo_run("tserver", &[], &[("TACP_SERVER_TEST", &addr.to_string())]);
    server
}

fn test_pap_authen_success() -> bool {
    use ipc::*;
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "pap-login", "test", "test"], Info {
        who: Who::Server,
        ty: AAA::Authen,
        success: true,
        user: "test".to_owned(),
        otherdata: None,
    })
}

fn test_pap_authen_fail() -> bool {
    use ipc::*;
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "pap-login", "test", "asdf"], Info {
        who: Who::Server,
        ty: AAA::Authen,
        success: false,
        user: "test".to_owned(),
        otherdata: None,
    })
}

fn test_author_success() -> bool {
    use ipc::*;
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "authorize", "--username", "test", "cmd=testing"], Info {
        who: Who::Server,
        ty: AAA::Author,
        success: true,
        user: "test".to_owned(),
        otherdata: None,
    })
}

fn test_author_fail() -> bool {
    use ipc::*;
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "authorize", "--username", "test", "cmd=test-deny-string"], Info {
        who: Who::Server,
        ty: AAA::Author,
        success: false,
        user: "test".to_owned(),
        otherdata: None,
    })
}

fn test_acct_success() -> bool {
    use ipc::*;
    native_client_test(false, &["--server", "localhost", "--port", "9999", "--key", "b", "account", "--username", "test", "testing"], Info {
        who: Who::Server,
        ty: AAA::Acct,
        success: true,
        user: "test".to_owned(),
        otherdata: None,
    })
}


fn native_client_test(inverted: bool, args: &[&str], expected: Info) -> bool {
    fn run_client_with_args(args: &[&str]) -> ProcessHandle {
        cargo_run("tclient", args, &[])
    }
    let client = run_client_with_args(args);
    while let Ok(_s) = client.stdout.recv_timeout(Duration::from_secs(1)) {/*dbg!(_s);*/}
    let mut found = false;
    ReceivedInfos.write().unwrap().retain(|x|{
        if !found && x == &expected {
            found = true;
            return false;
        }
        return true;
    });
    found == !inverted
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
