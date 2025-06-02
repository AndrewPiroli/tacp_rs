use crate::ipc::*;
use crate::process::*;
use std::net::SocketAddr;
pub fn launch_server_with_test_mode(addr: &SocketAddr) -> ProcessHandle {
    HeardFromServer.store(false, std::sync::atomic::Ordering::Release);
    let server = cargo_run("tserver", &[], &[("TACP_SERVER_TEST", &addr.to_string())]);
    server
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
