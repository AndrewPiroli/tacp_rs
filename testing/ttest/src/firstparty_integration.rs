use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::Duration;

use crate::ipc::{AAA, Controller, Info, Who};
use crate::process::{ProcessHandle, cargo_run};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);

struct FirstPartyFixture {
    controller: Controller,
    server: ProcessHandle,
    server_addr: SocketAddr,
}

impl FirstPartyFixture {
    fn start() -> Self {
        let controller = Controller::start();
        let controller_addr = controller.addr.to_string();
        let server = cargo_run(
            "tserver",
            &[],
            &[("TACP_SERVER_TEST", controller_addr.as_str())],
        );
        let server_addr = controller
            .wait_for_server(PROCESS_TIMEOUT)
            .unwrap_or_else(|error| {
                let (stdout, stderr) = server.output();
                panic!("{error}\nserver stdout:\n{stdout}\nserver stderr:\n{stderr}");
            });
        Self {
            controller,
            server,
            server_addr,
        }
    }

    fn run_client(&self, command: &[&str], expected: Info, expected_output: &str) {
        let host = self.server_addr.ip().to_string();
        let port = self.server_addr.port().to_string();
        let mut args = vec![
            "--server",
            host.as_str(),
            "--port",
            port.as_str(),
            "--key",
            "b",
        ];
        args.extend_from_slice(command);

        let mut client = cargo_run("tclient", &args, &[]);
        let status = client.wait(PROCESS_TIMEOUT).unwrap_or_else(|error| {
            let (stdout, stderr) = client.output();
            panic!("failed waiting for client: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        });
        let (stdout, stderr) = client.output();
        let (server_stdout, server_stderr) = self.server.output();
        let status = status.unwrap_or_else(|| {
            panic!(
                "client timed out\nstdout:\n{stdout}\nstderr:\n{stderr}\nserver stdout:\n{server_stdout}\nserver stderr:\n{server_stderr}"
            );
        });

        assert!(
            status.success(),
            "client exited with {status}\nstdout:\n{stdout}\nstderr:\n{stderr}\nserver stdout:\n{server_stdout}\nserver stderr:\n{server_stderr}"
        );
        assert!(
            stderr.is_empty(),
            "client wrote to stderr:\n{stderr}\nstdout:\n{stdout}\nserver stdout:\n{server_stdout}\nserver stderr:\n{server_stderr}"
        );
        assert!(
            stdout.contains(expected_output),
            "client did not decode the expected response `{expected_output}`\nstdout:\n{stdout}\nserver stdout:\n{server_stdout}\nserver stderr:\n{server_stderr}"
        );

        let report = self
            .controller
            .receive_report(PROCESS_TIMEOUT)
            .unwrap_or_else(|error| {
                panic!(
                    "{error}\nclient stdout:\n{stdout}\nclient stderr:\n{stderr}\nserver stdout:\n{server_stdout}\nserver stderr:\n{server_stderr}"
                );
            });
        assert_eq!(
            report, expected,
            "unexpected server report\nclient stdout:\n{stdout}\nclient stderr:\n{stderr}\nserver stdout:\n{server_stdout}\nserver stderr:\n{server_stderr}"
        );
    }
}

impl Drop for FirstPartyFixture {
    fn drop(&mut self) {
        self.server.terminate();
    }
}

fn expected(ty: AAA, success: bool) -> Info {
    expected_with_data(ty, success, None)
}

fn expected_with_data(ty: AAA, success: bool, otherdata: Option<&str>) -> Info {
    Info {
        who: Who::Server,
        ty,
        success,
        user: "test".to_owned(),
        otherdata: otherdata.map(str::to_owned),
    }
}

#[cfg(not(miri))]
#[test]
fn pap_authentication_accepts_valid_password() {
    FirstPartyFixture::start().run_client(
        &["pap-login", "test", "test"],
        expected(AAA::Authen, true),
        "Authentication passed",
    );
}

#[cfg(not(miri))]
#[test]
fn pap_authentication_rejects_invalid_password() {
    FirstPartyFixture::start().run_client(
        &["pap-login", "test", "asdf"],
        expected(AAA::Authen, false),
        "Authentication failed",
    );
}

#[cfg(not(miri))]
#[test]
fn ascii_authentication_accepts_valid_password() {
    FirstPartyFixture::start().run_client(
        &["ascii-login", "test", "test"],
        expected(AAA::Authen, true),
        "Authentication passed",
    );
}

#[cfg(not(miri))]
#[test]
fn command_authorization_accepts_allowed_command() {
    FirstPartyFixture::start().run_client(
        &["authorize", "--username", "test", "cmd=testing"],
        expected(AAA::Author, true),
        "Authorization Success (as-is)",
    );
}

#[cfg(not(miri))]
#[test]
fn command_authorization_rejects_denied_command() {
    FirstPartyFixture::start().run_client(
        &["authorize", "--username", "test", "cmd=test-deny-string"],
        expected(AAA::Author, false),
        "Authorization Failed",
    );
}

#[cfg(not(miri))]
#[test]
fn accounting_request_succeeds() {
    FirstPartyFixture::start().run_client(
        &["account", "--username", "test", "task_id=testing"],
        expected_with_data(AAA::Acct, true, Some("task_id=testing")),
        "Accouting Success",
    );
}

#[test]
fn argvalpair_parsing_and_formatting() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use tacp::argvalpair::*;

    let basic = [
        (
            "test=abc",
            ("test", false, Value::Str(Cow::Borrowed("abc"))),
        ),
        ("abc=123", ("abc", false, Value::Numeric(123.0))),
        ("working*true", ("working", true, Value::Boolean(true))),
        (
            "floating*4321.949",
            ("floating", true, Value::Numeric(4321.949)),
        ),
        ("empty=", ("empty", false, Value::Empty)),
        (
            "ip4=192.168.1.1",
            (
                "ip4",
                false,
                Value::IPAddr(IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap())),
            ),
        ),
        (
            "ip6=2001:db8::dead",
            (
                "ip6",
                false,
                Value::IPAddr(IpAddr::V6(Ipv6Addr::from_str("2001:db8::dead").unwrap())),
            ),
        ),
    ];
    for (input, (argument, optional, value)) in basic {
        let parsed = ArgValPair::try_from(input)
            .unwrap_or_else(|error| panic!("failed to parse `{input}`: {error:?}"));
        assert_eq!(parsed.argument, argument, "argument parsed from `{input}`");
        assert_eq!(
            parsed.optional, optional,
            "optionality parsed from `{input}`"
        );
        assert_eq!(parsed.value, value, "value parsed from `{input}`");
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
    for input in v4_addrs {
        let addr = Ipv4Addr::from_str(input).unwrap();
        assert_eq!(
            Value::IPAddr(IpAddr::V4(addr)).to_string(),
            addr.to_string()
        );
    }
    for input in v6_addrs {
        let addr = Ipv6Addr::from_str(input).unwrap();
        assert_eq!(
            Value::IPAddr(IpAddr::V6(addr)).to_string(),
            addr.to_string()
        );
    }
}

#[test]
fn packet_components_over_the_wire_limit_are_rejected() {
    static EMPTY: &[u8; 0] = &[0; 0];
    static BIG8: &[u8; 266] = &[0; 266];
    static BIG16: &[u8; 65_536] = &[0; 65_536];
    use tacp::*;

    let rejected = [
        AuthenStartPacket::new(
            AuthenStartAction::LOGIN,
            15,
            AuthenType::ASCII,
            AuthenService::NONE,
            BIG8,
            EMPTY,
            EMPTY,
            EMPTY,
        )
        .is_err(),
        AuthenStartPacket::new(
            AuthenStartAction::LOGIN,
            15,
            AuthenType::ASCII,
            AuthenService::NONE,
            EMPTY,
            BIG8,
            EMPTY,
            EMPTY,
        )
        .is_err(),
        AuthenStartPacket::new(
            AuthenStartAction::LOGIN,
            15,
            AuthenType::ASCII,
            AuthenService::NONE,
            EMPTY,
            EMPTY,
            BIG8,
            EMPTY,
        )
        .is_err(),
        AuthenStartPacket::new(
            AuthenStartAction::LOGIN,
            15,
            AuthenType::ASCII,
            AuthenService::NONE,
            EMPTY,
            EMPTY,
            EMPTY,
            BIG8,
        )
        .is_err(),
        AuthenReplyPacket::new(AuthenReplyStatus::ERROR, AuthenReplyFlags(0), BIG16, EMPTY)
            .is_err(),
        AuthenReplyPacket::new(AuthenReplyStatus::ERROR, AuthenReplyFlags(0), EMPTY, BIG16)
            .is_err(),
        AuthenContinuePacket::new(AuthenContinueFlags(0), BIG16, EMPTY).is_err(),
        AuthenContinuePacket::new(AuthenContinueFlags(0), EMPTY, BIG16).is_err(),
        AuthorRequestPacket::new(
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            BIG8,
            EMPTY,
            EMPTY,
            &[EMPTY],
        )
        .is_err(),
        AuthorRequestPacket::new(
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            EMPTY,
            BIG8,
            EMPTY,
            &[EMPTY],
        )
        .is_err(),
        AuthorRequestPacket::new(
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            EMPTY,
            EMPTY,
            BIG8,
            &[EMPTY],
        )
        .is_err(),
        AuthorRequestPacket::new(
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            EMPTY,
            EMPTY,
            EMPTY,
            &[BIG8],
        )
        .is_err(),
        AuthorReplyPacket::new(AuthorStatus::ERROR, &[EMPTY], BIG16, EMPTY).is_err(),
        AuthorReplyPacket::new(AuthorStatus::ERROR, &[EMPTY], EMPTY, BIG16).is_err(),
        AuthorReplyPacket::new(AuthorStatus::ERROR, &[BIG8], EMPTY, EMPTY).is_err(),
        AcctRequestPacket::new(
            AcctFlags::RecordStart,
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            BIG8,
            EMPTY,
            EMPTY,
            &[EMPTY],
        )
        .is_err(),
        AcctRequestPacket::new(
            AcctFlags::RecordStart,
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            EMPTY,
            BIG8,
            EMPTY,
            &[EMPTY],
        )
        .is_err(),
        AcctRequestPacket::new(
            AcctFlags::RecordStart,
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            EMPTY,
            EMPTY,
            BIG8,
            &[EMPTY],
        )
        .is_err(),
        AcctRequestPacket::new(
            AcctFlags::RecordStart,
            AuthorMethod::ENABLE,
            15,
            AuthenType::ASCII,
            AuthenService::ENABLE,
            EMPTY,
            EMPTY,
            EMPTY,
            &[BIG8],
        )
        .is_err(),
        AcctReplyPacket::new(AcctStatus::SUCCESS, BIG16, EMPTY).is_err(),
        AcctReplyPacket::new(AcctStatus::SUCCESS, EMPTY, BIG16).is_err(),
    ];
    assert!(
        rejected.into_iter().all(|value| value),
        "an oversized packet component was accepted"
    );
}
