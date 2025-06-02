#![allow(non_upper_case_globals)]
#![cfg_attr(miri, allow(unused_assignments, dead_code, unused_imports, unused_macros))]

use std::error::*;
use std::result::Result;

use std::io::Write;
use ipc::{start_webserver, CurrentPolicy, HeardFromServer, ListenAddr,};
mod process;
mod ipc;
mod pcap;
mod firstparty_integration;

struct Test {
    name: &'static str,
    func: fn() -> bool,
}

fn get_tests() -> Vec<Test> {
    use firstparty_integration::*;
    vec![
        Test { name: "1st Party PAP Authentication 1", func: test_pap_authen_success },
        Test { name: "1st Party PAP Authentication 2", func: test_pap_authen_fail },
        Test { name: "1st Party Command Authorization 1", func: test_author_success },
        Test { name: "1st Party Command Authorization 2", func: test_author_fail },
        Test { name: "1st Party Accounting 1", func: test_acct_success },
        // Add more tests here
    ]
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
    } else {
        println!("PCAP Replay Test - FAIL");
    }
    // Back to client server testing stuff
    *CurrentPolicy.write().unwrap() = include_str!("../basicpolicy.yaml").to_owned();
    while ListenAddr.get().is_none() {}
    let addr = ListenAddr.get().unwrap();
    let _s = firstparty_integration::launch_server_with_test_mode(addr);
    let mut tries = 10;
    loop {
        use std::sync::atomic::Ordering::*;
        if HeardFromServer.load(Acquire) { break; }
        std::thread::sleep(std::time::Duration::from_secs(1 * (10 - tries)));
        if tries == 0 { panic!("server never checked in"); }
        tries -= 1;
    }
    let mut stdout = std::io::stdout().lock();
    for test in get_tests() {
        writeln!(stdout, "{}: {}", test.name, if (test.func)() { "PASS" } else { "FAIL" }).unwrap();
    }
    Ok(())
}
