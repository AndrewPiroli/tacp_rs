#![cfg_attr(miri, allow(dead_code, unused_imports))]

#[cfg(test)]
mod firstparty_integration;
#[cfg(test)]
mod ipc;
#[cfg(test)]
mod pcap;
#[cfg(test)]
mod process;

fn main() {
    eprintln!("Run this package's tests with `cargo test -p ttest`.");
}
