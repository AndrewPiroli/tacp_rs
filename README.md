# An implementations of the TACACS+ Protocol in Rust.

Current status: **Alpha**

Not recommended for production use (yet).

My style is to avoid external dependencies when reasonable, I am not afraid of nightly features or using unsafe.

## Main crate: tacp

Contains the protocol definitions, a zero-copy parser/decoder, and an experimental encoder. `no_std` always, but does require `alloc` and a nightly compiler.

RFC Compliance Status: **Very Good** - All definitions are in place, the treatment of string values is left to the implementer, I may add a helper for this in the final release.

ROADMAP:

  - [ ] Cool name
  - [x] Basic Protocol Implementation
    - [x] Packet parsing
      - [x] "Encryption"
      - [x] Authentication
      - [x] Authorization
      - [x] Accounting
    - [x] Full RFC compliance
  - [ ] Documentation
    - [x] RFC info in comments
    - [x] Make doc comments nice
  - [ ] Polish things
    - [ ] Errors (handling, reporting)
    - [x] Don't crash
    - [x] Custom Allocator Support
    - [x] "Zero-copy" parser
  - [ ] Security
    - [ ] Usage of unsafe
    - [ ] Direct fuzzing
    - [x] Use miri

## Testing infrastructure

### tserver - Basic testing server

A TACACS+ server with enough features to test most client operations.

### tclient - Basic testing client

A basic TACACS+ client that can make requests to a server.

### ttest - A WIP testing system

Current features:
 - runs the test client and server against each other.
 - Reads pcap files from the pcap directory and ensures all TACACS+ packets within can be parsed.
 - Supports running under miri with a reduced set of tests

Other projects we can test interop with in the future:

 * https://github.com/ansible/tacacs_plus
 * https://github.com/AuthScaffold/tacacs-rs
