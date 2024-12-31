# A TACACS+ Protocol Parser and Server.

Current status: **Alpha**

Not recommended for production use (yet).

My style is to avoid external dependencies when reasonable, I am not afraid of nightly features or using unsafe.

## Main crate: tacp

Contains the protocol definitions, a zero-copy parser/decoder, and an expiramental encoder. `no_std` always, but does require `alloc` and a nightly compiler.

The encoding side of things is new and expiramental, so it is behind a feature flag (`dst-construct`) and all methods are marked unsafe.

RFC Compliance Status: **Mostly compliant** - where it counts at least.

ROADMAP:

  - [ ] Cool name
  - [x] Basic Protocol Implementation
    - [x] Packet parsing
      - [x] "Encryption"
      - [x] Authentication
      - [x] Authorization
      - [x] Accounting
    - [ ] Full RFC compliance
  - [ ] Documentation
    - [x] RFC info in comments
    - [ ] Make doc comments nice
  - [ ] Polish things
    - [ ] Errors (handling, reporting)
    - [ ] Don't crash
    - [ ] Make `alloc` optional (other option: allocator API?)
    - [x] "Zero-copy" parser
  - [ ] Security
    - [ ] Usage of unsafe
    - [ ] Direct fuzzing

## tserver - Basic testing server

A TACACS+ server with enough features to test most client operations.

## tclient - Basic testing client

A basic TACACS+ client that can make requests to a server.

## ttest - A WIP testing system

Currently runs the test client and server against each other.

Other projects we can test interop with in the future:

 * https://github.com/ansible/tacacs_plus
 * https://github.com/AuthScaffold/tacacs-rs
