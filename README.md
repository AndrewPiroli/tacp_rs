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
    - [ ] Document policy file
  - [ ] Polish things
    - [ ] Errors (handling, reporting)
    - [ ] Don't crash
    - [ ] Make `alloc` optional
    - [x] "Zero-copy" parser
  - [ ] Security
    - [ ] Usage of unsafe
    - [ ] Direct fuzzing

## tacpd/ - The "reference" server implementation.

Right now this is kind of a mess because it's living as an undifferentiated zygote.
Some of the things it has only make sense in a production TACACS+ server,
but right now it's really only useful as a test-wrapper of the `tacp` crate. At some point in the future, this crate
will commit to one of those 2 goals and a new server will be written to fufill the other one.