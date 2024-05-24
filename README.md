This is a toy, do not use !!!!

tacp/ - protocol definitions, encoders, and decoders. no_std, requires alloc. Permissive License (MIT/Apache)

tacpd/ - reference server implementation. Copyleft license (GPL)

TODO:

  - [ ] Cool name
  - [x] Basic Protocol Implementation
    - [x] Packet parsing and reply
      - [x] "Encryption"
      - [x] Authentication
      - [x] Authorization
      - [x] Accounting
  - [ ] Documentation
    - [x] RFC info in comments
    - [ ] Make doc comments nice
    - [ ] Document policy file
  - [ ] Polish things
    - [ ] Errors (handling, reporting)
    - [ ] Don't crash
    - [ ] Config/policy validation
  - [ ] Performance
    - [ ] Benchmark performance
      - [ ] Load generation (how?)
    - [ ] Multi-threading
    - [ ] Multi-processing / sharding
  - [ ] Security
    - [ ] Fuzzing (how?)
    - [ ] Unsafe usage
  - [ ] Policy
    - [x] Clients
    - [x] Users
    - [x] Authorization
    - [ ] Authentication
    - [ ] Accounting
    - [x] Groups
  - [ ] Features
     - [ ] Authentication
       - [x] Basic Protocol stuff
         - [x] Define users manually in policy file
         - [x] ASCII
         - [x] PAP
         - [x] CHAP
       - [ ] LDAP Proxying
       - [ ] RADIUS Proxying
       - [ ] Other external sources?
       - [ ] Builtin 2 factor (TOTP?, HTOP?)
    - [ ] Authorization
      - [x] ACL type stuff in Policy
      - [ ] What else?
    - [ ] Accounting
      - [ ] Syslog
      - [ ] File logging
      - [ ] Graylog (?)
      - [ ] Other ideas (?)
  - [ ] Misc random ideas
    - [ ] Some kind of embedded scripting language to do cool stuff ??
    - [ ] Web UI ?
