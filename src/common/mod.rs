//! Code shared by the client and the server.
//!
//! Anything both halves must agree on lives here — the CLI surface, the cryptography, the
//! wire bodies, and the constants that would otherwise drift out of sync if each side kept
//! its own copy.

pub mod cli;
pub mod consts;
pub mod crypto;
pub mod env;
pub mod wire;
