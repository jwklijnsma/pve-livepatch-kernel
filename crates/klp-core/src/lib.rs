//! Shared building blocks for the hvpatch node agent and the build tooling.
//!
//! Everything in here is pure logic without side effects on the running
//! kernel, so it can be unit-tested on any platform.

pub mod elf;
pub mod manifest;
pub mod naming;
pub mod policy;
pub mod sig;

pub use manifest::Manifest;
