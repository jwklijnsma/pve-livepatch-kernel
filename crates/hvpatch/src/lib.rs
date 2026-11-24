//! hvpatch node agent.
//!
//! The agent never compiles anything and never decides fleet order. It
//! fetches the signed manifest for exactly the running kernel, verifies it,
//! loads the module, watches the transition and backs out if anything looks
//! wrong.

pub mod agent;
pub mod check;
pub mod config;
pub mod fake;
pub mod kernel;
pub mod linux;
pub mod lock;
pub mod repo;
pub mod report;
pub mod setup;
pub mod state;

pub use agent::Agent;
pub use config::Config;
