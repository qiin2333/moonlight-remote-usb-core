//! Platform-neutral Remote USB protocol core.
//!
//! The crate is deliberately transport- and platform-agnostic. Integrators
//! serialize all calls for one session on an owner loop and move bytes between
//! the returned events and their authenticated transport.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::too_many_arguments)]

pub mod broker;
pub mod error;
pub mod executor;
pub mod ffi;
pub mod pdu;
pub mod session;
pub mod transport;
pub mod usbip;
pub mod wire;

pub use error::{CoreError, CoreResult};

pub const PROTOCOL_VERSION: u16 = 1;
pub const ABI_VERSION: u32 = 1;
