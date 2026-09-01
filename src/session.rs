//! High-level session API.
//!
//! `Transport` is re-exported as the stable Rust session engine. Keeping this
//! module separate leaves room for policy-free multi-device orchestration in a
//! future protocol version without changing the transport codec modules.

pub use crate::transport::{
    Role, Transport as Session, TransportConfig as SessionConfig, TransportEvent as SessionEvent,
    TransportState as SessionState,
};
