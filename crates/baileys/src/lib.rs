//! WhatsApp Web client library. A Rust port of Baileys.
pub mod proto {
    pub use waproto::*;
}
pub mod auth;
pub mod crypto;
pub mod defaults;
pub mod error;
pub mod events;
pub mod signal;
pub mod socket;
pub mod types;
pub mod utils;
pub mod wabinary;
pub mod wam;
pub mod wausync;
