//! Same as src/Socket. Upstream layers functions by object spread. Here one `Socket` struct holds
//! shared state, and each file adds its methods in an `impl` block, with the same names in snake_case.
//!
//! Threads, which replace the event loop of upstream:
//! - One reader thread reads the transport, runs Noise, completes the waiters of `query`, and hands
//!   each other frame to a lane. No handler and no event listener runs on it, with one exception:
//!   a frame or an error that ends the connection, because nothing can be waited for after that.
//! - Two lanes are worker threads: one for messages, one for everything else. A lane runs its work in
//!   order, so a handler can call `query` and block: the reader still runs. A lane has a thread only
//!   while it has work, so an idle connection has only the reader.
//! - Keep-alive and other timers use the shared timer of `utils::time`.
//! - Fire-and-forget promises are jobs on the control lane. A short thread does the work that waits
//!   for a long time or for the control lane: the pre-key upload and the placeholder resend.
//! `end` stops all of these. See `Socket::end`.
pub mod business;
pub mod chats;
pub mod client;
pub mod communities;
pub mod groups;
pub mod messages_recv;
pub mod messages_send;
pub mod mex;
pub mod newsletter;
#[allow(clippy::module_inception)]
pub mod socket;
pub use chats::build_profile_picture_query_content;
pub use client::{Transport, WebSocketClient};
pub use communities::extract_community_metadata;
pub use groups::extract_group_metadata;
pub use socket::{Socket, make_socket};
pub(crate) use socket::LaneId;

use crate::error::Result;
use crate::types::SocketConfig;

/// `makeWASocket`. Start from `default_connection_config()` and set `auth`.
///
/// Different from upstream: this does not touch the network. Add your listeners, then call
/// `connect`. With threads, a socket that connects by itself could emit before you listen.
pub fn make_wa_socket(config: SocketConfig) -> Result<Socket> {
    fixed_mmap_threshold();
    make_socket(config)
}
/// Different from upstream, for a process that runs for a long time. glibc raises its mmap threshold to the size of
/// each large block that is freed, up to 32 MB. After the first history chunk, the large buffers of a sync then come
/// from a thread heap, and their pages stay in RAM after the sync: on a real account, 32 MB free for 2 MB in use.
/// A fixed threshold, the glibc default of 128 KiB, gives each large block back to the system when it is freed.
#[cfg(all(feature = "native", target_env = "gnu"))]
fn fixed_mmap_threshold() {
    const M_MMAP_THRESHOLD: i32 = -3;
    unsafe extern "C" {
        fn mallopt(param: i32, value: i32) -> i32;
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: mallopt changes only a setting of this process's allocator.
    ONCE.call_once(|| unsafe {
        mallopt(M_MMAP_THRESHOLD, 128 * 1024);
    });
}
#[cfg(not(all(feature = "native", target_env = "gnu")))]
fn fixed_mmap_threshold() {}
/// Runs when a lane has been idle for `LANE_IDLE_MS`, so once after each burst of work. The blocks of a burst, such
/// as a decoded history chunk, are small and come from a thread heap. glibc gives back only the top of that heap,
/// and a few long-lived blocks keep it in RAM: on a real account, 26 MB free for 2 MB in use after the sync.
/// `malloc_trim` gives back every free page in it.
#[cfg(all(feature = "native", target_env = "gnu"))]
pub(crate) fn release_free_memory() {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    // SAFETY: malloc_trim only gives free pages back to the system.
    unsafe { malloc_trim(0) };
}
#[cfg(not(all(feature = "native", target_env = "gnu")))]
pub(crate) fn release_free_memory() {}
