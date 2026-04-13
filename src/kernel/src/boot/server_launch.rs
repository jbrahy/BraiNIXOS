//! Boot-time re-export of server process creation from `process::server_launch`.
//!
//! The canonical implementation lives in `crate::process::server_launch` so it
//! compiles on host targets (aarch64-apple-darwin) for unit testing. This module
//! re-exports the public API under the `boot::server_launch` path used by
//! `boot::phases` on x86_64.

pub use crate::process::server_launch::create_server_process;
pub use crate::process::server_launch::grant_initial_capability_to_server;
pub use crate::process::server_launch::ServerLaunchError;
pub use crate::process::server_launch::ServerProcessHandle;
