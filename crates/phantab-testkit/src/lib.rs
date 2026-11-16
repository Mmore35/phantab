//! Test support shared by every lane (docs/TESTING.md).
//!
//! - [`skip_unless_chrome`]: the Chrome a browser test drives, or a printed skip.
//! - [`TempDir`]: a scratch folder (runtime, profile, config) removed on drop.
//! - [`FixtureServer`]: the fixture pages over HTTP on two loopback origins,
//!   `http://127.0.0.1:<a>` and its cross-site twin `http://localhost:<b>`,
//!   recording every request so a test can say what was sent, and where.
//! - [`sign_in`]: the values a fake saved-login provider hands out, and the
//!   encoded forms a no-leak check searches for.
//! - [`parity`]: the parity benchmark's account site (`bench/parity`), which the fixture server serves.
//!
//! Nothing here touches the owner's Chrome, profile, registry or client configs.
#![forbid(unsafe_code)] // SR-58: unsafe lives only in phantab-window's OS modules.

mod chrome;
mod http;
mod pages;
pub mod parity;
mod server;
pub mod sign_in;
mod temp;

pub use chrome::{CHROME_ENV, skip_unless_chrome, test_native_host_name};
pub use pages::{fixture_paths, fixture_source, fixtures_dir, foreign_extension_dir};
pub use server::{FixtureServer, Gate, Listener, RecordedRequest};
pub use temp::TempDir;
