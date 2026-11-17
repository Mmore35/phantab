//! phantab-cdp: the CDP layer. See docs/ARCHITECTURE.md § CDP layer.
//!
//! A small CDP (Chrome devtools protocol) client for exactly one page over any [`Transport`]: the extension
//! relay ([`RelayTransport`]) or a browser-level [`Connection`] over Chrome's debugging pipe or a
//! WebSocket ([`Browser`]). It replaces the parts of puppeteer-core 25 the Node engine used; every
//! deliberate difference is noted where it lives.
#![forbid(unsafe_code)] // SR-58: unsafe lives only in phantab-window's OS modules.

mod browser;
mod connection;
mod devtools;
mod dom;
mod error;
mod events;
mod handle;
mod input;
mod keyboard_layout;
mod page;
mod pipe;
mod transport;
mod ws;

pub use browser::{Browser, LaunchOptions, default_args, spawn_guard};
pub use connection::Connection;
pub use devtools::{
    CONSOLE_KEPT, CONSOLE_TEXT, ConsoleMessage, ConsoleRead, Evaluated, NetworkRead, REQUESTS_KEPT, Redirect,
    Request, clean_headers,
};
#[cfg(feature = "test-seams")]
pub use dom::Unsettled;
pub use dom::{COVERED_PREFIX, ClickError};
pub use error::CdpError;
pub use events::{DEVTOOLS_EVENTS, EVENTS, reads_devtools_event, reads_event};
pub use handle::{Arg, JsHandle};
pub use input::combo_keys;
pub use page::{
    BoundingBox, DIALOG_MESSAGE_LIMIT, Dialog, FrameId, FrameInfo, History, HistoryEntry, PASSKEY_WATCH,
    Page, PageOptions, PasskeyAsks,
};
pub use transport::{RelayFuture, RelaySendFn, RelayTransport, SessionId, Transport, TransportEvent};
