//! phantab: lets AI agents use the owner's own signed-in Chrome, in windows the owner never sees.
//! Module map: `docs/ARCHITECTURE.md` § Pieces.
#![forbid(unsafe_code)] // SR-58: unsafe lives only in phantab-window's OS modules.

pub mod bitwarden;
pub mod bridge;
pub mod cdp_methods;
pub mod cli;
pub mod engine;
pub mod engine_api;
pub mod extension_files;
pub mod hello;
pub mod host;
pub mod install;
pub mod mcp;
pub mod mode;
pub mod page_js;
pub mod panic_hook;
pub mod paths;
pub mod runtime;
pub mod service;
pub mod sign_in_guard;
pub mod signin;
pub mod util;
pub mod vaults;
pub mod work;
