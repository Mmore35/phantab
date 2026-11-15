//! `browser_sign_in`: types and submits a saved login on the page, and answers only a
//! status. A value exists in the service as one local of the call, and goes in no record, result, error,
//! log line or file (THREAT-MODEL SR-38 to SR-47).
//!
//! - [`host`]: what the call needs from its engine ([`Host`], [`SignInRecord`]).
//! - [`pipeline`]: the call itself, one function per step.
//! - [`signup`]: `browser_sign_up`, which fills a sign-up form with a new password; [`generate`]: that
//!   password.
//! - [`source`]: which saved-login source the config picks ([`source::CredentialSource`]).
//! - [`provider`], [`seal`]: the external provider command and its sealed answer.
//! - [`bitwarden`]: the built-in Bitwarden source (docs/BITWARDEN.md).
//! - [`web`]: URL rules and the leak forms; [`page`]: the in-page functions, verbatim.
//! - [`secret`]: zeroizing holders; [`label`]: the only answers that leave.
//! - [`options`]: time budgets and the test-only switches; the debug-logging check.

pub(crate) mod bitwarden;
mod generate;
mod host;
mod label;
mod options;
mod page;
pub(crate) mod passkey;
mod pipeline;
mod provider;
mod seal;
mod secret;
mod signup;
pub(crate) mod source;
mod web;

pub(crate) use pipeline::challenge_shows;
pub(crate) use web::challenge_frame;

pub use host::{Host, Phase, SignInRecord, check_call};
pub(crate) use label::Outcome;
pub use options::{Options, Times, debug_logging_on};
pub use pipeline::sign_in;
#[cfg(feature = "test-seams")]
pub use provider::ask_for_test;
pub(crate) use provider::program_is_absolute;
#[cfg(any(test, feature = "test-seams"))]
pub use seal::{request_digest, seal};
#[cfg(test)]
pub(crate) use secret::Secret;
pub use secret::{Echo, Leftover, OnPage};

/// The [`Echo`] a sign-in that filled `password` and `code` leaves when the site shows it back, for the
/// engine's tests.
#[cfg(test)]
pub(crate) fn echo_for_test(password: &str, code: Option<&str>) -> Echo {
    let password = Secret::new(password.to_owned());
    let code = code.map(|c| Secret::new(c.to_owned()));
    Echo::new(&web::echo_forms(Some(&password)), code.as_ref(), true).expect("a random key")
}
#[cfg(feature = "test-seams")]
pub use signup::sign_up_with_source_for_test;
pub use signup::{SECRET_ON_PAGE, before_screenshot, sign_up, sweep_sign_up};
#[cfg(feature = "test-seams")]
pub use source::MemorySource;
#[cfg(feature = "test-seams")]
pub use source::{bitwarden_ask_for_test, bitwarden_create_for_test};
