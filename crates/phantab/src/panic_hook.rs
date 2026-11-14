//! The panic hook (THREAT-MODEL SR-59). A panic message can hold page text, a URL or a value read from
//! an account, so the hook prints where the panic happened and never its payload. Release builds abort
//! after it (`panic = "abort"`), so a panic never leaves a half-working service behind.

use std::io::Write as _;

/// Replaces the default hook. Call first thing in `main`.
pub fn install() {
    std::panic::set_hook(Box::new(|info| {
        let at = info.location().map_or_else(
            || "an unknown place".to_owned(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let _ = writeln!(
            std::io::stderr(),
            "phantab: internal error at {at}. Its message is not shown, since it can hold page text."
        );
    }));
    test_seam();
}

/// Test builds only: `PHANTAB_TEST_PANIC=<payload>` panics with that payload, so a test can check the
/// hook's output.
fn test_seam() {
    #[cfg(feature = "test-seams")]
    #[allow(clippy::panic, reason = "the seam exists to panic; test builds only")]
    if let Some(payload) = std::env::var_os("PHANTAB_TEST_PANIC") {
        std::panic::panic_any(payload.to_string_lossy().into_owned());
    }
}
