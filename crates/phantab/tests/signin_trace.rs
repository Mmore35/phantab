//! The TRACE sentinel (THREAT-MODEL SR-41, SR-42): with every phantab target at
//! TRACE, a sign-in refuses with `debug-logging`; with that check switched off (test builds only), no form
//! of the fixture password is in the captured logs, a result, an error or the guard file. Its own binary,
//! since the subscriber is process-wide. Skips without `PHANTAB_TEST_CHROME`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod signin_support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use phantab::signin::debug_logging_on;
use phantab_testkit::sign_in::{find_leak, fixture_leak_forms};
use phantab_testkit::skip_unless_chrome;
use serde_json::{Value, json};
use signin_support::{Fixture, Lane, Seen};
use tracing_subscriber::util::SubscriberInitExt as _;

/// SR-42's caps over `trace`.
const SR42_TRACE: &str =
    "trace,hyper=info,hyper_util=info,h2=info,tungstenite=info,tokio_tungstenite=info,rmcp=info,reqwest=info";

/// Everything the subscriber writes.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_trace_a_sign_in_refuses_and_nothing_leaks_when_it_runs_anyway() {
    let Some(chrome) = skip_unless_chrome() else { return };
    let capture = Capture::default();
    let writer = capture.clone();
    // `RUST_LOG=trace` as the service must take it (SR-42): every target at TRACE except the third-party
    // wire crates, capped at INFO. Uncapped, `tungstenite::protocol` logs each WebSocket frame at TRACE,
    // and the fill's frame carries the values. `try_init` also routes the `log` crate into this subscriber.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(SR42_TRACE))
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish()
        .try_init()
        .unwrap();
    tracing::trace!("sentinel subscriber up");
    assert!(debug_logging_on(), "a TRACE subscriber is debug logging");

    let fx = Fixture::new();
    let profile = tempfile::Builder::new().prefix("phantab-sign-in-trace-").tempdir().unwrap();
    let lane = Lane::launch(&chrome, profile.path(), fx.provider(), fx.guard()).await;
    let seen = Seen::default();
    let mut errors: Vec<String> = Vec::new();

    // Refused before anything is fetched.
    fx.reset();
    let r = lane.open("a", &fx.url("one")).await;
    let refused = lane.sign("a", &r.id, &json!({})).await.unwrap();
    seen.note(&refused);
    assert_eq!(refused, json!({"status": "failed", "reason": "debug-logging"}));
    assert_eq!(fx.requests().len(), 0);
    assert_eq!(fx.server.posts().len(), 0);
    lane.close(&r).await;

    // Run anyway: a submit, an echo and a code step, every value through the logged paths.
    let anyway = lane.with(Some(fx.provider()), Lane::test_options().with_debug_logging_ignored(true));
    let sign = async |page: &str, want: &[Value]| {
        let r = anyway.open("a", &fx.url(page)).await;
        for w in want {
            let out = anyway.sign("a", &r.id, &json!({})).await.unwrap();
            seen.note(&out);
            assert_eq!(&out, w, "{page}");
        }
        if anyway.has(&r.id) {
            anyway.close(&r).await;
        }
    };
    fx.reset();
    sign("one", &[json!({"status": "submitted"})]).await;
    fx.reset();
    // An echo goes on and says so; its outcome is the page's.
    let r = anyway.open("a", &fx.url("echo")).await;
    let echoed = anyway.sign("a", &r.id, &json!({})).await.unwrap();
    seen.note(&echoed);
    assert_eq!(echoed["echoed"], json!(true), "{echoed}");
    anyway.close(&r).await;
    fx.reset();
    sign("passthencode", &[json!({"status": "next-step"}), json!({"status": "submitted"})]).await;
    let posted = fx.server.posts().len();
    assert!(posted >= 2, "the values really went out ({posted} posts)");
    for id in ["no-such-page", "p0"] {
        errors.push(anyway.sign("a", id, &json!({})).await.unwrap_err().0);
    }

    lane.close_all().await;
    let _ = lane.browser.close().await;

    let forms = fixture_leak_forms();
    let logs = String::from_utf8_lossy(&capture.0.lock().unwrap()).into_owned();
    // phantab itself logs little at TRACE (SR-41: method, id, session, size and timing only).
    assert!(logs.contains("sentinel subscriber up"), "the subscriber captured the run");
    // Name the targets that logged a value, never the lines.
    let leaking: std::collections::BTreeSet<&str> = logs
        .lines()
        .filter(|l| find_leak(l, &forms).is_some())
        .map(|l| l.split_whitespace().nth(2).unwrap_or("?"))
        .collect();
    assert!(leaking.is_empty(), "a value is in the TRACE log, from {leaking:?}");
    let results = seen.results.lock().unwrap().join("\n");
    assert!(find_leak(&results, &forms).is_none(), "a value is in a result");
    assert!(find_leak(&errors.join("\n"), &forms).is_none(), "a value is in an error");
    let guard = std::fs::read_to_string(fx.guard()).unwrap();
    assert!(find_leak(&guard, &forms).is_none(), "a value is in the guard file");
}
