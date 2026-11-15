//! `browser_sign_up` against a real Chrome and a sign-up source held in memory (never a real vault), on
//! the testkit `signup/*` fixtures. Skips without `PHANTAB_TEST_CHROME`.
//!
//! The plan's fixture gate: the password and the confirm field are filled, the saved value equals the
//! page's (compared inside the test, never printed), and no result, record, log line, screenshot refusal
//! or runtime file holds any form of it. Every check on a value is a bool, so a failure prints no value.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod signin_support;

use std::io::Write as _;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::FutureExt as _;
use phantab::signin::{
    MemorySource, Phase, SECRET_ON_PAGE, SignInRecord, before_screenshot, sign_up,
    sign_up_with_source_for_test, sweep_sign_up,
};
use phantab_testkit::skip_unless_chrome;
use serde_json::{Value, json};
use signin_support::{Fixture, Lane, Rec, Seen};

const USER: &str = "new-user@example.test";
/// A login the owner's vault already holds for the fixture origin (the `filled-existing` case).
const SAVED: &str = "Alr3ady-saved_pw!";

/// Every log line this test's process writes, at `info` (what a production build logs).
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Cx {
    lane: Lane,
    fx: Fixture,
    seen: Seen,
    sources: Mutex<Vec<Arc<MemorySource>>>,
}

impl Cx {
    async fn open(&self, page: &str) -> Arc<Rec> {
        self.lane.open("a", &self.fx.signup_url(page)).await
    }

    fn origin(&self) -> String {
        self.fx.server.origin().to_owned()
    }

    fn keep(&self, src: &Arc<MemorySource>) {
        let mut all = self.sources.lock().unwrap();
        if !all.iter().any(|s| Arc::ptr_eq(s, src)) {
            all.push(Arc::clone(src));
        }
    }

    /// Whether any password any source made or holds, in any form the sweep looks for, is in `text`.
    fn leaks(&self, text: &str) -> bool {
        self.sources.lock().unwrap().iter().any(|s| s.found_in(text))
    }

    fn note(&self, result: &Value) {
        self.seen.note(result);
        assert!(!self.leaks(&result.to_string()), "a password is in the result");
    }

    /// `browser_sign_up {pageId, username, ...args}` with `src` as the owner's vault.
    async fn up_on(&self, lane: &Lane, r: &Rec, src: &Arc<MemorySource>, args: Value) -> Value {
        self.keep(src);
        let mut a = json!({"pageId": r.id, "username": USER});
        for (k, v) in args.as_object().into_iter().flatten() {
            a[k] = v.clone();
        }
        let result = sign_up_with_source_for_test(lane, "a", &a, src).await.unwrap();
        self.note(&result);
        assert!(!self.leaks(&r.mark_debug()), "a password is in the record");
        result
    }

    async fn up(&self, r: &Rec, src: &Arc<MemorySource>) -> Value {
        self.up_on(&self.lane, r, src, json!({})).await
    }

    /// One page, one sign-up, the tab closed: the result.
    async fn once(&self, page: &str, src: &Arc<MemorySource>) -> Value {
        let r = self.open(page).await;
        let out = self.up(&r, src).await;
        if self.lane.has(&r.id) {
            self.lane.close(&r).await;
        }
        out
    }

    fn held(&self, r: &Rec) -> Arc<dyn SignInRecord> {
        self.lane.get(&r.id).unwrap()
    }

    /// The page's non-empty field values: how many, and whether every one is the password `src` saved for
    /// this origin and the test's username. Never the values themselves.
    async fn filled(&self, r: &Rec, src: &MemorySource) -> (usize, bool) {
        let values = typed(r).await;
        let origin = self.origin();
        (values.len(), values.iter().all(|v| src.saved_matches(&origin, USER, v)))
    }

    /// The lengths of the page's non-empty field values, and whether every character is in `allowed`.
    async fn shape(&self, r: &Rec, allowed: &dyn Fn(char) -> bool) -> (Vec<usize>, bool) {
        let values = typed(r).await;
        (values.iter().map(String::len).collect(), values.iter().all(|v| v.chars().all(allowed)))
    }
}

/// The non-empty values of every text-like field in every frame and open shadow root (not a checkbox's
/// or a radio's `on`).
const TYPED: &str = "()=>{const roots=[document];for(let i=0;i<roots.length;i++)for(const el of roots[i].querySelectorAll('*'))if(el.shadowRoot)roots.push(el.shadowRoot);return roots.flatMap(x=>[...x.querySelectorAll('input')]).filter(el=>el.type!=='checkbox'&&el.type!=='radio').map(el=>el.value).filter(v=>v);}";

async fn typed(r: &Rec) -> Vec<String> {
    let page = SignInRecord::page(r);
    let mut out = Vec::new();
    for f in page.frames() {
        if let Ok(Ok(Value::Array(vals))) =
            tokio::time::timeout(Duration::from_secs(5), page.evaluate(&f.id, TYPED, vec![])).await
        {
            out.extend(vals.into_iter().filter_map(|v| v.as_str().map(str::to_owned)));
        }
    }
    out
}

/// Waits for the page's title to be `want` (after a navigation the page itself started).
async fn title_becomes(r: &Rec, want: &str) -> bool {
    let page = SignInRecord::page(r);
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        if let Ok(main) = page.main_frame() {
            let read = tokio::time::timeout(
                Duration::from_secs(2),
                page.evaluate_main(&main, "()=>document.title", vec![]),
            )
            .await;
            if matches!(read, Ok(Ok(ref v)) if v == want) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn status(s: &str) -> Value {
    json!({"status": s})
}

fn status_reason(s: &str, r: &str) -> Value {
    json!({"status": s, "reason": r})
}

fn source() -> Arc<MemorySource> {
    Arc::new(MemorySource::default())
}

fn today() -> String {
    let days = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 86_400;
    // Howard Hinnant's civil_from_days, as signup.rs dates an item.
    let z = i64::try_from(days).unwrap() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_sign_up_against_a_real_chrome_and_a_memory_source() {
    let Some(chrome) = skip_unless_chrome() else { return };
    let logs = Logs::default();
    let writer = logs.clone();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .try_init();
    let fx = Fixture::new();
    let profile = tempfile::Builder::new().prefix("phantab-sign-up-profile-").tempdir().unwrap();
    let lane = Lane::launch(&chrome, profile.path(), fx.provider(), fx.guard()).await;
    let cx = Cx { lane, fx, seen: Seen::default(), sources: Mutex::default() };
    cx.fx.reset();
    let mut failed: Vec<String> = Vec::new();
    let only = std::env::var("PHANTAB_SIGNUP_CASE").ok();

    macro_rules! case {
        ($name:expr, $body:expr) => {{
            let name: String = $name.to_string();
            if only.as_deref().is_none_or(|o| name.contains(o)) {
                let began = Instant::now();
                let outcome = AssertUnwindSafe(Box::pin($body)).catch_unwind().await;
                eprintln!(
                    "case {} ({} ms): {}",
                    name,
                    began.elapsed().as_millis(),
                    if outcome.is_ok() { "ok" } else { "FAILED" }
                );
                if outcome.is_err() {
                    failed.push(name);
                    cx.lane.close_all().await;
                }
            }
        }};
    }

    case!("the gate: a new password saved, filled, refused a screenshot, submitted, then cleared", async {
        cx.fx.reset();
        let src = source();
        let r = cx.open("basic").await;
        assert_eq!(cx.up(&r, &src).await, status("filled"));
        assert_eq!((src.count(), src.creates()), (1, 1));
        assert_eq!(src.names(), vec![format!("127.0.0.1 (sign-up {})", today())]);
        let (n, saved) = cx.filled(&r, &src).await;
        assert_eq!(n, 1, "only the password field is filled");
        assert!(saved, "the page's value is not the saved password");
        let (lengths, allowed) = cx.shape(&r, &|c| c.is_ascii_alphanumeric() || "!@$%*-_".contains(c)).await;
        assert_eq!(lengths, vec![20]);
        assert!(allowed, "a character outside the alphabet");
        // While it is on the page: marked, and a screenshot is refused with a message that holds no value.
        assert!(r.marked());
        let e = before_screenshot(&cx.lane, &cx.held(&r)).await.unwrap_err();
        assert_eq!(e.0, SECRET_ON_PAGE);
        assert!(e.0.starts_with("secret-on-page"));
        assert!(!cx.leaks(&e.0));
        // phantab fills; the agent submits. The site gets it once, in the POST body only.
        r.eval_main("()=>{document.querySelector('form').requestSubmit();return 1}").await;
        assert!(title_becomes(&r, "Landed").await, "the form did not submit");
        let posts = cx.fx.server.posts();
        assert_eq!(posts.len(), 1);
        let sent = posts[0].form("pw").unwrap_or_default();
        assert!(src.saved_matches(&cx.origin(), USER, &sent), "the site did not get the saved password");
        assert!(!cx.leaks(&posts[0].url), "the password is in the address");
        // The page it landed on holds no value: the next sweep clears the mark and screenshots work again.
        assert!(!sweep_sign_up(&cx.lane, &cx.held(&r)).await.unwrap());
        assert!(!r.marked());
        before_screenshot(&cx.lane, &cx.held(&r)).await.unwrap();
        cx.lane.close(&r).await;
    });

    case!("the gate: the password and the confirm field get the same value, and no box is ticked", async {
        let src = source();
        let r = cx.open("confirm").await;
        assert_eq!(cx.up(&r, &src).await, status("filled"));
        let (n, saved) = cx.filled(&r, &src).await;
        assert_eq!(n, 2);
        assert!(saved, "a field is not the saved password");
        assert_eq!(r.eval_main("()=>document.querySelector('[name=terms]').checked").await, json!(false));
        assert_eq!(r.eval_main("()=>location.pathname").await, json!("/signup/confirm"));
        cx.lane.close(&r).await;
    });

    case!("an existing login fills its own password; regenerate replaces it", async {
        let src = Arc::new(MemorySource::default().holding(&cx.origin(), USER, SAVED));
        let r = cx.open("basic").await;
        assert_eq!(cx.up(&r, &src).await, status("filled-existing"));
        assert_eq!(src.count(), 1);
        let values = typed(&r).await;
        assert!(values.iter().any(|v| v == SAVED), "the saved password was not filled");
        cx.lane.close(&r).await;
        let r = cx.open("basic").await;
        assert_eq!(cx.up_on(&cx.lane, &r, &src, json!({"regenerate": true})).await, status("filled"));
        assert_eq!(src.count(), 1);
        let (n, saved) = cx.filled(&r, &src).await;
        assert!(n == 1 && saved, "the page's value is not the replaced password");
        assert!(!src.saved_matches(&cx.origin(), USER, SAVED), "regenerate kept the old password");
        cx.lane.close(&r).await;
        // Another username at the same origin is a new login, under the agent's own name for it.
        let r = cx.open("basic").await;
        let args = json!({"username": "second@example.test", "name": "Second account"});
        assert_eq!(cx.up_on(&cx.lane, &r, &src, args).await, status("filled"));
        assert_eq!(src.count(), 2);
        assert!(src.names().contains(&"Second account".to_owned()));
        cx.lane.close(&r).await;
    });

    case!("maxlength cuts the password; below twelve is refused before the vault", async {
        let src = source();
        let r = cx.open("maxlength").await;
        assert_eq!(cx.up(&r, &src).await, status("filled"));
        let (lengths, _) = cx.shape(&r, &|_| true).await;
        assert_eq!(lengths, vec![16, 16]);
        cx.lane.close(&r).await;
        let src = source();
        assert_eq!(cx.once("shortmax", &src).await, status_reason("not-a-sign-up", "password-too-short"));
        assert_eq!(src.creates(), 0);
    });

    case!("passwordrules narrow the alphabet and the length", async {
        let src = source();
        let r = cx.open("rules").await;
        assert_eq!(cx.up(&r, &src).await, status("filled"));
        let (lengths, allowed) = cx.shape(&r, &|c| c.is_ascii_lowercase() || c.is_ascii_digit()).await;
        assert_eq!(lengths, vec![14]);
        assert!(allowed, "a character the rules do not allow");
        cx.lane.close(&r).await;
    });

    for page in ["shadow", "framed"] {
        case!(format!("a sign-up form in {page}"), async {
            let src = source();
            let r = cx.open(page).await;
            assert_eq!(cx.up(&r, &src).await, status("filled"));
            let (n, saved) = cx.filled(&r, &src).await;
            assert!(n == 1 && saved, "the field is not the saved password");
            cx.lane.close(&r).await;
        });
    }

    for (page, reason) in [
        ("crossframe", "third-party-frame"),
        ("elsewhere", "form-posts-elsewhere"),
        ("pay", "pay-button"),
        ("card", "card-fields"),
        ("getform", "get-form"),
        ("signin", "sign-in-form"),
        ("change", "change-password"),
    ] {
        case!(format!("{page}: refused ({reason}), nothing asked of the vault, nothing filled"), async {
            let src = source();
            let r = cx.open(page).await;
            assert_eq!(cx.up(&r, &src).await, status_reason("not-a-sign-up", reason));
            assert_eq!(src.creates(), 0);
            assert!(typed(&r).await.is_empty());
            assert!(!r.marked());
            cx.lane.close(&r).await;
        });
    }

    case!("a page that is not https is refused", async {
        let src = source();
        let strict = cx.lane.with(None, Lane::test_options().with_loopback(false));
        let r = cx.open("basic").await;
        assert_eq!(cx.up_on(&strict, &r, &src, json!({})).await, status_reason("not-a-sign-up", "not-https"));
        assert_eq!(src.creates(), 0);
        cx.lane.close(&r).await;
    });

    case!("a show-password toggle blanks the field before it is shown", async {
        let src = source();
        let r = cx.open("reveal").await;
        assert_eq!(cx.up(&r, &src).await, status("filled"));
        r.eval_main("()=>{document.getElementById('show').click();return 1}").await;
        let shown = r
            .eval_main("()=>[document.getElementById('pw').type,document.getElementById('pw').value==='']")
            .await;
        assert_eq!(shown, json!(["text", true]));
        assert!(!sweep_sign_up(&cx.lane, &cx.held(&r)).await.unwrap());
        assert!(!r.marked());
        cx.lane.close(&r).await;
    });

    case!("a copy in another field is blanked; the password field keeps it", async {
        let src = source();
        let r = cx.open("copy").await;
        assert_eq!(cx.up(&r, &src).await, status("filled"));
        assert_eq!(r.eval_main("()=>document.getElementById('echo').value===''").await, json!(true));
        let (n, saved) = cx.filled(&r, &src).await;
        assert!(n == 1 && saved, "the password field lost the password");
        assert!(sweep_sign_up(&cx.lane, &cx.held(&r)).await.unwrap());
        cx.lane.close(&r).await;
    });

    case!("a copy in the page's text ends the page", async {
        let src = source();
        let r = cx.open("copytext").await;
        let target = r.target().to_owned();
        assert_eq!(cx.up(&r, &src).await, status("leak-stopped"));
        assert!(!cx.lane.has(&r.id));
        assert!(!cx.lane.tab_open(&target).await);
    });

    case!("the vault's own refusals answer as they are, and fill nothing", async {
        for refusal in ["locked", "ask-first", "ambiguous", "refused", "provider-failed"] {
            let src = Arc::new(MemorySource::refusing(refusal));
            let r = cx.open("basic").await;
            assert_eq!(cx.up(&r, &src).await, status(refusal));
            assert_eq!(src.creates(), 1);
            assert!(typed(&r).await.is_empty());
            assert!(!r.marked());
            cx.lane.close(&r).await;
        }
    });

    case!("no source, and a command source, start nothing", async {
        cx.fx.reset();
        let r = cx.open("basic").await;
        let args = json!({"pageId": r.id, "username": USER});
        let none = cx.lane.with(None, Lane::test_options());
        let result = sign_up(&none, "a", &args).await.unwrap();
        cx.note(&result);
        assert_eq!(result, status("no-provider"));
        // The lane's own provider is the fake command provider: it has no create, so it is never run.
        let result = sign_up(&cx.lane, "a", &args).await.unwrap();
        cx.note(&result);
        assert_eq!(result, status("no-provider-create"));
        assert!(cx.fx.requests().is_empty(), "the command provider was run");
        assert!(typed(&r).await.is_empty());
        cx.lane.close(&r).await;
    });

    case!("owner-has-page, busy and blank-unconfirmed before anything starts", async {
        let src = source();
        let r = cx.open("basic").await;
        r.set_paused(true);
        assert_eq!(cx.up(&r, &src).await, status("owner-has-page"));
        r.set_paused(false);
        r.set_phase(Some(Phase::Running));
        assert_eq!(cx.up(&r, &src).await, status("busy"));
        r.set_phase(Some(Phase::Unblanked));
        assert_eq!(cx.up(&r, &src).await, status_reason("failed", "blank-unconfirmed"));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(src.creates(), 0);
        cx.lane.close(&r).await;
    });

    case!("a bad argument, an unknown page, or another session's, is an error that names no value", async {
        let src = source();
        let r = cx.open("basic").await;
        for args in [
            json!({"pageId": r.id}),
            json!({"pageId": r.id, "username": ""}),
            json!({"pageId": r.id, "username": "a\nb"}),
            json!({"pageId": r.id, "username": USER, "name": 5}),
        ] {
            assert!(sign_up_with_source_for_test(&cx.lane, "a", &args, &src).await.is_err(), "{args}");
        }
        for (client, id) in [("a", json!("no-such-page")), ("b", json!(r.id))] {
            let args = json!({"pageId": id, "username": USER});
            let e = sign_up_with_source_for_test(&cx.lane, client, &args, &src).await.unwrap_err();
            assert_eq!(e.0, "Unknown page or page belongs to another agent session.");
        }
        assert_eq!(src.creates(), 0);
        cx.lane.close(&r).await;
    });

    case!("no leak: no password is in a result, the record, a log line or the runtime folder", async {
        if only.is_some() {
            return;
        }
        let seen: Vec<String> = cx.seen.statuses.lock().unwrap().iter().cloned().collect();
        for want in ["filled", "filled-existing", "not-a-sign-up", "leak-stopped", "no-provider-create"] {
            assert!(seen.iter().any(|s| s == want), "{want} was not reached");
        }
        assert!(cx.sources.lock().unwrap().iter().map(|s| s.count()).sum::<usize>() >= 5);
        let results = cx.seen.results.lock().unwrap().join("\n");
        assert!(!cx.leaks(&results), "tool results hold a password");
        let _ = std::io::stderr().flush();
        let logged = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
        assert!(!cx.leaks(&logged), "the log holds a password");
        for entry in walk(cx.fx.runtime.path()) {
            let text = String::from_utf8_lossy(&std::fs::read(&entry).unwrap_or_default()).into_owned();
            assert!(!cx.leaks(&text), "{} holds a password", entry.display());
        }
    });

    cx.lane.close_all().await;
    let _ = cx.lane.browser.close().await;
    assert!(failed.is_empty(), "failed cases: {failed:#?}");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
