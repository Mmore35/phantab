//! `browser_sign_in` against a real Chrome and the fake provider: every documented
//! sign-in case, on the testkit `sign-in/*` fixtures. Skips without `PHANTAB_TEST_CHROME`.
//!
//! One test, one Chrome, cases in a fixed order: the last case checks every status was reached and
//! no form of the fixture password is in a result, an error or the runtime folder.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod signin_support;

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::FutureExt as _;
use phantab::sign_in_guard::{clear_guard, iso, now_millis};
use phantab::signin::{Phase, SignInRecord as _, check_call};
use phantab_testkit::sign_in::{CODE, PASSWORD, USERNAME, find_leak, fixture_leak_forms};
use phantab_testkit::{RecordedRequest, skip_unless_chrome};
use serde_json::{Value, json};
use signin_support::{ALL_STATUSES, Fixture, Lane, Rec, Seen};

struct Cx {
    lane: Lane,
    fx: Fixture,
    seen: Seen,
}

impl Cx {
    async fn open(&self, page: &str) -> Arc<Rec> {
        self.lane.open("a", &self.fx.url(page)).await
    }

    async fn open_watched(&self, page: &str) -> Arc<Rec> {
        self.lane.open_watched("a", &self.fx.url(page)).await
    }

    /// Signs: no value in the result, and none left in a field unless the page is held.
    async fn sign_on(&self, lane: &Lane, r: &Rec, args: Value) -> Value {
        let result = lane.sign("a", &r.id, &args).await.unwrap();
        self.seen.note(&result);
        assert!(find_leak(&result.to_string(), &fixture_leak_forms()).is_none(), "a value is in the result");
        if self.lane.has(&r.id) && r.phase() != Some(Phase::Unblanked) {
            let left = r.input_values().await;
            let status = &result["status"];
            assert!(!left.iter().any(|v| v == PASSWORD), "{status} left the password in a field");
            assert!(!left.iter().any(|v| v == CODE), "{status} left the code in a field");
        }
        result
    }

    async fn sign(&self, r: &Rec) -> Value {
        self.sign_on(&self.lane, r, json!({})).await
    }

    /// After a site showed a value back: the call went on and said so, the page is
    /// still the agent's, and the echoes handed to the host leave no form of a value in the page's URL,
    /// title or markup, which do show one. A failure names the form's index, never the form.
    async fn echoed(&self, r: &Rec, result: &Value) {
        assert_ne!(result["status"], json!("leak-stopped"), "{result}");
        assert_eq!(result["echoed"], json!(true), "{result}");
        assert!(result["note"].as_str().is_some_and(|n| n.contains("redacts")), "{result}");
        assert!(self.lane.has(&r.id), "the page stays the agent's");
        let shown = r
            .eval_main("()=>[location.href,document.title,document.documentElement.outerHTML].join(' ')")
            .await;
        let shown = shown.as_str().unwrap().to_owned();
        let forms = fixture_leak_forms();
        assert!(find_leak(&shown, &forms).is_some(), "the fixture shows a value");
        let echoes = self.lane.echoes.lock().unwrap().clone();
        assert!(!echoes.is_empty(), "the host was handed an echo");
        let mut redacted = shown;
        for echo in &echoes {
            if let Some(out) = echo.redact(&redacted) {
                redacted = out;
            }
        }
        let left = forms.iter().position(|f| redacted.contains(f.as_str()));
        assert_eq!(left, None, "form {left:?} of the value is left after the redaction");
        assert!(redacted.contains("[redacted]"));
    }

    async fn once(&self, page: &str) -> Value {
        self.fx.reset();
        let r = self.open(page).await;
        let out = self.sign(&r).await;
        if self.lane.has(&r.id) {
            self.lane.close(&r).await;
        }
        out
    }

    fn posts(&self) -> Vec<RecordedRequest> {
        self.fx.server.posts()
    }

    fn post_field(&self, i: usize, name: &str) -> Option<String> {
        self.posts().get(i).and_then(|p| p.form(name))
    }

    /// Whether POST `i` carried `value` in `name`. A bool, so a failure does not print the value.
    fn posted(&self, i: usize, name: &str, value: &str) -> bool {
        self.post_field(i, name).as_deref() == Some(value)
    }

    fn requests(&self) -> Vec<Value> {
        self.fx.requests()
    }

    fn url_any(&self, i: usize, pred: &dyn Fn(&str) -> bool) -> bool {
        self.requests()[i]["urls"].as_array().unwrap().iter().any(|u| pred(u.as_str().unwrap()))
    }

    fn control(&self, fields: &Value) {
        self.fx.control(fields);
    }

    /// Signs while `during` runs when the page reaches `/hook/detach-me`.
    async fn sign_with_hook<F, Fut>(&self, r: &Rec, during: F) -> Value
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        let gate = self.fx.server.gate("detach-me");
        let hook = async {
            if gate.arrived(Duration::from_secs(20)).await {
                during().await;
            }
            gate.release();
        };
        let (result, ()) = tokio::join!(self.sign(r), hook);
        drop(gate);
        result
    }
}

fn status(s: &str) -> Value {
    json!({"status": s})
}

fn status_reason(s: &str, r: &str) -> Value {
    json!({"status": s, "reason": r})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_sign_in_against_a_real_chrome_and_a_fake_provider() {
    let Some(chrome) = skip_unless_chrome() else { return };
    let fx = Fixture::new();
    let profile = tempfile::Builder::new().prefix("phantab-sign-in-profile-").tempdir().unwrap();
    let lane = Lane::launch(&chrome, profile.path(), fx.provider(), fx.guard()).await;
    let cx = Cx { lane, fx, seen: Seen::default() };
    cx.fx.control(&json!({}));
    let mut failed: Vec<String> = Vec::new();
    let only = std::env::var("PHANTAB_SIGNIN_CASE").ok();

    macro_rules! case {
        ($name:expr, $body:expr) => {{
            let name: String = $name.to_string();
            if only.as_deref().is_none_or(|o| name.contains(o)) {
                let began = Instant::now();
                // Boxed: 67 case futures inline in one test future overflow the test thread's stack, which
                // aborts the process and leaves this Chrome running, holding the output pipe open.
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

    case!("one-page form: both values sent once, in one POST", async {
        assert_eq!(cx.once("one").await, status("submitted"));
        assert_eq!(cx.posts().len(), 1);
        assert_eq!(cx.post_field(0, "user").as_deref(), Some(USERNAME));
        assert!(cx.posted(0, "pass", PASSWORD), "the password was not posted");
        let q = &cx.requests()[0];
        assert_eq!(q["want"], json!(["username", "password"]));
        assert_eq!(q["accountKey"], Value::Null);
        assert_eq!(q["account"], Value::Null);
        assert!(cx.url_any(0, &|u| u.ends_with("/one")));
        assert!(q["urls"].as_array().unwrap().iter().all(|u| !u.as_str().unwrap().contains('?')));
    });

    case!("username then password on two pages: the first step fetches no password", async {
        cx.fx.reset();
        let r = cx.open("userstep").await;
        assert_eq!(cx.sign(&r).await, status("next-step"));
        assert_eq!(cx.sign(&r).await, status("submitted"));
        let q = cx.requests();
        assert_eq!(q[0]["want"], json!(["username"]));
        assert_eq!(q[1]["want"], json!(["password"]));
        assert_eq!(q[1]["accountKey"], "account-one");
        assert_eq!(cx.post_field(0, "email").as_deref(), Some(USERNAME));
        assert!(cx.posted(1, "pass", PASSWORD), "the value was not posted");
        cx.lane.close(&r).await;
    });

    case!("password then code, and another account answering a held page is refused", async {
        cx.fx.reset();
        let r = cx.open("passthencode").await;
        assert_eq!(cx.sign(&r).await, status("next-step"));
        cx.control(&json!({"accountKey": "account-two"}));
        assert_eq!(cx.sign(&r).await, status("refused"));
        cx.control(&json!({}));
        assert_eq!(cx.sign(&r).await, status("submitted"));
        assert_eq!(cx.requests()[2]["want"], json!(["code"]));
        assert!(cx.posted(1, "otp", CODE), "the value was not posted");
        cx.lane.close(&r).await;
    });

    for (name, page) in [
        ("a frame", "framed"),
        ("a nested frame", "nested"),
        ("a cross-site frame", "crossframe"),
        ("a shadow root", "shadow"),
        ("no <form>", "noform"),
    ] {
        case!(format!("form in {name}"), async {
            assert_eq!(cx.once(page).await, status("submitted"));
            assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
            if page == "crossframe" {
                assert!(cx.url_any(0, &|u| u.contains("localhost")));
            }
        });
    }

    case!("a form with its button outside it: the sign-in control is found", async {
        cx.fx.reset();
        let r = cx.open("outside").await;
        assert_eq!(cx.sign(&r).await, status("next-step"));
        assert_eq!(cx.requests()[0]["want"], json!(["username"]));
        assert_eq!(cx.post_field(0, "email").as_deref(), Some(USERNAME));
        cx.lane.close(&r).await;
    });

    for (name, page) in [
        ("deep in the page", "deep"),
        (
            "beside a \"Sign in with\" button, disabled until typed in, with the password held back",
            "inertpass",
        ),
    ] {
        case!(format!("a username step with its button {name}"), async {
            cx.fx.reset();
            let r = cx.open(page).await;
            assert_eq!(cx.sign(&r).await, status("next-step"));
            assert_eq!(cx.requests()[0]["want"], json!(["username"]));
            assert_eq!(cx.post_field(0, "email").as_deref(), Some(USERNAME));
            assert_eq!(cx.sign(&r).await, status("submitted"));
            assert!(cx.posted(1, "pass", PASSWORD), "the value was not posted");
            cx.lane.close(&r).await;
        });
    }

    case!("a username step with two sign-in buttons is a wall, not a refusal", async {
        assert_eq!(cx.once("twobuttons").await, status_reason("wall", "no-clear-submit"));
        assert_eq!(cx.requests().len(), 0);
    });

    case!("another form's button is never taken for this form's", async {
        assert_eq!(cx.once("otherform").await, status("submitted"));
        assert_eq!(cx.posts().len(), 1);
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
        assert!(!cx.posts()[0].path.contains("wrong"));
    });

    case!("no form and no button: a wall, with no fetch", async {
        assert_eq!(cx.once("nobutton").await, status_reason("wall", "no-clear-submit"));
        assert_eq!(cx.requests().len(), 0);
    });

    case!("a React-style field takes the fill, and blanks when the page keeps it", async {
        cx.fx.reset();
        let r = cx.open("react").await;
        assert_eq!(cx.sign(&r).await, status("still-asking"));
        assert!(
            cx.post_field(0, "pass").as_deref() == Some(PASSWORD),
            "the site read the value through its own state"
        );
        assert_eq!(r.eval_main("()=>window.reactState").await, json!(""), "its state was blanked too");
        cx.lane.close(&r).await;
    });

    case!("a site that opens a frame on submit is the next step", async {
        assert_eq!(cx.once("opensframe").await, status("next-step"));
    });

    case!("a field hidden, not removed, after submit is blanked", async {
        cx.fx.reset();
        let r = cx.open("hides").await;
        assert_eq!(cx.sign(&r).await, status("submitted"));
        assert_eq!(r.eval_main("()=>document.querySelector('#p').value").await, json!(""));
        cx.lane.close(&r).await;
    });

    case!("a visible field with a code beside it is the next step, after blanking", async {
        assert_eq!(cx.once("codebeside").await, status("next-step"));
    });

    for (page, reason) in [
        ("newpass", "new-password"),
        ("twopass", "two-passwords"),
        ("card", "card-fields"),
        ("cardframe", "card-fields"),
        ("pay", "pay-button"),
        ("subscribe", "not-sign-in-step"),
        ("forgot-password", "not-sign-in-step"),
        ("signup", "sign-up"),
        ("blank", "no-field"),
    ] {
        case!(format!("/{page} is not a sign-in, and fetches nothing"), async {
            let mut want = status_reason("not-a-sign-in", reason);
            // A form that asks for a new password names the tool that makes one.
            if ["new-password", "two-passwords", "sign-up"].contains(&reason) {
                want["next"] = json!("browser_sign_up");
            }
            assert_eq!(cx.once(page).await, want);
            assert_eq!(cx.requests().len(), 0);
            assert_eq!(cx.posts().len(), 0);
        });
    }

    for (page, reason) in [("passkey", "passkey"), ("captcha", "captcha")] {
        case!(format!("/{page} is a wall"), async {
            assert_eq!(cx.once(page).await, status_reason("wall", reason));
            assert_eq!(cx.requests().len(), 0);
        });
    }

    case!("/captcha-frame, a captcha a person can see, is a wall", async {
        assert_eq!(cx.once("captcha-frame").await, status_reason("wall", "captcha"));
        assert_eq!(cx.requests().len(), 0);
        assert_eq!(cx.posts().len(), 0);
    });

    // A visible check the owner has not solved walls; once solved, its box stays but every response field is
    // filled, and the sign-in goes on (auth.tesla.com, 2026-11-06).
    case!("/captcha-unsolved, a visible check with an empty response, is a wall", async {
        assert_eq!(cx.once("captcha-unsolved").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });
    case!("/captcha-solved, a visible check the owner solved, is not a wall", async {
        assert_eq!(cx.once("captcha-solved").await, status("submitted"));
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
    });
    // The response fields are read in the document that holds the check: a framed sign-in whose check was
    // solved signs in, and a filled field on the outer page does not hide the framed check still asking.
    case!("/captcha-framed-solved, a framed sign-in's solved check, is not a wall", async {
        assert_eq!(cx.once("captcha-framed-solved").await, status("submitted"));
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
    });
    case!(
        "/captcha-framed-unsolved, a framed check still asking beside a filled outer field, is a wall",
        async {
            assert_eq!(cx.once("captcha-framed-unsolved").await, status_reason("wall", "captcha"));
            assert_eq!(cx.posts().len(), 0);
        }
    );

    // Only the check's own kind of response field answers for it: a filled reCAPTCHA score token does not
    // make an hCaptcha checkbox solved, while the check's own field counts inside an open shadow root.
    case!("/captcha-other-kind, a check beside another kind's filled field, is a wall", async {
        assert_eq!(cx.once("captcha-other-kind").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });
    case!("/captcha-shadow-solved, a solved check whose field is in a shadow root, is not a wall", async {
        assert_eq!(cx.once("captcha-shadow-solved").await, status("submitted"));
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
    });
    // A check scrolled up out of an inner scroller can be scrolled back: it still shows.
    case!("/captcha-scrolled, a check scrolled away inside a dialog, is a wall", async {
        assert_eq!(cx.once("captcha-scrolled").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });
    // A check slotted into a web component's scroller, scrolled away, can be scrolled back too.
    case!("/captcha-slotted-scrolled, a check slotted into a scrolled shadow scroller, is a wall", async {
        assert_eq!(cx.once("captcha-slotted-scrolled").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });
    // A right-to-left page starts scrolled to its right end: a check off the left is reached by scrolling.
    case!("/captcha-rtl, a check off the left of a right-to-left page, is a wall", async {
        assert_eq!(cx.once("captcha-rtl").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });
    // An inner right-to-left scroller starts at its right end, and a column-reverse one at its bottom:
    // a check past their start edge is reached by scrolling, so it still shows.
    case!("/captcha-inner-rtl, a check off the left of a right-to-left scroller, is a wall", async {
        assert_eq!(cx.once("captcha-inner-rtl").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });
    case!("/captcha-column-reverse, a check above a column-reverse scroller's start, is a wall", async {
        assert_eq!(cx.once("captcha-column-reverse").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });
    // The page's own scroll counts for a check inside a web component's shadow root too.
    case!("/captcha-shadow-scrolled, a check in a shadow root on a scrolled page, is a wall", async {
        assert_eq!(cx.once("captcha-shadow-scrolled").await, status_reason("wall", "captcha"));
        assert_eq!(cx.posts().len(), 0);
    });

    // Invisible widgets ask nothing of a person: the page signs in as if they were not there. That holds
    // for a frame parked far above a long scrolled page too, whether it is placed on the page (only the
    // page's real scroll can bring it back) or fixed (no scroll moves it).
    for page in [
        "captcha-invisible",
        "captcha-zero",
        "captcha-hidden",
        "captcha-offscreen",
        "captcha-parked-long",
        "captcha-parked-fixed",
    ] {
        case!(format!("/{page}, a captcha frame no one can see, is not a wall"), async {
            assert_eq!(cx.once(page).await, status("submitted"));
            assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
        });
    }

    // A passkey request waiting is the owner's to answer, whatever the form looks like.
    // The fixtures' passkey pop-up is a stand-in that never calls the browser's own WebAuthn.
    case!("a passkey asked as the page loads is a passkey wall, before anything is asked or filled", async {
        cx.fx.reset();
        let r = cx.open_watched("passkey-onload").await;
        assert_eq!(cx.sign(&r).await, status_reason("wall", "passkey"));
        assert_eq!(cx.requests().len(), 0, "no value fetched");
        assert_eq!(cx.posts().len(), 0);
        assert!(r.input_values().await.iter().all(String::is_empty), "nothing typed under the pop-up");
        cx.lane.close(&r).await;
    });

    case!("a passkey asked after the username step is a passkey wall, not next-step", async {
        cx.fx.reset();
        let r = cx.open_watched("passkey-ask").await;
        assert_eq!(cx.sign(&r).await, status_reason("wall", "passkey"));
        assert_eq!(cx.requests()[0]["want"], json!(["username"]));
        assert_eq!(cx.posts().len(), 0, "the page asked for the passkey instead of posting");
        cx.lane.close(&r).await;
    });

    // The page the password lands on asks for a security key, with no field: the owner's to give,
    // not a sign-in done, so it is never reported as submitted.
    case!("a password that lands on a security-key step is a passkey wall, not submitted", async {
        cx.fx.reset();
        let r = cx.open_watched("passthenkey").await;
        assert_eq!(cx.sign(&r).await, status_reason("wall", "passkey"));
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
        cx.lane.close(&r).await;
    });

    case!("A->C->A framing names C to the provider", async {
        cx.fx.reset();
        cx.control(&json!({"wallIfUrl": "localhost"}));
        let r = cx.open("aca").await;
        for _ in 0..50 {
            if r.page().frames().len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(cx.sign(&r).await, status_reason("wall", "form-posts-elsewhere"));
        assert!(cx.url_any(0, &|u| u.contains("localhost")));
        assert_eq!(cx.posts().len(), 0);
        cx.lane.close(&r).await;
    });

    case!("action=\"javascript:void(0)\" is left out and submits through the page script", async {
        assert_eq!(cx.once("jsaction").await, status("submitted"));
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
        assert!(!cx.url_any(0, &|u| u.starts_with("javascript")));
    });

    case!("<input name=action> and <input name=method> do not hide the real attributes", async {
        assert_eq!(cx.once("actionfield").await, status("submitted"));
        assert_eq!(cx.posts()[0].path, "/post/ok");
        assert!(cx.url_any(0, &|u| u.ends_with("/post/ok")));
    });

    // SR-34: markup that shadows a form's or the document's own properties, and a page that replaces the
    // builtins the sign-in scripts use, change nothing they read: the scripts run in the isolated world
    // and read through its prototypes.
    for page in ["clobber-base", "clobber-id", "tamper"] {
        case!(format!("/{page}: the action is still read, and a cross-site one still named"), async {
            cx.fx.reset();
            cx.control(&json!({"wallIfUrl": "localhost"}));
            let r = cx.open(page).await;
            assert_eq!(cx.sign(&r).await, status_reason("wall", "form-posts-elsewhere"));
            assert!(cx.url_any(0, &|u| u.contains("localhost")));
            assert_eq!(cx.posts().len(), 0);
            cx.lane.close(&r).await;
        });
    }

    case!("/clobber-get: <input name=getAttribute> does not turn off the GET stop", async {
        assert_eq!(cx.once("clobber-get").await, status_reason("wall", "form-posts-in-the-clear"));
        assert_eq!(cx.posts().len(), 0);
    });

    case!("/clobber-doc: <img name=body> and the like on the document change nothing", async {
        assert_eq!(cx.once("clobber-doc").await, status("submitted"));
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
    });

    case!(
        "/form-button: a <form role=button> whose fields shadow what the scan and the aim read is still pressed",
        async {
            assert_eq!(cx.once("form-button").await, status("submitted"));
            assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
        }
    );

    // A press that never happened is not a send: the fields are blanked, nothing is posted, and the
    // account is not stopped, so the next sign on the same page goes through.
    case!(
        "/rerender: a button replaced before the press is no send, and the next sign goes through",
        async {
            cx.fx.reset();
            let r = cx.open("rerender").await;
            assert_eq!(cx.sign(&r).await, status("not-ready"));
            assert_eq!(cx.posts().len(), 0);
            assert_eq!(cx.sign(&r).await, status("submitted"));
            assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
            cx.lane.close(&r).await;
        }
    );

    // An echo into the URL's query, the DOM, the hash as base64, or the DOM past clobbered globals: the
    // call goes on, the page stays, and the echo redacts every form the page shows.
    for page in ["leak-url", "leak-dom", "leak-hash", "leak-clobber"] {
        case!(format!("/{page}: an echo is found, redacted, and the call goes on"), async {
            cx.fx.reset();
            let r = cx.open(page).await;
            let signed = cx.sign(&r).await;
            cx.echoed(&r, &signed).await;
            assert_eq!(cx.posts().len(), 0);
            cx.lane.close(&r).await;
        });
    }

    case!("/unresolved: a form action that is not a URL is refused, never skipped", async {
        assert_eq!(cx.once("unresolved").await, status("refused"));
        assert_eq!(cx.requests().len(), 0);
        assert_eq!(cx.posts().len(), 0);
    });

    // T8: a frame inside the control is what a press there would land on, so the click is not sent; the
    // aim sees one in the light tree or an open shadow root, the locator click's check one in a closed one.
    // Another site's frame laid over the button with `pointer-events: none` (`overframe`) is refused too:
    // a known false refusal (SR-34), since Chrome could route the press into it.
    for page in ["aimframe", "closedframe", "overframe"] {
        case!(format!("/{page}: a frame over the button is a wall, and nothing is pressed"), async {
            assert_eq!(cx.once(page).await, status_reason("wall", "no-clear-submit"));
            assert_eq!(cx.posts().len(), 0);
        });
    }

    case!("a form whose action leaves is named to the provider", async {
        cx.fx.reset();
        cx.control(&json!({"wallIfUrl": "localhost"}));
        let r = cx.open("leaves").await;
        assert_eq!(cx.sign(&r).await, status_reason("wall", "form-posts-elsewhere"));
        assert_eq!(cx.posts().len(), 0);
        cx.lane.close(&r).await;
    });

    case!("a page or form address that is not secure is refused before fetching", async {
        assert_eq!(cx.once("plainhttp").await, status("refused"));
        assert_eq!(cx.requests().len(), 0);
        let strict = cx.lane.with(Some(cx.fx.provider()), phantab::signin::Options::default());
        let r = cx.open("one").await;
        assert_eq!(cx.sign_on(&strict, &r, json!({})).await, status("refused"));
        cx.lane.close(&r).await;
    });

    case!("a navigation between asking and filling fills nothing", async {
        cx.fx.reset();
        cx.control(&json!({"delayMs": 1500}));
        let r = cx.open("moves").await;
        assert_eq!(cx.sign(&r).await, status("not-ready"));
        assert_eq!(cx.posts().len(), 0);
        cx.lane.close(&r).await;
    });

    for page in ["getform", "getshadow"] {
        case!(format!("/{page}: an unintercepted GET is stopped"), async {
            assert_eq!(cx.once(page).await, status_reason("wall", "form-posts-in-the-clear"));
            assert_eq!(cx.posts().len(), 0);
        });
    }

    case!("a site that echoes the value: an agent page stays open, redacted", async {
        cx.fx.reset();
        let r = cx.open("echo").await;
        let signed = cx.sign(&r).await;
        cx.echoed(&r, &signed).await;
        assert!(cx.lane.tab_open(r.target()).await, "the agent page stays open");
        assert_eq!(cx.posts().len(), 1);
        // The account is not stopped: the next sign-in on the site goes through.
        assert_eq!(cx.once("one").await, status("submitted"));
        cx.lane.close(&r).await;
    });

    case!("a site that echoes the value: an owner tab stays the agent's, redacted", async {
        cx.fx.reset();
        let r = cx.lane.attach_owner_tab("a", &cx.fx.url("echo")).await;
        let signed = cx.sign(&r).await;
        cx.echoed(&r, &signed).await;
        assert!(cx.lane.tab_open(r.target()).await, "the owner's tab stays open");
        cx.lane.close(&r).await;
    });

    case!("a site that ignores untrusted input is one send, then the account stops until cleared", async {
        cx.fx.reset();
        let r = cx.open("ignores").await;
        assert_eq!(cx.sign(&r).await, status("still-asking"));
        assert_eq!(cx.posts().len(), 1);
        assert_eq!(cx.sign(&r).await, status_reason("stopped", "rejected"));
        assert_eq!(cx.posts().len(), 1);
        assert_eq!(cx.requests().len(), 1, "a stopped host fetches nothing");
        assert_eq!(clear_guard(&cx.fx.guard(), "127.0.0.1").await.unwrap(), json!({"cleared": 1}));
        assert_eq!(cx.sign(&r).await, status("still-asking"));
        assert_eq!(cx.posts().len(), 2);
        cx.lane.close(&r).await;
    });

    case!("a page that comes back asking is still-asking, not another step", async {
        assert_eq!(cx.once("wrong").await, status("still-asking"));
    });

    case!("limits: 2 password sends an hour, 6 a day, and a username step does not count", async {
        cx.fx.reset();
        let r = cx.open("one").await;
        for _ in 0..2 {
            assert_eq!(cx.sign(&r).await, status("submitted"));
            r.page().goto(&cx.fx.url("one"), Duration::from_secs(30)).await.unwrap();
        }
        assert_eq!(cx.sign(&r).await, status_reason("stopped", "limit"));
        assert_eq!(cx.posts().len(), 2);
        let guard = |submits: Vec<String>| {
            json!({"version": 1, "accounts": {"account-one": {"hosts": ["127.0.0.1"], "stopped": null, "submits": submits}}})
                .to_string()
        };
        let old = now_millis() - 2 * 3_600_000;
        std::fs::write(cx.fx.guard(), guard((0..6).map(|i| iso(old - i * 60_000)).collect())).unwrap();
        assert_eq!(cx.sign(&r).await, status_reason("stopped", "limit"));
        let day = now_millis() - 25 * 3_600_000;
        std::fs::write(cx.fx.guard(), guard((0..6).map(|i| iso(day - i)).collect())).unwrap();
        assert_eq!(cx.sign(&r).await, status("submitted"), "the day limit clears itself");
        cx.lane.close(&r).await;
    });

    case!("a damaged guard file refuses all, until sign-in-clear all", async {
        cx.fx.reset();
        std::fs::write(cx.fx.guard(), "{not json").unwrap();
        let r = cx.open("one").await;
        assert_eq!(cx.sign(&r).await, status_reason("stopped", "guard-file"));
        assert_eq!(cx.requests().len(), 0);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_phantab"))
            .args(["sign-in-clear", "all"])
            .env("PHANTAB_RUNTIME", cx.fx.runtime.path())
            .env("PHANTAB_CLIENT", "")
            // The owner's terminal and what they type back, in a test build (stdin is a pipe here).
            .env("PHANTAB_TEST_TERMINAL", "1")
            .env("PHANTAB_TEST_TYPED", "all")
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("all"));
        assert_eq!(cx.sign(&r).await, status("submitted"));
        cx.lane.close(&r).await;
    });

    case!("a normal detach after submit classifies as usual", async {
        cx.fx.reset();
        let r = cx.open("detaching").await;
        let result = cx.sign_with_hook(&r, || r.detach()).await;
        assert_eq!(result, status("submitted"));
        cx.lane.close(&r).await;
    });

    case!("a detach with no re-attach is unknown, and stops the account", async {
        cx.fx.reset();
        let r = cx.open("detaching").await;
        let result = cx
            .sign_with_hook(&r, || async {
                r.fail_recover(true);
                r.detach().await;
            })
            .await;
        assert_eq!(result, status("unknown"));
        r.fail_recover(false);
        r.recover().await.unwrap();
        r.page().goto(&cx.fx.url("detaching"), Duration::from_secs(30)).await.unwrap();
        assert_eq!(cx.sign(&r).await, status_reason("stopped", "unknown"));
        cx.lane.close(&r).await;
    });

    // In the owner's Chrome a hidden page re-attaches now and then, and every handle from before dies with
    // the old link.
    case!("a re-attach while the provider answers: the page is read again and filled once", async {
        cx.fx.reset();
        cx.control(&json!({"delayMs": 800}));
        let r = cx.open("one").await;
        let detach = async {
            let end = Instant::now() + Duration::from_secs(5);
            while cx.requests().is_empty() && Instant::now() < end {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            r.detach().await;
        };
        let (result, ()) = tokio::join!(cx.sign(&r), detach);
        assert_eq!(result, status("submitted"));
        assert_eq!(cx.posts().len(), 1);
        assert!(cx.posted(0, "pass", PASSWORD), "the value was not posted");
        cx.lane.close(&r).await;
    });

    case!("a read that fails after the landing page was read: the landing page stands", async {
        cx.fx.reset();
        let r = cx.open("landsthendetaches").await;
        let result = cx
            .sign_with_hook(&r, || async {
                r.fail_recover(true);
                r.detach().await;
            })
            .await;
        assert_eq!(result, status("submitted"));
        r.fail_recover(false);
        r.recover().await.unwrap();
        cx.lane.close(&r).await;
    });

    for (answer, want) in [
        (json!({"status": "none"}), json!({"status": "none"})),
        (
            json!({"status": "ambiguous", "count": 3, "extra": "dropped"}),
            json!({"status": "ambiguous", "count": 3}),
        ),
        (json!({"status": "refused", "why": "stack trace"}), json!({"status": "refused"})),
        (json!({"status": "ask-first"}), json!({"status": "ask-first"})),
        (json!({"status": "locked"}), json!({"status": "locked"})),
        (json!({"status": "provider-failed"}), json!({"status": "provider-failed"})),
        (json!({"status": "busy"}), json!({"status": "busy"})),
        (
            json!({"status": "wall", "reason": "code-not-saved"}),
            json!({"status": "wall", "reason": "code-not-saved"}),
        ),
        (
            json!({"status": "wall", "reason": "free text from a provider"}),
            json!({"status": "wall", "reason": "no-clear-submit"}),
        ),
        (json!({"status": "made-up-status"}), json!({"status": "provider-failed"})),
        (json!("not json"), json!({"status": "provider-failed"})),
    ] {
        case!(format!("provider answer {answer} reaches the agent as literal labels"), async {
            cx.fx.reset();
            cx.control(&json!({"answer": answer}));
            let r = cx.open("one").await;
            assert_eq!(cx.sign(&r).await, want);
            assert_eq!(cx.posts().len(), 0);
            cx.lane.close(&r).await;
        });
    }

    case!("a seal whose digest differs is refused, and fills nothing", async {
        cx.fx.reset();
        cx.control(&json!({"badDigest": true}));
        let r = cx.open("one").await;
        assert_eq!(cx.sign(&r).await, status("refused"));
        assert_eq!(cx.posts().len(), 0);
        cx.lane.close(&r).await;
    });

    case!("a provider's stderr goes nowhere", async {
        cx.fx.reset();
        cx.control(&json!({"noise": format!("PROVIDER-NOISE {PASSWORD}")}));
        let r = cx.open("one").await;
        assert_eq!(cx.sign(&r).await, status("submitted"));
        cx.lane.close(&r).await;
    });

    case!(
        "a replaced page that holds still ends the settle early; a form it brings in later is read",
        async {
            cx.fx.reset();
            cx.control(&json!({}));
            let long =
                cx.lane.with(Some(cx.fx.provider()), Lane::test_options().with_times(|t| t.settle_ms = 6000));
            let r = cx.open("one").await;
            let began = Instant::now();
            assert_eq!(cx.sign_on(&long, &r, json!({})).await, status("submitted"));
            assert!(
                began.elapsed() < Duration::from_millis(4500),
                "waited out the settle: {:?}",
                began.elapsed()
            );
            cx.lane.close(&r).await;
            // The code form comes 700 ms after the load, inside the 1.5 s the page must hold still.
            let r = cx.open("passlate").await;
            assert_eq!(cx.sign_on(&long, &r, json!({})).await, status("next-step"));
            cx.lane.close(&r).await;
        }
    );

    case!("no provider installed says so, and other tools still work", async {
        let bare = cx.lane.with(None, Lane::test_options());
        let r = cx.open("one").await;
        assert_eq!(cx.sign_on(&bare, &r, json!({})).await, status("no-provider"));
        let as_dyn: Arc<dyn phantab::signin::SignInRecord> = cx.lane.get(&r.id).unwrap();
        assert!(check_call(&as_dyn).is_ok());
        assert_eq!(r.eval_main("()=>document.title").await, json!("Sign in"));
        cx.lane.close(&r).await;
    });

    case!("the fill deadline: past it nothing goes out", async {
        cx.fx.reset();
        cx.control(&json!({"delayMs": 4000}));
        let short =
            cx.lane.with(Some(cx.fx.provider()), Lane::test_options().with_times(|t| t.fill_by_ms = 1500));
        let r = cx.open("one").await;
        let began = Instant::now();
        assert_eq!(cx.sign_on(&short, &r, json!({})).await, status("busy"));
        assert!(began.elapsed() < Duration::from_millis(4000));
        assert_eq!(cx.posts().len(), 0);
        cx.lane.close(&r).await;
    });

    case!(
        "during a slow provider another agent answers, this page is held, and an owner takeover stops the fill",
        async {
            cx.fx.reset();
            cx.control(&json!({"delayMs": 2500}));
            let r = cx.open("one").await;
            let other = cx.lane.open("b", &cx.fx.url("blank")).await;
            let side = async {
                tokio::time::sleep(Duration::from_millis(800)).await;
                let began = Instant::now();
                let title = cx.lane.serializer_run_title(&other).await;
                assert_eq!(title, json!("Plain"));
                assert!(
                    began.elapsed() < Duration::from_millis(2000),
                    "another agent's call waited for the provider"
                );
                let held: Arc<dyn phantab::signin::SignInRecord> = cx.lane.get(&r.id).unwrap();
                for _ in ["snapshot", "screenshot", "act", "show"] {
                    let e = check_call(&held).unwrap_err();
                    assert!(e.0.contains("sign-in is running"), "{}", e.0);
                }
                let again = cx.lane.sign("a", &r.id, &json!({})).await.unwrap();
                cx.seen.note(&again);
                assert_eq!(again, status("busy"), "one sign-in at a time on a page");
                r.set_paused(true);
            };
            let none = json!({});
            let (result, ()) = tokio::join!(cx.lane.sign("a", &r.id, &none), side);
            let result = result.unwrap();
            cx.seen.note(&result);
            assert_eq!(result, status("owner-has-page"));
            assert_eq!(cx.posts().len(), 0);
            r.set_paused(false);
            cx.lane.close(&r).await;
            cx.lane.close(&other).await;
        }
    );

    case!("a blank that cannot be confirmed holds the page until a later blank confirms", async {
        cx.fx.reset();
        let r = cx.open("one").await;
        r.set_phase(Some(Phase::Unblanked));
        let result = cx.lane.sign("a", &r.id, &json!({})).await.unwrap();
        cx.seen.note(&result);
        assert_eq!(result, status_reason("failed", "blank-unconfirmed"));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(r.phase(), None);
        let held: Arc<dyn phantab::signin::SignInRecord> = cx.lane.get(&r.id).unwrap();
        assert!(check_call(&held).is_ok());
        r.set_phase(Some(Phase::Unblanked));
        let e = check_call(&held).unwrap_err();
        assert!(e.0.contains("could not confirm"), "{}", e.0);
        tokio::time::sleep(Duration::from_millis(500)).await;
        cx.lane.close(&r).await;
    });

    case!("owner-has-page before anything starts", async {
        let r = cx.open("one").await;
        r.set_paused(true);
        assert_eq!(cx.sign(&r).await, status("owner-has-page"));
        r.set_paused(false);
        cx.lane.close(&r).await;
    });

    case!("an unknown page, or another session's, is an error that names no value", async {
        let r = cx.open("one").await;
        for (client, id) in [("a", json!("no-such-page")), ("b", json!(r.id)), ("a", json!(5))] {
            let e = phantab::signin::sign_in(&cx.lane, client, &json!({"pageId": id})).await.unwrap_err();
            assert_eq!(e.0, "Unknown page or page belongs to another agent session.");
            cx.seen.results.lock().unwrap().push(e.0);
        }
        cx.lane.close(&r).await;
    });

    case!(
        "no leak: every status was reached, and no value is in a result, an error or the runtime folder",
        async {
            if only.is_some() {
                return;
            }
            let seen: Vec<String> = cx.seen.statuses.lock().unwrap().iter().cloned().collect();
            let mut all: Vec<String> = ALL_STATUSES.iter().map(|s| (*s).to_owned()).collect();
            all.sort();
            assert_eq!(seen, all);
            // Each case's reset removes the guard file and the provider log, so leave both behind: a send,
            // then an echo, which goes on.
            assert_eq!(cx.once("one").await, status("submitted"));
            let r = cx.open("echo").await;
            let signed = cx.sign(&r).await;
            cx.echoed(&r, &signed).await;
            cx.lane.close(&r).await;
            let forms = fixture_leak_forms();
            let results = cx.seen.results.lock().unwrap().join("\n");
            assert!(find_leak(&results, &forms).is_none(), "tool results hold a value");
            let mut searched = 0;
            for entry in walk(cx.fx.runtime.path()) {
                // This test's own instructions to the fake provider.
                if entry.file_name().is_some_and(|n| n == "provider.json") {
                    continue;
                }
                let text = String::from_utf8_lossy(&std::fs::read(&entry).unwrap_or_default()).into_owned();
                searched += 1;
                assert!(find_leak(&text, &forms).is_none(), "{} holds a value", entry.display());
            }
            assert!(searched >= 2, "searched {searched} files");
        }
    );

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
