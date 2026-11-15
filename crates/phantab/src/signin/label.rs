//! What a sign-in answers: only literal labels leave the call (THREAT-MODEL SR-39).

use serde_json::{Map, Value};

use super::provider::WALL_REASONS;

/// Every status a call may answer.
pub(crate) const STATUS: &[&str] = &[
    "submitted",
    "next-step",
    "still-asking",
    "unknown",
    "wall",
    "not-a-sign-in",
    "not-ready",
    "none",
    "ambiguous",
    "refused",
    "ask-first",
    "locked",
    "provider-failed",
    "busy",
    "stopped",
    "owner-has-page",
    "failed",
    "no-provider",
    // The old answer to a site that shows a value back. phantab no longer gives it: the call goes
    // on and says `echoed`. Kept, so a reader of the old answers still parses it.
    "leak-stopped",
];

/// The `note` beside `echoed: true`. Literals: they name no value, page or site.
const ECHOED_PASSWORD: &str = "The site showed the password back on the page after it was typed. phantab redacts it from everything it returns, and refuses screenshots of that tab until the tab closes. The site's page and anything running on it could read the password: if this password is in use, a reset is advisable.";
const ECHOED_CODE: &str = "The site showed the one-time code back on the page after it was typed. phantab redacts it from everything it returns, and refuses screenshots of that tab until the tab closes.";

/// Which value a site showed back on its page after the submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Echoed {
    Password,
    Code,
}

/// The reasons besides [`WALL_REASONS`] (`REASONS` is both).
const OTHER_REASONS: &[&str] = &[
    "new-password",
    "two-passwords",
    "card-fields",
    "pay-button",
    "sign-up",
    "not-sign-in-step",
    "no-field",
    "rejected",
    "limit",
    "guard-file",
    "debug-logging",
    "page-ended",
    "blank-unconfirmed",
    "error",
];

/// A reason the label keeps (`REASONS`, or `unknown`), as a literal; `None` for any other text, which
/// the label would drop. The page's own `refuse` and `wall` words pass through this.
pub(crate) fn reason(text: &str) -> Option<&'static str> {
    WALL_REASONS.iter().chain(OTHER_REASONS).chain(&["unknown"]).copied().find(|r| *r == text)
}

/// Every status `browser_sign_up` may answer (phantab's own).
pub(crate) const SIGN_UP_STATUS: &[&str] = &[
    "filled",
    "filled-existing",
    "not-a-sign-up",
    "not-ready",
    "no-provider",
    "no-provider-create",
    "ask-first",
    "locked",
    "provider-failed",
    "refused",
    "ambiguous",
    "busy",
    "stopped",
    "owner-has-page",
    "failed",
    "leak-stopped",
];

/// The reasons a sign-up answer keeps.
const SIGN_UP_REASONS: &[&str] = &[
    "no-field",
    "sign-in-form",
    "change-password",
    "pay-button",
    "card-fields",
    "get-form",
    "not-https",
    "third-party-frame",
    "form-posts-elsewhere",
    "password-too-short",
    "password-rules",
    "page-moved",
    "not-taken",
    "page-ended",
    "debug-logging",
    "blank-unconfirmed",
    "rejected",
    "guard-file",
    "error",
    "unknown",
];

/// A sign-up reason as a literal; `None` for any other text, which the label drops.
pub(crate) fn sign_up_reason(text: &str) -> Option<&'static str> {
    SIGN_UP_REASONS.iter().copied().find(|r| *r == text)
}

/// One answer before it is labelled. Every field is a literal: nothing a page or provider wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) status: &'static str,
    pub(crate) reason: Option<&'static str>,
    pub(crate) count: Option<i64>,
    /// The site showed a value back.
    pub(crate) echoed: Option<Echoed>,
}

impl Outcome {
    pub(crate) const fn of(status: &'static str) -> Self {
        Outcome { status, reason: None, count: None, echoed: None }
    }

    pub(crate) const fn with(status: &'static str, reason: &'static str) -> Self {
        Outcome { status, reason: Some(reason), count: None, echoed: None }
    }

    pub(crate) const fn echoed(self, echoed: Echoed) -> Self {
        Outcome { echoed: Some(echoed), ..self }
    }

    pub(crate) const FAILED: Outcome = Outcome::with("failed", "error");
}

/// `label(v)`: the status when it is one, the reason when it is one, the count of an `ambiguous`; then
/// `echoed: true` and its note when the site showed a value back.
pub(crate) fn label(v: &Outcome) -> Value {
    if !STATUS.contains(&v.status) {
        return label(&Outcome { echoed: v.echoed, ..Outcome::FAILED });
    }
    let mut out = Map::new();
    out.insert("status".into(), v.status.into());
    if let Some(r) = v.reason.and_then(reason) {
        out.insert("reason".into(), r.into());
    }
    if v.status == "ambiguous"
        && let Some(n) = v.count
    {
        out.insert("count".into(), n.into());
    }
    if v.status == "not-a-sign-in" && v.reason.is_some_and(|r| SIGN_UP_SHAPED.contains(&r)) {
        out.insert("next".into(), "browser_sign_up".into());
    }
    if let Some(echoed) = v.echoed {
        out.insert("echoed".into(), true.into());
        let note = match echoed {
            Echoed::Password => ECHOED_PASSWORD,
            Echoed::Code => ECHOED_CODE,
        };
        out.insert("note".into(), note.into());
    }
    Value::Object(out)
}

/// The not-a-sign-in reasons that mean the page asks for a new password: the answer names the tool that
/// makes one (`next`), so the agent need not guess.
const SIGN_UP_SHAPED: &[&str] = &["new-password", "two-passwords", "sign-up"];

/// `browser_sign_up`'s label: the status when it is one, the reason when it is one, the count of an
/// `ambiguous`; anything else is `failed/error`.
pub(crate) fn label_sign_up(v: &Outcome) -> Value {
    if !SIGN_UP_STATUS.contains(&v.status) {
        return label_sign_up(&Outcome::FAILED);
    }
    let mut out = Map::new();
    out.insert("status".into(), v.status.into());
    if let Some(r) = v.reason.and_then(sign_up_reason) {
        out.insert("reason".into(), r.into());
    }
    if v.status == "ambiguous"
        && let Some(n) = v.count
    {
        out.insert("count".into(), n.into());
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn only_literals_leave() {
        assert_eq!(label(&Outcome::of("submitted")), json!({"status": "submitted"}));
        assert_eq!(label(&Outcome::with("wall", "captcha")), json!({"status": "wall", "reason": "captcha"}));
        assert_eq!(
            label(&Outcome::with("stopped", "unknown")),
            json!({"status": "stopped", "reason": "unknown"})
        );
        assert_eq!(
            label(&Outcome::with("stopped", "limit")),
            json!({"status": "stopped", "reason": "limit"})
        );
        assert_eq!(label(&Outcome::with("wall", "made-up")), json!({"status": "wall"}));
        assert_eq!(label(&Outcome::of("ok")), json!({"status": "failed", "reason": "error"}));
        assert_eq!(label(&Outcome::of("")), json!({"status": "failed", "reason": "error"}));
        let many = Outcome { count: Some(4), ..Outcome::of("ambiguous") };
        assert_eq!(label(&many), json!({"status": "ambiguous", "count": 4}));
        let stray = Outcome { count: Some(4), ..Outcome::of("none") };
        assert_eq!(label(&stray), json!({"status": "none"}));
        // Key order: status, reason, count.
        let both = Outcome { status: "ambiguous", reason: Some("error"), count: Some(2), echoed: None };
        assert_eq!(label(&both).to_string(), r#"{"status":"ambiguous","reason":"error","count":2}"#);
        // An echo adds `echoed` and its note, after the rest; the status stays the call's own.
        let shown = label(&Outcome::of("submitted").echoed(Echoed::Password));
        assert_eq!(shown["status"], json!("submitted"));
        assert_eq!(shown["echoed"], json!(true));
        assert!(shown["note"].as_str().is_some_and(|n| n.contains("reset")), "{shown}");
        let keys: Vec<&String> = shown.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["status", "echoed", "note"]);
        let code = label(&Outcome::with("stopped", "rejected").echoed(Echoed::Code));
        assert_eq!((&code["reason"], &code["echoed"]), (&json!("rejected"), &json!(true)));
        assert!(code["note"].as_str().is_some_and(|n| n.contains("code") && !n.contains("reset")));
        assert_eq!(label(&Outcome::of("ok").echoed(Echoed::Code))["echoed"], json!(true));
        for s in STATUS {
            assert_eq!(label(&Outcome::of(s))["status"], json!(s));
        }
        assert_eq!(reason("rejected"), Some("rejected"));
        assert_eq!(reason("Rejected"), None);
        assert_eq!(reason("pay-button"), Some("pay-button"));
        assert_eq!(reason("code-boxes"), Some("code-boxes"));
        // A sign-up-shaped refusal names the tool that makes a new password.
        assert_eq!(
            label(&Outcome::with("not-a-sign-in", "two-passwords")).to_string(),
            r#"{"status":"not-a-sign-in","reason":"two-passwords","next":"browser_sign_up"}"#
        );
        assert_eq!(label(&Outcome::with("not-a-sign-in", "card-fields"))["next"], Value::Null);
    }

    #[test]
    fn sign_up_answers_only_literals() {
        assert_eq!(label_sign_up(&Outcome::of("filled")), json!({"status": "filled"}));
        assert_eq!(
            label_sign_up(&Outcome::with("not-a-sign-up", "password-too-short")),
            json!({"status": "not-a-sign-up", "reason": "password-too-short"})
        );
        assert_eq!(label_sign_up(&Outcome::with("filled", "made-up")), json!({"status": "filled"}));
        assert_eq!(label_sign_up(&Outcome::of("submitted")), json!({"status": "failed", "reason": "error"}));
        let many = Outcome { count: Some(2), ..Outcome::of("ambiguous") };
        assert_eq!(label_sign_up(&many), json!({"status": "ambiguous", "count": 2}));
        for s in SIGN_UP_STATUS {
            assert_eq!(label_sign_up(&Outcome::of(s))["status"], json!(s));
        }
    }
}
