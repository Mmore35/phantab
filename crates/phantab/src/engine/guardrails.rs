//! The `guardrails` setting in `config.json` (`docs/GUARDRAILS.md`): how much Phantab itself holds an
//! agent back. Phantab acts as the owner, so by default it runs at parity: the agent gets the access
//! the owner has, and the owner's own guardrails (his agent's rules and approvals) do the holding back.
//!
//! The protections he never feels are not guardrails and hold in every mode: secrets never reach a
//! result, log or service-written file, the vault session stays tied to Phantab's own program, and the
//! service stays on loopback behind its token.

use std::sync::Arc;
use std::time::Duration;

use phantab_cdp::Arg;
use serde_json::Value;

use super::ops::shadow_point;
use super::record::Rec;
use super::{Engine, until};
use crate::engine_api::{EngineError, EngineResult};
use crate::page_js::ACTIONABLE;
use crate::runtime::Config;
use crate::util::{js_string, truthy};

/// The sensitive-set check: which of the three kinds a control is, or `null`. It returns only that
/// word, never the page's text (SR-32).
pub(super) const SENSITIVE: &str = include_str!("../page_js/sensitive.js");

/// `config.json`'s `guardrails`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Guardrails {
    /// `"parity"`, the default when the key is absent: no Phantab guardrail at all. The agent gets the
    /// access the owner has, and the agent's own setup owns the guardrails. `"none"`, this mode's first
    /// name, still reads as parity, so a config written with it keeps working.
    Parity,
    /// `"light"`: only the sensitive-set confirmation.
    Light,
    /// `"full"`: light, plus every guardrail Phantab had before (the sign-in limits and stops, the
    /// owner's handback before `resume`, confirmation before recovering an orphaned handoff).
    Full,
}

impl Guardrails {
    /// Any other value counts as `full`, so a mistyped setting never loosens anything.
    pub(crate) fn of(config: &Config) -> Self {
        match config.other.get("guardrails") {
            None | Some(Value::Null) => Self::Parity,
            Some(Value::String(s)) if s == "parity" || s == "none" => Self::Parity,
            Some(Value::String(s)) if s == "light" => Self::Light,
            Some(_) => Self::Full,
        }
    }

    /// Whether a sensitive-set action waits for `ownerConfirmed`.
    pub(crate) fn confirms(self) -> bool {
        self != Self::Parity
    }

    pub(crate) fn full(self) -> bool {
        self == Self::Full
    }
}

/// What the refusal calls each kind. The agent sees only this, never the control's own text.
fn kind(word: &str) -> Option<&'static str> {
    match word {
        "payment" => Some("a payment or checkout"),
        "password" => Some("a password or two-factor change"),
        "delete" => Some("deleting an account or vault items"),
        _ => None,
    }
}

/// The keys that work a focused control: Enter submits a field's form, Space presses a button.
const PRESSING: &[&str] = &["Enter", "NumpadEnter", " ", "Space", "Spacebar"];

impl Engine {
    pub(crate) fn guardrails(&self) -> Guardrails {
        Guardrails::of(&self.setup.config)
    }

    /// The sensitive-set confirmation, in `light` and `full`: a click, `click_xy` or press of Enter or
    /// Space on a control that reads as a payment or checkout, a password or two-factor change, or
    /// deleting an account or vault items is refused until the agent repeats it with `ownerConfirmed`
    /// true, which it sets only once the owner has approved that step in chat. It is the same
    /// `ownerConfirmed` that `resume` takes.
    ///
    /// It reads only, and runs before the act. A page that cannot be read lets the act through: this is
    /// the light check by design, a prompt for the owner's word, not a wall (a cross-origin frame's own
    /// buttons are not read either; see `docs/GUARDRAILS.md` § Gaps).
    ///
    /// # Errors
    /// The refusal; or, for `click`, the selector's wait failing exactly as the act's own would.
    pub(crate) async fn confirm_first(&self, r: &Arc<Rec>, args: &Value, action: &str) -> EngineResult<()> {
        if !self.guardrails().confirms() || args.get("ownerConfirmed").is_some_and(truthy) {
            return Ok(());
        }
        let num = |k: &str| args.get(k).and_then(Value::as_f64).filter(|n| n.is_finite());
        let selector = js_string(args.get("selector").filter(|v| !v.is_null()));
        let how: Vec<Value> = match action {
            "click" => vec!["selector".into(), selector.clone().into()],
            "click_xy" => match (num("x"), num("y")) {
                (Some(x), Some(y)) => vec!["point".into(), x.into(), y.into()],
                _ => return Ok(()),
            },
            "press" => {
                let key = js_string(args.get("key").filter(|v| !v.is_null()));
                if !PRESSING.contains(&key.as_str()) {
                    return Ok(());
                }
                vec!["focus".into(), key.into()]
            }
            _ => return Ok(()),
        };
        let asked = self
            .cdp(r, None, |p, signal| {
                let (mut how, selector) = (how.clone(), selector.clone());
                async move {
                    if action == "click" {
                        let sel = Value::String(selector.clone());
                        let waited =
                            until(&p, &selector, ACTIONABLE, &[sel], Duration::from_secs(10), Some(&signal))
                                .await;
                        // The act clicks an element only an open shadow root has at its point, so that point
                        // is what is checked.
                        if let Err(e) = waited {
                            let Some((x, y)) = shadow_point(&e.0) else { return Err(e) };
                            how = vec!["point".into(), x.into(), y.into()];
                        }
                    }
                    let Ok(frame) = p.main_frame() else { return Ok(None) };
                    let said = p.evaluate(&frame, SENSITIVE, how.into_iter().map(Arg::Value).collect()).await;
                    // `cdp` takes any error that becomes a `Failed`; the waits here answer `EngineError`.
                    Ok::<_, EngineError>(said.ok().and_then(|v| v.as_str().and_then(kind)))
                }
            })
            .await?;
        match asked {
            Some(what) => Err(EngineError(format!(
                "Confirm first: this looks like {what}. Ask the owner, and only once they approve it, repeat the same act with ownerConfirmed true."
            ))),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn with(value: Option<Value>) -> Config {
        let mut c = Config::default();
        if let Some(v) = value {
            c.other.insert("guardrails".to_owned(), v);
        }
        c
    }

    #[test]
    fn parity_by_default_and_full_for_anything_unknown() {
        assert_eq!(Guardrails::of(&with(None)), Guardrails::Parity);
        assert_eq!(Guardrails::of(&with(Some(Value::Null))), Guardrails::Parity);
        assert_eq!(Guardrails::of(&with(Some(json!("parity")))), Guardrails::Parity);
        assert_eq!(Guardrails::of(&with(Some(json!("light")))), Guardrails::Light);
        assert_eq!(Guardrails::of(&with(Some(json!("full")))), Guardrails::Full);
        for odd in
            [json!("Parity"), json!("None"), json!("off"), json!(""), json!(false), json!(0), json!({})]
        {
            assert_eq!(Guardrails::of(&with(Some(odd.clone()))), Guardrails::Full, "{odd}");
        }
    }

    /// `"none"` was parity's first name; a config already written with it keeps meaning parity.
    #[test]
    fn none_still_means_parity() {
        assert_eq!(Guardrails::of(&with(Some(json!("none")))), Guardrails::Parity);
    }

    #[test]
    fn a_config_file_carries_the_setting() {
        for mode in ["parity", "none"] {
            let c: Config =
                serde_json::from_value(json!({ "profileDirectory": "Default", "guardrails": mode })).unwrap();
            assert_eq!(Guardrails::of(&c), Guardrails::Parity, "{mode}");
            // An older service keeps the key it does not know when the installer rewrites the file.
            assert_eq!(serde_json::to_value(&c).unwrap()["guardrails"], json!(mode));
        }
    }

    #[test]
    fn modes() {
        assert!(!Guardrails::Parity.confirms() && !Guardrails::Parity.full());
        assert!(Guardrails::Light.confirms() && !Guardrails::Light.full());
        assert!(Guardrails::Full.confirms() && Guardrails::Full.full());
    }

    #[test]
    fn only_the_three_kinds_name_themselves() {
        assert_eq!(kind("payment"), Some("a payment or checkout"));
        assert_eq!(kind("password"), Some("a password or two-factor change"));
        assert_eq!(kind("delete"), Some("deleting an account or vault items"));
        assert_eq!(kind("Pay $40 now"), None);
    }

    /// SR-77: the check asks a page object for nothing a page's markup can shadow. Every property a
    /// document or a form lets an element's `name` or `id` replace is read off a prototype instead
    /// (`E.querySelector.call(f, …)`), so the only member looked up on a page object is a list's `length`.
    /// The real-Chrome lane runs the script on such a page (`engine_chrome.rs`); this keeps a later
    /// edit from adding a direct read where that lane does not run.
    #[test]
    fn the_sensitive_check_asks_page_objects_for_nothing_markup_can_shadow() {
        // The script's own names for page objects, as arrow parameters and locals.
        const PAGE_OBJECTS: &[&str] = &["document", "el", "c", "f", "s"];
        let code = SENSITIVE.as_bytes();
        let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
        let mut direct = Vec::new();
        for holder in PAGE_OBJECTS {
            let read = format!("{holder}.");
            for (at, _) in SENSITIVE.match_indices(&read) {
                if at > 0 && (word(code[at - 1]) || code[at - 1] == b'.') {
                    continue; // The tail of a longer name, such as `tagOf.call`.
                }
                let member: String =
                    SENSITIVE[at + read.len()..].chars().take_while(char::is_ascii_alphanumeric).collect();
                direct.push(format!("{holder}.{member}"));
            }
        }
        assert_eq!(direct, Vec::<String>::new(), "read these through a prototype");
        // What it reads instead.
        for through in [
            "D.querySelector.call(document,",
            "D.elementFromPoint.call(document,",
            "get(D,'activeElement').call(document)",
            "E.getAttribute.call(",
            "E.closest.call(",
            "E.matches.call(",
            "E.querySelector.call(",
            "E.querySelectorAll.call(",
        ] {
            assert!(SENSITIVE.contains(through), "{through}");
        }
    }
}
