//! The `work` setting (THREAT-MODEL SR-92): phantab for a work laptop or a managed machine.
//!
//! On, four things are off, whatever else the config says: the sign-in tools (`browser_sign_in` and
//! `browser_sign_up` are not listed, and the service refuses them naming the setting), every sign-in
//! provider (the engine never starts one), the automatic hand-off of a human check (a check is reported
//! to the agent as it is; `browser_show` still hands a page over), and the phone viewer (the
//! `remoteViewer` listener never starts). `browser_status` lists the four.
//!
//! Absent or `false` is off and `true` is on. Any other value counts as on, the strict choice, and
//! `browser_status` says it was not understood. `work` and `devTools` are separate settings: only
//! `phantab install --work` writes both.

use serde_json::{Value, json};

use crate::runtime::Config;

/// The config key.
pub const KEY: &str = "work";

/// What `work` turns off, as `browser_status` lists it.
pub const OFF: [&str; 4] = [
    "browser_sign_in and browser_sign_up: not listed, and refused",
    "sign-in providers: none is started",
    "the automatic hand-off of a human check: a check is reported as it is; browser_show still hands the page over",
    "the phone viewer: remoteViewer does not listen",
];

/// The engine methods `work` refuses, by their tool names.
pub const REFUSED: [&str; 2] = ["sign_in", "sign_up"];

/// Whether `work` is on: absent and `false` are off, everything else is on.
#[must_use]
pub fn on(config: &Config) -> bool {
    !matches!(config.other.get(KEY), None | Some(Value::Bool(false)))
}

/// The value of `work` when it is neither `true` nor `false`: it counts as on, and status says so.
#[must_use]
pub fn not_understood(config: &Config) -> Option<&Value> {
    config.other.get(KEY).filter(|v| !v.is_boolean())
}

/// `browser_status`'s `work` field; `None` while it is off, so a status without it reads as before.
#[must_use]
pub fn status(config: &Config) -> Option<Value> {
    if !on(config) {
        return None;
    }
    let mut out = json!({ "on": true, "off": OFF });
    if let Some(v) = not_understood(config) {
        out["note"] = json!(format!(
            "work is {v}, which is neither true nor false, so it counts as on. Set it to true or false in config.json."
        ));
    }
    Some(out)
}

/// The refusal of `browser_<name>` while `work` is on: it names the setting.
#[must_use]
pub fn refusal(name: &str) -> String {
    format!(
        "browser_{name} is off on this machine: phantab's config.json sets \"work\" (docs/WORK-LAPTOP.md), which turns sign-in and sign-up off. Sign in yourself in the page, or hand it over with browser_show."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(value: Option<Value>) -> Config {
        let mut c = Config::default();
        if let Some(v) = value {
            c.other.insert(KEY.into(), v);
        }
        c
    }

    #[test]
    fn work_is_off_only_when_absent_or_false_and_any_other_value_is_on_and_said() {
        for (value, is_on, said) in [
            (None, false, false),
            (Some(json!(false)), false, false),
            (Some(json!(true)), true, false),
            (Some(json!("false")), true, true),
            (Some(json!("yes")), true, true),
            (Some(json!(0)), true, true),
            (Some(Value::Null), true, true),
            (Some(json!({})), true, true),
        ] {
            let c = with(value.clone());
            assert_eq!(on(&c), is_on, "{value:?}");
            let status = status(&c);
            assert_eq!(status.is_some(), is_on, "{value:?}");
            if let Some(s) = status {
                assert_eq!(s["off"].as_array().unwrap().len(), 4);
                assert_eq!(s.get("note").is_some(), said, "{value:?}: {s}");
            }
        }
    }

    #[test]
    fn the_refusal_names_the_setting() {
        let r = refusal("sign_in");
        assert!(r.starts_with("browser_sign_in is off") && r.contains("\"work\""), "{r}");
    }
}
