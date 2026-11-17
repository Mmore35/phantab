//! What the engine keeps after a sign-in saw the site show the password or code back on its page.
//! Rather than close the tab and stop the account, phantab goes on, and from then on:
//!
//! - every string the agent receives (results, errors, keys included, `status`, `release`) has each
//!   form of the value written `[redacted]`, for the rest of the service's life. The text is not keyed
//!   to a page: the value can turn up anywhere the site put it (another tab it opens, a title in the
//!   tab list, a fresh attach to the same tab), and a redaction finds only the value itself.
//! - a screenshot of the page's tab is refused until the tab closes: an image cannot be redacted. A
//!   shared tab is marked by its profile and tab ID, so a fresh attach to it is refused too; an
//!   isolated page by its record, which ends with it.
//!
//! Nothing here is a guardrail: it holds in every `guardrails` mode.

use std::sync::Arc;

use serde_json::{Map, Value};

use super::Engine;
use super::marks::TabMark;
use super::record::Rec;
use crate::bridge::{Profile, TabId};
use crate::engine_api::EngineError;
use crate::signin::Echo;

/// The agent's answer to a screenshot of a marked tab.
pub(crate) const SCREENSHOT_REFUSED: &str = "Screenshot refused: a sign-in on this tab saw the site show the password or code back on the page, and an image of it cannot be redacted. Use a snapshot, which phantab redacts. Screenshots of this tab work again once it closes.";

/// `text` with each echo's forms written `[redacted]`, or `None` when none was in it.
fn redact_str(echoes: &[Arc<Echo>], text: &str) -> Option<String> {
    let mut out: Option<String> = None;
    for echo in echoes {
        if let Some(r) = echo.redact(out.as_deref().unwrap_or(text)) {
            out = Some(r);
        }
    }
    out
}

/// Redacts every string in `value`, keys included. `skip` names an object key whose value is left
/// alone (a screenshot's image).
fn redact_value(echoes: &[Arc<Echo>], value: &mut Value, skip: Option<&str>) {
    match value {
        Value::String(s) => {
            if let Some(r) = redact_str(echoes, s) {
                *s = r;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| redact_value(echoes, v, None)),
        Value::Object(map) => redact_map(echoes, map, skip),
        _ => {}
    }
}

fn redact_map(echoes: &[Arc<Echo>], map: &mut Map<String, Value>, skip: Option<&str>) {
    if map.keys().any(|k| redact_str(echoes, k).is_some()) {
        // Rebuilt in order; two keys that redact alike keep the later value, as a JSON object would.
        let old = std::mem::take(map);
        for (k, v) in old {
            let k = redact_str(echoes, &k).unwrap_or(k);
            map.insert(k, v);
        }
    }
    for (k, v) in map.iter_mut() {
        if Some(k.as_str()) != skip {
            redact_value(echoes, v, None);
        }
    }
}

impl Engine {
    /// The echoes so far; empty until a sign-in sees one.
    fn echoes(&self) -> Vec<Arc<Echo>> {
        self.st().echoes.clone()
    }

    /// A sign-in saw an echo on `r`'s page: keep it, and mark the tab.
    pub(crate) fn add_echo(&self, r: &Rec, echo: Arc<Echo>) {
        // The tab whose screenshots are refused.
        let mark = TabMark::of(r);
        let mut st = self.st();
        st.echoes.push(echo);
        if !st.echo_marks.contains(&mark) {
            st.echo_marks.push(mark);
        }
    }

    /// An echo seen on a page that has since ended: its text is still redacted.
    pub(crate) fn keep_echo(&self, echo: Arc<Echo>) {
        self.st().echoes.push(echo);
    }

    /// Whether a screenshot of `r` is refused.
    pub(crate) fn echo_marked(&self, r: &Rec) -> bool {
        let (tab, isolated) = {
            let s = r.lock();
            (s.tab_id, s.isolated.is_some())
        };
        self.st().echo_marks.iter().any(|m| match m {
            TabMark::Tab(profile, t) => !isolated && *profile == r.profile && Some(*t) == tab,
            TabMark::Page(id) => *id == r.id,
        })
    }

    /// The tab closed: its screenshots are no longer refused.
    pub(crate) fn echo_tab_closed(&self, profile: &Profile, tab: TabId) {
        let mut st = self.st();
        if !st.echo_marks.is_empty() {
            st.echo_marks.retain(|m| *m != TabMark::Tab(profile.clone(), tab));
        }
    }

    /// The isolated page `id` is gone, and its browser with it.
    pub(crate) fn echo_page_gone(&self, id: &str) {
        let mut st = self.st();
        if !st.echo_marks.is_empty() {
            st.echo_marks.retain(|m| *m != TabMark::Page(id.to_owned()));
        }
    }

    /// `result` as the agent receives it: every string redacted (a screenshot's image left alone).
    pub(crate) fn redacted<T: Redact>(&self, mut result: T, image: bool) -> T {
        let echoes = self.echoes();
        if !echoes.is_empty() {
            result.redact(&echoes, image);
        }
        result
    }
}

/// What [`Engine::redacted`] redacts.
pub(crate) trait Redact {
    fn redact(&mut self, echoes: &[Arc<Echo>], image: bool);
}

impl Redact for Value {
    fn redact(&mut self, echoes: &[Arc<Echo>], image: bool) {
        redact_value(echoes, self, image.then_some("data"));
    }
}

impl Redact for Map<String, Value> {
    fn redact(&mut self, echoes: &[Arc<Echo>], _image: bool) {
        redact_map(echoes, self, None);
    }
}

impl Redact for EngineError {
    fn redact(&mut self, echoes: &[Arc<Echo>], _image: bool) {
        if let Some(r) = redact_str(echoes, &self.0) {
            self.0 = r;
        }
    }
}

impl<T: Redact, E: Redact> Redact for Result<T, E> {
    fn redact(&mut self, echoes: &[Arc<Echo>], image: bool) {
        match self {
            Ok(v) => v.redact(echoes, image),
            Err(e) => e.redact(echoes, image),
        }
    }
}
