//! Several credential sources at once (docs/VAULTS.md § Order of choice; THREAT-MODEL SR-84, SR-86).
//! A [`Chain`] is itself a [`CredentialSource`], so the sign-in and sign-up calls hold one source as
//! before. With one source configured and no `vault` named, no chain is made at all
//! ([`super::source::open_for`]), so a config written before the list answers byte for byte as it did.
//!
//! A sign-in:
//! 1. a held account key goes back to the source that issued it: `<name>:<key>` to the source named
//!    `<name>`, a bare key to the bare source (`default`, else the Bitwarden one), and to no other;
//! 2. the agent's `vault` argument narrows the sources to the one it names (an unknown name is
//!    `provider-failed`), and an owner's site pin (`sites`) narrows them to the sources pinned to the
//!    page's origin; the two together leave only a source both allow;
//! 3. a source that did not declare what the call needs (`lookup`, and `totp` for a code) is skipped;
//! 4. the rest are asked in config order, against one deadline. `none`, `locked`, `busy` and
//!    `provider-failed` fall through to the next; any other answer (`refused`, `ask-first`, `wall`,
//!    `ambiguous`) stops the chain, so no second vault can overrule an owner's no (fail closed);
//! 5. when every source fell through, the answer is the most telling seen: `locked` > `busy` >
//!    `provider-failed` > `none`.
//!
//! Matches are never merged across vaults: the first source that has the login answers. Its account
//! key comes back prefixed with its name, except the bare source's, which stays as it was, so held
//! accounts and ask-first files written before the list keep working.
//!
//! A sign-up saves to exactly one source that declared `create`: the one `vault` names, else the first
//! pinned to the page's origin, else `saveTo`, else the first in order. A sign-up password is never
//! written to two vaults.

use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

use super::Outcome;
use super::caps::Caps;
use super::provider::Answer;
use super::seal::Request;
use super::source::{CreateRequest, Created, CredentialSource};

/// One configured source, with what the chain needs to route to it.
pub(crate) struct Entry {
    pub(crate) name: String,
    /// Its account keys go out as they are, not prefixed (`default`, or the Bitwarden source).
    pub(crate) bare: bool,
    /// The origins the owner pinned to it.
    pub(crate) sites: Vec<String>,
    pub(crate) source: Box<dyn CredentialSource>,
}

/// The sources in config order, the sign-up target, and the agent's `vault`.
pub(crate) struct Chain {
    pub(crate) entries: Vec<Entry>,
    pub(crate) save_to: Option<String>,
    pub(crate) vault: Option<String>,
}

/// The statuses that let the next source be asked, most telling first.
const FALL_THROUGH: &[&str] = &["locked", "busy", "provider-failed", "none"];

fn rank(status: &str) -> Option<usize> {
    FALL_THROUGH.iter().position(|s| *s == status)
}

/// The origin (`scheme://host[:port]`) of a URL, as the config's `sites` are written.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    let origin = url.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

impl Chain {
    fn named(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// The sources a call may use: the agent's `vault`, then the owner's pins for these origins.
    /// `Err` is the answer when the agent named a vault that is not configured.
    fn allowed(&self, origins: &[String]) -> Result<Vec<&Entry>, Outcome> {
        let mut out: Vec<&Entry> = self.entries.iter().collect();
        if let Some(vault) = &self.vault {
            if self.named(vault).is_none() {
                return Err(Outcome::of("provider-failed"));
            }
            out.retain(|e| e.name == *vault);
        }
        let pinned = |e: &Entry| e.sites.iter().any(|s| origins.contains(s));
        if self.entries.iter().any(pinned) {
            out.retain(|e| pinned(e));
        }
        Ok(out)
    }

    /// A bare key must not read as one this chain would send to a named source.
    fn reads_as_named(&self, key: &str) -> bool {
        key.split_once(':')
            .is_some_and(|(prefix, _)| self.entries.iter().any(|e| !e.bare && e.name == prefix))
    }
}

#[async_trait]
impl CredentialSource for Chain {
    fn caps(&self) -> Caps {
        self.entries.iter().fold(Caps::default(), |all, e| all.with(e.source.caps()))
    }

    async fn ask(&self, request: &Request, budget: Duration) -> Answer {
        let deadline = Instant::now() + budget;
        let origins: Vec<String> = request.urls.iter().filter_map(|u| origin_of(u)).collect();
        let mut entries = match self.allowed(&origins) {
            Ok(entries) => entries,
            Err(why) => return Answer::Not(why),
        };
        // The held account goes back to the source that issued it, with its own key.
        let mut key = request.account_key.clone();
        if let Some(held) = &request.account_key {
            match held.split_once(':') {
                Some((prefix, rest)) if self.entries.iter().any(|e| !e.bare && e.name == prefix) => {
                    entries.retain(|e| e.name == prefix);
                    key = Some(rest.to_owned());
                }
                _ => entries.retain(|e| e.bare),
            }
        }
        let mut need = Caps::LOOKUP;
        if request.want.contains(&"code") {
            need = need.with(Caps::TOTP);
        }
        let asked = Request { account_key: key, ..request.clone() };
        let mut best: Option<Outcome> = None;
        for entry in entries.into_iter().filter(|e| e.source.caps().has(need)) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                best = Some(better(best, Outcome::of("busy")));
                break;
            }
            match entry.source.ask(&asked, left).await {
                Answer::Ok { values, account_key } => {
                    if entry.bare {
                        if self.reads_as_named(&account_key) {
                            return Answer::Not(Outcome::of("provider-failed"));
                        }
                        return Answer::Ok { values, account_key };
                    }
                    return Answer::Ok { values, account_key: format!("{}:{account_key}", entry.name) };
                }
                Answer::Not(why) if rank(why.status).is_some() => best = Some(better(best, why)),
                Answer::Not(why) => return Answer::Not(why),
            }
        }
        Answer::Not(best.unwrap_or_else(|| Outcome::of("none")))
    }

    async fn create(&self, request: &CreateRequest, budget: Duration) -> Created {
        let origins: Vec<String> = origin_of(&request.origin).into_iter().collect();
        let entries = match self.allowed(&origins) {
            Ok(entries) => entries,
            Err(why) => return Created::Not(why),
        };
        let creates: Vec<&Entry> =
            entries.into_iter().filter(|e| e.source.caps().has(Caps::CREATE)).collect();
        let pinned_here = creates.iter().any(|e| e.sites.iter().any(|s| origins.contains(s)));
        let chosen = if self.vault.is_some() || pinned_here {
            creates.first().copied()
        } else {
            self.save_to
                .as_deref()
                .and_then(|name| creates.iter().copied().find(|e| e.name == name))
                .or_else(|| creates.first().copied())
        };
        match chosen {
            Some(entry) => entry.source.create(request, budget).await,
            None => Created::Not(Outcome::of("no-provider-create")),
        }
    }
}

/// The more telling of two fall-through answers.
fn better(best: Option<Outcome>, seen: Outcome) -> Outcome {
    match best {
        Some(b) if rank(b.status) <= rank(seen.status) => b,
        _ => seen,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::signin::secret::{Secret, Values};
    use crate::signin::source::Saved;

    /// A source that answers one fixed status (or a login with key `k`) and counts its calls.
    struct Fixed {
        answer: &'static str,
        caps: Caps,
        asks: AtomicUsize,
        keys: Mutex<Vec<Option<String>>>,
    }

    impl Fixed {
        fn new(answer: &'static str, caps: Caps) -> Fixed {
            Fixed { answer, caps, asks: 0.into(), keys: Mutex::default() }
        }
    }

    #[async_trait]
    impl CredentialSource for std::sync::Arc<Fixed> {
        fn caps(&self) -> Caps {
            self.caps
        }

        async fn ask(&self, request: &Request, _budget: Duration) -> Answer {
            self.asks.fetch_add(1, Ordering::SeqCst);
            self.keys.lock().unwrap().push(request.account_key.clone());
            match self.answer {
                "ok" => Answer::Ok {
                    values: Values { password: Some(Secret::new("p".into())), ..Values::default() },
                    account_key: "k".into(),
                },
                "ok-colon" => Answer::Ok { values: Values::default(), account_key: "work:k".into() },
                status => Answer::Not(Outcome::of(status)),
            }
        }

        async fn create(&self, _request: &CreateRequest, _budget: Duration) -> Created {
            self.asks.fetch_add(1, Ordering::SeqCst);
            if self.caps.has(Caps::CREATE) {
                Created::Ok { password: Secret::new("made".into()), saved: Saved::New }
            } else {
                Created::Not(Outcome::of("no-provider-create"))
            }
        }
    }

    const LT: Caps = Caps::LOOKUP.with(Caps::TOTP);
    const ALL: Caps = LT.with(Caps::CREATE);

    fn chain(sources: &[(&str, bool, &[&str], &std::sync::Arc<Fixed>)]) -> Chain {
        Chain {
            entries: sources
                .iter()
                .map(|(name, bare, sites, s)| Entry {
                    name: (*name).to_owned(),
                    bare: *bare,
                    sites: sites.iter().map(|s| (*s).to_owned()).collect(),
                    source: Box::new(std::sync::Arc::clone(s)),
                })
                .collect(),
            save_to: None,
            vault: None,
        }
    }

    fn request(key: Option<&str>, want: &[&'static str]) -> Request {
        Request {
            urls: vec!["https://a.test/login".into()],
            account: None,
            account_key: key.map(str::to_owned),
            want: want.to_vec(),
        }
    }

    fn status(answer: &Answer) -> String {
        match answer {
            Answer::Ok { account_key, .. } => format!("ok {account_key}"),
            Answer::Not(o) => o.status.to_owned(),
        }
    }

    async fn ask(c: &Chain, key: Option<&str>) -> String {
        status(&c.ask(&request(key, &["password"]), Duration::from_secs(5)).await)
    }

    #[tokio::test]
    async fn every_status_pair_falls_through_or_stops() {
        let statuses =
            ["none", "locked", "busy", "provider-failed", "refused", "ask-first", "wall", "ambiguous", "ok"];
        for first in statuses {
            for second in statuses {
                let one = std::sync::Arc::new(Fixed::new(first, LT));
                let two = std::sync::Arc::new(Fixed::new(second, LT));
                let got = ask(&chain(&[("one", false, &[], &one), ("two", false, &[], &two)]), None).await;
                let want = match (first, second) {
                    ("ok", _) => "ok one:k".to_owned(),
                    (f, _) if rank(f).is_none() => f.to_owned(),
                    (_, "ok") => "ok two:k".to_owned(),
                    (_, s) if rank(s).is_none() => s.to_owned(),
                    (f, s) => if rank(f) <= rank(s) { f } else { s }.to_owned(),
                };
                assert_eq!(got, want, "{first} then {second}");
                let second_asked = two.asks.load(Ordering::SeqCst) == 1;
                assert_eq!(
                    second_asked,
                    rank(first).is_some(),
                    "{first} then {second}: was the second asked"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_owner_s_no_is_never_overridden() {
        for stop in ["refused", "ask-first", "wall", "ambiguous"] {
            let a = std::sync::Arc::new(Fixed::new(stop, LT));
            let b = std::sync::Arc::new(Fixed::new("ok", LT));
            let c = chain(&[("one", false, &[], &a), ("two", false, &[], &b)]);
            assert_eq!(ask(&c, None).await, stop);
            assert_eq!(b.asks.load(Ordering::SeqCst), 0, "{stop}");
        }
    }

    #[tokio::test]
    async fn keys_are_prefixed_and_go_back_to_their_issuer() {
        let d = std::sync::Arc::new(Fixed::new("ok", LT));
        let w = std::sync::Arc::new(Fixed::new("ok", LT));
        let c = chain(&[("default", true, &[], &d), ("work", false, &[], &w)]);
        assert_eq!(ask(&c, None).await, "ok k", "the bare source keeps today's key");
        assert_eq!(ask(&c, Some("work:abc")).await, "ok work:k");
        assert_eq!(w.keys.lock().unwrap().last().cloned().flatten().as_deref(), Some("abc"), "unprefixed");
        assert_eq!(d.asks.load(Ordering::SeqCst), 1, "a work key never goes to default");
        assert_eq!(ask(&c, Some("sha-bare")).await, "ok k");
        assert_eq!(w.asks.load(Ordering::SeqCst), 1, "a bare key never goes to work");
        // A prefix that names no source is a bare key.
        assert_eq!(ask(&c, Some("home:x")).await, "ok k");
        assert_eq!(d.keys.lock().unwrap().last().cloned().flatten().as_deref(), Some("home:x"));
    }

    #[tokio::test]
    async fn a_bare_key_that_reads_as_a_named_one_fails_closed() {
        let d = std::sync::Arc::new(Fixed::new("ok-colon", LT));
        let w = std::sync::Arc::new(Fixed::new("none", LT));
        let c = chain(&[("default", true, &[], &d), ("work", false, &[], &w)]);
        assert_eq!(ask(&c, None).await, "provider-failed");
    }

    #[tokio::test]
    async fn the_vault_and_site_pins_narrow_the_chain() {
        let a = std::sync::Arc::new(Fixed::new("ok", LT));
        let b = std::sync::Arc::new(Fixed::new("ok", LT));
        let mut c = chain(&[("one", false, &[], &a), ("two", false, &[], &b)]);
        c.vault = Some("two".into());
        assert_eq!(ask(&c, None).await, "ok two:k");
        assert_eq!(a.asks.load(Ordering::SeqCst), 0);
        c.vault = Some("nope".into());
        assert_eq!(ask(&c, None).await, "provider-failed", "an unknown vault");
        let mut c = chain(&[("one", false, &[], &a), ("two", false, &["https://a.test"], &b)]);
        assert_eq!(ask(&c, None).await, "ok two:k", "the pinned source only");
        assert_eq!(a.asks.load(Ordering::SeqCst), 0);
        c.vault = Some("one".into());
        assert_eq!(ask(&c, None).await, "none", "the owner's pin wins over the agent's vault");
        let other = chain(&[("one", false, &[], &a), ("two", false, &["https://b.test"], &b)]);
        assert_eq!(ask(&other, None).await, "ok one:k", "a pin for another site narrows nothing");
    }

    #[tokio::test]
    async fn a_source_is_asked_only_for_what_it_declared() {
        let lookup = std::sync::Arc::new(Fixed::new("ok", Caps::LOOKUP));
        let totp = std::sync::Arc::new(Fixed::new("ok", LT));
        let c = chain(&[("one", false, &[], &lookup), ("two", false, &[], &totp)]);
        let code = c.ask(&request(None, &["code"]), Duration::from_secs(5)).await;
        assert_eq!(status(&code), "ok two:k");
        assert_eq!(lookup.asks.load(Ordering::SeqCst), 0);
        let write_only = std::sync::Arc::new(Fixed::new("ok", Caps::CREATE));
        let c = chain(&[("w", false, &[], &write_only)]);
        assert_eq!(ask(&c, None).await, "none");
        assert_eq!(write_only.asks.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_budget_is_shared() {
        let a = std::sync::Arc::new(Fixed::new("none", LT));
        let c = chain(&[("one", false, &[], &a)]);
        let answer = c.ask(&request(None, &["password"]), Duration::ZERO).await;
        assert_eq!(status(&answer), "busy");
        assert_eq!(a.asks.load(Ordering::SeqCst), 0);
    }

    fn create_request(origin: &str) -> CreateRequest {
        CreateRequest {
            origin: origin.into(),
            username: "u".into(),
            name: "n".into(),
            rules: crate::signin::generate::rules(None, None, None).unwrap(),
            regenerate: false,
        }
    }

    async fn create(c: &Chain, origin: &str) -> String {
        match c.create(&create_request(origin), Duration::from_secs(5)).await {
            Created::Ok { .. } => "ok".into(),
            Created::Not(o) => o.status.to_owned(),
        }
    }

    #[tokio::test]
    async fn a_sign_up_saves_to_exactly_one_source() {
        let read = std::sync::Arc::new(Fixed::new("ok", LT));
        let one = std::sync::Arc::new(Fixed::new("ok", ALL));
        let two = std::sync::Arc::new(Fixed::new("ok", ALL));
        let counts = || {
            (
                read.asks.load(Ordering::SeqCst),
                one.asks.load(Ordering::SeqCst),
                two.asks.load(Ordering::SeqCst),
            )
        };
        let mut c = chain(&[("r", false, &[], &read), ("one", false, &[], &one), ("two", false, &[], &two)]);
        assert_eq!(create(&c, "https://a.test").await, "ok");
        assert_eq!(counts(), (0, 1, 0), "the first that creates");
        c.save_to = Some("two".into());
        assert_eq!(create(&c, "https://a.test").await, "ok");
        assert_eq!(counts(), (0, 1, 1), "saveTo");
        c.vault = Some("one".into());
        assert_eq!(create(&c, "https://a.test").await, "ok");
        assert_eq!(counts(), (0, 2, 1), "the agent's vault");
        c.vault = Some("r".into());
        assert_eq!(create(&c, "https://a.test").await, "no-provider-create", "a vault that cannot create");
        c.vault = Some("nope".into());
        assert_eq!(create(&c, "https://a.test").await, "provider-failed");
        let mut pinned = chain(&[("one", false, &[], &one), ("two", false, &["https://a.test"], &two)]);
        pinned.save_to = Some("one".into());
        assert_eq!(create(&pinned, "https://a.test").await, "ok");
        assert_eq!(counts(), (0, 2, 2), "the site pin wins over saveTo");
        let none = chain(&[("r", false, &[], &read)]);
        assert_eq!(create(&none, "https://a.test").await, "no-provider-create");
        assert_eq!(counts().0, 0);
    }

    #[test]
    fn origins_are_written_as_sites_are() {
        assert_eq!(origin_of("https://a.test/x?y#z").as_deref(), Some("https://a.test"));
        assert_eq!(origin_of("https://A.Test:8443/").as_deref(), Some("https://a.test:8443"));
        assert_eq!(origin_of("https://a.test:443/").as_deref(), Some("https://a.test"));
        assert_eq!(origin_of("data:text/html,x"), None);
        assert_eq!(origin_of("not a url"), None);
    }
}
