//! The CDP methods the bridge relays (THREAT-MODEL SR-20). The list lives once, in the extension
//! (`extension/src/cdp-methods.ts`), which refuses everything else; the service reads the same file and
//! refuses first, so an off-list method never leaves this process either.
//!
//! Events go the other way and have their own list, [`phantab_cdp::EVENTS`], which the bridge welcome
//! hands the extension (perf-data-3). The tests here keep both lists complete.

use std::collections::BTreeSet;
use std::sync::LazyLock;

const SOURCE: &str = include_str!("../../../extension/src/cdp-methods.ts");

/// The quoted names of one `export const` section of [`SOURCE`]. The file keeps one `'Domain.method',`
/// per line. A missing section is empty, so nothing of it is relayed; the tests name every section.
fn section(name: &str) -> BTreeSet<&'static str> {
    let Some(at) = SOURCE.find(&format!("export const {name}:")) else {
        return BTreeSet::new();
    };
    let rest = &SOURCE[at..];
    let end = rest[1..].find("export const").map_or(rest.len(), |e| e + 1);
    rest[..end].lines().filter_map(|line| line.trim().strip_prefix('\'')?.strip_suffix("',")).collect()
}

/// Every method on the list's first part, relayed whatever the settings.
pub static ALLOWED: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| section("CDP_METHODS"));

/// The developer-tools commands (SR-90), relayed only while `devTools` is on.
pub static DEVTOOLS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| section("DEVTOOLS_METHODS"));

/// The extension's copy of the developer-tools events; the tests keep it equal to
/// [`phantab_cdp::DEVTOOLS_EVENTS`].
#[cfg(test)]
static DEVTOOLS_EVENTS: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| section("DEVTOOLS_EVENTS"));

/// Whether the bridge may relay `method` to `chrome.debugger` whatever the settings.
#[must_use]
pub fn allowed(method: &str) -> bool {
    ALLOWED.contains(method)
}

/// Whether `method` is a developer-tools command (SR-90), relayed only while `devTools` is on.
#[must_use]
pub fn devtools(method: &str) -> bool {
    DEVTOOLS.contains(method)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use phantab_cdp::EVENTS;

    use super::*;

    /// Sent only on a browser connection (`Browser`, a Chrome the engine launched, over its pipe),
    /// never through the relay; the relay must not carry them.
    /// `Page.handleJavaScriptDialog` is sent only for a headless page: the extension answers a hidden
    /// window's dialogs itself, and the service must not answer one the owner can see.
    const BROWSER_ONLY: &[&str] = &[
        "Browser.close",
        "Browser.getVersion",
        "Page.handleJavaScriptDialog",
        "Target.attachToTarget",
        "Target.closeTarget",
        "Target.createTarget",
        "Target.getTargets",
    ];
    /// Every `.rs` file under `dir` but test ones, as `(path, non-test code)` ([`code`]): a `tests.rs`, and
    /// a `tests` folder beside it, which holds that module's own submodules (`engine/tests/queue.rs`), so
    /// a fake page's method names there are not counted as code that reads them.
    fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_none_or(|n| n != "tests") {
                    sources(&path, out);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") || path.file_name().is_some_and(|n| n == "tests.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            out.push((path.display().to_string(), code(&text).to_owned()));
        }
    }

    /// A file up to its inline test module: `#[cfg(test)]` before `mod <name> {`. A
    /// `#[cfg(test)] mod tests;` line (engine/mod.rs) names a file and does not end this one.
    fn code(text: &str) -> &str {
        for (at, tag) in text.match_indices("#[cfg(test)]") {
            let line = text[at + tag.len()..].trim_start().lines().next().unwrap_or_default();
            if line.starts_with("mod ") && line.trim_end().ends_with('{') {
                return &text[..at];
            }
        }
        text
    }

    /// Whether `domain` is shaped like a CDP domain: `Page`, `Runtime`, `DOM`.
    fn cdp_domain(domain: &str) -> bool {
        domain.len() > 1
            && domain.chars().all(|c| c.is_ascii_alphabetic())
            && domain.starts_with(|c: char| c.is_ascii_uppercase())
            && domain.chars().nth(1).is_some_and(|c| c.is_ascii_lowercase() || ["DOM", "IO"].contains(&domain))
    }

    /// Whether a string literal's text is a `"Domain.method"` CDP name.
    fn cdp_name(piece: &str) -> bool {
        let Some((domain, method)) = piece.split_once('.') else { return false };
        let cdp_method = method.starts_with(|c: char| c.is_ascii_lowercase())
            && method.chars().all(|c| c.is_ascii_alphanumeric());
        cdp_domain(domain) && cdp_method
    }

    /// The non-test code of phantab-cdp and phantab: what both scans below read, so a name used
    /// anywhere in either crate is classified by one test and its reads checked by the other.
    /// The two crates are named on purpose: phantab-window has no CDP names outside its tests and
    /// phantab-testkit is test-only. A new crate that sends or reads CDP must be added here.
    fn crate_sources() -> Vec<(String, String)> {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        sources(&crates.join("phantab-cdp").join("src"), &mut files);
        sources(&crates.join("phantab").join("src"), &mut files);
        files
    }

    /// `"Domain.method"` string literals in `files` ([`sources`], [`lex`]).
    fn literals(files: &[(String, String)]) -> BTreeSet<&str> {
        files
            .iter()
            .flat_map(|(_, code)| lex(code).1)
            .map(|(piece, _)| piece)
            .filter(|p| cdp_name(p))
            .collect()
    }

    /// One pass over Rust code that knows escapes (`\"`), char literals (`'"'`), raw strings
    /// (`r#"…"#`, `br"…"`, `cr"…"`) and comments (`//`, nested `/* */`). Returns the code with each string literal
    /// reduced to `""` and each comment or char literal to a blank, so the bracket walks below count
    /// only code, and each literal's text with the offset of its `""` there. A quoted name in a
    /// comment is not a literal.
    fn lex(code: &str) -> (String, Vec<(&str, usize)>) {
        let b = code.as_bytes();
        let ident = |i: usize| i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        let (mut skel, mut found) = (String::with_capacity(code.len()), Vec::new());
        let mut i = 0;
        while i < b.len() {
            let rest = &b[i..];
            if rest.starts_with(b"//") {
                i += rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
                skel.push(' ');
                continue;
            }
            if rest.starts_with(b"/*") {
                let (mut depth, mut j) = (0usize, i);
                while j < b.len() {
                    if b[j..].starts_with(b"/*") {
                        depth += 1;
                        j += 2;
                    } else if b[j..].starts_with(b"*/") {
                        depth -= 1;
                        j += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        j += 1;
                    }
                }
                i = j.min(b.len());
                skel.push(' ');
                continue;
            }
            // `r"…"`, `br"…"`, `cr"…"`; not an identifier ending in r (`for"`).
            let raw = b[i] == b'r' && (!ident(i) || (matches!(b[i - 1], b'b' | b'c') && !ident(i - 1)));
            let hashes = if raw { rest[1..].iter().take_while(|&&c| c == b'#').count() } else { 0 };
            if raw && rest.get(1 + hashes) == Some(&b'"') {
                let open = i + 2 + hashes;
                let close = format!("\"{}", "#".repeat(hashes));
                let end = code[open..].find(&close).map_or(code.len(), |e| open + e);
                found.push((&code[open..end], skel.len()));
                skel.push_str("\"\"");
                i = (end + close.len()).min(b.len());
                continue;
            }
            if b[i] == b'"' {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let end = j.min(b.len());
                found.push((&code[i + 1..end], skel.len()));
                skel.push_str("\"\"");
                i = end + 1;
                continue;
            }
            if b[i] == b'\'' {
                // `'\''`, `'\u{..}'`: up to the next quote after the escaped character.
                if rest.get(1) == Some(&b'\\') {
                    let close = rest.get(3..).and_then(|r| r.iter().position(|&c| c == b'\''));
                    i += close.map_or(rest.len(), |at| 3 + at + 1);
                    skel.push_str("'_'");
                    continue;
                }
                // `'x'` (any char); a lifetime `'a` has no closing quote.
                if let Some(c) = code[i + 1..].chars().next()
                    && b.get(i + 1 + c.len_utf8()) == Some(&b'\'')
                {
                    i += 2 + c.len_utf8();
                    skel.push_str("'_'");
                    continue;
                }
            }
            let c = code[i..].chars().next().unwrap_or(' ');
            skel.push(c);
            i += c.len_utf8();
        }
        (skel, found)
    }

    /// The bracket closing the group `after` starts in, and what follows it; `None` past a `;`.
    fn first_close(after: &str) -> Option<(char, &str)> {
        let mut depth = 0usize;
        for (i, c) in after.char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => return Some((c, &after[i + 1..])),
                ')' | ']' | '}' => depth -= 1,
                ';' if depth == 0 => return None,
                _ => {}
            }
        }
        None
    }

    /// Whether `after` goes on as a match arm's pattern: `=>`, `| next`, `if guard`.
    fn arm(after: &str) -> bool {
        let a = after.trim_start();
        a.starts_with("=>") || (a.starts_with('|') && !a.starts_with("||")) || a.starts_with("if ")
    }

    /// Whether the literal is inside a pattern's parentheses: `Some("X") =>`, `("X", c) =>`,
    /// `Ok(("X", _)) |`, or a `let` pattern (`if let Some("X") = m`, `let Some("X") = m else`). A
    /// tuple in a slice or a call (`[("X", v)]`, `send("X", v),`) is not.
    fn in_pattern(mut after: &str) -> bool {
        while let Some((')', rest)) = first_close(after) {
            let next = rest.trim_start();
            if arm(rest) || (next.starts_with('=') && !next.starts_with("==") && !next.starts_with("=>")) {
                return true;
            }
            if !rest.trim_start().starts_with(')') {
                return false;
            }
            after = rest;
        }
        false
    }

    /// Whether the literal is in an inline list the code searches: `["X", "Y"].contains(&m)`.
    fn in_searched_list(after: &str) -> bool {
        first_close(after).is_some_and(|(c, rest)| {
            let rest = rest.trim_start();
            c == ']' && (rest.starts_with(".contains(") || rest.starts_with(".iter().any("))
        })
    }

    /// Whether the literal is in a `matches!(value, pattern)` pattern, inside any parentheses there
    /// (`matches!(m, Some("X"))`); a name in the value (`matches!(send("X"), Ok(_))`) is not.
    fn in_matches(before: &str) -> bool {
        let (mut depth, mut comma) = (0usize, false);
        for (i, c) in before.char_indices().rev() {
            match c {
                ')' | ']' | '}' => depth += 1,
                '(' if depth == 0 => {
                    if comma && before[..i].trim_end().ends_with("matches!") {
                        return true;
                    }
                    comma = false;
                }
                '[' | '{' | ';' if depth == 0 => return false,
                '(' | '[' | '{' => depth -= 1,
                ',' if depth == 0 => comma = true,
                _ => {}
            }
        }
        false
    }

    /// Whether a `const`/`static` after `before` starts an item, not a const generic (`<const N:`).
    fn item_start(before: &str) -> bool {
        let p = before.trim_end();
        p.is_empty()
            || p.ends_with([';', '}', '{', ']'])
            || p.ends_with("pub")
            || p.rsplit_once("pub(").is_some_and(|(_, r)| r.ends_with(')') && !r.contains(['(', '\n']))
    }

    /// The spans of `skel` holding a `const NAME:` or `static NAME:` item's type and value, to its
    /// `;`. A name in one is a list the code checks a method against, so it counts as read.
    fn items(skel: &str) -> Vec<std::ops::Range<usize>> {
        let mut spans = Vec::new();
        for word in ["const ", "static "] {
            for (at, _) in skel.match_indices(word) {
                let before = &skel[..at];
                if before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_') || !item_start(before) {
                    continue;
                }
                let rest = skel[at + word.len()..].trim_start();
                let name = rest
                    .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
                    .unwrap_or(rest.len());
                if name == 0 || !rest[name..].trim_start().starts_with(':') {
                    continue; // `const fn`, `&'static str`
                }
                let start = skel.len() - rest.len();
                let mut depth = 0isize;
                let end = skel[start..]
                    .char_indices()
                    .find(|&(_, c)| {
                        match c {
                            '(' | '[' | '{' => depth += 1,
                            ')' | ']' | '}' => depth -= 1,
                            _ => {}
                        }
                        c == ';' && depth == 0
                    })
                    .map_or(skel.len(), |(i, _)| start + i);
                spans.push(start..end);
            }
        }
        spans
    }

    /// The CDP names `code` checks a method against, in the shapes it sees; those are the events it
    /// reads:
    /// - a match arm: `"X" =>`, `"X" | "Y"`, `"X" if`, inside a pattern's parentheses
    ///   (`("X", c) =>`, `Some("X") =>`), a `let` pattern (`if let Some("X") = m`), or in a
    ///   `matches!` pattern;
    /// - a comparison: the literal on either side (`== "X"`, `"X" != m`), `Some` of it on the
    ///   right only (`== Some("X")`, `!= Some("X")`), or `m.eq("X")`;
    /// - a list: `["X", "Y"].contains(&m)`, or any `const`/`static` item.
    ///
    /// A name it sends is a call's argument instead (`send(None, "X", ..)`, `=> send("X")`). Not
    /// seen: `Some("X") == m`, `"X".eq(m)`, `eq_ignore_ascii_case`, a `let` list or a set searched
    /// later, a macro's literal argument. Such a read still fails [`sent`]'s test if the name is
    /// filed as a command, and a prefix is refused outright ([`prefixes`]).
    fn matched(code: &str) -> Vec<&str> {
        let (skel, found) = lex(code);
        let items = items(&skel);
        let mut out = Vec::new();
        for (piece, at) in found {
            if !cdp_name(piece) {
                continue;
            }
            let (before, after) = (skel[..at].trim_end(), &skel[at + 2..]);
            let next = after.trim_start();
            let compared = before.ends_with("==")
                || before.ends_with("!=")
                || before.ends_with(".eq(")
                || before.ends_with("== Some(")
                || before.ends_with("!= Some(")
                || (before.ends_with('|') && !before.ends_with("||"))
                || next.starts_with("==")
                || next.starts_with("!=");
            if arm(after)
                || compared
                || in_pattern(after)
                || in_searched_list(after)
                || in_matches(before)
                || items.iter().any(|span| span.contains(&at))
            {
                out.push(piece);
            }
        }
        out
    }

    /// Literals shaped like a CDP domain prefix that are not one.
    const NOT_A_PREFIX: &[&str] = &[
        "Cancelled.", // bitwarden.rs: a message printed to the owner
    ];

    /// The literals in `code` that read CDP names by prefix: a `"Domain."`, a format string whose
    /// text before its first `{` is one or a name (`format!("Page.{e}")`), or a name a
    /// `starts_with`, `strip_prefix` or `trim_start_matches` tests a method against.
    fn prefixes(code: &str) -> Vec<&str> {
        let (skel, found) = lex(code);
        let tests = [".starts_with(", ".strip_prefix(", ".trim_start_matches("];
        let domain_dot = |text: &str| text.strip_suffix('.').is_some_and(cdp_domain);
        found
            .into_iter()
            .filter(|&(piece, at)| {
                let before = skel[..at].trim_end();
                let head = piece.split_once('{').map(|(head, _)| head);
                domain_dot(piece)
                    || head.is_some_and(|h| domain_dot(h) || cdp_name(h))
                    || (cdp_name(piece) && tests.iter().any(|t| before.ends_with(t)))
            })
            .map(|(piece, _)| piece)
            .collect()
    }

    /// Calls a name passed to is compared or looked up, not sent.
    const NOT_CALLS: &[&str] = &[
        "Some",
        "Ok",
        "Err",
        "eq",
        "ne",
        "eq_ignore_ascii_case",
        "contains",
        "starts_with",
        "ends_with",
        "strip_prefix",
        "strip_suffix",
        "trim_start_matches",
        "trim_end_matches",
        "find",
        "matches",
    ];

    /// Whether the literal `before` ends at is directly an argument of a call `name(..)` that is not
    /// one of [`NOT_CALLS`]: `send(None, "X", ..)`, `self.send("X")`. A literal in a tuple, slice,
    /// block, pattern or macro is not.
    fn call_argument(before: &str) -> bool {
        let mut depth = 0usize;
        for (i, c) in before.char_indices().rev() {
            match c {
                ')' | ']' | '}' => depth += 1,
                '(' | '[' | '{' if depth > 0 => depth -= 1,
                '(' => {
                    let name = before[..i]
                        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .next()
                        .unwrap_or_default();
                    return !name.is_empty() && !NOT_CALLS.contains(&name);
                }
                '[' | '{' | ';' => return false,
                _ => {}
            }
        }
        false
    }

    /// The CDP names `code` passes straight to a call ([`call_argument`]): the commands it sends.
    fn sent(code: &str) -> Vec<&str> {
        let (skel, found) = lex(code);
        found
            .into_iter()
            .filter(|&(piece, at)| cdp_name(piece) && call_argument(&skel[..at]))
            .map(|(piece, _)| piece)
            .collect()
    }

    #[test]
    fn the_list_is_parsed_and_bans_the_dangerous_domains() {
        assert!(ALLOWED.len() >= 20, "{ALLOWED:?}");
        let parsed = ALLOWED.len() + DEVTOOLS.len() + DEVTOOLS_EVENTS.len();
        assert_eq!(parsed, SOURCE.matches('\'').count() / 2, "a quoted line the parser missed");
        for m in ALLOWED.iter() {
            let domain = m.split('.').next().unwrap_or_default();
            assert!(["DOM", "Emulation", "Input", "Page", "Runtime", "Target"].contains(&domain), "{m}");
            assert!(!["Network", "Storage", "Fetch", "Browser", "Security"].contains(&domain), "{m}");
            assert!(!["Target.createBrowserContext", "Page.setDownloadBehavior"].contains(m), "{m}");
            assert!(!BROWSER_ONLY.contains(m), "{m} is browser-level; the relay must not carry it");
        }
        assert!(allowed("Page.navigate"));
        assert!(!allowed("Network.getAllCookies"));
        assert!(!allowed("Storage.getCookies"));
        assert!(!allowed(""));
        assert!(
            !allowed("Network.enable") && devtools("Network.enable"),
            "a developer tool in the first part"
        );
    }

    /// SR-90, L1: the developer-tools part holds the four commands it names and none of the bans, and
    /// its events are the service's [`phantab_cdp::DEVTOOLS_EVENTS`], never an `...ExtraInfo` one.
    #[test]
    fn the_developer_tools_part_is_exact_and_holds_no_cookie_command() {
        let want = [
            "Emulation.clearGeolocationOverride",
            "Emulation.setCPUThrottlingRate",
            "Emulation.setEmulatedMedia",
            "Emulation.setGeolocationOverride",
            "Emulation.setUserAgentOverride",
            "IO.close",
            "IO.read",
            "Log.enable",
            "Network.emulateNetworkConditions",
            "Network.enable",
            "Network.getResponseBody",
            "Page.removeScriptToEvaluateOnNewDocument",
            "Runtime.terminateExecution",
            "Tracing.end",
            "Tracing.start",
        ];
        assert_eq!(DEVTOOLS.iter().copied().collect::<Vec<_>>(), want);
        for m in DEVTOOLS.iter().chain(DEVTOOLS_EVENTS.iter()) {
            assert!(!ALLOWED.contains(m), "{m} is in both parts");
            assert!(!m.contains("Cookie") && !m.ends_with("ExtraInfo"), "{m}");
            let domain = m.split('.').next().unwrap_or_default();
            assert!(!["Storage", "Fetch", "Browser", "Security"].contains(&domain), "{m}");
        }
        let events: Vec<&str> = DEVTOOLS_EVENTS.iter().copied().collect();
        assert_eq!(events, phantab_cdp::DEVTOOLS_EVENTS, "cdp-methods.ts and phantab_cdp disagree");
        for banned in
            ["Network.getAllCookies", "Network.getCookies", "Network.setCookie", "Storage.getCookies"]
        {
            assert!(!allowed(banned) && !devtools(banned), "{banned}");
        }
    }

    /// SR-20, L1: every CDP name the code uses is classified. A new one anywhere in phantab-cdp or
    /// phantab fails here until it is listed in cdp-methods.ts (a command, so allowed by the extension
    /// too), named browser-only, or put on `phantab_cdp::EVENTS` (an event).
    #[test]
    fn every_method_the_code_sends_is_on_the_list() {
        let files = crate_sources();
        let found = literals(&files);
        assert!(found.contains("Page.navigate"), "the scan found nothing: {found:?}");
        let unclassified: Vec<&&str> = found
            .iter()
            .filter(|m| {
                !allowed(m)
                    && !devtools(m)
                    && !BROWSER_ONLY.contains(m)
                    && !EVENTS.contains(m)
                    && !phantab_cdp::reads_devtools_event(m)
            })
            .collect();
        assert!(
            unclassified.is_empty(),
            "CDP names the code uses that neither extension/src/cdp-methods.ts, BROWSER_ONLY nor \
             phantab_cdp::EVENTS lists; a command it sends goes in cdp-methods.ts, an event it reads in \
             phantab_cdp::EVENTS, not in cdp-methods.ts: {unclassified:?}"
        );
    }

    /// perf-data-3: an event filed in cdp-methods.ts as a command passes the test above and is then
    /// dropped by the extension. A command is sent, so every command name the code uses must be
    /// passed straight to a call somewhere ([`sent`]); an event the code only reads is not, in
    /// whatever shape it reads it. A read through a helper call (`is(m, "X")`) still counts as a send.
    #[test]
    fn every_command_the_code_names_is_sent() {
        let files = crate_sources();
        let sends: BTreeSet<&str> = files.iter().flat_map(|(_, code)| sent(code)).collect();
        assert!(sends.contains("Page.navigate"), "the scan found no send: {sends:?}");
        let used = literals(&files);
        let unsent: Vec<&&str> = used
            .iter()
            .filter(|m| (allowed(m) || devtools(m) || BROWSER_ONLY.contains(m)) && !sends.contains(**m))
            .collect();
        assert!(
            unsent.is_empty(),
            "command names the code uses but never passes to a call: an event the code reads goes on \
             phantab_cdp::EVENTS, not in cdp-methods.ts (a command sent another way: send it from a \
             call): {unsent:?}"
        );
    }

    /// perf-data-3: the extension forwards only `phantab_cdp::EVENTS`, so an event the code matches
    /// anywhere in phantab-cdp or phantab that the list lacks would never arrive. This fails until it
    /// is listed, also when it was filed as a command instead, and fails for a listed event no code
    /// matches any more. It sees the shapes [`matched`] names, not a name built at run time.
    #[test]
    fn every_event_the_code_matches_is_forwarded() {
        // The list itself is a `const`, which [`matched`] counts as read.
        let list = Path::new("phantab-cdp").join("src").join("events.rs");
        let files: Vec<_> =
            crate_sources().into_iter().filter(|(file, _)| !Path::new(file).ends_with(&list)).collect();
        let mut found = BTreeSet::new();
        for (file, code) in &files {
            found.extend(matched(code).into_iter().map(|m| (m, file.as_str())));
        }
        let names: BTreeSet<&str> = found.iter().map(|(m, _)| *m).collect();
        // The scan sees each shape the code uses today: arms, `==`, connection.rs's tuple patterns.
        for seen in ["Page.frameNavigated", "Inspector.detached", "Page.javascriptDialogClosed"] {
            assert!(names.contains(seen), "the scan missed {seen}: {names:?}");
        }
        let missing: Vec<_> = found
            .iter()
            .filter(|(m, _)| !phantab_cdp::reads_event(m) && !phantab_cdp::reads_devtools_event(m))
            .collect();
        assert!(
            missing.is_empty(),
            "events the code matches that phantab_cdp::EVENTS lacks (a command in a pattern, list or \
             const counts as read: send it from the call instead): {missing:?}"
        );
        // Stale means named nowhere, not unmatched: an event read in a shape the scan does not see
        // stays listed, so its fix never has to go into cdp-methods.ts, where it would be dropped.
        let any_literal = literals(&files);
        let stale: Vec<&&str> = EVENTS
            .iter()
            .chain(phantab_cdp::DEVTOOLS_EVENTS)
            .filter(|m| !any_literal.contains(**m))
            .collect();
        assert!(stale.is_empty(), "phantab_cdp::EVENTS names events no code names: {stale:?}");
        for m in EVENTS.iter().chain(phantab_cdp::DEVTOOLS_EVENTS) {
            assert!(
                !allowed(m) && !devtools(m) && !BROWSER_ONLY.contains(m),
                "{m} is an event, not a command"
            );
        }
    }

    /// What [`the_event_scan_tells_a_match_from_a_send`] scans: each shape [`matched`], [`sent`] and
    /// [`lex`] must see, and the ones they must not.
    const EVENT_FIXTURE: &str = r###"
fn f(method: &str) {
    match method {
        "Page.aArm" => {}
        "Page.bOr" | "Page.cOr" => {}
        "Page.dGuard" if true => {}
        _ => {}
    }
    match (method, x) {
        ("Page.eTuple", Some(c)) => {}
    }
    if method == "Page.fEq" || method != "Page.gNe" {}
    match name {
        Some("Page.hSome") => {}
        Ok(("Page.iNested", _)) | Err(_) => {}
    }
    if "Page.jLeft" == method || "Page.kLeftNe" != method {}
    let a = matches!(method, "Page.lMatches" | "Page.mMatchesOr");
    let b = matches!(name.as_deref(), Some("Page.nMatchesSome"));
    let c = method.eq("Page.oEq");
    let d = ["Page.pInline", "Page.qInline"].contains(&method);
    send(None, "Page.sendOne", json!({}));
    self.send("Page.sendTwo", json!({}));
    Some(t) => self.send("Page.sendThree", json!({})),
    let x = ["Page.listed", "Page.listedToo"];
    let y = [("Page.sliceTuple", json!({}))];
    let z = vec![("Page.vecTuple", 1), ("Page.vecTupleToo", 2)];
    let w = matches!(send(c, "Page.sendInMatches"), Ok(_)); // an open ( in a comment
    let v = split(')').send("Page.afterCharLiteral", 1);
    if ev.method.as_deref() == Some("Page.vEqSome") || m != Some("Page.wNeSome") {}
    if let Some("Page.xIfLet") = m {}
    let Some("Page.yLetElse") = m else { return };
    let s = Some("Page.someValue");
    // "Page.inLineComment" => {}
    /* "Page.inBlockComment" => { /* nested */ } */
    let q = '"';
    match m { "Page.zAfterQuoteChar" => {} }
    let e = "a \" b";
    match m { "Page.zzAfterEscape" => {} }
    match m { r#"Page.zzzRaw"# => {} }
    let q = ('\'', '\u{27}');
    match m { "Page.zLexA" => {} }
    let q = (b'"', br#"a"b"#);
    match m { "Page.zLexB" => {} }
    let q = r##"a"#b"##;
    match m { "Page.zLexC" => {} }
    let q = "a\\";
    match m { "Page.zLexD" => {} }
    /* " /* ' */ */
    match m { "Page.zLexE" => {} }
    fn l<'a>(m: &'a str) -> bool { m == "Page.zLexF" }
    let q = cr"\";
    match m { "Page.zLexG" => {} }
    if Some("Page.someLeft") == m || "Page.eqLeft".eq(m) || m.eq_ignore_ascii_case("Page.eqIgnore") {}
}
fn k<const N: usize>() { send("Page.sendInConstGeneric", 1); }
const READS: &[&str] = &["Page.rConst", "Page.sConst"];
pub(crate) static ALSO: [(&str, u8); 1] = [("Page.tStatic", 1)];
const fn h() -> &'static str { "Page.constFn" }
#[cfg(test)]
mod tests;
fn g(m: &str) -> bool { m == "Page.uAfterModLine" }
#[cfg(test)]
mod tests {
    fn h(m: &str) -> bool { m == "Page.inTests" }
}
"###;

    /// The scan behind [`every_event_the_code_matches_is_forwarded`] sees each shape it names and
    /// tells a match from a send, and reads past a `#[cfg(test)] mod tests;` line but not into a test
    /// module.
    #[test]
    fn the_event_scan_tells_a_match_from_a_send() {
        let text = EVENT_FIXTURE;
        assert_eq!(
            matched(code(text)),
            [
                "Page.aArm",
                "Page.bOr",
                "Page.cOr",
                "Page.dGuard",
                "Page.eTuple",
                "Page.fEq",
                "Page.gNe",
                "Page.hSome",
                "Page.iNested",
                "Page.jLeft",
                "Page.kLeftNe",
                "Page.lMatches",
                "Page.mMatchesOr",
                "Page.nMatchesSome",
                "Page.oEq",
                "Page.pInline",
                "Page.qInline",
                "Page.vEqSome",
                "Page.wNeSome",
                "Page.xIfLet",
                "Page.yLetElse",
                "Page.zAfterQuoteChar",
                "Page.zzAfterEscape",
                "Page.zzzRaw",
                "Page.zLexA",
                "Page.zLexB",
                "Page.zLexC",
                "Page.zLexD",
                "Page.zLexE",
                "Page.zLexF",
                "Page.zLexG",
                "Page.rConst",
                "Page.sConst",
                "Page.tStatic",
                "Page.uAfterModLine"
            ]
        );
        assert_eq!(
            sent(code(text)),
            [
                "Page.sendOne",
                "Page.sendTwo",
                "Page.sendThree",
                "Page.sendInMatches",
                "Page.afterCharLiteral",
                "Page.sendInConstGeneric"
            ]
        );
    }

    /// perf-data-3: the extension forwards events by exact name, so code that reads them by a prefix
    /// (`m.starts_with("Page.")`) or a name built from a prefix literal (`format!("Page.{e}")`,
    /// `format!("{}{}", "Target.", e)`) would never see one, and [`matched`] cannot list it. Such a
    /// literal fails here; a name split at its dot (`split_once('.')`) is not seen.
    #[test]
    fn no_code_reads_an_event_by_prefix() {
        let files = crate_sources();
        let found: Vec<(&str, &str)> = files
            .iter()
            .flat_map(|(file, code)| prefixes(code).into_iter().map(move |p| (p, file.as_str())))
            .filter(|(p, _)| !NOT_A_PREFIX.contains(p))
            .collect();
        assert!(
            found.is_empty(),
            "the extension forwards CDP events by exact name only (phantab_cdp::EVENTS): code that \
             reads events by a prefix or a built name would never see one; match the full names (if \
             this is not CDP, add it to NOT_A_PREFIX): {found:?}"
        );
    }

    /// [`prefixes`] flags a domain prefix and a name tested as a prefix, not a name or other text.
    #[test]
    fn the_prefix_scan_sees_a_domain_prefix() {
        let text = r#"
fn f(m: &str) {
    if m.starts_with("Page.") {}
    let n = format!("{}{}", "Target.", e);
    let r = m.strip_prefix("Page.frame");
    let t = m == format!("Page.{e}") || m == format!("Target.attached{e}") || m == format!("{e}.x");
    eprintln!("Cancelled.");
    let x = ["Done", "a.b", "Page.navigate", "DOM."];
}
"#;
        assert_eq!(
            prefixes(text),
            ["Page.", "Target.", "Page.frame", "Page.{e}", "Target.attached{e}", "Cancelled.", "DOM."]
        );
    }
}
