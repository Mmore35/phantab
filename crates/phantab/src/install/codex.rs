//! Codex `config.toml`: replace one `[mcp_servers.<name>]` table (and its subtables) as text, so every other
//! byte of the file stays as the owner wrote it.
//!
//! Why text and not `toml_edit`: the file is spliced as text, so every byte outside the entry stays
//! as it was. `toml_edit` re-renders what it touches and decides on its own which comments and
//! blank lines belong to which table and where a new table goes, so a comment above the next table or
//! the file's trailing whitespace could move. The splice below cannot change a byte outside the tables it
//! names; the `toml` crate only parses, to check that nothing else changed meaning.

use std::fmt::Write as _;
use std::ops::Range;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Number, Value};

/// The entry's tables, in order, as this regex would match them:
/// `(?ms)^\[mcp_servers\.(?:"NAME"|NAME)(?:\.[^\]]+)?\]\r?\n.*?(?=^\[|\Z)`.
/// A header at a line start, then everything up to the next line that starts with `[`, or the end.
pub(crate) fn tables(text: &str, name: &str) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < text.len() {
        if let Some(body) = header_end(&text[at..], name) {
            let end = next_bracket_line(text, at + body);
            found.push(at..end);
            at = end;
            continue;
        }
        match text[at..].find('\n') {
            Some(i) => at += i + 1,
            None => break,
        }
    }
    found
}

/// The length of the header line `line` starts with, newline included, when it names this server.
fn header_end(line: &str, name: &str) -> Option<usize> {
    let rest = line.strip_prefix("[mcp_servers.")?;
    let quoted = format!("\"{name}\"");
    let rest = rest.strip_prefix(quoted.as_str()).or_else(|| rest.strip_prefix(name))?;
    // `(?:\.[^\]]+)?\]`: a subtable runs to the first `]`, with at least one character before it.
    let rest = match rest.strip_prefix('.') {
        Some(sub) => {
            let close = sub.find(']')?;
            if close == 0 {
                return None;
            }
            &sub[close..]
        }
        None => rest,
    };
    let rest = rest.strip_prefix(']')?;
    let rest = rest.strip_prefix('\r').unwrap_or(rest);
    let rest = rest.strip_prefix('\n')?;
    Some(line.len() - rest.len())
}

/// The first line start at or after `from` (itself a line start) whose line begins with `[`, else the end.
fn next_bracket_line(text: &str, from: usize) -> usize {
    let mut at = from;
    while at < text.len() {
        if text[at..].starts_with('[') {
            return at;
        }
        match text[at..].find('\n') {
            Some(i) => at += i + 1,
            None => return text.len(),
        }
    }
    text.len()
}

/// The Codex edit: the first table becomes `block`, later ones (subtables) go; with none,
/// `block` is appended after one blank line. An empty `block` removes the entry.
pub(crate) fn edit(text: &str, name: &str, block: &str) -> String {
    let found = tables(text, name);
    if found.is_empty() {
        return if block.is_empty() { text.to_owned() } else { format!("{}\n\n{block}", text.trim_end()) };
    }
    let mut out = String::with_capacity(text.len() + block.len());
    let mut start = 0;
    for (index, range) in found.into_iter().enumerate() {
        out.push_str(&text[start..range.start]);
        if index == 0 {
            out.push_str(block);
        }
        start = range.end;
    }
    out.push_str(&text[start..]);
    out
}

/// The text the tables for `name` hold now (the recovery record's `original`), or `None`.
pub(crate) fn original(text: &str, name: &str) -> Option<String> {
    let old: String = tables(text, name).into_iter().map(|r| &text[r]).collect();
    (!old.is_empty()).then_some(old)
}

/// The table phantab writes. Strings use TOML's basic-string escapes, so any path is safe in it.
pub(crate) fn block(name: &str, command: &str, args: &[String]) -> String {
    let args: Vec<String> = args.iter().map(|a| string(a)).collect();
    format!(
        "[mcp_servers.\"{name}\"]\ncommand = {}\nargs = [{}]\nstartup_timeout_sec = 30\ntool_timeout_sec = 120\n\n",
        string(command),
        args.join(", ")
    )
}

/// `block` as the recovery record's `installed` value: what parsing the table gives.
pub(crate) fn desired(command: &str, args: &[String]) -> Value {
    serde_json::json!({
        "command": command,
        "args": args,
        "startup_timeout_sec": 30,
        "tool_timeout_sec": 120,
    })
}

fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn parse(text: &str) -> Result<toml::Table> {
    toml::from_str(text).context("not valid TOML")
}

/// `mcp_servers.<name>`, if present.
pub(crate) fn entry(table: &toml::Table, name: &str) -> Result<Option<toml::Value>> {
    match table.get("mcp_servers") {
        None => Ok(None),
        Some(toml::Value::Table(servers)) => Ok(servers.get(name).cloned()),
        Some(_) => bail!("mcp_servers is not a table"),
    }
}

/// The file's meaning apart from this entry: the entry gone, and `mcp_servers` too when that empties it.
pub(crate) fn without_entry(mut table: toml::Table, name: &str) -> Result<toml::Table> {
    if let Some(value) = table.get_mut("mcp_servers") {
        let Some(servers) = value.as_table_mut() else { bail!("mcp_servers is not a table") };
        servers.remove(name);
        if servers.is_empty() {
            table.remove("mcp_servers");
        }
    }
    Ok(table)
}

/// A TOML value as the JSON the recovery record holds.
pub(crate) fn to_json(value: &toml::Value) -> Value {
    match value {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::Number((*i).into()),
        toml::Value::Float(f) => Number::from_f64(*f).map_or(Value::Null, Value::Number),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(items) => Value::Array(items.iter().map(to_json).collect()),
        toml::Value::Table(table) => {
            Value::Object(table.iter().map(|(k, v)| (k.clone(), to_json(v))).collect::<Map<_, _>>())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "my-browser";

    #[test]
    fn named_subtables_go_and_neighbors_stay() {
        let text = "model = \"fixture\"\n[mcp_servers.other]\ncommand=\"keep\"\n[mcp_servers.\"my-browser\"]\ncommand=\"old\"\n[mcp_servers.\"my-browser\".env]\nTEST=\"old\"\n[projects.\"elsewhere\"]\ntrust_level=\"trusted\"\n";
        let updated = edit(text, NAME, "[mcp_servers.\"my-browser\"]\ncommand=\"new\"\n\n");
        let d = parse(&updated).unwrap();
        let new = entry(&d, NAME).unwrap().unwrap();
        assert_eq!(to_json(&new), serde_json::json!({"command": "new"}));
        assert_eq!(d["mcp_servers"]["other"]["command"].as_str(), Some("keep"));
        assert_eq!(d["projects"]["elsewhere"]["trust_level"].as_str(), Some("trusted"));
        assert_eq!(
            updated,
            "model = \"fixture\"\n[mcp_servers.other]\ncommand=\"keep\"\n[mcp_servers.\"my-browser\"]\ncommand=\"new\"\n\n[projects.\"elsewhere\"]\ntrust_level=\"trusted\"\n"
        );
    }

    #[test]
    fn matches_the_documented_regex_edges() {
        // Bare and quoted names, CRLF, a body that runs to the end.
        let text = "a=1\r\n[mcp_servers.my-browser]\r\nx=1\r\n# note\r\n[other]\r\ny=2\r\n[mcp_servers.\"my-browser\".env]\r\nK=\"v\"";
        let found: Vec<&str> = tables(text, NAME).into_iter().map(|r| &text[r]).collect();
        assert_eq!(
            found,
            ["[mcp_servers.my-browser]\r\nx=1\r\n# note\r\n", "[mcp_servers.\"my-browser\".env]\r\nK=\"v\""]
        );
        // A longer name, an indented header, an empty subtable name, a header with text after `]`.
        for miss in [
            "[mcp_servers.my-browser-2]\nx=1\n",
            " [mcp_servers.my-browser]\nx=1\n",
            "[mcp_servers.my-browser.]\nx=1\n",
            "[mcp_servers.my-browser] # c\nx=1\n",
            "[[mcp_servers.my-browser]]\nx=1\n",
        ] {
            assert!(tables(miss, NAME).is_empty(), "{miss:?}");
        }
    }

    #[test]
    fn appends_after_one_blank_line_and_removes_cleanly() {
        let block = block(NAME, r"C:\p\phantab.exe", &["mcp".to_owned()]);
        let added = edit("model=\"unchanged\"\n\n\n", NAME, &block);
        assert_eq!(
            added,
            "model=\"unchanged\"\n\n[mcp_servers.\"my-browser\"]\ncommand = \"C:\\\\p\\\\phantab.exe\"\nargs = [\"mcp\"]\nstartup_timeout_sec = 30\ntool_timeout_sec = 120\n\n"
        );
        let value = entry(&parse(&added).unwrap(), NAME).unwrap().unwrap();
        assert_eq!(to_json(&value), desired(r"C:\p\phantab.exe", &["mcp".to_owned()]));
        assert_eq!(edit(&added, NAME, &block), added);
        assert_eq!(edit("model=1\n", NAME, ""), "model=1\n");
        let restored = edit(&added, NAME, "");
        assert_eq!(restored, "model=\"unchanged\"\n\n");
    }

    #[test]
    fn strings_escape_quotes_backslashes_and_controls() {
        let tricky = "a\"b\\c\nd\u{1}e\u{7f}f é";
        let block = block(NAME, tricky, &["mcp".to_owned(), "--server-name".to_owned(), "x".to_owned()]);
        let value = entry(&parse(&block).unwrap(), NAME).unwrap().unwrap();
        assert_eq!(value["command"].as_str(), Some(tricky));
        assert_eq!(value["args"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn without_entry_drops_an_emptied_container() {
        let t = parse("[mcp_servers.\"my-browser\"]\ncommand=\"x\"\n").unwrap();
        assert!(without_entry(t, NAME).unwrap().is_empty());
        assert!(entry(&parse("mcp_servers = 1\n").unwrap(), NAME).is_err());
    }
}
