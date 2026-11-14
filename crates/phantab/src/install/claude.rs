//! Claude Code's `.claude.json`: set or remove `mcpServers.<name>`, keeping every other value. A file whose
//! data would not change is returned as it was, byte for byte; otherwise it is written
//! with a two-space indent, keys in their original order and non-ASCII as is.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

const SERVERS: &str = "mcpServers";

pub(crate) fn parse(text: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(text).context("not valid JSON")?;
    if !value.is_object() {
        bail!("not a JSON object");
    }
    Ok(value)
}

fn servers(value: &mut Value) -> Result<&mut Map<String, Value>> {
    value.as_object_mut().with_context(|| format!("{SERVERS} is not an object"))
}

/// `mcpServers.<name>`, if present.
pub(crate) fn entry(data: &Value, name: &str) -> Result<Option<Value>> {
    match data.get(SERVERS) {
        None => Ok(None),
        Some(Value::Object(servers)) => Ok(servers.get(name).cloned()),
        Some(_) => bail!("{SERVERS} is not an object"),
    }
}

/// The server entry phantab registers.
pub(crate) fn desired(command: &str, args: &[String]) -> Value {
    serde_json::json!({ "command": command, "args": args, "type": "stdio" })
}

/// The Claude edit: `replacement` set as the entry, or the entry removed when `None`.
pub(crate) fn edit(text: &str, data: &Value, name: &str, replacement: Option<&Value>) -> Result<String> {
    let mut updated = data.clone();
    let root = updated.as_object_mut().context("not a JSON object")?;
    match replacement {
        Some(value) => {
            let servers = servers(root.entry(SERVERS).or_insert_with(|| Value::Object(Map::new())))?;
            servers.insert(name.to_owned(), value.clone());
        }
        None => {
            if let Some(found) = root.get_mut(SERVERS) {
                servers(found)?.retain(|key, _| key != name);
            }
        }
    }
    if &updated == data {
        return Ok(text.to_owned());
    }
    Ok(serde_json::to_string_pretty(&updated)? + "\n")
}

/// The file's meaning apart from this entry: the entry gone, and `mcpServers` too when that empties it.
pub(crate) fn without_entry(mut data: Value, name: &str) -> Result<Value> {
    let root = data.as_object_mut().context("not a JSON object")?;
    if let Some(found) = root.get_mut(SERVERS) {
        let servers = servers(found)?;
        servers.retain(|key, _| key != name);
        if servers.is_empty() {
            root.retain(|key, _| key != SERVERS);
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_sensitive_keys_and_idempotence() {
        let text =
            r#"{"projects":{"C:/Project":1,"c:/project":2},"mcpServers":{"other":{"command":"keep"}}}"#;
        let desired = serde_json::json!({"command": "new"});
        let changed = edit(text, &parse(text).unwrap(), "my-browser", Some(&desired)).unwrap();
        assert_eq!(edit(&changed, &parse(&changed).unwrap(), "my-browser", Some(&desired)).unwrap(), changed);
        let data = parse(&changed).unwrap();
        assert_eq!(data["projects"], parse(text).unwrap()["projects"]);
        assert_eq!(data["mcpServers"]["other"]["command"], "keep");
    }

    #[test]
    fn keeps_key_order_and_unchanged_bytes() {
        let text = "{\"z\": 1, \"mcpServers\": {\"b\": 1, \"phantab\": 2, \"a\": 3}, \"é\": \"ü\"}";
        let data = parse(text).unwrap();
        assert_eq!(edit(text, &data, "missing", None).unwrap(), text);
        let removed = edit(text, &data, "phantab", None).unwrap();
        assert_eq!(
            removed,
            "{\n  \"z\": 1,\n  \"mcpServers\": {\n    \"b\": 1,\n    \"a\": 3\n  },\n  \"é\": \"ü\"\n}\n"
        );
        let added =
            edit("{}", &parse("{}").unwrap(), "phantab", Some(&desired("c", &["mcp".to_owned()]))).unwrap();
        assert_eq!(
            added,
            "{\n  \"mcpServers\": {\n    \"phantab\": {\n      \"command\": \"c\",\n      \"args\": [\n        \"mcp\"\n      ],\n      \"type\": \"stdio\"\n    }\n  }\n}\n"
        );
    }

    #[test]
    fn refuses_shapes_it_cannot_edit() {
        assert!(parse("[]").is_err());
        assert!(entry(&parse(r#"{"mcpServers": []}"#).unwrap(), "phantab").is_err());
        let data = parse(r#"{"mcpServers": {"phantab": 1}}"#).unwrap();
        assert_eq!(without_entry(data, "phantab").unwrap(), serde_json::json!({}));
    }
}
