//! `uphold schema` -- the JSON Schema of the policy file.
//!
//! The schema is derived, not written. `schemars` reads the same `#[serde]`
//! attributes the TOML deserializer does, so `deny_unknown_fields` becomes
//! `additionalProperties: false`, `rename` becomes the key a person types, and a
//! struct field with a `default` is not required. A hand-written schema would be
//! a second list of the keys, and the repository already removed one of those
//! once for exactly that reason.
//!
//! What it cannot say, it does not claim. The deserializer's reading is only the
//! first half of loading a policy: a rule carrying two checks, a bundled-set
//! header in a repository's own file, an `owner` beside an `owner_from` and a
//! regular expression that does not compile are all refused after the read, with
//! the rule's id in the message. A document that validates here has the right
//! shape; `uphold scan` is still what says it loads.

use crate::config::PolicyFile;
use crate::error::{Fatal, Result};

/// The schema as `uphold schema` prints it: pretty JSON, one trailing newline.
///
/// The output is a function of the source tree and the locked `schemars`
/// version alone, so the committed copy can be compared byte for byte.
pub(crate) fn document() -> Result<String> {
    let schema = schemars::generate::SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<PolicyFile>();
    let mut value = serde_json::to_value(&schema)
        .map_err(|error| Fatal::new(format!("the policy schema did not serialize: {error}")))?;
    without_null(&mut value);
    let mut text = serde_json::to_string_pretty(&value)
        .map_err(|error| Fatal::new(format!("the policy schema did not serialize: {error}")))?;
    text.push('\n');
    Ok(text)
}

/// Take `null` out of the schema, wherever the generator put it.
///
/// TOML has no null, so a field that is an `Option` means "may be absent" and
/// nothing else. `schemars` 1 has no setting that stops it adding `null` to the
/// type of every such field (and `"default": null` beside it), and leaving that
/// in would tell an editor that a value this format cannot write is accepted.
/// Three shapes carry it: a `type` array, an `anyOf`/`oneOf` branch, and a null
/// default. Whatever is left with one member stops being a list.
fn without_null(value: &mut serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::Object(object) => {
            if object.get("default") == Some(&Value::Null) {
                object.remove("default");
            }
            if let Some(Value::Array(types)) = object.get_mut("type") {
                types.retain(|kind| kind != "null");
                if types.len() == 1 {
                    let only = types.remove(0);
                    object.insert("type".to_owned(), only);
                }
            }
            for key in ["anyOf", "oneOf"] {
                let Some(Value::Array(branches)) = object.get_mut(key) else {
                    continue;
                };
                branches
                    .retain(|branch| branch.get("type").and_then(Value::as_str) != Some("null"));
                if branches.len() == 1 {
                    let only = branches.remove(0);
                    object.remove(key);
                    if let Value::Object(only) = only {
                        object.extend(only);
                    }
                }
            }
            for child in object.values_mut() {
                without_null(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(without_null),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
