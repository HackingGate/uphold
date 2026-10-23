//! `docs/schema/principles.schema.json` against the binary, the standard and
//! this repository's own policy files.
//!
//! The committed file is what `uphold schema` prints, byte for byte
//! (`UPHOLD_SCHEMA_GOLDEN=bless` writes it). It is then held to the JSON Schema
//! 2020-12 metaschema, every policy file this repository ships has to validate
//! against it, and a few documents the deserializer refuses have to be refused
//! here too. A schema that only matched the binary's own output would be a
//! transcript; these are what make it a claim someone else can check.

#![expect(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;

const COMMITTED: &str = "docs/schema/principles.schema.json";

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn printed() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("schema")
        .current_dir(manifest())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

fn committed() -> Value {
    serde_json::from_str(&std::fs::read_to_string(manifest().join(COMMITTED)).unwrap()).unwrap()
}

/// A policy file as the document a schema validates: TOML read into JSON's
/// model, which is the reading an editor's language server does too.
fn policy(text: &str) -> Value {
    let table: toml::Table = text.parse().unwrap();
    serde_json::to_value(table).unwrap()
}

fn errors(text: &str) -> Vec<String> {
    let validator = jsonschema::draft202012::new(&committed()).unwrap();
    validator
        .iter_errors(&policy(text))
        .map(|error| format!("{error} at {}", error.instance_path()))
        .collect()
}

#[test]
fn the_committed_schema_is_what_the_binary_prints() {
    let printed = printed();
    let path = manifest().join(COMMITTED);
    if std::env::var("UPHOLD_SCHEMA_GOLDEN").as_deref() == Ok("bless") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &printed).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap();
    assert!(
        committed == printed,
        "{COMMITTED} is not what `uphold schema` prints; regenerate it with \
         `UPHOLD_SCHEMA_GOLDEN=bless cargo test --test schema_cli`"
    );
}

#[test]
fn the_schema_is_a_valid_2020_12_schema() {
    let schema = committed();
    assert_eq!(
        schema.get("$schema").and_then(Value::as_str).unwrap(),
        "https://json-schema.org/draft/2020-12/schema"
    );
    jsonschema::draft202012::meta::validate(&schema).unwrap();
}

#[test]
fn every_policy_file_this_repository_ships_validates() {
    let mut paths = vec![manifest().join("policy/principles.toml")];
    for entry in std::fs::read_dir(manifest().join("policy/base")).unwrap() {
        let path = entry.unwrap().path();
        if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            paths.push(path);
        }
    }
    assert!(paths.len() > 2, "no bundled set was found: {paths:?}");
    for path in paths {
        let found = errors(&std::fs::read_to_string(&path).unwrap());
        assert!(
            found.is_empty(),
            "{} does not validate: {found:#?}",
            path.display()
        );
    }
}

#[test]
fn a_policy_that_uses_the_less_common_shapes_validates() {
    // The shapes the shipped files do not exercise: a shim scope in its two
    // spellings (a bare word and a one-key table), an override, a remote
    // policy and a retired waiver row.
    let found = errors(
        r#"
owner = "acme"
visibility = "public"
[inherit]
sets = ["credentials"]
disabled_rules = ["x"]
[[inherit.remote]]
repo = "acme/policy"
rev = "0123456789abcdef0123456789abcdef01234567"
path = "policy.toml"
[override.some-rule]
message = "m"
[override.some-rule.files]
exclude = ["vendor/**"]
[rule.r]
regexp = "x"
files.reach = "pinned"
command.scope = "public-target"
command.before = ["gh pr create"]
[[shim]]
command = "gh"
match = ["pr:create"]
scope = { command = { command = "true" } }
[[shim.verbs]]
match = ["pr:create"]
editor = "never"
[[supply_chain.waive]]
scanner = "guarddog"
package = "pypi:x@1"
check = "c"
reason = "r"
"#,
    );
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_document_the_deserializer_refuses_is_refused_by_the_schema() {
    // Each of these is read by `toml::from_str::<PolicyFile>` as an error, so a
    // schema that accepted one would be offering an editor a policy that does
    // not load.
    for (what, text) in [
        (
            "an unknown key on a rule",
            "[rule.r]\nregexp = \"x\"\nregex = \"y\"\n",
        ),
        ("an unknown top-level key", "extends = [\"x\"]\n"),
        (
            "an unknown key under files",
            "[rule.r]\nregexp = \"x\"\nfiles.includes = [\".\"]\n",
        ),
        ("a wrong type for a string", "owner = 3\n"),
        (
            "a wrong type for a list",
            "[rule.r]\nregexp = \"x\"\nallowed_scripts = \"Latin\"\n",
        ),
        ("a number where a flag belongs", "redact_matches = 1\n"),
        (
            "a negative size",
            "[rule.r]\nregexp = \"x\"\nmax_lines = -1\n",
        ),
        (
            "a reach that is not one",
            "[rule.r]\nregexp = \"x\"\nfiles.reach = \"everywhere\"\n",
        ),
        (
            "an override key that would change the check",
            "[override.r]\nregexp = \"x\"\n",
        ),
        (
            "an override file key that is not a scope",
            "[override.r.files]\nmultiline = true\n",
        ),
        (
            "an unknown shim scope",
            "[[shim]]\ncommand = \"gh\"\nscope = \"sometimes\"\n",
        ),
        (
            "a shim with no command",
            "[[shim]]\nmatch = [\"pr:create\"]\n",
        ),
    ] {
        assert!(!errors(text).is_empty(), "{what} was accepted:\n{text}");
    }
}
