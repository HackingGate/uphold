//! The Claude Code plugin under `plugins/claude-code/`: the one copy of the
//! hook entries a user or repository enables, in place of JSON pasted into a
//! settings file.
//!
//! Two properties are held here, because the plugin format accepts a file
//! that loses either one. Every entry runs `uphold hook claude-code` and
//! nothing else, so the plugin cannot become a carrier for some other
//! command. And every entry on an event that can refuse -- `PreToolUse` and
//! `Stop` -- carries `onFailure: "block"`: without it a hook that cannot start
//! (`uphold` missing from `PATH`, exit 127) is a non-blocking error and the
//! tool call or the turn's end proceeds, so the plugin would fail open.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    reason = "A test asserts on the outcome; a panic in the harness IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::Path;

use serde_json::{Value, json};

const COMMAND: &str = "uphold hook claude-code";
const BLOCKING_EVENTS: &[&str] = &["PreToolUse", "Stop"];

/// Every way `hooks` departs from the two properties, one line each.
fn refusals(hooks: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let Some(events) = hooks.get("hooks").and_then(Value::as_object) else {
        return vec!["no `hooks` object".to_owned()];
    };
    for event in BLOCKING_EVENTS {
        if !events.contains_key(*event) {
            found.push(format!("{event}: no entry"));
        }
    }
    for (event, groups) in events {
        let handlers = groups
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|group| group.get("hooks").and_then(Value::as_array))
            .flatten();
        for handler in handlers {
            let command = handler.get("command").and_then(Value::as_str);
            if command != Some(COMMAND) {
                found.push(format!("{event}: runs {command:?}, not {COMMAND:?}"));
            }
            if BLOCKING_EVENTS.contains(&event.as_str())
                && handler.get("onFailure").and_then(Value::as_str) != Some("block")
            {
                found.push(format!("{event}: no onFailure \"block\""));
            }
        }
    }
    found
}

fn shipped() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/claude-code/hooks/hooks.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("hooks.json is readable"))
        .expect("hooks.json is JSON")
}

#[test]
fn the_shipped_hooks_run_only_uphold_and_fail_closed() {
    assert_eq!(refusals(&shipped()), Vec::<String>::new());
}

#[test]
fn a_blocking_entry_without_on_failure_is_refused() {
    for event in BLOCKING_EVENTS {
        let mut hooks = shipped();
        let handler = hooks["hooks"][*event][0]["hooks"][0]
            .as_object_mut()
            .expect("a handler object");
        handler.remove("onFailure");
        assert_eq!(
            refusals(&hooks),
            vec![format!("{event}: no onFailure \"block\"")]
        );
    }
}

#[test]
fn an_entry_running_another_command_is_refused() {
    let mut hooks = shipped();
    hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"] = json!("sh -c true");
    assert_eq!(
        refusals(&hooks),
        vec![format!(
            "SessionStart: runs Some(\"sh -c true\"), not {COMMAND:?}"
        )]
    );
}

#[test]
fn a_missing_blocking_event_is_refused() {
    let mut hooks = shipped();
    hooks["hooks"]
        .as_object_mut()
        .expect("the events object")
        .remove("Stop");
    assert_eq!(refusals(&hooks), vec!["Stop: no entry".to_owned()]);
}
