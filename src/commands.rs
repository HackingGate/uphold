//! A document that tells a reader to run `<command> <verb>` must name a verb the
//! command dispatches on.
//!
//! The sibling of `links-resolve`, for the other half of what a document asserts
//! about a tree. That one resolves a path a reader would CLICK; this resolves a
//! command a reader would RUN. Both are prose that happens to be checkable, and
//! before either existed both failed the same way: silently, forever, with every
//! gate in every repository still green.
//!
//! The defect it was built from, measured rather than imagined. A `README.md`
//! opened with `fg-registry credentials` for as long as the file existed. That
//! command has two verbs and `credentials` was never one of them -- the binary's
//! own error names the alternatives -- so the answer was one invocation away.
//! Nobody invoked it, because a reader who trusts the README has no reason to and
//! a reader who does not is not reading the README.
//!
//! WHY THE DISPATCH AND NOT `--help`.
//!
//! Running the binary needs a build -- warm locally, cold in CI, and a gate that
//! needs the network is a gate that gets skipped -- and it invites the far worse
//! mistake of resolving a verb by RUNNING it: `fg-registry sync` in a document
//! would be "verified" by fast-forwarding thirty-nine submodules. Only the help
//! text is safe to execute for, and help text is prose too. A doc comment drifts
//! from the switch below it exactly as the README drifted.
//!
//! The switch IS the verb list. `case "sync":` is not a description of what the
//! command accepts; it is the mechanism by which it accepts it, and it cannot be
//! stale without also being broken.
//!
//! WHY A COMMAND MUST AGREE WITH ITSELF BEFORE IT JUDGES ANYONE.
//!
//! A verb list read wrong is worse than no verb list: it produces confident
//! findings against documents that were right. Measured on the implementation
//! this ports -- the first run reported 38 findings, one binary supplied 22 of
//! them by dispatching in a form the parser could not read while an unrelated
//! switch in the same binary supplied a plausible-looking verb list, and every
//! one of those findings was false and read as real.
//!
//! So a command judges documents only when two independent readings of its own
//! sources agree: the string labels of its dispatch, and the verbs its own usage
//! block names about itself. When they disagree the parse is not trusted, and the
//! command is counted, named and skipped rather than guessed at. That count is
//! reported every run, which is what keeps a check that read four commands out of
//! a hundred from reading like one that read all of them.
//!
//! WHY A GRAMMAR AND NOT A LINE MATCHER. The implementation this replaces read
//! dispatches with a regex over lines and an allow-list of eight subject
//! spellings taken off dispatches in one workspace. Both halves of its measured
//! false-finding rate come from that: a tagless `switch {` is a line the matcher
//! cannot read, and a subject list read off one tree is a list that describes one
//! tree. A grammar answers the question structurally, and the crate was already
//! in this binary for [`crate::comments`].

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use tree_sitter::{Node, Parser};

/// The languages a command's dispatch can be read from.
///
/// Two, and the second is here to keep the first from being a special case: a
/// third is a grammar dependency and one row in [`Language::of_path`]. Go
/// because it is the language the defect was measured in; Rust because this
/// binary is written in it, so the rule can be pointed at its own tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    Go,
    Rust,
}

/// Where the string labels of a dispatch live in one grammar.
///
/// A table rather than a function per language, for the reason
/// `parameterize-do-not-enumerate` gives: the two readings differ only by node
/// names, so a second walk written out for the second language would be one unit
/// with an unextracted parameter -- and the next grammar would need an author
/// instead of a row.
#[derive(Debug, Clone, Copy)]
struct Shape {
    /// The node that dispatches: a Go expression switch, a Rust match.
    switch: &'static str,
    /// The field holding what is being dispatched ON. Absent on a Go tagless
    /// `switch {`, which is exactly the form that has to be skipped rather than
    /// read wrong.
    subject: &'static str,
    /// One branch of it.
    arm: &'static str,
    /// The field of a branch holding the labels it matches.
    labels: &'static str,
    /// The literal node a label is, when the label is a string.
    string: &'static str,
    /// The node a catch-all branch is, where the grammar gives it one of its
    /// own. Go spells `default:` as a different node from `case`; Rust spells it
    /// as an ordinary arm whose pattern binds instead of matching a literal, and
    /// is `None` here because the empty-label test already finds it.
    default: Option<&'static str>,
}

impl Language {
    /// The language of a repository-relative path, or `None` for a file whose
    /// dispatch this cannot read.
    pub(crate) fn of_path(path: &str) -> Option<Self> {
        match path.rsplit_once('.') {
            Some((_, "go")) => Some(Self::Go),
            Some((_, "rs")) => Some(Self::Rust),
            _ => None,
        }
    }

    fn grammar(self) -> tree_sitter::Language {
        match self {
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
        }
    }

    const fn shape(self) -> Shape {
        match self {
            Self::Go => Shape {
                switch: "expression_switch_statement",
                subject: "value",
                arm: "expression_case",
                labels: "value",
                string: "interpreted_string_literal",
                default: Some("default_case"),
            },
            Self::Rust => Shape {
                switch: "match_expression",
                subject: "value",
                arm: "match_arm",
                labels: "pattern",
                string: "string_literal",
                default: None,
            },
        }
    }
}

/// A string literal with its quotes taken off.
///
/// The grammars name the content node differently and both wrap it in the
/// delimiters, so the delimiters are trimmed rather than the content node looked
/// up by a name that would be a third thing to keep in [`Shape`].
fn unquoted(node: Node<'_>, source: &str) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?;
    let inner = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))?;
    (!inner.is_empty() && !inner.contains('\\')).then(|| inner.to_owned())
}

/// Every string label of one branch.
fn labels_of(arm: Node<'_>, shape: Shape, source: &str) -> Vec<String> {
    let Some(pattern) = arm.child_by_field_name(shape.labels) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut cursor = pattern.walk();
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        if node.kind() == shape.string {
            if let Some(text) = unquoted(node, source) {
                found.push(text);
            }
            continue;
        }
        stack.extend(node.children(&mut cursor));
    }
    found
}

/// The verbs one dispatch offers, or `None` if this node is not a dispatch.
///
/// Three structural conditions, and each one is a false finding the line matcher
/// this replaces produced:
///
/// * it dispatches on SOMETHING. A Go tagless `switch {` is a chain of boolean
///   arms, not a lookup, and reading its arms as verbs is where 22 of one run's
///   38 findings came from.
/// * at least two branches match STRING literals. A match over an enum is a
///   state machine, and its variants are not things a reader types.
/// * a catch-all branch exists. A command dispatching on a word the user chose
///   has to answer for a word it does not know, and a lookup with no default is
///   almost never one.
///
/// The conditions are deliberately structural rather than a list of subject
/// spellings. An allow-list of subjects read off one workspace's dispatches is a
/// list that describes that workspace, and the agreement gate above this is what
/// disciplines a generous reading -- not a narrow one that silently misses a
/// dispatch spelled a way nobody had seen yet.
fn dispatch_labels(node: Node<'_>, shape: Shape, source: &str) -> Option<BTreeSet<String>> {
    node.child_by_field_name(shape.subject)?;
    let mut cursor = node.walk();
    let mut verbs: BTreeSet<String> = BTreeSet::new();
    let mut arms = 0usize;
    let mut catch_all = false;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        for child in current.children(&mut cursor) {
            if shape.default == Some(child.kind()) {
                catch_all = true;
                continue;
            }
            if child.kind() == shape.arm {
                let labels = labels_of(child, shape, source);
                if labels.is_empty() {
                    catch_all = true;
                } else {
                    arms += 1;
                    verbs.extend(labels);
                }
                continue;
            }
            // A Go switch keeps its cases in a block, and a Rust match keeps its
            // arms in a `match_block`. Descending rather than naming the block
            // kind keeps [`Shape`] to what actually differs.
            if child.kind() != shape.switch {
                stack.push(child);
            }
        }
    }
    (arms >= 2 && catch_all).then_some(verbs)
}

/// Every verb the sources of one command dispatch on.
///
/// Unioned across the declared sources, because a `main` that delegates keeps
/// its dispatch one package over and both files are the command's own. What
/// bounds the union is the DECLARATION: a pattern names one command's sources,
/// so a sibling binary in the same repository cannot lend it verbs. That
/// collision is not hypothetical -- a repository-wide widening in the
/// implementation this ports resolved a flag-only command to the verbs of its
/// neighbour, and a document naming one of them would have passed.
pub(crate) fn dispatched(sources: &[(String, String)]) -> BTreeSet<String> {
    let mut verbs: BTreeSet<String> = BTreeSet::new();
    for (path, text) in sources {
        let Some(language) = Language::of_path(path) else {
            continue;
        };
        let mut parser = Parser::new();
        if parser.set_language(&language.grammar()).is_err() {
            continue;
        }
        let Some(tree) = parser.parse(text.as_bytes(), None) else {
            continue;
        };
        let shape = language.shape();
        let mut cursor = tree.root_node().walk();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == shape.switch {
                if let Some(found) = dispatch_labels(node, shape, text) {
                    verbs.extend(found);
                }
            }
            stack.extend(node.children(&mut cursor));
        }
    }
    // `-h` and `--help` sit in the same switch as the real verbs and are not
    // verbs a document would be wrong to name.
    verbs.retain(|verb| !verb.starts_with('-'));
    verbs
}

/// What may sit to the left of a command name and still leave the text an
/// invocation: a comment leader, a shell prompt, and the path the binary is
/// reached by. Anything else means the name is a word in a sentence.
fn lead() -> &'static Regex {
    static LEAD: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    #[expect(
        clippy::unwrap_used,
        reason = "a literal pattern that compiles or does not, decided at the first call and not by any input"
    )]
    LEAD.get_or_init(|| Regex::new(r"^[\s>]*(?://+|#+|\*)?\s*[$%]?\s*(?:\./)?").unwrap())
}

/// `<command> [flags] <verb>`, anchored where the lead ends.
fn invocation(command: &str) -> Option<Regex> {
    Regex::new(&format!(
        r"^{}(?:\.sh)?\s+(?:-{{1,2}}[A-Za-z0-9][^\s]*\s+)*([a-z][a-z0-9-]*)",
        regex::escape(command)
    ))
    .ok()
}

/// The verbs a command's own sources name in a USAGE position.
///
/// The second reading, and deliberately the same first-token rule the documents
/// are held to, applied to the command's own usage block. A sentence such as
/// "Command fg-registry operates on the workspace" is not in a usage position and
/// contributes nothing; `//\tfg-registry sync [options]` in a doc comment is, and
/// contributes `sync`.
pub(crate) fn documented(command: &str, sources: &[(String, String)]) -> BTreeSet<String> {
    let Some(pattern) = invocation(command) else {
        return BTreeSet::new();
    };
    let mut verbs = BTreeSet::new();
    for (_, text) in sources {
        for line in text.lines() {
            if let Some(verb) = first_verb(line, &pattern) {
                verbs.insert(verb);
            }
        }
    }
    verbs
}

/// The verb this text invokes, if it invokes one at all.
///
/// Anchored after the lead, because an invocation BEGINS with the binary.
/// Searching anywhere in the text is what matched a command name inside an
/// ordinary sentence and inside a column of an ASCII diagram, and both were false
/// findings on the first run of the implementation this ports.
fn first_verb(text: &str, pattern: &Regex) -> Option<String> {
    let start = lead().find(text).map_or(0, |found| found.end());
    let rest = text.get(start..)?;
    let captured = pattern.captures(rest)?;
    captured.get(1).map(|verb| verb.as_str().to_owned())
}

/// One place a document tells a reader to run something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mention {
    /// 1-based, matching every other line number this crate reports.
    pub line: u64,
    pub command: String,
    pub verb: String,
}

/// `(line number, code)` for every fenced-block line and every inline span.
///
/// Prose is not read at all. An instruction is written in a code span, and a
/// sentence that happens to contain the same two words in a row is not an
/// instruction -- matching it is how this check would earn a blanket waiver.
fn code_spans(text: &str) -> Vec<(u64, String)> {
    let mut spans: Vec<(u64, String)> = Vec::new();
    let mut fence: Option<char> = None;
    for (index, line) in text.lines().enumerate() {
        let number = index as u64 + 1;
        let trimmed = line.trim_start();
        let opener = trimmed
            .starts_with("```")
            .then_some('`')
            .or_else(|| trimmed.starts_with("~~~").then_some('~'));
        if let Some(marker) = opener {
            match fence {
                None => fence = Some(marker),
                Some(open) if open == marker => fence = None,
                Some(_) => {}
            }
            continue;
        }
        if fence.is_some() {
            spans.push((number, line.to_owned()));
            continue;
        }
        // An inline span is non-greedy and single-line: one that opened and never
        // closed on its line is not a span.
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let Some(after) = rest.get(open + 1..) else {
                break;
            };
            let Some(close) = after.find('`') else {
                break;
            };
            if let Some(code) = after.get(..close) {
                spans.push((number, code.to_owned()));
            }
            let Some(remainder) = after.get(close + 1..) else {
                break;
            };
            rest = remainder;
        }
    }
    spans
}

/// Every invocation a document names, for the commands whose verbs are trusted.
pub(crate) fn mentions(text: &str, commands: &BTreeMap<String, BTreeSet<String>>) -> Vec<Mention> {
    let mut found = Vec::new();
    for command in commands.keys() {
        // Cheap rejection first. Most documents name no command at all, and
        // compiling a pattern per command per file would be the cost this
        // avoids by asking a substring question first.
        if !text.contains(command.as_str()) {
            continue;
        }
        let Some(pattern) = invocation(command) else {
            continue;
        };
        for (line, code) in code_spans(text) {
            if let Some(verb) = first_verb(&code, &pattern) {
                found.push(Mention {
                    line,
                    command: command.clone(),
                    verb,
                });
            }
        }
    }
    found.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.command.cmp(&right.command))
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(path: &str, text: &str) -> Vec<(String, String)> {
        vec![(path.to_owned(), text.to_owned())]
    }

    fn verbs(named: &[&str]) -> BTreeSet<String> {
        named.iter().map(|verb| (*verb).to_owned()).collect()
    }

    fn offering(command: &str, named: &[&str]) -> BTreeMap<String, BTreeSet<String>> {
        let mut commands = BTreeMap::new();
        commands.insert(command.to_owned(), verbs(named));
        commands
    }

    const GO_DISPATCH: &str = r#"
package main

func main() {
	args := os.Args[1:]
	switch args[0] {
	case "sync":
		sync()
	case "services":
		services()
	default:
		usage()
	}
}
"#;

    #[test]
    fn a_go_switch_on_a_subcommand_is_the_verb_list() {
        let found = dispatched(&sources("cmd/fg-registry/main.go", GO_DISPATCH));
        assert_eq!(found, verbs(&["services", "sync"]));
    }

    /// The form that supplied 22 of one run's 38 false findings.
    ///
    /// A tagless `switch {` is a chain of boolean arms and not a lookup, so its
    /// arms are not verbs. The line matcher this replaces could not see the
    /// difference; the grammar reports the missing subject.
    #[test]
    fn a_tagless_switch_offers_no_verbs_rather_than_wrong_ones() {
        let tagless = r"
package main

func main() {
	switch {
	case ready():
		go run()
	case waiting():
		wait()
	default:
		stop()
	}
}
";
        assert!(dispatched(&sources("cmd/session/main.go", tagless)).is_empty());
    }

    /// A match over an enum is a state machine, and its variants are not things
    /// a reader types into a shell.
    #[test]
    fn a_match_with_no_string_labels_is_not_a_dispatch() {
        let states = r"
fn step(state: State) -> State {
    match state {
        State::Idle => State::Running,
        State::Running => State::Done,
        _ => state,
    }
}
";
        assert!(dispatched(&sources("src/main.rs", states)).is_empty());
    }

    /// A lookup on a word the user chose has to answer for a word it does not
    /// know. One without a catch-all is almost never a dispatch.
    #[test]
    fn a_string_match_with_no_catch_all_is_not_a_dispatch() {
        let exhaustive = r#"
fn label(kind: &str) -> &str {
    match kind {
        "a" => "first",
        "b" => "second",
        other => other,
    }
}
"#;
        // `other` binds rather than matching a literal, so it IS the catch-all
        // and this one resolves. The negative case is the same body with the
        // final arm removed, which does not compile in Rust and so cannot be
        // the shape a real dispatch takes.
        assert!(!dispatched(&sources("src/main.rs", exhaustive)).is_empty());
    }

    #[test]
    fn a_rust_match_on_a_subcommand_is_the_verb_list() {
        let rust = r#"
fn run(first: &str) -> Result<()> {
    match first {
        "scan" => scan(),
        "guard" => guard(),
        other => Err(unknown(other)),
    }
}
"#;
        let verbs = dispatched(&sources("src/main.rs", rust));
        assert!(verbs.contains("scan"), "{verbs:?}");
        assert!(verbs.contains("guard"), "{verbs:?}");
    }

    #[test]
    fn a_usage_block_reads_under_the_same_first_token_rule() {
        let go = r"
package main

// fg-registry sync [options]
// fg-registry services
//
// Command fg-registry operates on the workspace's own registries.
func main() {}
";
        let named = documented("fg-registry", &sources("cmd/fg-registry/main.go", go));
        assert!(named.contains("sync"), "{named:?}");
        assert!(named.contains("services"), "{named:?}");
        // The prose sentence is not in a usage position, so it contributes
        // nothing. Without the first-token rule it would contribute `operates`,
        // the two readings would disagree, and the command would skip itself
        // out over a sentence that was perfectly correct.
        assert!(!named.contains("operates"), "{named:?}");
    }

    #[test]
    fn only_a_code_span_is_read_and_only_at_its_first_token() {
        let document = "\
Read it with:

```
fg-registry credentials
```

The very fg-registry session it captures with is not an instruction, and
neither is `see fg-registry sync` in the middle of a span.
";
        let commands = offering("fg-registry", &["sync"]);
        let found = mentions(document, &commands);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found.first().map(|one| (one.verb.as_str(), one.line)),
            Some(("credentials", 4))
        );
    }

    /// A flag before the verb does not hide it, and a flag that takes a
    /// SEPARATE value does.
    ///
    /// Stated as a test rather than left to be discovered, because the failure
    /// direction matters: `--workspace here sync` reads `here` as the verb, and
    /// `here` is not in the verb list, so the rule reports a document that was
    /// right. Nothing in the text distinguishes a flag's value from a verb --
    /// only the command's own flag table does, and reading that is a second
    /// parse with a second way to be wrong. The narrow form is what is
    /// supported; `--flag=value` is unambiguous and passes through.
    #[test]
    fn a_flag_before_the_verb_does_not_hide_it_unless_it_takes_a_value() {
        let commands = offering("fg-registry", &["sync"]);
        for span in [
            "`fg-registry --verbose sync`",
            "`fg-registry --workspace=here sync`",
        ] {
            let found = mentions(&format!("{span}\n"), &commands);
            assert_eq!(found.len(), 1, "{span}: {found:?}");
            assert!(found.iter().any(|m| m.verb == "sync"), "{span}: {found:?}");
        }
        let valued = mentions("`fg-registry --workspace here sync`\n", &commands);
        assert!(
            valued.iter().any(|m| m.verb == "here"),
            "the limit, asserted so it cannot change silently: {valued:?}"
        );
    }
}
