//! Comments, as the parser sees them.
//!
//! Every other check in this crate reads bytes, which is the right answer when
//! the question is about bytes. It is the wrong answer for a rule about
//! comments: `let marker = "// TODO";` is a line containing `// TODO` and no
//! comment at all, and a rule written against the text cannot tell the
//! difference. So this module hands the checks a list of comments rather than a
//! list of lines, and the language decides what one is.
//!
//! The distinction that matters most here is the one a prefix test cannot make.
//! `///` starts with `//`, so any check that recognises a comment by its opening
//! characters treats a Rust doc comment as an ordinary one -- and a tool that
//! then deletes what it matched deletes the documentation of a public item. The
//! grammar gives the doc comment its own marker node, so [`Comment::doc`] is
//! read from the parse rather than guessed from the spelling.

use std::collections::BTreeSet;

use tree_sitter::{Node, Parser};

/// The languages a comment rule can be asked about.
///
/// Three, and the third is the demonstration of what the first two claimed: a
/// language is a grammar dependency and three lines in [`Language::for_path`],
/// not a redesign. Go cost neither a dependency nor a design -- the grammar was
/// already linked in for the doc-command resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    Rust,
    Python,
    Go,
}

impl Language {
    /// The language of a repository-relative path, or `None` for a file no
    /// comment rule can read.
    pub(crate) fn for_path(path: &str) -> Option<Self> {
        match path.rsplit_once('.') {
            Some((_, "rs")) => Some(Self::Rust),
            Some((_, "py" | "pyi")) => Some(Self::Python),
            Some((_, "go")) => Some(Self::Go),
            _ => None,
        }
    }

    fn grammar(self) -> tree_sitter::Language {
        match self {
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
        }
    }

    /// The node kinds that ARE comments in this grammar.
    const fn comment_kinds(self) -> &'static [&'static str] {
        match self {
            Self::Rust => &["line_comment", "block_comment"],
            Self::Python | Self::Go => &["comment"],
        }
    }
}

/// One comment, with the code it sits above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Comment {
    /// 1-based, matching every other line number this crate reports.
    pub line: u64,
    /// The comment with its markers removed. What a `comment_regexp` matches
    /// against, so a pattern never has to know how a language spells `//`.
    pub text: String,
    /// A documentation comment: `///` and `//!` in Rust. Kept apart from the
    /// ordinary kind because it is an artefact -- rustdoc publishes it -- and a
    /// rule that treats it as a comment about the code is a rule that deletes
    /// the public API's documentation.
    ///
    /// Always false for Python and for Go, and for Go that is a fact about the
    /// language rather than a gap here. godoc publishes the comment ABOVE a
    /// declaration with no marker to distinguish it -- `//` is the whole of the
    /// syntax -- so there is nothing in the grammar to read, and guessing from
    /// position would make every comment above a function a doc comment and
    /// exclude it from the check. An ordinary comment is the safe reading: it
    /// is the one that leaves the rule doing something.
    pub doc: bool,
    /// Whether the comment stands on its own line rather than trailing code.
    pub own_line: bool,
    /// Whether another comment sits directly above or below it. A comment in a
    /// run is prose spanning several lines, and judging one line of it alone
    /// reads half a sentence.
    pub in_run: bool,
    /// The words of the code this comment introduces: identifiers, split on
    /// case and underscore, plus the contents of any string literal. Empty when
    /// the comment introduces nothing.
    pub subject: BTreeSet<String>,
}

/// Words that carry no information about what code does, so their presence in a
/// comment should not stop it being trivial. Deliberately short: every word here
/// is one that appears in "the thing" as often as in "do the thing", and a list
/// that grew to include verbs would be the enumerated verb table this check
/// exists to avoid.
const FILLER: &[&str] = &[
    "a", "an", "the", "this", "that", "these", "those", "it", "its", "we", "our", "us", "to",
    "for", "of", "and", "or", "in", "on", "at", "by", "with", "from", "into", "as", "is", "are",
    "be", "all", "any", "each", "every", "new", "old", "existing", "current", "here", "then",
    "now", "again", "back", "up", "down", "out", "off", "over", "per",
];

/// Words that make a comment an explanation rather than a restatement.
///
/// A comment that says WHY -- a reason, a condition, a hazard -- is the comment
/// worth keeping, and no subset test can recognise one: "close the file" and
/// "close the file or the lock outlives the process" have the same words plus a
/// clause. The clause is what this list finds.
const EXPLANATORY: &[&str] = &[
    "because",
    "since",
    "so",
    "otherwise",
    "unless",
    "until",
    "while",
    "when",
    "if",
    "but",
    "though",
    "although",
    "however",
    "note",
    "todo",
    "fixme",
    "hack",
    "warning",
    "workaround",
    "caveat",
    "assumes",
    "assume",
    "must",
    "should",
    "cannot",
    "never",
    "always",
    "only",
    "ensure",
    "avoid",
    "prevent",
    "requires",
    "require",
    "needs",
    "need",
    "safety",
    "invariant",
];

/// Strip a comment's markers, whatever the language spells them as.
fn strip_markers(raw: &str) -> String {
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix("///")
        .or_else(|| trimmed.strip_prefix("//!"))
        .or_else(|| trimmed.strip_prefix("//"))
        .or_else(|| trimmed.strip_prefix("#"))
        .unwrap_or(trimmed);
    let body = body
        .strip_prefix("/*")
        .map_or(body, |rest| rest.trim_end_matches("*/"));
    body.trim().to_owned()
}

/// A Rust doc comment, read from the grammar rather than from the spelling.
///
/// The grammar marks `///` and `//!` with their own marker nodes inside the
/// comment. Falling back to the prefix when a grammar version does not emit
/// them keeps the answer right rather than convenient: the fallback is the
/// same test, done worse, and it is only reached when the better one is absent.
fn is_doc_comment(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    let marked = node.children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "doc_comment" | "outer_doc_comment_marker" | "inner_doc_comment_marker"
        )
    });
    if marked {
        return true;
    }
    let text = node_text(node, source);
    let trimmed = text.trim_start();
    trimmed.starts_with("///") || trimmed.starts_with("//!") || trimmed.starts_with("/**")
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or_default()
}

/// Split an identifier into its words: `set_zone_target` and `setZoneTarget`
/// both become `set`, `zone`, `target`.
fn identifier_words(identifier: &str, out: &mut BTreeSet<String>) {
    let mut word = String::new();
    let mut previous_lower = false;
    for character in identifier.chars() {
        if character.is_alphanumeric() {
            if character.is_uppercase() && previous_lower && !word.is_empty() {
                out.insert(std::mem::take(&mut word));
            }
            word.push(character.to_ascii_lowercase());
            previous_lower = character.is_lowercase() || character.is_numeric();
        } else {
            if !word.is_empty() {
                out.insert(std::mem::take(&mut word));
            }
            previous_lower = false;
        }
    }
    if !word.is_empty() {
        out.insert(word);
    }
}

/// Every word the code under a comment names.
///
/// String literals are in here beside the identifiers on purpose. `// Stop and
/// disable dnsmasq` over `systemd::stop("dnsmasq")` restates the literal, not an
/// identifier, and a subject built from identifiers alone would call that
/// comment informative.
fn subject_words(node: Node<'_>, source: &str) -> BTreeSet<String> {
    let mut words = BTreeSet::new();
    let mut cursor = node.walk();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        match current.kind() {
            // Identifiers and literals in one arm, because they are one thing
            // to this check: both are words the code puts on the page, and a
            // comment repeating either is repeating the code.
            // Go spells its literals differently -- `interpreted_string_literal`
            // and `raw_string_literal` -- and a subject built without them would
            // call `// Stop dnsmasq` over `exec.Command("systemctl", "stop",
            // "dnsmasq")` informative, which is the exact case the string
            // literals are here for. `package_identifier` is the name in an
            // import or a qualified call, which is a word the code puts on the
            // page like any other.
            "identifier"
            | "type_identifier"
            | "field_identifier"
            | "package_identifier"
            | "primitive_type"
            | "shorthand_field_identifier"
            | "string_content"
            | "string_literal"
            | "interpreted_string_literal"
            | "interpreted_string_literal_content"
            | "raw_string_literal"
            | "raw_string_literal_content"
            | "string" => {
                identifier_words(node_text(current, source), &mut words);
            }
            _ => {}
        }
        pending.extend(current.children(&mut cursor));
    }
    words
}

/// The statements a comment introduces.
///
/// A run of them, not one: `// Stop and disable dnsmasq` sits above a stop and a
/// disable, and a subject built from the first line alone would find `disable`
/// missing and call the comment informative. The run ends where the reader would
/// end it -- at a blank line, or at the next comment -- so what counts as "the
/// code this comment is about" is the same thing on the page and in the check.
fn introduced_code<'tree>(comment: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut sibling = comment.next_named_sibling();
    let mut previous_end = comment.end_position().row;
    let mut run = Vec::new();
    while let Some(node) = sibling {
        if kinds.contains(&node.kind()) {
            break;
        }
        // A blank line is where a reader stops attributing the comment.
        if node.start_position().row > previous_end + 1 {
            break;
        }
        previous_end = node.end_position().row;
        run.push(node);
        sibling = node.next_named_sibling();
    }
    run
}

/// Collect every comment in one file.
///
/// A file that does not parse is not an error and not silence either: the parse
/// tree of broken source still contains its comments, because the grammar's
/// error recovery keeps lexing. What a caller gets from a file it could not
/// read at all is an empty list, and the selection layer is what reports that.
pub(crate) fn collect(source: &str, language: Language) -> Vec<Comment> {
    let mut parser = Parser::new();
    if parser.set_language(&language.grammar()).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let kinds = language.comment_kinds();
    let mut nodes = Vec::new();
    let mut cursor = tree.walk();
    let mut pending = vec![tree.root_node()];
    while let Some(current) = pending.pop() {
        if kinds.contains(&current.kind()) {
            nodes.push(current);
        }
        pending.extend(current.children(&mut cursor));
    }
    nodes.sort_by_key(Node::start_byte);

    let lines: Vec<&str> = source.lines().collect();
    let comment_lines: BTreeSet<u64> = nodes
        .iter()
        .map(|node| node.start_position().row as u64 + 1)
        .collect();

    nodes
        .iter()
        .map(|&node| {
            let row = node.start_position().row;
            let line = row as u64 + 1;
            let own_line = lines.get(row).is_some_and(|text| {
                text.trim_start()
                    .starts_with(node_text(node, source).trim())
            });
            let in_run = comment_lines.contains(&line.saturating_sub(1))
                || comment_lines.contains(&(line + 1));
            let mut subject = BTreeSet::new();
            for code in introduced_code(node, kinds) {
                subject.extend(subject_words(code, source));
            }
            Comment {
                line,
                text: strip_markers(node_text(node, source)),
                // Rust is the one language here whose grammar marks a doc
                // comment. Python has no such syntax at all, and Go's godoc
                // comment is spelled `//` like every other -- see `Comment::doc`
                // for why guessing from position would be worse than not
                // asking.
                doc: language == Language::Rust && is_doc_comment(node, source),
                own_line,
                in_run,
                subject,
            }
        })
        .collect()
}

/// The words a comment contributes, filler removed.
fn comment_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    for token in text.split(|c: char| !c.is_alphanumeric()) {
        if token.is_empty() {
            continue;
        }
        let lowered = token.to_ascii_lowercase();
        if FILLER.contains(&lowered.as_str()) {
            continue;
        }
        words.push(lowered);
    }
    words
}

/// Whether two words name the same thing.
///
/// Exact match, then a shared stem, then a prefix of at least four characters --
/// which is what lets `config` recognise the `CONF` in `DNSMASQ_CONF_FILE`.
/// Four rather than three because `set` would otherwise match `settings`,
/// `setup` and `setter` alike, and a comment saying `set` beside code that
/// settles something is not a restatement.
fn same_word(comment_word: &str, subject_word: &str) -> bool {
    if comment_word == subject_word {
        return true;
    }
    let stem = |word: &str| {
        let word = word
            .strip_suffix("ing")
            .or_else(|| word.strip_suffix("ed"))
            .or_else(|| word.strip_suffix("es"))
            .or_else(|| word.strip_suffix('s'))
            .unwrap_or(word);
        word.strip_suffix('e').unwrap_or(word).to_owned()
    };
    let (left, right) = (stem(comment_word), stem(subject_word));
    if left == right && !left.is_empty() {
        return true;
    }
    let shorter = left.len().min(right.len());
    shorter >= 4 && (left.starts_with(&right) || right.starts_with(&left))
}

/// Does this comment say only what the code under it already says?
///
/// The test is a subset, not a pattern: every word the comment contributes has
/// to be a word the following code already names. That is the whole rule, and it
/// is why there is no verb list here -- `// Stop and disable dnsmasq` is trivial
/// because `stop`, `disable` and `dnsmasq` are all in the code, not because
/// "stop" is on a list of boring verbs. A comment carrying one word the code
/// does not have is a comment that says something, whatever the word is.
pub(crate) fn is_trivial(comment: &Comment) -> bool {
    if comment.doc || !comment.own_line || comment.in_run {
        return false;
    }
    if comment.subject.is_empty() {
        return false;
    }
    // A separator is not a remark about the code and is not judged as one. Its
    // words restate the section by design -- that is what a heading does -- so
    // a subset test calls every one of them trivial. Whether a tree wants them
    // is a question about house style, which is a `comment_regexp` a repository
    // writes if it wants to, and not a verdict this check should reach on its
    // own.
    if comment.text.contains("---") || comment.text.contains("===") {
        return false;
    }
    if comment.text.contains(['─', '━', '═', '┄', '│']) {
        return false;
    }
    // A worked example is not a restatement: `192.168.1.1/24 -> network =
    // 192.168.1.0` shares every token with the code and says the one thing the
    // code does not, which is what the answer comes out as.
    if comment.text.contains('=') || comment.text.contains('→') || comment.text.contains("->") {
        return false;
    }
    // A parenthesised aside is a qualification -- `(optional, comma-separated)`
    // -- and the words inside it are the part the code does not carry.
    if comment.text.contains('(') && comment.text.contains(')') {
        return false;
    }
    let words = comment_words(&comment.text);
    if words.is_empty() {
        return false;
    }
    if words
        .iter()
        .any(|word| EXPLANATORY.contains(&word.as_str()))
    {
        return false;
    }
    words.iter().all(|word| {
        comment
            .subject
            .iter()
            .any(|subject| same_word(word, subject))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust(source: &str) -> Vec<Comment> {
        collect(source, Language::Rust)
    }

    /// The reason this module exists. `grep-regex` finds `// TODO` in both of
    /// these lines; a comment rule must find it in one.
    #[test]
    fn a_comment_marker_inside_a_string_is_not_a_comment() {
        let found = rust("fn f() {\n    let marker = \"// TODO: not a comment\";\n}\n");
        assert!(found.is_empty(), "{found:?}");
    }

    /// `///` starts with `//`, which is how a prefix test loses a public item's
    /// documentation.
    #[test]
    fn a_doc_comment_is_not_an_ordinary_comment() {
        let found = rust("/// The outer EAP method.\npub struct Config;\n");
        assert_eq!(found.len(), 1);
        assert!(found[0].doc);
        assert!(!is_trivial(&found[0]));
    }

    #[test]
    fn an_inner_doc_comment_is_a_doc_comment() {
        let found = rust("//! Module docs.\npub struct Config;\n");
        assert_eq!(found.len(), 1);
        assert!(found[0].doc);
    }

    /// The literal is part of what the code says, so a comment repeating it is
    /// repeating the code.
    #[test]
    fn a_comment_restating_a_call_and_its_literal_is_trivial() {
        let found = rust(
            "fn f() {\n    // Stop and disable dnsmasq\n    systemd::stop(\"dnsmasq\");\n    systemd::disable(\"dnsmasq\");\n}\n",
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(is_trivial(&found[0]), "{:?}", found[0]);
    }

    /// The run stops where a reader stops attributing the comment.
    #[test]
    fn a_blank_line_ends_the_code_a_comment_is_about() {
        let found = rust(
            "fn f() {\n    // Stop dnsmasq\n    systemd::stop(\"dnsmasq\");\n\n    reload_relay();\n}\n",
        );
        assert!(!found[0].subject.contains("reload"), "{:?}", found[0]);
    }

    /// One word the code does not have, and the comment is saying something.
    #[test]
    fn a_comment_carrying_a_word_the_code_lacks_is_kept() {
        let found = rust(
            "fn f() {\n    // Validate the config offline before prompting.\n    validate_config(&runtime);\n}\n",
        );
        assert_eq!(found.len(), 1);
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    /// A reason is not a restatement, however few words it has.
    #[test]
    fn an_explanatory_clause_is_kept_even_when_its_words_are_in_the_code() {
        let found = rust(
            "fn f() {\n    // Stop dnsmasq because the relay holds the port.\n    systemd::stop(\"dnsmasq\");\n}\n",
        );
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    /// Judging one line of a multi-line comment reads half a sentence.
    #[test]
    fn a_comment_in_a_run_is_not_judged_alone() {
        let found = rust(
            "fn f() {\n    // Stop dnsmasq.\n    // The relay holds the port open otherwise.\n    systemd::stop(\"dnsmasq\");\n}\n",
        );
        assert!(
            found.iter().all(|comment| !is_trivial(comment)),
            "{found:?}"
        );
    }

    #[test]
    fn a_trailing_comment_is_not_judged_as_an_introduction() {
        let found = rust("fn f() {\n    systemd::stop(\"dnsmasq\"); // Stop dnsmasq\n}\n");
        assert_eq!(found.len(), 1);
        assert!(!found[0].own_line);
        assert!(!is_trivial(&found[0]));
    }

    #[test]
    fn python_comments_are_read_with_the_python_grammar() {
        let found = collect("# Load the config\nload_config()\n", Language::Python);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(is_trivial(&found[0]), "{:?}", found[0]);
    }

    #[test]
    fn a_python_shebang_is_not_judged_against_the_code_below_it() {
        let found = collect("#!/usr/bin/env python3\nload_config()\n", Language::Python);
        assert!(
            found.iter().all(|comment| !is_trivial(comment)),
            "{found:?}"
        );
    }

    #[test]
    fn go_comments_are_read_with_the_go_grammar() {
        let found = collect(
            "package main\n\nfunc f() {\n\t// Stop dnsmasq\n\tsystemd.Stop(\"dnsmasq\")\n}\n",
            Language::Go,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].text, "Stop dnsmasq");
        // The Go string literal is part of the subject, which is what makes
        // this a restatement rather than a comment carrying a new word.
        assert!(is_trivial(&found[0]), "{:?}", found[0]);
    }

    /// The reason the grammar is asked rather than the line: this file spells
    /// `//` inside a string and holds no comment at all.
    #[test]
    fn a_go_comment_marker_inside_a_string_is_not_a_comment() {
        let found = collect(
            "package main\n\nfunc f() {\n\tmarker := \"// TODO: not a comment\"\n\t_ = marker\n}\n",
            Language::Go,
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// Go has no doc-comment syntax, so every comment is an ordinary one --
    /// including the one godoc publishes.
    #[test]
    fn a_go_comment_above_a_declaration_is_an_ordinary_comment() {
        let found = collect(
            "package main\n\n// Config is the outer method.\ntype Config struct{}\n",
            Language::Go,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(!found[0].doc);
    }

    /// A comment whose subject could not be read is never trivial, whatever
    /// node kinds the grammar puts under it. The verdict a subject-free comment
    /// must never get is "says only what the code says", because nothing was
    /// read to compare it against.
    #[test]
    fn a_go_comment_with_no_readable_subject_is_not_trivial() {
        let found = collect("package main\n\n// Stop dnsmasq\n", Language::Go);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].subject.is_empty(), "{:?}", found[0]);
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    #[test]
    fn a_go_block_comment_loses_its_markers_like_every_other() {
        let found = collect(
            "package main\n\n/* Stop dnsmasq */\nfunc f() {}\n",
            Language::Go,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].text, "Stop dnsmasq");
    }

    #[test]
    fn an_identifier_splits_on_case_and_underscore() {
        let mut words = BTreeSet::new();
        identifier_words("set_zone_target", &mut words);
        identifier_words("setZoneTarget", &mut words);
        assert!(words.contains("set") && words.contains("zone") && words.contains("target"));
    }

    /// `config` and `CONF` are the same word here; `set` and `settings` are not.
    #[test]
    fn a_shared_prefix_counts_only_when_it_is_long_enough_to_mean_something() {
        assert!(same_word("config", "conf"));
        assert!(same_word("zones", "zone"));
        assert!(!same_word("set", "settings"));
    }

    /// A heading restates its section by design, so a subset test calls every
    /// separator trivial. Judging house style is not this check's job.
    #[test]
    fn a_separator_is_not_judged_as_a_remark_about_the_code() {
        let found = rust("fn f() {\n    // --- ICMP rules ---\n    add_icmp_rules();\n}\n");
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    /// Shares every token with the code, and says the one thing the code does
    /// not: what the answer comes out as.
    #[test]
    fn a_worked_example_is_not_a_restatement() {
        let found = rust(
            "fn f() {\n    // 192.168.1.1/24 = network 192.168.1.0\n    let network = network_of(address);\n}\n",
        );
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    #[test]
    fn a_parenthesised_aside_is_the_part_the_code_does_not_carry() {
        let found = rust(
            "fn f() {\n    // Ports (optional, comma-separated)\n    let ports = prompt(\"Ports\");\n}\n",
        );
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    #[test]
    fn a_language_is_chosen_by_extension_and_nothing_else() {
        assert_eq!(Language::for_path("src/scan.rs"), Some(Language::Rust));
        assert_eq!(Language::for_path("scripts/x.py"), Some(Language::Python));
        assert_eq!(Language::for_path("cmd/x/main.go"), Some(Language::Go));
        assert_eq!(Language::for_path("README.md"), None);
    }
}
