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
/// Three grammars, and the third is the demonstration of what the first two
/// claimed: a language is a grammar dependency and three lines in
/// [`Language::for_path`], not a redesign. Go cost neither a dependency nor a
/// design -- the grammar was already linked in for the doc-command resolver.
///
/// The fourth is not a grammar. TOML, YAML, shell, ini and the dotfiles agree
/// on one thing about comments -- a line whose first non-blank character is
/// `#` is one -- and disagree on everything else, so no parser is linked in for
/// them and none is needed for the one question this module asks of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    Rust,
    Python,
    Go,
    /// A file whose comments are its `#` lines: TOML, YAML, a shell script, an
    /// ini file, a dotfile. Read by line rather than by grammar, and the
    /// own-line restriction is what makes that sound -- a `#` after code may
    /// be inside a string (`color = "#fff"`), a `#` opening a line cannot be.
    HashLines,
}

impl Language {
    /// The language of a repository-relative path, or `None` for a file no
    /// comment rule can read.
    pub(crate) fn for_path(path: &str) -> Option<Self> {
        let name = path.rsplit('/').next().unwrap_or(path);
        // A leading dot is part of the NAME, not the start of an extension.
        // `.gitignore` has no extension at all, and reading one off it would
        // find `gitignore` -- while `.pre-commit-config.yaml` really is YAML
        // and has to stay YAML, which is why the dot is stripped before the
        // split rather than the whole name being treated as one.
        let extension = name
            .strip_prefix('.')
            .unwrap_or(name)
            .rsplit_once('.')
            .map(|(_, found)| found);
        match extension {
            Some("rs") => Some(Self::Rust),
            Some("py" | "pyi") => Some(Self::Python),
            Some("go") => Some(Self::Go),
            Some("toml" | "yaml" | "yml" | "sh" | "bash" | "zsh" | "fish" | "ini" | "cfg") => {
                Some(Self::HashLines)
            }
            // No extension. A dotfile is configuration -- `.gitignore`,
            // `.dockerignore`, `.editorconfig` -- and its remarks are `#`
            // lines. Anything else with no extension is a document, or a
            // binary, and neither has comments.
            None if name.starts_with('.') => Some(Self::HashLines),
            _ => None,
        }
    }

    /// The grammar and the node kinds that ARE comments in it, or `None` for
    /// the kind of file that is read by line.
    fn grammar(self) -> Option<(tree_sitter::Language, &'static [&'static str])> {
        match self {
            Self::Rust => Some((
                tree_sitter_rust::LANGUAGE.into(),
                &["line_comment", "block_comment"],
            )),
            Self::Python => Some((tree_sitter_python::LANGUAGE.into(), &["comment"])),
            Self::Go => Some((tree_sitter_go::LANGUAGE.into(), &["comment"])),
            Self::HashLines => None,
        }
    }

    /// What a selection error names when a rule reads none of these.
    pub(crate) const READABLE: &'static str = "Rust, Python, Go, or a file whose comments are `#` lines (TOML, YAML, shell, ini, a dotfile)";
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
    /// Always false for Python, for Go and for a `#`-line file, and for Go that
    /// is a fact about the language rather than a gap here. godoc publishes the
    /// comment ABOVE a declaration with no marker to distinguish it -- `//` is
    /// the whole of the syntax -- so there is nothing in the grammar to read,
    /// and guessing from position would make every comment above a function a
    /// doc comment and exclude it from the check. An ordinary comment is the
    /// safe reading: it is the one that leaves the rule doing something.
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
    let Some((grammar, kinds)) = language.grammar() else {
        return collect_hash_lines(source);
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

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

/// Every `#` line of a file no grammar reads.
///
/// The subject is the one line under the comment, not a run of statements: with
/// no tree there is no statement, and the next line is the unit a reader of a
/// TOML or YAML file attributes a comment to. A blank line under the comment
/// leaves the subject empty, as it does in the parsed languages, because that
/// is where the reader stops attributing it.
///
/// A shebang is an interpreter directive and not a remark, so the `#!` opening
/// a file is not a comment here. Nothing else that opens with `#` is excluded:
/// a `#` line inside a YAML block scalar is a comment in the script the scalar
/// holds, and the reader it is addressed to is the same one.
fn collect_hash_lines(source: &str) -> Vec<Comment> {
    let lines: Vec<&str> = source.lines().collect();
    let is_comment = |row: usize| {
        lines.get(row).is_some_and(|line| {
            let opener = line.trim_start();
            opener.starts_with('#') && !(row == 0 && opener.starts_with("#!"))
        })
    };
    lines
        .iter()
        .enumerate()
        .filter(|&(row, _)| is_comment(row))
        .map(|(row, line)| {
            let above = row.checked_sub(1).is_some_and(is_comment);
            let below = is_comment(row + 1);
            let next = lines.get(row + 1).copied().unwrap_or_default();
            let mut subject = BTreeSet::new();
            if !below && !next.trim().is_empty() {
                identifier_words(code_of_line(next), &mut subject);
            }
            Comment {
                line: row as u64 + 1,
                text: strip_markers(line),
                doc: false,
                own_line: true,
                in_run: above || below,
                subject,
            }
        })
        .collect()
}

/// A line without the remark trailing it, so the subject is what the code says
/// and not what a second comment beside it says.
///
/// Cut at a `#` that follows whitespace, which is the one spelling a trailing
/// comment has in every `#`-line format; a `#` inside a value is welded to what
/// precedes it (`"#fff"`, `url/#anchor`) and survives the cut.
fn code_of_line(line: &str) -> &str {
    let cut = line
        .char_indices()
        .find(|&(index, character)| {
            character == '#'
                && line
                    .get(..index)
                    .is_some_and(|before| before.ends_with(char::is_whitespace))
        })
        .map_or(line.len(), |(index, _)| index);
    line.get(..cut).unwrap_or(line)
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

/// The most content words a comment may carry and still be judged. Past this
/// it is a paragraph, and a paragraph whose every word is in the code beneath
/// it is describing that code rather than repeating it.
const JUDGED_WORDS: usize = 6;

/// A number with a unit -- `<n>ms`, `<n> KiB`, `<n>%` -- is a measurement, and a
/// measurement states something even when its digits also appear in the code:
/// which quantity the code's number is. `comment-facts` refuses the shape on
/// its own ground; this check leaves it alone rather than reach a second verdict
/// on the same line.
///
/// The digits must open their token, so `sha256`, `utf8` and `v2` are names and
/// not amounts, and the unit is a short run of letters that is not filler --
/// `<n> of <n>` is a proportion the measurement rule reads, not a unit this one
/// does.
fn has_measurement(text: &str) -> bool {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    tokens.iter().enumerate().any(|(index, token)| {
        let token = token.trim_start_matches(|c: char| !c.is_alphanumeric());
        if !token.starts_with(|c: char| c.is_ascii_digit()) {
            return false;
        }
        let rest =
            token.trim_start_matches(|c: char| c.is_ascii_digit() || matches!(c, '.' | ',' | '_'));
        let unit = if rest.is_empty() {
            tokens.get(index + 1).copied().unwrap_or_default()
        } else {
            rest
        };
        is_unit(unit)
    })
}

fn is_unit(token: &str) -> bool {
    const LONGEST_UNIT: usize = 5;
    let token = token.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '%');
    if token == "%" {
        return true;
    }
    !token.is_empty()
        && token.len() <= LONGEST_UNIT
        && token.chars().all(|c| c.is_ascii_alphabetic())
        && !FILLER.contains(&token.to_ascii_lowercase().as_str())
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
    // A link is a reference the code does not carry, whatever the words
    // around it say; a measurement is a claim about a quantity, judged by the
    // rule written for one.
    if comment.text.contains("://") || comment.text.contains("www.") {
        return false;
    }
    if has_measurement(&comment.text) {
        return false;
    }
    let words = comment_words(&comment.text);
    if words.is_empty() || words.len() > JUDGED_WORDS {
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

    /// The dot that opens a dotfile's name is not the dot before an extension.
    #[test]
    fn a_hash_line_file_is_known_by_extension_or_by_its_leading_dot() {
        for path in [
            "Cargo.toml",
            ".github/workflows/ci.yml",
            ".pre-commit-config.yaml",
            "scripts/install.sh",
            "setup.cfg",
            ".gitignore",
        ] {
            assert_eq!(
                Language::for_path(path),
                Some(Language::HashLines),
                "{path}"
            );
        }
        assert_eq!(Language::for_path("LICENSE"), None);
        assert_eq!(Language::for_path("docs/index.html"), None);
    }

    fn hashes(source: &str) -> Vec<Comment> {
        collect(source, Language::HashLines)
    }

    /// The case that opened this: a comment no text-only rule can see anything
    /// wrong with, because everything wrong with it is on the next line.
    #[test]
    fn a_hash_comment_restating_the_next_line_is_trivial() {
        let found = hashes("# the runner is ubuntu-latest\nrunner = \"ubuntu-latest\"\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].text, "the runner is ubuntu-latest");
        assert!(is_trivial(&found[0]), "{:?}", found[0]);
    }

    #[test]
    fn a_hash_comment_giving_a_reason_is_kept() {
        let found = hashes(
            "# ubuntu-latest, because the installer falls back to musl\nrunner = \"ubuntu-latest\"\n",
        );
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    #[test]
    fn a_hash_comment_carrying_a_word_the_line_lacks_is_kept() {
        let found = hashes("# the cheapest runner\nrunner = \"ubuntu-latest\"\n");
        assert!(!is_trivial(&found[0]), "{:?}", found[0]);
    }

    /// A link, a measurement and a paragraph are each doing something other
    /// than repeating, and none is judged.
    #[test]
    fn a_link_a_measurement_and_a_paragraph_are_not_judged() {
        for source in [
            "# runner https://example.test/runner\nrunner = \"ubuntu-latest\"\n",
            "# runner timeout 30 s\nrunner_timeout = 30\n",
            "# 50% of the runner\nrunner = \"ubuntu-latest\"\n",
            "# the ubuntu latest runner image name value default choice\nrunner = \"ubuntu latest image name value default choice\"\n",
        ] {
            let found = hashes(source);
            assert!(!is_trivial(&found[0]), "{:?}", found[0]);
        }
    }

    /// The measurement skip reads amounts, not the digits inside a name.
    #[test]
    fn a_number_is_a_measurement_only_with_a_unit_after_it() {
        assert!(has_measurement("timeout 30 s"));
        assert!(has_measurement("about 4KiB each"));
        assert!(has_measurement("~127 MB of rlib"));
        assert!(has_measurement("half, 50%"));
        assert!(!has_measurement("sha256 of the archive"));
        assert!(!has_measurement("python3 interpreter"));
        assert!(!has_measurement("since 2024"));
        assert!(!has_measurement("3 of them"));
        assert!(!has_measurement("v1.14.1 release"));
    }

    /// The trailing remark on the code line is not the code.
    #[test]
    fn a_trailing_remark_on_the_next_line_is_not_part_of_its_subject() {
        let found = hashes("# the runner\nrunner = \"x\" # runner of the job\n");
        assert!(!found[0].subject.contains("job"), "{:?}", found[0]);
        assert_eq!(
            code_of_line("color = \"#fff\" # swatch"),
            "color = \"#fff\" "
        );
        assert_eq!(code_of_line("url = \"a/#anchor\""), "url = \"a/#anchor\"");
    }

    /// A run is prose, and a blank line is where attribution stops -- the same
    /// two answers the parsed languages give.
    #[test]
    fn a_hash_comment_in_a_run_or_above_a_blank_line_is_not_judged() {
        let run = hashes("# the runner\n# is ubuntu-latest\nrunner = \"ubuntu-latest\"\n");
        assert_eq!(run.len(), 2, "{run:?}");
        assert!(run.iter().all(|comment| comment.in_run), "{run:?}");
        assert!(run.iter().all(|comment| !is_trivial(comment)), "{run:?}");
        let blank = hashes("# the runner\n\nrunner = \"ubuntu-latest\"\n");
        assert!(blank[0].subject.is_empty(), "{:?}", blank[0]);
        assert!(!is_trivial(&blank[0]), "{:?}", blank[0]);
    }

    /// A shebang is an interpreter directive; a `#` line further down a script
    /// is a comment like any other.
    #[test]
    fn a_shebang_is_not_a_comment_and_a_later_hash_line_is() {
        let found = hashes("#!/usr/bin/env bash\n# strict mode\nset -euo pipefail\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].line, 2);
        assert!(!found[0].in_run, "{:?}", found[0]);
    }

    /// A TOML table header and a YAML key are lines, and a comment repeating
    /// either is repeating the code.
    #[test]
    fn a_hash_comment_over_a_table_header_or_a_key_is_judged_against_it() {
        let table = hashes("# dependencies\n[dependencies]\n");
        assert!(is_trivial(&table[0]), "{:?}", table[0]);
        let key = hashes("# the release job\nrelease:\n  runs-on: ubuntu-latest\n");
        assert!(!is_trivial(&key[0]), "{:?}", key[0]);
    }
}
