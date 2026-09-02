//! Reading Rust with the parser this binary already carries.
//!
//! Shared because there are two structural rules now and there was one, and the
//! second one's whole cost is the question the structural-tier research asks:
//! what does a rule over a syntax tree cost once the reader exists? These
//! functions are that reader, and the answer for `structural_documentation.rs`
//! is a predicate and a list.
//!
//! `unparsed` is the one nobody may skip. tree-sitter recovers a tree from
//! almost any input, so a walk over a source that did not parse finds less than
//! is there and reports the same silence as a source that complies -- which is
//! `UNKNOWN -> PASS`, at the seam that decides it.

#![expect(
    clippy::expect_used,
    reason = "a test's reader reports by panicking; there is no caller to hand a Result to"
)]

use tree_sitter::{Node, Parser};

/// The tree, kept alive for the nodes handed out of these readers.
pub fn parse(source: &str) -> &'static tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("the Rust grammar this crate links");
    let tree = parser.parse(source, None).expect("a tree, or a timeout");
    Box::leak(Box::new(tree))
}

/// The line of the first region the grammar could not read, if there is one.
///
/// A structural check over a source this returns `Some` for has established
/// nothing about that source.
pub fn unparsed(source: &str) -> Option<usize> {
    let tree = parse(source);
    if !tree.root_node().has_error() {
        return None;
    }
    let mut cursor = tree.walk();
    let mut pending = vec![tree.root_node()];
    let mut first = None;
    while let Some(node) = pending.pop() {
        if node.is_error() || node.is_missing() {
            let line = node.start_position().row + 1;
            first = Some(first.map_or(line, |earlier: usize| earlier.min(line)));
        }
        pending.extend(node.children(&mut cursor));
    }
    // `has_error` is true and no node carries the flag only if the grammar
    // changed shape underneath this reader. Line 1 is the honest answer then:
    // something is wrong and the reader cannot say where.
    Some(first.unwrap_or(1))
}

/// Every call expression in `source`, with the text of the function called.
///
/// What the grammar recovered, which over a broken source is less than what is
/// there. Every caller asks `unparsed` first.
pub fn calls(source: &str) -> Vec<(String, Node<'_>)> {
    let tree = parse(source);

    let mut found = Vec::new();
    let mut cursor = tree.walk();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let text = source[function.byte_range()].to_owned();
                found.push((text, node));
            }
        }
        pending.extend(node.children(&mut cursor));
    }
    found
}

/// The function a node sits inside, by name.
pub fn enclosing_function<'a>(source: &'a str, node: Node<'a>) -> Option<String> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_item" {
            let name = parent.child_by_field_name("name")?;
            return Some(source[name.byte_range()].to_owned());
        }
        current = parent;
    }
    None
}

/// The `function_item` called `name`, if this source declares one.
pub fn function_named<'a>(source: &'a str, name: &str) -> Option<Node<'a>> {
    let tree = parse(source);
    let mut cursor = tree.walk();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "function_item"
            && node
                .child_by_field_name("name")
                .is_some_and(|found| source[found.byte_range()] == *name)
        {
            return Some(node);
        }
        pending.extend(node.children(&mut cursor));
    }
    None
}

/// One declaration at the top level of a file.
#[derive(Debug)]
pub struct Declaration {
    /// `fn`, `struct`, `enum`, `trait`, `type`, `const`, `static`.
    pub kind: &'static str,
    pub name: String,
    pub line: usize,
    /// Whether a `///` or `/** */` comment sits directly above it, looking past
    /// any attributes in between.
    pub documented: bool,
    /// Whether it is `pub(crate)` -- the surface one module offers another.
    pub shared: bool,
}

/// Every declaration directly under the file, in source order.
///
/// TOP LEVEL ONLY, and the limit is deliberate: a method inside an `impl` reads
/// under the type's own documentation, and a rule that demanded a docstring on
/// every one of them would be answered by whatever silences it fastest.
pub fn declarations(source: &str) -> Vec<Declaration> {
    let tree = parse(source);
    let mut cursor = tree.walk();
    let mut found = Vec::new();
    for node in tree.root_node().children(&mut cursor) {
        let kind = match node.kind() {
            "function_item" => "fn",
            "struct_item" => "struct",
            "enum_item" => "enum",
            "trait_item" => "trait",
            _ => continue,
        };
        let Some(name) = node.child_by_field_name("name") else {
            continue;
        };
        found.push(Declaration {
            kind,
            name: source[name.byte_range()].to_owned(),
            line: node.start_position().row + 1,
            documented: documented(source, node),
            shared: shared(node),
        });
    }
    found
}

/// Is there a doc comment above this declaration?
///
/// Attributes are stepped over: `#[derive(Debug)]` between the docstring and the
/// item is the ordinary spelling, and reading only the immediately previous
/// sibling calls every derived struct undocumented.
fn documented(source: &str, node: Node<'_>) -> bool {
    let mut previous = node.prev_sibling();
    while let Some(sibling) = previous {
        let text = &source[sibling.byte_range()];
        match sibling.kind() {
            "attribute_item" => previous = sibling.prev_sibling(),
            "line_comment" | "block_comment" => {
                return text.starts_with("///") || text.starts_with("/**")
            }
            _ => return false,
        }
    }
    false
}

/// Is this declaration reachable from another module -- `pub` or `pub(crate)`?
///
/// A private helper is read beside its only callers, which are in the same
/// file; a shared one is read by somebody who is not looking at this file at
/// all, and that is the difference the rule is scoped on.
fn shared(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|child| child.kind() == "visibility_modifier");
    found
}

/// Every `pub` field of one named struct, in source order.
///
/// Reads the parse rather than the text because a field list holds doc
/// comments, attributes and nested generics, and a regex over `pub \w+:` finds
/// the ones inside a `#[serde(...)]` argument and inside a comment as readily
/// as the real ones.
pub fn public_fields(source: &str, struct_name: &str) -> Vec<String> {
    let tree = parse(source);
    let mut cursor = tree.walk();
    let mut found = Vec::new();
    for node in tree.root_node().children(&mut cursor) {
        if node.kind() != "struct_item" {
            continue;
        }
        let named = node
            .child_by_field_name("name")
            .is_some_and(|name| source[name.byte_range()] == *struct_name);
        if !named {
            continue;
        }
        let Some(body) = node.child_by_field_name("body") else {
            continue;
        };
        let mut fields = body.walk();
        for field in body.children(&mut fields) {
            if field.kind() != "field_declaration" {
                continue;
            }
            let mut parts = field.walk();
            let public = field
                .children(&mut parts)
                .any(|child| child.kind() == "visibility_modifier");
            if !public {
                continue;
            }
            if let Some(name) = field.child_by_field_name("name") {
                found.push(source[name.byte_range()].to_owned());
            }
        }
    }
    found
}
