//! The predicates that read evidence and decide.
//!
//! A module here is handed an [`crate::evidence::Body`] and a rule, and
//! returns a refusal, a clean verdict, or the error that says it could not
//! decide. What it is never handed is a provider: the facts arrive with their
//! provenance on them, and the policy reads the strength and the name off the
//! fact when it reports, not off any type it knows.
//! `tests/structural_evidence.rs` refuses a policy file that names one,
//! because a policy that cannot be told which provider fed it is the one a
//! better provider can be slid under.
//!
//! The tests here are the ones a policy file may not carry, because they name
//! providers: the same policy judged over each provider's body in turn, and
//! the fallback from a parser that could not read to the text that could.

pub(crate) mod removed_function_named;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::removed_function_named::judge;
    use crate::config::Rule;
    use crate::evidence::{
        Body, Context, Evidence, Kind, Provider, Source, Strength, diff, git, syntax,
    };
    use crate::fixture;
    use crate::guard::Stage;

    fn rule() -> Rule {
        Rule::from_toml(
            "removed-function-named",
            "builtin = \"removed-function-named\"\ngit.hooks = [\"commit-msg\"]\n",
        )
        .expect("a rule the config accepts")
    }

    /// A repository with `before` committed at `path` and `after` staged.
    fn staged(path: &str, before: &str, after: &str) -> PathBuf {
        let root = fixture::scratch("policy");
        std::fs::create_dir_all(&root).unwrap();
        fixture::git(&root, &["init", "-q", "-b", "main"]);
        fixture::git(&root, &["config", "user.name", "Test"]);
        fixture::git(&root, &["config", "user.email", "test@example.test"]);
        std::fs::write(root.join(path), before).unwrap();
        fixture::git(&root, &["add", "-A"]);
        fixture::git(&root, &["commit", "-qm", "before", "--no-verify"]);
        std::fs::write(root.join(path), after).unwrap();
        fixture::git(&root, &["add", "-A"]);
        root
    }

    fn body(root: &Path, message: &str, path: &str, sources: &[&dyn Source]) -> Body {
        let changed = [path.to_owned()];
        Body::collect(
            sources,
            &Context {
                root,
                stage: Stage::CommitMsg,
                message: Some(message),
                changed: Some(&changed),
            },
        )
    }

    /// The report with the provider's name taken out, which is the only
    /// part of it a provider is allowed to change.
    fn without_provider(report: &str) -> String {
        report
            .lines()
            .map(|line| {
                line.split_once(" (seen by ")
                    .map_or(line, |(before, _)| before)
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    #[test]
    fn the_same_policy_refuses_the_same_removal_over_either_provider() {
        // The issue's criterion: a provider is replaced and the policy is not
        // rewritten. The parser's body and the text pattern's body are handed
        // to one predicate, and its report differs only in who saw the
        // function go.
        let root = staged(
            "lib.rs",
            "fn keep() {}\nfn drop_me(b: u8) {}\n",
            "fn keep() {}\n",
        );
        let by_tree = body(
            &root,
            "Tidy the module\n",
            "lib.rs",
            &[&git::Messages, &syntax::Declarations],
        );
        let by_text = body(
            &root,
            "Tidy the module\n",
            "lib.rs",
            &[&git::Messages, &diff::Lines],
        );
        let tree = judge(&rule(), &by_tree)
            .unwrap()
            .expect("the parser saw the removal");
        let text = judge(&rule(), &by_text)
            .unwrap()
            .expect("the pattern saw the removal");
        assert!(
            tree.report.contains("(seen by tree-sitter)"),
            "{}",
            tree.report
        );
        assert!(
            text.report.contains("(seen by diff-text)"),
            "{}",
            text.report
        );
        assert_eq!(
            without_provider(&tree.report),
            without_provider(&text.report)
        );
        assert!(
            tree.report.contains("lib.rs: `drop_me` is removed"),
            "{}",
            tree.report
        );

        // And named, either provider's body is clean.
        let named = "Drop drop_me\n\nNothing called it.\n";
        let named_by_tree = body(
            &root,
            named,
            "lib.rs",
            &[&git::Messages, &syntax::Declarations],
        );
        let named_by_text = body(&root, named, "lib.rs", &[&git::Messages, &diff::Lines]);
        assert!(judge(&rule(), &named_by_tree).unwrap().is_none());
        assert!(judge(&rule(), &named_by_text).unwrap().is_none());
    }

    #[test]
    fn a_parser_that_could_not_read_and_a_pattern_that_saw_nothing_is_could_not_look() {
        // ADR 0003's finding at this seam. The staged side does not parse, the
        // diff removes no `fn` line the pattern can see, and the verdict is
        // exit 2 -- not the clean that both readers' silence would add up to.
        let root = staged(
            "lib.rs",
            "fn keep() {}\n",
            "const S: &str = \"open;\nfn keep() {}\n",
        );
        let all: [&dyn Source; 3] = [&git::Messages, &syntax::Declarations, &diff::Lines];
        let collected = body(&root, "Break the string\n", "lib.rs", &all);
        let error = judge(&rule(), &collected).expect_err("nothing that could look, looked");
        let text = error.to_string();
        assert!(text.contains("could not be established"), "{text}");
        assert!(
            text.contains("tree-sitter: lib.rs:1 at the index did not parse"),
            "{text}"
        );
    }

    #[test]
    fn a_parser_that_could_not_read_and_a_pattern_that_saw_a_removal_refuses() {
        // Violation outranks could-not-look: the weaker provider adds a
        // refusal where the stronger one was silent for want of a tree.
        let root = staged(
            "lib.rs",
            "fn keep() {}\nfn drop_me() {}\n",
            "const S: &str = \"open;\nfn keep() {}\n",
        );
        let all: [&dyn Source; 3] = [&git::Messages, &syntax::Declarations, &diff::Lines];
        let collected = body(&root, "Break the string\n", "lib.rs", &all);
        let refusal = judge(&rule(), &collected)
            .unwrap()
            .expect("the pattern saw it go");
        assert!(
            refusal.report.contains("lib.rs: `drop_me` is removed"),
            "{}",
            refusal.report
        );
        assert!(
            refusal.report.contains("(seen by diff-text)"),
            "{}",
            refusal.report
        );
    }

    #[test]
    fn a_clean_change_with_no_message_is_clean_and_a_removal_with_none_is_could_not_look() {
        let root = staged("lib.rs", "fn keep() {}\n", "fn keep() {}\nfn more() {}\n");
        let all: [&dyn Source; 3] = [&git::Messages, &syntax::Declarations, &diff::Lines];
        let changed = [String::from("lib.rs")];
        let context = Context {
            root: &root,
            stage: Stage::PreCommit,
            message: None,
            changed: Some(&changed),
        };
        assert!(
            judge(&rule(), &Body::collect(&all, &context))
                .unwrap()
                .is_none()
        );

        let removing = staged("lib.rs", "fn keep() {}\nfn gone() {}\n", "fn keep() {}\n");
        let unread = Context {
            root: &removing,
            ..context
        };
        let error = judge(&rule(), &Body::collect(&all, &unread)).expect_err("no message was read");
        assert!(
            error.to_string().contains("no commit message was read"),
            "{error}"
        );
    }

    #[test]
    fn a_deleted_file_is_named_by_its_path_or_stem_and_a_kept_file_is_not() {
        // Every function in a deleted file is a removal, and the message that
        // names the file has named what a reader will search for. The same
        // message over a file that stays, with one function gone, names
        // nothing the reader can use.
        let deleted = fixture::scratch("policy-deleted");
        std::fs::create_dir_all(&deleted).unwrap();
        fixture::git(&deleted, &["init", "-q", "-b", "main"]);
        fixture::git(&deleted, &["config", "user.name", "Test"]);
        fixture::git(&deleted, &["config", "user.email", "test@example.test"]);
        std::fs::create_dir_all(deleted.join("src")).unwrap();
        std::fs::write(deleted.join("src/old.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        fixture::git(&deleted, &["add", "-A"]);
        fixture::git(&deleted, &["commit", "-qm", "before", "--no-verify"]);
        std::fs::remove_file(deleted.join("src/old.rs")).unwrap();
        fixture::git(&deleted, &["add", "-A"]);
        let all: [&dyn Source; 3] = [&git::Messages, &syntax::Declarations, &diff::Lines];
        for message in ["Delete src/old.rs\n", "Drop old, nothing read it\n"] {
            let collected = body(&deleted, message, "src/old.rs", &all);
            assert!(
                judge(&rule(), &collected).unwrap().is_none(),
                "{message:?} names the deleted file"
            );
        }
        let unnamed = body(&deleted, "Tidy the module\n", "src/old.rs", &all);
        let refusal = judge(&rule(), &unnamed)
            .unwrap()
            .expect("neither the file nor a function is named");
        assert!(
            refusal
                .report
                .contains("src/old.rs: `a` is removed by this change and the commit message does not name it or the deleted file"),
            "{}",
            refusal.report
        );
        // `folder` is not `old`, and `src/older.rs` is not `src/old.rs`.
        let near = body(
            &deleted,
            "Drop src/older.rs and the folder\n",
            "src/old.rs",
            &all,
        );
        assert!(judge(&rule(), &near).unwrap().is_some());

        let kept = staged("old.rs", "fn a() {}\nfn b() {}\n", "fn a() {}\n");
        let by_file = body(&kept, "Delete old.rs\n", "old.rs", &all);
        let refused = judge(&rule(), &by_file)
            .unwrap()
            .expect("the file stays, so naming it names no function");
        assert!(
            refused
                .report
                .contains("old.rs: `b` is removed by this change and the commit message does not name it (seen by"),
            "{}",
            refused.report
        );
    }

    const PARSER: Provider = Provider {
        name: "parser",
        strength: Strength::Proven,
        claims: &[Kind::FunctionRemoved, Kind::FunctionAdded],
    };
    const ORACLE: Provider = Provider {
        name: "oracle",
        strength: Strength::Inferred,
        claims: &[Kind::FunctionRemoved],
    };

    fn fact(provider: Provider, kind: Kind, subject: &str) -> Evidence {
        Evidence {
            kind,
            subject: subject.to_owned(),
            properties: BTreeMap::new(),
            provider,
            revision: String::from("HEAD..index"),
        }
    }

    #[test]
    fn two_proven_providers_disagreeing_is_refused_naming_both() {
        let other = Provider {
            name: "other-parser",
            ..PARSER
        };
        let collected = Body {
            found: vec![
                fact(git::PROVIDER, Kind::CommitIntent, "Drop go"),
                fact(PARSER, Kind::FunctionRemoved, "a.rs::go"),
                fact(other, Kind::FunctionAdded, "a.rs::go"),
            ],
            unavailable: Vec::new(),
            read: vec![git::PROVIDER, PARSER, other],
        };
        let refusal = judge(&rule(), &collected)
            .unwrap()
            .expect("a contradiction refuses");
        assert!(
            refusal
                .report
                .contains("a.rs::go: parser reports it removed and other-parser reports it added"),
            "{}",
            refusal.report
        );
    }

    #[test]
    fn an_inferred_removal_alone_is_no_refusal_and_cannot_cancel_a_proven_one() {
        // No AI provider exists; this is the double that proves the variant
        // does what the type says at the seam that decides an exit code.
        let alone = Body {
            found: vec![
                fact(git::PROVIDER, Kind::CommitIntent, "Tidy"),
                fact(ORACLE, Kind::FunctionRemoved, "a.rs::go"),
            ],
            unavailable: Vec::new(),
            read: vec![git::PROVIDER, ORACLE],
        };
        assert!(
            judge(&rule(), &alone).is_err(),
            "nothing deterministic read the change"
        );

        let overruled = Body {
            found: vec![
                fact(git::PROVIDER, Kind::CommitIntent, "Tidy"),
                fact(PARSER, Kind::FunctionRemoved, "a.rs::go"),
                fact(ORACLE, Kind::FunctionAdded, "a.rs::go"),
            ],
            unavailable: Vec::new(),
            read: vec![git::PROVIDER, PARSER, ORACLE],
        };
        let refusal = judge(&rule(), &overruled)
            .unwrap()
            .expect("the parser's refusal stands");
        assert!(
            refusal.report.contains("(seen by parser)"),
            "{}",
            refusal.report
        );
    }
}
