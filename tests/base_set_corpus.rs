//! The corpus: lines every promoted base rule must still refuse.
//!
//! A rule that stops matching produces NO OUTPUT AT ALL. The gate goes green,
//! stays green, and nothing anywhere says the check has stopped working -- which
//! makes a narrowed regex the one edit in this repository that cannot be caught
//! by reading a report. Every other failure here is loud; this one is the
//! absence of a report.
//!
//! These rules were promoted into `policy/base/` out of dozens of hand-copies in
//! consuming repositories, and the copies are what the samples below are drawn
//! from: the forms that were actually being refused before the promotion, one
//! per alternative in each pattern. A pattern edited in a way that drops one of
//! them fails here rather than in sixty-five repositories months later.
//!
//! Two properties, and the second is the one that keeps this file honest:
//!
//! * every sample under `refuses` is refused, BY THE RULE NAMED -- not by some
//!   other rule in the same set that happens to match it too;
//! * every content rule the bundled sets ship appears here. A rule added to a
//!   set with no corpus line fails this test, so the corpus cannot quietly fall
//!   behind the sets it describes.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// One rule's corpus: what it must refuse, and what it must not.
struct Case {
    set: &'static str,
    rule: &'static str,
    /// Where the sample has to live for the rule to select it. A rule scoped to
    /// `*.md` says nothing about a `.rs` file, and a corpus that ignored that
    /// would be testing the glob rather than the pattern.
    path: &'static str,
    refuses: &'static [&'static str],
    allows: &'static [&'static str],
}

/// What a set needs written beside `[inherit]` before it will load.
///
/// A set that supplies checkers and never shims is refused in a repository that
/// has not declared the `[[shim]]` tables itself -- which is the design (ADR
/// 0006) and not a gap, so the corpus writes the tables a consuming repository
/// writes. Keyed by set name rather than carried on every `Case`, because it is
/// a fact about the SET: every rule in one needs the same tables, and a
/// per-case field would be the same two tables transcribed once per rule.
const PRELUDE: &[(&str, &str)] = &[(
    "prose-shapes",
    "\n[[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\", \"--body\"]\n\n\
     [[shim]]\ncommand = \"git\"\nmatch = [\"push:*\"]\nscope = \"always\"\n",
)];

const CORPUS: &[Case] = &[
    Case {
        set: "process-residue",
        rule: "no-merge-conflict-markers",
        path: "sample.txt",
        refuses: &["<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> topic\n"],
        // The whole block or nothing: a lone row of equals signs is how RST and
        // Markdown underline a heading, and refusing that would make the rule
        // unusable in the documents it is most often read in.
        allows: &["Title\n=======\n\nprose about resolving a conflict\n"],
    },
    Case {
        set: "process-residue",
        rule: "no-hardcoded-home-paths",
        path: "sample.sh",
        refuses: &[
            "cp /home/alice/keys .\n",
            "open /Users/alice/Desktop\n",
            "copy C:\\Users\\alice\\file .\n",
        ],
        allows: &["cp \"$HOME/keys\" .\n", "open ~/Desktop\n"],
    },
    Case {
        set: "process-residue",
        rule: "no-dated-source-metadata",
        path: "sample.md",
        refuses: &["Date: 2026-08-14\n"],
        allows: &["Released on the fourteenth.\n"],
    },
    Case {
        set: "process-residue",
        rule: "no-status-source-metadata",
        path: "sample.md",
        refuses: &["Status: draft\n"],
        allows: &["The status of a record is a field in the record.\n"],
    },
    Case {
        set: "process-residue",
        rule: "no-task-tracker-references",
        path: "sample.md",
        refuses: &[
            "See github.com/acme/widget/issues/12 for the argument.\n",
            "Fixed in #451.\n",
        ],
        allows: &["The rule is stated here rather than in a tracker.\n"],
    },
    Case {
        set: "process-residue",
        rule: "no-process-history-references",
        path: "notes.rst",
        refuses: &[
            "as discussed in a thread, this is the answer\n",
            "issue #12 covers it\n",
            "https://github.com/acme/widget/pull/7 has the detail\n",
        ],
        allows: &["The decision and its reason are both written down here.\n"],
    },
    Case {
        set: "process-residue",
        rule: "no-tracked-private-data-paths",
        path: "artifacts/run.log",
        refuses: &["a build artefact somebody committed\n"],
        allows: &[],
    },
    Case {
        set: "credentials",
        rule: "no-committed-secret-material",
        path: "sample.conf",
        refuses: &[
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "ghp_000000000000000000000000000000000000\n",
            "AKIAIOSFODNN7EXAMPLE\n",
        ],
        allows: &["key_path = /etc/ssl/private/service.pem\n"],
    },
    Case {
        set: "credentials",
        rule: "no-committed-auth-key-values",
        path: "sample.conf",
        refuses: &["token = \"abcdefghijklmnopqrstuvwx\"\n"],
        allows: &["token = ${SERVICE_TOKEN}\n"],
    },
    Case {
        set: "credentials",
        rule: "no-env-secret-values",
        path: ".env",
        refuses: &["API_KEY=abcdef123456\n", "SERVICE_PASSWORD=hunter2\n"],
        allows: &["LOG_LEVEL=debug\n"],
    },
    Case {
        set: "credentials",
        rule: "no-browser-profile-artifacts",
        path: "profile/cookies.sqlite",
        refuses: &["a captured browser profile\n"],
        allows: &[],
    },
    Case {
        set: "unmanaged-pins",
        rule: "no-pinned-tool-install",
        path: "install.sh",
        refuses: &[
            "go install example.com/tool@v1.2.3\n",
            "pipx install ruff==0.14.0\n",
            "npm install -g typescript@5.4\n",
            // The two forms this repository's own install instructions create,
            // and the reason the rule is wider than the copies it replaced.
            "cargo install --git https://example.com/x --tag v1.1.0 x\n",
            "    ref: v1.1.0\n",
        ],
        allows: &[
            "go install example.com/tool@latest\n",
            "npm install -g typescript\n",
        ],
    },
    Case {
        set: "unmanaged-pins",
        rule: "no-pinned-release-download",
        path: "install.sh",
        refuses: &["fetch https://example.com/x/releases/download/v1.2.3/x.tar.gz\n"],
        allows: &["fetch https://example.com/x/releases/latest/x.tar.gz\n"],
    },
    Case {
        set: "unmanaged-pins",
        rule: "no-pinned-versioned-fetch",
        path: "install.sh",
        refuses: &["curl -fsSL https://example.com/dist/1.2.3/x.tar.gz\n"],
        allows: &["curl -fsSL https://example.com/dist/latest/x.tar.gz\n"],
    },
    // The `allows` here are the two forms the header of the set argues for and
    // the one it argues against, so a narrowing edit fails rather than quietly
    // stops covering them: a version manager's own bootstrap (`| sh`), which
    // has nowhere else to live, and a fetch that is not feeding an unpacker.
    Case {
        set: "hand-rolled-toolchain",
        rule: "no-hand-rolled-tool-install",
        path: "scripts/install-zig.sh",
        refuses: &[
            "curl -fsSL \"$url\" | tar -xJ -C \"$tmp\"\n",
            "wget -qO- \"$url\" | bsdtar -xf -\n",
            // The same two commands carrying the newline a formatter inserts
            // once the line gets long. Without the continuation alternative
            // these pass, which would make the rule switchable off by pressing
            // Enter.
            "curl -fsSL \"$url\" \\\n  | tar -xJ -C \"$tmp\"\n",
            "wget -qO- \\\n  \"$url\" | unzip -\n",
        ],
        allows: &[
            "curl -fsSL https://example.com/install | sh\n",
            "curl -fsSL \"$url\" -o \"$tmp/x.tar.xz\"\n",
            // A fetch and an unpack that are two separate commands rather than
            // one pipeline. This newline is NOT continued, so the multi-line
            // alternative must not reach across it -- otherwise the rule runs
            // away down the file and matches any curl above any tar.
            "curl -fsSL \"$url\" -o x.tar.xz\necho done\ntar -xf x.tar.xz\n",
        ],
    },
    // `allows` carries the sanctioned link, and it is the whole reason this
    // rule names a bin directory rather than `~/.local` alone: a link whose
    // SOURCE is the version the resolver picked is the remedy this set
    // recommends, and a rule that refused it would leave the caller that reads
    // no shell profile with no correct move at all. The `.local/share` and
    // `.local/state` samples are the other half of the same scoping -- an XDG
    // destination is not PATH.
    Case {
        set: "hand-rolled-toolchain",
        rule: "no-hand-rolled-tool-symlink",
        path: "scripts/install-zig.sh",
        refuses: &[
            "ln -sf \"$dest/zig\" \"$HOME/.local/bin/zig\"\n",
            "ln -s ~/.local/zig/zig /usr/local/bin/zig\n",
        ],
        allows: &[
            "ln -sfn \"$(mise which zig)\" /usr/local/bin/zig\n",
            "ln -sfn \"$repo/config\" \"$HOME/.config/zig\"\n",
            "ln -sfn \"$repo/x.desktop\" \"$HOME/.local/share/applications/x.desktop\"\n",
            "ln -sfn \"$repo/unit\" \"$HOME/.local/state/unit\"\n",
        ],
    },
    Case {
        set: "captured-fixtures",
        rule: "no-non-ascii-in-fixtures",
        path: "tests/fixtures/captured.json",
        refuses: &["{\"city\": \"Ka\u{0308}ln\"}\n"],
        allows: &["{\"city\": \"Cologne\"}\n"],
    },
    // The one `require_regexp` rule in any set, so what must be REFUSED is the
    // sample carrying no match. The second refusal is why the pattern is
    // anchored: a `permissions:` key nested under a job scopes that job and
    // leaves the workflow's own token grant untouched, so an unanchored pattern
    // would read a per-job block as the top-level declaration and pass exactly
    // the file this rule exists to find.
    Case {
        set: "default-token-grant",
        rule: "workflow-declares-permissions",
        path: ".github/workflows/ci.yml",
        refuses: &[
            "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n",
            "name: ci\non: [push]\njobs:\n  test:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n",
        ],
        allows: &[
            "name: ci\non: [push]\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
            // Legal YAML for the same key. Refusing it would be this rule
            // telling a workflow that declared its permissions that it did not.
            "name: ci\non: [push]\n\"permissions\":\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
            "name: ci\non: [push]\n'permissions':\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        ],
    },
    // The prose set. Its `allows` are the near misses each pattern was written
    // to let through, and they are the half worth reading: a shape rule that
    // widened by one alternative refuses the sentence it was written to permit,
    // and nothing in a report would say which edit did it.
    Case {
        set: "prose-shapes",
        rule: "no-announcing-sentence",
        path: "notes.md",
        refuses: &[
            "The next section will explain how the count is taken.\n",
            "As we will see, the ledger disagrees with the book.\n",
            "In what follows the two clocks are separated.\n",
        ],
        allows: &[
            // A data document says what it is about; it is not announcing a
            // sentence it is about to write.
            "This document is about the ledger and the book.\n",
            // A table is a thing on the page, not a paragraph promising one.
            "The following table lists every clock.\n",
        ],
    },
    Case {
        set: "prose-shapes",
        rule: "no-restating-clause",
        path: "notes.md",
        refuses: &[
            "The ledger is empty -- in other words, nothing was written to it.\n",
            "It returns zero \u{2014} which is to say the search found nothing.\n",
            "The clock is the venue's -- i.e. not this machine's.\n",
        ],
        allows: &[
            // A pronoun clause after a dash carries the sentence forward; it
            // does not say the first half again.
            "The count is taken once -- that is how it returns 0.\n",
            // The abbreviation on its own is somebody naming an example, and
            // the dash is what makes it a restatement.
            "Every clock, i.e. each of the four, is read separately.\n",
        ],
    },
    Case {
        set: "prose-shapes",
        rule: "no-empty-hedge",
        path: "notes.md",
        refuses: &[
            "Arguably the count is the one a reader wants.\n",
            "It is worth noting that the two clocks disagree.\n",
            "Needless to say the ledger is authoritative.\n",
        ],
        allows: &[
            // Deliberately not on the list: these can carry a real doubt, and
            // a rule refusing them would refuse the sentence that honestly
            // does not know.
            "Perhaps the clock is the venue's; nobody has measured it.\n",
            "The count might be stale, and the run before it would say.\n",
            "Note that the ledger is read twice.\n",
        ],
    },
    Case {
        set: "prose-shapes",
        rule: "no-unproposed-alternative",
        path: "notes.md",
        refuses: &[
            "One might argue the count belongs to the book.\n",
            "A sceptic might say the ledger is never read.\n",
            "It could be tempting to read the clock twice.\n",
        ],
        allows: &[
            // `one could` followed by a verb that is not an objection.
            "Not one could say it held before the run.\n",
            // The alternative that was actually proposed, being discussed.
            "The alternative was measured and it lost.\n",
        ],
    },
];

/// The rules this corpus does not cover, and why each is somewhere else.
///
/// Named rather than skipped silently: an uncovered rule that nobody wrote down
/// is indistinguishable from one somebody forgot, and the completeness check
/// below reads this list as the whole of the exemption.
const ELSEWHERE: &[(&str, &str)] = &[(
    "no-running-os-identity-metadata",
    "its literals are read off the running machine at scan time, so a committed sample \
         cannot express them -- tests/scan_cli.rs drives it with a planted identity",
)];

fn repository(policy: &str) -> PathBuf {
    let root = support::scratch("corpus");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
    root
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new(support::real_git())
        .args(args)
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn scan(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("scan")
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// Write one sample, track it, and ask the scan about it.
///
/// Tracked deliberately: selection is `git ls-files`, because a tracked file
/// some ignore pattern also matches is still pushed and still read by everyone
/// who clones it. An untracked sample would be testing nothing.
fn verdict(case: &Case, sample: &str) -> (i32, String) {
    let prelude = PRELUDE
        .iter()
        .find(|(set, _)| *set == case.set)
        .map_or("", |(_, text)| *text);
    let root = repository(&format!("[inherit]\nsets = [\"{}\"]\n{prelude}", case.set));
    let path = root.join(case.path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, sample).unwrap();
    git(&root, &["add", "-A"]);
    let output = scan(&root);
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let _ = std::fs::remove_dir_all(&root);
    (output.status.code().unwrap(), text)
}

#[test]
fn every_promoted_rule_still_refuses_what_it_was_promoted_for() {
    for case in CORPUS {
        for sample in case.refuses {
            let (code, report) = verdict(case, sample);
            assert_eq!(
                code, 1,
                "{}: {sample:?} was not refused.\n{report}",
                case.rule
            );
            assert!(
                report.contains(case.rule),
                "{}: {sample:?} was refused by something else, so this rule may have stopped \
                 matching without anything saying so.\n{report}",
                case.rule
            );
        }
    }
}

#[test]
fn the_corpus_does_not_refuse_what_the_rules_were_never_about() {
    // The other half, and it is not decoration: a rule widened until it matches
    // everything reports on every file, and a report on every file is one
    // nobody reads. These are the forms the rules were carefully written to let
    // through.
    for case in CORPUS {
        for sample in case.allows {
            let (code, report) = verdict(case, sample);
            assert_eq!(code, 0, "{}: {sample:?} was refused.\n{report}", case.rule);
        }
    }
}

#[test]
fn every_content_rule_in_every_bundled_set_is_in_the_corpus() {
    // What stops the corpus falling behind the sets. Read from the binary
    // rather than from a list kept here, because a list kept here is the drift
    // this whole tier exists to catch.
    //
    // Parsed rather than grepped, and the first version of this test is the
    // argument: it read the document line by line, mistook the close of a
    // nested `files` table for the close of the rule, found no check field, and
    // reported that every rule was covered. A completeness check that answers
    // "all covered" when it could not read the document is the exact failure
    // this repository is about.
    let listed = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["rules", "--sets", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert_eq!(
        listed.status.code().unwrap(),
        0,
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let sets = document.as_array().unwrap();
    assert!(!sets.is_empty(), "the binary listed no bundled sets at all");

    let mut missing: Vec<String> = Vec::new();
    let mut checked = 0_usize;
    for set in sets {
        for rule in set["rules"].as_array().unwrap() {
            // A built-in is compiled in and has its own tests; a corpus line
            // about one would be a line about this binary rather than about a
            // pattern. What is left is the patterns.
            let checks_content = ["regexp", "path_regexp", "require_regexp", "prose_regexp"]
                .iter()
                .any(|field| rule.get(field).is_some());
            if !checks_content {
                continue;
            }
            checked += 1;
            let id = rule["id"].as_str().unwrap();
            if CORPUS.iter().any(|case| case.rule == id)
                || ELSEWHERE.iter().any(|(named, _)| *named == id)
            {
                continue;
            }
            missing.push(id.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "these bundled rules check content and have no corpus line, so nothing would notice \
         if they stopped matching: {}",
        missing.join(", ")
    );
    // The count is asserted because "nothing was missing" and "nothing was
    // looked at" print the same.
    assert!(
        checked >= CORPUS.len(),
        "the sets ship {checked} content rules and the corpus holds {}, so the corpus is \
         describing rules the binary no longer has",
        CORPUS.len()
    );
}
