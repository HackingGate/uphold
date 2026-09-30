//! CLI tests for `files.reach`: a rule may reach the content its repository
//! pins.
//!
//! Every fixture is a real superproject with a real submodule, because what is
//! under test is what git reports about the pins -- a mode-160000 entry, a
//! member's own index, a mount git marks inactive -- and a stand-in for any of
//! those would pass a test git itself would fail.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A pattern that does not match its own spelling, so the policy file that
/// declares it is not a finding of its own.
const CANARY: &str = "CANAR[Y]";

fn repository(kind: &str) -> PathBuf {
    let root = support::scratch(kind);
    std::fs::create_dir_all(&root).unwrap();
    support::git(&root, &["init", "-q", "-b", "main"]);
    support::git(&root, &["config", "user.name", "Test"]);
    support::git(&root, &["config", "user.email", "test@example.test"]);
    root
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn commit(root: &Path, message: &str) {
    support::git(root, &["add", "-A"]);
    support::git(root, &["commit", "-q", "--allow-empty", "-m", message]);
}

/// A rule refusing the canary, at the reach given, with `extra` lines added to
/// its `files` table.
fn policy(root: &Path, reach: Option<&str>, extra: &str) {
    let reach = reach.map_or_else(String::new, |reach| format!("reach = \"{reach}\"\n"));
    write(
        root,
        "policy/principles.toml",
        &format!(
            "[rule.no-canary]\nmessage = \"no canary\"\nregexp = '{CANARY}'\n\n\
             [rule.no-canary.files]\n{reach}{extra}\n"
        ),
    );
}

/// A superproject pinning one member, `canary`, whose `docs/note.md` carries
/// the canary, and whose own policy would exclude every file it has -- which a
/// pinned rule of the superproject's must not read.
fn superproject(kind: &str) -> PathBuf {
    let root = repository(kind);
    write(&root, "README.md", "the superproject's own, and clean\n");
    support::submodule(
        &root,
        "canary",
        &[
            ("docs/note.md", "fine\nCANARY here\n"),
            (
                "policy/principles.toml",
                "[rule.no-canary]\nmessage = \"the member's own\"\nregexp = 'CANAR[Y]'\n\
                 [rule.no-canary.files]\nexclude = [\"**\"]\n",
            ),
        ],
    );
    commit(&root, "pin the member");
    root
}

fn uphold(root: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    support::without_git_environment(&mut command);
    command.args(args).current_dir(root).output().unwrap()
}

fn scan(root: &Path) -> Output {
    uphold(root, &["scan"])
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn text(output: &Output) -> String {
    let mut all = String::from_utf8_lossy(&output.stdout).into_owned();
    all.push_str(&String::from_utf8_lossy(&output.stderr));
    all
}

#[test]
fn a_pinned_rule_finds_the_canary_inside_the_member_under_the_mount_path() {
    let root = superproject("reach-pinned");
    policy(&root, Some("pinned"), "");
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("canary/docs/note.md:2:"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_repository_rule_on_the_same_tree_does_not_look_inside_the_member() {
    let root = superproject("reach-repository");
    for reach in [None, Some("repository")] {
        policy(&root, reach, "");
        let output = scan(&root);
        assert_eq!(code(&output), 0, "{reach:?}: {}", text(&output));
        assert!(!text(&output).contains("canary/"), "{}", text(&output));
    }
}

#[test]
fn a_pinned_rule_in_a_repository_that_pins_nothing_is_a_repository_rule() {
    let root = repository("reach-no-pins");
    write(&root, "a.txt", "CANARY\n");
    commit(&root, "no pins");
    for reach in [Some("pinned"), None] {
        policy(&root, reach, "");
        let output = scan(&root);
        assert_eq!(code(&output), 1, "{reach:?}: {}", text(&output));
        assert!(text(&output).contains("a.txt:1:"), "{}", text(&output));
    }
}

#[test]
fn an_uninitialised_member_is_exit_2_naming_the_mount_and_the_remedy() {
    let source = superproject("reach-uninitialised-source");
    policy(&source, Some("pinned"), "exclude = [\"/policy/**\"]");
    commit(&source, "the policy");
    let clone = support::scratch("reach-uninitialised");
    support::git(
        source.parent().unwrap(),
        &[
            "clone",
            "-q",
            &source.display().to_string(),
            &clone.display().to_string(),
        ],
    );
    assert!(
        std::fs::read_dir(clone.join("canary"))
            .unwrap()
            .next()
            .is_none()
    );

    let output = scan(&clone);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("canary"), "{}", text(&output));
    assert!(
        text(&output).contains("git submodule update --init canary"),
        "{}",
        text(&output)
    );
    assert!(!text(&output).contains("policy checks passed"));

    // The same tree read by a rule of its own repository is not a claim on
    // the member, and the absent checkout is nothing to it.
    policy(&clone, None, "exclude = [\"/policy/**\"]");
    assert_eq!(code(&scan(&clone)), 0, "{}", text(&scan(&clone)));
}

#[test]
fn a_checked_out_member_git_marks_inactive_is_exit_2_until_the_remedy_is_run() {
    // The case `git ls-files --recurse-submodules` would have skipped without
    // a word: the files are on disk, and git's activity filter leaves them out.
    let root = superproject("reach-inactive");
    policy(&root, Some("pinned"), "");
    support::git(&root, &["config", "submodule.canary.active", "false"]);
    assert!(root.join("canary/docs/note.md").is_file());

    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("inactive"), "{}", text(&output));
    assert!(
        text(&output).contains("git submodule update --init canary"),
        "{}",
        text(&output)
    );

    // The remedy it names is the one that works.
    support::git(
        &root,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "update",
            "--init",
            "canary",
        ],
    );
    let remedied = scan(&root);
    assert_eq!(code(&remedied), 1, "{}", text(&remedied));
    assert!(
        text(&remedied).contains("canary/docs/note.md:2:"),
        "{}",
        text(&remedied)
    );
}

#[test]
fn a_leading_slash_exclude_is_anchored_at_the_superproject_and_a_bare_name_is_not() {
    let root = superproject("reach-globs");
    write(&root, "vendor.txt", "CANARY at the root\n");
    write(&root.join("canary"), "vendor.txt", "CANARY in the member\n");
    commit(&root.join("canary"), "the member's vendor file");
    commit(&root, "the root's vendor file, and the bumped pin");

    policy(
        &root,
        Some("pinned"),
        "exclude = [\"/vendor.txt\", \"note.md\"]",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("canary/vendor.txt:1:"),
        "{}",
        text(&output)
    );
    assert!(
        !text(&output).contains("\nvendor.txt:1:") && !text(&output).starts_with("vendor.txt"),
        "the anchored exclude did not exempt the root's own file: {}",
        text(&output)
    );

    policy(
        &root,
        Some("pinned"),
        "exclude = [\"vendor.txt\", \"note.md\"]",
    );
    let bare = scan(&root);
    assert_eq!(code(&bare), 0, "{}", text(&bare));
}

#[test]
fn an_include_may_name_a_path_inside_a_mount_and_the_floor_counts_the_member_files() {
    let root = superproject("reach-include");
    policy(
        &root,
        Some("pinned"),
        "include = [\"canary/docs\"]\nmin_selected = 1",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("canary/docs/note.md:2:"),
        "{}",
        text(&output)
    );
    assert!(
        !text(&output).contains("selection floor"),
        "{}",
        text(&output)
    );

    // The same include at repository reach selects nothing under the mount,
    // and the floor says so.
    policy(&root, None, "include = [\"canary/docs\"]\nmin_selected = 1");
    let unpinned = scan(&root);
    assert!(
        text(&unpinned).contains("selected 0 file(s)"),
        "{}",
        text(&unpinned)
    );
}

#[test]
fn a_members_own_not_text_declaration_is_honoured_for_its_files() {
    let root = superproject("reach-attributes");
    let member = root.join("canary");
    write(&member, ".gitattributes", "*.bin -text\n");
    write(&member, "capture.bin", "CANARY in a declared capture\n");
    commit(&member, "a declared capture");
    commit(&root, "bump the pin");

    policy(&root, Some("pinned"), "exclude = [\"note.md\"]");
    let output = scan(&root);
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("declared not text in .gitattributes"),
        "{}",
        text(&output)
    );
    assert!(
        text(&output).contains("  canary/capture.bin"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_path_baseline_keyed_under_the_mount_suppresses_exactly_that_finding() {
    let root = superproject("reach-baseline");
    let member = root.join("canary");
    write(&member, "other.md", "CANARY too\n");
    commit(&member, "a second canary");
    commit(&root, "bump the pin");
    write(&root, "policy/canary.baseline", "canary/docs/note.md\n");

    policy(
        &root,
        Some("pinned"),
        "baseline = \"policy/canary.baseline\"",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("canary/other.md:1:"),
        "{}",
        text(&output)
    );
    assert!(
        !text(&output).contains("canary/docs/note.md"),
        "{}",
        text(&output)
    );
    assert!(!text(&output).contains("stale"), "{}", text(&output));
}

#[test]
fn a_size_baseline_keyed_under_the_mount_holds_that_file_and_no_other() {
    let root = superproject("reach-size");
    let member = root.join("canary");
    write(&member, "held.txt", "1\n2\n3\n");
    write(&member, "free.txt", "1\n2\n3\n");
    commit(&member, "two long files");
    commit(&root, "bump the pin");
    write(&root, "policy/size.baseline", "canary/held.txt 3\n");
    write(
        &root,
        "policy/principles.toml",
        "[rule.short]\nmessage = \"short files\"\nmax_lines = 2\n\n[rule.short.files]\n\
         reach = \"pinned\"\nglob = [\"*.txt\"]\nbaseline = \"policy/size.baseline\"\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("canary/free.txt: 3 lines"),
        "{}",
        text(&output)
    );
    assert!(
        !text(&output).contains("canary/held.txt"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_leading_slash_link_in_a_member_resolves_against_the_members_root() {
    let root = superproject("reach-links");
    let member = root.join("canary");
    write(
        &member,
        "guide.md",
        "[ok](/docs/note.md)\n[gone](/docs/absent.md)\n",
    );
    commit(&member, "a guide");
    commit(&root, "bump the pin");
    write(
        &root,
        "policy/principles.toml",
        "[rule.links]\nbuiltin = \"links-resolve\"\nmessage = \"links resolve\"\n\n\
         [rule.links.files]\nreach = \"pinned\"\nglob = [\"*.md\"]\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("canary/guide.md:2: /docs/absent.md -> no such file"),
        "{}",
        text(&output)
    );
    // `/docs/note.md` is the member's, and the superproject has no `docs/`.
    assert!(!root.join("docs").exists());
    assert!(
        !text(&output).contains("/docs/note.md ->"),
        "{}",
        text(&output)
    );
}

/// A superproject pinning `outer`, which pins `inner`, whose `deep.md` carries
/// the canary. `inner` is not checked out: the clone `submodule add` made of
/// the outer member carries the pin and not the content.
fn nested(kind: &str) -> PathBuf {
    let outer = repository(&format!("{kind}-outer-source"));
    write(&outer, "outer.md", "clean\n");
    support::submodule(&outer, "inner", &[("deep.md", "CANARY at depth\n")]);
    commit(&outer, "pin the inner member");

    let root = repository(kind);
    write(&root, "README.md", "clean\n");
    support::git(
        &root,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            &outer.display().to_string(),
            "outer",
        ],
    );
    commit(&root, "pin the outer member");
    policy(&root, Some("pinned"), "exclude = [\"/policy/**\"]");
    root
}

/// Check out the inner member of a [`nested`] fixture.
fn initialise_inner(root: &Path) {
    support::git(
        &root.join("outer"),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "update",
            "--init",
            "inner",
        ],
    );
}

#[test]
fn a_member_that_pins_a_member_is_followed_at_every_depth() {
    // The ADR leaves the depth open. A pin is a claim at every depth: the
    // superproject pins the outer member's commit, and that commit pins its
    // own member, so a rule claiming the pinned content reads both.
    let root = nested("reach-nested");
    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("outer/inner"), "{}", text(&output));
    assert!(
        text(&output).contains("git -C outer submodule update --init inner"),
        "{}",
        text(&output)
    );

    initialise_inner(&root);
    let initialised = scan(&root);
    assert_eq!(code(&initialised), 1, "{}", text(&initialised));
    assert!(
        text(&initialised).contains("outer/inner/deep.md:1:"),
        "{}",
        text(&initialised)
    );
}

#[test]
fn a_scan_run_from_a_hook_asks_each_member_about_itself() {
    // A hook runner exports `GIT_DIR` and `GIT_INDEX_FILE` for the repository
    // the hook fired in, and each outranks `current_dir`. A git asked about a
    // member with them still set answers about the superproject: its
    // submodules, its index. So the member is asked with them taken away, at
    // every depth -- here the inner member, which only the outer member's own
    // configuration marks inactive.
    let root = nested("reach-hooked");
    initialise_inner(&root);
    support::git(
        &root.join("outer"),
        &["config", "submodule.inner.active", "false"],
    );
    let hooked = |superproject: &Path| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
        support::without_git_environment(&mut command);
        command
            .arg("scan")
            .env("GIT_DIR", superproject.join(".git"))
            .env("GIT_INDEX_FILE", superproject.join(".git/index"))
            .current_dir(superproject)
            .output()
            .unwrap()
    };

    let output = hooked(&root);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("pinned at outer/inner is checked out and git marks it inactive"),
        "{}",
        text(&output)
    );

    support::git(
        &root.join("outer"),
        &["config", "submodule.inner.active", "true"],
    );
    let active = hooked(&root);
    assert_eq!(code(&active), 1, "{}", text(&active));
    assert!(
        text(&active).contains("outer/inner/deep.md:1:"),
        "{}",
        text(&active)
    );
}

#[test]
fn the_effective_rules_show_a_pinned_reach_and_only_that() {
    let root = superproject("reach-effective");
    write(
        &root,
        "policy/principles.toml",
        "[rule.reaches]\nmessage = \"m\"\nregexp = 'CANAR[Y]'\nfiles.reach = \"pinned\"\n\n\
         [rule.stays]\nmessage = \"m\"\nregexp = 'CANAR[Y]'\nfiles.include = [\".\"]\n",
    );
    let output = uphold(&root, &["rules", "--effective", "--json"]);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let rules: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let entry = |id: &str| rules.iter().find(|rule| rule["id"] == id).unwrap().clone();
    assert_eq!(
        entry("reaches"),
        serde_json::json!({"id": "reaches", "git_hooks": [], "seams": ["scan"], "reach": "pinned"})
    );
    assert_eq!(
        entry("stays"),
        serde_json::json!({"id": "stays", "git_hooks": [], "seams": ["scan"]})
    );

    let listed = uphold(&root, &["rules", "--effective"]);
    assert!(
        text(&listed).contains("reaches  (scan)  [reach: pinned]"),
        "{}",
        text(&listed)
    );
}

#[test]
fn a_reach_that_is_neither_value_is_refused_naming_both() {
    let root = superproject("reach-refused");
    policy(&root, Some("everywhere"), "");
    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("everywhere"), "{}", text(&output));
    assert!(
        text(&output).contains("repository") && text(&output).contains("pinned"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_pinned_reach_on_a_guard_scope_is_refused() {
    let root = superproject("reach-guard");
    write(
        &root,
        "policy/principles.toml",
        "[rule.unicode]\nbuiltin = \"prevent-unusual-unicode-in-files\"\n\
         message = \"m\"\ngit.hooks = [\"pre-commit\"]\n\n\
         [rule.unicode.files]\nreach = \"pinned\"\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("files.reach"), "{}", text(&output));
}
