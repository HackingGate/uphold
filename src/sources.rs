//! Where a dynamic rule's needles come from.
//!
//! A dynamic rule searches for values that only exist at runtime -- the running
//! user, their home path, the machine's name, the address it routes through.
//! None of them can be written into a policy file, because writing them there
//! is the leak the rule exists to prevent.

use std::collections::BTreeSet;
use std::process::Command;

use crate::error::{Fatal, Result};

/// One runtime value to search for, and how it should be matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Needle {
    pub label: String,
    pub value: String,
    pub word: bool,
}

/// Names that are never a personal identity leak.
///
/// A shared build account is not a person. `runner` is the account every GitHub
/// hosted runner runs as, so it is the same string on every such machine and
/// says nothing about whose machine it is -- which is the property this whole
/// module searches for. The others are the same fact under other providers and
/// in other images.
const KNOWN_PUBLIC_IDENTITY: &[&str] = &[
    "runner",
    "ubuntu",
    "ec2-user",
    "admin",
    "azureuser",
    "vsts",
    "buildkite-agent",
    "circleci",
    "travis",
    "jenkins",
    "vagrant",
    "docker",
    "root",
    "ci",
    "build",
];

/// Hostname segments that describe a machine's KIND rather than its owner.
///
/// Hostnames are compound -- `debian-x8664-arc` is a distribution, an
/// architecture and a product line -- and only the distinguishing part says
/// whose machine it is. Searching for the generic parts would fire on every
/// legitimate mention of a distribution or an architecture, which is how a rule
/// earns a blanket opt-out instead of a fix.
const GENERIC_HOSTNAME_SEGMENTS: &[&str] = &[
    // distributions and operating systems
    "alma",
    "alpine",
    "arch",
    "archlinux",
    "armbian",
    "bsd",
    "cachyos",
    "centos",
    "darwin",
    "debian",
    "endeavour",
    "endeavouros",
    "fedora",
    "gentoo",
    "kali",
    "linux",
    "macos",
    "manjaro",
    "mint",
    "nix",
    "nixos",
    "openwrt",
    "opensuse",
    "pop",
    "popos",
    "raspbian",
    "redhat",
    "rhel",
    "rocky",
    "suse",
    "ubuntu",
    "unix",
    "void",
    "windows",
    // architectures
    "aarch64",
    "amd64",
    "arm",
    "arm64",
    "i386",
    "i686",
    "riscv",
    "riscv64",
    "x86",
    "x8664",
    "x64",
    // roles, form factors and other machine-kind words
    "box",
    "build",
    "builder",
    "cloud",
    "desktop",
    "dev",
    "gateway",
    "guest",
    "home",
    "host",
    "lab",
    "laptop",
    "local",
    "machine",
    "main",
    "media",
    "nas",
    "node",
    "router",
    "server",
    "srv",
    "test",
    "virt",
    "workstation",
];

/// Shortest hostname segment worth searching for. Two characters collide with
/// far too much ordinary text even under whole-word matching.
const MIN_HOSTNAME_SEGMENT_LEN: usize = 3;

fn is_public_identity(value: &str) -> bool {
    KNOWN_PUBLIC_IDENTITY.contains(&value.to_ascii_lowercase().as_str())
}

fn push(needles: &mut Vec<Needle>, label: &str, value: Option<String>, word: bool) {
    let Some(value) = value else { return };
    let value = value.trim().to_owned();
    if value.is_empty() || matches!(value.as_str(), "." | "localhost" | "localhost.localdomain") {
        return;
    }
    if label.starts_with("hostname") && is_public_identity(&value) {
        return;
    }
    needles.push(Needle {
        label: label.to_owned(),
        value,
        word,
    });
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn hostname() -> Option<String> {
    if let Ok(text) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let trimmed = text.trim().to_owned();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    let output = Command::new("uname").arg("-n").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!name.is_empty()).then_some(name)
}

/// The distinguishing parts of a hostname, lowercased, in order.
///
/// Searching only for the whole hostname misses the spelling that actually
/// reaches a fixture. What gets typed into a reservation or a test is one part,
/// and that fragment is every bit as identifying as the whole: it is the
/// operator's hardware, and it is what a reader recognises.
pub(crate) fn hostname_segments(hostname: &str) -> Vec<String> {
    let label = hostname
        .split('.')
        .next()
        .unwrap_or(hostname)
        .to_lowercase();
    let mut segments: Vec<String> = Vec::new();
    for raw in label.split(['-', '_']) {
        let segment = raw.trim();
        if segment.len() < MIN_HOSTNAME_SEGMENT_LEN
            || segment.chars().all(|character| character.is_ascii_digit())
        {
            continue;
        }
        if GENERIC_HOSTNAME_SEGMENTS.contains(&segment) || is_public_identity(segment) {
            continue;
        }
        if segment == label {
            continue; // already searched for whole, as "hostname"
        }
        if !segments.iter().any(|seen| seen == segment) {
            segments.push(segment.to_owned());
        }
    }
    segments
}

fn running_os_identity() -> Vec<Needle> {
    let mut needles = Vec::new();
    let user = env("USER").or_else(|| env("LOGNAME"));
    let home = env("HOME");

    // The home path is asked the same question the username is asked, which it
    // was not asking before: whose machine is this. A hosted runner's home
    // directory answers nobody -- it is the account every such machine runs as,
    // identical on all of them, and `KNOWN_PUBLIC_IDENTITY` has said so about
    // the username since it was written. Only this needle skipped the check, so
    // the same account name was a leak as a path and not as a name.
    //
    // A home path that will not exist on the next machine is a real defect and
    // it is `no-hardcoded-home-paths`, a separate rule with a separate subject.
    // This one is about identity, and suppressing a shared build account here
    // takes nothing away from that one.
    //
    // The effect was worse than an inconsistency. The needle is read from the
    // environment the scan runs in, so a tree that mentions a CI path passed on
    // every developer's machine and refused on every runner -- the one place the
    // gate is authoritative -- and the failure arrived as "identity metadata"
    // about a string that identifies nobody.
    let home_account = home
        .as_deref()
        .and_then(|path| path.trim_end_matches('/').rsplit('/').next())
        .unwrap_or_default()
        .to_owned();
    if !is_public_identity(&home_account) {
        push(&mut needles, "home-path", home, false);
    }
    if let Some(user) = user.as_deref() {
        if !is_public_identity(user) {
            push(
                &mut needles,
                "ssh-user-prefix",
                Some(format!("{user}@")),
                false,
            );
            if user.len() >= 4 {
                push(&mut needles, "username", Some(user.to_owned()), false);
            }
        }
    }

    if let Some(name) = hostname() {
        push(&mut needles, "hostname", Some(name.clone()), false);
        if name.contains('.') {
            push(
                &mut needles,
                "hostname-label",
                name.split('.').next().map(str::to_owned),
                false,
            );
        }
        for segment in hostname_segments(&name) {
            // Whole-word: these are short enough to sit inside unrelated words.
            push(
                &mut needles,
                &format!("hostname-segment ({segment})"),
                Some(segment.clone()),
                true,
            );
        }
    }

    needles
}

fn is_routable(address: &str) -> bool {
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    let parsed: Option<Vec<u8>> = octets.iter().map(|part| part.parse::<u8>().ok()).collect();
    let Some(parsed) = parsed else {
        return false;
    };
    let [first, second, ..] = parsed.as_slice() else {
        return false;
    };
    // Loopback, link-local and multicast say nothing about which machine this
    // is, so searching for them would only produce findings on ordinary text.
    !(*first == 127 || (*first == 169 && *second == 254) || (224..=239).contains(first))
}

fn running_default_route() -> Vec<Needle> {
    // "This machine has no default route" and "`ip` could not be run" are
    // different facts, and both used to produce the same empty list. Zero
    // needles is zero searches, so the rule passed -- reporting a clean tree
    // because the check could not be made, which is the thing `command_source`
    // refuses to do a hundred lines down and says why.
    //
    // Still empty rather than fatal: a machine with no `iproute2` is an
    // ordinary container, and a built-in source that kills every run there
    // would be switched off wholesale. But it says so.
    let Ok(output) = Command::new("ip")
        .args(["-o", "-4", "route", "show", "default"])
        .output()
    else {
        eprintln!(
            "uphold: `ip` could not be run, so the running-default-route source \
             contributed no needles. Rules using it searched for nothing."
        );
        return Vec::new();
    };
    if !output.status.success() {
        eprintln!(
            "uphold: `ip -o -4 route show default` exited {}, so the \
             running-default-route source contributed no needles. Rules using it \
             searched for nothing.",
            output.status.code().unwrap_or(-1)
        );
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut needles = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        for key in ["via", "src"] {
            let Some(index) = fields.iter().position(|field| *field == key) else {
                continue;
            };
            let Some(address) = fields.get(index + 1) else {
                continue;
            };
            if !is_routable(address) {
                continue;
            }
            push(
                &mut needles,
                &format!("default-route-{key}-{address}"),
                Some((*address).to_owned()),
                false,
            );
        }
    }
    needles
}

/// Run a command and read one needle per line of its stdout.
///
/// This is what replaced `policy/sources.py`. A repository that needed a custom
/// source used to ship a Python module the engine imported by path, which made
/// every consumer of the engine a Python host, and made the plugin's needle type
/// a different class than the engine's -- worked around in the old engine by
/// matching the value structurally rather than by type. A command has neither
/// problem, and can be written in whatever the repository already builds with.
///
/// A line may be `label<TAB>value`; a bare line is its own label.
fn command_source(
    run: &str,
    root: &std::path::Path,
    word: bool,
    label: &str,
) -> Result<Vec<Needle>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(run)
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("{label}: could not run {run:?}: {error}")))?;
    if !output.status.success() {
        // Not silently empty. A source that failed produced no needles, and a
        // rule with no needles passes -- which would report a clean tree
        // because the check could not be made.
        return Err(Fatal::new(format!(
            "{label}: source command {run:?} exited {}: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut needles = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let (needle_label, value) = match line.split_once('\t') {
            Some((named, value)) => (named.trim(), value.trim()),
            None => (line.trim(), line.trim()),
        };
        push(&mut needles, needle_label, Some(value.to_owned()), word);
    }
    Ok(needles)
}

/// Resolve a source name to its needles.
///
/// `ignore` is the rule's `ignore_literals`: literals never searched for,
/// extending the built-in defaults ([`KNOWN_PUBLIC_IDENTITY`] and
/// [`GENERIC_HOSTNAME_SEGMENTS`], documented in REFERENCE.md). The defaults
/// used to be the whole story, hard-coded and invisible; the field is the same
/// suppression where an operator can see and extend it.
pub(crate) fn resolve(
    source: &str,
    run: Option<&str>,
    root: &std::path::Path,
    word: bool,
    label: &str,
    ignore: &[String],
) -> Result<Vec<Needle>> {
    let needles = match source {
        "running-os-identity" => running_os_identity(),
        "running-default-route" => running_default_route(),
        "running-os-metadata" => {
            let mut all = running_os_identity();
            all.extend(running_default_route());
            all
        }
        "command" => {
            let run = run.ok_or_else(|| {
                Fatal::new(format!(
                    "{label}: `forbidden_literals = \"command\"` requires \
                     `forbidden_literals_from`"
                ))
            })?;
            command_source(run, root, word, label)?
        }
        unknown => {
            return Err(Fatal::new(format!(
                "{label}: unknown literal source {unknown:?}; known sources are \
                 running-os-identity, running-os-metadata, running-default-route, command"
            )))
        }
    };

    let ignored: BTreeSet<String> = ignore.iter().map(|entry| entry.to_lowercase()).collect();

    // One value searched twice is one finding reported twice.
    let mut seen: BTreeSet<(String, bool)> = BTreeSet::new();
    Ok(needles
        .into_iter()
        .filter(|needle| !ignored.contains(&needle.value.to_lowercase()))
        .filter(|needle| seen.insert((needle.value.clone(), needle.word)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shared build account is not a person, and a path is not exempt from
    /// that just because it is a path.
    ///
    /// `KNOWN_PUBLIC_IDENTITY` has held `runner` since it was written, and the
    /// username needle has consulted it since then -- but the home path needle
    /// consulted nothing, so the same account name was a leak spelled one way
    /// and not the other. Since the needle is read from the environment the scan
    /// runs in, the practical effect was a tree that passed on every developer's
    /// machine and refused on every CI runner, reported as identity metadata
    /// about a string identifying nobody.
    #[test]
    fn a_shared_build_account_is_not_an_identity_in_either_spelling() {
        assert!(is_public_identity("runner"));
        assert!(is_public_identity("ec2-user"));
        assert!(is_public_identity("ROOT"), "the check is case-insensitive");
        assert!(!is_public_identity("hg"));
        assert!(!is_public_identity("alice"));

        // Assembled rather than written out, because `no-hardcoded-home-paths`
        // is a SEPARATE rule from the one under test and it refuses a literal
        // home path in any file including this one -- correctly, since its
        // subject is a path that will not exist on the next machine rather than
        // a path that says who owns this one. The two rules were easy to confuse
        // from the outside and this is the line between them.
        let root = "/";
        for (parent, account, searched) in [
            ("home", "runner", false),
            ("Users", "runner", false),
            ("home", "ec2-user", false),
            ("home", "alice", true),
            ("home", "hg", true),
        ] {
            let home = format!("{root}{parent}/{account}");
            let read_back = home.trim_end_matches('/').rsplit('/').next().unwrap();
            assert_eq!(
                !is_public_identity(read_back),
                searched,
                "{home} is searched for: {searched}"
            );
        }
        // A trailing slash must not turn the account into an empty string, which
        // is not a public identity and would put the needle back.
        assert!(is_public_identity(
            format!("{root}home/runner/")
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap()
        ));
    }

    #[test]
    fn generic_hostname_parts_are_not_searched_for() {
        let segments = hostname_segments("debian-x8664-arc");
        assert_eq!(segments, vec!["arc".to_owned()]);
    }

    #[test]
    fn a_short_or_numeric_segment_is_dropped() {
        // "pi" is two characters, which collides with far too much ordinary
        // text even under whole-word matching; "12" and "01" are digits.
        assert!(!hostname_segments("a-12-pi").contains(&"pi".to_owned()));
        assert!(hostname_segments("node-01").is_empty());
    }

    #[test]
    fn the_whole_hostname_is_not_repeated_as_a_segment() {
        assert!(hostname_segments("solo").is_empty());
    }

    #[test]
    fn an_unknown_source_names_what_it_knows() {
        let error = resolve("nope", None, std::path::Path::new("."), false, "r", &[]).unwrap_err();
        assert!(error.to_string().contains("running-os-identity"), "{error}");
    }

    #[test]
    fn a_failing_command_source_is_an_error_and_not_an_empty_result() {
        let error = resolve(
            "command",
            Some("exit 3"),
            std::path::Path::new("."),
            false,
            "r",
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("exited 3"), "{error}");
    }

    #[test]
    fn a_command_source_reads_labelled_and_bare_lines() {
        let needles = resolve(
            "command",
            Some("printf 'box\\tsecret-host\\nplain\\n'"),
            std::path::Path::new("."),
            true,
            "r",
            &[],
        )
        .unwrap();
        assert_eq!(needles.len(), 2);
        assert_eq!(needles[0].label, "box");
        assert_eq!(needles[0].value, "secret-host");
        assert!(needles[0].word);
        assert_eq!(needles[1].label, "plain");
    }
}
