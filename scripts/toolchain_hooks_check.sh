#!/usr/bin/env bash
# Drive the published toolchain ids under one hook runner, the way a consuming
# repository drives them.
#
#   scripts/toolchain_hooks_check.sh <pre-commit|prek> [hooks-repo] [ref]
#
# The toolchain ids (uphold-go-*, uphold-cargo-*) run the consumer's own go
# and cargo. So what needs testing is how a runner treats the manifest entry:
#   - does `args:` reach the command;
#   - does a missing toolchain fail the hook instead of skipping it;
#   - does a check stay a check.
# Reading the YAML cannot answer those. Only a real runner over a real
# repository can.
#
# For each id this script plants the defect the id exists to refuse and
# expects a refusal, then expects an unmodified fixture to pass.
#
# Needs go, cargo (with rustfmt and clippy), git and the runner on PATH.
# Set TOOLCHAIN_KEEP=1 to leave the scratch directory in place for reading.

set -euo pipefail

RUNNER=${1:?usage: toolchain_hooks_check.sh <pre-commit|prek> [hooks-repo] [ref]}
HOOKS_REPO=${2:-$(cd "$(dirname "$0")/.." && pwd)}
HOOKS_REF=${3:-$(git -C "$HOOKS_REPO" rev-parse HEAD)}

case $RUNNER in pre-commit|prek) ;; *) echo "runner must be pre-commit or prek" >&2; exit 2 ;; esac

WORK=$(mktemp -d)
if [ "${TOOLCHAIN_KEEP:-0}" != 1 ]; then
    trap 'rm -rf -- "$WORK"' EXIT
fi

say() { printf '\n== %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

# A branch at a neutral path, for the reasons consumer_check.sh gives: a
# consumer pins a branch or a tag, and a home path in the config is a fact
# this test would have invented.
HOOKS=$WORK/hooks
git clone -q "$HOOKS_REPO" "$HOOKS"
git -C "$HOOKS" checkout -q -B toolchain-under-test "$HOOKS_REF"

# A directory holding only what a runner needs, so a hook run under it has
# no go and no cargo. `env` and `sh` stay because the entries call them;
# leaving them out would make the hook fail for the wrong reason.
NOTOOLS=$WORK/no-toolchain-bin
mkdir -p "$NOTOOLS"
for tool in env sh "$RUNNER"; do
    ln -s "$(command -v "$tool")" "$NOTOOLS/$tool"
done
# The real git, not a wrapper in front of it: uphold's own shim is a `git` on
# PATH that hands off to the next git on PATH, and there is none in here.
for candidate in $(type -ap git); do
    if [ "$(basename "$(readlink -f "$candidate")")" = git ]; then
        ln -s "$candidate" "$NOTOOLS/git"
        break
    fi
done
[ -e "$NOTOOLS/git" ] || fail "no git binary on PATH that is not a wrapper"

# One consumer per language. It pins every id of its language. When given
# `<id> <args-flow-list>`, that one id carries the consumer's own `args:`.
consumer() {
    local dir=$1 ids=$2 args_id=${3:-} args=${4:-}
    rm -rf -- "$dir"
    mkdir -p "$dir"
    git -C "$dir" init -q -b main
    {
        echo "repos:"
        echo "  - repo: $HOOKS"
        echo "    rev: toolchain-under-test"
        echo "    hooks:"
        for id in $ids; do
            echo "      - id: $id"
            if [ "$id" = "$args_id" ]; then
                echo "        args: $args"
            fi
        done
    } > "$dir/.pre-commit-config.yaml"
}

stage() { git -C "$1" add -A; }

# run <dir> <id> -> the runner's exit status; output to $WORK/last.log
run() {
    local dir=$1 id=$2 status=0
    (cd "$dir" && "$RUNNER" run "$id" --all-files --hook-stage manual) > "$WORK/last.log" 2>&1 || status=$?
    return $status
}

passes() {
    run "$1" "$2" || { cat "$WORK/last.log"; fail "$2 refused a fixture it should pass ($3)"; }
    echo "ok: $2 passes $3"
}

refuses() {
    if run "$1" "$2"; then cat "$WORK/last.log"; fail "$2 passed $3"; fi
    if [ -n "${4:-}" ] && ! grep -q -- "$4" "$WORK/last.log"; then
        cat "$WORK/last.log"; fail "$2 refused $3, but not with \"$4\""
    fi
    echo "ok: $2 refuses $3"
}

refuses_without_toolchain() {
    local status=0
    (cd "$1" && PATH=$NOTOOLS "$RUNNER" run "$2" --all-files --hook-stage manual) > "$WORK/last.log" 2>&1 || status=$?
    [ "$status" != 0 ] || { cat "$WORK/last.log"; fail "$2 passed with $3 missing"; }
    # The tool's name alone would match the hook's own name in the output, so
    # look for it quoted, followed by the words a missing executable is
    # reported with. Each runner words this differently and prek uses two
    # lines: pre-commit "Executable `go` not found"; prek "Failed to run `go
    # build ...`" then "No such file or directory"; env "'cargo': No such file".
    tr '\n' ' ' < "$WORK/last.log" | grep -Eq -- "[\`'‘]$3[ \`'’].*(not found|No such file)" \
        || { cat "$WORK/last.log"; fail "$2 failed without $3 but did not say $3 is missing"; }
    echo "ok: $2 fails when $3 is missing"
}

# ── Go ───────────────────────────────────────────────────────────────

GO_IDS="uphold-go-build uphold-go-test"
G=$WORK/go

go_fixture() {
    consumer "$G" "$GO_IDS" "${1:-}" "${2:-}"
    mkdir -p "$G/cmd/app"
    printf 'module example.test/fixture\n\ngo 1.22\n' > "$G/go.mod"
    printf 'package fixture\n\n// One is one.\nfunc One() int { return 1 }\n' > "$G/one.go"
    printf 'package fixture\n\nimport "testing"\n\nfunc TestOne(t *testing.T) {\n\tif One() != 1 {\n\t\tt.Fatal("one")\n\t}\n}\n' > "$G/one_test.go"
    printf 'package main\n\nimport "example.test/fixture"\n\nfunc main() { _ = fixture.One() }\n' > "$G/cmd/app/main.go"
    stage "$G"
}

say "Go, under $RUNNER"
go_fixture
passes "$G" uphold-go-build "an unmodified module"
[ -z "$(git -C "$G" ls-files --others)" ] \
    || fail "uphold-go-build wrote into the tree: $(git -C "$G" ls-files --others)"
echo "ok: uphold-go-build wrote no binary into the tree"
passes "$G" uphold-go-test "an unmodified module"

# A module that is one main package is the case `-o /dev/null` exists for:
# `go build ./...` over several packages discards its output on its own, but
# over a single main package it writes the binary into the working directory.
consumer "$G" "$GO_IDS"
printf 'module example.test/fixture\n\ngo 1.22\n' > "$G/go.mod"
printf 'package main\n\nfunc main() {}\n' > "$G/main.go"
stage "$G"
passes "$G" uphold-go-build "a module that is one main package"
[ -z "$(git -C "$G" ls-files --others)" ] \
    || fail "uphold-go-build wrote into the tree: $(git -C "$G" ls-files --others)"
echo "ok: uphold-go-build wrote no binary for a lone main package"

go_fixture
printf 'package fixture\n\nfunc Two() int { return "two" }\n' > "$G/two.go"
stage "$G"
refuses "$G" uphold-go-build "a package that does not compile" "two.go"

go_fixture
printf 'package fixture\n\nimport "testing"\n\nfunc TestBroken(t *testing.T) { t.Fatal("broken") }\n' > "$G/broken_test.go"
stage "$G"
refuses "$G" uphold-go-test "a failing test" "TestBroken"

# `args:` replaces the default and reaches go: running only TestOne skips the
# broken test, so this passes only if the consumer's args were used.
go_fixture uphold-go-test '["-run", "TestOne", "./..."]'
printf 'package fixture\n\nimport "testing"\n\nfunc TestBroken(t *testing.T) { t.Fatal("broken") }\n' > "$G/broken_test.go"
stage "$G"
passes "$G" uphold-go-test "a broken test excluded by the consumer's args"

go_fixture
refuses_without_toolchain "$G" uphold-go-build go
refuses_without_toolchain "$G" uphold-go-test go

# ── Rust ─────────────────────────────────────────────────────────────

RUST_IDS="uphold-cargo-fmt uphold-cargo-clippy uphold-cargo-test uphold-cargo-check"
R=$WORK/rust
export CARGO_TARGET_DIR=$WORK/rust-target

rust_fixture() {
    consumer "$R" "$RUST_IDS"
    mkdir -p "$R/src"
    printf '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n' > "$R/Cargo.toml"
    cat > "$R/src/lib.rs" <<'RUST'
/// One is one.
pub fn one() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn one_is_one() {
        assert_eq!(super::one(), 1);
    }
}
RUST
    stage "$R"
}

say "Rust, under $RUNNER"
rust_fixture
for id in $RUST_IDS; do
    passes "$R" "$id" "an unmodified crate"
done

rust_fixture
printf 'pub fn badly( )->u32{2}\n' >> "$R/src/lib.rs"
stage "$R"
before=$(sha256sum "$R/src/lib.rs")
refuses "$R" uphold-cargo-fmt "an unformatted source" "lib.rs"
[ "$before" = "$(sha256sum "$R/src/lib.rs")" ] || fail "uphold-cargo-fmt rewrote the source it was checking"
echo "ok: uphold-cargo-fmt left the source as it was"

rust_fixture
printf '\npub fn warns() -> u32 {\n    let unused = 2;\n    1\n}\n' >> "$R/src/lib.rs"
stage "$R"
refuses "$R" uphold-cargo-clippy "a compiler warning" "unused"
refuses "$R" uphold-cargo-check "a compiler warning" "unused"
refuses "$R" uphold-cargo-test "a compiler warning" "unused"

rust_fixture
printf '\n#[cfg(test)]\nmod broken {\n    #[test]\n    fn broken() {\n        panic!("broken");\n    }\n}\n' >> "$R/src/lib.rs"
stage "$R"
refuses "$R" uphold-cargo-test "a failing test" "broken"

rust_fixture
printf '\npub fn needless(x: &u32) -> u32 {\n    return *x;\n}\n' >> "$R/src/lib.rs"
stage "$R"
refuses "$R" uphold-cargo-clippy "a clippy lint" "needless_return"

rust_fixture
for id in $RUST_IDS; do
    refuses_without_toolchain "$R" "$id" cargo
done

say "every toolchain id passed and refused as published, under $RUNNER"
