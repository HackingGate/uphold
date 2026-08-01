#!/usr/bin/env bash
set -euo pipefail

# coverage.sh — line coverage over the scan engine, with the floor that fails.
#
# One script for both seams. CI and the manual hook run THIS, so the number a
# contributor is held to locally is the number CI enforces: a floor that lives
# in a workflow file is one a local run cannot read, and the first time it is
# read is the push that trips it.
#
#   scripts/coverage.sh              summary to the terminal, fails under the floor
#   scripts/coverage.sh --lcov FILE  the same run, also writing lcov for upload
#
# The floor is a floor, not a target. It sits just under what the tree measures
# today, so it refuses a drop rather than rewarding a climb -- raise it in the
# commit that earns it, which is the only moment anyone can tell whether the new
# number is real. Overridable for a spike via COVERAGE_FLOOR, deliberately not
# for CI: the workflow passes no override, so a green run means the committed
# floor held.
floor="${COVERAGE_FLOOR:-81}"

lcov_path=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --lcov)
            [ "$#" -ge 2 ] || {
                echo "coverage: --lcov needs a path" >&2
                exit 2
            }
            lcov_path="$2"
            shift
            ;;
        --lcov=*) lcov_path="${1#--lcov=}" ;;
        -h | --help)
            sed -n '3,20p' "$0"
            exit 0
            ;;
        *)
            echo "coverage: unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift
done

# Both are cargo subcommands, so a missing one reports as "no such subcommand"
# from the run itself -- three lines down and past a build. toolchain.toml
# declares them; this says the same thing at the moment it is needed.
for tool in llvm-cov nextest; do
    cargo "$tool" --version >/dev/null 2>&1 || {
        echo "coverage: cargo-$tool is not installed" >&2
        echo "  install it: scripts/deps.sh install   (or: cargo install --locked cargo-$tool)" >&2
        exit 2
    }
done

# The integration tests spawn the binary rather than calling into a library --
# this crate has no lib target -- and llvm-cov instruments that binary and
# collects the child's profile, so those runs count. Without nextest they would
# not: the default harness reuses one process per test binary and the profiles
# collide.
#
# Lines, not branches: `--branch` needs `-Z coverage-options`, so it needs
# nightly, and a floor that only a nightly toolchain can measure is one a
# contributor on the pinned stable cannot reproduce.
args=(nextest --fail-under-lines "$floor")
if [ -n "$lcov_path" ]; then
    args+=(--lcov --output-path "$lcov_path")
else
    args+=(--summary-only)
fi

echo "==> cargo llvm-cov ${args[*]}"
cargo llvm-cov "${args[@]}"
