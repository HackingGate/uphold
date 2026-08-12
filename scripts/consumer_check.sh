#!/usr/bin/env bash
# Drive one hook runner the way a consuming repository drives it.
#
#   scripts/consumer_check.sh <pre-commit|prek|lefthook> [hooks-repo] [ref]
#
# The repository under test is NOT this one. Everything here happens in a
# throwaway git repository that pins this one, because every bug this script
# exists to catch was invisible from inside: a hook id nothing published, a
# seam predicate that matched only this repository's own hook names, a base set
# resolved against a directory only this repository has, and a pre-push guard
# that read git's stdin under a runner that does not forward it. Each of those
# passed every test here and failed on first contact with a consumer.
#
# Each runner is asked the same eight questions, because "supports lefthook" has
# to mean the same thing as "supports pre-commit" or it is a listing rather than
# a claim:
#
#   1. a clean commit passes
#   2. a commit message carrying an AI-authorship trailer is refused
#   3. a clean push passes
#   4. a later push carrying a zero-width space is refused -- which is only
#      possible if the guard learned WHAT IS BEING PUSHED, the fact each runner
#      delivers by a different channel
#   5. a rule that names `[rule.files]` and no `[rule.git]` is NOT run by a git
#      hook, because an absent table is a place the rule does not run
#   6. a false enforcement claim is refused when the declaration changes, and
#      the corrected one is accepted
#   7. an ordinary merge commit is made and passes, and a merge that would bring
#      in a zero-width space is refused
#   8. the manual-stage entry point runs and passes
#
# Question 4 is the one that matters for the runners. A guard that cannot see
# the push does not fail loudly by default; it falls back to some other tree and
# reports on that, so a runner can look supported while checking the wrong thing.
#
# Question 5 is the one that matters for the schema, and it is the only one here
# that fails by a check running where nobody asked for it rather than by one
# failing to run.
#
# Questions 6 to 8 exist because the consumer config below pins every published
# id, and pinning an id is not running it. Three of those ids fired nowhere:
# `uphold-check` is registered against a list of PATHS and no question edited
# one of them, `uphold-guard-merge` needs a merge commit and no question made
# one, and `uphold-guard-manual` sits at a stage reached only by an explicit
# invocation that nothing here made. A pinned id that never runs is this
# script's own failure mode, one level up -- it passes here, in a config that
# looks complete, and does nothing in the consumer that copies it.

set -euo pipefail

RUNNER=${1:?usage: consumer_check.sh <pre-commit|prek|lefthook> [hooks-repo] [ref]}
HOOKS_REPO=${2:-$(cd "$(dirname "$0")/.." && pwd)}
HOOKS_REF=${3:-$(git -C "$HOOKS_REPO" rev-parse --abbrev-ref HEAD)}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CONSUMER=$WORK/consumer
REMOTE=$WORK/remote.git

say() { printf '\n== %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

# Commit without invoking any hook. Used to plant what a guard is supposed to
# catch: a violation that arrived through a hook is not a test of the guard that
# is supposed to catch it later.
raw_commit() {
    git -C "$CONSUMER" add -A
    git -C "$CONSUMER" -c user.email=demo@example.test -c user.name=Demo \
        commit -q --no-verify -m "$1"
}

commit() {
    git -C "$CONSUMER" add -A
    git -C "$CONSUMER" -c user.email=demo@example.test -c user.name=Demo \
        commit -q -m "$1"
}

say "consumer: $CONSUMER  runner: $RUNNER  hooks: $HOOKS_REPO@$HOOKS_REF"

# The hooks repository is cloned to a neutral path and pinned by a branch name,
# rather than pinned where it already sits.
#
# Two reasons, and both are the consumer's reality rather than the test's
# convenience. A checkout's path goes into .pre-commit-config.yaml verbatim, and
# a working copy under a home directory puts a home path into a file the
# consumer's own content policy then reads and refuses -- which is the policy
# working, on a fact this script invented. And a bare sha is not fetchable from
# every transport, while a branch is; a consumer pins a tag or a branch.
HOOKS=$WORK/hooks
git clone -q "$HOOKS_REPO" "$HOOKS"
git -C "$HOOKS" checkout -q -B parity-under-test "$HOOKS_REF"
HOOKS_REPO=$HOOKS
HOOKS_REF=parity-under-test

git init -q --bare "$REMOTE"
mkdir -p "$CONSUMER/policy"
git init -q -b main "$CONSUMER"
git -C "$CONSUMER" remote add origin "$REMOTE"

# A policy that reaches every stage: a commit-msg guard, a guard that reads the
# tree an operation introduces (so pre-commit AND pre-push), and an inherited
# base set -- which a consuming repository does not have a copy of, and never
# will, because the engine compiles the bundled sets in.
cat > "$CONSUMER/policy/principles.toml" <<'POLICY'
allowed_scripts = ["Latin"]

[inherit]
sets = ["process-residue"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"
git.hooks = ["commit-msg"]

[rule.prevent-unusual-unicode]
builtin = "prevent-unusual-unicode"
git.hooks = ["commit-msg"]

[rule.prevent-unusual-unicode-in-files]
builtin = "prevent-unusual-unicode-in-files"
git.hooks = ["pre-commit", "pre-merge-commit", "pre-push", "manual"]

[rule.no-merge-commit]
builtin = "no-merge-commit"
git.hooks = ["pre-commit"]

# The fifth question below. This rule names a place and it is not a git hook,
# so no hook may run it -- and a rule that runs nowhere would answer the same
# way, which is why the question asks what a hook DOES.
[rule.no-todo-markers]
message = "Resolve the TODO or file it."
regexp = 'XXXFIXMEXXX'
files.exclude = ["policy/**"]
POLICY

cat > "$CONSUMER/policy/upheld.toml" <<'DECLARATION'
[[enforce]]
principle = "complete-mediation"
rule = "prevent-ai-author"
DECLARATION

printf 'A consuming repository.\n' > "$CONSUMER/README.md"

case "$RUNNER" in
pre-commit | prek)
    cat > "$CONSUMER/.pre-commit-config.yaml" <<CONFIG
default_install_hook_types: [pre-commit, commit-msg, pre-merge-commit, pre-push]
repos:
  - repo: $HOOKS_REPO
    rev: $HOOKS_REF
    hooks:
      - id: uphold-check
      - id: uphold-scan
      - id: uphold-scan-text
      - id: uphold-guard
      - id: uphold-guard-commit-msg
      - id: uphold-guard-merge
      - id: uphold-guard-push
      - id: uphold-guard-manual
CONFIG
    raw_commit "seed"
    (cd "$CONSUMER" && "$RUNNER" install --install-hooks >/dev/null)
    ;;
lefthook)
    # No ids and no pins: lefthook merges a config out of the remote. The
    # binary comes from PATH, which is the one thing this runner cannot do for
    # the consumer.
    command -v uphold >/dev/null || fail "lefthook needs \`uphold\` on PATH"
    cat > "$CONSUMER/lefthook.yml" <<CONFIG
remotes:
  - git_url: $HOOKS_REPO
    ref: $HOOKS_REF
    configs:
      - hooks/lefthook.yml
CONFIG
    raw_commit "seed"
    (cd "$CONSUMER" && lefthook install >/dev/null)
    ;;
*)
    fail "unknown runner $RUNNER"
    ;;
esac

say "1. a clean commit passes"
printf 'a line\n' > "$CONSUMER/note.txt"
commit "Add a note" || fail "a clean commit was refused"

say "2. a commit message carrying an AI-authorship trailer is refused"
printf 'another line\n' >> "$CONSUMER/note.txt"
git -C "$CONSUMER" add -A
if git -C "$CONSUMER" -c user.email=demo@example.test -c user.name=Demo commit -q -m \
    "Add another

Co-Authored-By: Someone <noreply@example.test>" >"$WORK/trailer.log" 2>&1; then
    fail "the AI-authorship trailer was accepted"
fi
grep -q "prevent-ai-author" "$WORK/trailer.log" ||
    fail "refused, but not by prevent-ai-author: $(cat "$WORK/trailer.log")"
commit "Add another"

say "3. a clean push passes"
git -C "$CONSUMER" push -q origin main >"$WORK/clean.log" 2>&1 ||
    fail "a clean push was refused: $(cat "$WORK/clean.log")"

say "4. a push carrying a zero-width space is refused"
# Planted with hooks off, so what catches it is the push guard reading the
# pushed range -- not the commit guard that would have caught it on the way in.
# It has to come AFTER a clean push: the range a first push introduces is the
# whole history, and a blob deleted in a later commit is still on the remote
# permanently, so a repository that ever committed one could never push again.
printf 'hidden\xe2\x80\x8b here\n' > "$CONSUMER/sneaky.txt"
raw_commit "Add a file"
if git -C "$CONSUMER" push -q origin main >"$WORK/push.log" 2>&1; then
    fail "a push carrying U+200B was accepted"
fi
grep -q "prevent-unusual-unicode-in-files" "$WORK/push.log" ||
    fail "the push was refused, but not by the guard that reads it: $(cat "$WORK/push.log")"
# A guard that could not see the push must say so rather than pass: exit 2 is
# could-not-look and is a failure of this test, not a version of question 4.
if grep -q "no ref line reached this guard" "$WORK/push.log"; then
    fail "$RUNNER did not deliver the pushed range to the guard"
fi
# The plant has answered its question and it is still in the tree. Every
# question after this one expects a tree that PASSES -- the merge guard reads
# the merged index and the manual guard reads the whole tree, and both would
# refuse for a reason this script planted rather than for the reason being
# asked about. Removed with hooks off, because a deletion is not what is under
# test either.
rm -f "$CONSUMER/sneaky.txt"
raw_commit "Remove the planted file"

say "5. a rule that names [rule.files] and no [rule.git] is not run by a hook"
# The marker is refused -- by the SCAN, which is the place the rule named. The
# proof is which reporter says so: `uphold scan` prints the rule id, and
# `uphold guard` prints "guard refused" and would have to have run this rule
# at a hook it never declared.
printf 'XXXFIXMEXXX\n' > "$CONSUMER/marker.txt"
git -C "$CONSUMER" add -A
if git -C "$CONSUMER" -c user.email=demo@example.test -c user.name=Demo \
    commit -q -m "Add a marker" >"$WORK/marker.log" 2>&1; then
    fail "the file scan did not run at all"
fi
grep -q "no-todo-markers" "$WORK/marker.log" ||
    fail "the scan did not refuse the marker: $(cat "$WORK/marker.log")"
if grep -q "guard refused: no-todo-markers" "$WORK/marker.log"; then
    fail "a rule with no [rule.git] was run by a git hook anyway"
fi
git -C "$CONSUMER" rm -q --cached marker.txt
rm -f "$CONSUMER/marker.txt"

say "6. a change to the declaration is reconciled, and a false claim is refused"
# The only check here that fires on a PATH rather than on every commit: it runs
# when the declaration changes, or when a file a claim is reconciled against
# changes, and stays silent otherwise. Which means every question above ran with
# it switched off, and a consumer who pinned it would have learned nothing about
# whether it works -- the same shape of hole as an id nothing publishes.
#
# Asked in the refusing direction first. A check that fires and cannot say no is
# indistinguishable, from the outside, from a check that never fired.
cat > "$CONSUMER/policy/upheld.toml" <<'DECLARATION'
[[enforce]]
principle = "complete-mediation"
rule = "prevent-ai-author"

# No rule in policy/principles.toml supplies this one, so the claim is false --
# which is a different answer from "could not look", and the exit code says so.
[[enforce]]
principle = "least-privilege"
rule = "prevent-public-push"
DECLARATION
git -C "$CONSUMER" add -A
if git -C "$CONSUMER" -c user.email=demo@example.test -c user.name=Demo \
    commit -q -m "Claim a rule this repository does not run" >"$WORK/claim.log" 2>&1; then
    fail "a false enforcement claim was accepted"
fi
grep -q "prevent-public-push" "$WORK/claim.log" ||
    fail "refused, but not by the declaration check: $(cat "$WORK/claim.log")"
# A declaration that could not be READ exits 2 and prints this instead, which
# would satisfy the grep above for the wrong reason: the seams a claim is
# resolved against live in the consumer's own config, and a runner that hands
# the checker the wrong working directory reads none of them.
if grep -q "could not look" "$WORK/claim.log"; then
    fail "the declaration check could not read this consumer: $(cat "$WORK/claim.log")"
fi

# And the accepting direction, which is the half a consumer lives in. The false
# claim is replaced by a true one rather than simply deleted: reverting the file
# to what it already held stages nothing, git refuses an empty commit, and the
# question would have passed on a commit that never happened.
cat > "$CONSUMER/policy/upheld.toml" <<'DECLARATION'
[[enforce]]
principle = "complete-mediation"
rule = "prevent-ai-author"

[[enforce]]
principle = "least-astonishment"
rule = "prevent-unusual-unicode"
DECLARATION
commit "Declare what enforces what" || fail "a true enforcement claim was refused"

say "7. a merge is guarded"
# git runs `pre-merge-commit` for a merge and `pre-commit` for a commit. They
# are different hook types, installed by different lines, and nothing above
# makes a merge at all -- so the stage every consumer pins was the stage nothing
# here ever entered. A branch carrying a zero-width space merging into the trunk
# with no file guard consulted is the failure this stage exists to prevent, and
# it is invisible until a merge happens.
git -C "$CONSUMER" checkout -q -b side
printf 'a side line\n' > "$CONSUMER/side.txt"
commit "Add a side note"
git -C "$CONSUMER" checkout -q main
git -C "$CONSUMER" -c user.email=demo@example.test -c user.name=Demo \
    merge -q --no-ff -m "Merge the side branch" side >"$WORK/merge.log" 2>&1 ||
    fail "an ordinary merge was refused: $(cat "$WORK/merge.log")"

# The same merge with something to find. Planted with hooks off so that what
# refuses it is the merge guard reading the merged index, not the commit guard
# that would have caught it on the branch.
git -C "$CONSUMER" checkout -q -b side-hidden
printf 'hidden\xe2\x80\x8b again\n' > "$CONSUMER/side-hidden.txt"
raw_commit "Add a side file"
git -C "$CONSUMER" checkout -q main
if git -C "$CONSUMER" -c user.email=demo@example.test -c user.name=Demo \
    merge -q --no-ff -m "Merge the hidden branch" side-hidden >"$WORK/merge-hidden.log" 2>&1; then
    fail "a merge carrying U+200B was accepted"
fi
grep -q "prevent-unusual-unicode-in-files" "$WORK/merge-hidden.log" ||
    fail "the merge was refused, but not by the file guard: $(cat "$WORK/merge-hidden.log")"
# A refused merge leaves the merged index in place for the author to fix. This
# is not that author, and the question after this one reads the tree.
git -C "$CONSUMER" merge --abort 2>/dev/null || true
git -C "$CONSUMER" reset -q --hard HEAD
git -C "$CONSUMER" branch -D side-hidden >/dev/null

say "8. the manual-stage entry point runs and passes"
# Where the slow guards live: the tree-wide name scans and the pin check each
# ask the forge over the network, so they are registered at a stage no commit
# and no push reaches. CI and a schedule are the only things that ever run them,
# and each runner spells that invocation differently -- which is exactly where
# "supported" decays into "listed", because an id pinned at a stage the runner
# has no way to reach is an id that runs nowhere and reports nothing.
case "$RUNNER" in
pre-commit | prek)
    (cd "$CONSUMER" && "$RUNNER" run --all-files --hook-stage manual) \
        >"$WORK/manual.log" 2>&1 ||
        fail "the manual stage failed: $(cat "$WORK/manual.log")"
    ;;
lefthook)
    # lefthook has no manual stage; `uphold-manual` is the named group that
    # stands in for one, and a consumer merging this repository's remote config
    # gets it under that name.
    (cd "$CONSUMER" && lefthook run uphold-manual) \
        >"$WORK/manual.log" 2>&1 ||
        fail "the manual group failed: $(cat "$WORK/manual.log")"
    ;;
esac

say "$RUNNER: all eight passed"
