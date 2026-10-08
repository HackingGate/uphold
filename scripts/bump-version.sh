#!/usr/bin/env bash
set -euo pipefail

# bump-version.sh -- make the "Prepare uphold X.Y.Z" commit, the first half of
# a release.
#
#   scripts/bump-version.sh X.Y.Z
#
# The version is written in several files, and a release that moved only some
# of them ships a README pinning a tag that installs the previous engine. So
# the edit is made pin by pin rather than by a search-and-replace over the
# tree, and then checked against what it should have been:
#
#   Cargo.toml          the [package] version
#   Cargo.lock          the version of the `name = "uphold"` entry
#   README.md           the `--tag`, `rev:` and `ref:` pins
#   hooks/lefthook.yml  the header comment's `ref:`
#
# Each file must change exactly the lines `expect` names below, and the old
# version must be gone from it; otherwise the files are restored and the script
# fails. Cargo.lock is then read back by
# `cargo metadata --locked --offline`, which refuses a lock that disagrees with
# the manifest, so the hand edit is proven by the tool that would otherwise
# rewrite it.
#
# The bump is made from main as origin has it: the script fetches, and refuses
# unless the checkout is on `main` at origin/main, so the prep pull request
# carries nothing but the version.
#
# The result is a commit on a new branch `prepare-X.Y.Z`, subject only. If the
# branch, the staging or the commit fails -- a commit hook refusing, say -- the
# script goes back to main, deletes the branch and restores the files before it
# fails, so a refused run leaves the checkout as it found it. Nothing
# is pushed: the script prints the push and the `gh pr create` to run next, and
# the tag is scripts/tag-release.sh's job once the pull request has merged.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

die() {
    printf 'bump-version: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage: scripts/bump-version.sh X.Y.Z

Write version X.Y.Z into Cargo.toml, Cargo.lock, README.md and
hooks/lefthook.yml, and commit it as "Prepare uphold X.Y.Z" on a new branch
prepare-X.Y.Z. X.Y.Z must be plain MAJOR.MINOR.PATCH and greater than the
version Cargo.toml carries now. The checkout must be on main at origin/main,
after a fetch. Nothing is pushed.

  -h, --help  show this help.
USAGE
}

case "${1:-}" in
    -h | --help)
        usage
        exit 0
        ;;
esac
[ "$#" -eq 1 ] || {
    usage >&2
    exit 2
}
new="$1"

# Plain MAJOR.MINOR.PATCH, no `v`, no pre-release, no leading zero: the tag is
# built from this string, and cargo refuses a leading zero anyway.
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
[[ "$new" =~ $semver ]] || die "'$new' is not a plain version (want N.N.N, e.g. 1.28.0)"

cd -- "$repo_root"

files=(Cargo.toml Cargo.lock README.md hooks/lefthook.yml)
# The lines each file must change, in the order of `files`.
expect=(1 1 3 1)

# Tracked changes only. The commit stages these four files by name, so an
# untracked file cannot ride along; a modified tracked one would make the
# line counts below lie, and a restore would throw it away.
[ -z "$(git status --porcelain --untracked-files=no)" ] ||
    die "the working tree has uncommitted changes; commit or stash them first"

# The prep commit is the one tag-release.sh will tag, so it must sit directly
# on origin/main: from a stale main or a side branch, the pull request would
# carry other changes under a subject that says it only bumps the version.
git fetch -q origin || die "git fetch origin failed"
current="$(git symbolic-ref -q --short HEAD || true)"
[ "$current" = main ] ||
    die "run this on main, not ${current:-a detached HEAD}; git switch main first"
head_sha="$(git rev-parse HEAD)"
origin_sha="$(git rev-parse -q --verify 'origin/main^{commit}')" ||
    die "no origin/main after the fetch"
[ "$head_sha" = "$origin_sha" ] ||
    die "main ($head_sha) is not origin/main ($origin_sha); git pull --ff-only, or drop the local commits, first"

branch="prepare-$new"
if git rev-parse -q --verify "refs/heads/$branch" >/dev/null; then
    die "branch $branch already exists"
fi

# package_version FILE-CONTENT-ON-STDIN -> the [package] table's version.
package_version() {
    awk '
        /^\[/ { in_package = ($0 == "[package]") }
        in_package && /^version = "/ {
            sub(/^version = "/, ""); sub(/"$/, ""); print; exit
        }
    '
}

old="$(package_version <Cargo.toml)"
[[ "$old" =~ $semver ]] || die "Cargo.toml's [package] version '$old' is not N.N.N"

# version_gt A B -> A is greater than B, compared field by field as numbers.
version_gt() {
    local a b i
    IFS=. read -ra a <<<"$1"
    IFS=. read -ra b <<<"$2"
    for i in 0 1 2; do
        [ "${a[i]}" -gt "${b[i]}" ] && return 0
        [ "${a[i]}" -lt "${b[i]}" ] && return 1
    done
    return 1
}
version_gt "$new" "$old" || die "$new is not greater than the current version $old"

# fail MESSAGE -> put the four files back as they were committed, then die.
fail() {
    git checkout -- "${files[@]}"
    die "$* (the four files are restored)"
}

# rewrite FILE AWK-PROGRAM -> run the program over FILE with `old` and `new`
# set, writing back in place. `cat >` keeps the file's mode. The programs are
# awk, single-quoted so the shell leaves their `$0` alone, which is what
# SC2016 is disabled for at each call.
rewrite() {
    local file="$1" program="$2" tmp
    tmp="$(mktemp)" || fail "mktemp failed while rewriting $file"
    if ! awk -v old="$old" -v new="$new" "$program" "$file" >"$tmp" ||
        ! cat "$tmp" >"$file"; then
        rm -f "$tmp"
        fail "could not rewrite $file"
    fi
    rm -f "$tmp"
}

# Only the [package] table's version; a dependency written as a table has a
# `version =` line too.
# shellcheck disable=SC2016
rewrite Cargo.toml '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && $0 == "version = \"" old "\"" { $0 = "version = \"" new "\"" }
    { print }
'
# The line after `name = "uphold"`; a dependency may share the version number.
# shellcheck disable=SC2016
rewrite Cargo.lock '
    prev == "name = \"uphold\"" && $0 == "version = \"" old "\"" {
        $0 = "version = \"" new "\""
    }
    { prev = $0; print }
'
# A pin is a line that ends in one of these, followed by the version.
# shellcheck disable=SC2016
rewrite README.md '
    function ends_with(s, t) {
        return length(s) >= length(t) && substr(s, length(s) - length(t) + 1) == t
    }
    {
        n = split("--tag v|rev: v|ref: v", pins, "|")
        for (i = 1; i <= n; i++) {
            if (ends_with($0, pins[i] old)) {
                $0 = substr($0, 1, length($0) - length(old)) new
                break
            }
        }
        print
    }
'
# The commented `ref:` in the header, where a consumer copies the pin from.
# shellcheck disable=SC2016
rewrite hooks/lefthook.yml '
    /^#/ && length($0) >= length("ref: v" old) &&
        substr($0, length($0) - length("ref: v" old) + 1) == "ref: v" old {
        $0 = substr($0, 1, length($0) - length(old)) new
    }
    { print }
'

for i in "${!files[@]}"; do
    file="${files[i]}"
    want="${expect[i]}"
    got="$(git diff --numstat -- "$file" | awk '{ print $1 " " $2 }')"
    [ "$got" = "$want $want" ] ||
        fail "$file: expected $want line(s) changed, got '${got:-none}'"
done

# The old version must be gone from each file, read the way each file spells
# it. Cargo.lock is read only at the uphold entry, for the reason above.
leftover="$(grep -nF "\"$old\"" Cargo.toml || true)"
[ -z "$leftover" ] || fail "Cargo.toml still carries $old: $leftover"
leftover="$(grep -nF "v$old" README.md hooks/lefthook.yml || true)"
[ -z "$leftover" ] || fail "a pin still reads v$old: $leftover"
lock_version="$(awk 'prev == "name = \"uphold\"" { print; exit } { prev = $0 }' Cargo.lock)"
[ "$lock_version" = "version = \"$new\"" ] ||
    fail "Cargo.lock's uphold entry reads '$lock_version', not version \"$new\""

command -v cargo >/dev/null 2>&1 || fail "cargo is needed to check Cargo.lock"
cargo metadata --locked --offline --format-version 1 >/dev/null ||
    fail "cargo metadata --locked --offline refused the edited Cargo.lock"

# undo_commit STEP -> leave the prep branch, delete it, restore the four files,
# then die naming the step that failed. Each undo step is allowed to fail on its
# own (the branch may not exist yet), and the last check says whether the
# checkout is back where it started.
undo_commit() {
    git reset -q -- "${files[@]}" || true
    git checkout -q -- "${files[@]}" || true
    if [ "$(git symbolic-ref -q --short HEAD || true)" != main ]; then
        git checkout -q main || true
    fi
    if git rev-parse -q --verify "refs/heads/$branch" >/dev/null; then
        git branch -q -D "$branch" || true
    fi
    local on dirty kept=0
    on="$(git symbolic-ref -q --short HEAD || true)"
    dirty="$(git status --porcelain --untracked-files=no)"
    git rev-parse -q --verify "refs/heads/$branch" >/dev/null && kept=1
    [ "$on" = main ] && [ -z "$dirty" ] && [ "$kept" -eq 0 ] &&
        die "$1 failed; back on main, $branch deleted and the four files restored"
    die "$1 failed, and the checkout could not be fully restored; check git status and git branch"
}

git checkout -q -b "$branch" || undo_commit "git checkout -b $branch"
git add -- "${files[@]}" || undo_commit "git add"
git commit -q -m "Prepare uphold $new" || undo_commit "git commit (a hook may have refused it)"

printf 'Committed "Prepare uphold %s" on branch %s (%s -> %s).\n' \
    "$new" "$branch" "$old" "$new"
cat <<NEXT

Next:
  git push -u origin $branch
  gh pr create --title "Prepare uphold $new" --body "Version bump."

After it merges: scripts/tag-release.sh to check, then with --push to tag
NEXT
