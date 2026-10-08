#!/usr/bin/env bash
set -euo pipefail

# tag-release.sh -- tag the merged "Prepare uphold X.Y.Z" commit and push the
# tag, the second half of a release.
#
#   scripts/tag-release.sh            tag origin/main and push the tag
#   scripts/tag-release.sh --dry-run  every check, then print what it would do
#
# The tag push is what .github/workflows/release.yml runs on, and a pushed tag
# is a release other people install from, so the script tags nothing it has not
# first tied to the version bump that names it:
#
#   - the version is read from origin/main's Cargo.toml, not from the local
#     checkout, which may be a branch or behind;
#   - origin/main's subject must be exactly "Prepare uphold X.Y.Z (#N)", the
#     squash merge of scripts/bump-version.sh's pull request, so the tag lands
#     on the commit that bumped the version and not on whatever merged after it;
#   - vX.Y.Z must exist neither here nor on origin. A moved release tag is a
#     different binary under a name consumers already pinned.
#
# The tag is annotated, with the message "uphold X.Y.Z", and only that ref is
# pushed: never --tags, which would publish every stray local tag, and never
# --force.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

die() {
    printf 'tag-release: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage: scripts/tag-release.sh [--dry-run]

Tag origin/main as vX.Y.Z, where X.Y.Z is origin/main's Cargo.toml version and
origin/main's subject is "Prepare uphold X.Y.Z (#N)", then push that tag alone.

  --dry-run   run every check and print the tag and push, changing nothing.
  -h, --help  show this help.
USAGE
}

dry_run=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) dry_run=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
    shift
done

cd -- "$repo_root"

git fetch -q origin --tags || die "git fetch origin --tags failed"

sha="$(git rev-parse -q --verify 'origin/main^{commit}')" || die "no origin/main after the fetch"

version="$(git show origin/main:Cargo.toml | awk '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && /^version = "/ {
        sub(/^version = "/, ""); sub(/"$/, ""); print; exit
    }
')"
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
[[ "$version" =~ $semver ]] ||
    die "origin/main's Cargo.toml [package] version '$version' is not N.N.N"
tag="v$version"

subject="$(git log -1 --format=%s "$sha")"
expected="^Prepare uphold ${version//./\\.} \(#[0-9]+\)$"
[[ "$subject" =~ $expected ]] ||
    die "origin/main ($sha) is '$subject', not 'Prepare uphold $version (#N)'; merge the prep pull request first, or tag by hand"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    die "$tag already exists locally"
fi
# ls-remote exits 2 for "no such ref"; anything else non-zero means origin was
# not asked, which is not the same as the tag being absent.
rc=0
git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null || rc=$?
case "$rc" in
    0) die "$tag already exists on origin" ;;
    2) ;;
    *) die "could not ask origin for $tag (git ls-remote exited $rc)" ;;
esac

if [ "$dry_run" -eq 1 ]; then
    cat <<DRY
Dry run; nothing changed. origin/main is $sha, "$subject".
Would run:
  git tag -a $tag -m "uphold $version" $sha
  git push origin refs/tags/$tag
DRY
    exit 0
fi

git tag -a "$tag" -m "uphold $version" "$sha"
git cat-file -p "$tag"
echo
git push origin "refs/tags/$tag"
printf 'Pushed %s. The release workflow builds the release page from it.\n' "$tag"
