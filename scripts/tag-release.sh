#!/usr/bin/env bash
set -euo pipefail

# tag-release.sh -- tag the merged "Prepare uphold X.Y.Z" commit and push the
# tag, the second half of a release.
#
#   scripts/tag-release.sh         every check, then print what it would do
#   scripts/tag-release.sh --push  every check, then tag origin/main and push
#
# Publishing is opt-in: without --push nothing is created or pushed.
# `--dry-run` is accepted as the earlier spelling of the default.
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
#   - the subject alone is a title anyone can type, so the commit's content
#     must also be the bump: its parent's Cargo.toml version must be lower than
#     X.Y.Z, and it may change only the files bump-version.sh edits;
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
Usage: scripts/tag-release.sh [--push]

Check that origin/main is the merged version bump to X.Y.Z -- its Cargo.toml
version, its subject "Prepare uphold X.Y.Z (#N)", a lower version in its
parent, and no files changed but the version files -- and print the tag and
push that would publish it. Nothing is created or pushed unless --push is given.

  --push      create the annotated tag vX.Y.Z on origin/main and push it alone.
  --dry-run   the default, accepted for the earlier spelling; not with --push.
  -h, --help  show this help.
USAGE
}

push=0
dry_run=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --push) push=1 ;;
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

if [ "$push" -eq 1 ] && [ "$dry_run" -eq 1 ]; then
    printf 'tag-release: --push and --dry-run contradict each other\n' >&2
    usage >&2
    exit 2
fi

cd -- "$repo_root"

git fetch -q origin --tags || die "git fetch origin --tags failed"

sha="$(git rev-parse -q --verify 'origin/main^{commit}')" || die "no origin/main after the fetch"

# package_version_at REV -> the [package] version in REV's Cargo.toml.
package_version_at() {
    git show "$1:Cargo.toml" | awk '
        /^\[/ { in_package = ($0 == "[package]") }
        in_package && /^version = "/ {
            sub(/^version = "/, ""); sub(/"$/, ""); print; exit
        }
    '
}

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

version="$(package_version_at "$sha")"
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
[[ "$version" =~ $semver ]] ||
    die "origin/main's Cargo.toml [package] version '$version' is not N.N.N"
tag="v$version"

subject="$(git log -1 --format=%s "$sha")"
expected="^Prepare uphold ${version//./\\.} \(#[0-9]+\)$"
[[ "$subject" =~ $expected ]] ||
    die "origin/main ($sha) is '$subject', not 'Prepare uphold $version (#N)'; merge the prep pull request first, or tag by hand"

# The subject is a claim; the content is the proof. The commit must raise the
# version from its parent's, read the same way, and touch nothing else.
parent="$(git rev-parse -q --verify "$sha^1^{commit}")" ||
    die "origin/main ($sha) has no parent, so nothing shows it raised the version"
previous="$(package_version_at "$parent")"
[[ "$previous" =~ $semver ]] ||
    die "the parent $parent's Cargo.toml [package] version '$previous' is not N.N.N"
version_gt "$version" "$previous" ||
    die "origin/main ($sha) is titled 'Prepare uphold $version' but does not raise the version: its parent already carries $previous"
version_files=(Cargo.toml Cargo.lock README.md hooks/lefthook.yml)
changed_files="$(git diff --name-only "$parent" "$sha")" ||
    die "could not diff origin/main ($sha) against its parent"
while IFS= read -r changed; do
    allowed=0
    for f in "${version_files[@]}"; do
        [ "$changed" = "$f" ] && allowed=1
    done
    [ "$allowed" -eq 1 ] ||
        die "origin/main ($sha) changes $changed, which a version bump does not touch (only ${version_files[*]})"
done <<<"$changed_files"

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

if [ "$push" -eq 0 ]; then
    cat <<DRY
Dry run; nothing changed. origin/main is $sha, "$subject" ($previous -> $version).
Would run:
  git tag -a $tag -m "uphold $version" $sha
  git push origin refs/tags/$tag
Run again with --push to create and push the tag.
DRY
    exit 0
fi

git tag -a "$tag" -m "uphold $version" "$sha"
git cat-file -p "$tag"
echo
git push origin "refs/tags/$tag"
printf 'Pushed %s. The release workflow builds the release page from it.\n' "$tag"
