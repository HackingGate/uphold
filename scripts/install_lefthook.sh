#!/usr/bin/env bash
set -euo pipefail

# install_lefthook.sh -- put the pinned lefthook release binary on PATH.
#
# CI used to reach this state with `go install github.com/evilmartians/lefthook`,
# which compiled the manager from source in two separate jobs and spent about
# three minutes a run producing the byte-identical program the release page
# already publishes. What those jobs are asking is whether this repository's
# hook configuration works under lefthook, not whether lefthook builds, so the
# published binary answers the question and the compile was pure cost.
#
# The download is verified against the checksum file the release ships. A
# release archive that arrives corrupt, truncated, or from something that is not
# the release is a binary this script refuses to install rather than one it
# hands to a green run.
#
# The version comes from the environment and is not defaulted here. A default
# would be a second pin next to the workflow's, free to disagree with it, and
# the one that goes stale silently is always the copy.
#
# Usage:  LEFTHOOK_VERSION=2.1.9 scripts/install_lefthook.sh [install-dir]
#
# Under GitHub Actions the install directory is appended to $GITHUB_PATH; run
# anywhere else it is printed, and putting it on PATH is the caller's business.

version="${LEFTHOOK_VERSION:-}"
if [ -z "$version" ]; then
    echo "install_lefthook.sh: LEFTHOOK_VERSION is not set" >&2
    exit 2
fi

bindir="${1:-$HOME/.local/bin}"

# The release names the machine the way `uname -m` does on the platforms this
# runs on, with one exception, and an unknown machine is an error rather than a
# guess at an asset name that would 404 halfway through.
machine="$(uname -m)"
case "$machine" in
    x86_64 | aarch64) ;;
    arm64) machine=aarch64 ;;
    *)
        echo "install_lefthook.sh: no published lefthook build for $machine" >&2
        exit 2
        ;;
esac

asset="lefthook_${version}_Linux_${machine}.gz"
base="https://github.com/evilmartians/lefthook/releases/download/v${version}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

curl --fail --silent --show-error --location \
    --output "$workdir/$asset" "$base/$asset"
curl --fail --silent --show-error --location \
    --output "$workdir/lefthook_checksums.txt" "$base/lefthook_checksums.txt"

# The checksum file covers every platform's asset; only the line for the one
# that was downloaded is checked, because `sha256sum -c` on the whole file
# fails on the assets that were never fetched.
(
    cd "$workdir"
    grep " ${asset}\$" lefthook_checksums.txt | sha256sum --check --strict -
)

gunzip "$workdir/$asset"
mkdir -p "$bindir"
install -m 0755 "$workdir/${asset%.gz}" "$bindir/lefthook"

if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$bindir" >>"$GITHUB_PATH"
else
    echo "lefthook $version installed in $bindir"
fi

"$bindir/lefthook" version
