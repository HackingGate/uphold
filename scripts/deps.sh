#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# deps.sh — per-repo host/build-toolchain entrypoint.
#
# Reads this repo's ./toolchain.toml and either verifies (check) or installs
# (install) the NON-language host toolchain it declares: system packages with
# version pins, cross-distro package-name mapping, and non-package setup steps.
# Language deps (cargo/pip/npm) and inter-repo SHAs are out of scope.
#
# Three record kinds, split by WHO PROVIDES the thing:
#   [[tool]]    a language/container toolchain with its own install path —
#               rustup, zig, docker. CI provides these via setup actions
#               (dtolnay/rust-toolchain, mlugg/setup-zig), a dev box via the
#               distro package or a [[setup]] step.
#   [[system]]  what comes from the system package manager EVERYWHERE, CI
#               included: native link deps (libnm, libnl-route-3, libpam), the
#               helpers that resolve them (pkg-config), and host binaries the
#               lint hooks shell out to (ripgrep). Probed with
#               `pkg-config --exists <name>` unless the row overrides `check`.
#   [[setup]]   a non-package step (rustup default toolchain, builder image).
#
# This worker is generic and BYTE-IDENTICAL across every repo that carries it;
# only the adjacent toolchain.toml differs. A workspace-level `scripts/deps.sh`
# driver merely calls this — it centralizes nothing.
#
#   scripts/deps.sh check      verify the host satisfies toolchain.toml (default,
#                              read-only; exits non-zero with actionable hints on
#                              the first unmet requirement).
#   scripts/deps.sh install    install missing packages + run setup steps
#                              (idempotent).
#   scripts/deps.sh packages   print the [[system]] package names for a distro,
#                              space-separated, on stdout. This is what CI
#                              installs, so toolchain.toml stays the ONE place a
#                              native link dep is declared.
#   scripts/deps.sh tool-pin N print the `pin` of [[tool]] N — the exact version
#                              CI installs via a setup action. Prints nothing and
#                              exits 1 when the tool is not declared, which is
#                              how CI asks "does this repo need zig at all?".
#
# Requires: bash, python3 >= 3.11 (tomllib), coreutils. On Arch it drives pacman,
# on Debian apt-get; both via sudo when not already root.
# ─────────────────────────────────────────────────────────────────────────────

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
manifest="$repo_root/toolchain.toml"

die() {
    printf 'deps: error: %s\n' "$*" >&2
    exit 1
}
log() { printf '==> %s\n' "$*" >&2; }

usage() {
    cat <<'USAGE'
Usage: scripts/deps.sh [check|install|packages|tool-pin NAME] [--distro arch|debian]

Verify or install this repo's host/build-toolchain, declared in ./toolchain.toml.

  check      (default) read-only preflight; exits non-zero with install hints
             on the first unmet requirement.
  install    install missing packages and run declared setup steps (idempotent).
  packages   print this repo's [[system]] package names (native link deps and
             the build helpers that resolve them) for the target distro,
             space-separated on stdout. CI installs exactly this list, so a
             native dep is declared once, in toolchain.toml.
  tool-pin N print the `pin` of [[tool]] N (the exact version CI installs).
             Exits 1 if the tool is not declared by this repo.

  --distro D report/install for distro D instead of the detected one; only
             meaningful for `packages`.
  -h, --help show this help.
USAGE
}

action="check"
distro_override=""
tool_arg=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        check | install | packages) action="$1" ;;
        tool-pin)
            action="tool-pin"
            [ "$#" -ge 2 ] || die "tool-pin needs a tool name"
            tool_arg="$2"
            shift
            ;;
        --distro)
            [ "$#" -ge 2 ] || die "--distro needs a value (arch|debian)"
            distro_override="$2"
            shift
            ;;
        --distro=*) distro_override="${1#--distro=}" ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1 (want check|install|packages|tool-pin)" ;;
    esac
    shift
done

[ -f "$manifest" ] || die "no toolchain.toml at repo root ($manifest)"
command -v python3 >/dev/null 2>&1 || die "python3 is required to parse toolchain.toml"

# ── host / distro detection ──────────────────────────────────────────────────
detect_distro() {
    local id="" like=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"
        like="${ID_LIKE:-}"
    fi
    case " $id $like " in
        *" arch "*) echo arch ;;
        *" debian "* | *" ubuntu "*) echo debian ;;
        *)
            # last-resort probe by package manager
            if command -v pacman >/dev/null 2>&1; then
                echo arch
            elif command -v apt-get >/dev/null 2>&1; then
                echo debian
            else
                echo unknown
            fi
            ;;
    esac
}
distro="${distro_override:-$(detect_distro)}"

sudo_cmd=()
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && sudo_cmd=(sudo)
fi

# ── manifest extraction (python does TOML parsing only) ──────────────────────
# Emits, one record per line, with command/text fields base64-encoded so
# newlines survive: fields are joined with US (\x1f), a non-whitespace
# separator so EMPTY fields are preserved (a TAB IFS would collapse them). An `optional`
# item is reported when unsatisfied but does NOT fail `check` (e.g. the release
# docker builder, unneeded for a plain dev build).
#   TOOL\t<name>\t<b64 check>\t<b64 version>\t<b64 want>\t<b64 packages>\t<b64 hint>\t<opt>\t<b64 pin>
#   SYS\t<name>\t<b64 check>\t<b64 packages>\t<b64 hint>\t<opt>
#   SETUP\t<name>\t<b64 check>\t<b64 run>\t<opt>
_extract() {
    python3 - "$manifest" "$distro" <<'PY'
import base64, sys, tomllib

path, distro = sys.argv[1], sys.argv[2]
with open(path, "rb") as fh:
    data = tomllib.load(fh)

def b(s):
    return base64.b64encode((s or "").encode()).decode()

def opt(item):
    return "1" if item.get("optional", False) else "0"

def pkgs(tool):
    p = tool.get("packages", {})
    v = p.get(distro, "") if isinstance(p, dict) else ""
    if isinstance(v, list):
        v = " ".join(v)
    return v

rows = []
for t in data.get("tool", []):
    rows.append("\x1f".join([
        "TOOL", t.get("name", "?"),
        b(t.get("check", "")), b(t.get("version", "")),
        b(t.get("want", "")), b(pkgs(t)), b(t.get("hint", "")), opt(t),
        b(t.get("pin", "")),
    ]))
for s in data.get("system", []):
    name = s.get("name", "?")
    # A [[system]] row names a pkg-config module unless it says otherwise, so
    # the probe writes itself for the common case.
    rows.append("\x1f".join([
        "SYS", name,
        b(s.get("check", "") or f"pkg-config --exists {name}"),
        b(pkgs(s)), b(s.get("hint", "")), opt(s),
    ]))
for s in data.get("setup", []):
    rows.append("\x1f".join([
        "SETUP", s.get("name", "?"),
        b(s.get("check", "")), b(s.get("run", "")), opt(s),
    ]))
sys.stdout.write("\n".join(rows))
if rows:
    sys.stdout.write("\n")
PY
}

_d() { base64 -d <<<"$1"; }

# ── version-constraint helpers ───────────────────────────────────────────────
_ver_extract() { grep -oE '[0-9]+(\.[0-9]+)*' <<<"$1" | head -1; }

# _ver_cmp A B -> prints -1 (A<B) / 0 (A==B) / 1 (A>B) via sort -V.
_ver_cmp() {
    local a="$1" b="$2" first
    [ "$a" = "$b" ] && {
        echo 0
        return
    }
    first="$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)"
    [ "$first" = "$a" ] && echo -1 || echo 1
}

# _prefix_eq INSTALLED WANT -> INSTALLED == WANT or INSTALLED starts with WANT.
_prefix_eq() {
    local inst="$1" want="$2"
    [ "$inst" = "$want" ] || [ "${inst#"$want".}" != "$inst" ]
}

# _one_constraint INSTALLED CONSTRAINT -> exit 0 if satisfied.
_one_constraint() {
    local inst="$1" c="$2" lo hi num
    c="${c#"${c%%[![:space:]]*}"}" # ltrim
    c="${c%"${c##*[![:space:]]}"}" # rtrim
    if [[ "$c" == *" - "* ]]; then
        lo="${c%% - *}"
        hi="${c##* - }"
        [ "$(_ver_cmp "$inst" "$lo")" != "-1" ] && [ "$(_ver_cmp "$inst" "$hi")" != 1 ]
        return
    fi
    case "$c" in
        ">="*) num="${c#>=}" && [ "$(_ver_cmp "$inst" "${num## }")" != "-1" ] ;;
        "<="*) num="${c#<=}" && [ "$(_ver_cmp "$inst" "${num## }")" != 1 ] ;;
        ">"*) num="${c#>}" && [ "$(_ver_cmp "$inst" "${num## }")" = 1 ] ;;
        "<"*) num="${c#<}" && [ "$(_ver_cmp "$inst" "${num## }")" = "-1" ] ;;
        "!="*) num="${c#!=}" && [ "$(_ver_cmp "$inst" "${num## }")" != 0 ] ;;
        "=="*) num="${c#==}" && _prefix_eq "$inst" "${num## }" ;;
        "="*) num="${c#=}" && _prefix_eq "$inst" "${num## }" ;;
        *) _prefix_eq "$inst" "$c" ;;
    esac
}

# _want_ok INSTALLED "c1, c2, ..." -> all comma-separated constraints hold.
_want_ok() {
    local inst="$1" want="$2" c
    local IFS=,
    for c in $want; do
        _one_constraint "$inst" "$c" || return 1
    done
    return 0
}

# ── package install ──────────────────────────────────────────────────────────
install_packages() {
    local pkgs="$1"
    [ -n "$pkgs" ] || return 0
    case "$distro" in
        arch)
            log "pacman -S --needed $pkgs"
            # shellcheck disable=SC2086
            "${sudo_cmd[@]}" pacman -S --needed --noconfirm $pkgs
            ;;
        debian)
            log "apt-get install -y $pkgs"
            # shellcheck disable=SC2086
            "${sudo_cmd[@]}" apt-get install -y $pkgs
            ;;
        *) die "unsupported distro for automatic install; install manually: $pkgs" ;;
    esac
}

# ── check / install drivers ──────────────────────────────────────────────────
missing=0
optmiss=0
records="$(_extract)"

run_check() {
    # $1 = decoded check command; empty => treated as "present" (setup-only tool)
    [ -n "$1" ] || return 0
    bash -c "$1" >/dev/null 2>&1
}

# mark_unmet OPTIONAL — record a miss, honoring optional (report but don't fail).
mark_unmet() {
    if [ "$1" = 1 ]; then
        optmiss=1
    else
        missing=1
    fi
}
# glyph OPTIONAL -> ✗ (hard) or ⚠ (optional)
glyph() { [ "$1" = 1 ] && printf '⚠' || printf '✗'; }

do_check() {
    local kind name f2 f3 f4 f5 f6 f7 f8
    while IFS=$'\037' read -r kind name f2 f3 f4 f5 f6 f7 f8; do
        [ -n "$kind" ] || continue
        case "$kind" in
            TOOL)
                local check version want pkgs hint opt pin
                check="$(_d "$f2")"
                version="$(_d "$f3")"
                want="$(_d "$f4")"
                pkgs="$(_d "$f5")"
                hint="$(_d "$f6")"
                opt="$f7"
                pin="$(_d "$f8")"
                # The CI pin and the accepted range are two statements of the
                # same requirement; if they disagree the manifest is lying to
                # one of its readers. Checked before the host is even probed,
                # because it is wrong on every host.
                if [ -n "$pin" ] && [ -n "$want" ] && ! _want_ok "$pin" "$want"; then
                    missing=1
                    printf '  ✗ %s — CI pin %s does NOT satisfy want %s (fix toolchain.toml)\n' \
                        "$name" "$pin" "$want" >&2
                fi
                if ! run_check "$check"; then
                    mark_unmet "$opt"
                    printf '  %s %s — not found%s\n' "$(glyph "$opt")" "$name" \
                        "$([ "$opt" = 1 ] && echo ' (optional)')" >&2
                    [ -n "$pkgs" ] && printf '      install: %s (%s)\n' "$pkgs" "$distro" >&2
                    [ -n "$hint" ] && printf '      hint: %s\n' "$hint" >&2
                    continue
                fi
                if [ -n "$want" ] && [ -n "$version" ]; then
                    local out inst
                    out="$(bash -c "$version" 2>/dev/null || true)"
                    inst="$(_ver_extract "$out")"
                    if [ -z "$inst" ]; then
                        printf '  ? %s — present, version unreadable (want %s)\n' "$name" "$want" >&2
                    elif _want_ok "$inst" "$want"; then
                        printf '  ✓ %s %s (want %s)\n' "$name" "$inst" "$want" >&2
                    else
                        mark_unmet "$opt"
                        printf '  %s %s %s — does NOT satisfy %s\n' "$(glyph "$opt")" "$name" "$inst" "$want" >&2
                        [ -n "$hint" ] && printf '      hint: %s\n' "$hint" >&2
                    fi
                else
                    printf '  ✓ %s\n' "$name" >&2
                fi
                ;;
            SYS)
                local scheck spkgs shint sopt
                scheck="$(_d "$f2")"
                spkgs="$(_d "$f3")"
                shint="$(_d "$f4")"
                sopt="$f5"
                if run_check "$scheck"; then
                    printf '  ✓ %s\n' "$name" >&2
                else
                    mark_unmet "$sopt"
                    printf '  %s %s — native dep not found%s\n' "$(glyph "$sopt")" "$name" \
                        "$([ "$sopt" = 1 ] && echo ' (optional)')" >&2
                    [ -n "$spkgs" ] && printf '      install: %s (%s)\n' "$spkgs" "$distro" >&2
                    [ -n "$shint" ] && printf '      hint: %s\n' "$shint" >&2
                fi
                ;;
            SETUP)
                local scheck opt
                scheck="$(_d "$f2")"
                opt="$f4"
                if [ -n "$scheck" ]; then
                    if bash -c "$scheck" >/dev/null 2>&1; then
                        printf '  ✓ setup: %s\n' "$name" >&2
                    else
                        mark_unmet "$opt"
                        printf '  %s setup: %s — not satisfied (run: scripts/deps.sh install)%s\n' \
                            "$(glyph "$opt")" "$name" "$([ "$opt" = 1 ] && echo ' (optional)')" >&2
                    fi
                else
                    printf '  · setup: %s (no check; run install to apply)\n' "$name" >&2
                fi
                ;;
        esac
    done <<<"$records"

    [ "$optmiss" -ne 0 ] && log "note: optional items unsatisfied (needed only for release/cross-build)"
    if [ "$missing" -ne 0 ]; then
        log "toolchain check FAILED — run: scripts/deps.sh install"
        exit 1
    fi
    log "toolchain OK ($distro)"
}

do_install() {
    local kind name f2 f3 f4 f5 f6 f7 f8
    # First pass: collect missing packages, split required vs optional. Optional
    # packages may not exist in every distro's repos (e.g. nfpm is AUR-only on
    # Arch), so their install is best-effort and never fails the run.
    local want_pkgs="" opt_pkgs=""
    while IFS=$'\037' read -r kind name f2 f3 f4 f5 f6 f7 f8; do
        local check version want pkgs opt
        case "$kind" in
            TOOL)
                check="$(_d "$f2")"
                version="$(_d "$f3")"
                want="$(_d "$f4")"
                pkgs="$(_d "$f5")"
                opt="$f7"
                ;;
            SYS)
                check="$(_d "$f2")"
                version=""
                want=""
                pkgs="$(_d "$f3")"
                opt="$f5"
                ;;
            *) continue ;;
        esac
        [ -n "$pkgs" ] || continue
        # (re)install if missing OR version unsatisfied
        local need=0
        run_check "$check" || need=1
        if [ "$need" -eq 0 ] && [ -n "$want" ] && [ -n "$version" ]; then
            local inst
            inst="$(_ver_extract "$(bash -c "$version" 2>/dev/null || true)")"
            [ -n "$inst" ] && ! _want_ok "$inst" "$want" && need=1
        fi
        [ "$need" -eq 1 ] || continue
        if [ "$opt" = 1 ]; then
            opt_pkgs="$opt_pkgs $pkgs"
        else
            want_pkgs="$want_pkgs $pkgs"
        fi
    done <<<"$records"

    if [ -n "${want_pkgs// /}" ]; then
        install_packages "$want_pkgs"
    else
        log "all required packages already satisfied"
    fi
    if [ -n "${opt_pkgs// /}" ]; then
        log "optional packages:${opt_pkgs} (best-effort)"
        install_packages "$opt_pkgs" || log "warning: optional package install failed (install manually if needed)"
    fi

    # Second pass: run setup steps whose check fails (or that have none), in order.
    while IFS=$'\037' read -r kind name f2 f3 f4 f5 f6 f7 f8; do
        [ "$kind" = SETUP ] || continue
        local scheck srun opt
        scheck="$(_d "$f2")"
        srun="$(_d "$f3")"
        opt="$f4"
        if [ -n "$scheck" ] && bash -c "$scheck" >/dev/null 2>&1; then
            printf '  ✓ setup: %s (already satisfied)\n' "$name" >&2
            continue
        fi
        [ -n "$srun" ] || {
            printf '  · setup: %s (no run step)\n' "$name" >&2
            continue
        }
        log "setup: $name"
        if ! bash -c "$srun"; then
            if [ "$opt" = 1 ]; then
                log "warning: optional setup step failed: $name (skipping)"
            else
                die "setup step failed: $name"
            fi
        fi
    done <<<"$records"

    log "install complete — re-run 'scripts/deps.sh check' to verify"
}

# do_packages — print the [[system]] package names for $distro on stdout, one
# space-separated line, deduplicated and in manifest order. Nothing else goes to
# stdout (diagnostics use stderr), so a caller can splice it straight into an
# install command. A repo with no native deps prints an empty line and exits 0 —
# "nothing to install" is a valid answer, not an error.
do_packages() {
    local kind name f2 f3 f4 f5 f6 f7 f8 out="" pkgs p
    while IFS=$'\037' read -r kind name f2 f3 f4 f5 f6 f7 f8; do
        [ "$kind" = SYS ] || continue
        pkgs="$(_d "$f3")"
        for p in $pkgs; do
            case " $out " in
                *" $p "*) ;;
                *) out="$out $p" ;;
            esac
        done
    done <<<"$records"
    printf '%s\n' "${out# }"
}

# do_tool_pin NAME — print [[tool]] NAME's `pin` on stdout. Exit 1 when the repo
# does not declare the tool at all, so `if scripts/deps.sh tool-pin zig` reads as
# "does this repo need zig?". A declared tool with no pin prints an empty line
# and exits 0 — declared but unpinned is a different answer from undeclared.
do_tool_pin() {
    local kind name f2 f3 f4 f5 f6 f7 f8
    while IFS=$'\037' read -r kind name f2 f3 f4 f5 f6 f7 f8; do
        [ "$kind" = TOOL ] || continue
        [ "$name" = "$tool_arg" ] || continue
        printf '%s\n' "$(_d "$f8")"
        return 0
    done <<<"$records"
    return 1
}

[ "$distro" = unknown ] && log "warning: unrecognized distro; package install unavailable (check still works)"

case "$action" in
    check) do_check ;;
    install) do_install ;;
    packages) do_packages ;;
    tool-pin) do_tool_pin ;;
esac
