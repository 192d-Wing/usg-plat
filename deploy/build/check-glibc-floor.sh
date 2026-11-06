#!/bin/sh
# Fail when a shipped binary or package needs a newer glibc than the
# supported floor: EL9 (2.34) for ELF symbol versions and rpm Requires,
# Debian 12 (2.36) for the .deb `Depends: libc6 (>= X)`.
#
# Usage: check-glibc-floor.sh [--deb FILE.deb] [--rpm FILE.rpm] [ELF ...]
# A .deb or .rpm is also unpacked and every ELF file inside is checked.
# Exit: 0 within the floor; 1 over the floor (or nothing checked); 2 usage
# or missing tool.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 (Baseline Configuration), SA-15 (Development Process,
#   Standards, and Tools) - the build baseline (EL9 container) is verified on
#   its output, so a runner change cannot raise the install floor silently
set -eu

ELF_MAX=2.34
DEB_LIBC6_MAX=2.36

die() { echo "check-glibc-floor: $1" >&2; exit "${2:-1}"; }
for t in readelf sort; do command -v "$t" >/dev/null 2>&1 || die "missing tool: $t" 2; done

# le A B: version A <= B (sort -V).
le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$2" ]; }

fail=0
checked=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

check_elf() {
    f=$1
    # Version needs (.gnu.version_r) name every GLIBC_x.y the loader must provide.
    vers=$(readelf -W -V "$f" 2>/dev/null | sed -n 's/.*Name: GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -uV)
    max=$(printf '%s\n' "$vers" | tail -n1)
    checked=$((checked + 1))
    # The .deb Depends is explicit (libc6, libgcc-s1): any other NEEDED
    # library would be an undeclared dependency.
    extra=$(readelf -W -d "$f" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' |
        grep -vxE 'libc\.so\.6|libm\.so\.6|libgcc_s\.so\.1|ld-linux-(aarch64|x86-64)\.so\.[0-9]+' | tr '\n' ' ' || true)
    if [ -n "$extra" ]; then
        echo "FAIL $f: NEEDED library outside the declared set: $extra"
        fail=1
    fi
    if [ -z "$max" ]; then
        echo "ok   $f: no GLIBC_ version needs"
    elif le "$max" "$ELF_MAX"; then
        echo "ok   $f: max GLIBC_$max (<= $ELF_MAX)"
    else
        over=$(printf '%s\n' "$vers" | while read -r v; do le "$v" "$ELF_MAX" || printf '%s ' "$v"; done)
        echo "FAIL $f: needs GLIBC_$max (> $ELF_MAX): $over"
        fail=1
    fi
}

check_tree() {
    find "$1" -type f > "$work/files"
    while IFS= read -r f; do
        if [ "$(head -c 4 "$f" | od -An -c | tr -d ' \n')" = "177ELF" ]; then check_elf "$f"; fi
    done < "$work/files"
}

while [ $# -gt 0 ]; do
    case "$1" in
    --deb)
        [ $# -ge 2 ] || die "--deb needs a file" 2
        command -v dpkg-deb >/dev/null 2>&1 || die "missing tool: dpkg-deb" 2
        dep=$(dpkg-deb -f "$2" Depends)
        floor=$(printf '%s\n' "$dep" | tr ',' '\n' | sed -n 's/^ *libc6 *(>= *\([0-9][0-9.]*\)[^)]*).*/\1/p' | head -n1)
        checked=$((checked + 1))
        if [ -z "$floor" ]; then
            echo "FAIL $2: Depends has no versioned libc6 ($dep)"; fail=1
        elif le "$floor" "$DEB_LIBC6_MAX"; then
            echo "ok   $2: Depends libc6 (>= $floor) (<= $DEB_LIBC6_MAX)"
        else
            echo "FAIL $2: Depends libc6 (>= $floor) (> $DEB_LIBC6_MAX)"; fail=1
        fi
        d="$work/deb$checked"; mkdir -p "$d"; dpkg-deb -x "$2" "$d"; check_tree "$d"
        shift 2 ;;
    --rpm)
        [ $# -ge 2 ] || die "--rpm needs a file" 2
        for t in rpm rpm2cpio cpio; do command -v "$t" >/dev/null 2>&1 || die "missing tool: $t" 2; done
        max=$(rpm -qp --requires "$2" 2>/dev/null | sed -n 's/.*(GLIBC_\([0-9][0-9.]*\)).*/\1/p' | sort -uV | tail -n1)
        checked=$((checked + 1))
        if [ -n "$max" ] && ! le "$max" "$ELF_MAX"; then
            echo "FAIL $2: Requires GLIBC_$max (> $ELF_MAX)"; fail=1
        else
            echo "ok   $2: Requires max GLIBC_${max:-none} (<= $ELF_MAX)"
        fi
        d="$work/rpm$checked"; mkdir -p "$d"
        rpm2cpio "$2" > "$work/p.cpio"; (cd "$d" && cpio -id --quiet < "$work/p.cpio")
        check_tree "$d"
        shift 2 ;;
    -*) die "unknown option $1" 2 ;;
    *) check_elf "$1"; shift ;;
    esac
done

[ "$checked" -gt 0 ] || die "nothing checked" 1
exit "$fail"
