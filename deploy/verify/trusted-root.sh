#!/bin/sh
# Fetch the Sigstore public-good trusted root for the usg-plat-verify package
# and check it against the digest pinned in deploy/verify/trusted_root.sha256.
#
#   trusted-root.sh [--out FILE]      fetch, refuse unless the digest is the pin
#   trusted-root.sh --update [--out FILE]
#                                     fetch and rewrite the pin (make
#                                     trusted-root-update; the change is
#                                     reviewed in a PR)
#   trusted-root.sh --self-test       stub-cosign tests (make test-verify)
#
# The root comes from `cosign initialize` (TUF, starting from the root embedded
# in cosign) run with an empty HOME and TUF_ROOT, then copied out of the TUF
# cache. `cosign trusted-root create` is not used: it does not fetch.
# COSIGN selects the cosign binary (default: cosign on PATH, >= 3.0.3).
#
# Exit: 0 ok, 1 digest mismatch or bad root, 2 usage or tool error.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SI-7(15) (Code Authentication) - the trust anchors the
#   install-time gate verifies release signatures against are pinned
# - NIST 800-53: CM-14 (Signed Components), SR-11 (Component Authenticity)
# - NIST 800-53: CM-3 (Configuration Change Control) - a new root changes the
#   pin, which only lands through a reviewed PR
set -eu

here=$(cd "$(dirname "$0")" && pwd)
PIN=${TRUSTED_ROOT_PIN:-$here/trusted_root.sha256}
COSIGN=${COSIGN:-cosign}
MEDIA_TYPE='application/vnd.dev.sigstore.trustedroot+json;version=0.1'

die() { echo "trusted-root: $*" >&2; exit 2; }
refuse() { echo "trusted-root: REFUSED: $*" >&2; exit 1; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | cut -d' ' -f1
    else
        shasum -a 256 -- "$1" | cut -d' ' -f1
    fi
}

# Print the CA, tlog and ctlog entries so the PR diff can be reviewed.
summary() {
    command -v python3 >/dev/null 2>&1 || { echo "trusted-root: (python3 missing, no summary)" >&2; return 0; }
    python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
for key in ("certificateAuthorities", "tlogs", "ctlogs"):
    for e in d.get(key, []):
        if not isinstance(e, dict):
            continue
        name = e.get("uri") or e.get("baseUrl") or "?"
        v = e.get("validFor", {}) or e.get("publicKey", {}).get("validFor", {})
        print("  %-22s %s  %s .. %s" % (key, name, v.get("start", "?"), v.get("end", "open")))
' "$1" >&2 || echo "trusted-root: (summary failed)" >&2
}

fetch() { # fetch OUT
    out=$1
    tmp=$(mktemp -d)
    # Only ever remove the directory mktemp created.
    trap 'rm -rf -- "$tmp"' EXIT INT TERM
    mkdir -p "$tmp/home"
    if ! HOME="$tmp/home" TUF_ROOT="$tmp/home/.sigstore/root" "$COSIGN" initialize >"$tmp/init.log" 2>&1; then
        cat "$tmp/init.log" >&2
        die "cosign initialize failed ($COSIGN)"
    fi
    src="$tmp/home/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json"
    [ -f "$src" ] && [ ! -L "$src" ] || die "cosign initialize did not write $src"
    grep -qF "\"mediaType\": \"$MEDIA_TYPE\"" "$src" ||
        grep -qF "\"mediaType\":\"$MEDIA_TYPE\"" "$src" ||
        refuse "unexpected mediaType (want $MEDIA_TYPE)"
    mkdir -p "$(dirname "$out")"
    cp -- "$src" "$out.tmp"
    chmod 0644 "$out.tmp"
    mv -f -- "$out.tmp" "$out"
    rm -rf -- "$tmp"
    trap - EXIT INT TERM
}

run() { # run UPDATE OUT
    update=$1
    out=$2
    fetch "$out"
    got=$(sha256_of "$out")
    echo "trusted-root: fetched $out sha256 $got" >&2
    summary "$out"
    if [ "$update" = 1 ]; then
        printf '%s  trusted_root.json\n' "$got" >"$PIN.tmp"
        mv -f -- "$PIN.tmp" "$PIN"
        echo "trusted-root: pin updated ($PIN); review the summary above in the PR" >&2
        return 0
    fi
    [ -f "$PIN" ] || die "no pin file $PIN (run make trusted-root-update)"
    want=$(sed -n 's/^\([0-9a-f]\{64\}\)  trusted_root\.json$/\1/p' "$PIN")
    [ -n "$want" ] || die "malformed pin file $PIN"
    if [ "$got" != "$want" ]; then
        rm -f -- "$out"
        refuse "digest $got != pinned $want; a Sigstore root rotation needs make trusted-root-update and a reviewed PR"
    fi
    echo "trusted-root: OK, matches pin" >&2
}

self_test() {
    t=$(mktemp -d)
    trap 'rm -rf -- "$t"' EXIT INT TERM
    fail=0
    # Stub cosign: writes a fixture root into the TUF cache it is pointed at,
    # and records the HOME it saw (must be the empty one, never the caller's).
    cat >"$t/cosign" <<'EOF'
#!/bin/sh
[ "$1" = initialize ] || exit 9
[ "$TUF_ROOT" = "$HOME/.sigstore/root" ] || exit 8
[ -z "$(ls -A "$HOME")" ] || exit 7
d="$TUF_ROOT/tuf-repo-cdn.sigstore.dev/targets"
mkdir -p "$d"
cp "$FIXTURE" "$d/trusted_root.json"
EOF
    chmod 0755 "$t/cosign"
    printf '{\n  "mediaType": "%s",\n  "tlogs": []\n}\n' "$MEDIA_TYPE" >"$t/good.json"
    printf '{\n  "mediaType": "%s",\n  "tlogs": [{"baseUrl": "https://x.invalid"}]\n}\n' "$MEDIA_TYPE" >"$t/other.json"
    printf '{\n  "mediaType": "application/json",\n  "tlogs": []\n}\n' >"$t/badtype.json"
    printf '%s  trusted_root.json\n' "$(sha256_of "$t/good.json")" >"$t/pin"

    check() { # check NAME WANT_RC FIXTURE ARGS...
        name=$1 want=$2 fx=$3
        shift 3
        rc=0
        FIXTURE="$t/$fx" COSIGN="$t/cosign" TRUSTED_ROOT_PIN="$t/pin" \
            sh "$here/trusted-root.sh" "$@" >"$t/log" 2>&1 || rc=$?
        if [ "$rc" = "$want" ]; then
            echo "ok   $name"
        else
            echo "FAIL $name (rc $rc, want $want)"
            cat "$t/log"
            fail=1
        fi
    }
    check "matching digest accepted" 0 good.json --out "$t/out/a.json"
    [ -f "$t/out/a.json" ] || { echo "FAIL accepted root not written"; fail=1; }
    check "mismatching digest refused" 1 other.json --out "$t/out/b.json"
    [ ! -e "$t/out/b.json" ] || { echo "FAIL refused root left behind"; fail=1; }
    check "wrong mediaType refused" 1 badtype.json --out "$t/out/c.json"
    check "missing cosign is an error" 2 good.json --out "$t/out/d.json" --cosign "$t/nonexistent"
    cp "$t/pin" "$t/pin.orig"
    check "update rewrites the pin" 0 other.json --update --out "$t/out/e.json"
    if [ "$(sed 's/ .*//' "$t/pin")" != "$(sha256_of "$t/other.json")" ]; then
        echo "FAIL pin not rewritten"
        fail=1
    fi
    cp "$t/pin.orig" "$t/pin"
    printf 'garbage\n' >"$t/pin"
    check "malformed pin is an error" 2 good.json --out "$t/out/f.json"
    # The committed pin must be well formed.
    if ! grep -qx '[0-9a-f]\{64\}  trusted_root\.json' "$here/trusted_root.sha256"; then
        echo "FAIL committed pin $here/trusted_root.sha256 malformed"
        fail=1
    else
        echo "ok   committed pin well formed"
    fi
    rm -rf -- "$t"
    trap - EXIT INT TERM
    return "$fail"
}

update=0
out=
while [ $# -gt 0 ]; do
    case $1 in
        --update) update=1 ;;
        --out) [ $# -ge 2 ] || die "--out needs a file"; out=$2; shift ;;
        --cosign) [ $# -ge 2 ] || die "--cosign needs a path"; COSIGN=$2; shift ;;
        --self-test) self_test; exit $? ;;
        -h | --help) sed -n '2,17p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done
command -v "$COSIGN" >/dev/null 2>&1 || die "cosign not found ($COSIGN); set COSIGN="
[ -n "$out" ] || out="$here/../../target/verify/trusted_root.json"
run "$update" "$out"
