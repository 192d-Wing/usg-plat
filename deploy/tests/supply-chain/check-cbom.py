#!/usr/bin/env python3
"""CBOM drift checks T3-T5 for usg-plat (run with `python3 -I`).

  --graph      T3: every activated crate in the dependency graph (Linux
               x86_64/aarch64 and bpfel-unknown-none) whose crates.io
               category is cryptography* or that carries a crypto keyword is
               listed in crypto-allow.toml, and only the listed direct
               dependents pull it in. test-only crates must not be reachable
               from the shipped binaries over normal/build edges.
  --sources    T4: every Rust source file (outside tests/, benches/,
               examples/) that calls a crypto API carries `// CBOM: <bom-ref>`
               naming an existing component; every CBOM evidence occurrence
               points at a real file carrying a marker for that bom-ref;
               `rustls::crypto` / `aws_lc_rs` outside crates/plat-tls fails.
  --structure  T5: CycloneDX 1.6, unique bom-refs, every reference resolves,
               every algorithm is provided by exactly one library, library
               versions equal Cargo.lock, and JSON-schema validation against
               the vendored schema (check-jsonschema; required when CI=true).
  --all        all three.
  --self-test  fixtures proving each check bites.

Standard library only, no network (`cargo metadata --offline --locked`).
T1 (policy facts) is crates/plat-tls/tests/cbom.rs.

COMPLIANCE MAPPING:
- NIST 800-53: CM-8 (System Component Inventory), SR-3 (Supply Chain
  Controls), SA-11 (Developer Testing), SC-13 (Cryptographic Protection)
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CBOM = ROOT / "docs/compliance/cbom.cdx.json"
ALLOW = ROOT / "deploy/tests/supply-chain/crypto-allow.toml"
SCHEMA = ROOT / "deploy/tests/supply-chain/schema/bom-1.6.schema.json"
PLATFORMS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "bpfel-unknown-none")
SHIPPED = ("platd", "plat-xdp-loader")
CLASSES = {"provider", "primitive", "protocol", "parsing", "non-crypto", "test-only"}
KEYWORDS = {"crypto", "cryptography", "tls", "ssl", "hash", "sha2", "digest", "aes", "ecdsa", "rsa", "kem", "pqc",
            "signature", "x509", "hmac"}
API = re.compile(r"\b(sha2|aws_lc_rs|ring|openssl)::|\brustls::crypto\b|\buse\s+(sha2|aws_lc_rs|ring|openssl)\b")
TLS_ONLY = re.compile(r"\brustls::crypto\b|\baws_lc_rs\b")
MARKER = re.compile(r"//[!/]?\s*CBOM:\s*(\S+)")
SKIP_DIRS = {"tests", "benches", "examples", "target"}
KINDS = ("normal", "build", "dev")


# ---------------------------------------------------------------- T3 graph

def _dep_active(decls, features, fdefs, name):
    """Optional dependency `name` is active if an enabled feature enables it."""
    if not decls or not all(d.get("optional") for d in decls):
        return True
    keys = {name} | {d.get("rename") for d in decls if d.get("rename")}
    for f in features:
        if f in keys:
            return True
        for item in fdefs.get(f, []):
            if item.startswith("dep:") and item[4:] in keys:
                return True
            head = item.split("/", 1)[0]
            if head in keys and "?" not in item:
                return True
    return False


def active_edges(meta):
    """[(parent_name, child_id, kind)] over activated edges (cargo metadata
    lists weak `dep?/feat` targets as resolved even when not built)."""
    pk = {p["id"]: p for p in meta["packages"]}
    out = []
    for node in meta["resolve"]["nodes"]:
        parent = pk[node["id"]]
        feats = set(node.get("features", []))
        for d in node["deps"]:
            child = pk[d["pkg"]]
            decls = [x for x in parent["dependencies"]
                     if x["name"] == child["name"] or x.get("rename") == d["name"]]
            if not _dep_active(decls, feats, parent.get("features", {}), decls[0]["name"] if decls else child["name"]):
                continue
            for k in d["dep_kinds"]:
                out.append((parent["name"], d["pkg"], k["kind"] or "normal"))
    return out


def flagged(pkg):
    cats = [c for c in pkg.get("categories", []) if c.startswith("cryptography")]
    kws = [k for k in pkg.get("keywords", []) if k.lower() in KEYWORDS]
    return cats + kws


def check_graph(metas, allow):
    """metas: {platform: cargo metadata}. Returns error strings."""
    errs = []
    crates = allow.get("crate", {})
    for name, e in crates.items():
        if e.get("class") not in CLASSES:
            errs.append(f"crypto-allow.toml: {name} has class {e.get('class')!r}")
        if not e.get("rationale"):
            errs.append(f"crypto-allow.toml: {name} has no rationale")
    for plat, meta in metas.items():
        pk = {p["id"]: p for p in meta["packages"]}
        edges = active_edges(meta)
        reach = {}
        for parent, child, kind in edges:
            reach.setdefault(parent, set()).add((child, kind))
        # Shipped closure over normal/build edges.
        ids_by_name = {}
        for p in meta["packages"]:
            ids_by_name.setdefault(p["name"], []).append(p["id"])
        shipped, todo = set(), [i for n in SHIPPED for i in ids_by_name.get(n, [])]
        while todo:
            i = todo.pop()
            if i in shipped:
                continue
            shipped.add(i)
            todo.extend(c for c, k in reach.get(pk[i]["name"], ()) if k in ("normal", "build"))
        active = {c for _, c, _ in edges} | {n["id"] for n in meta["resolve"]["nodes"] if pk[n["id"]]["source"] is None}
        for parent, child, kind in edges:
            p = pk[child]
            if p["source"] is None:
                continue
            hits = flagged(p)
            entry = crates.get(p["name"])
            if hits and entry is None:
                errs.append(f"[{plat}] unknown crypto crate {p['name']} {p['version']} ({', '.join(hits)}) via {parent}")
                continue
            if entry is None:
                continue
            if parent not in entry.get(kind, []):
                errs.append(f"[{plat}] {p['name']}: new {kind} dependent {parent} (allowed: {entry.get(kind, [])})")
        for i in active & shipped:
            e = crates.get(pk[i]["name"])
            if e and e.get("class") == "test-only":
                errs.append(f"[{plat}] test-only crate {pk[i]['name']} is reachable from the shipped binaries")
    return sorted(set(errs))


def cargo_metadata(platform):
    out = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", platform],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    return json.loads(out)


# -------------------------------------------------------------- T4 sources

def bom_refs(bom):
    return {c["bom-ref"] for c in bom.get("components", []) if "bom-ref" in c}


def marker_ok(marker, refs):
    if marker.endswith("/*"):
        return any(r.startswith(marker[:-1]) for r in refs)
    return marker in refs


def covers(markers, ref):
    return any(m == ref or (m.endswith("/*") and ref.startswith(m[:-1])) for m in markers)


def rust_files(root):
    for top in ("crates", "services"):
        for dirpath, dirnames, files in os.walk(root / top):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for f in files:
                if f.endswith(".rs"):
                    yield Path(dirpath) / f


def check_sources(root, bom):
    errs = []
    refs = bom_refs(bom)
    markers_by_file = {}
    for path in rust_files(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        markers = MARKER.findall(text)
        markers_by_file[rel] = markers
        for m in markers:
            if not marker_ok(m, refs):
                errs.append(f"{rel}: CBOM marker {m} names no component")
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))
        if not rel.startswith("crates/plat-tls/") and TLS_ONLY.search(code):
            errs.append(f"{rel}: rustls::crypto / aws_lc_rs outside crates/plat-tls (CLAUDE.md: crypto behind plat-tls)")
        if API.search(code) and not markers:
            errs.append(f"{rel}: calls a crypto API but carries no // CBOM: marker")
    for c in bom.get("components", []):
        for o in c.get("evidence", {}).get("occurrences", []):
            loc = o.get("location", "")
            if not (root / loc).is_file():
                errs.append(f"{c['bom-ref']}: occurrence {loc} does not exist")
            elif not covers(markers_by_file.get(loc, MARKER.findall((root / loc).read_text(encoding="utf-8"))),
                            c["bom-ref"]):
                errs.append(f"{c['bom-ref']}: occurrence {loc} has no // CBOM: marker for it")
    return errs


# ------------------------------------------------------------ T5 structure

def lock_versions(lock_text):
    lock = tomllib.loads(lock_text)
    out = {}
    for p in lock.get("package", []):
        out.setdefault(p["name"], set()).add(p["version"])
    return out


def check_structure(bom, locked):
    errs = []
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        errs.append("CBOM must be CycloneDX specVersion 1.6")
    comps = bom.get("components", [])
    seen = set()
    for c in comps:
        r = c.get("bom-ref")
        if r in seen:
            errs.append(f"duplicate bom-ref {r}")
        seen.add(r)
    meta_ref = bom.get("metadata", {}).get("component", {}).get("bom-ref")
    known = seen | {meta_ref}

    def need(r, where):
        if r not in known:
            errs.append(f"{where}: reference {r} does not resolve")

    for c in comps:
        pp = c.get("cryptoProperties", {}).get("protocolProperties", {})
        for r in pp.get("cryptoRefArray", []):
            need(r, c["bom-ref"])
        for s in pp.get("cipherSuites", []):
            for r in s.get("algorithms", []):
                need(r, f"{c['bom-ref']} {s.get('name')}")
    provided = {}
    for d in bom.get("dependencies", []):
        need(d.get("ref"), "dependencies")
        for r in d.get("dependsOn", []):
            need(r, f"dependencies {d.get('ref')}")
        for r in d.get("provides", []):
            need(r, f"provides {d.get('ref')}")
            provided[r] = provided.get(r, 0) + 1
    for c in comps:
        if c.get("cryptoProperties", {}).get("assetType") == "algorithm":
            n = provided.get(c["bom-ref"], 0)
            if n != 1:
                errs.append(f"{c['bom-ref']} is provided {n} times (want exactly 1)")
        if c.get("type") == "library":
            vs = locked.get(c.get("name"), set())
            if c.get("version") not in vs:
                errs.append(f"{c['bom-ref']}: {c.get('name')} {c.get('version')} not in Cargo.lock {sorted(vs)}")
            if c.get("purl") != f"pkg:cargo/{c.get('name')}@{c.get('version')}":
                errs.append(f"{c['bom-ref']}: purl {c.get('purl')} does not match name/version")
    return errs


def schema_validate(path):
    """Validates `path` against the vendored 1.6 schema. Required when CI=true."""
    cmd = os.environ.get("CHECK_JSONSCHEMA") or ("check-jsonschema" if shutil.which("check-jsonschema") else "")
    if not cmd:
        if os.environ.get("CI") == "true":
            return ["check-jsonschema is required in CI (pip install --require-hashes -r "
                    "deploy/tests/supply-chain/requirements-jsonschema.txt)"]
        print("WARNING: check-jsonschema not installed; schema validation skipped", file=sys.stderr)
        return []
    r = subprocess.run([*shlex.split(cmd), "--schemafile", str(SCHEMA), str(path)], cwd=ROOT)
    return [] if r.returncode == 0 else [f"{path}: CycloneDX 1.6 schema validation failed"]


def check_schema_sums():
    sums = ROOT / "deploy/tests/supply-chain/schema/SHA256SUMS"
    import hashlib
    errs = []
    for line in sums.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        want, name = line.split(maxsplit=1)
        f = sums.parent / name.strip().lstrip("*")
        got = hashlib.sha256(f.read_bytes()).hexdigest() if f.is_file() else "missing"
        if got != want:
            errs.append(f"schema/{name.strip()}: sha256 {got} != {want}")
    return errs


# --------------------------------------------------------------- self-test

def _meta(pkgs, edges, features=None):
    """Synthetic cargo metadata: pkgs {name: (source, keywords)}, edges
    [(parent, child, kind)]."""
    packages = [{"id": n, "name": n, "version": "1.0.0", "source": s, "keywords": kw, "categories": [],
                 "dependencies": [{"name": c, "optional": False} for p, c, _ in edges if p == n],
                 "features": {}} for n, (s, kw) in pkgs.items()]
    nodes = [{"id": n, "features": (features or {}).get(n, []),
              "deps": [{"name": c, "pkg": c, "dep_kinds": [{"kind": None if k == "normal" else k}]}
                       for p, c, k in edges if p == n]} for n in pkgs]
    return {"packages": packages, "resolve": {"nodes": nodes}}


def self_test():
    reg = "registry+https://github.com/rust-lang/crates.io-index"
    pkgs = {"platd": (None, []), "plat-tls": (None, []), "plat-xlat": (None, []),
            "rustls": (reg, ["tls"]), "ring": (reg, ["crypto"]), "proptest": (reg, []), "chacha20": (reg, ["crypto"])}
    allow = {"crate": {"rustls": {"class": "protocol", "rationale": "x", "normal": ["plat-tls"]},
                       "chacha20": {"class": "test-only", "rationale": "x", "normal": ["proptest"]}}}
    base = [("platd", "plat-tls", "normal"), ("plat-tls", "rustls", "normal")]
    ok = check_graph({"t": _meta(pkgs, base)}, allow)
    assert ok == [], ok
    # Unknown crypto crate.
    e = check_graph({"t": _meta(pkgs, base + [("plat-xlat", "ring", "normal")])}, allow)
    assert any("unknown crypto crate ring" in x for x in e), e
    # Allowed crate with a new dependent.
    e = check_graph({"t": _meta(pkgs, base + [("plat-xlat", "rustls", "normal")])}, allow)
    assert any("new normal dependent plat-xlat" in x for x in e), e
    # test-only crate reachable from a shipped binary.
    e = check_graph({"t": _meta(pkgs, base + [("platd", "proptest", "normal"), ("proptest", "chacha20", "normal")])},
                    allow)
    assert any("test-only crate chacha20" in x for x in e), e
    # ... but fine behind a dev edge.
    e = check_graph({"t": _meta(pkgs, base + [("platd", "proptest", "dev"), ("proptest", "chacha20", "normal")])},
                    allow)
    assert e == [], e
    # Weak optional dependency (dep?/feat) is not active.
    m = _meta(pkgs, base + [("rustls", "ring", "normal")])
    rp = next(p for p in m["packages"] if p["name"] == "rustls")
    rp["dependencies"] = [{"name": "ring", "optional": True}]
    rp["features"] = {"alloc": ["ring?/alloc"], "ring": ["dep:ring"]}
    next(n for n in m["resolve"]["nodes"] if n["id"] == "rustls")["features"] = ["alloc"]
    assert check_graph({"t": m}, allow) == [], check_graph({"t": m}, allow)
    next(n for n in m["resolve"]["nodes"] if n["id"] == "rustls")["features"] = ["alloc", "ring"]
    assert any("unknown crypto crate ring" in x for x in check_graph({"t": m}, allow))

    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"bom-ref": "platd"}},
           "components": [
               {"bom-ref": "crypto/algorithm/sha-256/x", "cryptoProperties": {"assetType": "algorithm"},
                "evidence": {"occurrences": [{"location": "crates/a/src/lib.rs"}]}},
               {"bom-ref": "lib/x", "type": "library", "name": "x", "version": "1.0.0", "purl": "pkg:cargo/x@1.0.0"}],
           "dependencies": [{"ref": "lib/x", "provides": ["crypto/algorithm/sha-256/x"]}]}
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        src = root / "crates/a/src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text("// CBOM: crypto/algorithm/sha-256/x\nuse sha2::Sha256;\n")
        assert check_sources(root, bom) == [], check_sources(root, bom)
        # Missing marker.
        (src / "other.rs").write_text("use sha2::Sha256;\n")
        assert any("no // CBOM: marker" in x for x in check_sources(root, bom))
        (src / "other.rs").unlink()
        # Dangling occurrence.
        bad = json.loads(json.dumps(bom))
        bad["components"][0]["evidence"]["occurrences"].append({"location": "crates/a/src/gone.rs"})
        assert any("does not exist" in x for x in check_sources(root, bad))
        # Marker naming no component.
        (src / "lib.rs").write_text("// CBOM: crypto/algorithm/nope\n// CBOM: crypto/algorithm/sha-256/x\n")
        assert any("names no component" in x for x in check_sources(root, bom))
        # rustls::crypto outside plat-tls.
        (src / "lib.rs").write_text("// CBOM: crypto/algorithm/sha-256/x\nuse rustls::crypto::CryptoProvider;\n")
        assert any("outside crates/plat-tls" in x for x in check_sources(root, bom))
        # Allowed inside plat-tls.
        tls = root / "crates/plat-tls/src"
        tls.mkdir(parents=True)
        (src / "lib.rs").write_text("// CBOM: crypto/algorithm/sha-256/x\n")
        (tls / "p.rs").write_text("// CBOM: crypto/algorithm/sha-256/x\nuse rustls::crypto::CryptoProvider;\n")
        assert check_sources(root, bom) == [], check_sources(root, bom)
        # Ring buffers are not the ring crate.
        (tls / "q.rs").write_text("let ring = Ring::new(); // a replication ring\n")
        assert check_sources(root, bom) == [], check_sources(root, bom)

    locked = {"x": {"1.0.0"}}
    assert check_structure(bom, locked) == [], check_structure(bom, locked)
    dup = json.loads(json.dumps(bom))
    dup["components"].append(dict(dup["components"][1]))
    assert any("duplicate bom-ref lib/x" in x for x in check_structure(dup, locked))
    assert any("not in Cargo.lock" in x for x in check_structure(bom, {"x": {"2.0.0"}}))
    twice = json.loads(json.dumps(bom))
    twice["dependencies"].append({"ref": "lib/x", "provides": ["crypto/algorithm/sha-256/x"]})
    assert any("provided 2 times" in x for x in check_structure(twice, locked))
    dangling = json.loads(json.dumps(bom))
    dangling["dependencies"][0]["dependsOn"] = ["lib/missing"]
    assert any("does not resolve" in x for x in check_structure(dangling, locked))
    print("check-cbom self-test: ok")


def main(argv):
    args = set(argv[1:])
    if not args or not args <= {"--graph", "--sources", "--structure", "--all", "--self-test"}:
        print(__doc__, file=sys.stderr)
        return 2
    if "--self-test" in args:
        self_test()
        args.discard("--self-test")
    if "--all" in args:
        args |= {"--graph", "--sources", "--structure"}
    bom = json.loads(CBOM.read_text(encoding="utf-8"))
    errs = []
    if "--graph" in args:
        allow = tomllib.loads(ALLOW.read_text(encoding="utf-8"))
        errs += check_graph({p: cargo_metadata(p) for p in PLATFORMS}, allow)
    if "--sources" in args:
        errs += check_sources(ROOT, bom)
    if "--structure" in args:
        errs += check_structure(bom, lock_versions((ROOT / "Cargo.lock").read_text(encoding="utf-8")))
        errs += check_schema_sums()
        errs += schema_validate(CBOM)
    for e in errs:
        print(f"ERROR: {e}", file=sys.stderr)
    if errs:
        return 1
    if args - {"--all"}:
        print(f"check-cbom: ok ({', '.join(sorted(a[2:] for a in args if a != '--all'))})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
