#!/usr/bin/env python3
"""Finishes and cross-checks the CycloneDX SBOM of the shipped binaries
(run with `python3 -I`; standard library only, no network).

  sbom-finish.py --target <triple> --out <file> --raw <platd_bin.cdx.json>
                 --raw <plat-xdp-loader_bin.cdx.json> [--features xdp]
                 [--auditable <bin> ...] [--xdp-object <obj> --embedded-root <dir>]
  sbom-finish.py --self-test

Steps (plan §1.1, §1.1b, §1.1c):
 1. Merge the per-binary cargo-cyclonedx SBOMs into one document with
    metadata.component = platd; replace the absolute checkout path in
    bom-refs with `path+file:///usg-plat`, so the file is machine-independent.
 2. metadata.timestamp from SOURCE_DATE_EPOCH (default: the commit time);
    serialNumber = UUIDv5 over (commit, triple, variant, tool version), so
    the same commit and architecture give a byte-identical SBOM.
 3. externalReferences: the CBOM (`urn:cdx:<serial>/<version>`).
 4. T6: the registry packages in the SBOM equal the closure of platd and
    plat-xdp-loader over normal and build edges in `cargo metadata` (same
    name, version, purl; no extras); aws-lc-fips-sys, aws-lc-rs and rustls
    are present.
 5. T7 (--auditable, Linux): the cargo-auditable `.dep-v0` section of each
    binary is present; its runtime packages equal that binary's normal-edge
    closure and its build packages are a subset of the build closure.
 6. T8 (--xdp-object): adds the eBPF object as a component with its SHA-256,
    nested crates (bpfel graph and build-std from the sysroot lock) and the
    build formulation; the hash must equal `<obj>.sha256` and the newest
    embedded copy under --embedded-root, and check-object.py must pass on it.
 7. Schema validation against the vendored CycloneDX 1.5 schema
    (check-jsonschema; required when CI=true).

COMPLIANCE MAPPING:
- NIST 800-53: CM-8 (System Component Inventory), SR-4 (Provenance), SI-7
  (Software Integrity), SA-11 (Developer Testing), RA-5 (cargo audit bin input)
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CBOM = ROOT / "docs/compliance/cbom.cdx.json"
SCHEMA = HERE / "schema/bom-1.5.schema.json"
SHIPPED = ("platd", "plat-xdp-loader")
REQUIRED = ("aws-lc-fips-sys", "aws-lc-rs", "rustls")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
NS = uuid.UUID("6f1f3c9e-1c51-4d7b-9a51-7c1b0f6d8a20")  # usg-plat SBOM namespace


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True, **kw).stdout


# ------------------------------------------------------------------ merge

def normalise(text, root):
    return text.replace(f"path+file://{root}", "path+file:///usg-plat")


def merge(raws, root):
    """raws: [(binary name, parsed json)] -> one BOM (platd first)."""
    docs = [json.loads(normalise(json.dumps(d), root)) for _, d in raws]
    base = docs[0]
    comps = {c["bom-ref"]: c for d in docs for c in d.get("components", [])}
    for d in docs[1:]:
        mc = dict(d["metadata"]["component"])
        mc["type"] = "application"
        comps.setdefault(mc["bom-ref"], mc)
    deps = {}
    for d in docs:
        for e in d.get("dependencies", []):
            deps.setdefault(e["ref"], set()).update(e.get("dependsOn", []))
    base["components"] = [comps[k] for k in sorted(comps)]
    base["dependencies"] = [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(deps.items())]
    return base


def commit_info():
    try:
        sha = run(["git", "rev-parse", "HEAD"]).strip()
        ts = run(["git", "log", "-1", "--format=%ct"]).strip()
    except (OSError, subprocess.CalledProcessError):
        sha, ts = "unknown", "0"
    return sha, int(os.environ.get("SOURCE_DATE_EPOCH", ts))


def finish(bom, *, commit, epoch, triple, variant, tool):
    import datetime
    md = bom.setdefault("metadata", {})
    md["timestamp"] = datetime.datetime.fromtimestamp(epoch, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    props = [p for p in md.get("properties", []) if not p.get("name", "").startswith("usg-plat:")]
    props += [{"name": "usg-plat:commit", "value": commit}, {"name": "usg-plat:target", "value": triple},
              {"name": "usg-plat:variant", "value": variant}, {"name": "usg-plat:generator", "value": tool}]
    md["properties"] = props
    bom["serialNumber"] = f"urn:uuid:{uuid.uuid5(NS, f'{commit}|{triple}|{variant}|{tool}')}"
    bom["version"] = 1
    cbom = json.loads(CBOM.read_text(encoding="utf-8"))
    serial = cbom["serialNumber"].removeprefix("urn:uuid:")
    bom["externalReferences"] = [{"type": "bom", "url": f"urn:cdx:{serial}/{cbom['version']}",
                                  "comment": "CBOM: docs/compliance/cbom.cdx.json (/usr/share/doc/platd/cbom.cdx.json)"}]
    return bom


# ---------------------------------------------------------------- T6 / T7

TREE_LINE = re.compile(r"^(\S+) v(\S+)(?: \((.*?)\))?(?: \(proc-macro\))?(?: \(\*\))?$")


def parse_tree(text):
    """`cargo tree --prefix none -f '{p}'` lines -> {(name, version): local}."""
    out = {}
    for line in text.splitlines():
        line = line.strip().removesuffix(" (*)")
        if not line:
            continue
        procmacro = line.endswith(" (proc-macro)")
        line = line.removesuffix(" (proc-macro)")
        m = TREE_LINE.match(line)
        if not m:
            continue
        local = bool(m.group(3) and m.group(3).startswith("/"))
        out[(m.group(1), m.group(2))] = (local, procmacro)
    return out


def cargo_tree(pkgs, edges, target, features=()):
    """Registry packages cargo resolves for building `pkgs` (feature
    resolver 3, the same resolution as `cargo build`): {(name, version): procmacro}."""
    cmd = ["cargo", "tree", "--locked", "--offline", "--prefix", "none", "-f", "{p}", "-e", edges, "--target", target]
    for p in pkgs:
        cmd += ["-p", p]
    if features:
        cmd += ["--features", ",".join(features)]
    return {k: pm for k, (local, pm) in parse_tree(run(cmd)).items() if not local}


def prune(bom, want):
    """Drops registry components cargo does not build (cargo-cyclonedx 0.5.9
    lists optional and weak `dep?/feature` dependencies without feature
    activation, e.g. ring through rustls-webpki); records them in metadata."""
    keep, dropped = [], []
    for c in bom.get("components", []):
        if c.get("bom-ref", "").startswith(REGISTRY) and (c.get("name"), c.get("version")) not in want:
            dropped.append(c["bom-ref"])
        else:
            keep.append(c)
    bom["components"] = keep
    gone = set(dropped)
    bom["dependencies"] = [{"ref": d["ref"], "dependsOn": [x for x in d.get("dependsOn", []) if x not in gone]}
                           for d in bom.get("dependencies", []) if d["ref"] not in gone]
    if dropped:
        names = ",".join(sorted(r.split("#", 1)[1] for r in dropped))
        bom["metadata"].setdefault("properties", []).append(
            {"name": "usg-plat:pruned-not-built", "value": names})
    return bom


def sbom_registry(bom):
    out = set()
    for c in bom.get("components", []):
        if c.get("bom-ref", "").startswith(REGISTRY):
            if c.get("purl", "").split("?")[0] != f"pkg:cargo/{c['name']}@{c['version']}":
                out.add(("BAD-PURL:" + c["name"], c.get("purl", "")))
            out.add((c["name"], c["version"]))
    return out


def cross_check(bom, want):
    errs = []
    have = sbom_registry(bom)
    for n, v in sorted(want - have):
        errs.append(f"T6: {n} {v} is shipped (cargo tree) but missing from the SBOM")
    for n, v in sorted(have - want):
        errs.append(f"T6: {n} {v} is in the SBOM but not shipped")
    names = {n for n, _ in have}
    for r in REQUIRED:
        if r not in names:
            errs.append(f"T6: {r} missing from the SBOM")
    return errs


def dep_v0(binary):
    """Decoded cargo-auditable data, or None if the section is absent."""
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "dep-v0"
        r = subprocess.run(["objcopy", "-O", "binary", "--only-section=.dep-v0", str(binary), str(out)],
                           capture_output=True)
        if r.returncode != 0 or not out.is_file() or out.stat().st_size == 0:
            return None
        return json.loads(zlib.decompress(out.read_bytes()))


def auditable_check(info, normal, build):
    """info: decoded .dep-v0; normal/build: {(name, version)} registry closures."""
    if info is None:
        return ["T7: no .dep-v0 section (binary not built with cargo auditable)"]
    errs = []
    rt = {(p["name"], p["version"]) for p in info["packages"]
          if p.get("source") == "crates.io" and p.get("kind", "runtime") == "runtime"}
    bd = {(p["name"], p["version"]) for p in info["packages"]
          if p.get("source") == "crates.io" and p.get("kind") == "build"}
    for x in sorted(rt ^ normal):
        errs.append(f"T7: runtime package {x} differs between .dep-v0 and the SBOM normal closure")
    for x in sorted(bd - build):
        errs.append(f"T7: build package {x} in .dep-v0 is not in the SBOM build closure")
    return errs


# ---------------------------------------------------------------------- T8

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def newest_embedded(root):
    objs = sorted(Path(root).glob("plat-xdp-*/out/plat-xdp-ebpf"), key=lambda p: p.stat().st_mtime)
    return objs[-1] if objs else None


def bpf_linker_pin():
    text = (ROOT / "deploy/tests/xdp/install-bpf-linker.sh").read_text(encoding="utf-8")
    ver = re.search(r"^BPF_LINKER_VERSION=(\S+)", text, re.M)
    shas = dict(re.findall(r"^SHA256_(\w+)=([0-9a-f]{64})", text, re.M))
    return (ver.group(1) if ver else "unknown"), shas


def object_component(obj, digest, version, nested):
    return {
        "type": "application", "bom-ref": "bpf/plat-xdp-ebpf", "name": "plat-xdp-ebpf", "version": version,
        "description": "eBPF XDP fast-path program (ELF, bpfel-unknown-none), embedded in plat-xdp via include_bytes",
        "purl": f"pkg:generic/usg-plat/plat-xdp-ebpf@{version}?arch=bpfel",
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "licenses": [{"expression": "MIT OR GPL-2.0-only"}],
        "properties": [{"name": "usg-plat:object-license", "value": "Dual MIT/GPL"},
                       {"name": "usg-plat:target", "value": "bpfel-unknown-none"},
                       {"name": "usg-plat:embedded-in", "value": "plat-xdp"},
                       {"name": "usg-plat:min-kernel", "value": "6.6"}],
        "components": nested,
    }


def object_check(obj, embedded_root):
    errs = []
    digest = sha256(obj)
    side = Path(f"{obj}.sha256")
    want = side.read_text().split()[0] if side.is_file() else "missing"
    if want != digest:
        errs.append(f"T8: {obj} sha256 {digest} != {side} ({want})")
    emb = newest_embedded(embedded_root)
    if emb is None:
        errs.append(f"T8: no embedded plat-xdp-ebpf under {embedded_root}")
    elif sha256(emb) != digest:
        errs.append(f"T8: embedded object {emb} ({sha256(emb)}) differs from the gated object ({digest})")
    elif not errs:
        r = subprocess.run([sys.executable, "-I", str(ROOT / "deploy/tests/xdp/check-object.py"), str(emb)], cwd=ROOT)
        if r.returncode != 0:
            errs.append(f"T8: check-object.py failed on {emb}")
    return digest, errs


def ebpf_nested(version):
    cmd = ["cargo", "tree", "--locked", "--offline", "--prefix", "none", "-f", "{p}", "-e", "normal",
           "--target", "bpfel-unknown-none", "-p", "plat-xdp-ebpf"]
    nested = []
    for (name, ver), (local, procmacro) in sorted(parse_tree(run(cmd)).items()):
        if name == "plat-xdp-ebpf":
            continue
        purl = f"pkg:generic/usg-plat/{name}@{ver}" if local else f"pkg:cargo/{name}@{ver}"
        c = {"type": "library", "bom-ref": f"bpf/plat-xdp-ebpf/{name}@{ver}", "name": name,
             "version": ver, "purl": purl}
        if procmacro:
            c["scope"] = "excluded"
            c["properties"] = [{"name": "usg-plat:kind", "value": "proc-macro"}]
        nested.append(c)
    sysroot = run(["rustc", "--print", "sysroot"]).strip()
    rustc_v = run(["rustc", "-vV"])
    rver = re.search(r"^release: (\S+)", rustc_v, re.M).group(1)
    llvm = re.search(r"^LLVM version: (\d+)", rustc_v, re.M)
    lock = Path(sysroot) / "lib/rustlib/src/rust/library/Cargo.lock"
    import tomllib
    locked = {p["name"]: p["version"] for p in tomllib.loads(lock.read_text()).get("package", [])} if lock.is_file() else {}
    nested.append({"type": "library", "bom-ref": "bpf/plat-xdp-ebpf/core", "name": "core", "version": rver,
                   "purl": f"pkg:generic/rust-lang/core@{rver}",
                   "properties": [{"name": "usg-plat:kind", "value": "build-std"}]})
    cb = locked.get("compiler_builtins", "unknown")
    nested.append({"type": "library", "bom-ref": "bpf/plat-xdp-ebpf/compiler_builtins", "name": "compiler_builtins",
                   "version": cb, "purl": f"pkg:cargo/compiler_builtins@{cb}",
                   "properties": [{"name": "usg-plat:kind", "value": "build-std"}]})
    linker_v, shas = bpf_linker_pin()
    tools = [{"type": "application", "bom-ref": "tool/rustc", "name": "rustc", "version": rver,
              "properties": [{"name": "usg-plat:llvm-major", "value": llvm.group(1) if llvm else "unknown"}]},
             {"type": "application", "bom-ref": "tool/bpf-linker", "name": "bpf-linker", "version": linker_v,
              "hashes": [{"alg": "SHA-256", "content": shas.get("X86_64" if platform.machine() == "x86_64" else "AARCH64", "")}],
              "properties": [{"name": "usg-plat:installer", "value": "deploy/tests/xdp/install-bpf-linker.sh"}]}]
    formulation = [{"bom-ref": "formula/plat-xdp-ebpf", "components": tools, "workflows": [{
        "bom-ref": "workflow/build-object", "uid": "build-object",
        "description": "deploy/tests/xdp/build-object.sh and crates/plat-xdp/build.rs: cargo build -p plat-xdp-ebpf "
                       "--target bpfel-unknown-none -Z build-std=core (RUSTC_BOOTSTRAP on that child only), "
                       "bpf-linker, fixed flags and path remaps",
        "taskTypes": ["build"]}]}]
    return nested, formulation


# ------------------------------------------------------------------ schema

def schema_validate(path):
    cmd = os.environ.get("CHECK_JSONSCHEMA") or ("check-jsonschema" if shutil.which("check-jsonschema") else "")
    if not cmd:
        if os.environ.get("CI") == "true":
            return ["check-jsonschema is required in CI"]
        print("WARNING: check-jsonschema not installed; SBOM schema validation skipped", file=sys.stderr)
        return []
    r = subprocess.run([*shlex.split(cmd), "--schemafile", str(SCHEMA), str(path)], cwd=ROOT)
    return [] if r.returncode == 0 else [f"{path}: CycloneDX 1.5 schema validation failed"]


def dump(bom):
    return json.dumps(bom, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------- self-test

def self_test():
    root = "/build/usg-plat"
    def comp(n, v):
        return {"type": "library", "bom-ref": f"{REGISTRY}#{n}@{v}", "name": n, "version": v,
                "purl": f"pkg:cargo/{n}@{v}"}
    platd = {"bomFormat": "CycloneDX", "specVersion": "1.5",
             "metadata": {"component": {"bom-ref": f"path+file://{root}/services/platd#0.1.0", "name": "platd"}},
             "components": [comp("rustls", "0.23.46"), comp("aws-lc-rs", "1.19.0"), comp("aws-lc-fips-sys", "0.14.4")],
             "dependencies": [{"ref": f"path+file://{root}/services/platd#0.1.0",
                               "dependsOn": [f"{REGISTRY}#rustls@0.23.46"]}]}
    loader = {"metadata": {"component": {"bom-ref": f"path+file://{root}/services/plat-xdp-loader#0.1.0",
                                         "name": "plat-xdp-loader"}},
              "components": [comp("libc", "0.2.180")], "dependencies": []}
    m = merge([("platd", platd), ("plat-xdp-loader", loader)], root)
    assert root not in json.dumps(m), "absolute path left in bom-refs"
    want = {("rustls", "0.23.46"), ("aws-lc-rs", "1.19.0"), ("aws-lc-fips-sys", "0.14.4"), ("libc", "0.2.180")}
    assert cross_check(m, want) == [], cross_check(m, want)
    assert any("missing from the SBOM" in e for e in cross_check(m, want | {("serde", "1.0.0")}))
    assert any("not shipped" in e for e in cross_check(m, want - {("libc", "0.2.180")}))
    no_rustls = json.loads(json.dumps(m))
    no_rustls["components"] = [c for c in no_rustls["components"] if c.get("name") != "rustls"]
    assert any("rustls missing" in e for e in cross_check(no_rustls, want - {("rustls", "0.23.46")}))
    # Determinism: same inputs give byte-identical output; another arch differs.
    kw = dict(commit="c0ffee", epoch=1793700000, triple="x86_64-unknown-linux-gnu", variant="default", tool="t 1")
    a = dump(finish(merge([("platd", platd), ("plat-xdp-loader", loader)], root), **kw))
    b = dump(finish(merge([("platd", platd), ("plat-xdp-loader", loader)], root), **kw))
    assert a == b, "SBOM output is not deterministic"
    kw["triple"] = "aarch64-unknown-linux-gnu"
    assert dump(finish(merge([("platd", platd)], root), **kw)) != a
    # cargo tree parsing and pruning.
    t = parse_tree("platd v0.1.0 (/x/services/platd)\nrustls v0.23.46\naya-ebpf-macros v0.2.0 (proc-macro)\n"
                   "rustls v0.23.46 (*)\n")
    assert t == {("platd", "0.1.0"): (True, False), ("rustls", "0.23.46"): (False, False),
                 ("aya-ebpf-macros", "0.2.0"): (False, True)}, t
    extra = json.loads(json.dumps(m))
    extra["components"].append(comp("ring", "0.17.14"))
    pruned = prune(extra, want)
    assert ("ring", "0.17.14") not in sbom_registry(pruned)
    assert any(p["name"] == "usg-plat:pruned-not-built" and "ring@0.17.14" in p["value"]
               for p in pruned["metadata"]["properties"])
    # T7 set logic.
    info = {"packages": [{"name": "rustls", "version": "0.23.46", "source": "crates.io"},
                         {"name": "cc", "version": "1.2.0", "source": "crates.io", "kind": "build"},
                         {"name": "platd", "version": "0.1.0", "source": "local"}]}
    assert auditable_check(info, {("rustls", "0.23.46")}, {("rustls", "0.23.46"), ("cc", "1.2.0")}) == []
    assert auditable_check(None, set(), set())
    assert auditable_check(info, {("rustls", "0.23.46"), ("x", "1")}, {("cc", "1.2.0")})
    assert auditable_check(info, {("rustls", "0.23.46")}, set())
    # T8: tampered object hash fails.
    with tempfile.TemporaryDirectory() as d:
        obj = Path(d) / "plat-xdp-ebpf"
        obj.write_bytes(b"\x7fELF object")
        Path(f"{obj}.sha256").write_text("0" * 64 + "  plat-xdp-ebpf\n")
        emb = Path(d) / "build/plat-xdp-1/out"
        emb.mkdir(parents=True)
        (emb / "plat-xdp-ebpf").write_bytes(b"\x7fELF object")
        _, errs = object_check(obj, Path(d) / "build")
        assert any("sha256" in e for e in errs), errs
        Path(f"{obj}.sha256").write_text(sha256(obj) + "  plat-xdp-ebpf\n")
        (emb / "plat-xdp-ebpf").write_bytes(b"\x7fELF other")
        _, errs = object_check(obj, Path(d) / "build")
        assert any("differs from the gated object" in e for e in errs), errs
    print("sbom-finish self-test: ok")


# ------------------------------------------------------------------- main

def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--target")
    ap.add_argument("--out")
    ap.add_argument("--raw", action="append", default=[])
    ap.add_argument("--features", default="")
    ap.add_argument("--auditable", action="append", default=[])
    ap.add_argument("--xdp-object")
    ap.add_argument("--embedded-root", default=str(ROOT / "target/dist/build"))
    ap.add_argument("--tool", default="cargo-cyclonedx")
    a = ap.parse_args(argv[1:])
    if a.self_test:
        self_test()
        return 0
    if not (a.target and a.out and len(a.raw) == len(SHIPPED)):
        ap.error("--target, --out and one --raw per shipped binary (platd, plat-xdp-loader) are required")
    raws = [(n, json.loads(Path(p).read_text(encoding="utf-8"))) for n, p in zip(SHIPPED, a.raw)]
    bom = merge(raws, str(ROOT))
    variant = "xdp" if a.features else "default"
    commit, epoch = commit_info()
    bom = finish(bom, commit=commit, epoch=epoch, triple=a.target, variant=variant, tool=a.tool)

    feats = [f"{b}/{f}" for b in SHIPPED for f in a.features.split(",") if f]
    want = set(cargo_tree(SHIPPED, "normal,build", a.target, feats))
    bom = prune(bom, want)
    errs = cross_check(bom, want)

    for b in a.auditable:
        if platform.system() != "Linux" or not shutil.which("objcopy"):
            print(f"T7: skipped for {b} (needs Linux and objcopy)", file=sys.stderr)
            continue
        name = Path(b).name
        own = [f for f in feats if f.startswith(f"{name}/")]
        normal = set(cargo_tree([name], "normal", a.target, own))
        nb = set(cargo_tree([name], "normal,build", a.target, own))
        errs += [f"{b}: {e}" for e in auditable_check(dep_v0(b), normal, nb)]

    if a.xdp_object:
        version = bom["metadata"]["component"].get("version", "0.0.0")
        digest, oerrs = object_check(a.xdp_object, a.embedded_root)
        errs += oerrs
        nested, formulation = ebpf_nested(version)
        bom["components"].append(object_component(a.xdp_object, digest, version, nested))
        xdp_ref = next((c["bom-ref"] for c in bom["components"] if c.get("name") == "plat-xdp"), None)
        if xdp_ref is None:
            errs.append("T8: plat-xdp is not in the SBOM (build with --features xdp)")
        else:
            for d in bom["dependencies"]:
                if d["ref"] == xdp_ref:
                    d["dependsOn"] = sorted(set(d["dependsOn"]) | {"bpf/plat-xdp-ebpf"})
        bom["formulation"] = formulation

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(dump(bom), encoding="utf-8")
    errs += schema_validate(out)
    for e in errs:
        print(f"ERROR: {e}", file=sys.stderr)
    if errs:
        return 1
    print(f"sbom-finish: {out} ({len(bom['components'])} components, sha256 {sha256(out)})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
