#!/usr/bin/env python3
"""QA negative tests for check-cbom.py T3 (graph drift), run with
`python3 -I deploy/tests/supply-chain/test_drift_negative.py`.

Uses the real crypto-allow.toml and the real `cargo metadata` for
x86_64-unknown-linux-gnu, then injects edges in memory:
  1. ring (unknown crypto crate) under plat-xlat         -> fails
  2. aws-lc-rs (allowed) under plat-nat64 (not a parent) -> fails
  3. rustls as a build edge of plat-tls (only normal)    -> fails
  4. blake9 (category "cryptography") under plat-packet -> flagged by category
  5. the unmodified graph                                -> passes

COMPLIANCE MAPPING:
- NIST 800-53: SA-11 (Developer Testing), SR-3 (Supply Chain Controls)
"""

import copy
import importlib.util
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_cbom", HERE / "check-cbom.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

ALLOW = tomllib.loads(cc.ALLOW.read_text(encoding="utf-8"))
PLAT = "x86_64-unknown-linux-gnu"
REG = "registry+https://github.com/rust-lang/crates.io-index"


def ids(meta, name):
    return [p["id"] for p in meta["packages"] if p["name"] == name]


def add_pkg(meta, name, cats=(), kws=()):
    pid = f"{REG}#{name}@9.9.9"
    meta["packages"].append({"id": pid, "name": name, "version": "9.9.9", "source": REG, "keywords": list(kws),
                             "categories": list(cats), "dependencies": [], "features": {}})
    meta["resolve"]["nodes"].append({"id": pid, "features": [], "deps": []})
    return pid


def add_edge(meta, parent, child_id, child_name, kind=None):
    pid = ids(meta, parent)[0]
    pkg = next(p for p in meta["packages"] if p["id"] == pid)
    pkg["dependencies"].append({"name": child_name, "optional": False, "kind": kind})
    node = next(n for n in meta["resolve"]["nodes"] if n["id"] == pid)
    node["deps"].append({"name": child_name.replace("-", "_"), "pkg": child_id, "dep_kinds": [{"kind": kind}]})


def main():
    base = cc.cargo_metadata(PLAT)
    assert cc.check_graph({PLAT: base}, ALLOW) == [], cc.check_graph({PLAT: base}, ALLOW)

    m = copy.deepcopy(base)
    add_edge(m, "plat-xlat", add_pkg(m, "ring", kws=["crypto"]), "ring")
    e = cc.check_graph({PLAT: m}, ALLOW)
    assert any("unknown crypto crate ring" in x and "plat-xlat" in x for x in e), e

    m = copy.deepcopy(base)
    awslc = ids(m, "aws-lc-rs")[0]
    add_edge(m, "plat-nat64", awslc, "aws-lc-rs")
    e = cc.check_graph({PLAT: m}, ALLOW)
    assert any("aws-lc-rs: new normal dependent plat-nat64" in x for x in e), e

    m = copy.deepcopy(base)
    add_edge(m, "plat-tls", ids(m, "rustls")[0], "rustls", kind="build")
    e = cc.check_graph({PLAT: m}, ALLOW)
    assert any("rustls: new build dependent plat-tls" in x for x in e), e

    m = copy.deepcopy(base)
    add_edge(m, "plat-packet", add_pkg(m, "blake9", cats=["cryptography"]), "blake9")
    e = cc.check_graph({PLAT: m}, ALLOW)
    assert any("unknown crypto crate blake9" in x for x in e), e

    print("drift negative tests: ok (5 cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
