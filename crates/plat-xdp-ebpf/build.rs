//! Link options of the eBPF object, set here so every build of the program
//! (`make xdp`, `deploy/tests/xdp/build-object.sh`, and `plat-xdp`'s
//! nested build in WU3) links the same object. Nothing is emitted for the
//! host stub.
//!
//! - `--disable-expand-memcpy-in-order`: with bpf-linker's default
//!   in-order expansion LLVM lowers every `memset` (zeroing the
//!   `bpf_fib_lookup` struct and the output header block) to a call into
//!   a `.text` `memset` with a loop: a bpf-to-bpf call, an extra stack
//!   frame and a back-edge (PERF-009). The generic lowering expands them
//!   to stores.
//! - `--disable-memory-builtins`: do not export `memcpy` / `memset` /
//!   `memmove` / `memcmp` / `bcmp` (each a loop in `.text`). Any call LLVM
//!   still emits is then an unresolved symbol that fails the link, instead
//!   of a loop in the object.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_CFG_TARGET_ARCH").is_some_and(|a| a == "bpf") {
        println!("cargo::rustc-link-arg-bins=--disable-expand-memcpy-in-order");
        println!("cargo::rustc-link-arg-bins=--disable-memory-builtins");
    }
}
