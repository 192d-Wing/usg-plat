//! Builds and embeds the `plat-xdp-ebpf` object when the `xdp` feature is on
//! (plan §15).
//!
//! The nested `bpfel-unknown-none` build is the one `aya-build` 0.2.1 runs
//! (`--release`, `-Z build-std=core`, `--cfg bpf_target_arch`,
//! `-Cdebuginfo=2`, `-Clink-arg=--btf`), with the path remaps of
//! `deploy/tests/xdp/build-object.sh` and the same target directory, so the
//! embedded object is byte-identical to the gated one (the level-2 suite
//! and `make xdp` compare the SHA-256 values). The call is vendored rather
//! than using `aya_build::build_ebpf` so that `RUSTC_BOOTSTRAP=1` is set
//! with `Command::env` on that one child only: no `std::env::set_var`
//! (which is `unsafe` in edition 2024), and the outer workspace build never
//! sees it (CLAUDE.md rule 6, brief "Correction: licences").
//!
//! - Feature off: nothing is built or embedded.
//! - Feature on with `AYA_BUILD_SKIP=1` (clippy on a host without
//!   bpf-linker): an empty placeholder is embedded and the loader refuses
//!   at run time ("built without the eBPF object").
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-15 (Development Process, Standards, and Tools), CM-2
//!   (Baseline Configuration) - one pinned compiler; unstable features only
//!   for the nested BPF build
//! - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//!   reproducible, path-independent object, identical to the gated one

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const OBJECT: &str = "plat-xdp-ebpf";

fn main() {
    if let Err(e) = run() {
        println!("cargo::error=plat-xdp: {e}");
        std::process::exit(1);
    }
}

fn var(k: &str) -> Result<String, String> {
    env::var(k).map_err(|_| format!("{k} not set"))
}

fn run() -> Result<(), String> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=AYA_BUILD_SKIP");
    if env::var_os("CARGO_FEATURE_XDP").is_none() {
        return Ok(());
    }
    let out = PathBuf::from(var("OUT_DIR")?);
    let dst = out.join(OBJECT);
    if env::var("AYA_BUILD_SKIP").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
        println!("cargo::warning=AYA_BUILD_SKIP set: embedding an empty eBPF object; the loader will refuse to attach");
        return fs::write(&dst, []).map_err(|e| format!("writing {}: {e}", dst.display()));
    }

    let manifest = PathBuf::from(var("CARGO_MANIFEST_DIR")?);
    let repo = canon(&manifest.join("../.."))?;
    for p in ["crates/plat-xdp-ebpf", "crates/plat-xdp-core", "Cargo.lock", "Cargo.toml", "rust-toolchain.toml"] {
        println!("cargo::rerun-if-changed={}", repo.join(p).display());
    }

    // The kernel the loader runs on is the target's architecture
    // (build-object.sh uses the host's; equal for native builds).
    let arch = match var("CARGO_CFG_TARGET_ARCH")?.as_str() {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        a => return Err(format!("unsupported target architecture {a} for the eBPF object")),
    };
    let cargo_home = match env::var_os("CARGO_HOME") {
        Some(h) => PathBuf::from(h),
        None => PathBuf::from(var("HOME")?).join(".cargo"),
    };
    let cargo_home = canon(&cargo_home)?;
    let sysroot = sysroot()?;

    let sep = "\x1f";
    let flags = [
        format!("--cfg=bpf_target_arch=\"{arch}\""),
        "-Cdebuginfo=2".into(),
        "-Clink-arg=--btf".into(),
        format!("--remap-path-prefix={}=/usg-plat", repo.display()),
        format!("--remap-path-prefix={}=/cargo", cargo_home.display()),
        format!("--remap-path-prefix={sysroot}=/rustc"),
    ]
    .join(sep);

    let target_dir = repo.join("target/xdp-ebpf");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(&repo)
        .args(["build", "--package", OBJECT, "--bins", "--release", "--target", "bpfel-unknown-none"])
        .args(["-Z", "build-std=core", "--locked", "--target-dir"])
        .arg(&target_dir)
        // The one place RUSTC_BOOTSTRAP is set: this child's environment
        // (`-Z build-std` on stable 1.99.1; plan §15, R13).
        .env("RUSTC_BOOTSTRAP", "1")
        .env("CARGO_ENCODED_RUSTFLAGS", &flags)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // The outer build's compiler wrappers and build-script variables must
    // not reach the nested build (aya-build removes the first two too).
    for k in [
        "RUSTC",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_WRAPPER",
        "RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "TARGET",
        "HOST",
        "OPT_LEVEL",
        "DEBUG",
        "PROFILE",
        "NUM_JOBS",
    ] {
        cmd.env_remove(k);
    }
    let st = cmd.status().map_err(|e| format!("spawning the nested eBPF cargo build: {e}"))?;
    if !st.success() {
        return Err(format!(
            "nested eBPF build failed ({st}); needs bpf-linker (deploy/tests/xdp/install-bpf-linker.sh) and rust-src, or set AYA_BUILD_SKIP=1"
        ));
    }
    let built = target_dir.join("bpfel-unknown-none/release").join(OBJECT);
    fs::copy(&built, &dst).map_err(|e| format!("copying {} to {}: {e}", built.display(), dst.display()))?;
    Ok(())
}

fn canon(p: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn sysroot() -> Result<String, String> {
    let o = Command::new("rustc")
        .args(["--print", "sysroot"])
        .env_remove("RUSTC")
        .output()
        .map_err(|e| format!("rustc --print sysroot: {e}"))?;
    if !o.status.success() {
        return Err("rustc --print sysroot failed".into());
    }
    let s = String::from_utf8(o.stdout).map_err(|_| "rustc sysroot is not UTF-8".to_string())?;
    Ok(s.trim().to_string())
}
