//! Route hooks: `cluster.ha.hooks.announce` / `withdraw`, run out of
//! process (`exec` with argv `<slice-cidr> <epoch> <reason>`, no shell),
//! serialized on the `plat-cluster-hook` thread, killed after
//! `hook_timeout_ms`. The thread also maintains `state_dir/announce.d/`
//! (one file per owned slice, `a.b.c.d_len`, content `<epoch> <reason>`)
//! for routing daemons that watch files. Every run is audited
//! (`cluster_hook`); failures are counted and the slice stays as it is
//! (routing is the operator's concern, plan F11).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CP-10, SC-7 - routes follow slice ownership
//! - NIST 800-53: AU-2, AU-12 - `cluster_hook` records with exit code and
//!   duration
//! - NIST 800-53: CM-5, AC-6 - hooks are absolute paths owned by root (or
//!   the daemon user) and not group/world-writable, in directories that
//!   are too (SEC-7), checked at start and again before every run; the
//!   environment is cleared; SC-5 - bounded job queue and a timeout per
//!   run; each run is its own process group, killed as a whole on timeout
//!   (SEC-6)

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use plat_audit::{AuditSink, Event, HookKind, HookRun};
use plat_common::{Clock, Ipv4Cidr};

use super::slice_cidr;

/// One hook run.
#[derive(Debug, Clone)]
pub struct HookJob {
    pub kind: HookKind,
    pub slice: Ipv4Cidr,
    pub epoch: u64,
    pub reason: &'static str,
}

#[derive(Debug, Default)]
pub struct HookStats {
    /// [announce, withdraw]
    pub failures: [AtomicU64; 2],
    pub runs: AtomicU64,
}

fn kind_ix(k: HookKind) -> usize {
    match k {
        HookKind::Announce => 0,
        HookKind::Withdraw => 1,
    }
}

/// Checks a configured hook: absolute, a regular file (not a symlink),
/// executable, owned by root or by `daemon_uid`, not group/world-writable;
/// and every directory above it (after resolving symlinks) owned by root
/// or `daemon_uid` and not group/world-writable, except a root-owned
/// sticky directory such as `/tmp` (only an entry's owner can replace it
/// there, and the entry is checked in turn).
pub fn check_hook(p: &Path, daemon_uid: u32) -> Result<(), String> {
    if !p.is_absolute() {
        return Err(format!("{}: hook path must be absolute", p.display()));
    }
    let parent = p.parent().ok_or_else(|| format!("{}: hook path has no directory", p.display()))?;
    let real = std::fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    for d in real.ancestors() {
        let m = std::fs::metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
        let mode = m.permissions().mode();
        if m.uid() != 0 && m.uid() != daemon_uid {
            return Err(format!("{}: hook directory must be owned by root", d.display()));
        }
        let sticky_root = m.uid() == 0 && mode & 0o1000 != 0;
        if mode & 0o022 != 0 && !sticky_root {
            return Err(format!("{}: hook directory must not be group- or world-writable", d.display()));
        }
    }
    let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !m.file_type().is_file() {
        return Err(format!("{}: hook must be a regular file", p.display()));
    }
    if m.uid() != 0 && m.uid() != daemon_uid {
        return Err(format!("{}: hook must be owned by root", p.display()));
    }
    let mode = m.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(format!("{}: hook must not be group- or world-writable", p.display()));
    }
    if mode & 0o100 == 0 {
        return Err(format!("{}: hook is not executable", p.display()));
    }
    Ok(())
}

/// Announce file name of a slice (`/` becomes `_`, as in the shipped hooks).
pub fn announce_name(c: Ipv4Cidr) -> String {
    c.to_string().replace('/', "_")
}

/// Handle of the hook thread.
#[derive(Debug)]
pub struct Hooks {
    tx: Option<SyncSender<HookJob>>,
    handle: Option<JoinHandle<()>>,
    pub stats: Arc<HookStats>,
    audit: AuditSink,
}

struct Runner {
    announce: Option<PathBuf>,
    withdraw: Option<PathBuf>,
    state_dir: PathBuf,
    daemon_uid: u32,
    timeout: Duration,
    audit: AuditSink,
    stats: Arc<HookStats>,
}

impl Hooks {
    /// Starts the hook thread; clears stale announce files (nothing is
    /// owned at start).
    pub fn spawn(
        announce: Option<PathBuf>,
        withdraw: Option<PathBuf>,
        state_dir: PathBuf,
        daemon_uid: u32,
        timeout: Duration,
        capacity: usize,
        audit: AuditSink,
    ) -> std::io::Result<Self> {
        let ann = state_dir.join("announce.d");
        if std::fs::symlink_metadata(&ann).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(std::io::Error::other(format!("{} is a symbolic link", ann.display())));
        }
        std::fs::create_dir_all(&ann)?;
        std::fs::set_permissions(&ann, std::fs::Permissions::from_mode(0o750))?;
        for e in std::fs::read_dir(&ann)?.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
        let stats = Arc::new(HookStats::default());
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity.max(16));
        let r =
            Runner { announce, withdraw, state_dir, daemon_uid, timeout, audit: audit.clone(), stats: stats.clone() };
        let handle = std::thread::Builder::new().name("plat-cluster-hook".into()).spawn(move || r.run(&rx))?;
        Ok(Self { tx: Some(tx), handle: Some(handle), stats, audit })
    }

    /// Queues a job without blocking; a full queue counts and audits a
    /// failed run.
    pub fn submit(&self, job: HookJob) {
        let Some(tx) = &self.tx else { return };
        if let Err(TrySendError::Full(j) | TrySendError::Disconnected(j)) = tx.try_send(job) {
            if let Some(c) = self.stats.failures.get(kind_ix(j.kind)) {
                c.fetch_add(1, Ordering::Relaxed);
            }
            self.audit.emit(hook_event(&j, None, 0, false));
        }
    }

    /// Runs the queued jobs to the end and stops the thread.
    pub fn join(&mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Hooks {
    fn drop(&mut self) {
        self.join();
    }
}

fn hook_event(j: &HookJob, exit_code: Option<i32>, duration_us: u64, success: bool) -> Event {
    Event::ClusterHook {
        ts_us: Clock::wall_us(),
        run: Arc::new(HookRun {
            hook: j.kind,
            slice: slice_cidr(j.slice),
            epoch: j.epoch,
            exit_code,
            duration_us,
            success,
        }),
    }
}

impl Runner {
    fn run(&self, rx: &Receiver<HookJob>) {
        while let Ok(j) = rx.recv() {
            self.announce_file(&j);
            let path = match j.kind {
                HookKind::Announce => self.announce.as_ref(),
                HookKind::Withdraw => self.withdraw.as_ref(),
            };
            let Some(p) = path else { continue };
            self.stats.runs.fetch_add(1, Ordering::Relaxed);
            let t = Instant::now();
            let code = self.exec(p, &j);
            let ok = code == Some(0);
            if !ok {
                if let Some(c) = self.stats.failures.get(kind_ix(j.kind)) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                tracing::warn!(hook = j.kind.as_str(), slice = %j.slice, ?code, "cluster hook failed");
            }
            self.audit.emit(hook_event(&j, code, t.elapsed().as_micros() as u64, ok));
        }
    }

    fn announce_file(&self, j: &HookJob) {
        let f = self.state_dir.join("announce.d").join(announce_name(j.slice));
        match j.kind {
            HookKind::Announce => {
                let tmp = f.with_extension("tmp");
                let res = std::fs::write(&tmp, format!("{} {}\n", j.epoch, j.reason))
                    .and_then(|()| std::fs::rename(&tmp, &f));
                if let Err(e) = res {
                    tracing::warn!("announce file {}: {e}", f.display());
                }
            }
            HookKind::Withdraw => {
                let _ = std::fs::remove_file(&f);
            }
        }
    }

    /// Exit code, `None` when not started (including a hook that no
    /// longer passes [`check_hook`]) or killed on timeout.
    fn exec(&self, p: &Path, j: &HookJob) -> Option<i32> {
        use std::os::unix::process::CommandExt;
        // SEC-7: the file or a directory above it may have changed since
        // start.
        if let Err(e) = check_hook(p, self.daemon_uid) {
            tracing::error!("cluster hook not run: {e}");
            return None;
        }
        let mut child = Command::new(p)
            .arg(j.slice.to_string())
            .arg(j.epoch.to_string())
            .arg(j.reason)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("PLAT_STATE_DIR", &self.state_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // SEC-6: its own process group, so a timeout (or normal exit)
            // kills whatever it started too. A descendant that calls
            // `setsid`/`setpgid` leaves the group and escapes this kill;
            // hooks are root-owned operator scripts (SEC-7), trusted not to.
            .process_group(0)
            .spawn()
            .ok()?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(st)) => {
                    // SEC-R1-2: reap background children left in the group
                    // after a normal exit too. ESRCH (group already empty) is
                    // the common case and is ignored.
                    let pgid = rustix::process::Pid::from_child(&child);
                    let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
                    return st.code();
                }
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                _ => {
                    let pgid = rustix::process::Pid::from_child(&child);
                    if rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL).is_err() {
                        let _ = child.kill();
                    }
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;
    use crate::test_pki::TempDir;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn job() -> HookJob {
        HookJob { kind: HookKind::Announce, slice: "192.0.2.16/28".parse().unwrap(), epoch: 7, reason: "startup" }
    }

    fn me(d: &TempDir) -> u32 {
        std::fs::metadata(d.path()).unwrap().uid()
    }

    /// SEC-7: a hook in a group- or world-writable directory is refused.
    #[test]
    fn hook_directories_are_checked() {
        let d = TempDir::new("hookdir");
        let ok = script(d.path(), "ok", "exit 0");
        check_hook(&ok, me(&d)).unwrap();
        let open = d.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        let bad = script(&open, "bad", "exit 0");
        let e = check_hook(&bad, me(&d)).unwrap_err();
        assert!(e.contains("hook directory must not be group- or world-writable"), "{e}");
        // Owned by someone else (neither root nor the daemon user).
        let e = check_hook(&ok, me(&d).wrapping_add(4242).max(1)).unwrap_err();
        assert!(e.contains("owned by root"), "{e}");
    }

    /// SEC-6, SEC-7: the hook is re-checked before it runs; a run that
    /// times out is killed with everything it started (process group).
    #[test]
    fn timeout_kills_the_process_group_and_recheck_refuses() {
        let d = TempDir::new("hookrun");
        let pidfile = d.path().join("child.pid");
        let ran = d.path().join("ran");
        let hang = script(d.path(), "hang", &format!("sleep 30 &\necho $! > {}\nwait", pidfile.display()));
        let later = script(d.path(), "later", &format!("touch {}", ran.display()));
        let (sink, rx) = AuditSink::bounded(64);
        let state = TempDir::new("hookstate");
        let mut h = Hooks::spawn(
            Some(hang),
            Some(later.clone()),
            state.path().to_path_buf(),
            me(&d),
            Duration::from_millis(300),
            16,
            sink,
        )
        .unwrap();
        h.submit(job());
        // The withdraw hook became group-writable after start.
        std::fs::set_permissions(&later, std::fs::Permissions::from_mode(0o775)).unwrap();
        h.submit(HookJob { kind: HookKind::Withdraw, ..job() });
        h.join();
        let runs: Vec<_> = rx
            .try_iter()
            .filter_map(|e| match e {
                Event::ClusterHook { run, .. } => Some((run.hook, run.exit_code, run.success)),
                _ => None,
            })
            .collect();
        assert_eq!(runs, vec![(HookKind::Announce, None, false), (HookKind::Withdraw, None, false)]);
        assert!(!ran.exists(), "a hook failing the re-check is not run");
        assert_eq!(h.stats.failures[0].load(Ordering::Relaxed), 1);
        // The background child of the killed hook is gone too.
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        let t = Instant::now();
        while rustix::process::test_kill_process(pid).is_ok() {
            assert!(t.elapsed() < Duration::from_secs(5), "background child {pid:?} survived the timeout");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// SEC-R1-2: a hook that exits normally leaves no background child.
    #[test]
    fn normal_exit_kills_the_process_group() {
        let d = TempDir::new("hookexit");
        let pidfile = d.path().join("child.pid");
        let bg = script(d.path(), "bg", &format!("sleep 30 &\necho $! > {}\nexit 0", pidfile.display()));
        let (sink, _rx) = AuditSink::bounded(64);
        let state = TempDir::new("hookstate2");
        let mut h =
            Hooks::spawn(Some(bg), None, state.path().to_path_buf(), me(&d), Duration::from_secs(5), 16, sink).unwrap();
        h.submit(job());
        h.join();
        assert_eq!(h.stats.failures[0].load(Ordering::Relaxed), 0);
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        let t = Instant::now();
        while rustix::process::test_kill_process(pid).is_ok() {
            assert!(t.elapsed() < Duration::from_secs(5), "background child {pid:?} survived the hook exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
