//! The logger: one thread owns the local hash-chained file (the
//! authoritative AU-9 copy); each syslog destination has its own sender
//! thread behind a bounded hand-off, so a slow or unreachable collector can
//! never stall the file or the event queue.
//!
//! ```text
//!  queue ─▶ plat-audit ─▶ local file (format, hash, checkpoint, rotate)
//!              │  try_send (batch, never blocks)
//!              ├────────▶ plat-syslog-0 ─▶ collector (UDP / TCP / TLS)
//!              └────────▶ plat-syslog-1 ─▶ ...
//! ```
//!
//! File lifecycle. A new file (start-up, size rotation, recovery) is always
//! prepared under a hidden temporary name (`.<name>.new`): header written,
//! flushed and synced. Only then is the live file moved aside
//! (`<name>.<µs>`), the new file renamed into place and the directory
//! synced. A live file that holds no record (header only) is replaced in
//! place instead of rotated, so restarts do not consume retention slots.
//! After a write failure the retry prepares the new file the same way and
//! also writes, checkpoints and syncs the pending batch into it before it is
//! installed; a failed retry leaves nothing behind and rotates or prunes
//! nothing. Retention (`max_files`) runs only after a size rotation, counts
//! only files with a header and at least one checkpoint, and deletes a file
//! only after its `audit_retention_prune` (`scheduled`) record is synced;
//! the result (`deleted` / `failed`) is recorded in the next batch. Rotated
//! files are ordered by their header `next_seq`, not by the wall-clock name.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-5 - file failure sets `AuditStats::degraded` (new
//!   bindings refused under `refuse_new_bindings`, `/healthz` 503) and is
//!   recorded as `audit_output_failure`; recovery is declared only after a
//!   checkpoint in the new file is synced; undelivered remote records are
//!   counted and recorded as `audit_remote_loss` in the local file.
//! - NIST 800-53: AU-5(1) - `min_free_bytes` free-space threshold
//!   (`audit_storage_threshold`, degraded while below or undeterminable).
//! - NIST 800-53: AU-9 - SHA-256 chain across batches and across files;
//!   atomic rotation; chain resumes from the newest file on disk.
//! - NIST 800-53: AU-4, AU-11 - rotation size and `max_files` retention,
//!   each deletion audited (`audit_retention_prune`).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError};
use plat_common::Clock;
use plat_common::config::{AuditConfig, AuditFileConfig, LogFormat, SyslogConfig, SyslogTransport};
use sha2::{Digest, Sha256};

use crate::LOG_SCHEMA_VERSION;
use crate::event::{
    Event, LeaseState, OutputFailureReason, PruneState, RecoveryReason, RemoteLossReason, StorageState,
};
use crate::format;
use crate::sink::{AuditStats, RemoteStats};

/// Identity stamped on every record.
#[derive(Debug, Clone)]
pub struct NodeIdent {
    pub name: String,
    pub id: u16,
    pub pid: u32,
}

/// Source of periodic counter snapshots (drops etc.) for summary records.
pub type CounterSource = Box<dyn Fn() -> Vec<(&'static str, u64)> + Send>;

/// Domain-separation prefix for the hash chain (v2: file header and
/// checkpoint sequence range are bound into the chain).
pub const CHAIN_GENESIS: &[u8] = b"usg-plat audit chain v2";

/// Batches queued per syslog destination before records are counted as
/// remote loss.
const REMOTE_QUEUE_BATCHES: usize = 64;
/// How often a failed local file is retried.
const REOPEN_INTERVAL: Duration = Duration::from_secs(1);
/// TCP/TLS reconnect back-off; records sent during it are counted as lost.
const TCP_BACKOFF: Duration = Duration::from_secs(5);
/// Tail of an existing file read at start-up to find its last checkpoint.
const RESUME_TAIL_BYTES: u64 = 8 << 20;
/// Tail read first when classifying a rotated file for retention.
const CLASSIFY_TAIL_BYTES: u64 = 64 << 10;
/// Largest file considered for [`disposable`] (a header line is ~300 B).
const DISPOSABLE_MAX_BYTES: u64 = 4096;
/// How often free space on the log volume is checked (AU-5(1)).
const SPACE_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Upper bound of a checkpoint line without the node name (~420 B with
/// 20-digit sequence numbers).
const CHECKPOINT_RESERVE: u64 = 512;
/// Sequence numbers reserved per write of the high-water file
/// (`.<name>.seq`): at most one small synced write per this many records.
const SEQ_LEASE: u64 = 1 << 20;

/// Chain value a file starts from: `SHA-256(GENESIS || header line)`. The
/// header line carries the previous file's final chain and sequence
/// numbers, so editing it or dropping a file breaks verification.
pub fn chain_seed(header_line: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_GENESIS);
    h.update(header_line);
    h.finalize().into()
}

/// One checkpoint step: `SHA-256(chain || batch_sha256 || seq_first || seq_last)`
/// (sequence numbers big-endian u64), so the checkpoint's sequence range
/// cannot be edited either.
pub fn chain_step(chain: &[u8; 32], batch: &[u8; 32], seq_first: u64, seq_last: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(chain);
    h.update(batch);
    h.update(seq_first.to_be_bytes());
    h.update(seq_last.to_be_bytes());
    h.finalize().into()
}

/// Where the previous file's verified chain ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Resume {
    /// Final `chain_sha256` (all zero: no predecessor known).
    chain: [u8; 32],
    /// `seq_last` of that checkpoint.
    seq: u64,
    /// Highest record sequence seen, checkpointed or not.
    max_seq: u64,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":");
    let i = line.find(&pat)? + pat.len();
    let rest = line.get(i..)?;
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let end = rest.find(['"', ',', '}']).unwrap_or(rest.len());
    rest.get(..end)
}

/// What a scan of an existing audit file found.
#[derive(Debug, Clone, Copy, Default)]
struct FileInfo {
    resume: Resume,
    /// `next_seq` of the `audit_chain_continue` header on the first line.
    header_next: Option<u64>,
    /// A checkpoint was seen in the scanned tail.
    has_checkpoint: bool,
    len: u64,
}

fn header_next_seq(f: &mut File) -> Option<u64> {
    let mut head = Vec::new();
    f.seek(SeekFrom::Start(0)).ok()?;
    f.take(4096).read_to_end(&mut head).ok()?;
    let line = std::str::from_utf8(head.split(|b| *b == b'\n').next()?).ok()?;
    if field(line, "event.action") != Some("audit_chain_continue") {
        return None;
    }
    field(line, "plat.audit.next_seq")?.parse().ok()
}

/// Reads the header and up to `tail` bytes from the end of an audit file.
/// Best effort: unknown values stay zero / false.
fn inspect(path: &Path, tail: u64) -> Option<FileInfo> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let mut info = FileInfo { len, header_next: header_next_seq(&mut f), ..FileInfo::default() };
    let start = len.saturating_sub(tail);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.take(tail).read_to_end(&mut buf).ok()?;
    // A final line without its newline was cut off (short write, power
    // cut): it is never a usable checkpoint.
    let complete = match buf.iter().rposition(|b| *b == b'\n') {
        Some(i) => buf.get(..=i).unwrap_or_default(),
        None => &[],
    };
    let text = String::from_utf8_lossy(complete);
    let mut lines = text.lines();
    if start > 0 {
        lines.next(); // partial line
    }
    let r = &mut info.resume;
    for line in lines {
        if field(line, "event.action") == Some("audit_checkpoint") {
            let chain = field(line, "plat.audit.chain_sha256").and_then(|h| hex::decode(h).ok());
            let seq = field(line, "plat.audit.seq_last").and_then(|s| s.parse::<u64>().ok());
            if let (Some(c), Some(s)) = (chain, seq)
                && let Ok(c) = <[u8; 32]>::try_from(c.as_slice())
            {
                r.chain = c;
                r.seq = s;
                r.max_seq = r.max_seq.max(s);
                info.has_checkpoint = true;
            }
        } else if let Some(s) = field(line, "event.sequence").and_then(|s| s.parse::<u64>().ok()) {
            r.max_seq = r.max_seq.max(s);
        } else if !info.has_checkpoint && field(line, "event.action") == Some("audit_chain_continue") {
            // A header with no checkpoint after it: keep its predecessor.
            if let (Some(c), Some(s)) = (
                field(line, "plat.audit.prev_chain").and_then(|h| hex::decode(h).ok()),
                field(line, "plat.audit.prev_seq").and_then(|s| s.parse::<u64>().ok()),
            ) && let Ok(c) = <[u8; 32]>::try_from(c.as_slice())
            {
                r.chain = c;
                r.seq = s;
            }
            if let Some(n) = field(line, "plat.audit.next_seq").and_then(|s| s.parse::<u64>().ok()) {
                r.max_seq = r.max_seq.max(n.saturating_sub(1));
            }
        }
    }
    // The header bounds the numbers in use even when the tail shows none.
    if let Some(n) = info.header_next {
        r.max_seq = r.max_seq.max(n.saturating_sub(1));
    }
    Some(info)
}

/// The last checkpoint (and highest sequence) of an existing audit file.
fn read_resume(path: &Path) -> Resume {
    inspect(path, RESUME_TAIL_BYTES).map(|i| i.resume).unwrap_or_default()
}

/// True for an empty file or one holding exactly one complete
/// `audit_chain_continue` header line: it holds no evidence (the next file's
/// header names the same predecessor). Anything else, including content not
/// written by this logger, is kept.
fn disposable(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false };
    let mut buf = Vec::new();
    if Read::by_ref(&mut f).take(DISPOSABLE_MAX_BYTES + 1).read_to_end(&mut buf).is_err() {
        return false;
    }
    if buf.is_empty() {
        return true;
    }
    let Some(line) = buf.strip_suffix(b"\n") else { return false };
    if line.contains(&b'\n') {
        return false;
    }
    header_next_seq(&mut f).is_some()
}

/// Retention view of a rotated file: (header `next_seq`, highest record
/// sequence, last checkpoint chain). `None` without a header or without a
/// checkpoint: such a file is neither counted nor deleted by retention.
type Classified = Option<(u64, u64, [u8; 32])>;

fn classify(path: &Path) -> Classified {
    let mut i = inspect(path, CLASSIFY_TAIL_BYTES)?;
    if !i.has_checkpoint && i.len > CLASSIFY_TAIL_BYTES {
        i = inspect(path, RESUME_TAIL_BYTES)?;
    }
    if !i.has_checkpoint {
        return None;
    }
    Some((i.header_next?, i.resume.max_seq, i.resume.chain))
}

fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// Hidden name a new file is prepared under; never matches `<name>.<µs>`.
fn temp_path(path: &Path) -> PathBuf {
    let mut n = OsString::from(".");
    n.push(path.file_name().unwrap_or_default());
    n.push(".new");
    dir_of(path).join(n)
}

/// Durable sequence high-water mark `.<name>.seq` next to the live file
/// (not matched by the rotated-file pattern).
fn lease_path(path: &Path) -> PathBuf {
    let mut n = OsString::from(".");
    n.push(path.file_name().unwrap_or_default());
    n.push(".seq");
    dir_of(path).join(n)
}

/// The reserved sequence high-water mark and the state it was found in;
/// 0 unless [`LeaseState::Ok`]. Absent: an installation from before it
/// existed. Corrupt: a torn write, or not a regular file; the files decide.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-9, SC-5 - opened without following a symlink and
///   without blocking (a FIFO planted in the log directory cannot hang
///   start-up), and used only if `fstat` on the open descriptor shows a
///   regular file (SEC-304).
fn read_lease(path: &Path) -> (u64, LeaseState) {
    let f = match open_lease(&lease_path(path)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, LeaseState::Absent),
        Err(_) => return (0, LeaseState::Corrupt),
    };
    let mut b = Vec::new();
    if f.take(64).read_to_end(&mut b).is_err() {
        return (0, LeaseState::Corrupt);
    }
    match std::str::from_utf8(&b).ok().and_then(|t| t.strip_suffix('\n')).and_then(|t| t.parse().ok()) {
        Some(v) => (v, LeaseState::Ok),
        None => (0, LeaseState::Corrupt),
    }
}

#[cfg(unix)]
fn open_lease(p: &Path) -> std::io::Result<File> {
    use rustix::fs::{FileType, Mode, OFlags};
    let fd =
        rustix::fs::open(p, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?;
    if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file"));
    }
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_lease(p: &Path) -> std::io::Result<File> {
    let f = File::open(p)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file"));
    }
    Ok(f)
}

/// Durably records that sequence numbers up to `reserved` may be in use:
/// written to a temporary file, synced, renamed over the old one.
fn write_lease(path: &Path, reserved: u64) -> std::io::Result<()> {
    let to = lease_path(path);
    let mut tmp = to.clone().into_os_string();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = create_new(&tmp)?;
        f.write_all(format!("{reserved}\n").as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &to)?;
    sync_dir(&to)
}

/// Rotated files `<path>.<µs>`, oldest first.
fn rotated_files(path: &Path) -> Vec<(u64, PathBuf)> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return Vec::new() };
    let Ok(rd) = std::fs::read_dir(dir_of(path)) else { return Vec::new() };
    let mut v: Vec<(u64, PathBuf)> = rd
        .filter_map(Result::ok)
        .filter_map(|e| {
            let n = e.file_name();
            let ts = n.to_str()?.strip_prefix(name)?.strip_prefix('.')?.parse::<u64>().ok()?;
            Some((ts, e.path()))
        })
        .collect();
    v.sort_unstable();
    v
}

/// Rotated files in chain order, oldest first: by the header `next_seq`
/// (files without a header first), the name's timestamp only as a
/// tiebreak. The wall clock can step backwards between rotations, so the
/// name alone does not give the order (NIST-203 / SEC-201).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-9, AU-11 - retention and resume follow the chain,
///   not the wall clock (AU-8 dependency removed)
fn rotated_in_chain_order(path: &Path) -> Vec<(Option<u64>, u64, PathBuf)> {
    let mut v: Vec<(Option<u64>, u64, PathBuf)> = rotated_files(path)
        .into_iter()
        .map(|(ts, p)| (File::open(&p).ok().and_then(|mut f| header_next_seq(&mut f)), ts, p))
        .collect();
    v.sort_unstable();
    v
}

/// Renames `from` to an unused `<base>.<µs>`.
fn rotate_aside(from: &Path, base: &Path) -> std::io::Result<PathBuf> {
    let mut ts = Clock::wall_us();
    loop {
        let mut to = base.as_os_str().to_owned();
        to.push(format!(".{ts}"));
        let to = PathBuf::from(to);
        if !to.exists() {
            std::fs::rename(from, &to)?;
            return Ok(to);
        }
        ts += 1;
    }
}

/// Makes renames and deletions in the log directory durable (Linux, the
/// deployment target; elsewhere a directory `fsync` is either unsupported or,
/// on macOS, a device-wide cache flush that stalls every other writer).
fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        File::open(dir_of(path))?.sync_all()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Ok(())
    }
}

/// Makes the file's data (and size) durable at a checkpoint: `fdatasync` on
/// Linux; plain `fsync` on other Unix (on macOS `sync_data` would be a
/// device-wide `F_FULLFSYNC` per batch).
fn sync_data(f: &File) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        rustix::fs::fdatasync(f).map_err(std::io::Error::from)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        rustix::fs::fsync(f).map_err(std::io::Error::from)
    }
    #[cfg(not(unix))]
    {
        f.sync_data()
    }
}

/// Bytes available to an unprivileged writer on the volume holding `dir`.
fn available_bytes(dir: &Path) -> std::io::Result<u64> {
    #[cfg(test)]
    if let Some(v) = fault::volume_of(dir) {
        return Ok(u64::try_from(v.load(Ordering::SeqCst)).unwrap_or(0));
    }
    #[cfg(unix)]
    {
        let s = rustix::fs::statvfs(dir)?;
        Ok(s.f_bavail.saturating_mul(s.f_frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// Test seam: a directory with a byte budget behaves like a volume with
/// that much free space (writes past it fail with `StorageFull`; deleting a
/// file written by the logger gives its bytes back).
#[cfg(test)]
pub(crate) mod fault {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicI64;
    use std::sync::{Arc, Mutex};

    static VOLUMES: Mutex<Vec<(PathBuf, Arc<AtomicI64>)>> = Mutex::new(Vec::new());

    /// Gives `dir` a free-space budget; returns the handle to change it.
    pub(crate) fn volume(dir: &Path, free: i64) -> Arc<AtomicI64> {
        let v = Arc::new(AtomicI64::new(free));
        if let Ok(mut g) = VOLUMES.lock() {
            g.push((dir.to_path_buf(), v.clone()));
        }
        v
    }

    static NO_TRUNCATE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Makes every cut-back (`set_len`) of a file under `dir` fail.
    pub(crate) fn fail_truncate(dir: &Path) {
        if let Ok(mut g) = NO_TRUNCATE.lock() {
            g.push(dir.to_path_buf());
        }
    }

    pub(crate) fn truncate_fails(path: &Path) -> bool {
        NO_TRUNCATE.lock().is_ok_and(|g| g.iter().any(|d| path.starts_with(d)))
    }

    pub(crate) fn volume_of(path: &Path) -> Option<Arc<AtomicI64>> {
        let g = VOLUMES.lock().ok()?;
        g.iter().find(|(d, _)| path.starts_with(d)).map(|(_, v)| v.clone())
    }
}

/// The open audit file (a plain `File`; under `cfg(test)` it may sit on a
/// simulated volume, see [`fault`]).
struct AuditFile {
    f: File,
    #[cfg(test)]
    vol: Option<Arc<std::sync::atomic::AtomicI64>>,
    #[cfg(test)]
    written: u64,
    #[cfg(test)]
    no_truncate: bool,
}

impl AuditFile {
    fn new(f: File, _path: &Path) -> Self {
        Self {
            f,
            #[cfg(test)]
            vol: fault::volume_of(_path),
            #[cfg(test)]
            written: 0,
            #[cfg(test)]
            no_truncate: fault::truncate_fails(_path),
        }
    }

    /// Cuts the file back to `len` bytes (the end of its last checkpoint)
    /// and syncs it; a simulated volume gets the cut bytes back.
    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        #[cfg(test)]
        if self.no_truncate {
            return Err(std::io::Error::other("simulated set_len failure"));
        }
        self.f.set_len(len)?;
        self.f.seek(SeekFrom::Start(len))?;
        self.f.sync_all()?;
        #[cfg(test)]
        if let Some(v) = &self.vol {
            v.fetch_add(i64::try_from(self.written.saturating_sub(len)).unwrap_or(0), Ordering::SeqCst);
            self.written = self.written.min(len);
        }
        Ok(())
    }

    /// The file is being deleted: a simulated volume gets its bytes back.
    fn release(self) {
        #[cfg(test)]
        if let Some(v) = &self.vol {
            v.fetch_add(i64::try_from(self.written).unwrap_or(0), Ordering::SeqCst);
        }
    }
}

impl Write for AuditFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        if let Some(v) = &self.vol {
            let left = usize::try_from(v.load(Ordering::SeqCst)).unwrap_or(0);
            if left == 0 && !buf.is_empty() {
                return Err(std::io::Error::new(std::io::ErrorKind::StorageFull, "simulated full volume"));
            }
            let n = self.f.write(&buf[..buf.len().min(left)])?;
            v.fetch_sub(i64::try_from(n).unwrap_or(0), Ordering::SeqCst);
            self.written += n as u64;
            return Ok(n);
        }
        self.f.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

/// Local append-only file with SHA-256 batch checkpoints (AU-9).
///
/// Each file starts with an `audit_chain_continue` header naming the
/// previous file's final chain and sequence numbers; the chain is seeded
/// from that line. Every batch of record lines is hashed; a checkpoint line
/// then records `batch_sha256` and
/// `chain_sha256 = SHA-256(prev_chain || batch_sha256 || seq_first || seq_last)`.
///
/// This is **tamper-evident only against an editor who cannot recompute
/// SHA-256**: the chain is unkeyed, so anyone with write access to the file
/// can rewrite a suffix (or a whole file) and recompute every checkpoint.
/// Editing, inserting, deleting or reordering lines without recomputing is
/// detected by `platd verify-log`, and a rewritten file no longer links to
/// its successor's header. Protection against a privileged rewriter needs
/// the syslog copy on a separate system (AU-9(2)) or keyed/signed
/// checkpoints (POAM-003).
struct FileOut {
    w: BufWriter<AuditFile>,
    bytes: u64,
    /// File length at the end of the last flushed and synced checkpoint
    /// (the header for a new file): the point a failed batch is cut back to.
    durable: u64,
    /// At least one record is in this file.
    has_records: bool,
    /// Length of the last record line written (eager rotation estimate).
    last_line: u64,
    /// Room kept for the checkpoint line when deciding whether a record fits.
    reserve: u64,
    max_bytes: u64,
    batch: Sha256,
    batch_first: Option<u64>,
    chain: [u8; 32],
    /// Temporary name until [`FileOut::install`] moves the file into place.
    tmp: Option<PathBuf>,
}

/// Creates `path` exclusively (any stale file of that name is removed first).
fn create_new(path: &Path) -> std::io::Result<File> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NIST 800-53: AU-9 - owner rw, group r, no world access.
        o.mode(0o640);
    }
    o.open(path)
}

fn header_line(out: &mut Vec<u8>, node: &NodeIdent, prev: &Resume, next_seq: u64) {
    out.clear();
    out.extend_from_slice(b"{\"@timestamp\":\"");
    format::rfc3339(out, Clock::wall_us());
    let _ = writeln!(
        out,
        "\",\"plat.schema\":{LOG_SCHEMA_VERSION},\"event.action\":\"audit_chain_continue\",\"observer.name\":\"{}\",\
         \"plat.node_id\":{},\"plat.audit.prev_chain\":\"{}\",\"plat.audit.prev_seq\":{},\"plat.audit.next_seq\":{next_seq}}}",
        node.name,
        node.id,
        hex::encode(prev.chain),
        prev.seq
    );
}

impl FileOut {
    /// Prepares the next file under its temporary name and writes the header
    /// that links it to `prev`. Nothing at `cfg.path` is touched until
    /// [`FileOut::install`]; on error the temporary file is removed.
    fn prepare(
        cfg: &AuditFileConfig,
        prev: &Resume,
        next_seq: u64,
        node: &NodeIdent,
        scratch: &mut Vec<u8>,
    ) -> std::io::Result<Self> {
        let path = cfg.path.as_path();
        std::fs::create_dir_all(dir_of(path))?;
        let tmp = temp_path(path);
        let f = create_new(&tmp)?;
        header_line(scratch, node, prev, next_seq);
        let mut out = Self {
            w: BufWriter::with_capacity(1 << 20, AuditFile::new(f, &tmp)),
            bytes: scratch.len() as u64,
            durable: scratch.len() as u64,
            has_records: false,
            last_line: 0,
            reserve: CHECKPOINT_RESERVE + node.name.len() as u64,
            max_bytes: cfg.max_bytes,
            batch: Sha256::new(),
            batch_first: None,
            chain: chain_seed(scratch),
            tmp: Some(tmp),
        };
        match out.w.write_all(scratch).and_then(|()| out.w.flush()) {
            Ok(()) => Ok(out),
            Err(e) => {
                out.discard();
                Err(e)
            }
        }
    }

    /// Makes the prepared file the live file: flush and `sync_all` (so the
    /// header, and any checkpoint, is on disk before the name is), move
    /// a live file that holds records aside (`<path>.<µs>`), rename this file
    /// into place (atomically replacing a live file without records), sync
    /// the directory. A header-only file lost in a crash is harmless: start-up
    /// resumes from the newest file that has a checkpoint.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9 - the old file is only renamed, never deleted;
    ///   a crash leaves either the old live file or its rotated copy (start-up
    ///   then resumes from the newest file, see `resume_for`). The file is
    ///   synced before the rename and the directory after it, so a power cut
    ///   cannot leave an empty live file (L12).
    fn install(&mut self, path: &Path) -> std::io::Result<()> {
        self.w.flush()?;
        self.sync()?;
        let Some(tmp) = self.tmp.clone() else { return Ok(()) };
        if path.exists() && !disposable(path) {
            rotate_aside(path, path)?;
        }
        std::fs::rename(&tmp, path)?;
        self.tmp = None;
        sync_dir(path)
    }

    fn record(&mut self, seq: u64, line: &[u8]) -> std::io::Result<()> {
        self.batch_first.get_or_insert(seq);
        self.batch.update(line);
        self.bytes += line.len() as u64;
        self.has_records = true;
        self.last_line = line.len() as u64;
        self.w.write_all(line)
    }

    /// Writes the checkpoint for the current batch, flushes and syncs the
    /// file data. The chain (and the cut-back point) advances only once the
    /// checkpoint is durable.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9, AU-5 - a checkpoint is write + fsync; records
    ///   counted as written survive a power cut (L12).
    // POAM: POAM-003 - checkpoints are an unkeyed SHA-256 chain (integrity
    // against non-privileged edits only); keyed/signed checkpoints pending.
    fn checkpoint(&mut self, last_seq: u64, node: &NodeIdent, scratch: &mut Vec<u8>) -> std::io::Result<()> {
        let Some(first) = self.batch_first.take() else {
            return self.w.flush();
        };
        let digest: [u8; 32] = std::mem::take(&mut self.batch).finalize().into();
        let chain = chain_step(&self.chain, &digest, first, last_seq);
        scratch.clear();
        scratch.extend_from_slice(b"{\"@timestamp\":\"");
        format::rfc3339(scratch, Clock::wall_us());
        let _ = writeln!(
            scratch,
            "\",\"plat.schema\":{LOG_SCHEMA_VERSION},\"event.action\":\"audit_checkpoint\",\"observer.name\":\"{}\",\
             \"plat.node_id\":{},\"plat.audit.seq_first\":{first},\"plat.audit.seq_last\":{last_seq},\
             \"plat.audit.batch_sha256\":\"{}\",\"plat.audit.chain_sha256\":\"{}\"}}",
            node.name,
            node.id,
            hex::encode(digest),
            hex::encode(chain)
        );
        self.bytes += scratch.len() as u64;
        self.w.write_all(scratch)?;
        self.w.flush()?;
        sync_data(&self.w.get_ref().f)?;
        self.chain = chain;
        self.durable = self.bytes;
        Ok(())
    }

    /// Writes the leading records of `batch` that fit under `max_bytes`
    /// (with room for the checkpoint) and checkpoints them; returns how many
    /// were written. A file without records always takes the first record,
    /// so a file exceeds `max_bytes` only by a single oversized record.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-4 - rotation size is a bound, not a trigger checked
    ///   after the batch (L12: 1 MiB files grew to ~1.6 MB).
    fn write_fitting(
        &mut self,
        batch: &[(u64, Event)],
        node: &NodeIdent,
        line: &mut Vec<u8>,
    ) -> std::io::Result<usize> {
        let mut n = 0usize;
        for (seq, ev) in batch {
            line.clear();
            format::json(line, *seq, node, ev);
            line.push(b'\n');
            if self.has_records && self.bytes + line.len() as u64 + self.reserve > self.max_bytes {
                break;
            }
            self.record(*seq, line)?;
            n += 1;
        }
        if let Some(&(last, _)) = n.checked_sub(1).and_then(|i| batch.get(i)) {
            self.checkpoint(last, node, line)?;
        }
        Ok(n)
    }

    /// Writes every record of `batch` and its checkpoint.
    fn write_batch(&mut self, batch: &[(u64, Event)], node: &NodeIdent, line: &mut Vec<u8>) -> std::io::Result<()> {
        for (seq, ev) in batch {
            line.clear();
            format::json(line, *seq, node, ev);
            line.push(b'\n');
            self.record(*seq, line)?;
        }
        let last = batch.last().map_or(0, |(s, _)| *s);
        self.checkpoint(last, node, line)
    }

    fn sync(&self) -> std::io::Result<()> {
        self.w.get_ref().f.sync_all()
    }

    /// A write failed: drops the buffered bytes and cuts the file back to
    /// the end of its last durable checkpoint, so no record of the failed
    /// batch (e.g. a binding that was then refused) and no partial
    /// checkpoint stays on disk outside the chain. A file still under its
    /// temporary name is deleted instead.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9, AU-10 - the failed file ends at a checkpoint and
    ///   verifies; the cut records are counted lost (`audit_output_failure`).
    fn abandon(self) -> std::io::Result<()> {
        if self.tmp.is_some() {
            self.discard();
            return Ok(());
        }
        let durable = self.durable;
        let (mut f, _) = self.w.into_parts();
        f.truncate(durable)
    }

    /// Drops the writer without flushing buffered bytes (the file failed or
    /// was rotated after a flushed checkpoint). A file still under its
    /// temporary name is deleted: it was never part of the chain.
    fn discard(self) {
        let tmp = self.tmp;
        let (f, _) = self.w.into_parts();
        if let Some(t) = tmp {
            let _ = std::fs::remove_file(t);
            f.release();
        }
    }
}

/// Chain and sequence to continue from at start-up: the live file, or the
/// newest rotated file if that holds a later checkpoint (or the live file is
/// missing after a crash or an external move). The highest sequence seen in
/// either is never reused.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-9, AU-10 - the chain and sequence numbers never
///   restart while any audit file is present.
///
/// "Newest rotated file" is the one with the highest header `next_seq`,
/// not the latest name (NIST-203), and every rotated header bounds
/// `max_seq` from below.
fn resume_for(path: &Path) -> Resume {
    let live = path.exists().then(|| read_resume(path));
    let rotated = rotated_in_chain_order(path);
    let header_max = rotated.iter().filter_map(|(n, ..)| *n).max().map_or(0, |n| n.saturating_sub(1));
    let newest = rotated.last().map(|(_, _, p)| read_resume(p));
    let mut r = match (live, newest) {
        (Some(l), Some(n)) => {
            let mut r = if n.seq > l.seq { n } else { l };
            r.max_seq = l.max_seq.max(n.max_seq);
            r
        }
        (Some(r), None) | (None, Some(r)) => r,
        (None, None) => Resume::default(),
    };
    r.max_seq = r.max_seq.max(header_max);
    r
}

/// How the live file left by the previous run is damaged, if it is: empty,
/// without a complete header line, or ending in a partial line (a power
/// cut or short write). Read before the file is replaced or rotated.
fn startup_damage(path: &Path) -> Option<RecoveryReason> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return Some(RecoveryReason::EmptyFile);
    }
    let mut head = Vec::new();
    Read::by_ref(&mut f).take(4096).read_to_end(&mut head).ok()?;
    if !head.contains(&b'\n') || header_next_seq(&mut f).is_none() {
        return Some(RecoveryReason::MissingHeader);
    }
    let mut last = [0u8; 1];
    f.seek(SeekFrom::End(-1)).ok()?;
    f.read_exact(&mut last).ok()?;
    (last[0] != b'\n').then_some(RecoveryReason::TruncatedTail)
}

/// A temporary file left by a crash: removed if it holds no record,
/// otherwise kept as a rotated file so its records stay in the chain.
fn rescue_temp(path: &Path) {
    let tmp = temp_path(path);
    if !tmp.exists() {
        return;
    }
    if disposable(&tmp) {
        let _ = std::fs::remove_file(&tmp);
    } else if let Err(e) = rotate_aside(&tmp, path) {
        tracing::warn!("audit file: keeping {}: {e}", tmp.display());
    }
}

/// A rotated file scheduled for deletion by retention.
struct PruneDue {
    /// Its `scheduled` record is in the batch being written (set when the
    /// batch starts); only armed entries are deleted after a checkpoint.
    armed: bool,
    path: PathBuf,
    rotated_us: u64,
    seq_first: u64,
    seq_last: u64,
    chain_prefix: u64,
}

impl PruneDue {
    fn record(&self, state: PruneState) -> Event {
        Event::RetentionPrune {
            ts_us: Clock::wall_us(),
            rotated_us: self.rotated_us,
            seq_first: self.seq_first,
            seq_last: self.seq_last,
            chain_prefix: self.chain_prefix,
            state,
        }
    }
}

/// The authoritative local file and its failure state.
struct FileDest {
    cfg: AuditFileConfig,
    out: Option<FileOut>,
    /// Last durable point (flushed checkpoint), for the next file's header.
    resume: Resume,
    /// Records not written during the current outage.
    lost: u64,
    next_retry: Instant,
    /// Free space is below `min_free_bytes` (AU-5(1)).
    low: bool,
    next_space_check: Instant,
    /// Rotated files whose `audit_retention_prune` (`scheduled`) records are
    /// in the next batch; deleted once that batch's checkpoint is synced.
    prune_due: Vec<PruneDue>,
    /// Retention classification cache, by rotation time.
    classified: BTreeMap<u64, Classified>,
    /// Highest sequence number durably reserved in `.<name>.seq`.
    lease: u64,
    /// Highest sequence number handed out; the lease must cover it.
    lease_want: u64,
    /// The last lease write failed (one record per failure streak).
    lease_failing: bool,
    /// Next lease write attempt while failing (every flush interval).
    lease_retry: Instant,
    lease_retry_every: Duration,
    /// The sequence space is used up: nothing more is written (SEC-302).
    exhausted: bool,
}

impl FileDest {
    fn new(cfg: AuditFileConfig, out: FileOut, resume: Resume) -> Self {
        let now = Instant::now();
        Self {
            cfg,
            out: Some(out),
            resume,
            lost: 0,
            next_retry: now,
            low: false,
            next_space_check: now,
            prune_due: Vec::new(),
            classified: BTreeMap::new(),
            lease: 0,
            lease_want: 0,
            lease_failing: false,
            lease_retry: now,
            lease_retry_every: REOPEN_INTERVAL,
            exhausted: false,
        }
    }

    /// Reserves sequence numbers up to at least `seq` before any record
    /// numbered above the current reservation reaches a destination, so a
    /// start-up after the newest file was emptied or cut off never reuses
    /// a number (AU-9, AU-10). Also called on every flush tick with `seq`
    /// 0 so a failed write is retried each flush interval, not only at the
    /// next lease boundary; no synced write per batch while it fails.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5 - a failed lease write is counted
    ///   (`seq_lease_failures`, `output_errors`) and announced once per
    ///   failure streak as `audit_output_failure` (`seq_lease_failed`).
    fn reserve(&mut self, seq: u64, stats: &AuditStats) -> Option<Event> {
        self.lease_want = self.lease_want.max(seq);
        let now = Instant::now();
        if self.lease_want <= self.lease || (self.lease_failing && now < self.lease_retry) {
            return None;
        }
        let to = self.lease_want.saturating_add(SEQ_LEASE);
        match write_lease(&self.cfg.path, to) {
            Ok(()) => {
                self.lease = to;
                if std::mem::take(&mut self.lease_failing) {
                    tracing::warn!("audit file {}: sequence high-water mark written again", self.cfg.path.display());
                }
                None
            }
            Err(e) => {
                stats.seq_lease_failures.fetch_add(1, Ordering::Relaxed);
                stats.output_errors.fetch_add(1, Ordering::Relaxed);
                self.lease_retry = now + self.lease_retry_every;
                if std::mem::replace(&mut self.lease_failing, true) {
                    tracing::debug!("audit file {}: sequence high-water mark: {e}", self.cfg.path.display());
                    return None;
                }
                tracing::error!("audit file {}: sequence high-water mark: {e}", self.cfg.path.display());
                Some(Event::OutputFailure {
                    ts_us: Clock::wall_us(),
                    lost: 0,
                    recovered: false,
                    reason: Some(OutputFailureReason::SeqLeaseFailed),
                })
            }
        }
    }

    fn publish(&self, stats: &AuditStats) {
        stats.set_file_state(self.out.is_none() || self.exhausted, self.low);
    }

    /// The file failed: abandon it (buffered bytes are not written), retry
    /// in [`REOPEN_INTERVAL`]. Nothing is rotated, pruned or deleted here;
    /// scheduled prunes get a `failed` result record in `carry`.
    fn fail(&mut self, stats: &AuditStats, e: &std::io::Error, carry: &mut Vec<Event>) {
        if let Some(f) = self.out.take() {
            f.discard();
        }
        carry.extend(self.prune_due.drain(..).map(|d| d.record(PruneState::Failed)));
        stats.output_errors.fetch_add(1, Ordering::Relaxed);
        self.next_retry = Instant::now() + REOPEN_INTERVAL;
        self.publish(stats);
        tracing::error!("audit file {}: {e}; new bindings refused until it recovers", self.cfg.path.display());
    }

    /// AU-5(1): at most every [`SPACE_CHECK_INTERVAL`], compares free space
    /// with `min_free_bytes`; returns the record for a crossing. Recovery
    /// needs 10 % above the threshold so the state does not flap.
    fn check_space(&mut self, stats: &AuditStats) -> Option<Event> {
        let min = self.cfg.min_free_bytes;
        if min == 0 {
            return None;
        }
        let now = Instant::now();
        if now < self.next_space_check {
            return None;
        }
        self.next_space_check = now + SPACE_CHECK_INTERVAL;
        let available = match available_bytes(dir_of(&self.cfg.path)) {
            Ok(a) => a,
            // COMPLIANCE MAPPING:
            // - NIST 800-53: AU-5(1) - free space that cannot be determined
            //   is treated as below the threshold (fail closed) and recorded
            //   once (SEC-204); it clears when a check succeeds again with
            //   enough space.
            Err(e) => {
                stats.output_errors.fetch_add(1, Ordering::Relaxed);
                if self.low {
                    tracing::debug!("audit volume free space: {e}");
                    return None;
                }
                self.low = true;
                self.publish(stats);
                tracing::error!("audit volume free space cannot be determined ({e}); new bindings refused");
                return Some(Event::StorageThreshold {
                    ts_us: Clock::wall_us(),
                    available: 0,
                    threshold: min,
                    state: StorageState::Unknown,
                });
            }
        };
        let below = if !self.low && available < min {
            true
        } else if self.low && available >= min.saturating_add(min / 10) {
            false
        } else {
            return None;
        };
        self.low = below;
        self.publish(stats);
        if below {
            tracing::error!("audit volume has {available} bytes free (< min_free_bytes {min}); new bindings refused");
        } else {
            tracing::warn!("audit volume has {available} bytes free again");
        }
        let state = if below { StorageState::Below } else { StorageState::Recovered };
        Some(Event::StorageThreshold { ts_us: Clock::wall_us(), available, threshold: min, state })
    }

    /// After a size rotation: queues an `audit_retention_prune` record for
    /// each of the oldest rotated files beyond `max_files`. Only files with
    /// a header and at least one checkpoint count; others are kept.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-4, AU-11 - bounded retention by file count.
    /// - NIST 800-53: AU-9, AU-2 - every deletion is itself an audit record
    ///   in the live chain (and sent to syslog) before the file goes.
    fn schedule_prune(&mut self, carry: &mut Vec<Event>) {
        let max = self.cfg.max_files as usize;
        if max == 0 {
            return;
        }
        let files = rotated_files(&self.cfg.path);
        let present: std::collections::BTreeSet<u64> = files.iter().map(|(ts, _)| *ts).collect();
        self.classified.retain(|ts, _| present.contains(ts));
        let mut real = Vec::new();
        for (ts, p) in files {
            // Already scheduled by an earlier rotation in the same batch.
            if self.prune_due.iter().any(|d| d.rotated_us == ts) {
                continue;
            }
            if let Some(c) = *self.classified.entry(ts).or_insert_with(|| classify(&p)) {
                real.push((ts, p, c));
            }
        }
        // Oldest by chain position (header `next_seq`), not by the
        // wall-clock name (NIST-203 / SEC-201).
        real.sort_unstable_by_key(|(ts, _, (next, ..))| (*next, *ts));
        let excess = real.len().saturating_sub(max);
        for (ts, path, (seq_first, seq_last, chain)) in real.into_iter().take(excess) {
            let mut head = [0u8; 8];
            head.copy_from_slice(&chain[..8]);
            let due = PruneDue {
                armed: false,
                path,
                rotated_us: ts,
                seq_first,
                seq_last,
                chain_prefix: u64::from_be_bytes(head),
            };
            carry.push(due.record(PruneState::Scheduled));
            self.classified.remove(&ts);
            self.prune_due.push(due);
        }
    }

    /// Deletes the files whose `scheduled` prune records were just
    /// checkpointed, after syncing that checkpoint, and queues each result
    /// (`deleted` / `failed`) in `carry` for the next batch.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-3, AU-9, AU-11 - the log states what retention
    ///   actually removed (NIST-202); a failed prune is retried, with a new
    ///   `scheduled` record, at the next rotation.
    fn run_prune(&mut self, f: &FileOut, stats: &AuditStats, carry: &mut Vec<Event>) {
        if !self.prune_due.iter().any(|d| d.armed) {
            return;
        }
        let (due, later): (Vec<PruneDue>, Vec<PruneDue>) = self.prune_due.drain(..).partition(|d| d.armed);
        self.prune_due = later;
        if let Err(e) = f.sync() {
            stats.output_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("audit retention postponed: {e}");
            carry.extend(due.into_iter().map(|d| d.record(PruneState::Failed)));
            return;
        }
        for d in due {
            let state = match std::fs::remove_file(&d.path) {
                Ok(()) => {
                    tracing::info!("audit retention: removed {}", d.path.display());
                    PruneState::Deleted
                }
                Err(e) => {
                    stats.output_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("audit retention: removing {}: {e}", d.path.display());
                    PruneState::Failed
                }
            };
            carry.push(d.record(state));
        }
        if let Err(e) = sync_dir(&self.cfg.path) {
            tracing::warn!("audit retention: syncing directory: {e}");
        }
    }
}

/// Wire connection of one syslog destination.
enum SyslogConn {
    Udp(UdpSocket),
    Tcp(Option<BufWriter<TcpStream>>, Option<Instant>),
    #[cfg(feature = "tls")]
    Tls(Box<TlsDest>),
}

/// One RFC 5425 destination: TLS 1.3 over TCP, verified against the
/// configured CA and `server_name`, full-chain revocation (stapled OCSP for
/// the leaf), optional client certificate.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: SC-8, SC-8(1), AU-9(2) - audit records leave the box
///   only inside TLS (no plaintext fallback)
/// - NIST 800-53: IA-3, IA-5(2)(b)(1) - collector authenticated by certificate,
///   revocation checked on this sender thread (never the logger thread)
/// - RFC 5425 §4.2 (TLS), §4.3 (octet counting), §4.4 (close_notify),
///   §5.2 (server name); TLS 1.3 only (documented deviation from the
///   RFC 5425 TLS 1.2 mandatory suite)
#[cfg(feature = "tls")]
struct TlsDest {
    config: Arc<rustls::ClientConfig>,
    name: rustls_pki_types::ServerName<'static>,
    conn: Option<(rustls::ClientConnection, TcpStream)>,
    last_try: Option<Instant>,
    /// Handshake deadline: `max(2 s, revocation budget + 1 s)`.
    handshake: Duration,
    /// Cause of the current outage (attributed to back-off losses too).
    down: Option<RemoteLossReason>,
}

/// How long a connect waits after the handshake for the collector to
/// reject our certificate (or our lack of one): in TLS 1.3 the server
/// verifies the client only after the client's Finished. Connects are rare
/// (start, after an outage), so this costs nothing in steady state.
#[cfg(feature = "tls")]
const CLIENT_CERT_VERDICT_WAIT: Duration = Duration::from_millis(300);

/// Connect and write timeout of a stream destination.
const STREAM_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(feature = "tls")]
impl TlsDest {
    fn new(cfg: &SyslogConfig, opts: Option<&crate::tls::TlsOptions>) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let invalid =
            |e: plat_tls::TlsError| Error::new(ErrorKind::InvalidInput, format!("syslog {}: {e}", cfg.address));
        let Some(t) = &cfg.tls else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("syslog {}: [audit.syslog.tls] missing", cfg.address),
            ));
        };
        let Some(opts) = opts else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("syslog {}: TLS transport needs Logger::with_tls", cfg.address),
            ));
        };
        let checker = opts.checker_for(t).map_err(invalid)?;
        let rev = checker.settings();
        let budget = if rev.mode == plat_common::config::RevocationMode::Off { Duration::ZERO } else { rev.budget };
        let handshake = STREAM_TIMEOUT.max(budget + Duration::from_secs(1));
        let settings = plat_tls::ClientSettings::from_config(t, opts.pq_hybrid, Some(checker));
        let config = plat_tls::client_config(&settings).map_err(invalid)?;
        let name = plat_tls::policy::server_name(&t.server_name).map_err(invalid)?;
        Ok(Self { config, name, conn: None, last_try: None, handshake, down: None })
    }

    /// Connects and completes the handshake (certificate and revocation
    /// checks run here, bounded by `handshake`).
    fn connect(&mut self, addr: &SocketAddr) -> Result<(), RemoteLossReason> {
        use plat_tls::stream::FailureClass;
        let mut sock = TcpStream::connect_timeout(addr, STREAM_TIMEOUT).map_err(|e| {
            tracing::warn!("syslog {addr}: {e}");
            RemoteLossReason::Io
        })?;
        let _ = sock.set_nodelay(true);
        let mut conn = rustls::ClientConnection::new(self.config.clone(), self.name.clone()).map_err(|e| {
            tracing::warn!("syslog {addr}: TLS: {e}");
            RemoteLossReason::TlsHandshake
        })?;
        let mut res = plat_tls::stream::handshake(&mut conn, &mut sock, Instant::now() + self.handshake);
        if res.is_ok() {
            res = plat_tls::stream::await_rejection(&mut conn, &mut sock, CLIENT_CERT_VERDICT_WAIT);
        }
        if let Err(e) = res {
            tracing::warn!("syslog {addr}: {e}");
            return Err(match e.class() {
                FailureClass::Io => RemoteLossReason::Io,
                FailureClass::Revoked | FailureClass::RevocationUnknown => RemoteLossReason::TlsRevocation,
                FailureClass::BadCertificate | FailureClass::NoCertificate => RemoteLossReason::TlsVerify,
                FailureClass::Timeout | FailureClass::Handshake => RemoteLossReason::TlsHandshake,
            });
        }
        self.conn = Some((conn, sock));
        Ok(())
    }
}

/// One syslog destination, owned by its sender thread.
struct SyslogOut {
    cfg: SyslogConfig,
    conn: SyslogConn,
    stats: Arc<RemoteStats>,
}

impl SyslogOut {
    fn new(cfg: SyslogConfig, tls: Option<&TlsOptionsRef>) -> std::io::Result<Self> {
        let conn = match cfg.transport {
            SyslogTransport::Udp => {
                let bind: SocketAddr = if cfg.address.is_ipv4() {
                    ([0, 0, 0, 0], 0).into()
                } else {
                    (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
                };
                let s = UdpSocket::bind(bind)?;
                s.connect(cfg.address)?;
                SyslogConn::Udp(s)
            }
            SyslogTransport::Tcp => SyslogConn::Tcp(None, None),
            #[cfg(feature = "tls")]
            SyslogTransport::Tls => SyslogConn::Tls(Box::new(TlsDest::new(&cfg, tls)?)),
            // Built without TLS: refuse rather than send in the clear (SC-8).
            #[cfg(not(feature = "tls"))]
            SyslogTransport::Tls => {
                let _: Option<&TlsOptionsRef> = tls;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "syslog transport \"tls\" is not available in this build (built without the `tls` feature)",
                ));
            }
        };
        let transport = match cfg.transport {
            SyslogTransport::Udp => "udp",
            SyslogTransport::Tcp => "tcp",
            SyslogTransport::Tls => "tls",
        };
        let stats = Arc::new(RemoteStats::new(cfg.address, transport));
        Ok(Self { cfg, conn, stats })
    }

    fn format(&self, seq: u64, node: &NodeIdent, ev: &Event, msg: &mut Vec<u8>) {
        msg.clear();
        format::syslog_header(msg, node, &self.cfg.app_name, ev);
        match self.cfg.format {
            LogFormat::Json => format::json(msg, seq, node, ev),
            LogFormat::Cef => format::cef(msg, seq, node, ev),
        }
    }

    /// RFC 6587 §3.4.1 / RFC 5425 §4.3 octet counting: `MSG-LEN SP MSG`.
    fn frame(&self, batch: &[(u64, Event)], node: &NodeIdent, msg: &mut Vec<u8>, buf: &mut Vec<u8>) {
        buf.clear();
        for (seq, ev) in batch {
            self.format(*seq, node, ev, msg);
            let _ = write!(buf, "{} ", msg.len());
            buf.extend_from_slice(msg);
        }
    }

    /// Sends one batch. Returns the number of records not delivered and
    /// the number of failed operations; the cause of a loss is noted in
    /// `stats` for the next `audit_remote_loss` record.
    ///
    /// UDP is one datagram (one `send` syscall) per record: RFC 5426 allows
    /// one message per datagram, and batching with `sendmmsg` would need
    /// `unsafe` FFI outside `plat-io`. The cost stays on this thread, off the
    /// file path. TCP and TLS (octet counting) are one write per batch; on
    /// failure the whole batch is counted as lost (some frames may have
    /// arrived), and records during the reconnect back-off are lost.
    fn send_batch(
        &mut self,
        batch: &[(u64, Event)],
        node: &NodeIdent,
        msg: &mut Vec<u8>,
        buf: &mut Vec<u8>,
    ) -> (u64, u64) {
        let n = batch.len() as u64;
        match self.conn {
            SyslogConn::Udp(ref s) => {
                // POAM: POAM-018 one datagram (one syscall) per record; no
                // sendmmsg / UDP GSO batching yet.
                let mut lost = 0;
                for (seq, ev) in batch {
                    self.format(*seq, node, ev, msg);
                    if s.send(msg).is_err() {
                        lost += 1;
                    }
                }
                if lost > 0 {
                    self.stats.note_loss(RemoteLossReason::Io);
                }
                (lost, u64::from(lost > 0))
            }
            SyslogConn::Tcp(..) => {
                self.frame(batch, node, msg, buf);
                let SyslogConn::Tcp(conn, last_try) = &mut self.conn else { return (0, 0) };
                if conn.is_none() {
                    if last_try.is_some_and(|t| t.elapsed() < TCP_BACKOFF) {
                        self.stats.note_loss(RemoteLossReason::Io);
                        return (n, 0);
                    }
                    *last_try = Some(Instant::now());
                    match TcpStream::connect_timeout(&self.cfg.address, STREAM_TIMEOUT).and_then(|s| {
                        s.set_nodelay(true)?;
                        s.set_write_timeout(Some(STREAM_TIMEOUT))?;
                        Ok(s)
                    }) {
                        Ok(s) => *conn = Some(BufWriter::with_capacity(1 << 20, s)),
                        Err(e) => {
                            tracing::warn!("syslog {}: {e}", self.cfg.address);
                            self.stats.count_failure(RemoteLossReason::Io);
                            self.stats.note_loss(RemoteLossReason::Io);
                            return (n, 1);
                        }
                    }
                }
                let res = match conn.as_mut() {
                    Some(w) => w.write_all(buf).and_then(|()| w.flush()),
                    None => Ok(()),
                };
                match res {
                    Ok(()) => (0, 0),
                    Err(e) => {
                        tracing::warn!("syslog {}: {e}", self.cfg.address);
                        *conn = None;
                        self.stats.count_failure(RemoteLossReason::Io);
                        self.stats.note_loss(RemoteLossReason::Io);
                        (n, 1)
                    }
                }
            }
            #[cfg(feature = "tls")]
            SyslogConn::Tls(..) => {
                self.frame(batch, node, msg, buf);
                let SyslogConn::Tls(t) = &mut self.conn else { return (0, 0) };
                if t.conn.is_none() {
                    if t.last_try.is_some_and(|at| at.elapsed() < TCP_BACKOFF) {
                        self.stats.note_loss(t.down.unwrap_or(RemoteLossReason::Io));
                        return (n, 0);
                    }
                    t.last_try = Some(Instant::now());
                    match t.connect(&self.cfg.address) {
                        Ok(()) => {
                            t.down = None;
                            self.stats.tls_handshakes.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(r) => {
                            t.down = Some(r);
                            self.stats.count_failure(r);
                            self.stats.note_loss(r);
                            return (n, 1);
                        }
                    }
                }
                let Some((conn, sock)) = t.conn.as_mut() else { return (n, 0) };
                match plat_tls::stream::write_all(conn, sock, buf, Instant::now() + STREAM_TIMEOUT) {
                    Ok(()) => (0, 0),
                    Err(e) => {
                        tracing::warn!("syslog {}: {e}", self.cfg.address);
                        t.conn = None;
                        t.down = Some(RemoteLossReason::Io);
                        self.stats.count_failure(RemoteLossReason::Io);
                        self.stats.note_loss(RemoteLossReason::Io);
                        (n, 1)
                    }
                }
            }
        }
    }

    /// Orderly close at shutdown: TLS sends `close_notify` (RFC 5425 §4.4),
    /// bounded by the write timeout.
    fn close(&mut self) {
        match &mut self.conn {
            SyslogConn::Udp(_) => {}
            SyslogConn::Tcp(conn, _) => {
                if let Some(w) = conn.as_mut() {
                    let _ = w.flush();
                }
            }
            #[cfg(feature = "tls")]
            SyslogConn::Tls(t) => {
                if let Some((conn, sock)) = t.conn.as_mut() {
                    plat_tls::stream::close(conn, sock, STREAM_TIMEOUT);
                }
                t.conn = None;
            }
        }
    }
}

#[cfg(feature = "tls")]
type TlsOptionsRef = crate::tls::TlsOptions;
/// Placeholder so `SyslogOut::new` has one signature in both builds.
#[cfg(not(feature = "tls"))]
type TlsOptionsRef = ();

type Batch = Arc<Vec<(u64, Event)>>;

/// The logger thread's handle to one syslog sender thread.
struct Remote {
    tx: Option<Sender<Batch>>,
    addr: SocketAddr,
    remote: Arc<RemoteStats>,
    /// Records not delivered (written by the sender thread and on hand-off).
    lost: Arc<AtomicU64>,
    reported: u64,
    thread: Option<JoinHandle<()>>,
}

impl Remote {
    fn spawn(out: SyslogOut, i: usize, node: NodeIdent, stats: Arc<AuditStats>) -> std::io::Result<Self> {
        let (tx, rx) = crossbeam_channel::bounded::<Batch>(REMOTE_QUEUE_BATCHES);
        let lost = Arc::new(AtomicU64::new(0));
        let addr = out.cfg.address;
        let remote = out.stats.clone();
        let l = lost.clone();
        let thread = std::thread::Builder::new().name(format!("plat-syslog-{i}")).spawn(move || {
            let mut out = out;
            let (mut msg, mut buf) = (Vec::with_capacity(512), Vec::with_capacity(1 << 16));
            for batch in rx.iter() {
                let (n, errors) = out.send_batch(&batch, &node, &mut msg, &mut buf);
                if n > 0 {
                    l.fetch_add(n, Ordering::Relaxed);
                }
                if errors > 0 {
                    stats.output_errors.fetch_add(errors, Ordering::Relaxed);
                }
            }
            out.close();
        })?;
        Ok(Self { tx: Some(tx), addr, remote, lost, reported: 0, thread: Some(thread) })
    }

    /// Hands a batch over without blocking; a full queue is remote loss.
    fn offer(&self, batch: &Batch) {
        let Some(tx) = &self.tx else { return };
        match tx.try_send(batch.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.lost.fetch_add(batch.len() as u64, Ordering::Relaxed);
            }
        }
    }

    /// A `RemoteLoss` record for losses not yet reported.
    fn loss_event(&mut self, stats: &AuditStats) -> Option<Event> {
        let l = self.lost.load(Ordering::Relaxed);
        if l <= self.reported {
            return None;
        }
        let d = l - self.reported;
        self.reported = l;
        stats.remote_lost.fetch_add(d, Ordering::Relaxed);
        // `plat.reason`: the cause noted by the sender thread; absent when
        // the only losses were a full hand-off queue.
        Some(Event::RemoteLoss {
            ts_us: Clock::wall_us(),
            ip: self.addr.ip(),
            port: self.addr.port(),
            lost: d,
            reason: self.remote.take_reason(),
        })
    }

    /// Closes the hand-off and waits for queued batches to be sent.
    fn close(&mut self) {
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Builder for the logger thread.
pub struct Logger {
    cfg: AuditConfig,
    node: NodeIdent,
    rx: Receiver<Event>,
    stats: Arc<AuditStats>,
    counters: Option<CounterSource>,
    #[cfg(feature = "tls")]
    tls: Option<crate::tls::TlsOptions>,
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logger").field("node", &self.node).finish_non_exhaustive()
    }
}

/// Join handle for the logger thread.
#[derive(Debug)]
pub struct LoggerHandle(JoinHandle<()>);

impl LoggerHandle {
    /// Waits for the logger to drain. Drop every `AuditSink` clone first.
    pub fn join(self) {
        let _ = self.0.join();
    }
}

/// Numbers `events` (drained) with consecutive sequence numbers after
/// `seq`; returns the numbered batch and how many events were dropped.
/// Every batch leaves one number free: when the 64-bit space cannot hold
/// the events plus that one, they are dropped and the last number goes to
/// an `audit_output_failure` (`seq_exhausted`); afterwards everything is
/// dropped (`exhausted`). Never wraps (release builds do not check overflow).
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-5, AU-10 - sequence exhaustion fails closed and is
///   announced; no number is ever reused (SEC-302).
fn number(events: &mut Vec<Event>, seq: &mut u64, exhausted: &mut bool) -> (Vec<(u64, Event)>, u64) {
    let n = events.len() as u64;
    if !*exhausted && seq.checked_add(n.saturating_add(1)).is_some() {
        let first = *seq;
        let batch = (first + 1..).zip(events.drain(..)).collect();
        *seq = first + n;
        return (batch, 0);
    }
    events.clear();
    if std::mem::replace(exhausted, true) {
        return (Vec::new(), n);
    }
    match seq.checked_add(1) {
        Some(s) => {
            *seq = s;
            let ev = Event::OutputFailure {
                ts_us: Clock::wall_us(),
                lost: n,
                recovered: false,
                reason: Some(OutputFailureReason::SeqExhausted),
            };
            (vec![(s, ev)], n)
        }
        None => (Vec::new(), n),
    }
}

/// Start-up found no sequence number left to continue with.
fn exhausted_error() -> std::io::Error {
    std::io::Error::other("audit sequence space exhausted (SEC-302); archive the audit files and reset the chain")
}

impl Logger {
    pub fn new(cfg: AuditConfig, node: NodeIdent, rx: Receiver<Event>, stats: Arc<AuditStats>) -> Self {
        Self {
            cfg,
            node,
            rx,
            stats,
            counters: None,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    /// TLS syslog policy and the shared revocation checker. Required when
    /// any destination uses `transport = "tls"` (else `spawn` fails).
    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, opts: crate::tls::TlsOptions) -> Self {
        self.tls = Some(opts);
        self
    }

    pub fn with_counters(mut self, src: CounterSource) -> Self {
        self.counters = Some(src);
        self
    }

    /// Opens every destination (failing fast on configuration errors) and
    /// starts the threads. The new file continues the chain and sequence
    /// numbers of the newest file on disk; a previous live file holding
    /// records is moved aside, one holding none is replaced. Nothing is
    /// deleted at start-up.
    pub fn spawn(self) -> std::io::Result<LoggerHandle> {
        let mut scratch = Vec::with_capacity(512);
        let mut seq = 0u64;
        let mut carry = Vec::new();
        let file = match &self.cfg.file {
            Some(f) => {
                let damage = startup_damage(&f.path);
                rescue_temp(&f.path);
                let resume = resume_for(&f.path);
                let (mut lease, mut lease_state) = read_lease(&f.path);
                // COMPLIANCE MAPPING:
                // - NIST 800-53: AU-9, AU-10, SC-5 - the lease is used whenever
                //   it is below the wrap guard, so no sequence number is ever
                //   reused even when the files holding the top numbers are
                //   gone (`high` when it is more than one lease above the
                //   files). Only a value near u64::MAX, which would burn the
                //   sequence space, is ignored as `inflated` (SEC-302).
                if lease_state == LeaseState::Ok {
                    if lease > u64::MAX - 2 * SEQ_LEASE {
                        lease_state = LeaseState::Inflated;
                    } else if lease > resume.max_seq.saturating_add(SEQ_LEASE) {
                        lease_state = LeaseState::High;
                    }
                }
                if !matches!(lease_state, LeaseState::Ok | LeaseState::High) {
                    lease = 0;
                }
                if lease_state == LeaseState::High {
                    tracing::warn!(
                        "audit file {}: sequence high-water mark {} is more than one lease above the files; used",
                        f.path.display(),
                        lease_path(&f.path).display()
                    );
                }
                if matches!(lease_state, LeaseState::Inflated | LeaseState::Corrupt) {
                    tracing::warn!(
                        "audit file {}: sequence high-water mark {} is {}; ignored",
                        f.path.display(),
                        lease_path(&f.path).display(),
                        lease_state.as_str()
                    );
                }
                // Fail closed: an inflated lease next to files that are
                // themselves above the wrap guard leaves nothing safe to
                // number from (SEC-302).
                if lease_state == LeaseState::Inflated && resume.max_seq > u64::MAX - 2 * SEQ_LEASE {
                    return Err(exhausted_error());
                }
                seq = resume.max_seq;
                // COMPLIANCE MAPPING:
                // - NIST 800-53: AU-9, AU-10 - after damage the files no
                //   longer show every number used (an emptied file held
                //   records); resume above the durable high-water mark so
                //   no sequence number is reused. The skipped range is
                //   announced by `audit_recovery` (`max_seq`).
                if damage.is_some() {
                    seq = seq.max(lease);
                }
                // COMPLIANCE MAPPING:
                // - NIST 800-53: AU-5, AU-9 - a damaged newest file (power
                //   cut) is announced by an `audit_recovery` record so the
                //   SIEM sees a possible gap after the last durable checkpoint.
                if let Some(reason) = damage {
                    tracing::warn!(
                        "audit file {}: {}; records after sequence {} may be lost",
                        f.path.display(),
                        reason.as_str(),
                        resume.seq
                    );
                    carry.push(Event::AuditRecovery {
                        ts_us: Clock::wall_us(),
                        reason,
                        last_checkpoint_seq: resume.seq,
                        max_seq: seq,
                        lease_state,
                    });
                }
                // Fail closed: no sequence number left to continue with.
                let next = seq.checked_add(2).map(|_| seq + 1).ok_or_else(exhausted_error)?;
                let mut out = FileOut::prepare(f, &resume, next, &self.node, &mut scratch)?;
                if let Err(e) = out.install(&f.path) {
                    out.discard();
                    return Err(e);
                }
                let mut fd = FileDest::new(f.clone(), out, resume);
                fd.lease = lease;
                fd.lease_retry_every = Duration::from_millis(self.cfg.flush_interval_ms).max(Duration::from_millis(1));
                fd.publish(&self.stats);
                Some(fd)
            }
            None => None,
        };
        #[cfg(feature = "tls")]
        let tls = self.tls.as_ref();
        #[cfg(not(feature = "tls"))]
        let tls: Option<&TlsOptionsRef> = None;
        // Fail closed: an unreadable CA, certificate or key, or a bad
        // server name, stops the start (no plaintext fallback).
        let outs = self.cfg.syslog.iter().cloned().map(|c| SyslogOut::new(c, tls)).collect::<Result<Vec<_>, _>>()?;
        self.stats.set_remotes(outs.iter().map(|o| o.stats.clone()).collect());
        let remotes = outs
            .into_iter()
            .enumerate()
            .map(|(i, o)| Remote::spawn(o, i, self.node.clone(), self.stats.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let h = std::thread::Builder::new()
            .name("plat-audit".into())
            .spawn(move || self.run(file, remotes, seq, scratch, carry))?;
        Ok(LoggerHandle(h))
    }

    fn run(
        self,
        mut file: Option<FileDest>,
        mut remotes: Vec<Remote>,
        mut seq: u64,
        mut line: Vec<u8>,
        mut carry: Vec<Event>,
    ) {
        let flush_every = Duration::from_millis(self.cfg.flush_interval_ms);
        let summary_every = Duration::from_secs(self.cfg.summary_interval_secs);
        let mut last_summary = Instant::now();
        let mut lost_reported = 0u64;
        let mut pending: Vec<Event> = Vec::with_capacity(self.cfg.batch_max);
        let mut exhausted = false;

        loop {
            let first = self.rx.recv_timeout(flush_every);
            let disconnected = matches!(first, Err(RecvTimeoutError::Disconnected));
            pending.append(&mut carry);
            if let Ok(ev) = first {
                pending.push(ev);
                pending.extend(self.rx.try_iter().take(self.cfg.batch_max - 1));
            }

            // AU-5: report lost records as soon as the logger sees them.
            let lost = self.stats.lost.load(Ordering::Relaxed);
            if lost > lost_reported {
                pending.push(Event::QueueOverflow { ts_us: Clock::wall_us(), lost: lost - lost_reported });
                lost_reported = lost;
            }
            pending.extend(remotes.iter_mut().filter_map(|r| r.loss_event(&self.stats)));
            if !summary_every.is_zero() && last_summary.elapsed() >= summary_every {
                last_summary = Instant::now();
                if let Some(src) = &self.counters {
                    let ts_us = Clock::wall_us();
                    pending.extend(src().into_iter().map(|(name, value)| Event::Counter { ts_us, name, value }));
                }
            }

            let mut recover = false;
            if let Some(fd) = file.as_mut() {
                pending.extend(fd.check_space(&self.stats));
                // SEC-303: a failed lease write is retried every tick.
                pending.extend(fd.reserve(0, &self.stats));
                // A due retry of a failed file leads with the `recovered`
                // record; it is rewritten to `degraded` if the retry fails.
                if fd.out.is_none() && !fd.exhausted && !disconnected && Instant::now() >= fd.next_retry {
                    recover = true;
                    pending.insert(
                        0,
                        Event::OutputFailure { ts_us: Clock::wall_us(), lost: fd.lost, recovered: true, reason: None },
                    );
                }
            }
            if !pending.is_empty() {
                let (mut batch, dropped) = number(&mut pending, &mut seq, &mut exhausted);
                if !batch.is_empty() {
                    self.write_file(file.as_mut(), &mut batch, recover, &mut line, &mut carry);
                    let batch: Batch = Arc::new(batch);
                    for r in &remotes {
                        r.offer(&batch);
                    }
                }
                self.count_dropped(dropped);
                if exhausted {
                    self.stop_exhausted(file.as_mut());
                }
            }

            if disconnected {
                for r in &mut remotes {
                    r.close();
                }
                // Final remote losses (e.g. the collector was down at stop),
                // and records produced by the last writes (retention).
                let mut tail: Vec<Event> = remotes.iter_mut().filter_map(|r| r.loss_event(&self.stats)).collect();
                for _ in 0..4 {
                    tail.append(&mut carry);
                    if tail.is_empty() {
                        break;
                    }
                    let (mut batch, dropped) = number(&mut tail, &mut seq, &mut exhausted);
                    if !batch.is_empty() {
                        self.write_file(file.as_mut(), &mut batch, false, &mut line, &mut carry);
                    }
                    self.count_dropped(dropped);
                }
                if let Some(f) = file.as_ref().and_then(|fd| fd.out.as_ref())
                    && f.sync().is_err()
                {
                    self.stats.output_errors.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
    }

    /// Retries a failed file with this batch (led by the `recovered`
    /// record): the new file is prepared under its temporary name, the batch
    /// is written and checkpointed, the file is synced, and only then is it
    /// moved into place and `degraded` cleared. A failed retry removes the
    /// temporary file; nothing is rotated or pruned.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-5 - recovery is declared only once a checkpoint in
    ///   the new file is durable, and not while free space is below
    ///   `min_free_bytes` (AU-5(1)); no fail-open window on a full disk.
    /// - NIST 800-53: AU-9, AU-11 - retries never delete or rotate files.
    fn recover(&self, fd: &mut FileDest, batch: &[(u64, Event)], line: &mut Vec<u8>) -> bool {
        fd.next_retry = Instant::now() + REOPEN_INTERVAL;
        let (Some(&(first, _)), Some(&(last, _))) = (batch.first(), batch.last()) else { return false };
        if fd.low {
            return false;
        }
        let res = FileOut::prepare(&fd.cfg, &fd.resume, first, &self.node, line).and_then(|mut nf| {
            match nf.write_batch(batch, &self.node, line).and_then(|()| nf.install(&fd.cfg.path)) {
                Ok(()) => Ok(nf),
                Err(e) => {
                    nf.discard();
                    Err(e)
                }
            }
        });
        match res {
            Ok(nf) => {
                fd.resume = Resume { chain: nf.chain, seq: last, max_seq: last };
                fd.out = Some(nf);
                self.stats.written.fetch_add(batch.len() as u64, Ordering::Relaxed);
                tracing::warn!("audit file {} recovered; {} records were not written", fd.cfg.path.display(), fd.lost);
                fd.lost = 0;
                fd.publish(&self.stats);
                true
            }
            Err(e) => {
                self.stats.output_errors.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("audit file retry: {e}");
                false
            }
        }
    }

    /// Writes one batch to the file (if configured), checkpoints, rotates.
    /// `written` counts only records whose checkpoint was flushed.
    fn write_file(
        &self,
        file: Option<&mut FileDest>,
        batch: &mut [(u64, Event)],
        recover: bool,
        line: &mut Vec<u8>,
        carry: &mut Vec<Event>,
    ) {
        let n = batch.len() as u64;
        let Some(fd) = file else {
            self.stats.written.fetch_add(n, Ordering::Relaxed);
            return;
        };
        if let Some(&(last, _)) = batch.last() {
            carry.extend(fd.reserve(last, &self.stats));
        }
        let Some(mut f) = fd.out.take() else {
            if !(recover && self.recover(fd, batch, line)) {
                // Still down: the other destinations must not be told otherwise.
                if let Some((_, Event::OutputFailure { recovered, .. })) = batch.first_mut() {
                    *recovered = false;
                }
                fd.lost += n;
                self.stats.file_lost.fetch_add(n, Ordering::Relaxed);
            }
            return;
        };
        // The `scheduled` prune records carried from the last rotation are
        // in this batch.
        for d in &mut fd.prune_due {
            d.armed = true;
        }
        let mut rest: &[(u64, Event)] = batch;
        loop {
            let k = match f.write_fitting(rest, &self.node, line) {
                Ok(k) => k,
                Err(e) => {
                    // L12: cut the file back to its last checkpoint; the
                    // records of this chunk are lost, never half on disk.
                    // COMPLIANCE MAPPING:
                    // - NIST 800-53: AU-5, AU-9 - a failed cut-back leaves
                    //   records outside the chain; it is announced with its
                    //   own reason, not only counted (SEC-7).
                    if let Err(te) = f.abandon() {
                        self.stats.output_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::error!("audit file {}: cutting back a failed batch: {te}", fd.cfg.path.display());
                        carry.push(Event::OutputFailure {
                            ts_us: Clock::wall_us(),
                            lost: 0,
                            recovered: false,
                            reason: Some(OutputFailureReason::TruncateFailed),
                        });
                    }
                    self.file_failed(fd, &e, rest.len() as u64, carry);
                    return;
                }
            };
            let (done, left) = rest.split_at(k.min(rest.len()));
            rest = left;
            if let Some(&(last, _)) = done.last() {
                self.stats.written.fetch_add(done.len() as u64, Ordering::Relaxed);
                fd.resume = Resume { chain: f.chain, seq: last, max_seq: last };
                // Retention records from the previous rotation are in this
                // batch: delete their files now that it is checkpointed.
                fd.run_prune(&f, &self.stats, carry);
            }
            // Rotate once a record like the last one would no longer fit,
            // so an idle file is not left one record short of full.
            if rest.is_empty() && f.bytes + f.reserve + f.last_line <= f.max_bytes {
                fd.out = Some(f);
                return;
            }
            // Full (the next record does not fit, or one like the last
            // would not): rotate, then write the rest into the new file.
            let rotated = f.sync().and_then(|()| {
                let next = fd.resume.max_seq.checked_add(1).ok_or_else(exhausted_error)?;
                let mut nf = FileOut::prepare(&fd.cfg, &fd.resume, next, &self.node, line)?;
                match nf.install(&fd.cfg.path) {
                    Ok(()) => Ok(nf),
                    Err(e) => {
                        nf.discard();
                        Err(e)
                    }
                }
            });
            f.discard();
            match rotated {
                Ok(nf) => {
                    f = nf;
                    fd.schedule_prune(carry);
                }
                Err(e) => {
                    self.file_failed(fd, &e, rest.len() as u64, carry);
                    return;
                }
            }
            if rest.is_empty() {
                fd.out = Some(f);
                return;
            }
        }
    }

    /// Events dropped because the sequence space is used up: counted as
    /// not written to the file (AU-5).
    fn count_dropped(&self, dropped: u64) {
        if dropped > 0 {
            self.stats.file_lost.fetch_add(dropped, Ordering::Relaxed);
            self.stats.output_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// SEC-302: the sequence space is used up. The file (holding the
    /// `seq_exhausted` record, checkpointed) is synced and closed for good;
    /// the logger stays degraded so new bindings are refused (fail closed).
    fn stop_exhausted(&self, file: Option<&mut FileDest>) {
        let Some(fd) = file else {
            self.stats.set_file_state(true, false);
            return;
        };
        if std::mem::replace(&mut fd.exhausted, true) {
            return;
        }
        if let Some(f) = fd.out.take() {
            if f.sync().is_err() {
                self.stats.output_errors.fetch_add(1, Ordering::Relaxed);
            }
            f.discard();
        }
        fd.publish(&self.stats);
        tracing::error!(
            "audit file {}: sequence space exhausted; audit output stopped, new bindings refused",
            fd.cfg.path.display()
        );
    }

    /// The live file failed with `lost` records of the batch not written:
    /// degraded, counted, and announced to the remaining destinations (AU-5).
    fn file_failed(&self, fd: &mut FileDest, e: &std::io::Error, lost: u64, carry: &mut Vec<Event>) {
        fd.fail(&self.stats, e, carry);
        fd.lost += lost;
        self.stats.file_lost.fetch_add(lost, Ordering::Relaxed);
        carry.push(Event::OutputFailure { ts_us: Clock::wall_us(), lost, recovered: false, reason: None });
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use plat_common::config::{AuditMode, OverflowPolicy};

    use super::*;
    use crate::sink::AuditSink;
    use crate::verify::{GapAccount, LinkIssue, VerifyReport, link, verify};

    fn cfg(path: &Path, max_bytes: u64, max_files: u32, min_free_bytes: u64) -> AuditConfig {
        AuditConfig {
            mode: AuditMode::PortBlock,
            queue_capacity: 4096,
            on_overflow: OverflowPolicy::RefuseNewBindings,
            batch_max: 8,
            flush_interval_ms: 10,
            summary_interval_secs: 0,
            file: Some(AuditFileConfig { path: path.into(), max_bytes, max_files, min_free_bytes }),
            syslog: vec![],
        }
    }

    fn ev(i: u16) -> Event {
        Event::PortBlockAlloc {
            ts_us: 1_793_196_960_000_000,
            sub: 0x2001_0db8 << 96,
            sub_len: 64,
            v4: 0xc000_0201,
            port_lo: i,
            port_hi: i.wrapping_add(511),
        }
    }

    fn node() -> NodeIdent {
        NodeIdent { name: "plat-unit".into(), id: 3, pid: 1 }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("plat-audit-unit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn wait(what: &str, f: impl Fn() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn written(s: &AuditStats) -> u64 {
        s.written.load(Ordering::Relaxed)
    }

    fn rotated_names(path: &Path) -> Vec<PathBuf> {
        rotated_files(path).into_iter().map(|(_, p)| p).collect()
    }

    /// Every audit file in `dir`, verified, oldest first.
    fn verified(dir: &Path) -> Vec<(PathBuf, VerifyReport)> {
        let mut v: Vec<(PathBuf, VerifyReport)> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("audit.jsonl"))
            .map(|p| {
                let r = verify(BufReader::new(File::open(&p).unwrap())).unwrap();
                assert!(r.ok(), "{}: {r:?}", p.display());
                (p, r)
            })
            .collect();
        v.sort_by_key(|(_, r)| r.next_seq);
        v
    }

    fn issues(v: &[(PathBuf, VerifyReport)]) -> Vec<LinkIssue> {
        link(&v.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>())
    }

    /// Keeps `degraded` asserted for `d` while offering records, as the data
    /// plane would.
    fn hold_degraded(sink: &AuditSink, d: Duration, what: &str) {
        let t = Instant::now();
        let mut i = 0u16;
        while t.elapsed() < d {
            assert!(sink.stats().degraded(), "{what}: degraded cleared without a durable checkpoint");
            assert!(!sink.has_room(), "{what}: refuse_new_bindings must stay engaged");
            sink.emit(ev(i));
            i = i.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// NIST-101 / SEC-103 and NIST-102 regression on a simulated full
    /// volume: an outage longer than `max_files` retry intervals neither
    /// rotates nor deletes any file, leaves no fragments, and `degraded`
    /// never clears, including when the header of a retry fits but its
    /// batch does not. Repair recovers with one gap of exactly `file_lost`.
    #[test]
    fn full_volume_never_rotates_prunes_or_flaps() {
        let dir = tmpdir("full");
        let vol = fault::volume(&dir, i64::MAX / 2);
        let path = dir.join("audit.jsonl");
        let (sink, rx) = AuditSink::bounded(4096);
        let stats = sink.stats().clone();
        let h = Logger::new(cfg(&path, 4096, 2, 0), node(), rx, stats.clone()).spawn().unwrap();
        for i in 0..300 {
            assert!(sink.emit(ev(i)));
        }
        wait("records", || written(&stats) >= 300 && sink.queued() == 0);
        // The last batch may still be in flight (each checkpoint is synced);
        // the last rotation's prune records go out with the next batch and
        // its files are deleted after that checkpoint.
        std::thread::sleep(Duration::from_millis(300));
        wait("retention settled", || rotated_names(&path).len() == 2);
        std::thread::sleep(Duration::from_millis(100));
        let before = rotated_names(&path);
        assert_eq!(before.len(), 2, "{before:?}");

        // Disk full.
        vol.store(0, Ordering::SeqCst);
        for i in 0..20 {
            sink.emit(ev(1000 + i));
        }
        wait("degraded", || stats.degraded());
        assert!(stats.file_down() && !stats.storage_low());
        let errors = stats.output_errors.load(Ordering::Relaxed);
        hold_degraded(&sink, Duration::from_millis(3500), "full volume");
        assert!(stats.output_errors.load(Ordering::Relaxed) >= errors + 3, "retries happened");
        wait("no temporary file", || !temp_path(&path).exists());
        assert_eq!(rotated_names(&path), before, "NIST-101: nothing rotated or deleted during the outage");

        // Nearly full: a retry's header fits, its batch does not.
        vol.store(400, Ordering::SeqCst);
        hold_degraded(&sink, Duration::from_millis(2500), "header fits");
        wait("failed retries leave no file and no bytes behind", || {
            !temp_path(&path).exists() && vol.load(Ordering::SeqCst) == 400
        });
        assert_eq!(rotated_names(&path), before, "NIST-101: nothing rotated or deleted during the outage");

        // Space freed: recovers, and the failed live file is kept.
        vol.store(i64::MAX / 2, Ordering::SeqCst);
        wait("recovered", || !stats.degraded());
        // One record: more could fill the 4 KiB file, rotate it and let
        // retention prune `before` legitimately.
        assert!(sink.emit(ev(2000)));
        drop(sink);
        h.join();
        for p in &before {
            assert!(p.exists(), "{} survived the outage", p.display());
        }
        let lost = stats.file_lost.load(Ordering::Relaxed);
        assert!(lost > 0);
        let files = verified(&dir);
        assert_eq!(files.len(), before.len() + 2, "rotated + failed live file + new live file");
        let newest = std::fs::read_to_string(&files.last().unwrap().0).unwrap();
        let first_record = newest.lines().nth(1).unwrap();
        assert!(first_record.contains("\"plat.audit.state\":\"recovered\""), "{first_record}");
        assert!(first_record.contains(&format!("\"plat.audit.lost\":{lost}")), "{first_record} lost={lost}");
        let is = issues(&files);
        assert_eq!(is.len(), 1, "{is:?}");
        match &is[0] {
            LinkIssue::Gap { first, last, accounted, .. } => {
                assert!(last - first + 1 == lost && *accounted == Some(GapAccount::OutputFailure), "{is:?}")
            }
            other => panic!("{other:?}"),
        }
    }

    /// AU-5(1): below `min_free_bytes` the pipeline is degraded (bindings
    /// refused) but records keep being written; it clears only 10 % above
    /// the threshold. Both crossings are recorded.
    #[test]
    fn free_space_threshold_degrades_and_recovers() {
        let dir = tmpdir("threshold");
        let vol = fault::volume(&dir, 10_000_000);
        let path = dir.join("audit.jsonl");
        let (sink, rx) = AuditSink::bounded(4096);
        let stats = sink.stats().clone();
        let h = Logger::new(cfg(&path, 1 << 30, 0, 1_000_000), node(), rx, stats.clone()).spawn().unwrap();
        for i in 0..5 {
            sink.emit(ev(i));
        }
        wait("records", || written(&stats) >= 5);
        assert!(!stats.degraded());

        vol.store(500_000, Ordering::SeqCst);
        wait("storage low", || stats.storage_low());
        assert!(stats.degraded() && !stats.file_down() && !sink.has_room());
        let w = written(&stats);
        for i in 0..5 {
            assert!(sink.emit(ev(100 + i)));
        }
        wait("records still written while low", || written(&stats) >= w + 5);

        vol.store(1_050_000, Ordering::SeqCst); // above the threshold, below +10 %
        std::thread::sleep(Duration::from_millis(1500));
        assert!(stats.storage_low(), "hysteresis");
        vol.store(5_000_000, Ordering::SeqCst);
        wait("recovered", || !stats.degraded());
        drop(sink);
        h.join();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"plat.audit.state\":\"below_threshold\",\"plat.audit.available_bytes\":"), "{text}");
        assert!(text.contains("\"event.action\":\"audit_storage_threshold\""));
        assert!(text.contains("\"plat.audit.state\":\"recovered\",\"plat.audit.available_bytes\":"));
        assert!(verify(text.as_bytes()).unwrap().ok());
    }

    /// SEC-105: a crash can leave the newest records in the temporary file
    /// and no live file. Start-up keeps that file as a rotated file and
    /// continues its chain and sequence numbers.
    #[test]
    fn startup_keeps_a_crashed_temporary_file_and_continues_its_chain() {
        let dir = tmpdir("rescue");
        let path = dir.join("audit.jsonl");
        for (n, base) in [(10u16, 0u16), (5, 100)] {
            let (sink, rx) = AuditSink::bounded(1024);
            let h = Logger::new(cfg(&path, 1 << 30, 0, 0), node(), rx, sink.stats().clone()).spawn().unwrap();
            for i in 0..n {
                sink.emit(ev(base + i));
            }
            drop(sink);
            h.join();
            if base == 0 {
                // Crash between "rename live aside" and "rename new file in".
                std::fs::rename(&path, temp_path(&path)).unwrap();
            }
        }
        assert!(!temp_path(&path).exists());
        let files = verified(&dir);
        assert_eq!(files.iter().map(|(_, r)| r.next_seq).collect::<Vec<_>>(), vec![1, 11]);
        assert!(issues(&files).is_empty(), "{:?}", issues(&files));
    }

    fn file_dest(dir: &Path, min_free_bytes: u64) -> FileDest {
        let fcfg = AuditFileConfig { path: dir.join("audit.jsonl"), max_bytes: 1 << 30, max_files: 2, min_free_bytes };
        let mut scratch = Vec::new();
        let mut out = FileOut::prepare(&fcfg, &Resume::default(), 1, &node(), &mut scratch).unwrap();
        out.install(&fcfg.path).unwrap();
        FileDest::new(fcfg, out, Resume::default())
    }

    /// SEC-204: when free space cannot be determined, the threshold fails
    /// closed (degraded) and is recorded once, as state `unknown`; a later
    /// successful check with enough space recovers.
    #[test]
    fn undeterminable_free_space_fails_closed_once() {
        let dir = tmpdir("statvfs");
        let stats = AuditSink::bounded(1).0.stats().clone();
        let mut fd = file_dest(&dir, 1_000_000);
        fd.cfg.path = dir.join("no-such-dir").join("audit.jsonl");
        let ev = fd.check_space(&stats);
        assert!(
            matches!(ev, Some(Event::StorageThreshold { state: StorageState::Unknown, threshold: 1_000_000, .. })),
            "{ev:?}"
        );
        assert!(stats.storage_low() && stats.degraded());
        assert_eq!(stats.output_errors.load(Ordering::Relaxed), 1);
        fd.next_space_check = Instant::now();
        assert_eq!(fd.check_space(&stats), None, "recorded once");
        assert!(stats.degraded(), "still fail closed");
        fd.cfg.path = dir.join("audit.jsonl");
        let _vol = fault::volume(&dir, 10_000_000);
        fd.next_space_check = Instant::now();
        let ev = fd.check_space(&stats);
        assert!(matches!(ev, Some(Event::StorageThreshold { state: StorageState::Recovered, .. })), "{ev:?}");
        assert!(!stats.degraded());
    }

    /// NIST-202: each scheduled prune gets a result record with the real
    /// outcome: `deleted`, or `failed` when the unlink fails or the file
    /// fails before the deletion.
    #[test]
    fn prune_results_record_the_real_outcome() {
        let dir = tmpdir("pruneresult");
        let stats = AuditSink::bounded(1).0.stats().clone();
        let mut fd = file_dest(&dir, 0);
        let due = |path: PathBuf, rotated_us| PruneDue {
            armed: true,
            path,
            rotated_us,
            seq_first: 1,
            seq_last: 2,
            chain_prefix: 7,
        };
        let present = dir.join("audit.jsonl.1");
        std::fs::write(&present, b"x").unwrap();
        fd.prune_due.push(due(present.clone(), 1));
        fd.prune_due.push(due(dir.join("audit.jsonl.2"), 2)); // unlink fails
        let f = fd.out.take().unwrap();
        let mut carry = Vec::new();
        fd.run_prune(&f, &stats, &mut carry);
        assert!(!present.exists());
        let states: Vec<(u64, PruneState)> = carry
            .iter()
            .filter_map(|e| match *e {
                Event::RetentionPrune { rotated_us, state, .. } => Some((rotated_us, state)),
                _ => None,
            })
            .collect();
        assert_eq!(states, vec![(1, PruneState::Deleted), (2, PruneState::Failed)]);
        assert_eq!(carry[1].outcome(), Some("failure"));
        // A file failure before the deletion records `failed`, not nothing.
        fd.out = Some(f);
        fd.prune_due.push(due(dir.join("audit.jsonl.3"), 3));
        let mut carry = Vec::new();
        fd.fail(&stats, &std::io::Error::other("test"), &mut carry);
        assert!(matches!(carry[..], [Event::RetentionPrune { rotated_us: 3, state: PruneState::Failed, .. }]));
        assert!(fd.prune_due.is_empty());
    }

    /// A header-only temporary file holds nothing and is simply removed.
    #[test]
    fn startup_removes_an_empty_temporary_file() {
        let dir = tmpdir("emptytmp");
        let path = dir.join("audit.jsonl");
        let mut header = Vec::new();
        header_line(&mut header, &node(), &Resume::default(), 1);
        std::fs::write(temp_path(&path), &header).unwrap();
        let (sink, rx) = AuditSink::bounded(1024);
        let h = Logger::new(cfg(&path, 1 << 30, 0, 0), node(), rx, sink.stats().clone()).spawn().unwrap();
        sink.emit(ev(1));
        drop(sink);
        h.join();
        assert!(!temp_path(&path).exists());
        assert_eq!(verified(&dir).len(), 1);
    }

    fn run_once(path: &Path, c: AuditConfig, events: impl Iterator<Item = Event>) {
        let (sink, rx) = AuditSink::bounded(4096);
        let h = Logger::new(c, node(), rx, sink.stats().clone()).spawn().unwrap();
        for e in events {
            assert!(sink.emit(e));
        }
        drop(sink);
        h.join();
        assert!(path.exists());
    }

    /// L12 regression: the volume accepts part of a batch (a short write)
    /// and then fails with ENOSPC. The failed file is cut back to its last
    /// checkpoint: it verifies with no tail, no record of the failed batch
    /// (bindings then refused) stays on disk, and the failed batch shows up
    /// as exactly the counted gap.
    #[test]
    fn short_write_then_enospc_cuts_back_to_the_last_checkpoint() {
        let dir = tmpdir("shortwrite");
        let vol = fault::volume(&dir, i64::MAX / 2);
        let path = dir.join("audit.jsonl");
        let (sink, rx) = AuditSink::bounded(4096);
        let stats = sink.stats().clone();
        let h = Logger::new(cfg(&path, 1 << 30, 0, 0), node(), rx, stats.clone()).spawn().unwrap();
        for i in 0..10 {
            assert!(sink.emit(ev(i)));
        }
        wait("records", || written(&stats) >= 10);
        let good = std::fs::metadata(&path).unwrap().len();

        // Room for one record and half a checkpoint, as seen on ext4/xfs.
        let mut one = Vec::new();
        format::json(&mut one, 11, &node(), &ev(5000));
        vol.store(i64::try_from(one.len() + 200).unwrap(), Ordering::SeqCst);
        for i in 0..8 {
            sink.emit(ev(5000 + i));
        }
        wait("degraded", || stats.degraded());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.len() as u64, good, "cut back to the last checkpoint");
        assert!(text.lines().last().unwrap().contains("\"event.action\":\"audit_checkpoint\""));
        assert!(!text.contains("\"source.port\":5000") && !text.contains(":5000,"), "{text}");
        let r = verify(text.as_bytes()).unwrap();
        assert!(r.ok() && !r.has_unverified_tail(), "{r:?}");

        vol.store(i64::MAX / 2, Ordering::SeqCst);
        wait("recovered", || !stats.degraded());
        drop(sink);
        h.join();
        let lost = stats.file_lost.load(Ordering::Relaxed);
        assert!(lost >= 8, "the failed batch is counted lost: {lost}");
        let files = verified(&dir);
        assert!(files.iter().all(|(_, r)| !r.has_unverified_tail()), "{files:?}");
        let is = issues(&files);
        assert!(
            matches!(is[..], [LinkIssue::Gap { first, last, accounted: Some(GapAccount::OutputFailure), .. }] if last - first + 1 == lost),
            "{is:?}"
        );
    }

    /// L12 regression: a power cut left a partial final line (the newest
    /// file did not end at a checkpoint). `verify` reports a truncated tail,
    /// not a chain mismatch; start-up continues from the last complete
    /// checkpoint (the next header links), and writes `audit_recovery`.
    #[test]
    fn truncated_tail_is_unverified_and_the_next_file_links() {
        let dir = tmpdir("trunctail");
        let path = dir.join("audit.jsonl");
        run_once(&path, cfg(&path, 1 << 30, 0, 0), (0..20).map(ev));
        let text = std::fs::read(&path).unwrap();
        std::fs::write(&path, &text[..text.len() - 40]).unwrap(); // mid-checkpoint
        let r = verify(&text[..text.len() - 40]).unwrap();
        assert!(r.ok(), "{r:?}");
        assert!(r.truncated_tail_bytes > 0 && r.has_unverified_tail(), "{r:?}");

        let (lease, _) = read_lease(&path);
        assert!(lease > r.last_seq, "high-water mark {lease} covers {}", r.last_seq);
        run_once(&path, cfg(&path, 1 << 30, 0, 0), (100..103).map(ev));
        let files = verified(&dir);
        assert_eq!(files.len(), 2);
        // The partial record's number is never reused: numbering resumes
        // above the high-water mark, and the skipped range is announced.
        assert_eq!(files[1].1.next_seq, lease + 1);
        let is = issues(&files);
        assert!(
            matches!(is[..], [LinkIssue::Gap { last, accounted: Some(GapAccount::Recovery), .. }] if last == lease),
            "{is:?}"
        );
        let newest = std::fs::read_to_string(&path).unwrap();
        let first = newest.lines().nth(1).unwrap();
        assert!(first.contains("\"event.action\":\"audit_recovery\""), "{first}");
        assert!(first.contains("\"plat.reason\":\"truncated_tail\""), "{first}");
        let lcs = files[0].1.last_checkpoint_seq;
        assert!(first.contains(&format!("\"plat.audit.last_checkpoint_seq\":{lcs},")), "{first} {lcs}");
    }

    /// L12 regression: power cut left a 0-byte live file. Start-up replaces
    /// it and the first record is `audit_recovery` naming the last durable
    /// sequence, a visible gap signal for the SIEM.
    #[test]
    fn startup_with_an_empty_newest_file_records_audit_recovery() {
        let dir = tmpdir("emptylive");
        let path = dir.join("audit.jsonl");
        run_once(&path, cfg(&path, 1 << 30, 0, 0), (0..5).map(ev));
        std::fs::rename(&path, dir.join("audit.jsonl.1")).unwrap();
        File::create(&path).unwrap();
        let (lease, _) = read_lease(&path);
        assert!(lease >= 5, "{lease}");
        run_once(&path, cfg(&path, 1 << 30, 0, 0), (10..12).map(ev));
        let newest = std::fs::read_to_string(&path).unwrap();
        let first = newest.lines().nth(1).unwrap();
        assert!(first.contains("\"event.action\":\"audit_recovery\""), "{first}");
        assert!(first.contains("\"plat.reason\":\"empty_file\""), "{first}");
        assert!(
            first.contains(&format!("\"plat.audit.last_checkpoint_seq\":5,\"plat.audit.max_seq\":{lease}")),
            "{first}"
        );
        let files = verified(&dir);
        let is = issues(&files);
        assert!(
            matches!(is[..], [LinkIssue::Gap { first: 6, last, accounted: Some(GapAccount::Recovery), .. }] if last == lease),
            "{is:?}"
        );

        // results-run2 L12 emulation: the file holding the recovery record
        // is moved aside and the live file emptied; the next recovery record
        // must not reuse its number (nor any other number used before).
        let used = files.iter().map(|(_, r)| r.last_seq).max().unwrap();
        std::fs::rename(&path, dir.join("audit.jsonl.2")).unwrap();
        File::create(&path).unwrap();
        run_once(&path, cfg(&path, 1 << 30, 0, 0), (30..32).map(ev));
        let text = std::fs::read_to_string(&path).unwrap();
        let r = verify(text.as_bytes()).unwrap();
        assert!(r.ok() && r.next_seq > used, "resumed at {} after {used} was used", r.next_seq);
        assert!(text.contains("\"plat.audit.lease_state\":\"ok\""), "{text}");
        // Lose the evidence: that file is deleted too, so the lease is more
        // than one lease above every file; it is still used (`high`) and no
        // number is reused (SEC-302).
        let used = used.max(r.last_seq);
        std::fs::remove_file(dir.join("audit.jsonl.2")).unwrap();
        std::fs::write(&path, b"").unwrap();
        run_once(&path, cfg(&path, 1 << 30, 0, 0), std::iter::once(ev(40)));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"plat.audit.lease_state\":\"high\""), "{text}");
        let r = verify(text.as_bytes()).unwrap();
        assert!(r.ok() && r.next_seq > used, "resumed at {} after {used} was used", r.next_seq);
        // A clean restart writes no recovery record.
        run_once(&path, cfg(&path, 1 << 30, 0, 0), std::iter::once(ev(20)));
        assert!(!std::fs::read_to_string(&path).unwrap().contains("audit_recovery"));
    }

    /// SEC-7: when the cut-back after a failed batch itself fails, the
    /// failure is counted and announced as `audit_output_failure` with
    /// `plat.reason:"truncate_failed"` (to the remaining destinations).
    #[test]
    fn failed_cut_back_is_announced_with_its_own_reason() {
        let dir = tmpdir("notruncate");
        let vol = fault::volume(&dir, i64::MAX / 2);
        fault::fail_truncate(&dir);
        let path = dir.join("audit.jsonl");
        let collector = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        collector.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut c = cfg(&path, 1 << 30, 0, 0);
        c.syslog = vec![SyslogConfig {
            address: collector.local_addr().unwrap(),
            transport: SyslogTransport::Udp,
            format: LogFormat::Json,
            app_name: "platd".into(),
            tls: None,
        }];
        let (sink, rx) = AuditSink::bounded(4096);
        let stats = sink.stats().clone();
        let h = Logger::new(c, node(), rx, stats.clone()).spawn().unwrap();
        for i in 0..4 {
            assert!(sink.emit(ev(i)));
        }
        wait("records", || written(&stats) >= 4);
        let errors = stats.output_errors.load(Ordering::Relaxed);
        vol.store(200, Ordering::SeqCst);
        for i in 0..8 {
            sink.emit(ev(5000 + i));
        }
        wait("degraded", || stats.degraded());
        assert!(stats.output_errors.load(Ordering::Relaxed) > errors, "the failed cut-back is counted");
        let mut got = false;
        let mut b = [0u8; 4096];
        let t = Instant::now();
        while !got && t.elapsed() < Duration::from_secs(5) {
            if let Ok(n) = collector.recv(&mut b) {
                let s = String::from_utf8_lossy(&b[..n]);
                got = s.contains("\"event.action\":\"audit_output_failure\"")
                    && s.contains("\"plat.reason\":\"truncate_failed\"");
            }
        }
        assert!(got, "audit_output_failure (truncate_failed) sent to syslog");
        drop(sink);
        h.join();
    }

    /// L12 regression: with large batches, rotated files used to exceed
    /// `max_bytes` by most of a batch. Now a file exceeds it only when a
    /// single record does not fit into an empty file.
    #[test]
    fn rotation_never_exceeds_max_bytes() {
        let dir = tmpdir("rotbound");
        let path = dir.join("audit.jsonl");
        let mut c = cfg(&path, 8192, 0, 0);
        c.batch_max = 256;
        c.flush_interval_ms = 200;
        run_once(&path, c, (0..1000).map(ev));
        let files = verified(&dir);
        assert!(files.len() > 10, "{}", files.len());
        for (p, _) in &files {
            let len = std::fs::metadata(p).unwrap().len();
            assert!(len <= 8192, "{}: {len} bytes", p.display());
        }
        assert!(issues(&files).is_empty(), "{:?}", issues(&files));
        assert_eq!(files.iter().map(|(_, r)| r.records).sum::<u64>(), 1000);
    }

    /// A rotated file holding only a header that starts at `next_seq`, so
    /// start-up resumes near the end of the sequence space.
    fn header_only(dir: &Path, next_seq: u64) {
        let mut h = Vec::new();
        header_line(&mut h, &node(), &Resume::default(), next_seq);
        std::fs::write(dir.join("audit.jsonl.1"), h).unwrap();
    }

    /// SEC-302: a lease above the wrap guard (near u64::MAX) is ignored and
    /// recorded as `inflated`; numbering resumes from the files and nothing
    /// wraps. One just below the guard is used (`high`).
    #[test]
    fn inflated_lease_is_ignored_and_recorded() {
        let dir = tmpdir("inflated");
        let path = dir.join("audit.jsonl");
        run_once(&path, cfg(&path, 1 << 30, 0, 0), (0..5).map(ev));
        for planted in [u64::MAX, u64::MAX - 2 * SEQ_LEASE + 1] {
            std::fs::write(lease_path(&path), format!("{planted}\n")).unwrap();
            assert_eq!(read_lease(&path), (planted, LeaseState::Ok));
            std::fs::write(&path, b"").unwrap(); // damaged: the lease would be used
            run_once(&path, cfg(&path, 1 << 30, 0, 0), std::iter::once(ev(9)));
            let text = std::fs::read_to_string(&path).unwrap();
            let first = text.lines().nth(1).unwrap();
            assert!(first.contains("\"plat.audit.lease_state\":\"inflated\""), "{first}");
            let r = verify(text.as_bytes()).unwrap();
            assert!(r.ok() && r.next_seq < 100, "{r:?}");
            let (lease, state) = read_lease(&path);
            assert_eq!(state, LeaseState::Ok);
            assert!(lease > r.last_seq && lease <= r.last_seq + SEQ_LEASE, "rewritten: {lease}");
        }
        let planted = u64::MAX - 2 * SEQ_LEASE;
        std::fs::write(lease_path(&path), format!("{planted}\n")).unwrap();
        std::fs::write(&path, b"").unwrap();
        run_once(&path, cfg(&path, 1 << 30, 0, 0), std::iter::once(ev(9)));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"plat.audit.lease_state\":\"high\""), "{text}");
        let r = verify(text.as_bytes()).unwrap();
        assert!(r.ok() && r.next_seq > planted, "{r:?}");
    }

    /// SEC-302: a lease of u64::MAX that is within bounds of the files (they
    /// end near u64::MAX) does not wrap: start-up fails closed.
    #[test]
    fn lease_at_u64_max_fails_closed_without_wrapping() {
        let dir = tmpdir("leasemax");
        let path = dir.join("audit.jsonl");
        header_only(&dir, u64::MAX - 1);
        std::fs::write(lease_path(&path), format!("{}\n", u64::MAX)).unwrap();
        File::create(&path).unwrap(); // empty live file: damaged, lease used
        let (_sink, rx) = AuditSink::bounded(16);
        let e = Logger::new(cfg(&path, 1 << 30, 0, 0), node(), rx, Arc::default()).spawn().unwrap_err();
        assert!(e.to_string().contains("exhausted"), "{e}");
    }

    /// SEC-302: running out of sequence numbers stops the file after a
    /// checkpointed `seq_exhausted` record and stays degraded (fail closed);
    /// later events are counted, never numbered from 0 again.
    #[test]
    fn sequence_exhaustion_fails_closed() {
        let dir = tmpdir("exhaust");
        let path = dir.join("audit.jsonl");
        header_only(&dir, u64::MAX - 3);
        let (sink, rx) = AuditSink::bounded(64);
        let stats = sink.stats().clone();
        let h = Logger::new(cfg(&path, 1 << 30, 0, 0), node(), rx, stats.clone()).spawn().unwrap();
        assert!(sink.emit(ev(0)));
        wait("first record", || written(&stats) >= 1);
        for i in 1..6 {
            sink.emit(ev(i));
        }
        wait("degraded", || stats.degraded());
        assert!(!sink.has_room());
        drop(sink);
        h.join();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"plat.reason\":\"seq_exhausted\""), "{text}");
        let r = verify(text.as_bytes()).unwrap();
        assert!(r.ok() && !r.has_unverified_tail(), "{r:?}");
        assert!(r.next_seq == u64::MAX - 3 && r.records >= 2 && r.last_seq < u64::MAX, "{r:?}");
        assert!(stats.file_lost.load(Ordering::Relaxed) > 0);
    }

    /// SEC-304: a symlink, FIFO or directory at the lease path is
    /// `corrupt`, and a FIFO does not hang start-up.
    #[cfg(unix)]
    #[test]
    fn lease_must_be_a_regular_file() {
        let dir = tmpdir("leasekind");
        let path = dir.join("audit.jsonl");
        let lp = lease_path(&path);
        assert_eq!(read_lease(&path), (0, LeaseState::Absent));
        let target = dir.join("target");
        std::fs::write(&target, b"7\n").unwrap();
        std::os::unix::fs::symlink(&target, &lp).unwrap();
        assert_eq!(read_lease(&path), (0, LeaseState::Corrupt), "symlink");
        std::fs::remove_file(&lp).unwrap();
        std::fs::write(&lp, b"garbage\n").unwrap();
        assert_eq!(read_lease(&path), (0, LeaseState::Corrupt), "unparsable");
        std::fs::remove_file(&lp).unwrap();
        std::fs::create_dir(&lp).unwrap();
        assert_eq!(read_lease(&path), (0, LeaseState::Corrupt), "directory");
        std::fs::remove_dir(&lp).unwrap();
        assert!(std::process::Command::new("mkfifo").arg(&lp).status().unwrap().success());
        let t = Instant::now();
        assert_eq!(read_lease(&path), (0, LeaseState::Corrupt), "fifo");
        // A damaged start with the FIFO in place completes too.
        File::create(&path).unwrap();
        run_once(&path, cfg(&path, 1 << 30, 0, 0), std::iter::once(ev(1)));
        assert!(t.elapsed() < Duration::from_secs(5));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"plat.audit.lease_state\":\"corrupt\""), "{text}");
    }

    /// SEC-303: a failed lease write is counted every time, announced once
    /// per failure streak, and retried every flush interval without new
    /// records.
    #[test]
    fn lease_write_failure_is_audited_once_and_retried() {
        let dir = tmpdir("leasefail");
        let path = dir.join("audit.jsonl");
        let lp = lease_path(&path);
        std::fs::create_dir(&lp).unwrap(); // rename onto it fails
        let (sink, rx) = AuditSink::bounded(64);
        let stats = sink.stats().clone();
        let h = Logger::new(cfg(&path, 1 << 30, 0, 0), node(), rx, stats.clone()).spawn().unwrap();
        assert!(sink.emit(ev(1)));
        wait("retries", || stats.seq_lease_failures.load(Ordering::Relaxed) >= 3);
        assert!(sink.emit(ev(2)));
        wait("records", || written(&stats) >= 3);
        std::fs::remove_dir(&lp).unwrap();
        // No new record: the flush tick alone retries.
        wait("lease written", || read_lease(&path).1 == LeaseState::Ok);
        drop(sink);
        h.join();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("\"plat.reason\":\"seq_lease_failed\"").count(), 1, "{text}");
        assert!(read_lease(&path).0 > verify(text.as_bytes()).unwrap().last_seq);
    }
}
