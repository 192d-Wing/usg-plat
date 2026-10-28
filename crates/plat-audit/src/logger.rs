//! The logger: one thread owns the local hash-chained file (the
//! authoritative AU-9 copy); each syslog destination has its own sender
//! thread behind a bounded hand-off, so a slow or unreachable collector can
//! never stall the file or the event queue.
//!
//! ```text
//!  queue ─▶ plat-audit ─▶ local file (format, hash, checkpoint, rotate)
//!              │  try_send (batch, never blocks)
//!              ├────────▶ plat-syslog-0 ─▶ collector (UDP / TCP)
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
use crate::event::{Event, PruneState, StorageState};
use crate::format;
use crate::sink::AuditStats;

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
/// TCP reconnect back-off; records sent during it are counted as lost.
const TCP_BACKOFF: Duration = Duration::from_secs(5);
/// Tail of an existing file read at start-up to find its last checkpoint.
const RESUME_TAIL_BYTES: u64 = 8 << 20;
/// Tail read first when classifying a rotated file for retention.
const CLASSIFY_TAIL_BYTES: u64 = 64 << 10;
/// Largest file considered for [`disposable`] (a header line is ~300 B).
const DISPOSABLE_MAX_BYTES: u64 = 4096;
/// How often free space on the log volume is checked (AU-5(1)).
const SPACE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

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
    let text = String::from_utf8_lossy(&buf);
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
}

impl AuditFile {
    fn new(f: File, _path: &Path) -> Self {
        Self {
            f,
            #[cfg(test)]
            vol: fault::volume_of(_path),
            #[cfg(test)]
            written: 0,
        }
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

    /// Makes the prepared file the live file: flush (and `sync_all` when
    /// `durable`, i.e. it already holds a checkpoint that must survive), move
    /// a live file that holds records aside (`<path>.<µs>`), rename this file
    /// into place (atomically replacing a live file without records), sync
    /// the directory. A header-only file lost in a crash is harmless: start-up
    /// resumes from the newest file that has a checkpoint.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: AU-9 - the old file is only renamed, never deleted;
    ///   a crash leaves either the old live file or its rotated copy (start-up
    ///   then resumes from the newest file, see `resume_for`).
    fn install(&mut self, path: &Path, durable: bool) -> std::io::Result<()> {
        self.w.flush()?;
        if durable {
            self.sync()?;
        }
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
        self.w.write_all(line)
    }

    /// Writes the checkpoint for the current batch and flushes. The chain
    /// advances only once the checkpoint is flushed.
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
        self.chain = chain;
        Ok(())
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
        }
    }

    fn publish(&self, stats: &AuditStats) {
        stats.set_file_state(self.out.is_none(), self.low);
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
            let due = PruneDue { path, rotated_us: ts, seq_first, seq_last, chain_prefix: u64::from_be_bytes(head) };
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
        if self.prune_due.is_empty() {
            return;
        }
        if let Err(e) = f.sync() {
            stats.output_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("audit retention postponed: {e}");
            carry.extend(self.prune_due.drain(..).map(|d| d.record(PruneState::Failed)));
            return;
        }
        for d in self.prune_due.drain(..) {
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
}

/// One syslog destination, owned by its sender thread.
// POAM: POAM-005 - syslog is UDP/TCP without TLS (RFC 5425); use a
// protected management network until TLS transport is implemented.
struct SyslogOut {
    cfg: SyslogConfig,
    conn: SyslogConn,
}

impl SyslogOut {
    fn new(cfg: SyslogConfig) -> std::io::Result<Self> {
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
        };
        Ok(Self { cfg, conn })
    }

    fn format(&self, seq: u64, node: &NodeIdent, ev: &Event, msg: &mut Vec<u8>) {
        msg.clear();
        format::syslog_header(msg, node, &self.cfg.app_name, ev);
        match self.cfg.format {
            LogFormat::Json => format::json(msg, seq, node, ev),
            LogFormat::Cef => format::cef(msg, seq, node, ev),
        }
    }

    /// Sends one batch. Returns the number of records not delivered.
    ///
    /// UDP is one datagram (one `send` syscall) per record: RFC 5426 allows
    /// one message per datagram, and batching with `sendmmsg` would need
    /// `unsafe` FFI outside `plat-io`. The cost stays on this thread, off the
    /// file path. TCP (RFC 6587 §3.4.1 octet counting) is one write per batch;
    /// on failure the whole batch is counted as lost (some frames may have
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
                let mut lost = 0;
                for (seq, ev) in batch {
                    self.format(*seq, node, ev, msg);
                    if s.send(msg).is_err() {
                        lost += 1;
                    }
                }
                (lost, u64::from(lost > 0))
            }
            SyslogConn::Tcp(..) => {
                buf.clear();
                for (seq, ev) in batch {
                    self.format(*seq, node, ev, msg);
                    let _ = write!(buf, "{} ", msg.len());
                    buf.extend_from_slice(msg);
                }
                let SyslogConn::Tcp(conn, last_try) = &mut self.conn else { return (0, 0) };
                if conn.is_none() {
                    if last_try.is_some_and(|t| t.elapsed() < TCP_BACKOFF) {
                        return (n, 0);
                    }
                    *last_try = Some(Instant::now());
                    match TcpStream::connect_timeout(&self.cfg.address, Duration::from_secs(2)).and_then(|s| {
                        s.set_nodelay(true)?;
                        s.set_write_timeout(Some(Duration::from_secs(2)))?;
                        Ok(s)
                    }) {
                        Ok(s) => *conn = Some(BufWriter::with_capacity(1 << 20, s)),
                        Err(e) => {
                            tracing::warn!("syslog {}: {e}", self.cfg.address);
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
                        (n, 1)
                    }
                }
            }
        }
    }
}

type Batch = Arc<Vec<(u64, Event)>>;

/// The logger thread's handle to one syslog sender thread.
struct Remote {
    tx: Option<Sender<Batch>>,
    addr: SocketAddr,
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
        })?;
        Ok(Self { tx: Some(tx), addr, lost, reported: 0, thread: Some(thread) })
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
        Some(Event::RemoteLoss { ts_us: Clock::wall_us(), ip: self.addr.ip(), port: self.addr.port(), lost: d })
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

/// Numbers events with consecutive sequence numbers after `seq`.
fn number(events: impl Iterator<Item = Event>, seq: &mut u64) -> Vec<(u64, Event)> {
    events
        .map(|ev| {
            *seq += 1;
            (*seq, ev)
        })
        .collect()
}

impl Logger {
    pub fn new(cfg: AuditConfig, node: NodeIdent, rx: Receiver<Event>, stats: Arc<AuditStats>) -> Self {
        Self { cfg, node, rx, stats, counters: None }
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
        let file = match &self.cfg.file {
            Some(f) => {
                rescue_temp(&f.path);
                let resume = resume_for(&f.path);
                seq = resume.max_seq;
                let mut out = FileOut::prepare(f, &resume, seq + 1, &self.node, &mut scratch)?;
                if let Err(e) = out.install(&f.path, false) {
                    out.discard();
                    return Err(e);
                }
                let fd = FileDest::new(f.clone(), out, resume);
                fd.publish(&self.stats);
                Some(fd)
            }
            None => None,
        };
        let outs = self.cfg.syslog.iter().cloned().map(SyslogOut::new).collect::<Result<Vec<_>, _>>()?;
        let remotes = outs
            .into_iter()
            .enumerate()
            .map(|(i, o)| Remote::spawn(o, i, self.node.clone(), self.stats.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let h = std::thread::Builder::new()
            .name("plat-audit".into())
            .spawn(move || self.run(file, remotes, seq, scratch))?;
        Ok(LoggerHandle(h))
    }

    fn run(self, mut file: Option<FileDest>, mut remotes: Vec<Remote>, mut seq: u64, mut line: Vec<u8>) {
        let flush_every = Duration::from_millis(self.cfg.flush_interval_ms);
        let summary_every = Duration::from_secs(self.cfg.summary_interval_secs);
        let mut last_summary = Instant::now();
        let mut lost_reported = 0u64;
        let mut pending: Vec<Event> = Vec::with_capacity(self.cfg.batch_max);
        let mut carry: Vec<Event> = Vec::new();

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
                // A due retry of a failed file leads with the `recovered`
                // record; it is rewritten to `degraded` if the retry fails.
                if fd.out.is_none() && !disconnected && Instant::now() >= fd.next_retry {
                    recover = true;
                    pending.insert(0, Event::OutputFailure { ts_us: Clock::wall_us(), lost: fd.lost, recovered: true });
                }
            }
            if !pending.is_empty() {
                let mut batch = number(pending.drain(..), &mut seq);
                self.write_file(file.as_mut(), &mut batch, recover, &mut line, &mut carry);
                let batch: Batch = Arc::new(batch);
                for r in &remotes {
                    r.offer(&batch);
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
                    let mut batch = number(tail.drain(..), &mut seq);
                    self.write_file(file.as_mut(), &mut batch, false, &mut line, &mut carry);
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
            match nf.write_batch(batch, &self.node, line).and_then(|()| nf.install(&fd.cfg.path, true)) {
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
        match f.write_batch(batch, &self.node, line) {
            Ok(()) => {
                let last = batch.last().map_or(0, |(s, _)| *s);
                self.stats.written.fetch_add(n, Ordering::Relaxed);
                fd.resume = Resume { chain: f.chain, seq: last, max_seq: last };
                // Retention records from the previous rotation are in this
                // batch: delete their files now that it is checkpointed.
                fd.run_prune(&f, &self.stats, carry);
                if f.bytes < f.max_bytes {
                    fd.out = Some(f);
                    return;
                }
                let rotated = f.sync().and_then(|()| {
                    let mut nf = FileOut::prepare(&fd.cfg, &fd.resume, last + 1, &self.node, line)?;
                    match nf.install(&fd.cfg.path, false) {
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
                        fd.out = Some(nf);
                        fd.schedule_prune(carry);
                    }
                    Err(e) => {
                        fd.fail(&self.stats, &e, carry);
                        carry.push(Event::OutputFailure { ts_us: Clock::wall_us(), lost: 0, recovered: false });
                    }
                }
            }
            Err(e) => {
                f.discard();
                fd.fail(&self.stats, &e, carry);
                fd.lost += n;
                self.stats.file_lost.fetch_add(n, Ordering::Relaxed);
                // Tell the remaining destinations now (AU-5).
                carry.push(Event::OutputFailure { ts_us: Clock::wall_us(), lost: n, recovered: false });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use plat_common::config::{AuditMode, OverflowPolicy};

    use super::*;
    use crate::sink::AuditSink;
    use crate::verify::{LinkIssue, VerifyReport, link, verify};

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
        wait("records", || written(&stats) >= 300);
        // The last rotation's prune records go out with the next batch and
        // its files are deleted after that checkpoint.
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
        for i in 0..5 {
            assert!(sink.emit(ev(2000 + i)));
        }
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
            LinkIssue::Gap { first, last, .. } => assert_eq!(last - first + 1, lost),
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
        out.install(&fcfg.path, false).unwrap();
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
        let due = |path: PathBuf, rotated_us| PruneDue { path, rotated_us, seq_first: 1, seq_last: 2, chain_prefix: 7 };
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
}
