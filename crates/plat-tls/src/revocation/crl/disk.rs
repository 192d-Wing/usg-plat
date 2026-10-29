//! Optional on-disk CRL cache (`revocation.cache_dir`, off by default) so
//! a restart during a CRL-distribution outage does not leave `hard_fail`
//! without data.
//!
//! Only raw CRL DER that was already verified is written (never OCSP), as
//! `<hex sha256(source)>.crl`, mode 0600, via a temporary file and
//! `rename`, inside a directory checked at start to be ours and 0700
//! (`load::check_cache_dir`). At start, files are triaged structurally
//! (size, DER, freshness, supported features); stale or invalid files are
//! deleted. Survivors are kept as unverified bytes and fully re-verified
//! (issuer, signature, IDP) against the real issuer before first use; a
//! file that fails is deleted. Disk contents are never trusted unverified,
//! so tampering can only delete data.
//!
//! `crl-numbers` holds the highest cRLNumber seen per issuer key and IDP
//! scope (`<hex ikh> <hex scope> <hex number>` lines, 0600, atomic
//! replace), so a restart cannot be used to roll back to an older CRL
//! (SEC-005). Malformed lines are skipped; the file is bounded in size and
//! line count. A file that exists but is rejected (oversize, unreadable,
//! not UTF-8) or has skipped lines is reported as an [`HwmProblem`] so the
//! caller can warn, count and audit it (SEC-103). Writes are serialised and
//! use a unique temporary name (SEC-102). A rejected file is renamed to
//! `crl-numbers.rejected.<unix_ts>` (0600, newest 3 kept) before it can be
//! overwritten, so the evidence survives (SEC-202). Every atomic replace
//! fsyncs the directory after the rename (best effort, SEC-201). Stale
//! temporary files of other (crashed) processes are removed at start
//! (SEC-202). Tampering with it can only cause newer-than-real marks,
//! i.e. refused CRLs (fail closed), never acceptance of an old CRL.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5(2)(b)(2) - local cache of revocation data
//! - NIST 800-53: SC-28, AC-3 - private directory and 0600 files
//! - NIST 800-53: SI-7 - re-verification of persisted CRLs before use
//! - NIST 800-53: SC-5 - file count and size bounds on load

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use super::cache::{HwmKey, MAX_CRL_NUMBER, SrcKey};
use super::parse;

const SUFFIX: &str = ".crl";
/// cRLNumber high-water-mark file.
const HWM_FILE: &str = "crl-numbers";
/// Size cap of [`HWM_FILE`] (bytes).
const HWM_MAX_BYTES: u64 = 1 << 20;

/// Prefix of moved-aside rejected [`HWM_FILE`]s.
const HWM_REJECTED: &str = "crl-numbers.rejected.";
/// Rejected [`HWM_FILE`]s kept (SEC-202).
const HWM_REJECTED_KEEP: usize = 3;
/// Directory entries examined by the start-up scans (SC-5).
const SCAN_MAX: usize = 4096;

/// Per-process counter making temporary file names unique.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Why an existing `crl-numbers` file was (partly) not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwmProblem {
    /// Larger than the size cap: ignored.
    Oversize,
    /// Could not be opened/read (incl. not a regular file): ignored.
    Unreadable,
    /// Not UTF-8: ignored.
    NotUtf8,
    /// This many malformed (or over-limit) lines were skipped.
    BadLines(usize),
}

impl HwmProblem {
    /// `event.reason` of the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oversize => "state_oversize",
            Self::Unreadable => "state_unreadable",
            Self::NotUtf8 => "state_not_utf8",
            Self::BadLines(_) => "state_bad_lines",
        }
    }
}

/// Result of [`DiskCache::load_hwm`].
#[derive(Debug, Default)]
pub struct HwmLoad {
    pub marks: Vec<(HwmKey, Vec<u8>)>,
    pub problem: Option<HwmProblem>,
    /// Where the rejected file was moved (SEC-202), if it was.
    pub moved_to: Option<PathBuf>,
    /// A rejected regular file could not be moved aside (SEC-303); it
    /// stays in place and may be overwritten by the next write.
    pub move_failed: bool,
}

/// Outcome of a successful atomic replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored {
    /// The directory fsync after the rename succeeded (SEC-201). When
    /// `false` the new content is in place but may not survive power loss.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: IA-5(2)(b)(2) - durability of persisted revocation
    ///   state (failures counted separately, SEC-308)
    pub dir_synced: bool,
}

/// `.<file>.<pid>.<seq>.tmp` written by [`DiskCache::write_atomic`]:
/// the pid if `n` has that shape and `<file>` is one of ours.
fn parse_tmp_name(n: &str) -> Option<u32> {
    let mid = n.strip_prefix('.')?.strip_suffix(".tmp")?;
    let mut it = mid.rsplitn(3, '.');
    let seq = it.next()?;
    let pid = it.next()?;
    let file = it.next()?;
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) || seq.len() > 20 {
        return None;
    }
    if file != HWM_FILE && parse_name(file).is_none() {
        return None;
    }
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

/// `(ts, n)` of `crl-numbers.rejected.<ts>[-<n>]`.
fn parse_rejected_name(n: &str) -> Option<(u64, u32)> {
    let rest = n.strip_prefix(HWM_REJECTED)?;
    let (ts, k) = match rest.split_once('-') {
        Some((t, k)) => (t, k.parse().ok()?),
        None => (rest, 0),
    };
    if ts.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((ts.parse().ok()?, k))
}

/// Grace period before a foreign temporary file counts as stale
/// (SEC-305): tolerates clock steps and a writer that is still running.
const TMP_STALE_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

/// Renames `src` to `dst` without ever replacing an existing `dst`
/// (SEC-303): `renameat2(RENAME_NOREPLACE)` / `renamex_np(RENAME_EXCL)`
/// where available, else `link` + `unlink`. `AlreadyExists` means `dst`
/// is taken.
#[cfg(unix)]
fn rename_noreplace(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        match renameat_with(CWD, src, CWD, dst, RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(()),
            Err(e) if e == rustix::io::Errno::EXIST => return Err(e.into()),
            // Unsupported by the kernel or file system: fall through.
            Err(_) => {}
        }
    }
    fs::hard_link(src, dst)?;
    fs::remove_file(src)
}

/// Portable fallback: check, then rename (racy only against writers that
/// already have write access to our private directory).
#[cfg(not(unix))]
fn rename_noreplace(src: &Path, dst: &Path) -> std::io::Result<()> {
    if fs::symlink_metadata(dst).is_ok() {
        return Err(std::io::ErrorKind::AlreadyExists.into());
    }
    fs::rename(src, dst)
}

/// Sets mode 0600 on the moved-aside file through an fd opened with
/// `O_NOFOLLOW`, after `fstat` on that fd shows a regular file (SEC-302).
#[cfg(unix)]
fn restrict_regular(p: &Path) -> bool {
    use rustix::fs::{FileType, Mode, OFlags, fchmod, fstat, open};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let Ok(fd) = open(p, flags, Mode::empty()) else { return false };
    let Ok(st) = fstat(&fd) else { return false };
    FileType::from_raw_mode(st.st_mode) == FileType::RegularFile && fchmod(&fd, Mode::RUSR | Mode::WUSR).is_ok()
}

#[cfg(not(unix))]
fn restrict_regular(_p: &Path) -> bool {
    true
}

/// Best-effort fsync of `dir` so a completed rename survives power loss.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> bool {
    fs::File::open(dir).and_then(|d| d.sync_all()).is_ok()
}

/// Not supported portably off Unix; reported as not synced.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> bool {
    false
}

#[derive(Debug, Clone)]
pub struct DiskCache {
    dir: PathBuf,
}

fn name(k: &SrcKey) -> String {
    let mut s = crate::revocation::hex(k);
    s.push_str(SUFFIX);
    s
}

fn parse_name(n: &str) -> Option<SrcKey> {
    let h = n.strip_suffix(SUFFIX)?;
    if h.len() != 64 {
        return None;
    }
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(k)
}

/// Reads at most `max` bytes of a regular file (never blocks on a FIFO,
/// see [`crate::load::open_regular`]); `None` if the file is larger.
pub fn read_capped(p: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let f = crate::load::open_regular(p)?;
    let mut buf = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    Ok((buf.len() as u64 <= max).then_some(buf))
}

fn unhex(h: &str, out: &mut [u8]) -> Option<()> {
    if h.len() != out.len() * 2 {
        return None;
    }
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(())
}

fn parse_hwm_line(l: &str) -> Option<(HwmKey, Vec<u8>)> {
    let mut it = l.split(' ');
    let (mut ikh, mut scope) = ([0u8; 32], [0u8; 32]);
    unhex(it.next()?, &mut ikh)?;
    unhex(it.next()?, &mut scope)?;
    let nh = it.next()?;
    if it.next().is_some() || nh.is_empty() || nh.len() % 2 != 0 || nh.len() > MAX_CRL_NUMBER * 2 {
        return None;
    }
    let mut n = vec![0u8; nh.len() / 2];
    unhex(nh, &mut n)?;
    Some(((ikh, scope), n))
}

/// Parses `crl-numbers` text: at most `max` marks; malformed and
/// over-limit lines are counted.
fn parse_hwm_text(text: &str, max: usize) -> HwmLoad {
    let mut marks = Vec::new();
    let mut bad = 0usize;
    for l in text.lines() {
        match parse_hwm_line(l) {
            Some(m) if marks.len() < max => marks.push(m),
            _ => bad += 1,
        }
    }
    HwmLoad { marks, problem: (bad > 0).then_some(HwmProblem::BadLines(bad)), ..HwmLoad::default() }
}

impl DiskCache {
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.to_path_buf() }
    }

    pub fn path(&self, k: &SrcKey) -> PathBuf {
        self.dir.join(name(k))
    }

    /// Loads at most `max_files` files of at most `max_bytes` each that
    /// pass [`parse::inspect`]; deletes stale/invalid ones. Unrelated
    /// files in the directory are left alone.
    pub fn load(&self, max_files: usize, max_bytes: u64, now: u64, skew: u64) -> Vec<(SrcKey, Vec<u8>)> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(&self.dir) else { return out };
        for ent in rd.flatten().take(max_files.saturating_mul(4).max(16)) {
            let Some(k) = ent.file_name().to_str().and_then(parse_name) else { continue };
            let p = ent.path();
            let ok = match read_capped(&p, max_bytes) {
                Ok(Some(der)) if parse::inspect(&der, now, skew).is_ok() && out.len() < max_files => {
                    out.push((k, der));
                    true
                }
                _ => false,
            };
            if !ok {
                tracing::warn!("revocation: removing unusable cached CRL {}", p.display());
                let _ = fs::remove_file(&p);
            }
        }
        out
    }

    /// Writes verified DER atomically with mode 0600.
    pub fn store(&self, k: &SrcKey, der: &[u8]) -> std::io::Result<Stored> {
        self.write_atomic(&name(k), der)
    }

    /// Loads at most `max` cRLNumber high-water marks. A missing file is
    /// not a problem; anything else that loses marks is reported.
    ///
    /// A rejected file (any [`HwmProblem`]) is moved aside before the
    /// first write could replace it (SEC-202).
    pub fn load_hwm(&self, max: usize) -> HwmLoad {
        let mut l = self.read_hwm(max);
        if l.problem.is_some() {
            match self.move_aside_hwm(SystemTime::now()) {
                Ok(p) => l.moved_to = p,
                Err(e) => {
                    tracing::warn!("revocation: could not move rejected {HWM_FILE} aside: {e}");
                    l.move_failed = true;
                }
            }
        }
        l
    }

    fn read_hwm(&self, max: usize) -> HwmLoad {
        let b = match read_capped(&self.dir.join(HWM_FILE), HWM_MAX_BYTES) {
            Ok(Some(b)) => b,
            Ok(None) => return HwmLoad { problem: Some(HwmProblem::Oversize), ..HwmLoad::default() },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HwmLoad::default(),
            Err(_) => return HwmLoad { problem: Some(HwmProblem::Unreadable), ..HwmLoad::default() },
        };
        let Ok(text) = std::str::from_utf8(&b) else {
            return HwmLoad { problem: Some(HwmProblem::NotUtf8), ..HwmLoad::default() };
        };
        parse_hwm_text(text, max)
    }

    /// Moves a rejected regular [`HWM_FILE`] to `crl-numbers.rejected.
    /// <ts>[-<n>]` without replacing anything (SEC-303), restricts it to
    /// 0600 through an `O_NOFOLLOW` fd (SEC-302), then prunes all other
    /// rejected files but the newest [`HWM_REJECTED_KEEP`] − 1, never the
    /// one just moved (SEC-301). A non-regular `crl-numbers` (directory,
    /// symlink, ...) is left in place: `Ok(None)` (SEC-304; the caller
    /// still counts and audits the problem).
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: SI-7, AU-9 (supporting; the authoritative record is
    ///   the hash-chained state_rejected audit event)
    fn move_aside_hwm(&self, now: SystemTime) -> std::io::Result<Option<PathBuf>> {
        let src = self.dir.join(HWM_FILE);
        let md = match fs::symlink_metadata(&src) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if !md.file_type().is_file() {
            tracing::warn!("revocation: rejected {HWM_FILE} is not a regular file; left in place");
            return Ok(None);
        }
        let ts = now.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut moved = None;
        for k in 0u32..16 {
            let dst = if k == 0 {
                self.dir.join(format!("{HWM_REJECTED}{ts}"))
            } else {
                self.dir.join(format!("{HWM_REJECTED}{ts}-{k}"))
            };
            match rename_noreplace(&src, &dst) {
                Ok(()) => {
                    moved = Some(dst);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        let dst = moved.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists))?;
        if !restrict_regular(&dst) {
            tracing::warn!("revocation: could not restrict {} to mode 0600", dst.display());
        }
        sync_dir(&self.dir);
        self.prune_rejected(&dst);
        Ok(Some(dst))
    }

    /// Keeps `keep` (just moved aside) and the newest
    /// [`HWM_REJECTED_KEEP`] − 1 other rejected regular files by name;
    /// a future-dated planted name can only push out older evidence,
    /// never `keep` (SEC-301). Non-regular entries are never touched.
    fn prune_rejected(&self, keep: &Path) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        let mut found: Vec<((u64, u32), PathBuf)> = rd
            .flatten()
            .take(SCAN_MAX)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .filter_map(|e| Some((parse_rejected_name(e.file_name().to_str()?)?, e.path())))
            .filter(|(_, p)| p != keep)
            .collect();
        found.sort_by_key(|f| std::cmp::Reverse(f.0));
        for (_, p) in found.into_iter().skip(HWM_REJECTED_KEEP.saturating_sub(1)) {
            let _ = fs::remove_file(&p);
        }
    }

    /// Removes our own temporary files (`.<crl-numbers|hash.crl>.<pid>.
    /// <seq>.tmp`) left by a crashed process: regular files only (lstat,
    /// symlinks are never followed), not of this process, last modified
    /// before `start` − 60 s (SEC-305). Returns how many were removed.
    pub fn remove_stale_tmp(&self, start: SystemTime) -> usize {
        let Some(cutoff) = start.checked_sub(TMP_STALE_GRACE) else { return 0 };
        let Ok(rd) = fs::read_dir(&self.dir) else { return 0 };
        let me = std::process::id();
        let mut n = 0;
        for ent in rd.flatten().take(SCAN_MAX) {
            let Some(pid) = ent.file_name().to_str().and_then(parse_tmp_name) else { continue };
            if pid == me {
                continue;
            }
            let p = ent.path();
            let Ok(md) = fs::symlink_metadata(&p) else { continue };
            if !md.file_type().is_file() || !md.modified().is_ok_and(|m| m < cutoff) {
                continue;
            }
            if fs::remove_file(&p).is_ok() {
                n += 1;
            }
        }
        n
    }

    /// Replaces the high-water-mark file atomically (mode 0600).
    pub fn store_hwm(&self, marks: &[(HwmKey, Vec<u8>)]) -> std::io::Result<Stored> {
        let mut out = String::new();
        for ((ikh, scope), n) in marks {
            out.push_str(&crate::revocation::hex(ikh));
            out.push(' ');
            out.push_str(&crate::revocation::hex(scope));
            out.push(' ');
            out.push_str(&crate::revocation::hex(n));
            out.push('\n');
        }
        self.write_atomic(HWM_FILE, out.as_bytes())
    }

    /// Temporary file, fsync, rename, then a best-effort directory fsync
    /// (SEC-201): its failure does not undo the rename, so it is reported
    /// in [`Stored`] rather than as an error.
    ///
    /// COMPLIANCE MAPPING:
    /// - NIST 800-53: IA-5(2)(b)(2) - persisted revocation data and
    ///   rollback state
    /// - NIST 800-53: SC-24, CP-10 - persisted state survives power loss
    fn write_atomic(&self, file: &str, data: &[u8]) -> std::io::Result<Stored> {
        let fin = self.dir.join(file);
        // SEC-102: unique per process and call, so concurrent writers never
        // share (or delete) a temporary file.
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self.dir.join(format!(".{file}.{}.{seq}.tmp", std::process::id()));
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let r = (|| {
            let mut f = o.open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            fs::rename(&tmp, &fin)
        })();
        if r.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        r.map(|()| Stored { dir_synced: sync_dir(&self.dir) })
    }

    pub fn remove(&self, k: &SrcKey) {
        let _ = fs::remove_file(self.path(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hwm_lines() {
        let l = format!("{} {} 0a01", "ab".repeat(32), "cd".repeat(32));
        assert_eq!(parse_hwm_line(&l), Some((([0xab; 32], [0xcd; 32]), vec![0x0a, 0x01])));
        for bad in [
            String::new(),
            format!("{} {}", "ab".repeat(32), "cd".repeat(32)),
            format!("{} {} 0", "ab".repeat(32), "cd".repeat(32)),
            format!("{} {} zz", "ab".repeat(32), "cd".repeat(32)),
            format!("{} {} {}", "ab".repeat(32), "cd".repeat(32), "00".repeat(21)),
            format!("{} {} 01 x", "ab".repeat(32), "cd".repeat(32)),
        ] {
            assert_eq!(parse_hwm_line(&bad), None, "{bad}");
        }
    }

    #[test]
    fn hwm_problems_are_reported() {
        let good = format!("{} {} 0a", "ab".repeat(32), "cd".repeat(32));
        let l = parse_hwm_text(&format!("{good}\njunk\n{good}\n"), 1);
        assert_eq!(l.marks.len(), 1);
        assert_eq!(l.problem, Some(HwmProblem::BadLines(2)));
        assert_eq!(parse_hwm_text(&good, 4).problem, None);

        let dir = std::env::temp_dir().join(format!("plat-hwm-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let d = DiskCache::new(&dir);
        let l = d.load_hwm(4);
        assert!(l.marks.is_empty() && l.problem.is_none(), "missing file is fine");
        fs::write(dir.join(HWM_FILE), [0xffu8, 0xfe, b'\n']).unwrap();
        assert_eq!(d.load_hwm(4).problem, Some(HwmProblem::NotUtf8));
        fs::write(dir.join(HWM_FILE), vec![b'a'; (HWM_MAX_BYTES + 1) as usize]).unwrap();
        assert_eq!(d.load_hwm(4).problem, Some(HwmProblem::Oversize));
        assert!(!dir.join(HWM_FILE).exists(), "moved aside");
        fs::create_dir(dir.join(HWM_FILE)).unwrap();
        assert_eq!(d.load_hwm(4).problem, Some(HwmProblem::Unreadable));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_round_trip() {
        let k = [0xab; 32];
        assert_eq!(parse_name(&name(&k)), Some(k));
        assert_eq!(parse_name("x.crl"), None);
        assert_eq!(parse_name(&"g".repeat(64)), None);
    }

    fn tmpdir(tag: u32) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("plat-disk-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn store_syncs_dir() {
        let dir = tmpdir(line!());
        let d = DiskCache::new(&dir);
        let s = d.store_hwm(&[(([1; 32], [2; 32]), vec![3])]).unwrap();
        assert_eq!(s.dir_synced, cfg!(unix));
        assert_eq!(d.load_hwm(4).marks.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejected_hwm_is_moved_aside_and_bounded() {
        let dir = tmpdir(line!());
        let d = DiskCache::new(&dir);
        for ts in [1u64, 2, 3] {
            fs::write(dir.join(format!("{HWM_REJECTED}{ts}")), b"old").unwrap();
        }
        fs::write(dir.join(HWM_FILE), [0xffu8, 0xfe]).unwrap();
        let l = d.load_hwm(4);
        assert_eq!(l.problem, Some(HwmProblem::NotUtf8));
        let moved = l.moved_to.unwrap();
        assert!(!dir.join(HWM_FILE).exists());
        assert_eq!(fs::read(&moved).unwrap(), [0xffu8, 0xfe]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&moved).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Newest three kept (the new one + 2 others): the oldest went.
        assert!(!dir.join(format!("{HWM_REJECTED}1")).exists());
        assert!(dir.join(format!("{HWM_REJECTED}2")).exists());
        assert!(dir.join(format!("{HWM_REJECTED}3")).exists());
        // Same second: a distinct name, never an overwrite.
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(5);
        fs::write(dir.join(HWM_FILE), b"x").unwrap();
        let first = d.move_aside_hwm(t).unwrap().unwrap();
        assert_eq!(first, dir.join(format!("{HWM_REJECTED}5")));
        fs::write(dir.join(HWM_FILE), b"y").unwrap();
        assert_eq!(d.move_aside_hwm(t).unwrap(), Some(dir.join(format!("{HWM_REJECTED}5-1"))));
        assert_eq!(fs::read(&first).unwrap(), b"x", "never overwritten");
        // A good file is left in place.
        d.store_hwm(&[(([1; 32], [2; 32]), vec![3])]).unwrap();
        assert!(d.load_hwm(4).moved_to.is_none() && dir.join(HWM_FILE).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_dated_rejected_never_prunes_new() {
        let dir = tmpdir(line!());
        let d = DiskCache::new(&dir);
        let far = u64::MAX / 2;
        for k in 0..5u64 {
            fs::write(dir.join(format!("{HWM_REJECTED}{}", far + k)), b"planted").unwrap();
        }
        fs::write(dir.join(HWM_FILE), [0xffu8]).unwrap();
        let moved = d.load_hwm(4).moved_to.unwrap();
        assert_eq!(fs::read(&moved).unwrap(), [0xffu8], "just-moved file survives");
        let left = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with(HWM_REJECTED)))
            .count();
        assert_eq!(left, HWM_REJECTED_KEEP);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_regular_hwm_is_left_in_place() {
        let dir = tmpdir(line!());
        let d = DiskCache::new(&dir);
        let sub = dir.join(format!("{HWM_REJECTED}1"));
        fs::create_dir(&sub).unwrap();
        for ts in [2u64, 3, 4, 5] {
            fs::write(dir.join(format!("{HWM_REJECTED}{ts}")), b"old").unwrap();
        }
        fs::create_dir(dir.join(HWM_FILE)).unwrap();
        let l = d.load_hwm(4);
        assert_eq!(l.problem, Some(HwmProblem::Unreadable));
        assert!(l.moved_to.is_none() && !l.move_failed);
        assert!(dir.join(HWM_FILE).is_dir(), "directory left in place");
        // A regular file is moved; pruning skips the rejected-named directory.
        fs::remove_dir(dir.join(HWM_FILE)).unwrap();
        fs::write(dir.join(HWM_FILE), [0xffu8]).unwrap();
        assert!(d.load_hwm(4).moved_to.is_some());
        assert!(sub.is_dir(), "non-regular entries are never pruned");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tmp_names() {
        let h = "ab".repeat(32);
        assert_eq!(parse_tmp_name(".crl-numbers.123.0.tmp"), Some(123));
        assert_eq!(parse_tmp_name(&format!(".{h}.crl.9.17.tmp")), Some(9));
        for bad in
            [".other.1.2.tmp", ".crl-numbers.x.2.tmp", ".crl-numbers.1..tmp", "crl-numbers.1.2.tmp", ".crl-numbers.1.2"]
        {
            assert_eq!(parse_tmp_name(bad), None, "{bad}");
        }
        assert_eq!(parse_rejected_name("crl-numbers.rejected.17"), Some((17, 0)));
        assert_eq!(parse_rejected_name("crl-numbers.rejected.17-2"), Some((17, 2)));
        assert_eq!(parse_rejected_name("crl-numbers.rejected.x"), None);
    }

    #[test]
    fn stale_tmp_removed() {
        let dir = tmpdir(line!());
        let d = DiskCache::new(&dir);
        let other = std::process::id().wrapping_add(1);
        let stale = dir.join(format!(".crl-numbers.{other}.0.tmp"));
        let mine = dir.join(format!(".crl-numbers.{}.0.tmp", std::process::id()));
        let foreign = dir.join(format!(".unrelated.{other}.0.tmp"));
        for p in [&stale, &mine, &foreign] {
            fs::write(p, b"t").unwrap();
        }
        let sub = dir.join(format!(".crl-numbers.{other}.1.tmp"));
        fs::create_dir(&sub).unwrap();
        #[cfg(unix)]
        let link = {
            let target = dir.join("target");
            fs::write(&target, b"keep").unwrap();
            let link = dir.join(format!(".crl-numbers.{other}.2.tmp"));
            std::os::unix::fs::symlink(&target, &link).unwrap();
            link
        };
        // Nothing is older than a start in the past.
        assert_eq!(d.remove_stale_tmp(SystemTime::UNIX_EPOCH), 0);
        // Within the 60 s grace: kept.
        assert_eq!(d.remove_stale_tmp(SystemTime::now() + std::time::Duration::from_secs(5)), 0);
        assert!(stale.exists());
        let start = SystemTime::now() + std::time::Duration::from_secs(65);
        assert_eq!(d.remove_stale_tmp(start), 1);
        assert!(!stale.exists() && mine.exists() && foreign.exists() && sub.is_dir());
        #[cfg(unix)]
        {
            assert!(fs::symlink_metadata(&link).is_ok());
            assert_eq!(fs::read(dir.join("target")).unwrap(), b"keep");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
