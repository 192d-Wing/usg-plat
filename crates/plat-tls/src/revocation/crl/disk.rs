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
//! use a unique temporary name (SEC-102). Tampering with it can only cause newer-than-real marks,
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

use super::cache::{HwmKey, MAX_CRL_NUMBER, SrcKey};
use super::parse;

const SUFFIX: &str = ".crl";
/// cRLNumber high-water-mark file.
const HWM_FILE: &str = "crl-numbers";
/// Size cap of [`HWM_FILE`] (bytes).
const HWM_MAX_BYTES: u64 = 1 << 20;

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
    HwmLoad { marks, problem: (bad > 0).then_some(HwmProblem::BadLines(bad)) }
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
    pub fn store(&self, k: &SrcKey, der: &[u8]) -> std::io::Result<()> {
        self.write_atomic(&name(k), der)
    }

    /// Loads at most `max` cRLNumber high-water marks. A missing file is
    /// not a problem; anything else that loses marks is reported.
    pub fn load_hwm(&self, max: usize) -> HwmLoad {
        let b = match read_capped(&self.dir.join(HWM_FILE), HWM_MAX_BYTES) {
            Ok(Some(b)) => b,
            Ok(None) => return HwmLoad { marks: Vec::new(), problem: Some(HwmProblem::Oversize) },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HwmLoad::default(),
            Err(_) => return HwmLoad { marks: Vec::new(), problem: Some(HwmProblem::Unreadable) },
        };
        let Ok(text) = std::str::from_utf8(&b) else {
            return HwmLoad { marks: Vec::new(), problem: Some(HwmProblem::NotUtf8) };
        };
        parse_hwm_text(text, max)
    }

    /// Replaces the high-water-mark file atomically (mode 0600).
    pub fn store_hwm(&self, marks: &[(HwmKey, Vec<u8>)]) -> std::io::Result<()> {
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

    fn write_atomic(&self, file: &str, data: &[u8]) -> std::io::Result<()> {
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
        r
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
        fs::remove_file(dir.join(HWM_FILE)).unwrap();
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
}
