//! Offline verification of hash-chained audit files (`platd verify-log`).
//!
//! Per file: the `audit_chain_continue` header seeds the chain; records must
//! be numbered consecutively from its `next_seq`; each checkpoint must match
//! the batch hash, its `seq_first`/`seq_last`, and the chain. Records after
//! the last checkpoint (crash or truncation) are reported as unverified, and
//! so is a final partial line (no newline: a short write or power cut cut it
//! off); neither is a chain mismatch.
//!
//! Across files ([`link`]): each file's header must name the previous
//! file's final chain and checkpoint sequence, which detects a removed,
//! replaced or reordered file; a sequence gap between files means records
//! were not written locally. Such a gap is *accounted* (not a failure) only
//! when the file after it opens with a checkpointed `audit_output_failure`
//! record for the local file (`plat.audit.destination` `file`,
//! `plat.audit.state` `recovered`) whose `plat.audit.lost` equals the gap
//! size exactly: the logger writes that record as the first record of the
//! file it opens on recovery, with the number of records (and so sequence
//! numbers) lost since the outage began. Any other gap, or a lost count that
//! differs, is unexplained. A gap before a file opening with a valid
//! `audit_recovery` whose `plat.audit.max_seq` is the last number of the
//! gap is a separate class ([`GapAccount::Recovery`]): start-up could not
//! see every number the damaged file used and skipped to its durable
//! high-water mark, announcing the range; whether records in it existed
//! can only be settled against the remote copy (SEC-301). A file that ends
//! in a partial line may only be followed by one whose first record is
//! `audit_recovery` naming its last checkpoint (`truncated_tail`, or
//! `empty_file`/`missing_header` when the file holding that record was
//! damaged in turn), and an
//! `audit_recovery` may only follow such a file (or name the predecessor's
//! last checkpoint when the damaged file was empty or headerless, which
//! start-up replaces or `verify` rejects on its own).
//!
//! Limits: the chain is unkeyed. Someone who can write the files can
//! recompute every hash; truncation exactly at a checkpoint of the newest
//! file is not detectable locally. The syslog copy on a separate system
//! covers both (NIST 800-53 AU-9(2)); keyed checkpoints are POAM-003.

use std::io::BufRead;

use sha2::{Digest, Sha256};

use crate::logger::{chain_seed, chain_step};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub records: u64,
    pub checkpoints: u64,
    pub unverified_tail: u64,
    /// Bytes of a final partial line (no trailing newline), not parsed.
    pub truncated_tail_bytes: u64,
    /// First failure, with 1-based line number.
    pub error: Option<String>,
    /// From the header: the previous file's final chain (hex) and sequences.
    pub prev_chain: String,
    pub prev_seq: u64,
    pub next_seq: u64,
    /// Chain after the last checkpoint (hex); `prev_chain` if none.
    pub final_chain: String,
    /// `seq_last` of the last checkpoint; `prev_seq` if none.
    pub last_checkpoint_seq: u64,
    /// Sequence of the last record, checkpointed or not (`next_seq - 1` if none).
    pub last_seq: u64,
    /// The first record after the header is `audit_recovery`.
    pub recovery: Option<Recovery>,
    /// `plat.audit.lost` of an opening `audit_output_failure` (local file,
    /// `recovered`) covered by a checkpoint: what a gap before this file
    /// must equal to be accounted.
    pub opening_loss: Option<u64>,
}

/// An `audit_recovery` record opening a file (start-up found the previous
/// newest file damaged).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovery {
    /// `plat.reason`: `empty_file`, `missing_header` or `truncated_tail`.
    pub reason: String,
    /// `plat.audit.last_checkpoint_seq`: the last durable checkpoint found.
    pub last_checkpoint_seq: Option<u64>,
    /// `plat.audit.max_seq`: the highest sequence that may have been used;
    /// numbering resumes after it.
    pub max_seq: Option<u64>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }

    /// Content after the last checkpoint: complete records not covered by
    /// a checkpoint, or a partial final line.
    pub fn has_unverified_tail(&self) -> bool {
        self.unverified_tail > 0 || self.truncated_tail_bytes > 0
    }
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":");
    let i = line.find(&pat)? + pat.len();
    let rest = line.get(i..)?;
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let end = rest.find(['"', ',', '}']).unwrap_or(rest.len());
    rest.get(..end)
}

fn num(line: &str, key: &str) -> Option<u64> {
    field(line, key).and_then(|s| s.parse().ok())
}

pub fn verify<R: BufRead>(mut r: R) -> std::io::Result<VerifyReport> {
    let mut rep = VerifyReport::default();
    let mut buf = String::new();
    let mut lineno = 0u64;

    // Header.
    if r.read_line(&mut buf)? == 0 {
        rep.error = Some("empty file (no audit_chain_continue header)".into());
        return Ok(rep);
    }
    lineno += 1;
    if field(&buf, "event.action") != Some("audit_chain_continue") {
        rep.error = Some("line 1: missing audit_chain_continue header".into());
        return Ok(rep);
    }
    let (Some(prev_chain), Some(prev_seq), Some(next_seq)) =
        (field(&buf, "plat.audit.prev_chain"), num(&buf, "plat.audit.prev_seq"), num(&buf, "plat.audit.next_seq"))
    else {
        rep.error = Some("line 1: malformed audit_chain_continue header".into());
        return Ok(rep);
    };
    if prev_chain.len() != 64 || next_seq == 0 {
        rep.error = Some("line 1: malformed audit_chain_continue header".into());
        return Ok(rep);
    }
    rep.prev_chain = prev_chain.to_owned();
    rep.prev_seq = prev_seq;
    rep.next_seq = next_seq;
    rep.final_chain = rep.prev_chain.clone();
    rep.last_checkpoint_seq = prev_seq;
    let mut chain = chain_seed(buf.as_bytes());
    let mut expect = next_seq;
    // SEC-302: the record numbered u64::MAX was seen; no record may follow.
    let mut spent = false;
    let last_of = |expect: u64, spent: bool| if spent { u64::MAX } else { expect - 1 };
    let mut batch = Sha256::new();
    let mut batch_first: Option<u64> = None;
    let mut in_batch = 0u64;

    loop {
        buf.clear();
        if r.read_line(&mut buf)? == 0 {
            break;
        }
        lineno += 1;
        if !buf.ends_with('\n') {
            // A short write or power cut cut the last line off: report it as
            // an unverified tail, never as a chain or batch mismatch.
            rep.truncated_tail_bytes = buf.len() as u64;
            break;
        }
        let fail = |m: String| Some(format!("line {lineno}: {m}"));
        match field(&buf, "event.action") {
            Some("audit_checkpoint") => {
                let Some(first) = batch_first.take() else {
                    rep.error = fail("checkpoint without records".into());
                    return Ok(rep);
                };
                let last = last_of(expect, spent);
                let digest: [u8; 32] = std::mem::take(&mut batch).finalize().into();
                if hex::encode(digest) != field(&buf, "plat.audit.batch_sha256").unwrap_or("") {
                    rep.error = fail("batch hash mismatch (records altered, inserted or removed)".into());
                    return Ok(rep);
                }
                if num(&buf, "plat.audit.seq_first") != Some(first) || num(&buf, "plat.audit.seq_last") != Some(last) {
                    rep.error = fail("checkpoint seq_first/seq_last do not match records".into());
                    return Ok(rep);
                }
                chain = chain_step(&chain, &digest, first, last);
                let hex_chain = hex::encode(chain);
                if hex_chain != field(&buf, "plat.audit.chain_sha256").unwrap_or("") {
                    rep.error = fail("chain hash mismatch (checkpoint or header altered, or batch removed)".into());
                    return Ok(rep);
                }
                rep.checkpoints += 1;
                rep.final_chain = hex_chain;
                rep.last_checkpoint_seq = last;
                in_batch = 0;
            }
            Some("audit_chain_continue") => {
                rep.error = fail("second audit_chain_continue header (files concatenated?)".into());
                return Ok(rep);
            }
            _ => {
                if spent || num(&buf, "event.sequence") != Some(expect) {
                    rep.error = fail(format!("sequence gap: expected {expect}"));
                    return Ok(rep);
                }
                if rep.records == 0 && field(&buf, "event.action") == Some("audit_recovery") {
                    rep.recovery = Some(Recovery {
                        reason: field(&buf, "plat.reason").unwrap_or("").to_owned(),
                        last_checkpoint_seq: num(&buf, "plat.audit.last_checkpoint_seq"),
                        max_seq: num(&buf, "plat.audit.max_seq"),
                    });
                }
                if rep.records == 0
                    && field(&buf, "event.action") == Some("audit_output_failure")
                    && field(&buf, "plat.audit.destination") == Some("file")
                    && field(&buf, "plat.audit.state") == Some("recovered")
                {
                    rep.opening_loss = num(&buf, "plat.audit.lost");
                }
                batch_first.get_or_insert(expect);
                match expect.checked_add(1) {
                    Some(n) => expect = n,
                    None => spent = true,
                }
                batch.update(buf.as_bytes());
                in_batch += 1;
                rep.records += 1;
            }
        }
    }
    rep.unverified_tail = in_batch;
    rep.last_seq = last_of(expect, spent);
    // Only a checkpointed record explains a gap (the first checkpoint
    // covers the first record).
    if rep.checkpoints == 0 {
        rep.opening_loss = None;
        if let Some(r) = rep.recovery.as_mut() {
            r.max_seq = None;
        }
    }
    Ok(rep)
}

/// Which record accounts for a sequence gap between files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapAccount {
    /// Rule (a): a checkpointed `audit_output_failure` (local file,
    /// `recovered`) whose `plat.audit.lost` equals the gap size. A recorded
    /// loss; nothing else is missing.
    OutputFailure,
    /// Rule (b): an `audit_recovery` whose `plat.audit.max_seq` ends the
    /// gap. Start-up after a damaged file skipped to the high-water mark:
    /// whether records in the range existed can only be checked against
    /// the remote copy, so this is not a plain OK (SEC-301).
    Recovery,
}

impl GapAccount {
    /// `event.action` of the accounting record.
    pub fn record(self) -> &'static str {
        match self {
            Self::OutputFailure => "audit_output_failure",
            Self::Recovery => "audit_recovery",
        }
    }
}

/// A problem between consecutive files of one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkIssue {
    /// File `index` does not continue the chain of file `index - 1`.
    Broken { index: usize, reason: String },
    /// Records `first..=last` are in neither file (local write failure;
    /// look for `audit_output_failure`, and the syslog copy). `accounted`:
    /// the record opening file `index` that explains the gap, if any (see
    /// the module docs and [`GapAccount`]).
    Gap { index: usize, first: u64, last: u64, accounted: Option<GapAccount> },
}

/// Checks that verified reports, ordered oldest first (sort by `next_seq`),
/// form one chain.
pub fn link(reports: &[VerifyReport]) -> Vec<LinkIssue> {
    let mut v = Vec::new();
    for (i, w) in reports.windows(2).enumerate() {
        let (a, b) = (&w[0], &w[1]);
        let index = i + 1;
        if b.prev_chain != a.final_chain || b.prev_seq != a.last_checkpoint_seq {
            v.push(LinkIssue::Broken {
                index,
                reason: format!(
                    "header names chain {}.. at seq {}, previous file ends with {}.. at seq {}",
                    b.prev_chain.get(..12).unwrap_or(""),
                    b.prev_seq,
                    a.final_chain.get(..12).unwrap_or(""),
                    a.last_checkpoint_seq
                ),
            });
        } else if a.last_seq.checked_add(1).is_some_and(|f| b.next_seq > f) {
            // COMPLIANCE MAPPING:
            // - NIST 800-53: AU-5, AU-9 - a local loss is accepted only when
            //   the chain itself announces exactly that many lost records;
            //   a recovery skip is reported as its own class (SEC-301).
            let (first, last) = (a.last_seq + 1, b.next_seq - 1);
            let accounted = if b.opening_loss == Some(last - first + 1) {
                Some(GapAccount::OutputFailure)
            } else if b.recovery.as_ref().is_some_and(|r| r.max_seq == Some(last)) && recovery_issue(a, b).is_none() {
                Some(GapAccount::Recovery)
            } else {
                None
            };
            v.push(LinkIssue::Gap { index, first, last, accounted });
        } else if b.next_seq <= a.last_seq {
            v.push(LinkIssue::Broken { index, reason: format!("sequence {} reused", b.next_seq) });
        }
        if let Some(reason) = recovery_issue(a, b) {
            v.push(LinkIssue::Broken { index, reason });
        }
    }
    v
}

/// SEC-1: a partial final line is acceptable only in the newest file, or
/// when the next file opens with an `audit_recovery` (`truncated_tail`, or
/// `empty_file`/`missing_header` when the file holding that recovery was
/// damaged in turn) naming the damaged file's last checkpoint; an `audit_recovery` after an
/// intact file means records or a damaged file were removed or forged.
///
/// COMPLIANCE MAPPING:
/// - NIST 800-53: AU-9, AU-10 - an unexplained truncation inside the chain
///   (or an explanation without a truncation) fails verification.
fn recovery_issue(a: &VerifyReport, b: &VerifyReport) -> Option<String> {
    let names = |r: &Recovery| r.last_checkpoint_seq == Some(a.last_checkpoint_seq);
    match (&b.recovery, a.truncated_tail_bytes > 0) {
        (Some(r), true) if r.reason == "truncated_tail" && names(r) => None,
        // L12 stacked damage: the file that held the `truncated_tail`
        // recovery was itself emptied (or lost its header) and replaced;
        // start-up resumed from this file again, so its recovery names the
        // same last checkpoint. The skipped range is then a rule (b) gap.
        (Some(r), true) if (r.reason == "empty_file" || r.reason == "missing_header") && names(r) => None,
        (_, true) => Some(format!(
            "previous file ends in a partial line ({} bytes) and this file does not open with an \
             audit_recovery (truncated_tail, empty_file or missing_header) naming its last checkpoint {}",
            a.truncated_tail_bytes, a.last_checkpoint_seq
        )),
        // The damaged file was empty or headerless: start-up replaced it, or
        // `verify` rejects it on its own; the record must still name the
        // last checkpoint of the file it continues.
        (Some(r), false) if (r.reason == "empty_file" || r.reason == "missing_header") && names(r) => None,
        (Some(r), false) => Some(format!(
            "audit_recovery ({}, last checkpoint {:?}) follows an intact file ending at checkpoint {}",
            r.reason, r.last_checkpoint_seq, a.last_checkpoint_seq
        )),
        (None, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(last_checkpoint_seq: u64, truncated: u64, recovery: Option<(&str, u64)>) -> VerifyReport {
        VerifyReport {
            prev_chain: "a".repeat(64),
            final_chain: "a".repeat(64),
            prev_seq: last_checkpoint_seq,
            next_seq: last_checkpoint_seq + 1,
            last_checkpoint_seq,
            last_seq: last_checkpoint_seq,
            truncated_tail_bytes: truncated,
            recovery: recovery.map(|(r, s)| Recovery {
                reason: r.to_owned(),
                last_checkpoint_seq: Some(s),
                max_seq: None,
            }),
            ..VerifyReport::default()
        }
    }

    fn broken(a: &VerifyReport, b: &VerifyReport) -> bool {
        link(&[a.clone(), b.clone()]).iter().any(|i| matches!(i, LinkIssue::Broken { .. }))
    }

    /// SEC-1: a truncated tail inside the chain needs an `audit_recovery`
    /// naming the damaged file's last checkpoint.
    #[test]
    fn truncated_tail_inside_the_chain_needs_a_matching_recovery() {
        let a = rep(10, 37, None);
        assert!(broken(&a, &rep(10, 0, None)), "unexplained truncation");
        assert!(broken(&a, &rep(10, 0, Some(("truncated_tail", 9)))), "wrong checkpoint");
        assert!(broken(&a, &rep(10, 0, Some(("empty_file", 9)))), "wrong checkpoint");
        assert!(broken(&a, &rep(10, 0, Some(("other", 10)))), "wrong reason");
        assert!(broken(&a, &rep(10, 0, None)), "no recovery");
        // L12 stacked damage: the truncated_tail file was emptied in turn.
        assert!(!broken(&a, &rep(10, 0, Some(("empty_file", 10)))));
        assert!(!broken(&a, &rep(10, 0, Some(("missing_header", 10)))));
        assert!(!broken(&a, &rep(10, 0, Some(("truncated_tail", 10)))));
        // The newest file may end in a partial line.
        let newest = VerifyReport { prev_seq: 5, next_seq: 6, ..a };
        assert!(link(&[rep(5, 0, None), newest]).is_empty());
    }

    /// SEC-1: an `audit_recovery` after an intact file is a broken link.
    #[test]
    fn recovery_after_an_intact_file_is_flagged() {
        let a = rep(10, 0, None);
        assert!(broken(&a, &rep(10, 0, Some(("truncated_tail", 10)))));
        assert!(broken(&a, &rep(10, 0, Some(("empty_file", 4)))));
        assert!(!broken(&a, &rep(10, 0, Some(("empty_file", 10)))));
        assert!(!broken(&a, &rep(10, 0, Some(("missing_header", 10)))));
        assert!(!broken(&a, &rep(10, 0, None)));
    }

    fn gap(lost: Option<u64>, first: u64, last: u64) -> Vec<LinkIssue> {
        let a = VerifyReport { last_seq: first - 1, ..rep(first - 1, 0, None) };
        let mut b = rep(last + 3, 0, None);
        b.prev_chain = a.final_chain.clone();
        b.prev_seq = a.last_checkpoint_seq;
        b.next_seq = last + 1;
        b.last_seq = last + 3;
        b.opening_loss = lost;
        link(&[a, b])
    }

    /// L12: a gap is accounted only by an announced loss of exactly its size.
    #[test]
    fn gap_is_accounted_only_by_an_exact_lost_count() {
        let acc = |is: &[LinkIssue]| match is {
            [LinkIssue::Gap { first: 87, last: 128, accounted, .. }] => *accounted,
            other => panic!("{other:?}"),
        };
        assert_eq!(acc(&gap(Some(42), 87, 128)), Some(GapAccount::OutputFailure));
        assert_eq!(acc(&gap(None, 87, 128)), None);
        assert_eq!(acc(&gap(Some(41), 87, 128)), None);
        assert_eq!(acc(&gap(Some(43), 87, 128)), None);
        // An audit_recovery announcing the skipped range up to 128.
        let a = VerifyReport { last_seq: 86, ..rep(86, 0, None) };
        let mut b = rep(86, 0, Some(("empty_file", 86)));
        b.next_seq = 129;
        b.last_seq = 130;
        for (max, want) in [(Some(128), Some(GapAccount::Recovery)), (Some(127), None), (None, None)] {
            b.recovery.as_mut().unwrap().max_seq = max;
            assert_eq!(acc(&link(&[a.clone(), b.clone()])), want, "{max:?}");
        }
    }

    /// Only a checkpointed opening `audit_output_failure` for the local file
    /// in state `recovered` sets `opening_loss`.
    #[test]
    fn verify_reads_the_opening_loss_record_only_when_checkpointed() {
        let header = format!(
            "{{\"event.action\":\"audit_chain_continue\",\"plat.audit.prev_chain\":\"{}\",\
             \"plat.audit.prev_seq\":86,\"plat.audit.next_seq\":129}}\n",
            "0".repeat(64)
        );
        let of = |dest: &str, state: &str| {
            format!(
                "{{\"event.sequence\":129,\"event.action\":\"audit_output_failure\",\
                 \"plat.audit.destination\":\"{dest}\",\"plat.audit.state\":\"{state}\",\"plat.audit.lost\":42}}\n"
            )
        };
        // Unverified (no checkpoint): not trusted.
        let r = verify(format!("{header}{}", of("file", "recovered")).as_bytes()).unwrap();
        assert_eq!(r.opening_loss, None);
        // Checkpointed: build the checkpoint the way the logger does.
        for (dest, state, want) in
            [("file", "recovered", Some(42)), ("file", "degraded", None), ("syslog", "recovered", None)]
        {
            let rec = of(dest, state);
            let digest: [u8; 32] = Sha256::digest(rec.as_bytes()).into();
            let chain = chain_step(&chain_seed(header.as_bytes()), &digest, 129, 129);
            let cp = format!(
                "{{\"event.action\":\"audit_checkpoint\",\"plat.audit.seq_first\":129,\"plat.audit.seq_last\":129,\
                 \"plat.audit.batch_sha256\":\"{}\",\"plat.audit.chain_sha256\":\"{}\"}}\n",
                hex::encode(digest),
                hex::encode(chain)
            );
            let r = verify(format!("{header}{rec}{cp}").as_bytes()).unwrap();
            assert!(r.ok(), "{r:?}");
            assert_eq!(r.opening_loss, want, "{dest} {state}");
        }
    }

    /// The recovery record is picked up from real file content.
    #[test]
    fn verify_reads_the_opening_recovery_record() {
        let hdr = format!(
            "{{\"event.action\":\"audit_chain_continue\",\"plat.audit.prev_chain\":\"{}\",\
             \"plat.audit.prev_seq\":4,\"plat.audit.next_seq\":6}}\n",
            "0".repeat(64)
        );
        let rec = "{\"event.sequence\":6,\"event.action\":\"audit_recovery\",\"plat.reason\":\"truncated_tail\",\
                   \"plat.audit.last_checkpoint_seq\":4,\"plat.audit.max_seq\":5}\n";
        let r = verify(format!("{hdr}{rec}").as_bytes()).unwrap();
        assert_eq!(
            r.recovery,
            Some(Recovery { reason: "truncated_tail".into(), last_checkpoint_seq: Some(4), max_seq: None })
        );
        let r = verify(hdr.as_bytes()).unwrap();
        assert_eq!(r.recovery, None);
    }

    /// SEC-302: a file ending at sequence u64::MAX verifies without
    /// wrapping, and nothing may follow it in the same file or the next.
    #[test]
    fn verify_does_not_wrap_at_the_end_of_the_sequence_space() {
        let next = u64::MAX - 1;
        let header = format!(
            "{{\"event.action\":\"audit_chain_continue\",\"plat.audit.prev_chain\":\"{}\",\
             \"plat.audit.prev_seq\":0,\"plat.audit.next_seq\":{next}}}\n",
            "0".repeat(64)
        );
        let recs: String =
            [next, u64::MAX].iter().map(|s| format!("{{\"event.sequence\":{s},\"event.action\":\"x\"}}\n")).collect();
        let digest: [u8; 32] = Sha256::digest(recs.as_bytes()).into();
        let chain = chain_step(&chain_seed(header.as_bytes()), &digest, next, u64::MAX);
        let cp = format!(
            "{{\"event.action\":\"audit_checkpoint\",\"plat.audit.seq_first\":{next},\
             \"plat.audit.seq_last\":{},\"plat.audit.batch_sha256\":\"{}\",\"plat.audit.chain_sha256\":\"{}\"}}\n",
            u64::MAX,
            hex::encode(digest),
            hex::encode(chain)
        );
        let r = verify(format!("{header}{recs}{cp}").as_bytes()).unwrap();
        assert!(r.ok(), "{r:?}");
        assert_eq!((r.last_seq, r.last_checkpoint_seq), (u64::MAX, u64::MAX));
        let more = "{\"event.sequence\":0,\"event.action\":\"x\"}\n";
        assert!(!verify(format!("{header}{recs}{more}").as_bytes()).unwrap().ok());
        // A following file cannot continue after u64::MAX.
        let mut b = r.clone();
        b.prev_chain = r.final_chain.clone();
        b.next_seq = 1;
        assert!(matches!(link(&[r, b])[..], [LinkIssue::Broken { .. }]));
    }
}
