//! Offline verification of hash-chained audit files (`platd verify-log`).
//!
//! Per file: the `audit_chain_continue` header seeds the chain; records must
//! be numbered consecutively from its `next_seq`; each checkpoint must match
//! the batch hash, its `seq_first`/`seq_last`, and the chain. Records after
//! the last checkpoint (crash or truncation) are reported as unverified.
//!
//! Across files ([`link`]): each file's header must name the previous
//! file's final chain and checkpoint sequence, which detects a removed,
//! replaced or reordered file; a sequence gap between files means records
//! were not written locally (see `audit_output_failure`).
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
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.error.is_none()
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
    let mut batch = Sha256::new();
    let mut batch_first: Option<u64> = None;
    let mut in_batch = 0u64;

    loop {
        buf.clear();
        if r.read_line(&mut buf)? == 0 {
            break;
        }
        lineno += 1;
        let fail = |m: String| Some(format!("line {lineno}: {m}"));
        match field(&buf, "event.action") {
            Some("audit_checkpoint") => {
                let Some(first) = batch_first.take() else {
                    rep.error = fail("checkpoint without records".into());
                    return Ok(rep);
                };
                let last = expect - 1;
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
                if num(&buf, "event.sequence") != Some(expect) {
                    rep.error = fail(format!("sequence gap: expected {expect}"));
                    return Ok(rep);
                }
                batch_first.get_or_insert(expect);
                expect += 1;
                batch.update(buf.as_bytes());
                in_batch += 1;
                rep.records += 1;
            }
        }
    }
    rep.unverified_tail = in_batch;
    rep.last_seq = expect - 1;
    Ok(rep)
}

/// A problem between consecutive files of one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkIssue {
    /// File `index` does not continue the chain of file `index - 1`.
    Broken { index: usize, reason: String },
    /// Records `first..=last` are in neither file (local write failure;
    /// look for `audit_output_failure`, and the syslog copy).
    Gap { index: usize, first: u64, last: u64 },
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
        } else if b.next_seq > a.last_seq + 1 {
            v.push(LinkIssue::Gap { index, first: a.last_seq + 1, last: b.next_seq - 1 });
        } else if b.next_seq <= a.last_seq {
            v.push(LinkIssue::Broken { index, reason: format!("sequence {} reused", b.next_seq) });
        }
    }
    v
}
