//! File import: detect pack/index/loose, preserve bytes + offsets, persist candidates.

use crate::git::index::parse_index;
use crate::git::loose::parse_loose;
use crate::git::oid::{hash_object, sha1_raw, GitType, Oid};
use crate::git::pack::{parse_pack, PackKind};
use crate::models::CandidateEvidence;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub filename: String,
    pub candidates: usize,
    pub evidence: Vec<CandidateEvidence>,
}

fn sha256_file(buf: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(buf);
    hex::encode(h.finalize())
}

fn next_seq(conn: &Connection) -> rusqlite::Result<i64> {
    let v: Option<i64> = conn
        .query_row("SELECT MAX(imported_seq) FROM sources", [], |r| r.get(0))
        .ok()
        .flatten();
    Ok(v.unwrap_or(0) + 1)
}

fn store_bytes(data_dir: &Path, sub: &str, digest: &str, buf: &[u8]) -> std::io::Result<PathBuf> {
    let dir = data_dir.join(sub);
    fs::create_dir_all(&dir)?;
    let p = dir.join(digest);
    if !p.exists() {
        fs::write(&p, buf)?;
    }
    Ok(p)
}

pub fn detect_kind(buf: &[u8]) -> &'static str {
    if buf.len() >= 8 && &buf[0..4] == b"PACK" {
        "pack"
    } else if buf.len() >= 8 && &buf[0..4] == b"\xfftOc" {
        "index"
    } else {
        "loose"
    }
}
