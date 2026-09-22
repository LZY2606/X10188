//! Core "包链显微镜" analysis engine.
//!
//! Imported sources (pack / idx / loose object) are parsed without invoking
//! system git. Candidates are resolved into materialized objects with full
//! provenance; failures are isolated, budget exhaustion yields a retriable
//! paused state, and adding a base later only re-runs the affected subgraph.

use crate::delta::{apply_delta, DeltaStep};
use crate::gitobj::{hash_object, GitKind};
use crate::oid::Oid;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Identity of one object location: (source row id, absolute pack offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CandidateKey {
    pub source_id: i64,
    /// Absolute pack offset; u64::MAX for loose-object sources.
    pub offset: u64,
}

impl CandidateKey {
    pub fn loose(source_id: i64) -> CandidateKey {
        CandidateKey {
            source_id,
            offset: u64::MAX,
        }
    }
    pub fn tag(&self) -> String {
        if self.offset == u64::MAX {
            format!("loose#{}", self.source_id)
        } else {
            format!("pack#{}@{:#x}", self.source_id, self.offset)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Pack,
    Loose,
}

/// A raw, not-yet-resolved object location.
#[derive(Clone)]
pub struct Candidate {
    pub key: CandidateKey,
    pub origin: Origin,
    pub kind: GitKind,
    /// Oid claimed by idx (pack) or by loose path/filename.
    pub claimed_oid: Option<Oid>,
    pub declared_size: u64,
    pub base_ofs: Option<u64>,
    pub base_oid: Option<Oid>,
    pub idx_crc32: Option<u32>,
    pub measured_crc32: Option<u32>,
    pub loose_payload: Option<Vec<u8>>,
    /// Stable rank: (source content sha1, offset, source id) — import order free.
    pub rank: (String, u64, i64),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StepTrace {
    pub range: [usize; 2],
    pub kind: String,
    pub count: usize,
    pub src_range: Option<[usize; 2]>,
    pub out_range: [usize; 2],
}

impl From<&DeltaStep> for StepTrace {
    fn from(s: &DeltaStep) -> Self {
        StepTrace {
            range: [s.instr_range.0, s.instr_range.1],
            kind: match s.kind {
                crate::delta::StepKind::Insert => "insert",
                crate::delta::StepKind::Copy => "copy",
            }
            .into(),
            count: s.count,
            src_range: s.src_range.map(|(a, b)| [a, b]),
            out_range: [s.out_range.0, s.out_range.1],
        }
    }
}

/// One level of delta reconstruction evidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeltaTrace {
    pub base_key: String,
    pub base_oid: String,
    pub instr_start: usize,
    pub instr_end: usize,
    pub input_len: usize,
    pub output_len: usize,
    pub steps: Vec<StepTrace>,
    pub check_ok: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Pending,
    Resolved,
    Blocked,
    Paused,
    Corrupt,
}

impl serde::Serialize for NodeState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            NodeState::Pending => "pending",
            NodeState::Resolved => "resolved",
            NodeState::Blocked => "blocked",
            NodeState::Paused => "paused",
            NodeState::Corrupt => "corrupt",
        })
    }
}

/// Result of resolving one candidate.
#[derive(Clone)]
pub struct Resolved {
    pub key: CandidateKey,
    pub state: NodeState,
    pub kind: GitKind,
    pub payload: Option<Vec<u8>>,
    pub expected_oid: Oid,
    pub oid_ok: bool,
    pub traces: Vec<DeltaTrace>,
    pub evidence: Vec<String>,
    /// Keys walked on the way to the terminal blocker (nearest first).
    pub blocking_chain: Vec<CandidateKey>,
    /// Bytes expanded while resolving this exact node (its inflate/delta).
    pub own_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Budget {
    pub max_depth: usize,
    pub max_total_bytes: u64,
    pub max_object_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            max_total_bytes: 64 * 1024 * 1024,
            max_object_ratio: 0.5,
        }
    }
}

impl Budget {
    pub fn per_object_cap(&self) -> u64 {
        (self.max_total_bytes as f64 * self.max_object_ratio) as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Pack,
    Idx,
    Loose,
    Unknown,
}

pub struct SourceData {
    pub id: i64,
    pub name: String,
    pub kind: SourceKind,
    pub bytes: Vec<u8>,
    pub digest: String,
    /// Parse-time diagnostics (pack scan / idx fanout / loose decode).
    pub diagnostics: Vec<String>,
}

pub struct IdxAttachment {
    pub source_id: i64,
    pub pack_source_id: i64,
}

pub struct Engine {
    pub sources: BTreeMap<i64, SourceData>,
    pub candidates: BTreeMap<CandidateKey, Candidate>,
    pub resolved: HashMap<CandidateKey, Resolved>,
    /// oid -> keys claiming that oid via idx/filename (deterministic order).
    pub claim_by_oid: BTreeMap<Oid, Vec<CandidateKey>>,
    /// oid -> keys whose *materialized* content hashes to that oid.
    pub actual_by_oid: BTreeMap<Oid, Vec<CandidateKey>>,
    pub idx_attachments: Vec<IdxAttachment>,
    pub idx_details: HashMap<i64, crate::idx::IdxInfo>,
    pub pins: HashMap<Oid, i64>,
    pub budget: Budget,
    pub total_used: u64,
    pub budget_paused: bool,
    pub generation: u64,
}
