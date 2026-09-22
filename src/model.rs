//! Shared data model types used across storage and the resolution engine.

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_DEPTH: usize = 64;
pub const DEFAULT_TOTAL_BUDGET: u64 = 64 * 1024 * 1024;
pub const DEFAULT_SINGLE_RATIO: f64 = 0.8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    Full,
    OfsDelta,
    RefDelta,
    Loose,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::Full => "full",
            NodeKind::OfsDelta => "ofs-delta",
            NodeKind::RefDelta => "ref-delta",
            NodeKind::Loose => "loose",
        }
    }
    pub fn parse(s: &str) -> NodeKind {
        match s {
            "ofs-delta" => NodeKind::OfsDelta,
            "ref-delta" => NodeKind::RefDelta,
            "loose" => NodeKind::Loose,
            _ => NodeKind::Full,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeOrigin {
    Pack,
    Loose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRef {
    pub source_id: i64,
    pub offset: i64, // -1 for loose objects
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseRef {
    pub kind: String, // "ofs" | "oid"
    pub source_id: Option<i64>,
    pub offset: Option<i64>,
    pub oid_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateView {
    pub id: i64,
    pub node_source_id: i64,
    pub node_offset: i64,
    pub oid_hex: String,
    pub origin: String, // idx | loose-path | hash | ref-inferred
    pub source_label: String,
    pub hash_match: bool,
    pub confidence: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Budgets {
    pub max_depth: usize,
    pub total_bytes: u64,
    pub single_ratio: f64,
}

impl Budgets {
    pub fn defaults() -> Self {
        Budgets {
            max_depth: DEFAULT_MAX_DEPTH,
            total_bytes: DEFAULT_TOTAL_BUDGET,
            single_ratio: DEFAULT_SINGLE_RATIO,
        }
    }

    pub fn single_cap(&self) -> u64 {
        (self.total_bytes as f64 * self.single_ratio) as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolveStatus {
    Resolved,
    MissingBase,
    Cycle,
    BadObject,
    BudgetPaused,
    TooLarge,
    TooDeep,
    ParseError,
}

impl ResolveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolveStatus::Resolved => "resolved",
            ResolveStatus::MissingBase => "missing-base",
            ResolveStatus::Cycle => "cycle",
            ResolveStatus::BadObject => "bad-object",
            ResolveStatus::BudgetPaused => "budget-paused",
            ResolveStatus::TooLarge => "too-large",
            ResolveStatus::TooDeep => "too-deep",
            ResolveStatus::ParseError => "parse-error",
        }
    }
    pub fn parse(s: &str) -> ResolveStatus {
        match s {
            "resolved" => ResolveStatus::Resolved,
            "missing-base" => ResolveStatus::MissingBase,
            "cycle" => ResolveStatus::Cycle,
            "bad-object" => ResolveStatus::BadObject,
            "budget-paused" => ResolveStatus::BudgetPaused,
            "too-large" => ResolveStatus::TooLarge,
            "too-deep" => ResolveStatus::TooDeep,
            _ => ResolveStatus::ParseError,
        }
    }
    pub fn is_terminal_failure(self) -> bool {
        // Missing base and budget-paused are retryable; everything else is a
        // hard isolation of this object.
        !matches!(self, ResolveStatus::Resolved | ResolveStatus::MissingBase | ResolveStatus::BudgetPaused)
    }
}

/// A blocked-chain entry presented to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    pub node: NodeRef,
    pub kind: String,
    pub needs: Option<BaseRef>,
    pub reason: String,
}
