//! Shared data records surfaced by parser/store/engine.

use serde::{Deserialize, Serialize};

/// Where an object candidate lives on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Origin {
    Pack,
    Loose,
}

impl Origin {
    pub fn name(self) -> &'static str {
        match self {
            Origin::Pack => "pack",
            Origin::Loose => "loose",
        }
    }
    pub fn parse(s: &str) -> Origin {
        match s {
            "loose" => Origin::Loose,
            _ => Origin::Pack,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s {
            "info" => Severity::Info,
            "warning" => Severity::Warning,
            _ => Severity::Error,
        }
    }
}

/// A single piece of forensic evidence attached to an object or source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Issue {
    pub code: String,
    pub severity: Severity,
    pub message: String,
}

impl Issue {
    pub fn error(code: impl Into<String>, msg: impl Into<String>) -> Issue {
        Issue { code: code.into(), severity: Severity::Error, message: msg.into() }
    }
    pub fn warn(code: impl Into<String>, msg: impl Into<String>) -> Issue {
        Issue { code: code.into(), severity: Severity::Warning, message: msg.into() }
    }
    pub fn info(code: impl Into<String>, msg: impl Into<String>) -> Issue {
        Issue { code: code.into(), severity: Severity::Info, message: msg.into() }
    }
}

/// Reconstruction status for an object on a branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ResolveState {
    Resolved,
    Blocked,
    Paused,
}

impl ResolveState {
    pub fn name(self) -> &'static str {
        match self {
            ResolveState::Resolved => "resolved",
            ResolveState::Blocked => "blocked",
            ResolveState::Paused => "paused",
        }
    }
    pub fn parse(s: &str) -> ResolveState {
        match s {
            "resolved" => ResolveState::Resolved,
            "paused" => ResolveState::Paused,
            _ => ResolveState::Blocked,
        }
    }
    pub fn label_zh(self) -> &'static str {
        match self {
            ResolveState::Resolved => "已还原",
            ResolveState::Blocked => "阻塞",
            ResolveState::Paused => "预算暂停(可重试)",
        }
    }
}
