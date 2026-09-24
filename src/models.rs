//! Shared data types for parsed evidence and API payloads.

use serde::{Deserialize, Serialize};

/// One piece of forensic evidence attached to an object or a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Stable machine-readable code, e.g. `crc_mismatch`.
    pub code: String,
    /// Human readable explanation.
    pub message: String,
}

impl Evidence {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Evidence {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// A single delta instruction's decoded range (for the step audit trail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaOp {
    pub kind: String, // "copy" | "insert"
    pub op_start: u64,
    pub op_end: u64,
    pub src_off: Option<u64>,
    pub src_len: Option<u64>,
    pub insert_len: Option<u64>,
}
