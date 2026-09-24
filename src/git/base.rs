//! Shared small helpers for object addressing.

use crate::git::GitType;

/// Where a candidate object originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Pack,
    Loose,
}

impl SourceKind {
    pub fn name(self) -> &'static str {
        match self {
            SourceKind::Pack => "pack",
            SourceKind::Loose => "loose",
        }
    }
}

/// Fully typed reconstructed object.
#[derive(Debug, Clone)]
pub struct Reconstructed {
    pub obj_type: GitType,
    pub data: Vec<u8>,
}

/// Default resource budgets for reconstruction.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_depth: usize,
    pub max_total_bytes: u64,
    /// Maximum allowed output/input expansion ratio for a single object.
    pub max_single_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            max_total_bytes: 256 * 1024 * 1024,
            max_single_ratio: 64.0,
        }
    }
}
