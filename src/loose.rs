//! Loose object import: a single zlib stream of `<type> <len>\0<payload>`.

use crate::gitobj::{decode_loose_envelope, GitKind};
use crate::oid::Oid;

pub struct LooseOutcome {
    pub kind: GitKind,
    pub payload: Vec<u8>,
    /// Recomputed object id.
    pub actual_oid: Oid,
    pub stream_end: bool,
}

/// Parse a loose object file. The caller compares `actual_oid` against any
/// oid claimed by the path/filename.
pub fn parse_loose(buf: &[u8], max_bytes: usize) -> Result<LooseOutcome, String> {
    let r = crate::zlib::inflate_bounded(buf, max_bytes)
        .map_err(|e| format!("loose inflate failed: {e}"))?;
    let (kind, payload) = decode_loose_envelope(&r.data)?;
    let actual = crate::gitobj::hash_object(kind, payload);
    Ok(LooseOutcome {
        kind,
        payload: payload.to_vec(),
        actual_oid: actual,
        stream_end: r.stream_end,
    })
}
