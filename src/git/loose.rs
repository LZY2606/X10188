//! Loose object parsing (`zlib(type size\\0body)`).

use super::types::{hash_object, ObjType};
use super::zlib::{inflate_one, InflateLimits, InflateStatus};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct LooseImage {
    pub kind: Option<ObjType>,
    pub body: Vec<u8>,
    pub compressed_len: usize,
    pub inflated_len: u64,
    pub computed_oid: [u8; 20],
    pub status: &'static str,
    pub detail: String,
    pub header: String,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseImage> {
    // Loose objects carry the size only inside the inflated header, so parse
    // with claimed=0 (no size pre-check) under the permanent hard cap.
    let outcome = inflate_one(
        data,
        InflateLimits {
            claimed: 0,
            total_remaining: super::zlib::DEFAULT_HARD_CAP,
            max_ratio: u64::MAX,
            hard_cap: super::zlib::DEFAULT_HARD_CAP,
        },
    )?;

    let mut status = match outcome.status {
        InflateStatus::Ok => "ok",
        InflateStatus::SizeSpoof { .. } => "size_spoof",
        InflateStatus::Truncated => "truncated",
        InflateStatus::HardCapExceeded => "hard_cap",
        InflateStatus::BudgetPaused { .. } => "budget_paused",
    };
    let detail = match &outcome.status {
        InflateStatus::SizeSpoof { detail } => detail.clone(),
        _ => String::new(),
    };

    let mut kind = None;
    let mut body = Vec::new();
    let mut header = String::new();
    let mut computed = [0u8; 20];

    if status == "ok" {
        let nul = outcome
            .data
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::bad("loose object missing NUL in header"))?;
        header = String::from_utf8_lossy(&outcome.data[..nul]).to_string();
        let mut parts = header.split(' ');
        let type_name = parts
            .next()
            .ok_or_else(|| Error::bad("loose object missing type"))?;
        let size_str = parts
            .next()
            .ok_or_else(|| Error::bad("loose object missing size"))?;
        let declared_size: u64 = size_str
            .parse()
            .map_err(|_| Error::bad(format!("loose object size '{size_str}' not numeric")))?;
        body = outcome.data[nul + 1..].to_vec();

        if declared_size as usize != body.len() {
            status = "size_spoof";
            // detail already empty here
            return Ok(LooseImage {
                kind: None,
                body: Vec::new(),
                compressed_len: outcome.compressed_len,
                inflated_len: outcome.actual,
                computed_oid: computed,
                status,
                detail: format!(
                    "loose header declares size {declared_size} but body is {} bytes",
                    body.len()
                ),
                header,
            });
        }

        match ObjType::from_loose_name(type_name) {
            Ok(k) => kind = Some(k),
            Err(e) => {
                status = "bad_type";
                return Ok(LooseImage {
                    kind: None,
                    body: Vec::new(),
                    compressed_len: outcome.compressed_len,
                    inflated_len: outcome.actual,
                    computed_oid: computed,
                    status,
                    detail: e.to_string(),
                    header,
                });
            }
        }

        computed = hash_object(kind.unwrap(), &body);
    }

    Ok(LooseImage {
        kind,
        body,
        compressed_len: outcome.compressed_len,
        inflated_len: outcome.actual,
        computed_oid: computed,
        status,
        detail,
        header,
    })
}
