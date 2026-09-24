//! zlib stream handling with explicit byte-boundary detection, size-spoof
//! detection mid-inflation and budget-aware limits.

use crate::error::Result;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

#[derive(Debug, Clone)]
pub struct InflateLimits {
    /// Size advertised by the object header / delta varint. 0 = unknown.
    pub claimed: u64,
    /// Bytes still available in the global total-expansion budget.
    pub total_remaining: u64,
    /// Maximum allowed (claimed or actual) / compressed length.
    pub max_ratio: u64,
    /// Hard permanent ceiling for a single inflated object.
    pub hard_cap: u64,
}

impl Default for InflateLimits {
    fn default() -> Self {
        InflateLimits {
            claimed: 0,
            total_remaining: u64::MAX,
            max_ratio: u64::MAX,
            hard_cap: DEFAULT_HARD_CAP,
        }
    }
}

pub const DEFAULT_HARD_CAP: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateStatus {
    Ok,
    /// Actual inflated length did not match the advertised size. The zlib
    /// boundary was still located by draining the remainder.
    SizeSpoof { detail: String },
    /// zlib stream ended before a complete object.
    Truncated,
    /// Permanent hard cap exceeded.
    HardCapExceeded,
    /// Retryable budget pause.
    BudgetPaused { kind: String, limit: u64, need: u64 },
}

#[derive(Debug, Clone)]
pub struct InflateOutcome {
    /// Inflated bytes; empty unless status == Ok.
    pub data: Vec<u8>,
    /// Compressed bytes consumed, measured from the start of `input`.
    pub compressed_len: usize,
    pub trailing: usize,
    pub claimed: u64,
    pub actual: u64,
    pub status: InflateStatus,
}

impl InflateOutcome {
    pub fn ok(&self) -> bool {
        self.status == InflateStatus::Ok
    }
}

struct CountingReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Read for CountingReader<'a> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Inflate exactly one zlib stream contained in `input`. Always locates the
/// stream boundary when the stream is complete (even when the advertised
/// size is a lie), so pack parsing can advance to the next object.
pub fn inflate_one(input: &[u8], lim: &InflateLimits) -> Result<InflateOutcome> {
    let comp_len_hint = input.len() as u64;

    // Pre-flight budget checks against the claimed size.
    if lim.claimed > 0 {
        if lim.claimed > lim.total_remaining {
            return Ok(paused(
                input,
                0,
                lim.claimed,
                "total_expansion",
                lim.total_remaining,
                lim.claimed,
            ));
        }
        if comp_len_hint > 0 && lim.claimed > lim.max_ratio.saturating_mul(comp_len_hint) {
            return Ok(paused(
                input,
                0,
                lim.claimed,
                "single_object_ratio",
                lim.max_ratio,
                lim.claimed,
            ));
        }
        if lim.claimed > lim.hard_cap {
            return Ok(InflateOutcome {
                data: Vec::new(),
                compressed_len: 0,
                trailing: input.len(),
                claimed: lim.claimed,
                actual: 0,
                status: InflateStatus::HardCapExceeded,
            });
        }
    }

    let reader = CountingReader { buf: input, pos: 0 };
    let mut dec = ZlibDecoder::new(reader);
    let mut chunk = [0u8; 16 * 1024];
    let mut data: Vec<u8> = Vec::new();
    let mut actual: u64 = 0;
    let mut spoofed: Option<String> = None;

    loop {
        match dec.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                actual += n as u64;
                if spoofed.is_none() {
                    if lim.claimed > 0 && actual > lim.claimed {
                        // Decompression is only halfway (or less) and the
                        // advertised size is already disproven. Keep draining
                        // so the boundary is still recovered.
                        spoofed = Some(format!(
                            "inflated {} bytes but header claimed {}",
                            actual, lim.claimed
                        ));
                    } else if actual > lim.total_remaining {
                        dec.get_ref().pos;
                        return Ok(paused(
                            input,
                            dec.get_ref().pos,
                            actual,
                            "total_expansion",
                            lim.total_remaining,
                            actual,
                        ));
                    } else if actual > lim.hard_cap {
                        return Ok(InflateOutcome {
                            data: Vec::new(),
                            compressed_len: dec.get_ref().pos,
                            trailing: input.len() - dec.get_ref().pos,
                            claimed: lim.claimed,
                            actual,
                            status: InflateStatus::HardCapExceeded,
                        });
                    }
                }
                if spoofed.is_none() {
                    data.extend_from_slice(&chunk[..n]);
                }
            }
            Err(e) => {
                let consumed = dec.get_ref().pos;
                let kind = if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.to_string().contains("unexpected end")
                {
                    InflateStatus::Truncated
                } else {
                    InflateStatus::SizeSpoof {
                        detail: format!("zlib decode failed: {e}"),
                    }
                };
                return Ok(InflateOutcome {
                    data: Vec::new(),
                    compressed_len: consumed,
                    trailing: input.len() - consumed,
                    claimed: lim.claimed,
                    actual,
                    status: kind,
                });
            }
        }
    }

    let consumed = dec.get_ref().pos;
    // flate2 verifies the adler32 checksum when the stream terminates.
    drop(dec);

    let status = if let Some(detail) = spoofed {
        InflateStatus::SizeSpoof { detail }
    } else if lim.claimed > 0 && actual != lim.claimed {
        InflateStatus::SizeSpoof {
            detail: format!("inflated {actual} bytes but header claimed {}", lim.claimed),
        }
    } else if actual > lim.hard_cap {
        InflateStatus::HardCapExceeded
    } else if actual > lim.total_remaining {
        return Ok(paused(
            input,
            consumed,
            actual,
            "total_expansion",
            lim.total_remaining,
            actual,
        ));
    } else if comp_len_hint > 0
        && lim.max_ratio < u64::MAX
        && actual > lim.max_ratio.saturating_mul(comp_len_hint)
    {
        return Ok(InflateOutcome {
            data: Vec::new(),
            compressed_len: consumed,
            trailing: input.len() - consumed,
            claimed: lim.claimed,
            actual,
            status: InflateStatus::BudgetPaused {
                kind: "single_object_ratio".into(),
                limit: lim.max_ratio,
                need: actual,
            },
        });
    } else {
        InflateStatus::Ok
    };

    Ok(InflateOutcome {
        data: if status == InflateStatus::Ok { data } else { Vec::new() },
        compressed_len: consumed,
        trailing: input.len() - consumed,
        claimed: lim.claimed,
        actual,
        status,
    })
}

#[allow(clippy::too_many_arguments)]
fn paused(
    input: &[u8],
    consumed: usize,
    actual: u64,
    kind: &str,
    limit: u64,
    need: u64,
) -> InflateOutcome {
    InflateOutcome {
        data: Vec::new(),
        compressed_len: consumed,
        trailing: input.len() - consumed,
        claimed: actual,
        actual,
        status: InflateStatus::BudgetPaused {
            kind: kind.into(),
            limit,
            need,
        },
    }
}

/// Parse-time drain: only locate the boundary and check the claimed size.
/// No configurable budget is applied (imports must never be paused), only
/// the permanent hard cap.
pub fn drain_boundary(input: &[u8], claimed: u64) -> Result<InflateOutcome> {
    inflate_one(
        input,
        &InflateLimits {
            claimed,
            total_remaining: DEFAULT_HARD_CAP,
            max_ratio: u64::MAX,
            hard_cap: DEFAULT_HARD_CAP,
        },
    )
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).expect("zlib encode");
    enc.finish().expect("zlib finish")
}

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
