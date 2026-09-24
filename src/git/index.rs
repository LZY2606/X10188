//! Parse a Git pack `.idx` file (v2 preferred, v1 tolerated).

use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxProblem {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct IdxObject {
    pub oid: String,
    pub offset: u64,
    /// CRC32 from the v2 index, if present.
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct IdxSummary {
    pub version: u8,
    /// The 256-entry fanout table; fanout[255] = object count.
    pub fanout: [u32; 256],
    pub objects: Vec<IdxObject>,
    /// Pack checksum stored in the idx (bytes 40 before end for v2).
    pub pack_checksum: Option<String>,
    pub idx_checksum_stored: Option<String>,
    pub idx_checksum_actual: Option<String>,
    pub checksum_valid: bool,
    pub problems: Vec<IdxProblem>,
}

fn p(code: &str, msg: impl Into<String>) -> IdxProblem {
    IdxProblem {
        code: code.into(),
        message: msg.into(),
    }
}

pub fn parse_idx(data: &[u8]) -> IdxSummary {
    let mut problems = Vec::new();

    if data.len() >= 8 && &data[0..4] == b"\xfftOc" {
        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if version != 2 {
            return bad(format!("unsupported idx version {}", version));
        }
        parse_v2(data, &mut problems)
    } else {
        parse_v1(data, &mut problems)
    }
}

fn bad(msg: String) -> IdxSummary {
    IdxSummary {
        version: 0,
        fanout: [0u32; 256],
        objects: Vec::new(),
        pack_checksum: None,
        idx_checksum_stored: None,
        idx_checksum_actual: None,
        checksum_valid: false,
        problems: vec![p("bad_idx", msg)],
    }
}

fn parse_v2(data: &[u8], problems: &mut Vec<IdxProblem>) -> IdxSummary {
    // header 8, fanout 1024, oids 20*n, crc 4*n, offsets 4*n, 2x trailing sha
    if data.len() < 8 + 1024 + 40 {
        return bad("idx v2 too short for fanout + trailers".into());
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let s = 8 + i * 4;
        fanout[i] = u32::from_be_bytes(data[s..s + 4].try_into().unwrap());
    }
    let n = fanout[255] as usize;
    let oid_base = 8 + 1024;
    let crc_base = oid_base + 20 * n;
    let off_base = crc_base + 4 * n;
    let needed = off_base + 4 * n + 40;
    if data.len() < needed {
        problems.push(p("truncated_idx", format!(
            "idx needs {} bytes for {} objects, has {}",
            needed, n, data.len()
        )));
    }

    let mut objects = Vec::with_capacity(n);
    for i in 0..n {
        let os = oid_base + i * 20;
        if os + 20 > data.len() {
            break;
        }
        let oid = hex::encode(&data[os..os + 20]);
        let crc = if crc_base + 4 + i * 4 <= data.len() {
            Some(u32::from_be_bytes(
                data[crc_base + i * 4..crc_base + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            ))
        } else {
            None
        };
        let (offset, ok) = if off_base + 4 + i * 4 <= data.len() {
            let raw = u32::from_be_bytes(
                data[off_base + i * 4..off_base + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            if raw & 0x8000_0000 != 0 {
                // Large offset table index; rare in test data.
                let idx = (raw & 0x7fff_ffff) as usize;
                let large_base = off_base + 4 * n;
                let pos = large_base + idx * 8;
                if pos + 8 <= data.len() {
                    (u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap()), true)
                } else {
                    (0, false)
                }
            } else {
                (raw as u64, true)
            }
        } else {
            (0, false)
        };
        if !ok {
            problems.push(p("offset_table", format!("bad large offset for object {}", i)));
        }
        objects.push(IdxObject { oid, offset, crc32: crc });
    }

    validate_fanout(&mut fanout.clone(), n, problems);
    validate_order(&objects, problems);

    let (pack_sum, idx_stored, idx_actual, valid) = trailers_v2(data, n, off_base);
    if !valid {
        problems.push(p("idx_checksum", "idx SHA1 trailer mismatch"));
    }

    IdxSummary {
        version: 2,
        fanout,
        objects,
        pack_checksum: pack_sum,
        idx_checksum_stored: idx_stored,
        idx_checksum_actual: idx_actual,
        checksum_valid: valid,
        problems: std::mem::take(problems),
    }
}

fn trailers_v2(data: &[u8], n: usize, off_base: usize) -> (Option<String>, Option<String>, Option<String>, bool) {
    let large_base = off_base + 4 * n;
    // Layout assumes no 64-bit offsets in our fixtures; locate trailers as
    // the final 40 bytes (20 pack sum + 20 idx sum), which is always correct
    // when large offset table is empty.
    if data.len() < large_base + 40 {
        return (None, None, None, false);
    }
    // Use end-relative addressing: works regardless of large offset usage for
    // checksum validation.
    let idx_sum_at = data.len() - 20;
    let pack_sum_at = idx_sum_at - 20;
    let pack_sum = hex::encode(&data[pack_sum_at..idx_sum_at]);
    let stored_idx = hex::encode(&data[idx_sum_at..]);
    let mut h = Sha1::new();
    h.update(&data[..idx_sum_at]);
    let actual = hex::encode(h.finalize());
    let valid = stored_idx == actual;
    (Some(pack_sum), Some(stored_idx), Some(actual), valid)
}

fn parse_v1(data: &[u8], problems: &mut Vec<IdxProblem>) -> IdxSummary {
    // v1: 256 fanout u32 BE, then N * (4 offset, 20 oid), 2x sha trailer.
    if data.len() < 1024 + 40 {
        return bad("idx v1 too short".into());
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let s = i * 4;
        fanout[i] = u32::from_be_bytes(data[s..s + 4].try_into().unwrap());
    }
    let n = fanout[255] as usize;
    let need = 1024 + 24 * n + 40;
    if data.len() < need {
        problems.push(p("truncated_idx", format!(
            "v1 idx needs {} bytes, has {}", need, data.len())));
    }
    let mut objects = Vec::with_capacity(n);
    for i in 0..n {
        let base = 1024 + i * 24;
        if base + 24 > data.len() {
            break;
        }
        let offset = u32::from_be_bytes(data[base..base + 4].try_into().unwrap()) as u64;
        let oid = hex::encode(&data[base + 4..base + 24]);
        objects.push(IdxObject { oid, offset, crc32: None });
    }
    validate_fanout(&mut fanout.clone(), n, problems);
    validate_order(&objects, problems);

    let idx_sum_at = data.len() - 20;
    let pack_sum_at = idx_sum_at - 20;
    let pack_sum = hex::encode(&data[pack_sum_at..idx_sum_at]);
    let stored = hex::encode(&data[idx_sum_at..]);
    let mut h = Sha1::new();
    h.update(&data[..idx_sum_at]);
    let actual = hex::encode(h.finalize());
    let valid = stored == actual;
    if !valid {
        problems.push(p("idx_checksum", "idx SHA1 trailer mismatch"));
    }
    IdxSummary {
        version: 1,
        fanout,
        objects,
        pack_checksum: Some(pack_sum),
        idx_checksum_stored: Some(stored),
        idx_checksum_actual: Some(actual),
        checksum_valid: valid,
        problems: std::mem::take(problems),
    }
}

fn validate_fanout(fanout: &mut [u32; 256], n: usize, problems: &mut Vec<IdxProblem>) {
    let mut prev = 0u32;
    for (i, v) in fanout.iter().enumerate() {
        if *v < prev {
            problems.push(p("fanout_not_monotonic", format!(
                "fanout[{}]={} < previous {}", i, v, prev)));
        }
        prev = *v;
    }
    if fanout[255] as usize != n {
        problems.push(p("fanout_count", "fanout[255] inconsistent with table size"));
    }
}

fn validate_order(objs: &[IdxObject], problems: &mut Vec<IdxProblem>) {
    for w in objs.windows(2) {
        if w[0].oid >= w[1].oid {
            problems.push(p("oid_not_sorted", "oid table is not strictly sorted"));
            break;
        }
    }
}
