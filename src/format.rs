//! Parsing of Git pack files, idx files, loose objects, and delta instructions.
//!
//! No external git binary is used: only zlib (via flate2) and sha1/crc32.

use crate::types::{oid_hex, ObjType, Oid};
use flate2::{Decompress, FlushDecompress};

/// Result of inflating a single zlib stream, including exact stream boundaries.
#[derive(Debug, Clone)]
pub struct ZlibResult {
    /// Decompressed bytes.
    pub data: Vec<u8>,
    /// Total number of *compressed* bytes consumed (zlib header + body + trailer).
    pub consumed: usize,
}

/// Inflate exactly one zlib stream starting at `buf[pos]`.
///
/// `hard_cap` bounds total decompressed output so that a corrupt stream cannot
/// exhaust memory; decompression that needs more output than the cap returns
/// `Error::InflateCap`.
pub fn inflate_zlib_at(buf: &[u8], pos: usize, hard_cap: usize) -> Result<ZlibResult, Error> {
    if pos + 2 > buf.len() {
        return Err(Error::Truncated("zlib header".into()));
    }
    let cmf = buf[pos];
    let flg = buf[pos + 1];
    if cmf & 0x0f != 8 {
        return Err(Error::BadZlibHeader(format!("CM={}", cmf & 0x0f)));
    }
    if (cmf as u16 * 256 + flg as u16) % 31 != 0 {
        return Err(Error::BadZlibHeader("CMF/FLG not multiple of 31".into()));
    }
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = pos;
    let chunk = 16 * 1024;
    loop {
        if out.len() >= hard_cap {
            return Err(Error::InflateCap(hard_cap));
        }
        let avail = (hard_cap - out.len()).min(chunk);
        let from = out.len();
        out.resize(from + avail, 0);
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let r = dec.decompress(
            &buf[in_pos..],
            &mut out[from..from + avail],
            FlushDecompress::None,
        );
        let written = dec.total_out() - before_out;
        out.truncate(from + written);
        in_pos += (dec.total_in() - before_in) as usize;
        match r {
            Ok(flate2::Status::Ok) => {
                if in_pos >= buf.len() {
        return Err(Error::Truncated("zlib stream input exhausted".into()));
                }
            }
            Ok(flate2::Status::StreamEnd) => break,
            Ok(flate2::Status::BufError) => {
                return Err(Error::Inflate("BufError".into()));
            }
            Err(e) => return Err(Error::Inflate(e.to_string())),
        }
    }
    Ok(ZlibResult {
        data: out,
        consumed: dec.total_in() as usize,
    })
}

/// Read the little-endian base-128 size encoded in pack object headers.
/// Returns (size, bytes_consumed).
pub fn read_size(buf: &[u8], mut pos: usize) -> Result<(u64, usize), Error> {
    let start = pos;
    let mut size: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() {
            return Err(Error::Truncated("size varint".into()));
        }
        let b = buf[pos];
        pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err(Error::BadSize("size varint too long".into()));
        }
    }
    Ok((size, pos - start))
}

/// Decode the n-byte offset used by OFS_DELTA objects.
///
/// First byte: MSB, with its top bit always set when more bytes follow.
/// Subsequent bytes each contribute 7 bits with a continuation bit.
pub fn read_ofs_distance(buf: &[u8], mut pos: usize) -> Result<(u64, usize), Error> {
    let start = pos;
    if pos >= buf.len() {
        return Err(Error::Truncated("ofs-delta distance".into()));
    }
    let mut b = buf[pos];
    pos += 1;
    let mut dist: u64 = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if pos >= buf.len() {
            return Err(Error::Truncated("ofs-delta distance continuation".into()));
        }
        if dist >= (1u64 << 57) {
            return Err(Error::BadOffset("distance overflow".into()));
        }
        b = buf[pos];
        pos += 1;
        dist += 1;
        dist = (dist << 7) + (b & 0x7f) as u64;
    }
    Ok((dist, pos - start))
}

#[derive(Debug, Clone)]
pub enum Error {
    Truncated(String),
    BadMagic(String),
    BadZlibHeader(String),
    Inflate(String),
    InflateCap(usize),
    BadSize(String),
    BadType(u8),
    BadOffset(String),
    BadDelta(String),
    SizeSpoof { declared: u64, actual: u64 },
    BadChecksum(String),
    BadFanout(String),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Truncated(s) => write!(f, "truncated input: {s}"),
            Error::BadMagic(s) => write!(f, "bad magic: {s}"),
            Error::BadZlibHeader(s) => write!(f, "bad zlib header: {s}"),
            Error::Inflate(s) => write!(f, "zlib inflate error: {s}"),
            Error::InflateCap(n) => write!(f, "decompressed output exceeded hard cap of {n} bytes"),
            Error::BadSize(s) => write!(f, "bad size encoding: {s}"),
            Error::BadType(t) => write!(f, "unknown object type {t}"),
            Error::BadOffset(s) => write!(f, "bad delta offset: {s}"),
            Error::BadDelta(s) => write!(f, "bad delta: {s}"),
            Error::SizeSpoof { declared, actual } => write!(
                f,
                "declared size {declared} does not match decompressed size {actual}"
            ),
            Error::BadChecksum(s) => write!(f, "checksum mismatch: {s}"),
            Error::BadFanout(s) => write!(f, "bad idx fanout: {s}"),
            Error::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for Error {}

/// A parsed delta instruction with the byte range it occupies in the delta blob.
#[derive(Debug, Clone)]
pub struct DeltaInstr {
    pub op: String,
    /// Start offset within the delta blob (first opcode byte).
    pub range_start: usize,
    /// One-past-last byte of the full encoded instruction (including operands).
    pub range_end: usize,
    pub src_off: Option<u64>,
    pub src_len: Option<u64>,
    pub dst_len: Option<usize>,
}

/// Read one little-endian base-128 number used for delta header sizes.
fn read_le128(buf: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err(Error::Truncated("delta varint".into()));
        }
        let b = buf[*pos];
        *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::BadDelta("varint overflow".into()));
        }
    }
    Ok(val)
}

/// Apply a Git delta to `base`, returning (target bytes, decoded instructions).
///
/// Validates the delta header sizes against the actual base/target lengths, so
/// a forged size field is reported as an error before any copy can run.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<DeltaInstr>), Error> {
    let mut p = 0usize;
    let base_size = read_le128(delta, &mut p)?;
    if base_size as usize != base.len() {
        return Err(Error::BadDelta(format!(
            "delta header declares base size {base_size}, actual base is {}",
            base.len()
        )));
    }
    let target_size = read_le128(delta, &mut p)? as usize;
    let mut out = Vec::new();
    let mut instrs: Vec<DeltaInstr> = Vec::new();
    while p < delta.len() {
        let op_start = p;
        let op = delta[p];
        p += 1;
        if op & 0x80 != 0 {
            let mut off: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err(Error::Truncated("copy offset byte".into()));
                    }
                    off |= (delta[p] as u64) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        return Err(Error::Truncated("copy size byte".into()));
                    }
                    len |= (delta[p] as u64) << (8 * i);
                    p += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if off as usize > base.len() || off as usize + len as usize > base.len() {
                return Err(Error::BadDelta(format!(
                    "copy out of base bounds: off={off} len={len} base_len={}",
                    base.len()
                )));
            }
            out.extend_from_slice(&base[off as usize..off as usize + len as usize]);
            instrs.push(DeltaInstr {
                op: "copy".into(),
                range_start: op_start,
                range_end: p,
                src_off: Some(off),
                src_len: Some(len),
                dst_len: Some(len as usize),
            });
        } else if op != 0 {
            let n = op as usize;
            if p + n > delta.len() {
                return Err(Error::Truncated("insert payload".into()));
            }
            out.extend_from_slice(&delta[p..p + n]);
            p += n;
            instrs.push(DeltaInstr {
                op: "insert".into(),
                range_start: op_start,
                range_end: p,
                src_off: None,
                src_len: None,
                dst_len: Some(n),
            });
        } else {
            return Err(Error::BadDelta("opcode 0 is reserved".into()));
        }
    }
    if out.len() != target_size {
        return Err(Error::BadDelta(format!(
            "target size {target_size} does not match produced {} bytes",
            out.len()
        )));
    }
    Ok((out, instrs))
}
