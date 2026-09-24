//! Pure-Rust Git object / pack / idx / loose parsing primitives.
//! No external `git` binary is used anywhere in this crate.

use flate2::Decompress;
use sha1::{Digest, Sha1};
use std::fmt;

pub const OID_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_num(n: u8) -> Option<ObjType> {
        match n {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
    pub fn base_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag => Some(self.name()),
            _ => None,
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

impl fmt::Display for ObjType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Compute the Git object id (sha1 over `"<type> <len>\0<data>"`).
pub fn git_object_id(kind: ObjType, data: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", kind.name(), data.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(data);
    h.finalize().into()
}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

/// Read a little-endian base-128 size from a pack entry header.
/// Returns (value, header_len, type_num, msb_of_first).
pub fn read_pack_header(buf: &[u8]) -> Result<(u64, usize, u8), ParseError> {
    if buf.is_empty() {
        return Err(ParseError::Truncated("pack entry header"));
    }
    let b0 = buf[0];
    let mut size = (b0 & 0x0f) as u64;
    let kind = (b0 >> 4) & 0x07;
    let mut shift = 4;
    let mut idx = 1;
    let mut byte = b0;
    while byte & 0x80 != 0 {
        if idx >= buf.len() {
            return Err(ParseError::Truncated("pack entry size varint"));
        }
        byte = buf[idx];
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        idx += 1;
    }
    Ok((size, idx, kind))
}

/// Read the ofs-delta negative-offset encoding.
pub fn read_ofs_distance(buf: &[u8], mut idx: usize) -> Result<(u64, usize), ParseError> {
    if idx >= buf.len() {
        return Err(ParseError::Truncated("ofs-delta distance"));
    }
    let mut byte = buf[idx];
    let mut dist: u64 = (byte & 0x7f) as u64;
    idx += 1;
    while byte & 0x80 != 0 {
        if idx >= buf.len() {
            return Err(ParseError::Truncated("ofs-delta distance continuation"));
        }
        byte = buf[idx];
        idx += 1;
        dist = dist.wrapping_add(1);
        dist = (dist << 7) | (byte & 0x7f) as u64;
    }
    Ok((dist, idx))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated(&'static str),
    BadMagic(String),
    UnsupportedVersion(u32),
    BadType(u8),
    InvalidDelta(String),
    InflateError(String),
    SizeMismatch { declared: u64, actual: usize },
    Overshot { declared: u64, actual: usize },
    OffsetOutOfBounds { at: u64, distance: u64, target: i64 },
    ChecksumMismatch { what: &'static str, at: usize },
    CrcMismatch { at: u64, expected: u32, actual: u32 },
    Other(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated(s) => write!(f, "truncated data while reading {s}"),
            ParseError::BadMagic(s) => write!(f, "bad magic: {s}"),
            ParseError::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            ParseError::BadType(n) => write!(f, "invalid pack object type {n}"),
            ParseError::InvalidDelta(s) => write!(f, "invalid delta: {s}"),
            ParseError::InflateError(s) => write!(f, "zlib error: {s}"),
            ParseError::SizeMismatch { declared, actual } => write!(
                f,
                "decompressed size mismatch: header declared {declared}, got {actual}"
            ),
            ParseError::Overshot { declared, actual } => write!(
                f,
                "possible size spoof: stream exceeded declared {declared} bytes (produced {actual})"
            ),
            ParseError::OffsetOutOfBounds { at, distance, target } => write!(
                f,
                "ofs-delta distance {distance} at offset {at} points outside pack (target {target})"
            ),
            ParseError::ChecksumMismatch { what, at } => {
                write!(f, "{what} sha1 checksum mismatch at byte {at}")
            }
            ParseError::CrcMismatch { at, expected, actual } => write!(
                f,
                "CRC32 mismatch for entry at {at}: idx expects {expected:08x}, data has {actual:08x}"
            ),
            ParseError::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Result of a bounded raw inflate: keeps the exact zlib stream boundaries.
pub struct Inflated {
    pub data: Vec<u8>,
    /// Bytes consumed from the compressed stream (zlib boundary inside the pack).
    pub consumed: usize,
    pub stream_ended: bool,
}

/// Inflate one zlib stream from `input`, enforcing:
/// * `expect_size` — the pack-header declared expanded size (hard guard against
///   mid-stream size spoofs: producing more bytes is an error, not truncation)
/// * `hard_cap` — resource budget cap; exceeding it returns `BudgetExceeded`
///   (a retriable state, distinct from corruption).
pub fn inflate_stream(
    input: &[u8],
    expect_size: u64,
    hard_cap: usize,
) -> Result<Inflated, InflateError> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity(expect_size.min(4096) as usize);
    let mut tmp = [0u8; 8192];
    let mut input_pos = 0;
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let res = dec.decompress(
            &input[input_pos..],
            &mut tmp,
            flate2::FlushDecompress::None,
        );
        let produced = (dec.total_out() - before_out) as usize;
        let consumed = (dec.total_in() - before_in) as usize;
        input_pos += consumed;
        out.extend_from_slice(&tmp[..produced]);

        if out.len() as u64 > expect_size {
            return Err(InflateError::Overshot {
                declared: expect_size,
                actual: out.len(),
            });
        }
        if out.len() > hard_cap {
            return Err(InflateError::BudgetExceeded {
                produced: out.len(),
                cap: hard_cap,
            });
        }
        match res {
            Ok(flate2::Status::Ok) => {
                if input_pos >= input.len() {
                    return Err(InflateError::Other(
                        "ran out of compressed input before zlib stream end".into(),
                    ));
                }
            }
            Ok(flate2::Status::StreamEnd) => {
                if out.len() as u64 != expect_size {
                    return Err(InflateError::SizeMismatch {
                        declared: expect_size,
                        actual: out.len(),
                    });
                }
                return Ok(Inflated {
                    data: out,
                    consumed: dec.total_in() as usize,
                    stream_ended: true,
                });
            }
            Ok(flate2::Status::BufError) => {
                return Err(InflateError::Other("zlib buf error".into()));
            }
            Err(e) => return Err(InflateError::Other(e.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    SizeMismatch { declared: u64, actual: usize },
    Overshot { declared: u64, actual: usize },
    BudgetExceeded { produced: usize, cap: usize },
    Other(String),
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InflateError::SizeMismatch { declared, actual } => write!(
                f,
                "decompressed size mismatch: header declared {declared}, got {actual}"
            ),
            InflateError::Overshot { declared, actual } => write!(
                f,
                "possible size spoof: stream exceeded declared {declared} bytes (produced {actual})"
            ),
            InflateError::BudgetExceeded { produced, cap } => write!(
                f,
                "resource budget exceeded: produced {produced} > cap {cap}"
            ),
            InflateError::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawEntry {
    /// Absolute byte offset of the entry header in the pack.
    pub offset: u64,
    pub kind: ObjType,
    pub declared_size: u64,
    /// Byte offset where the zlib stream begins.
    pub data_offset: u64,
    /// Exact zlib boundary (bytes consumed); filled when inflate succeeds.
    pub compressed_len: Option<u64>,
    /// Negative distance for ofs-delta.
    pub ofs_distance: Option<u64>,
    /// Base oid for ref-delta.
    pub ref_base: Option<[u8; 20]>,
    /// Inflated payload (delta instructions or object payload).
    pub payload: Option<Vec<u8>>,
    pub inflate_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackScan {
    pub version: u32,
    pub num_objects: u32,
    pub entries: Vec<RawEntry>,
    /// Trailing 20-byte sha1 of the whole pack file.
    pub expected_checksum: [u8; 20],
    pub actual_checksum: [u8; 20],
    pub checksum_ok: bool,
    /// Fatal scan error that stopped the sequential walk.
    pub fatal: Option<String>,
}

const PACK_SIG: [u8; 4] = *b"PACK";

/// Sequentially walk a pack from its own structure (no idx needed), recording
/// raw offsets and exact zlib boundaries. A single bad entry is recorded on the
/// entry and, if the stream can no longer be located, stops the walk.
pub fn scan_pack(bytes: &[u8], hard_cap: usize) -> PackScan {
    let mut scan = PackScan {
        version: 0,
        num_objects: 0,
        entries: Vec::new(),
        expected_checksum: [0u8; 20],
        actual_checksum: [0u8; 20],
        checksum_ok: false,
        fatal: None,
    };
    if bytes.len() < 12 {
        scan.fatal = Some("pack shorter than 12-byte header".into());
        return scan;
    }
    if bytes[0..4] != PACK_SIG {
        scan.fatal = Some("missing PACK signature".into());
        return scan;
    }
    scan.version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    scan.num_objects = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    if scan.version != 2 {
        scan.fatal = Some(format!("unsupported pack version {}", scan.version));
        return scan;
    }

    let mut pos: usize = 12;
    for _ in 0..scan.num_objects {
        let entry_offset = pos as u64;
        let (size, hlen, typenum) = match read_pack_header(&bytes[pos..]) {
            Ok(v) => v,
            Err(e) => {
                scan.fatal = Some(format!("offset {pos}: {e}"));
                return scan;
            }
        };
        let kind = match ObjType::from_pack_num(typenum) {
            Some(k) => k,
            None => {
                scan.fatal = Some(format!("offset {pos}: invalid type {typenum}"));
                return scan;
            }
        };
        let mut entry = RawEntry {
            offset: entry_offset,
            kind,
            declared_size: size,
            data_offset: 0,
            compressed_len: None,
            ofs_distance: None,
            ref_base: None,
            payload: None,
            inflate_error: None,
        };
        let mut p = pos + hlen;
        if kind == ObjType::OfsDelta {
            match read_ofs_distance(bytes, p) {
                Ok((dist, np)) => {
                    entry.ofs_distance = Some(dist);
                    p = np;
                    let target = entry_offset as i64 - dist as i64;
                    if target < 12 || target >= entry_offset as i64 {
                        entry.inflate_error =
                            Some(ParseError::OffsetOutOfBounds {
                                at: entry_offset,
                                distance: dist,
                                target,
                            }.to_string());
                    }
                }
                Err(e) => {
                    scan.fatal = Some(format!("offset {pos}: {e}"));
                    return scan;
                }
            }
        } else if kind == ObjType::RefDelta {
            if p + 20 > bytes.len() {
                scan.fatal = Some(format!("offset {pos}: truncated ref-delta base oid"));
                return scan;
            }
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&bytes[p..p + 20]);
            entry.ref_base = Some(oid);
            p += 20;
        }
        entry.data_offset = p as u64;

        // If the ofs target is out of bounds we cannot know the zlib start
        // semantics any better, but the zlib stream still starts at p.
        match inflate_stream(&bytes[p..], size, hard_cap) {
            Ok(inf) => {
                entry.compressed_len = Some(inf.consumed as u64);
                entry.payload = Some(inf.data);
                pos = p + inf.consumed;
            }
            Err(e) => {
                entry.inflate_error = Some(entry
                    .inflate_error
                    .take()
                    .map(|prev| format!("{prev}; {e}"))
                    .unwrap_or_else(|| e.to_string()));
                scan.entries.push(entry);
                scan.fatal = Some(format!(
                    "offset {}: cannot locate next entry after inflate failure: {e}",
                    entry_offset
                ));
                return scan;
            }
        }
        scan.entries.push(entry);
    }

    // Trailer: 20-byte sha1 over all preceding bytes.
    if pos + 20 > bytes.len() {
        scan.fatal = Some(format!("offset {pos}: truncated pack checksum trailer"));
    } else {
        scan.expected_checksum.copy_from_slice(&bytes[pos..pos + 20]);
        let mut h = Sha1::new();
        h.update(&bytes[..pos]);
        scan.actual_checksum = h.finalize().into();
        scan.checksum_ok = scan.actual_checksum == scan.expected_checksum;
        if !scan.checksum_ok {
            scan.fatal = Some("pack trailing sha1 checksum mismatch".into());
        }
        if pos + 20 != bytes.len() {
            let extra = scan.fatal.take();
            scan.fatal = Some(format!(
                "{}; {} trailing garbage bytes after pack",
                extra.unwrap_or_default(),
                bytes.len() - (pos + 20)
            ));
        }
    }
    scan
}


#[derive(Debug, Clone)]
pub struct IdxObject {
    pub oid: [u8; 20],
    pub pack_offset: u64,
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct IdxScan {
    pub version: u32,
    pub fanout: [u32; 256],
    pub objects: Vec<IdxObject>,
    pub pack_checksum: [u8; 20],
    pub expected_idx_checksum: [u8; 20],
    pub actual_idx_checksum: [u8; 20],
    pub checksum_ok: bool,
    pub fanout_ok: bool,
    pub error: Option<String>,
}

pub fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap())
}

/// Parse a v1/v2 .idx and verify fanout monotonicity and trailing checksums.
pub fn scan_idx(bytes: &[u8]) -> IdxScan {
    let mut idx = IdxScan {
        version: 0,
        fanout: [0u32; 256],
        objects: Vec::new(),
        pack_checksum: [0u8; 20],
        expected_idx_checksum: [0u8; 20],
        actual_idx_checksum: [0u8; 20],
        checksum_ok: false,
        fanout_ok: true,
        error: None,
    };
    let rd_u32 = |off: usize| -> Result<u32, String> {
        bytes
            .get(off..off + 4)
            .map(u32be)
            .ok_or_else(|| format!("truncated idx at byte {off}"))
    };

    let is_v2 = bytes.len() >= 8
        && &bytes[0..4] == b"\xfftOc"
        && &bytes[4..8] == 2u32.to_be_bytes();

    let fanout_base = if is_v2 { 8 } else { 0 };
    idx.version = if is_v2 { 2 } else { 1 };
    for i in 0..256 {
        match rd_u32(fanout_base + i * 4) {
            Ok(v) => idx.fanout[i] = v,
            Err(e) => {
                idx.error = Some(e);
                return idx;
            }
        }
    }
    for w in idx.fanout.windows(2) {
        if w[0] > w[1] {
            idx.fanout_ok = false;
        }
    }
    let n = idx.fanout[255] as usize;

    if is_v2 {
        let names_base = 8 + 256 * 4;
        let crc_base = names_base + n * 20;
        let off_base = crc_base + n * 4;
        let big_base = off_base + n * 4;
        let mut big_count = 0usize;
        for i in 0..n {
            let name_off = names_base + i * 20;
            let mut oid = [0u8; 20];
            if name_off + 20 > bytes.len() {
                idx.error = Some(format!("truncated idx object name at {name_off}"));
                return idx;
            }
            oid.copy_from_slice(&bytes[name_off..name_off + 20]);
            let crc = rd_u32(crc_base + i * 4).ok();
            let off32 = match rd_u32(off_base + i * 4) {
                Ok(v) => v,
                Err(e) => {
                    idx.error = Some(e);
                    return idx;
                }
            };
            let offset = if off32 & 0x8000_0000 != 0 {
                big_count += 1;
                let big_index = (off32 & 0x7fff_ffff) as usize;
                let p = big_base + big_index * 8;
                match bytes.get(p..p + 8) {
                    Some(b) => u64::from_be_bytes(b.try_into().unwrap()),
                    None => {
                        idx.error = Some(format!("truncated 64-bit offset table at {p}"));
                        return idx;
                    }
                }
            } else {
                off32 as u64
            };
            idx.objects.push(IdxObject {
                oid,
                pack_offset: offset,
                crc32: crc,
            });
        }
        read_idx_trailer(bytes, &mut idx, big_base + big_count * 8);
    } else {
        let base = 256 * 4;
        for i in 0..n {
            let rec = base + i * 24;
            if rec + 24 > bytes.len() {
                idx.error = Some(format!("truncated v1 record at {rec}"));
                return idx;
            }
            let offset = u32be(&bytes[rec..rec + 4]) as u64;
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&bytes[rec + 4..rec + 24]);
            idx.objects.push(IdxObject {
                oid,
                pack_offset: offset,
                crc32: None,
            });
        }
        read_idx_trailer(bytes, &mut idx, base + n * 24);
    }
    idx
}

fn read_idx_trailer(bytes: &[u8], idx: &mut IdxScan, trailer: usize) {
    if trailer + 40 > bytes.len() {
        idx.error = Some(format!("truncated idx trailer at {trailer}"));
        return;
    }
    idx.pack_checksum.copy_from_slice(&bytes[trailer..trailer + 20]);
    idx.expected_idx_checksum
        .copy_from_slice(&bytes[trailer + 20..trailer + 40]);
    let mut h = Sha1::new();
    h.update(&bytes[..trailer + 20]);
    idx.actual_idx_checksum = h.finalize().into();
    idx.checksum_ok = idx.actual_idx_checksum == idx.expected_idx_checksum;
    if !idx.checksum_ok {
        idx.error = Some("idx trailing sha1 checksum mismatch".into());
    }
}

#[derive(Debug, Clone)]
pub struct LooseScan {
    pub kind: ObjType,
    pub declared_size: u64,
    pub data: Vec<u8>,
    pub expected_oid: [u8; 20],
    pub actual_oid: [u8; 20],
    pub oid_ok: bool,
    pub error: Option<String>,
}

/// Inflate a full zlib stream from `bytes` starting at 0, returning the output
/// and exact consumed length, bounded by `hard_cap`.
pub fn inflate_loose(bytes: &[u8], hard_cap: usize) -> Result<(Vec<u8>, usize), String> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut input_pos = 0;
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let res = dec.decompress(
            &bytes[input_pos..],
            &mut tmp,
            flate2::FlushDecompress::None,
        );
        input_pos += (dec.total_in() - before_in) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&tmp[..produced]);
        if out.len() > hard_cap {
            return Err(format!("loose object exceeds hard cap of {hard_cap} bytes"));
        }
        match res {
            Ok(flate2::Status::Ok) => {
                if input_pos >= bytes.len() {
                    return Err("ran out of compressed input before zlib stream end".into());
                }
            }
            Ok(flate2::Status::StreamEnd) => return Ok((out, dec.total_in() as usize)),
            Ok(flate2::Status::BufError) => return Err("zlib buf error".into()),
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Parse a loose object: zlib stream of `"<type> <size>\0<content>"`.
pub fn scan_loose(bytes: &[u8], expected_oid: &[u8; 20], hard_cap: usize) -> LooseScan {
    let mut ls = LooseScan {
        kind: ObjType::Blob,
        declared_size: 0,
        data: Vec::new(),
        expected_oid: *expected_oid,
        actual_oid: [0u8; 20],
        oid_ok: false,
        error: None,
    };
    let raw = match inflate_loose(bytes, hard_cap) {
        Ok((v, _)) => v,
        Err(e) => {
            ls.error = Some(e);
            return ls;
        }
    };
    let nul = match raw.iter().position(|&b| b == 0) {
        Some(p) => p,
        None => {
            ls.error = Some("loose object missing NUL header terminator".into());
            return ls;
        }
    };
    let header = match std::str::from_utf8(&raw[..nul]) {
        Ok(h) => h,
        Err(_) => {
            ls.error = Some("loose object header is not utf-8".into());
            return ls;
        }
    };
    let (type_s, size_s) = match header.split_once(' ') {
        Some(v) => v,
        None => {
            ls.error = Some("loose object header missing size".into());
            return ls;
        }
    };
    let kind = match type_s {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => {
            ls.error = Some(format!("unknown loose object type {other:?}"));
            return ls;
        }
    };
    let size: u64 = match size_s.parse() {
        Ok(v) => v,
        Err(_) => {
            ls.error = Some(format!("invalid loose object size {size_s:?}"));
            return ls;
        }
    };
    let data = raw[nul + 1..].to_vec();
    if data.len() as u64 != size {
        ls.error = Some(
            ParseError::SizeMismatch {
                declared: size,
                actual: data.len(),
            }
            .to_string(),
        );
    }
    ls.kind = kind;
    ls.declared_size = size;
    ls.actual_oid = git_object_id(kind, &data);
    ls.oid_ok = ls.actual_oid == ls.expected_oid;
    if !ls.oid_ok {
        ls.error = Some(format!(
            "loose object id mismatch: filename says {}, content hashes to {}",
            oid_hex(&ls.expected_oid),
            oid_hex(&ls.actual_oid)
        ));
    }
    ls.data = data;
    ls
}
