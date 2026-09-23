//! Pure-Rust parser for Git pack files (`pack-*.pack`).
//!
//! No system git is used. Entries are read sequentially while preserving
//! every offset; zlib stream boundaries are located with a Sync allocator
//! so downstream code knows exactly where each object ends.

use flate2::Decompress;
use flate2::FlushDecompress;
use sha1::{Digest, Sha1};

use crate::error::{ParseError, ParseResult};
use crate::types::{GitType, Oid};

#[derive(Clone, Debug)]
pub struct PackEntry {
    pub object_type: GitType,
    /// Declared uncompressed size from the pack header (or resulting size for deltas).
    pub declared_size: u64,
    /// Absolute offset of the entry header byte.
    pub entry_offset: u64,
    /// Absolute offset of the first compressed byte.
    pub data_offset: u64,
    /// Absolute offset just past the zlib stream.
    pub data_end: u64,
    /// Raw decompressed payload (object body, or delta instructions).
    pub payload: Vec<u8>,
    /// For ofs-delta: absolute offset of the base entry.
    pub base_offset: Option<u64>,
    /// For ref-delta: 20-byte object id of the base.
    pub base_oid: Option<Oid>,
    /// CRC32 over the *on-disk* bytes of the entry (header + compressed data),
    /// when an idx file provides one.
    pub crc_expected: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct PackFile {
    pub checksum: Oid,
    pub version: u32,
    pub num_objects: u32,
    pub entries: Vec<PackEntry>,
    /// Entry index keyed by entry offset, ascending (same order as entries).
    pub offset_index: Vec<(u64, usize)>,
    pub header_parse_ok: bool,
    pub errors: Vec<crate::types::Evidence>,
    pub trailer_verified: bool,
}

pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8], pos: usize) -> Self {
        Cursor { buf, pos }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn u8(&mut self) -> ParseResult<u8> {
        if self.pos >= self.buf.len() {
            return Err(ParseError::Truncated(format!(
                "need 1 byte at {}",
                self.pos
            )));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn take(&mut self, n: usize) -> ParseResult<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(ParseError::Truncated(format!(
                "need {n} bytes at {}",
                self.pos
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u32_be(&mut self) -> ParseResult<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

/// Read a pack object header: 3-bit type + variable-length size.
/// Returns (type, declared_size, header_len).
pub fn read_object_header(buf: &[u8], at: usize) -> ParseResult<(GitType, u64, usize)> {
    let mut cur = Cursor::new(buf, at);
    let first = cur.u8()?;
    let obj_type = GitType::from_pack_code((first >> 4) & 0b111)
        .ok_or_else(|| ParseError::Corrupt(format!("unknown object type at offset {at}")))?;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = cur.u8()?;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((obj_type, size, cur.pos() - at))
}

/// Decode the negative-distance header of an ofs-delta.
/// First byte was already read? No — call with data start (first byte after
/// the object header). Returns (distance, header_len).
pub fn read_ofs_distance(buf: &[u8], at: usize) -> ParseResult<(u64, usize)> {
    let mut cur = Cursor::new(buf, at);
    let mut byte = cur.u8()?;
    let mut dist = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        byte = cur.u8()?;
        dist = ((dist + 1) << 7) | (byte & 0x7f) as u64;
    }
    Ok((dist, cur.pos() - at))
}

/// Inflate one zlib stream starting at `at`, returning (bytes, end_offset).
/// The stream is considered complete when the inflater reports StreamEnd.
pub fn inflate_one(buf: &[u8], at: usize) -> ParseResult<(Vec<u8>, usize)> {
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut pos = at;
    // Grow output incrementally; the declared size is trusted only for
    // preallocation, never for truncation decisions.
    loop {
        if pos >= buf.len() {
            return Err(ParseError::Zlib(format!(
                "compressed stream truncated at {pos}"
            )));
        }
        let chunk = &buf[pos..];
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let mut tmp = [0u8; 16 * 1024];
        let status = dec
            .decompress(chunk, &mut tmp, FlushDecompress::None)
            .map_err(|e| ParseError::Zlib(e.to_string()))?;
        let consumed = (dec.total_in() - before_in) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        pos += consumed;
        out.extend_from_slice(&tmp[..produced]);
        match status {
            flate2::Status::StreamEnd => {
                // Adler/stream end reached. Some zlib streams are followed by
                // extra bytes; total_in counts exactly the consumed bytes.
                let end = at + dec.total_in() as usize;
                return Ok((out, end));
            }
            flate2::Status::Ok | flate2::Status::BufError => {
                if consumed == 0 && produced == 0 {
                    // Real progress needed; BufError may repeat with tiny chunks.
                }
            }
        }
        if dec.total_in() as usize >= chunk.len() && !matches!(status, flate2::Status::StreamEnd) {
            // Fed everything without StreamEnd -> truncated stream.
            return Err(ParseError::Zlib(format!(
                "compressed stream ended without zlib footer at {pos}"
            )));
        }
    }
}

/// Parse a single entry starting at `at`. Returns the entry and the offset
/// just past its zlib stream.
pub fn parse_entry(buf: &[u8], at: usize) -> ParseResult<(PackEntry, usize)> {
    let entry_offset = at as u64;
    let (obj_type, declared_size, header_len) = read_object_header(buf, at)?;
    let mut pos = at + header_len;

    let mut base_offset = None;
    let mut base_oid = None;
    match obj_type {
        GitType::OfsDelta => {
            let (dist, dlen) = read_ofs_distance(buf, pos)?;
            pos += dlen;
            let base = (entry_offset as i64) - (dist as i64);
            if base < 12 || base >= entry_offset as i64 {
                return Err(ParseError::BadOffset(base));
            }
            base_offset = Some(base as u64);
        }
        GitType::RefDelta => {
            if pos + 20 > buf.len() {
                return Err(ParseError::Truncated(format!(
                    "ref-delta base oid truncated at {pos}"
                )));
            }
            base_oid = Oid::from_bytes(&buf[pos..pos + 20]);
            pos += 20;
        }
        _ => {}
    }

    let data_offset = pos as u64;
    let (payload, data_end) = inflate_one(buf, pos)?;
    Ok((
        PackEntry {
            object_type: obj_type,
            declared_size,
            entry_offset,
            data_offset,
            data_end: data_end as u64,
            payload,
            base_offset,
            base_oid,
            crc_expected: None,
        },
        data_end,
    ))
}

/// Parse a whole pack buffer. Best-effort: a bad entry is recorded in
/// `errors` and parsing stops at that offset, but the header/trailer and all
/// earlier entries remain available.
pub fn parse_pack(buf: &[u8]) -> ParseResult<PackFile> {
    let mut errors = Vec::new();
    let mut cur = Cursor::new(buf, 0);
    let magic = cur.take(4)?;
    if magic != b"PACK" {
        return Err(ParseError::BadMagic(format!(
            "not a pack file: {:?}",
            String::from_utf8_lossy(magic)
        )));
    }
    let version = cur.u32_be()?;
    if version != 2 && version != 3 {
        return Err(ParseError::Unsupported(format!("pack version {version}")));
    }
    let num_objects = cur.u32_be()?;

    let mut entries: Vec<PackEntry> = Vec::with_capacity(num_objects.min(1 << 20) as usize);
    let mut offset_index: Vec<(u64, usize)> = Vec::new();
    let mut parse_failed: Option<(String, u64)> = None;

    while (entries.len() as u32) < num_objects {
        let entry_offset = cur.pos() as u64;
        match parse_entry(buf, cur.pos()) {
            Ok((entry, next_pos)) => {
                // Size-spoof detection at parse time: the zlib stream is the
                // ground truth, the header merely a claim.
                if entry.payload.len() as u64 != entry.declared_size {
                    errors.push(crate::types::Evidence {
                        code: "size_spoof".into(),
                        message: format!(
                            "{} at offset {entry_offset}: header declares {} bytes, stream produced {}",
                            entry.object_type.header_name(),
                            entry.declared_size,
                            entry.payload.len()
                        ),
                        offset: Some(entry_offset),
                        expected: Some(entry.declared_size.to_string()),
                        actual: Some(entry.payload.len().to_string()),
                    });
                }
                let idx = entries.len();
                offset_index.push((entry.entry_offset, idx));
                entries.push(entry);
                cur = Cursor::new(buf, next_pos);
            }
            Err(e) => {
                parse_failed = Some((e.to_string(), entry_offset));
                break;
            }
        }
    }

    // Trailer: 20-byte SHA1 over every preceding byte.
    let mut trailer_verified = false;
    if buf.len() >= 20 {
        let body_end = buf.len() - 20;
        let mut hasher = Sha1::new();
        hasher.update(&buf[..body_end]);
        let actual = hasher.finalize();
        let stored = &buf[body_end..];
        let checksum = Oid::from_bytes(stored).expect("20 bytes");
        trailer_verified = actual.as_slice() == stored;
        if !trailer_verified {
            errors.push(crate::types::Evidence {
                code: "pack_checksum".into(),
                message: "pack trailer SHA-1 does not match file contents".into(),
                offset: Some(body_end as u64),
                expected: Some(Oid::from_bytes(&actual).unwrap().hex()),
                actual: Some(checksum.hex()),
            });
        }
        if let Some((reason, at)) = parse_failed {
            errors.push(crate::types::Evidence::new("entry_error", reason).at(at));
        }
        Ok(PackFile {
            checksum,
            version,
            num_objects,
            entries,
            offset_index,
            header_parse_ok: true,
            errors,
            trailer_verified,
        })
    } else {
        Err(ParseError::Truncated("pack shorter than 20 bytes".into()))
    }
}

impl PackFile {
    /// Find the entry whose object header starts at `offset`.
    pub fn entry_at_offset(&self, offset: u64) -> Option<&PackEntry> {
        self.offset_index
            .binary_search_by(|(o, _)| o.cmp(&offset))
            .ok()
            .map(|i| &self.entries[self.offset_index[i].1])
    }
}
