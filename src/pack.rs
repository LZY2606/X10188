use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

/// Inflate a zlib stream, returning the decompressed bytes and the exact
/// number of input bytes consumed (the zlib stream boundary).
pub fn inflate(input: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let in_before = d.total_in();
        let out_before = d.total_out();
        let status = d
            .decompress(input, &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        let produced = (d.total_out() - out_before) as usize;
        out.extend_from_slice(&buf[..produced]);
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            _ => {
                if d.total_in() == in_before && produced == 0 {
                    return Err("truncated zlib stream".to_string());
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackEntryInfo {
    pub offset: u64,
    pub type_code: u8,
    pub type_name: String,
    pub declared_size: u64,
    pub data_offset: u64,
    pub compressed_len: u64,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub crc32: u32,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntryInfo>,
    pub trailer_ok: bool,
    pub pack_sha1: String,
    pub errors: Vec<String>,
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(bytes);
    c.sum()
}

/// Parse a PACK file: header, per-entry type/size varint, ofs-delta and
/// ref-delta base locators, zlib boundaries, per-entry CRC32 and trailer.
pub fn parse_pack(bytes: &[u8]) -> Result<PackInfo, String> {
    if bytes.len() < 12 + 20 {
        return Err("pack too small".to_string());
    }
    if &bytes[0..4] != b"PACK" {
        return Err("bad pack magic".to_string());
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    let count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let body_len = bytes.len() - 20;
    let mut info = PackInfo {
        version,
        count,
        pack_sha1: hex::encode(&bytes[body_len..]),
        ..Default::default()
    };
    let mut h = Sha1::new();
    h.update(&bytes[..body_len]);
    info.trailer_ok = hex::encode(h.finalize()) == info.pack_sha1;

    let mut off = 12usize;
    for _ in 0..count {
        if off >= body_len {
            info.errors.push(format!("truncated entry header at offset {off}"));
            break;
        }
        let entry_offset = off as u64;
        let start = off;
        let mut c = bytes[off];
        off += 1;
        let type_code = (c >> 4) & 0x7;
        let mut size = (c & 0x0f) as u64;
        let mut shift = 4u32;
        while c & 0x80 != 0 {
            if off >= body_len {
                break;
            }
            c = bytes[off];
            off += 1;
            size |= ((c & 0x7f) as u64) << shift;
            shift += 7;
        }
        let type_name = crate::gitobj::type_name(type_code)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("invalid-{type_code}"));
        let mut base_offset = None;
        let mut base_oid = None;
        let mut error = None;
        if type_code == 6 {
            if off >= body_len {
                error = Some("truncated ofs-delta base".to_string());
            } else {
                let mut b = bytes[off];
                off += 1;
                let mut dist: u64 = (b & 0x7f) as u64;
                while b & 0x80 != 0 {
                    if off >= body_len {
                        break;
                    }
                    b = bytes[off];
                    off += 1;
                    dist = ((dist + 1) << 7) | ((b & 0x7f) as u64);
                }
                match entry_offset.checked_sub(dist) {
                    Some(bo) => base_offset = Some(bo),
                    None => {
                        error = Some(format!(
                            "ofs-delta distance {dist} out of bounds at offset {entry_offset}"
                        ));
                    }
                }
            }
        } else if type_code == 7 {
            if off + 20 > body_len {
                error = Some("truncated ref-delta base oid".to_string());
            } else {
                base_oid = Some(hex::encode(&bytes[off..off + 20]));
                off += 20;
            }
        } else if crate::gitobj::type_name(type_code).is_none() {
            error = Some(format!("invalid object type code {type_code}"));
        }
        let data_offset = off as u64;
        let mut compressed_len = 0u64;
        if error.is_none() {
            match inflate(&bytes[off..body_len]) {
                Ok((out, used)) => {
                    compressed_len = used as u64;
                    if out.len() as u64 != size {
                        error = Some(format!(
                            "size fraud: header declares {size}, zlib stream yields {}",
                            out.len()
                        ));
                    }
                }
                Err(e) => {
                    error = Some(format!("zlib boundary failure at offset {data_offset}: {e}"));
                }
            }
        }
        let end = (data_offset + compressed_len) as usize;
        let crc32 = crc32(&bytes[start..end]);
        info.entries.push(PackEntryInfo {
            offset: entry_offset,
            type_code,
            type_name,
            declared_size: size,
            data_offset,
            compressed_len,
            base_offset,
            base_oid,
            crc32,
            error,
        });
        if compressed_len == 0 {
            info.errors
                .push(format!("stopping pack scan at offset {entry_offset}"));
            break;
        }
        off = end;
    }
    if off != body_len && info.errors.is_empty() {
        info.errors
            .push(format!("pack scan ended at {off}, expected {body_len}"));
    }
    Ok(info)
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Default)]
pub struct IdxInfo {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: Option<String>,
    pub errors: Vec<String>,
}

fn be32(bytes: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap())
}

/// Parse a pack index (v2 with magic, or v1 fanout-only layout).
pub fn parse_idx(bytes: &[u8]) -> Result<IdxInfo, String> {
    let mut info = IdxInfo::default();
    if bytes.len() < 4 {
        return Err("index too small".to_string());
    }
    if &bytes[0..4] == b"\xfftOc" {
        if bytes.len() < 8 + 1024 {
            return Err("index v2 too small".to_string());
        }
        let version = be32(bytes, 4);
        info.version = version;
        if version != 2 {
            return Err(format!("unsupported index version {version}"));
        }
        let mut off = 8usize;
        let mut fanout = vec![0u32; 256];
        for f in fanout.iter_mut() {
            *f = be32(bytes, off);
            off += 4;
        }
        for i in 1..256 {
            if fanout[i] < fanout[i - 1] {
                info.errors.push("fanout table not monotonic".to_string());
                break;
            }
        }
        let n = fanout[255] as usize;
        if bytes.len() < off + n * 32 + 40 {
            return Err("index v2 truncated".to_string());
        }
        let mut oids = Vec::with_capacity(n);
        for _ in 0..n {
            oids.push(hex::encode(&bytes[off..off + 20]));
            off += 20;
        }
        let mut crcs = Vec::with_capacity(n);
        for _ in 0..n {
            crcs.push(be32(bytes, off));
            off += 4;
        }
        let mut offs32 = Vec::with_capacity(n);
        for _ in 0..n {
            offs32.push(be32(bytes, off));
            off += 4;
        }
        let large_table = off;
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            let o = offs32[i];
            let offset = if o & 0x8000_0000 != 0 {
                let idx = (o & 0x7fff_ffff) as usize;
                let p = large_table + idx * 8;
                if p + 8 > bytes.len() {
                    return Err("index large-offset table truncated".to_string());
                }
                u64::from_be_bytes(bytes[p..p + 8].try_into().unwrap())
            } else {
                o as u64
            };
            entries.push(IdxEntry { oid: oids[i].clone(), crc32: crcs[i], offset });
        }
        if bytes.len() >= 40 {
            info.pack_sha1 = Some(hex::encode(&bytes[bytes.len() - 40..bytes.len() - 20]));
        }
        info.fanout = fanout;
        info.entries = entries;
        Ok(info)
    } else {
        if bytes.len() < 1024 {
            return Err("index v1 too small".to_string());
        }
        let mut off = 0usize;
        let mut fanout = vec![0u32; 256];
        for f in fanout.iter_mut() {
            *f = be32(bytes, off);
            off += 4;
        }
        let n = fanout[255] as usize;
        if bytes.len() != 1024 + n * 24 {
            return Err("index v1 size mismatch".to_string());
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let offset = be32(bytes, off) as u64;
            let oid = hex::encode(&bytes[off + 4..off + 24]);
            off += 24;
            entries.push(IdxEntry { oid, crc32: 0, offset });
        }
        info.version = 1;
        info.fanout = fanout;
        info.entries = entries;
        Ok(info)
    }
}

/// Loose object: zlib of "<type> <size>\0<content>".
pub struct LooseInfo {
    pub obj_type: String,
    pub declared_size: u64,
    pub header_len: usize,
    pub content_len: usize,
    pub compressed_len: usize,
    pub trailing: usize,
}

pub fn parse_loose(bytes: &[u8]) -> Result<LooseInfo, String> {
    let (raw, used) = inflate(bytes)?;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object header missing NUL".to_string())?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| "loose object header not utf-8".to_string())?;
    let mut parts = header.splitn(2, ' ');
    let obj_type = parts.next().unwrap_or("").to_string();
    if !matches!(obj_type.as_str(), "commit" | "tree" | "blob" | "tag") {
        return Err(format!("loose object has bad type '{obj_type}'"));
    }
    let declared_size: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "loose object header has bad size".to_string())?;
    Ok(LooseInfo {
        obj_type,
        declared_size,
        header_len: nul + 1,
        content_len: raw.len() - (nul + 1),
        compressed_len: used,
        trailing: bytes.len() - used,
    })
}
