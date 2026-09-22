use flate2::{Decompress, FlushDecompress, Status};
use std::fmt;

#[derive(Debug)]
pub enum ZlibError {
    Truncated,
    Corrupt(String),
    SizeExceeded { cap: u64, produced: u64 },
}

impl fmt::Display for ZlibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZlibError::Truncated => write!(f, "zlib stream truncated"),
            ZlibError::Corrupt(m) => write!(f, "zlib stream corrupt: {m}"),
            ZlibError::SizeExceeded { cap, produced } => {
                write!(f, "declared size cap {cap} exceeded (produced {produced} bytes)")
            }
        }
    }
}

pub fn decompress_capped(data: &[u8], cap: u64) -> Result<(Vec<u8>, usize), ZlibError> {
    let mut d = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before > data.len() {
            return Err(ZlibError::Corrupt("internal over-read".into()));
        }
        let status = d
            .decompress(&data[in_before..], &mut buf, FlushDecompress::None)
            .map_err(|e| ZlibError::Corrupt(e.to_string()))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > cap {
            return Err(ZlibError::SizeExceeded {
                cap,
                produced: out.len() as u64,
            });
        }
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            _ => {
                if d.total_in() as usize >= data.len() && produced == 0 {
                    return Err(ZlibError::Truncated);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub type_code: u8,
    pub declared_size: u64,
    pub base_distance: Option<u64>,
    pub base_oid: Option<String>,
    pub data_start: u64,
    pub data_end: u64,
    pub crc32: u32,
    pub payload: Option<Vec<u8>>,
    pub size_error: Option<String>,
}

#[derive(Debug)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: Option<String>,
    pub trailer_ok: bool,
    pub parse_error: Option<String>,
}

fn parse_obj_header(data: &[u8]) -> Result<(u8, u64, usize), String> {
    let b0 = *data.first().ok_or("truncated object header")?;
    let type_code = (b0 >> 4) & 7;
    let mut size = (b0 & 0x0f) as u64;
    let mut shift = 4;
    let mut i = 1;
    let mut cont = b0 & 0x80 != 0;
    while cont {
        let b = *data.get(i).ok_or("truncated object header")?;
        i += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        cont = b & 0x80 != 0;
        if shift > 63 {
            return Err("object header size overflow".into());
        }
    }
    Ok((type_code, size, i))
}

fn parse_ofs_distance(data: &[u8]) -> Result<(u64, usize), String> {
    let mut b = *data.first().ok_or("truncated ofs-delta offset")?;
    let mut i = 1;
    let mut v = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        b = *data.get(i).ok_or("truncated ofs-delta offset")?;
        i += 1;
        v = ((v + 1) << 7) | (b & 0x7f) as u64;
    }
    Ok((v, i))
}

fn parse_entry(data: &[u8], start: usize) -> Result<(PackEntry, usize), String> {
    let (type_code, size, hdr) = parse_obj_header(&data[start..])?;
    let mut pos = start + hdr;
    let mut base_distance = None;
    let mut base_oid = None;
    match type_code {
        6 => {
            let (d, n) = parse_ofs_distance(&data[pos..])?;
            base_distance = Some(d);
            pos += n;
        }
        7 => {
            if data.len() < pos + 20 {
                return Err("truncated ref-delta base oid".into());
            }
            base_oid = Some(hex::encode(&data[pos..pos + 20]));
            pos += 20;
        }
        1..=4 => {}
        t => return Err(format!("unknown object type code {t}")),
    }
    let data_start = pos;
    let (payload, size_error) = match decompress_capped(&data[pos..], size) {
        Ok((out, consumed)) => {
            pos += consumed;
            let err = if out.len() as u64 != size {
                Some(format!(
                    "declared size {size} but zlib stream yielded {} bytes",
                    out.len()
                ))
            } else {
                None
            };
            (Some(out), err)
        }
        Err(ZlibError::SizeExceeded { .. }) => {
            let (out, consumed) = decompress_capped(&data[pos..], u64::MAX)
                .map_err(|e| format!("zlib: {e}"))?;
            pos += consumed;
            let err = Some(format!(
                "declared size {size} but zlib stream yields {} bytes",
                out.len()
            ));
            (Some(out), err)
        }
        Err(e) => return Err(format!("zlib: {e}")),
    };
    let crc32 = crc32fast::hash(&data[start..pos]);
    Ok((
        PackEntry {
            offset: start as u64,
            type_code,
            declared_size: size,
            base_distance,
            base_oid,
            data_start: data_start as u64,
            data_end: pos as u64,
            crc32,
            payload,
            size_error,
        },
        pos,
    ))
}

pub fn parse_pack(data: &[u8]) -> Result<PackFile, String> {
    if data.len() < 12 || &data[..4] != b"PACK" {
        return Err("not a pack file (bad magic)".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(format!("unsupported pack version {version}"));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let mut entries = Vec::new();
    let mut pos = 12usize;
    let mut parse_error = None;
    for i in 0..count {
        match parse_entry(data, pos) {
            Ok((e, next)) => {
                pos = next;
                entries.push(e);
            }
            Err(msg) => {
                parse_error = Some(format!("entry {i}: {msg}"));
                break;
            }
        }
    }
    let (trailer, trailer_ok) = if parse_error.is_none() && data.len() >= pos + 20 {
        let t = hex::encode(&data[pos..pos + 20]);
        let ok = crate::gitobj::sha1_hex(&data[..pos]) == t;
        (Some(t), ok)
    } else {
        (None, false)
    };
    Ok(PackFile {
        version,
        count,
        entries,
        trailer,
        trailer_ok,
        parse_error,
    })
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxFile {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub sha1_ok: bool,
}

fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap())
}

pub fn parse_idx(data: &[u8]) -> Result<IdxFile, String> {
    if data.len() < 8 + 1024 + 40 || &data[..4] != b"\xfftOc" {
        return Err("not an idx v2 file (bad magic)".into());
    }
    if be32(data, 4) != 2 {
        return Err("unsupported idx version".into());
    }
    let mut fanout = [0u32; 256];
    for (i, f) in fanout.iter_mut().enumerate() {
        *f = be32(data, 8 + 4 * i);
    }
    let n = fanout[255] as usize;
    let oid_tab = 8 + 1024;
    let crc_tab = oid_tab + n * 20;
    let off_tab = crc_tab + n * 4;
    let big_tab = off_tab + n * 4;
    if data.len() < big_tab + 40 {
        return Err("truncated idx file".into());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&data[oid_tab + i * 20..oid_tab + i * 20 + 20]);
        let crc32 = be32(data, crc_tab + i * 4);
        let raw = be32(data, off_tab + i * 4);
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let at = big_tab + idx * 8;
            if data.len() < at + 8 + 40 {
                return Err("truncated idx large-offset table".into());
            }
            u64::from_be_bytes(data[at..at + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_sha1 = hex::encode(&data[data.len() - 40..data.len() - 20]);
    let sha1_ok = crate::gitobj::sha1_hex(&data[..data.len() - 20])
        == hex::encode(&data[data.len() - 20..]);
    Ok(IdxFile {
        fanout,
        entries,
        pack_sha1,
        sha1_ok,
    })
}

pub fn parse_loose(data: &[u8]) -> Result<(String, u64, Vec<u8>), String> {
    let (out, _) = decompress_capped(data, u64::MAX).map_err(|e| format!("zlib: {e}"))?;
    let nul = out
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object: missing header NUL")?;
    let hdr = std::str::from_utf8(&out[..nul]).map_err(|_| "loose object: bad header")?;
    let (t, sz) = hdr.split_once(' ').ok_or("loose object: bad header")?;
    let size: u64 = sz.parse().map_err(|_| "loose object: bad size")?;
    Ok((t.to_string(), size, out[nul + 1..].to_vec()))
}
