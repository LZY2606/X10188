use crate::model::{DeltaBase, ObjType};
use crate::util;
use flate2::{Decompress, FlushDecompress, Status};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub base: Option<DeltaBase>,
    pub data_offset: u64,
    pub compressed_len: u64,
    pub inflated_size: u64,
    pub size_fraud: bool,
}

#[derive(Debug, Default)]
pub struct PackFile {
    pub version: u32,
    pub declared_count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: String,
    pub trailer_actual: String,
    pub trailer_ok: bool,
    pub parse_error: Option<String>,
}

/// Inflate a zlib stream starting at data[0]; return (inflated, consumed_input_bytes).
/// The consumed length is the exact zlib boundary inside the pack.
pub fn inflate_bounded(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before >= data.len() {
            return Err("truncated zlib stream".into());
        }
        let status = d
            .decompress(&data[in_before..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib error: {}", e))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&buf[..produced]);
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if produced == 0 && d.total_in() as usize == in_before {
                    return Err("zlib stream stalled".into());
                }
            }
        }
    }
}

fn parse_entry_header(data: &[u8]) -> Result<(ObjType, u64, usize), String> {
    if data.is_empty() {
        return Err("empty entry header".into());
    }
    let mut pos = 0usize;
    let mut byte = data[pos];
    pos += 1;
    let type_code = (byte >> 4) & 0x7;
    let obj_type = ObjType::from_code(type_code)
        .ok_or_else(|| format!("invalid object type code {}", type_code))?;
    let mut size = (byte & 0x0f) as u64;
    let mut shift = 4u32;
    while byte & 0x80 != 0 {
        if pos >= data.len() {
            return Err("truncated size varint".into());
        }
        byte = data[pos];
        pos += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("size varint too large".into());
        }
    }
    Ok((obj_type, size, pos))
}

fn parse_ofs_distance(data: &[u8]) -> Result<(u64, usize), String> {
    if data.is_empty() {
        return Err("empty ofs-delta offset".into());
    }
    let mut pos = 0usize;
    let mut byte = data[pos];
    pos += 1;
    let mut dist = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if pos >= data.len() {
            return Err("truncated ofs-delta offset".into());
        }
        byte = data[pos];
        pos += 1;
        dist = ((dist + 1) << 7) | (byte & 0x7f) as u64;
    }
    Ok((dist, pos))
}

pub fn parse_pack(data: &[u8]) -> PackFile {
    let mut out = PackFile::default();
    if data.len() < 12 || &data[0..4] != b"PACK" {
        out.parse_error = Some("missing PACK signature".into());
        return out;
    }
    out.version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    out.declared_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let mut pos = 12usize;
    let body_end = data.len().saturating_sub(20);
    for _ in 0..out.declared_count {
        if pos >= body_end {
            out.parse_error = Some(format!("pack truncated at entry offset {}", pos));
            break;
        }
        let entry_offset = pos;
        let (obj_type, declared_size, hdr_len) = match parse_entry_header(&data[pos..body_end]) {
            Ok(v) => v,
            Err(e) => {
                out.parse_error = Some(format!("entry header at {}: {}", pos, e));
                break;
            }
        };
        pos += hdr_len;
        let mut base = None;
        match obj_type {
            ObjType::OfsDelta => match parse_ofs_distance(&data[pos..body_end]) {
                Ok((dist, used)) => {
                    base = Some(DeltaBase::Ofs { distance: dist });
                    pos += used;
                }
                Err(e) => {
                    out.parse_error = Some(format!("ofs-delta at {}: {}", entry_offset, e));
                    break;
                }
            },
            ObjType::RefDelta => {
                if pos + 20 > body_end {
                    out.parse_error =
                        Some(format!("ref-delta at {}: truncated base oid", entry_offset));
                    break;
                }
                base = Some(DeltaBase::Ref {
                    oid: util::hex_encode(&data[pos..pos + 20]),
                });
                pos += 20;
            }
            _ => {}
        }
        let data_offset = pos;
        match inflate_bounded(&data[pos..body_end]) {
            Ok((inflated, consumed)) => {
                let size_fraud = inflated.len() as u64 != declared_size;
                out.entries.push(PackEntry {
                    offset: entry_offset as u64,
                    obj_type,
                    declared_size,
                    base,
                    data_offset: data_offset as u64,
                    compressed_len: consumed as u64,
                    inflated_size: inflated.len() as u64,
                    size_fraud,
                });
                pos += consumed;
            }
            Err(e) => {
                out.parse_error = Some(format!("zlib stream at {}: {}", data_offset, e));
                break;
            }
        }
    }
    if data.len() >= 20 {
        out.trailer = util::hex_encode(&data[data.len() - 20..]);
        out.trailer_actual = util::sha1_hex(&data[..data.len() - 20]);
        out.trailer_ok = out.trailer == out.trailer_actual;
    }
    out
}
