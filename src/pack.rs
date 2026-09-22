use crate::types::{ErrCode, ObjType, ParsedEntry};
use crate::zlibutil::inflate_entry;

pub const PACK_SIG: &[u8; 4] = b"PACK";
pub const TRAILER_LEN: usize = 20;

#[derive(Debug)]
pub struct PackHeader {
    pub version: u32,
    pub count: u32,
    pub trailer_oid_hex: String,
    pub computed_checksum_hex: String,
}

#[derive(Debug)]
pub struct ParseFailure {
    pub offset: u64,
    pub code: ErrCode,
    pub note: String,
}

pub struct PackParse {
    pub header: PackHeader,
    pub entries: Vec<ParsedEntry>,
    pub failures: Vec<ParseFailure>,
}

pub fn parse_pack(data: &[u8], size_cap: u64) -> Result<PackParse, String> {
    if data.len() < 12 + TRAILER_LEN {
        return Err("file too short to be a v2 pack".into());
    }
    if &data[0..4] != PACK_SIG {
        return Err("bad pack signature".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {}", version));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let trailer_pos = data.len() - TRAILER_LEN;
    let trailer_oid_hex = crate::hexutil::to_hex(&data[trailer_pos..]);
    let computed_checksum_hex = crate::gitobj::sha1_hex(&data[..trailer_pos]);

    let mut entries = Vec::new();
    let mut failures = Vec::new();
    let mut pos = 12usize;
    let end = trailer_pos;

    for idx in 0..count {
        if pos >= end {
            failures.push(ParseFailure {
                offset: pos as u64,
                code: ErrCode::BadHeader,
                note: format!("entry {} starts beyond pack body", idx),
            });
            break;
        }
        let entry_offset = pos;
        let first = data[pos];
        pos += 1;
        let type_code = (first >> 4) & 0b111;
        let obj_type = match ObjType::from_code(type_code) {
            Some(t) => t,
            None => {
                failures.push(ParseFailure {
                    offset: entry_offset as u64,
                    code: ErrCode::BadHeader,
                    note: format!("unknown object type code {}", type_code),
                });
                break;
            }
        };
        let mut declared_size: u64 = (first & 0x0f) as u64;
        let mut shift = 4;
        let mut cont = first & 0x80 != 0;
        let mut header_bad = false;
        while cont {
            if pos >= end {
                header_bad = true;
                break;
            }
            let b = data[pos];
            pos += 1;
            declared_size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            cont = b & 0x80 != 0;
        }
        if header_bad {
            failures.push(ParseFailure {
                offset: entry_offset as u64,
                code: ErrCode::BadHeader,
                note: "object size header runs past pack body".into(),
            });
            break;
        }

        let mut base_offset = None;
        let mut base_oid = None;
        match obj_type {
            ObjType::OfsDelta => {
                if pos >= end {
                    failures.push(ParseFailure {
                        offset: entry_offset as u64,
                        code: ErrCode::BadHeader,
                        note: "missing ofs-delta distance".into(),
                    });
                    break;
                }
                let c1 = data[pos];
                pos += 1;
                let mut dist: u64 = (c1 & 0x7f) as u64;
                let mut b = c1;
                while b & 0x80 != 0 {
                    if pos >= end {
                        header_bad = true;
                        break;
                    }
                    b = data[pos];
                    pos += 1;
                    dist = ((dist + 1) << 7) | ((b & 0x7f) as u64);
                }
                if header_bad || dist > entry_offset as u64 {
                    failures.push(ParseFailure {
                        offset: entry_offset as u64,
                        code: ErrCode::BadOffset,
                        note: format!(
                            "ofs-delta distance {} out of range at offset {}",
                            dist, entry_offset
                        ),
                    });
                    break;
                }
                base_offset = Some(entry_offset as u64 - dist);
            }
            ObjType::RefDelta => {
                if pos + 20 > end {
                    failures.push(ParseFailure {
                        offset: entry_offset as u64,
                        code: ErrCode::BadHeader,
                        note: "ref-delta base oid truncated".into(),
                    });
                    break;
                }
                base_oid = Some(crate::hexutil::to_hex(&data[pos..pos + 20]));
                pos += 20;
            }
            _ => {}
        }

        let zlib_start = pos;
        let cap = declared_size.saturating_add(1).min(size_cap.saturating_add(1));
        let inf = inflate_entry(data, zlib_start, cap);
        let entry_end = inf.consumed_in;
        let mut parse_error = None;
        let mut parse_note = None;
        if inf.over_limit {
            parse_error = Some(ErrCode::SizeSpoof);
            parse_note = Some(format!(
                "declared {} bytes but stream produces more",
                declared_size
            ));
        } else if let Some(e) = inf.error {
            parse_error = Some(ErrCode::CorruptZlib);
            parse_note = Some(e);
        } else if !inf.ended {
            parse_error = Some(ErrCode::CorruptZlib);
            parse_note = Some("zlib stream did not end within pack body".into());
        } else if inf.data.len() as u64 != declared_size {
            parse_error = Some(ErrCode::SizeSpoof);
            parse_note = Some(format!(
                "declared {} bytes but inflated {} bytes",
                declared_size,
                inf.data.len()
            ));
        }
        entries.push(ParsedEntry {
            offset: entry_offset as u64,
            zlib_start,
            entry_end,
            obj_type,
            declared_size,
            base_offset,
            base_oid,
            payload: inf.data,
            parse_error,
            parse_note,
        });
        pos = entry_end;
    }

    Ok(PackParse {
        header: PackHeader {
            version,
            count,
            trailer_oid_hex,
            computed_checksum_hex,
        },
        entries,
        failures,
    })
}
