use super::checksum::{sha1_hex, to_hex};
use super::zlib::{inflate_at, ZlibError};
use super::{TYPE_OFS_DELTA, TYPE_REF_DELTA};

#[derive(Debug, Clone)]
pub struct ParsedPackEntry {
    pub offset: u64,
    pub obj_type: u8,
    pub declared_size: u64,
    pub inflated_len: u64,
    pub inflated: Vec<u8>,
    /// Compressed span: [zlib_start, zlib_end) within the pack file.
    pub zlib_start: u64,
    pub zlib_end: u64,
    pub crc32: u32,
    pub adler_ok: bool,
    pub base_offset: Option<u64>,
    pub base_ref: Option<String>,
    /// Size declared by the delta header once inflated.
    pub delta_base_size: Option<u64>,
    pub delta_result_size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PackError {
    pub offset: u64,
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub declared_count: u32,
    pub entries: Vec<ParsedPackEntry>,
    /// End of the last parsed object; the 20-byte SHA trailer follows.
    pub trailer_offset: u64,
    pub file_len: u64,
    pub checksum_expected: String,
    pub checksum_actual: String,
    pub checksum_ok: bool,
    pub errors: Vec<PackError>,
}

fn read_be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Read a pack entry header at `pos`: returns (obj_type, size, header_len).
fn read_entry_header(data: &[u8], pos: usize) -> Result<(u8, u64, usize), PackError> {
    if pos >= data.len() {
        return Err(PackError {
            offset: pos as u64,
            code: "truncated_header".into(),
            message: "no byte for entry header".into(),
        });
    }
    let first = data[pos];
    let obj_type = (first >> 4) & 0x7;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4;
    let mut p = pos + 1;
    let mut byte = first;
    while byte & 0x80 != 0 {
        if p >= data.len() {
            return Err(PackError {
                offset: pos as u64,
                code: "truncated_header".into(),
                message: "continuation byte missing".into(),
            });
        }
        byte = data[p];
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        p += 1;
    }
    Ok((obj_type, size, p - pos))
}

/// Decode the ofs-delta negative-offset varint immediately after the header.
fn read_ofs_delta(data: &[u8], mut p: usize) -> Result<(u64, usize), PackError> {
    let start = p;
    if p >= data.len() {
        return Err(PackError {
            offset: p as u64,
            code: "truncated_ofs".into(),
            message: "ofs-delta byte missing".into(),
        });
    }
    let mut byte = data[p];
    let mut ofs = (byte & 0x7f) as u64;
    p += 1;
    while byte & 0x80 != 0 {
        if p >= data.len() {
            return Err(PackError {
                offset: start as u64,
                code: "truncated_ofs".into(),
                message: "ofs-delta continuation missing".into(),
            });
        }
        byte = data[p];
        ofs = ofs.wrapping_add(1).wrapping_shl(7) | (byte & 0x7f) as u64;
        p += 1;
    }
    Ok((ofs, p - start))
}

/// Parse the two varint sizes at the start of an inflated delta body.
pub fn parse_delta_sizes(body: &[u8]) -> Option<(u64, u64, usize)> {
    let (base, n1) = read_delta_varint_at(body, 0)?;
    let (result, n2) = read_delta_varint_at(body, n1)?;
    Some((base, result, n1 + n2))
}

fn read_delta_varint_at(b: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0;
    let mut p = start;
    loop {
        if p >= b.len() {
            return None;
        }
        let x = b[p];
        p += 1;
        v |= ((x & 0x7f) as u64) << shift;
        if x & 0x80 == 0 {
            return Some((v, p - start));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

pub fn parse_pack(data: &[u8]) -> ParsedPack {
    let mut errors = Vec::new();
    let file_len = data.len() as u64;
    if data.len() < 32 || &data[0..4] != b"PACK" {
        errors.push(PackError {
            offset: 0,
            code: "bad_pack_header".into(),
            message: "missing PACK magic".into(),
        });
        let expected = if data.len() >= 20 {
            to_hex(&data[data.len() - 20..])
        } else {
            String::new()
        };
        return ParsedPack {
            version: 0,
            count: 0,
            declared_count: 0,
            entries: Vec::new(),
            trailer_offset: file_len.saturating_sub(20),
            file_len,
            checksum_expected: expected,
            checksum_actual: String::new(),
            checksum_ok: false,
            errors,
        };
    }
    let version = read_be_u32(&data[4..8]);
    let declared_count = read_be_u32(&data[8..12]);

    let mut entries: Vec<ParsedPackEntry> = Vec::new();
    let mut pos = 12usize;
    let mut aborted = false;

    while entries.len() < declared_count as usize {
        let entry_offset = pos as u64;
        let header = match read_entry_header(data, pos) {
            Ok(h) => h,
            Err(e) => {
                errors.push(e);
                aborted = true;
                break;
            }
        };
        let (obj_type, declared_size, header_len) = header;
        pos += header_len;

        let mut base_offset = None;
        let mut base_ref = None;

        if obj_type == TYPE_OFS_DELTA {
            match read_ofs_delta(data, pos) {
                Ok((neg, n)) => {
                    pos += n;
                    let bo = entry_offset.checked_sub(neg);
                    if bo.is_none() {
                        errors.push(PackError {
                            offset: entry_offset,
                            code: "ofs_underflow".into(),
                            message: format!("ofs-delta distance {} before pack start", neg),
                        });
                        aborted = true;
                        break;
                    }
                    base_offset = bo;
                }
                Err(e) => {
                    errors.push(e);
                    aborted = true;
                    break;
                }
            }
        } else if obj_type == TYPE_REF_DELTA {
            if pos + 20 > data.len() {
                errors.push(PackError {
                    offset: entry_offset,
                    code: "truncated_ref".into(),
                    message: "ref-delta base name missing".into(),
                });
                aborted = true;
                break;
            }
            base_ref = Some(to_hex(&data[pos..pos + 20]));
            pos += 20;
        } else if !(1..=4).contains(&obj_type) {
            errors.push(PackError {
                offset: entry_offset,
                code: "unknown_type".into(),
                message: format!("unsupported object type {}", obj_type),
            });
            aborted = true;
            break;
        }

        let zlib_start = pos as u64;
        let stream = match inflate_at(data, pos) {
            Ok(s) => s,
            Err(ZlibError::Truncated(m)) | Err(ZlibError::BadZlibHeader) => {
                errors.push(PackError {
                    offset: entry_offset,
                    code: "inflate_failed".into(),
                    message: m,
                });
                aborted = true;
                break;
            }
        };
        let zlib_end = zlib_start + stream.consumed as u64;
        pos += stream.consumed;

        // Spoofed size: entry header declares a different payload length.
        if obj_type != TYPE_OFS_DELTA && obj_type != TYPE_REF_DELTA
            && declared_size as usize != stream.data.len()
        {
            errors.push(PackError {
                offset: entry_offset,
                code: "size_spoof".into(),
                message: format!(
                    "header claims {} bytes but payload inflates to {}",
                    declared_size,
                    stream.data.len()
                ),
            });
        }
        if !stream.adler_ok {
            errors.push(PackError {
                offset: entry_offset,
                code: "bad_crc".into(),
                message: format!(
                    "zlib adler32 mismatch: trailer {:#010x} computed {:#010x}",
                    stream.adler_expected, stream.adler_actual
                ),
            });
        }

        let crc = super::checksum::crc32(&data[entry_offset as usize..zlib_end as usize]);
        let (delta_base_size, delta_result_size) =
            if obj_type == TYPE_OFS_DELTA || obj_type == TYPE_REF_DELTA {
                match parse_delta_sizes(&stream.data) {
                    Some((b, r, _)) => (Some(b), Some(r)),
                    None => {
                        errors.push(PackError {
                            offset: entry_offset,
                            code: "bad_delta_header".into(),
                            message: "delta size varints malformed".into(),
                        });
                        (None, None)
                    }
                }
            } else {
                (None, None)
            };

        entries.push(ParsedPackEntry {
            offset: entry_offset,
            obj_type,
            declared_size,
            inflated_len: stream.data.len() as u64,
            inflated: stream.data,
            zlib_start,
            zlib_end,
            crc32: crc,
            adler_ok: stream.adler_ok,
            base_offset,
            base_ref,
            delta_base_size,
            delta_result_size,
        });
    }

    let trailer_offset = pos as u64;
    let mut checksum_expected = String::new();
    let mut checksum_actual = String::new();
    let mut checksum_ok = false;
    if !aborted && data.len() >= trailer_offset as usize + 20 {
        checksum_expected = to_hex(&data[trailer_offset as usize..trailer_offset as usize + 20]);
        checksum_actual = sha1_hex(&data[..trailer_offset as usize]);
        checksum_ok = checksum_expected == checksum_actual;
        if !checksum_ok {
            errors.push(PackError {
                offset: trailer_offset,
                code: "bad_pack_checksum".into(),
                message: "pack SHA-1 trailer mismatch".into(),
            });
        }
    } else if aborted {
        errors.push(PackError {
            offset: trailer_offset,
            code: "scan_aborted".into(),
            message: "remaining objects could not be reached".into(),
        });
    }

    ParsedPack {
        version,
        count: entries.len() as u32,
        declared_count,
        entries,
        trailer_offset,
        file_len,
        checksum_expected,
        checksum_actual,
        checksum_ok,
        errors,
    }
}
