use crate::error::{Error, ErrorCode, R};
use crate::gitenc::{read_ofs_distance, read_pack_header_byte};
use crate::model::{ObjKind, PackEntry, PackInfo};
use crate::zlibw::inflate_at;
use sha1::{Digest, Sha1};

pub fn pack_sha1(buf: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(buf);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.finalize());
    out
}

/// Parse a complete pack byte buffer. Every entry is isolated: a failure on one
/// entry is returned through `entry_errors` while parsing continues.
pub fn parse_pack(buf: &[u8]) -> R<(PackInfo, Vec<(u64, Error)>)> {
    if buf.len() < 12 + 20 {
        return Err(Error::new(ErrorCode::PackTruncated, "file shorter than pack trailer"));
    }
    if &buf[0..4] != b"PACK" {
        return Err(Error::new(ErrorCode::PackBadMagic, "missing PACK magic"));
    }
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::new(
            ErrorCode::PackUnsupportedVersion,
            format!("pack version {} not supported", version),
        ));
    }
    let count = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
    let body_end = buf.len() - 20;
    let mut trailing = [0u8; 20];
    trailing.copy_from_slice(&buf[body_end..body_end + 20]);

    let mut entries = Vec::new();
    let mut entry_errors = Vec::new();
    let mut pos = 12usize;
    for _ in 0..count {
        if pos >= body_end {
            entry_errors.push((pos as u64, Error::new(ErrorCode::PackEntryTruncated, "ran into trailer")));
            break;
        }
        let entry_offset = pos;
        let parsed = (|| -> R<PackEntry> {
            let (bits, inflated_size, hlen) = read_pack_header_byte(buf, pos)?;
            let kind = ObjKind::from_bits(bits)
                .ok_or_else(|| Error::new(ErrorCode::EntryTypeUnknown, format!("type bits {}", bits)))?;
            let mut p = pos + hlen;
            let mut ofs_target = None;
            let mut ref_target = None;
            if kind == ObjKind::OfsDelta {
                let (dist, dlen) = read_ofs_distance(buf, p)?;
                if dist > entry_offset as u64 {
                    return Err(Error::new(
                        ErrorCode::OfsDeltaTargetOutOfRange,
                        format!("negative-offset delta distance {} underflows entry offset {}", dist, entry_offset),
                    ));
                }
                ofs_target = Some(entry_offset as u64 - dist);
                p += dlen;
            } else if kind == ObjKind::RefDelta {
                if p + 20 > body_end {
                    return Err(Error::new(ErrorCode::PackEntryTruncated, "ref-delta oid"));
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&buf[p..p + 20]);
                ref_target = Some(oid);
                p += 20;
            }
            if p >= body_end {
                return Err(Error::new(ErrorCode::PackEntryTruncated, "no compressed payload"));
            }
            let (data, clen) = inflate_at(&buf[p..body_end], crate::model::HARD_INFLATE_CAP)?;
            let header_size = (p - entry_offset) as u64;
            Ok(PackEntry {
                offset: entry_offset as u64,
                kind,
                header_size,
                inflated_size,
                data,
                compressed_len: clen,
                ofs_target,
                ref_target,
                crc: None,
            })
        })();
        match parsed {
            Ok(e) => {
                pos += e.header_size as usize + e.compressed_len;
                entries.push(e);
            }
            Err(e) => {
                entry_errors.push((entry_offset as u64, e));
                break;
            }
        }
    }

    let info = PackInfo { version, entries, trailing_sha: trailing };
    Ok((info, entry_errors))
}
