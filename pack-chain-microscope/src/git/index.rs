use super::checksum::{sha1_hex, to_hex};

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IndexError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    /// Per-entry result of comparing idx CRC against the packed byte span.
    /// Filled in when the matching pack is available: `None` = not compared.
    pub crc_mismatch: Vec<Option<bool>>,
    pub checksum_expected: String,
    pub checksum_actual: String,
    pub checksum_ok: bool,
    pub pack_checksum: String,
    pub errors: Vec<IndexError>,
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

pub fn parse_index(data: &[u8]) -> ParsedIndex {
    let mut errors = Vec::new();
    let mut empty = ParsedIndex {
        version: 0,
        fanout: Vec::new(),
        entries: Vec::new(),
        crc_mismatch: Vec::new(),
        checksum_expected: String::new(),
        checksum_actual: String::new(),
        checksum_ok: false,
        pack_checksum: String::new(),
        errors: Vec::new(),
    };

    if data.len() < 8 {
        empty.errors.push(IndexError {
            code: "truncated".into(),
            message: "index shorter than 8 bytes".into(),
        });
        return empty;
    }

    // v2 starts with the magic \377tOc and a 4-byte version.
    let v2 = &data[0..4] == b"\xfftOc";
    if v2 {
        let version = u32_at(data, 4);
        if version != 2 {
            empty.errors.push(IndexError {
                code: "unsupported_version".into(),
                message: format!("index version {} not supported", version),
            });
            empty.version = version;
            return empty;
        }
        let fanout_start = 8;
        let fanout: Vec<u32> = (0..256)
            .map(|i| u32_at(data, fanout_start + i * 4))
            .collect();
        let count = *fanout.last().unwrap();
        let mut pos = fanout_start + 256 * 4;

        let names_start = pos;
        let names_end = names_start + count as usize * 20;
        if data.len() < names_end {
            empty.errors.push(IndexError {
                code: "truncated_names".into(),
                message: "object name table truncated".into(),
            });
            return empty;
        }
        let oids: Vec<String> = (0..count as usize)
            .map(|i| to_hex(&data[names_start + i * 20..names_start + i * 20 + 20]))
            .collect();
        pos = names_end;

        let crc_end = pos + count as usize * 4;
        if data.len() < crc_end {
            empty.errors.push(IndexError {
                code: "truncated_crc".into(),
                message: "CRC table truncated".into(),
            });
            return empty;
        }
        let crcs: Vec<u32> = (0..count as usize).map(|i| u32_at(data, pos + i * 4)).collect();
        pos = crc_end;

        let off_end = pos + count as usize * 4;
        if data.len() < off_end {
            empty.errors.push(IndexError {
                code: "truncated_offsets".into(),
                message: "offset table truncated".into(),
            });
            return empty;
        }
        let mut offsets: Vec<u64> = Vec::with_capacity(count as usize);
        let mut large_count = 0usize;
        for i in 0..count as usize {
            let v = u32_at(data, pos + i * 4);
            if v & 0x8000_0000 != 0 {
                large_count += 1;
            }
            offsets.push(v as u64);
        }
        pos = off_end;

        let large_end = pos + large_count * 8;
        if data.len() < large_end {
            empty.errors.push(IndexError {
                code: "truncated_large_offsets".into(),
                message: "64-bit offset table truncated".into(),
            });
            return empty;
        }
        let large: Vec<u64> = (0..large_count)
            .map(|i| {
                let p = pos + i * 8;
                u64::from_be_bytes([
                    data[p],
                    data[p + 1],
                    data[p + 2],
                    data[p + 3],
                    data[p + 4],
                    data[p + 5],
                    data[p + 6],
                    data[p + 7],
                ])
            })
            .collect();
        pos = large_end;

        let mut large_idx = 0usize;
        for off in offsets.iter_mut() {
            if *off & 0x8000_0000 != 0 {
                let idx = (*off & 0x7fff_ffff) as usize;
                if idx >= large.len() {
                    errors.push(IndexError {
                        code: "bad_large_offset_index".into(),
                        message: "large-offset table index out of range".into(),
                    });
                } else {
                    *off = large[idx];
                }
                large_idx += 1;
            }
        }
        let _ = large_idx;

        // trailer: pack checksum (20) + index checksum (20)
        if pos + 40 > data.len() {
            errors.push(IndexError {
                code: "truncated_trailer".into(),
                message: "index trailer missing".into(),
            });
            return ParsedIndex {
                version: 2,
                fanout,
                entries: oids
                    .into_iter()
                    .zip(offsets)
                    .zip(crcs)
                    .map(|((oid, offset), crc32)| IndexEntry { oid, offset, crc32 })
                    .collect(),
                crc_mismatch: Vec::new(),
                checksum_expected: String::new(),
                checksum_actual: String::new(),
                checksum_ok: false,
                pack_checksum: String::new(),
                errors,
            };
        }
        let pack_checksum = to_hex(&data[pos..pos + 20]);
        let idx_expected = to_hex(&data[pos + 20..pos + 40]);
        let idx_actual = sha1_hex(&data[..pos + 20]);
        let idx_ok = idx_expected == idx_actual;
        if !idx_ok {
            errors.push(IndexError {
                code: "bad_index_checksum".into(),
                message: "index SHA-1 trailer mismatch".into(),
            });
        }

        let entries = oids
            .into_iter()
            .zip(offsets)
            .zip(crcs)
            .map(|((oid, offset), crc32)| IndexEntry { oid, offset, crc32 })
            .collect();
        let n = entries.len();
        ParsedIndex {
            version: 2,
            fanout,
            entries,
            crc_mismatch: vec![None; n],
            checksum_expected: idx_expected,
            checksum_actual: idx_actual,
            checksum_ok: idx_ok,
            pack_checksum,
            errors,
        }
    } else {
        // v1: fanout only, then interleaved records. Explicitly unsupported.
        empty.errors.push(IndexError {
            code: "unsupported_version".into(),
            message: "index v1 is not supported (provide a v2 index)".into(),
        });
        empty
    }
}
