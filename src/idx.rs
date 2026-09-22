//! Hand-written parser for Git pack index files (version 2 only).
//!
//! The fanout table is parsed fully and retained so the UI can show it;
//! offsets, per-entry CRC32 values and the pack/index trailer checksums
//! are exposed for cross-validation against the imported pack.

use crate::gitio::{hex_oid, sha1_bytes};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IdxInfo {
    pub entries: Vec<IdxEntry>,
    /// The full 256-bucket fanout table.
    pub fanout: Vec<u32>,
    pub pack_checksum: [u8; 20],
    pub idx_checksum: [u8; 20],
    pub pack_trailer_ok: bool,
    pub idx_trailer_ok: bool,
    pub fanout_error: Option<String>,
    pub trailer_error: Option<String>,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxInfo, String> {
    if data.len() < 8 {
        return Err("idx too small".into());
    }
    if &data[0..4] != b"\xfftOc" {
        // v1 indexes are deliberately not supported; refuse cleanly.
        return Err("only idx version 2 is supported (missing \\xfftOc magic)".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported idx version {version}"));
    }

    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        let p = 8 + i * 4;
        fanout.push(u32::from_be_bytes(data[p..p + 4].try_into().unwrap()));
    }
    let count = *fanout.last().unwrap() as usize;
    let expected_len = 8 + 256 * 4 + count * 20 + count * 4 + count * 4 + 40;
    if data.len() != expected_len {
        return Err(format!(
            "idx length {} inconsistent with fanout count {} (expected {expected_len})",
            data.len(),
            count
        ));
    }

    let mut fanout_error = None;
    let mut prev = 0u32;
    for (i, v) in fanout.iter().enumerate() {
        if *v < prev {
            fanout_error =
                Some(format!("fanout bucket {i} decreases: {prev} -> {v}"));
            break;
        }
        prev = *v;
    }
    if prev as usize != count {
        fanout_error = Some(format!(
            "fanout final value {prev} inconsistent with declared count {count}"
        ));
    }

    let oid_start = 8 + 256 * 4;
    let crc_start = oid_start + count * 20;
    let off_start = crc_start + count * 4;
    let trailer = off_start + count * 4;

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_start + i * 20..oid_start + (i + 1) * 20]);
        let crc32 = u32::from_be_bytes(
            data[crc_start + i * 4..crc_start + (i + 1) * 4]
                .try_into()
                .unwrap(),
        );
        let raw = u32::from_be_bytes(
            data[off_start + i * 4..off_start + (i + 1) * 4]
                .try_into()
                .unwrap(),
        );
        let offset = if raw & 0x8000_0000 != 0 {
            let lobe = (raw & 0x7fff_ffff) as usize;
            let base = trailer + lobe * 8;
            if base + 8 > data.len() {
                return Err("offset64 lobe points outside idx".into());
            }
            u64::from_be_bytes(data[base..base + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, offset, crc32 });
    }

    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[trailer..trailer + 20]);
    let mut idx_checksum = [0u8; 20];
    idx_checksum.copy_from_slice(&data[trailer + 20..trailer + 40]);

    let computed_pack_sum = sha1_bytes(&data[..trailer]);
    let pack_trailer_ok = computed_pack_sum == pack_checksum;
    let computed_idx_sum = sha1_bytes(&data[..trailer + 20]);
    let idx_trailer_ok = computed_idx_sum == idx_checksum;
    let trailer_error = if pack_trailer_ok && idx_trailer_ok {
        None
    } else {
        Some(format!(
            "idx trailer mismatch: packsum stored {} computed {}; idxsum stored {} computed {}",
            hex_oid(&pack_checksum),
            hex_oid(&computed_pack_sum),
            hex_oid(&idx_checksum),
            hex_oid(&computed_idx_sum),
        ))
    };

    Ok(IdxInfo {
        entries,
        fanout,
        pack_checksum,
        idx_checksum,
        pack_trailer_ok,
        idx_trailer_ok,
        fanout_error,
        trailer_error,
    })
}
