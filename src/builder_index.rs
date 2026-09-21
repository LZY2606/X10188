use crate::git::crc32;
use sha1::{Digest, Sha1};

pub fn build_index_v2(pack: &[u8], entries: &[(usize, [u8; 20])]) -> Vec<u8> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|(_, oid)| *oid);
    let count = sorted.len();
    let mut out = Vec::new();
    out.extend_from_slice(&0xff744f63u32.to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());
    let mut cumulative = 0usize;
    for first in 0..256 {
        cumulative = sorted
            .iter()
            .filter(|(_, oid)| oid[0] as usize <= first)
            .count();
        out.extend_from_slice(&(cumulative as u32).to_be_bytes());
    }
    for (_, oid) in &sorted {
        out.extend_from_slice(oid);
    }
    let mut offsets = sorted.iter().map(|(offset, _)| *offset).collect::<Vec<_>>();
    offsets.sort_unstable();
    for (offset, _) in &sorted {
        let end = offsets
            .iter()
            .find(|candidate| **candidate > *offset)
            .copied()
            .unwrap_or(pack.len() - 20);
        out.extend_from_slice(&crc32(&pack[*offset..end]).to_be_bytes());
    }
    for (offset, _) in sorted {
        out.extend_from_slice(&(offset as u32).to_be_bytes());
    }
    let mut hasher = Sha1::new();
    hasher.update(&pack[..pack.len() - 20]);
    let pack_checksum: [u8; 20] = hasher.finalize().into();
    out.extend_from_slice(&pack_checksum);
    let mut index_hasher = Sha1::new();
    index_hasher.update(&out);
    out.extend_from_slice(&index_hasher.finalize());
    out
}
