pub mod oid;
pub mod varint;
pub mod packhdr;
pub mod inflate;
pub mod delta;
pub mod idx;
pub mod object;
pub mod builder;

pub use oid::Oid;
pub use varint::{read_varint, write_varint};
pub use packhdr::{read_pack_header, PackObjHeader};
pub use inflate::{inflate_stream, InflateResult};
pub use delta::{apply_delta, DeltaStep};
pub use idx::{parse_idx, IdxData, IdxEntry};
pub use object::{git_object_id, split_loose, parse_tree_entries, TreeEntry, ObjectKind};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        _ => "unknown",
    }
}

pub fn is_delta(t: u8) -> bool {
    t == OBJ_OFS_DELTA || t == OBJ_REF_DELTA
}

pub fn kind_header_name(t: u8) -> Option<&'static str> {
    match t {
        OBJ_COMMIT => Some("commit"),
        OBJ_TREE => Some("tree"),
        OBJ_BLOB => Some("blob"),
        OBJ_TAG => Some("tag"),
        _ => None,
    }
}

pub fn crc32_bytes(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}
