pub mod checksum;
pub mod delta;
pub mod index;
pub mod loose;
pub mod pack;
pub mod zlib;

pub use checksum::{git_object_id, git_type_name};
pub use index::{IndexEntry, ParsedIndex};
pub use loose::ParsedLoose;
pub use pack::{ParsedPack, ParsedPackEntry};

pub const TYPE_COMMIT: u8 = 1;
pub const TYPE_TREE: u8 = 2;
pub const TYPE_BLOB: u8 = 3;
pub const TYPE_TAG: u8 = 4;
pub const TYPE_OFS_DELTA: u8 = 6;
pub const TYPE_REF_DELTA: u8 = 7;
