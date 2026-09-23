//! Low-level Git object parsing implemented from scratch (no system git).
//!
//! Covers pack header/object entries (including ofs-delta and ref-delta),
//! raw zlib stream boundaries, v1/v2 pack indexes with fanout, loose objects,
//! delta instruction decoding and SHA-1 object-id verification.

use std::fmt;

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

#[derive(Debug)]
pub struct GitError {
    pub message: String,
    pub offset: Option<usize>,
}

impl GitError {
    pub fn new<S: Into<String>>(message: S) -> Self {
        GitError { message: message.into(), offset: None }
    }
    pub fn at<S: Into<String>>(offset: usize, message: S) -> Self {
        GitError { message: message.into(), offset: Some(offset) }
    }
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(off) => write!(f, "at offset {:#x}: {}", off, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}
impl std::error::Error for GitError {}

impl From<std::io::Error> for GitError {
    fn from(e: std::io::Error) -> Self {
        GitError::new(format!("io: {e}"))
    }
}

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

pub fn is_base_type(t: u8) -> bool {
    matches!(t, OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG)
}
