pub mod sha;
pub mod zlib;
pub mod delta;
pub mod pack;
pub mod index;
pub mod loose;
pub mod object;

pub use object::{GitObject, ObjType};
