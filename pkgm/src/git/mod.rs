//! Git 底层解析（不调用系统 git）：pack / idx / loose / delta / zlib / sha1。
pub mod types;
pub mod varint;
pub mod zlib;
pub mod hash;
pub mod crc;
pub mod pack;
pub mod idx;
pub mod loose;
pub mod delta;

pub use types::ObjType;
