//! 包链显微镜：从零实现的 Git pack / index / loose object 取证分析核心。
//!
//! 不依赖系统 git：pack header、对象类型、ofs/ref delta、zlib 边界、
//! index fanout、CRC32、SHA-1 object id 与 delta 链还原全部自行实现。

pub mod attach;
pub mod db;
pub mod delta;
pub mod engine;
pub mod error;
pub mod git;
pub mod import;
pub mod index;
pub mod loose;
pub mod oid;
pub mod pack;
pub mod resolve;
pub mod snapshot;
pub mod types;
pub mod web;
pub mod zlib;

pub use engine::Engine;
pub use oid::Oid;
pub use types::Budget;
