//! 包链显微镜 (packscope): 纯 Rust 实现的 Git pack / index / loose object 取证分析器。
//!
//! 不依赖系统 `git` 完成任何核心解析：pack header、对象头、ofs-delta、ref-delta、
//! zlib 边界、index fanout、delta 链还原、object id 重算均在此 crate 内实现。

pub mod budget;
pub mod engine;
pub mod git;
pub mod store;
pub mod web;

pub use git::oid::{hex_to_oid, oid_to_hex, Oid};

/// 全局解压硬上限：单个被解压字节流不得超过此值，防止声明大小/压缩炸弹吃光内存。
pub const HARD_INFLATE_CAP: usize = 256 * 1024 * 1024;

/// 预览内容上限（字节），超出部分截断后记录真实长度。
pub const PREVIEW_CAP: usize = 256;
