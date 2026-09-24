//! 包链显微镜（packchain-microscope）
//!
//! 纯 Rust 实现的 Git pack / index / loose object 取证分析库，
//! 不调用系统 git 完成任何核心解析。

pub mod crc;
pub mod db;
pub mod delta;
pub mod engine;
pub mod gitobj;
pub mod index;
pub mod loose;
pub mod models;
pub mod oid;
pub mod pack;
pub mod resolver;
pub mod state;
pub mod zlib;

pub use engine::{Engine, RunSummary};
pub use models::{Budget, ResolveStatus};
pub use oid::{ObjType, Oid};
