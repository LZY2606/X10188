//! 包链显微镜 (Pack-chain microscope)
//!
//! 纯 Rust 实现的 Git pack / index / loose object 取证分析器。
//! 核心解析不调用系统 git。

pub mod builder;
pub mod core_engine;
pub mod delta;
pub mod git;
pub mod idx;
pub mod loose;
pub mod pack;
pub mod store;
pub mod web;
pub mod zlibx;
