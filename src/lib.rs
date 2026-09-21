//! 包链显微镜（pack-chain-microscope）核心库：
//! 从零实现 Git pack/index/loose object 解析与 delta 链还原，不调用系统 git。

pub mod delta;
pub mod gitid;
pub mod pack;
pub mod zutil;
