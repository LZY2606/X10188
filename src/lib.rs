//! 包链显微镜 (Pack-chain microscope): inspect Git packs, indexes and loose
//! objects without ever invoking a system `git` binary.

pub mod analyze;
pub mod git;
pub mod import;
pub mod pairing;
pub mod ingest;
pub mod store;
pub mod web;

pub use store::{Budget, Store};
