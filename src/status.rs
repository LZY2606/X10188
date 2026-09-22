/// Resolution status codes stored in `entries.status`.
pub const UNRESOLVED: i64 = 0;
pub const RESOLVED: i64 = 1;
pub const BLOCKED: i64 = 2;
pub const PAUSED: i64 = 3;
pub const CYCLE: i64 = 4;
pub const ERROR: i64 = 5;

pub fn name(s: i64) -> &'static str {
    match s {
        RESOLVED => "resolved",
        BLOCKED => "blocked",
        PAUSED => "paused",
        CYCLE => "cycle",
        ERROR => "error",
        _ => "unresolved",
    }
}

/// Source kinds.
pub const SRC_PACK: &str = "pack";
pub const SRC_IDX: &str = "idx";
pub const SRC_LOOSE: &str = "loose";
pub const SRC_UNKNOWN: &str = "unknown";
