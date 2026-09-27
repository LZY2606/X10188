#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_object_bytes: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 64,
            max_total_bytes: 1 << 30,
            max_object_bytes: 1 << 28,
        }
    }
}

impl Budget {
    pub fn new(max_depth: u32, max_total_bytes: u64, max_object_bytes: u64) -> Self {
        Budget { max_depth, max_total_bytes, max_object_bytes }
    }
}
