use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Pending,
    Resolved,
    MissingBase,
    Cycle,
    BadObject,
    BudgetPaused,
}

impl CandidateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateStatus::Pending => "pending",
            CandidateStatus::Resolved => "resolved",
            CandidateStatus::MissingBase => "missing_base",
            CandidateStatus::Cycle => "cycle",
            CandidateStatus::BadObject => "bad_object",
            CandidateStatus::BudgetPaused => "budget_paused",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "resolved" => CandidateStatus::Resolved,
            "missing_base" => CandidateStatus::MissingBase,
            "cycle" => CandidateStatus::Cycle,
            "bad_object" => CandidateStatus::BadObject,
            "budget_paused" => CandidateStatus::BudgetPaused,
            _ => CandidateStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Budget {
    pub max_depth: usize,
    pub max_total_bytes: usize,
    pub max_single_ratio: usize,
    pub bytes_used: usize,
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockedChain {
    pub candidate_id: i64,
    pub path: Vec<String>,
    pub reason: String,
}
