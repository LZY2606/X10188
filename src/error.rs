use std::fmt;

#[derive(Debug, Clone)]
pub enum AppError {
    Io(String),
    Db(String),
    Http(String),
    NotFound(String),
    Conflict(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(s) => write!(f, "io error: {s}"),
            AppError::Db(s) => write!(f, "db error: {s}"),
            AppError::Http(s) => write!(f, "http error: {s}"),
            AppError::NotFound(s) => write!(f, "not found: {s}"),
            AppError::Conflict(s) => write!(f, "conflict: {s}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Db(e.to_string())
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, body) = match &self {
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
