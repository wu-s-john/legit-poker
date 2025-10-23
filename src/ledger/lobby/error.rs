use sea_orm::DbErr;

#[derive(Debug, thiserror::Error)]
pub enum GameSetupError {
    #[error("database error: {0}")]
    Database(#[from] DbErr),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("{0} not found")]
    NotFound(&'static str),
}

impl GameSetupError {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }
}
