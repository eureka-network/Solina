use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolinaError {
    #[error("Failed to veriy solution: {0}")]
    FailedSolutionVerification(String),
}
